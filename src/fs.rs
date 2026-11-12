#[cfg(windows)]
use std::os::windows::prelude::*;
use std::{
    borrow::Cow,
    ffi::{OsStr, OsString},
    fmt::{Debug, Display},
    io::{Cursor, Read as _, Write as _},
    path::{Path, PathBuf},
    sync::atomic::{AtomicI32, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions as CapOpenOptions},
};
use serde_derive::{Deserialize, Serialize};
use serde_json::json;
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufStream as TokioBufStream},
};

use crate::{
    anyhow::{anyhow, Context},
    bail, get_version_number,
    message_proto::*,
    ResultType, Stream,
};
// https://doc.rust-lang.org/std/os/windows/fs/trait.MetadataExt.html
use crate::{
    compress::{compress, decompress_with_limit, MAX_DECOMPRESSED_SIZE},
    config::Config,
};

static NEXT_JOB_ID: AtomicI32 = AtomicI32::new(1);

pub fn get_next_job_id() -> i32 {
    NEXT_JOB_ID.fetch_add(1, Ordering::SeqCst)
}

pub fn update_next_job_id(id: i32) {
    NEXT_JOB_ID.store(id, Ordering::SeqCst);
}

pub fn read_dir(path: &Path, include_hidden: bool) -> ResultType<FileDirectory> {
    #[cfg(windows)]
    if "/" == &get_string(path) {
        let mut dir = FileDirectory {
            path: get_string(path),
            ..Default::default()
        };
        let drives = unsafe { winapi::um::fileapi::GetLogicalDrives() };
        for i in 0..32 {
            if drives & (1 << i) != 0 {
                let name = format!(
                    "{}:",
                    std::char::from_u32('A' as u32 + i as u32).unwrap_or('A')
                );
                dir.entries.push(FileEntry {
                    name,
                    entry_type: FileType::DirDrive.into(),
                    ..Default::default()
                });
            }
        }
        return Ok(dir);
    }
    let entries = path
        .read_dir()
        .with_context(|| format!("failed to read directory {}", path.display()))?;
    collect_directory_entries(path, include_hidden, entries)
}

fn collect_directory_entries(
    path: &Path,
    include_hidden: bool,
    entries: impl IntoIterator<Item = std::io::Result<std::fs::DirEntry>>,
) -> ResultType<FileDirectory> {
    let mut dir = FileDirectory {
        path: get_string(path),
        ..Default::default()
    };
    for entry in entries {
        let entry = entry
            .with_context(|| format!("failed to read an entry in directory {}", path.display()))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow!("directory entry name is not valid UTF-8"))?;
        // A native directory entry is a single leaf, not a second authority
        // selected through DirEntry::path(). Keep that invariant explicit.
        let mut components = Path::new(&name).components();
        if !matches!(components.next(), Some(std::path::Component::Normal(_)))
            || components.next().is_some()
        {
            bail!("directory entry name is not a single path component");
        }
        let p = path.join(&name);
        let mut is_hidden = false;
        // Windows DirEntry caches enumeration metadata. Preserve a fresh lookup
        // there so a vanished entry still fails the complete listing.
        #[cfg(not(windows))]
        let meta = entry
            .metadata()
            .with_context(|| format!("failed to read metadata for {}", p.display()))?;
        #[cfg(windows)]
        let meta = std::fs::symlink_metadata(&p)
            .with_context(|| format!("failed to read metadata for {}", p.display()))?;
        // docs.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants
        #[cfg(windows)]
        if meta.file_attributes() & 0x2 != 0 {
            is_hidden = true;
        }
        #[cfg(not(windows))]
        if name.find('.').unwrap_or(usize::MAX) == 0 {
            is_hidden = true;
        }
        if is_hidden && !include_hidden {
            continue;
        }
        let (entry_type, size) = {
            if meta.file_type().is_symlink() {
                if p.is_dir() {
                    (FileType::DirLink.into(), 0)
                } else {
                    (FileType::FileLink.into(), 0)
                }
            } else if meta.is_dir() {
                (FileType::Dir.into(), 0)
            } else if meta.is_file() {
                (FileType::File.into(), meta.len())
            } else {
                bail!("unsupported directory entry type: {}", p.display());
            }
        };
        let modified_time = meta
            .modified()
            .with_context(|| format!("failed to read modification time for {}", p.display()))?
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map(|x| x.as_secs())
            .unwrap_or(0);
        dir.entries.push(FileEntry {
            name,
            entry_type,
            is_hidden,
            size,
            modified_time,
            ..Default::default()
        });
    }
    Ok(dir)
}

#[inline]
pub fn get_file_name(p: &Path) -> String {
    p.file_name()
        .map(|p| p.to_str().unwrap_or(""))
        .unwrap_or("")
        .to_owned()
}

#[inline]
pub fn get_string(path: &Path) -> String {
    path.to_str().unwrap_or("").to_owned()
}

#[inline]
pub fn get_path(path: &str) -> PathBuf {
    Path::new(path).to_path_buf()
}

#[inline]
pub fn get_home_as_string() -> String {
    get_string(&Config::get_home())
}

fn read_dir_recursive(
    path: &Path,
    prefix: &Path,
    include_hidden: bool,
) -> ResultType<Vec<FileEntry>> {
    let mut files = Vec::new();
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed to read metadata for {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!(
            "recursive listing root is a symbolic link: {}",
            path.display()
        );
    }
    if metadata.is_dir() {
        // to-do: symbol link handling, cp the link rather than the content
        // to-do: file mode, for unix
        let fd = read_dir(path, include_hidden)?;
        for entry in fd.entries.iter() {
            match entry.entry_type.enum_value() {
                Ok(FileType::File) => {
                    let mut entry = entry.clone();
                    entry.name = get_string(&prefix.join(entry.name));
                    files.push(entry);
                }
                Ok(FileType::Dir) => {
                    let mut tmp = read_dir_recursive(
                        &path.join(&entry.name),
                        &prefix.join(&entry.name),
                        include_hidden,
                    )?;
                    files.append(&mut tmp);
                }
                _ => {}
            }
        }
        Ok(files)
    } else if metadata.is_file() {
        let modified_time = metadata
            .modified()
            .with_context(|| format!("failed to read modification time for {}", path.display()))?
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map(|x| x.as_secs())
            .unwrap_or(0);
        files.push(FileEntry {
            entry_type: FileType::File.into(),
            size: metadata.len(),
            modified_time,
            ..Default::default()
        });
        Ok(files)
    } else {
        bail!("unsupported recursive listing path: {}", path.display());
    }
}

pub fn get_recursive_files(path: &str, include_hidden: bool) -> ResultType<Vec<FileEntry>> {
    read_dir_recursive(&get_path(path), &get_path(""), include_hidden)
}

fn read_empty_dirs_recursive(
    path: &Path,
    prefix: &Path,
    include_hidden: bool,
) -> ResultType<Vec<FileDirectory>> {
    let mut dirs = Vec::new();
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed to read metadata for {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!(
            "recursive listing root is a symbolic link: {}",
            path.display()
        );
    }
    if metadata.is_dir() {
        // to-do: symbol link handling, cp the link rather than the content
        // to-do: file mode, for unix
        let fd = read_dir(path, include_hidden)?;
        if fd.entries.is_empty() {
            dirs.push(fd);
        } else {
            for entry in fd.entries.iter() {
                if let Ok(FileType::Dir) = entry.entry_type.enum_value() {
                    let mut tmp = read_empty_dirs_recursive(
                        &path.join(&entry.name),
                        &prefix.join(&entry.name),
                        include_hidden,
                    )?;
                    dirs.append(&mut tmp);
                }
            }
        }
        Ok(dirs)
    } else if metadata.is_file() {
        Ok(dirs)
    } else {
        bail!("unsupported recursive listing path: {}", path.display());
    }
}

pub fn get_empty_dirs_recursive(
    path: &str,
    include_hidden: bool,
) -> ResultType<Vec<FileDirectory>> {
    read_empty_dirs_recursive(&get_path(path), &get_path(""), include_hidden)
}

#[inline]
pub fn is_file_exists(file_path: &str) -> bool {
    Path::new(file_path).exists()
}

#[inline]
pub fn can_enable_overwrite_detection(version: i64) -> bool {
    version >= get_version_number("1.1.10")
}

/// Current peer-to-peer file transfer contract.
///
/// This is deliberately an exact-match capability: the pre-production protocol does not carry a
/// legacy compatibility mode for block ordering, terminal errors, or 64-bit resume offsets.
pub const FILE_TRANSFER_PROTOCOL_VERSION: u32 = 2;

pub fn validate_file_transfer_protocol_version(version: u32) -> ResultType<()> {
    if version != FILE_TRANSFER_PROTOCOL_VERSION {
        bail!(
            "unsupported file transfer protocol version {version}; expected {FILE_TRANSFER_PROTOCOL_VERSION}"
        );
    }
    Ok(())
}

#[repr(i32)]
#[derive(Copy, Clone, Serialize, Debug, PartialEq, Default)]
pub enum JobType {
    #[default]
    Generic = 0,
    Printer = 1,
}

impl From<JobType> for file_transfer_send_request::FileType {
    fn from(t: JobType) -> Self {
        match t {
            JobType::Generic => file_transfer_send_request::FileType::Generic,
            JobType::Printer => file_transfer_send_request::FileType::Printer,
        }
    }
}

impl From<i32> for JobType {
    fn from(value: i32) -> Self {
        match value {
            0 => JobType::Generic,
            1 => JobType::Printer,
            _ => JobType::Generic,
        }
    }
}

impl From<JobType> for i32 {
    fn from(val: JobType) -> Self {
        val as i32
    }
}

impl JobType {
    pub fn from_proto(t: ::protobuf::EnumOrUnknown<file_transfer_send_request::FileType>) -> Self {
        match t.enum_value() {
            Ok(file_transfer_send_request::FileType::Generic) => JobType::Generic,
            Ok(file_transfer_send_request::FileType::Printer) => JobType::Printer,
            _ => JobType::Generic,
        }
    }
}

#[derive(Debug)]
pub enum DataSource {
    FilePath(PathBuf),
    MemoryCursor(Cursor<Vec<u8>>),
}

impl Default for DataSource {
    fn default() -> Self {
        DataSource::FilePath(PathBuf::new())
    }
}

impl serde::Serialize for DataSource {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            DataSource::FilePath(p) => serializer.serialize_str(p.to_str().unwrap_or("")),
            DataSource::MemoryCursor(_) => serializer.serialize_str(""),
        }
    }
}

impl Display for DataSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DataSource::FilePath(p) => write!(f, "File: {}", p.to_string_lossy()),
            DataSource::MemoryCursor(_) => write!(f, "Bytes"),
        }
    }
}

impl DataSource {
    fn to_meta(&self) -> String {
        match self {
            DataSource::FilePath(p) => p.to_string_lossy().to_string(),
            DataSource::MemoryCursor(_) => "".to_string(),
        }
    }
}

enum DataStream {
    FileStream(File),
    BufStream(TokioBufStream<Cursor<Vec<u8>>>),
}

#[derive(Debug)]
struct PendingWrite {
    parent: Dir,
    final_name: OsString,
    temp_name: String,
    digest_name: OsString,
    modified_time: u64,
    renamed: bool,
}

#[derive(Debug, Default)]
struct WriteProgress {
    file_num: i32,
    bytes_written: u64,
    next_block_id: u32,
    eof_seen: bool,
}

impl WriteProgress {
    fn new(file_num: i32) -> Self {
        Self {
            file_num,
            ..Default::default()
        }
    }
}

impl Debug for DataStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DataStream::FileStream(fs) => write!(f, "{:?}", fs),
            DataStream::BufStream(_) => write!(f, "BufStream"),
        }
    }
}

impl DataStream {
    async fn write_all(&mut self, buf: &[u8]) -> ResultType<()> {
        match self {
            DataStream::FileStream(fs) => fs.write_all(buf).await?,
            DataStream::BufStream(bs) => bs.write_all(buf).await?,
        }
        Ok(())
    }

    async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            DataStream::FileStream(fs) => fs.read(buf).await,
            DataStream::BufStream(bs) => bs.read(buf).await,
        }
    }
}

#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct FileDigest {
    pub size: u64,
    pub modified: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub temp_name: String,
}

#[derive(Default, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TransferJob {
    pub id: i32,
    pub r#type: JobType,
    pub remote: String,
    pub data_source: DataSource,
    pub show_hidden: bool,
    pub is_remote: bool,
    pub is_last_job: bool,
    pub is_resume: bool,
    pub file_num: i32,
    #[serde(skip_serializing)]
    files: Vec<FileEntry>,
    pub conn_id: i32, // server only

    #[serde(skip_serializing)]
    data_stream: Option<DataStream>,
    #[serde(skip_serializing)]
    pending_write: Option<PendingWrite>,
    #[serde(skip_serializing)]
    terminal_error: Option<String>,
    #[serde(skip_serializing)]
    is_read_job: bool,
    #[serde(skip_serializing)]
    write_progress: WriteProgress,
    #[serde(skip_serializing)]
    next_read_block_id: u32,
    pub total_size: u64,
    finished_size: u64,
    transferred: u64,
    enable_overwrite_detection: bool,
    file_confirmed: bool,
    // indicating the last file is skipped
    file_skipped: bool,
    file_is_waiting: bool,
    default_overwrite_strategy: Option<bool>,
    #[serde(skip_serializing)]
    digest: FileDigest,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct TransferJobMeta {
    #[serde(default)]
    pub id: i32,
    #[serde(default)]
    pub remote: String,
    #[serde(default)]
    pub to: String,
    #[serde(default)]
    pub show_hidden: bool,
    #[serde(default)]
    pub file_num: i32,
    #[serde(default)]
    pub is_remote: bool,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct RemoveJobMeta {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub is_remote: bool,
    #[serde(default)]
    pub no_confirm: bool,
}

#[inline]
fn get_ext(name: &str) -> &str {
    if let Some(i) = name.rfind('.') {
        return &name[i + 1..];
    }
    ""
}

#[inline]
fn is_compressed_file(name: &str) -> bool {
    let compressed_exts = ["xz", "gz", "zip", "7z", "rar", "bz2", "tgz", "png", "jpg"];
    let ext = get_ext(name);
    compressed_exts.contains(&ext)
}

fn compress_file_block_with<F>(data: Vec<u8>, compressor: F) -> (Vec<u8>, bool)
where
    F: FnOnce(&[u8]) -> std::io::Result<Vec<u8>>,
{
    match compressor(&data) {
        Ok(compressed) if compressed.len() < data.len() => (compressed, true),
        Ok(_) => (data, false),
        Err(err) => {
            log::warn!("failed to compress file block, sending it uncompressed: {err}");
            (data, false)
        }
    }
}

fn checked_total_size(files: &[FileEntry]) -> ResultType<u64> {
    files.iter().try_fold(0u64, |total, file| {
        total
            .checked_add(file.size)
            .ok_or_else(|| anyhow!("declared file total size overflow"))
    })
}

fn validate_initial_file_num(file_num: i32, file_count: usize) -> ResultType<usize> {
    let file_num = usize::try_from(file_num).map_err(|_| anyhow!("wrong initial file number"))?;
    if file_num > file_count {
        bail!("wrong initial file number");
    }
    Ok(file_num)
}

pub fn validate_file_name_no_traversal(name: &str) -> ResultType<()> {
    if name.bytes().any(|b| b == 0) {
        bail!("file name contains null bytes");
    }
    let has_traversal = name
        .split(|c: char| c == '/' || (cfg!(windows) && c == '\\'))
        .filter(|s| !s.is_empty())
        .any(|s| s == "..");
    if has_traversal {
        bail!("path traversal detected in file name");
    }
    #[cfg(windows)]
    {
        if name.len() >= 2 {
            let bytes = name.as_bytes();
            if bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
                bail!("absolute path detected in file name");
            }
        }
        if name.starts_with('/') || name.starts_with('\\') {
            bail!("absolute path detected in file name");
        }
    }
    #[cfg(not(windows))]
    if name.starts_with('/') {
        bail!("absolute path detected in file name");
    }
    Ok(())
}

fn validate_transfer_file_names(files: &[FileEntry]) -> ResultType<()> {
    // Single-file transfer may use an empty relative name, because
    // the destination file path is carried by transfer metadata.
    if files.len() == 1 && files.first().is_some_and(|f| f.name.is_empty()) {
        return Ok(());
    }
    for file in files {
        if file.name.is_empty() {
            bail!("empty file name in multi-file transfer");
        }
        validate_file_name_no_traversal(&file.name)?;
    }
    Ok(())
}

#[inline]
fn validate_fs_path_argument(path: &str, arg_name: &str) -> ResultType<()> {
    if path.is_empty() {
        bail!("{arg_name} cannot be empty");
    }
    if path.bytes().any(|b| b == 0) {
        bail!("{arg_name} contains null bytes");
    }
    Ok(())
}

fn validate_no_symlink_components(base: &Path, name: &str) -> ResultType<()> {
    if name.is_empty() {
        return Ok(());
    }
    let mut current = base.to_path_buf();
    for component in Path::new(name).components() {
        match component {
            std::path::Component::Normal(seg) => {
                current.push(seg);
                // Best-effort guard: path-based checks are inherently TOCTOU-prone
                // if local filesystem state changes between validation and write.
                match std::fs::symlink_metadata(&current) {
                    Ok(meta) => {
                        // This is inherent to filesystem-based checks and acknowledged as a limitation.
                        // For true protection, you'd need openat(2) / O_NOFOLLOW at write time.
                        if meta.file_type().is_symlink() {
                            bail!("symlink path component is not allowed");
                        }
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                        // Component does not exist yet, continue best-effort validation.
                    }
                    Err(err) => {
                        bail!(
                            "failed to validate path component '{}': {}",
                            current.display(),
                            err
                        );
                    }
                }
            }
            std::path::Component::CurDir => {}
            _ => {
                bail!("invalid file name component");
            }
        }
    }
    Ok(())
}

/// Validate an untrusted relative file name and existing path components before joining it.
pub fn join_validated_path(base: &Path, name: &str) -> ResultType<PathBuf> {
    validate_file_name_no_traversal(name)?;
    validate_no_symlink_components(base, name)?;
    Ok(TransferJob::join(base, name))
}

const DOWNLOAD_TEMP_PREFIX: &str = ".camellia-download-";
const DOWNLOAD_TEMP_SUFFIX: &str = ".part";
const DIGEST_TEMP_PREFIX: &str = ".camellia-digest-";
const DIGEST_TEMP_SUFFIX: &str = ".tmp";
const MAX_DIGEST_BYTES: u64 = 4096;
const RANDOM_NAME_ATTEMPTS: usize = 16;

fn append_suffix(name: &OsStr, suffix: &str) -> OsString {
    let mut result = name.to_os_string();
    result.push(suffix);
    result
}

fn random_sidecar_name(prefix: &str, suffix: &str) -> String {
    format!("{prefix}{}{suffix}", uuid::Uuid::new_v4())
}

fn validate_download_temp_name(name: &str) -> ResultType<()> {
    let Some(uuid) = name
        .strip_prefix(DOWNLOAD_TEMP_PREFIX)
        .and_then(|name| name.strip_suffix(DOWNLOAD_TEMP_SUFFIX))
    else {
        bail!("invalid transfer temporary file name");
    };
    if uuid.len() != 36 || uuid::Uuid::parse_str(uuid)?.hyphenated().to_string() != uuid {
        bail!("invalid transfer temporary file name");
    }
    Ok(())
}

fn nofollow_read_options() -> CapOpenOptions {
    let mut options = CapOpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    options
}

fn nofollow_write_options(create_new: bool) -> CapOpenOptions {
    let mut options = CapOpenOptions::new();
    options
        .write(true)
        .create_new(create_new)
        .follow(FollowSymlinks::No);
    options
}

fn open_ambient_directory_nofollow(path: &Path, create: bool) -> ResultType<Dir> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut root = PathBuf::new();
    let mut components = Vec::new();
    for component in absolute.components() {
        match component {
            std::path::Component::Prefix(prefix) => root.push(prefix.as_os_str()),
            std::path::Component::RootDir => {
                root.push(std::path::MAIN_SEPARATOR.to_string());
            }
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if components.pop().is_none() {
                    bail!("directory path escapes its filesystem root");
                }
            }
            std::path::Component::Normal(component) => components.push(component.to_os_string()),
        }
    }
    if root.as_os_str().is_empty() {
        bail!("directory path has no filesystem root");
    }
    let mut directory = Dir::open_ambient_dir(root, ambient_authority())?;
    for component in components {
        directory = match directory.open_dir_nofollow(&component) {
            Ok(next) => next,
            Err(err) if create && err.kind() == std::io::ErrorKind::NotFound => {
                match directory.create_dir(&component) {
                    Ok(()) => {}
                    Err(create_err) if create_err.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(create_err) => return Err(create_err.into()),
                }
                directory.open_dir_nofollow(&component)?
            }
            Err(err) => return Err(err.into()),
        };
    }
    Ok(directory)
}

fn open_destination_parent(
    base: &Path,
    name: &str,
    create_directories: bool,
) -> ResultType<(Dir, OsString)> {
    validate_file_name_no_traversal(name)?;
    if name.is_empty() {
        let final_name = base
            .file_name()
            .filter(|name| !name.is_empty())
            .ok_or_else(|| anyhow!("destination file name is empty"))?
            .to_os_string();
        let parent = base.parent().filter(|path| !path.as_os_str().is_empty());
        let parent = parent.unwrap_or_else(|| Path::new("."));
        return Ok((
            open_ambient_directory_nofollow(parent, create_directories)?,
            final_name,
        ));
    }

    let mut parent = open_ambient_directory_nofollow(base, create_directories)?;
    let components = Path::new(name)
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(component) => Some(Ok(component.to_os_string())),
            std::path::Component::CurDir => None,
            _ => Some(Err(anyhow!("invalid file name component"))),
        })
        .collect::<ResultType<Vec<_>>>()?;
    let (final_name, parent_components) = components
        .split_last()
        .ok_or_else(|| anyhow!("destination file name is empty"))?;

    for component in parent_components {
        parent = match parent.open_dir_nofollow(component) {
            Ok(directory) => directory,
            Err(err) if create_directories && err.kind() == std::io::ErrorKind::NotFound => {
                match parent.create_dir(component) {
                    Ok(()) => {}
                    Err(create_err) if create_err.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(create_err) => return Err(create_err.into()),
                }
                parent.open_dir_nofollow(component)?
            }
            Err(err) => return Err(err.into()),
        };
    }
    Ok((parent, final_name.clone()))
}

fn read_digest(parent: &Dir, digest_name: &OsStr) -> ResultType<Option<FileDigest>> {
    let file = match parent.open_with(digest_name, &nofollow_read_options()) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_DIGEST_BYTES {
        bail!("invalid transfer digest file");
    }
    let mut content = String::new();
    file.into_std()
        .take(MAX_DIGEST_BYTES + 1)
        .read_to_string(&mut content)?;
    if content.len() as u64 > MAX_DIGEST_BYTES {
        bail!("transfer digest file is too large");
    }
    Ok(Some(serde_json::from_str(&content)?))
}

fn write_digest_atomically(
    parent: &Dir,
    digest_name: &OsStr,
    digest: &FileDigest,
) -> ResultType<()> {
    let content = serde_json::to_vec(digest)?;
    if content.len() as u64 > MAX_DIGEST_BYTES {
        bail!("transfer digest file is too large");
    }
    for _ in 0..RANDOM_NAME_ATTEMPTS {
        let temp_name = random_sidecar_name(DIGEST_TEMP_PREFIX, DIGEST_TEMP_SUFFIX);
        let file = match parent.open_with(&temp_name, &nofollow_write_options(true)) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err.into()),
        };
        let mut file = file.into_std();
        let result = (|| -> ResultType<()> {
            file.write_all(&content)?;
            file.sync_all()?;
            drop(file);
            parent.rename(&temp_name, parent, digest_name)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = parent.remove_file_or_symlink(&temp_name);
        }
        return result;
    }
    bail!("failed to allocate a unique transfer digest name")
}

fn remove_file_or_symlink_if_present(parent: &Dir, name: &OsStr) -> ResultType<()> {
    match parent.remove_file_or_symlink(name) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

fn ensure_safe_final_target(parent: &Dir, final_name: &OsStr) -> ResultType<()> {
    match parent.symlink_metadata(final_name) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            bail!("destination file is a symbolic link")
        }
        Ok(metadata) if !metadata.is_file() => bail!("destination is not a regular file"),
        Ok(_) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

fn prepare_new_write(
    base: &Path,
    name: &str,
    digest: &FileDigest,
    modified_time: u64,
) -> ResultType<(std::fs::File, PendingWrite)> {
    let (parent, final_name) = open_destination_parent(base, name, true)?;
    ensure_safe_final_target(&parent, &final_name)?;
    let digest_name = append_suffix(&final_name, ".digest");
    let legacy_download_name = append_suffix(&final_name, ".download");

    if let Ok(Some(previous_digest)) = read_digest(&parent, &digest_name) {
        if validate_download_temp_name(&previous_digest.temp_name).is_ok() {
            remove_file_or_symlink_if_present(&parent, OsStr::new(&previous_digest.temp_name))?;
        }
    }
    remove_file_or_symlink_if_present(&parent, &legacy_download_name)?;

    for _ in 0..RANDOM_NAME_ATTEMPTS {
        let temp_name = random_sidecar_name(DOWNLOAD_TEMP_PREFIX, DOWNLOAD_TEMP_SUFFIX);
        let file = match parent.open_with(&temp_name, &nofollow_write_options(true)) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err.into()),
        };
        let digest = FileDigest {
            size: digest.size,
            modified: digest.modified,
            temp_name: temp_name.clone(),
        };
        if let Err(err) = write_digest_atomically(&parent, &digest_name, &digest) {
            let _ = parent.remove_file_or_symlink(&temp_name);
            return Err(err);
        }
        return Ok((
            file.into_std(),
            PendingWrite {
                parent,
                final_name,
                temp_name,
                digest_name,
                modified_time,
                renamed: false,
            },
        ));
    }
    bail!("failed to allocate a unique transfer temporary file name")
}

fn open_resumed_write(
    base: &Path,
    name: &str,
    digest: &FileDigest,
    modified_time: u64,
) -> ResultType<(std::fs::File, PendingWrite)> {
    let (parent, final_name) = open_destination_parent(base, name, false)?;
    ensure_safe_final_target(&parent, &final_name)?;
    let digest_name = append_suffix(&final_name, ".digest");
    let stored_digest = read_digest(&parent, &digest_name)?
        .ok_or_else(|| anyhow!("transfer digest file is missing"))?;
    if stored_digest.size != digest.size || stored_digest.modified != digest.modified {
        bail!("transfer digest changed before resume");
    }
    validate_download_temp_name(&stored_digest.temp_name)?;
    let file = parent.open_with(&stored_digest.temp_name, &nofollow_write_options(false))?;
    if !file.metadata()?.is_file() {
        bail!("transfer temporary path is not a regular file");
    }
    Ok((
        file.into_std(),
        PendingWrite {
            parent,
            final_name,
            temp_name: stored_digest.temp_name,
            digest_name,
            modified_time,
            renamed: false,
        },
    ))
}

impl TransferJob {
    #[allow(clippy::too_many_arguments)]
    pub fn new_write(
        id: i32,
        r#type: JobType,
        remote: String,
        data_source: DataSource,
        file_num: i32,
        show_hidden: bool,
        is_remote: bool,
        enable_overwrite_detection: bool,
    ) -> Self {
        log::info!("new write {}", data_source);
        Self {
            id,
            r#type,
            remote,
            data_source,
            file_num,
            show_hidden,
            is_remote,
            files: Vec::new(),
            write_progress: WriteProgress::new(file_num),
            total_size: 0,
            enable_overwrite_detection,
            ..Default::default()
        }
    }

    pub fn with_files(mut self, files: Vec<FileEntry>) -> ResultType<Self> {
        self.set_files(files)?;
        Ok(self)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_read(
        id: i32,
        r#type: JobType,
        remote: String,
        data_source: DataSource,
        file_num: i32,
        show_hidden: bool,
        is_remote: bool,
        enable_overwrite_detection: bool,
    ) -> ResultType<Self> {
        log::info!("new read {}", data_source);
        let (files, total_size) = match &data_source {
            DataSource::FilePath(p) => {
                let p = p.to_str().ok_or(anyhow!("Invalid path"))?;
                let files = get_recursive_files(p, show_hidden)?;
                let total_size = checked_total_size(&files)?;
                (files, total_size)
            }
            DataSource::MemoryCursor(c) => (Vec::new(), c.get_ref().len() as u64),
        };
        validate_initial_file_num(file_num, files.len())?;
        Ok(Self {
            id,
            r#type,
            remote,
            data_source,
            file_num,
            show_hidden,
            is_remote,
            files,
            total_size,
            enable_overwrite_detection,
            is_read_job: true,
            ..Default::default()
        })
    }

    pub async fn get_buf_data(self) -> ResultType<Option<Vec<u8>>> {
        match self.data_stream {
            Some(DataStream::BufStream(mut bs)) => {
                bs.flush().await?;
                Ok(Some(bs.into_inner().into_inner()))
            }
            _ => Ok(None),
        }
    }

    #[inline]
    pub fn files(&self) -> &Vec<FileEntry> {
        &self.files
    }

    #[inline]
    pub fn set_files(&mut self, files: Vec<FileEntry>) -> ResultType<()> {
        validate_transfer_file_names(&files)?;
        validate_initial_file_num(self.file_num, files.len())?;
        let total_size = checked_total_size(&files)?;
        if let DataSource::FilePath(base) = &self.data_source {
            for file in &files {
                validate_no_symlink_components(base, &file.name)?;
            }
        }
        self.total_size = total_size;
        self.files = files;
        self.write_progress = WriteProgress::new(self.file_num);
        Ok(())
    }

    #[inline]
    pub fn set_digest(&mut self, size: u64, modified: u64) {
        self.digest.size = size;
        self.digest.modified = modified;
    }

    #[inline]
    pub fn id(&self) -> i32 {
        self.id
    }

    #[inline]
    pub fn total_size(&self) -> u64 {
        self.total_size
    }

    #[inline]
    pub fn finished_size(&self) -> u64 {
        self.finished_size
    }

    #[inline]
    pub fn transferred(&self) -> u64 {
        self.transferred
    }

    #[inline]
    pub fn file_num(&self) -> i32 {
        self.file_num
    }

    fn ensure_not_terminated(&self) -> ResultType<()> {
        if let Some(err) = self.terminal_error.as_deref() {
            bail!("file transfer is terminated: {err}");
        }
        Ok(())
    }

    fn record_terminal_error(&mut self, err: &crate::anyhow::Error) {
        if self.terminal_error.is_none() {
            self.terminal_error = Some(err.to_string());
        }
    }

    fn ensure_write_complete(&self) -> ResultType<()> {
        if self.r#type == JobType::Printer
            || matches!(self.data_source, DataSource::MemoryCursor(_))
        {
            return Ok(());
        }
        let file_num = usize::try_from(self.file_num).map_err(|_| anyhow!("wrong file number"))?;
        if self.files.is_empty() || file_num == self.files.len() {
            return Ok(());
        }
        if file_num > self.files.len() {
            bail!("file transfer ended with an invalid file number");
        }
        let is_last_file = file_num
            .checked_add(1)
            .is_some_and(|next| next == self.files.len());
        let current_file_complete = self.write_progress.file_num == self.file_num
            && self.write_progress.bytes_written == self.files[file_num].size
            && self.write_progress.eof_seen;
        if !is_last_file || !current_file_complete {
            bail!("file transfer ended before the declared files were complete");
        }
        Ok(())
    }

    async fn finalize_pending_write(&mut self) -> ResultType<()> {
        let Some(pending) = self.pending_write.as_ref() else {
            if let Some(DataStream::FileStream(file)) = self.data_stream.take() {
                file.sync_all().await?;
            }
            return Ok(());
        };
        let modified_time = i64::try_from(pending.modified_time)
            .map_err(|_| anyhow!("file modification time is out of range"))?;
        let stream = self
            .data_stream
            .take()
            .ok_or_else(|| anyhow!("transfer file stream is missing"))?;
        let DataStream::FileStream(file) = stream else {
            bail!("transfer file stream has the wrong type");
        };
        file.sync_all().await?;
        let file_for_metadata = file.into_std().await;

        tokio::task::spawn_blocking(move || -> ResultType<()> {
            filetime::set_file_handle_times(
                &file_for_metadata,
                None,
                Some(filetime::FileTime::from_unix_time(modified_time, 0)),
            )?;
            file_for_metadata.sync_all()?;
            drop(file_for_metadata);
            Ok(())
        })
        .await??;

        if !pending.renamed {
            let parent = pending.parent.try_clone()?;
            let final_name = pending.final_name.clone();
            let temp_name = pending.temp_name.clone();
            tokio::task::spawn_blocking(move || -> ResultType<()> {
                ensure_safe_final_target(&parent, &final_name)?;
                parent.rename(&temp_name, &parent, &final_name)?;
                Ok(())
            })
            .await??;
            self.pending_write
                .as_mut()
                .ok_or_else(|| anyhow!("transfer pending state disappeared"))?
                .renamed = true;
        }

        let parent = self
            .pending_write
            .as_ref()
            .ok_or_else(|| anyhow!("transfer pending state disappeared"))?
            .parent
            .try_clone()?;
        tokio::task::spawn_blocking(move || parent.open(".")?.sync_all()).await??;

        let pending = self
            .pending_write
            .as_ref()
            .ok_or_else(|| anyhow!("transfer pending state disappeared"))?;
        let parent = pending.parent.try_clone()?;
        let digest_name = pending.digest_name.clone();
        tokio::task::spawn_blocking(move || -> ResultType<()> {
            remove_file_or_symlink_if_present(&parent, &digest_name)?;
            parent.open(".")?.sync_all()?;
            Ok(())
        })
        .await??;
        self.pending_write.take();
        Ok(())
    }

    pub async fn modify_time(&mut self) -> ResultType<()> {
        self.ensure_not_terminated()?;
        let result = async {
            self.ensure_write_complete()?;
            if self.r#type != JobType::Printer {
                self.finalize_pending_write().await?;
            }
            Ok(())
        }
        .await;
        if let Err(err) = &result {
            self.record_terminal_error(err);
        }
        result
    }

    pub async fn remove_download_file(&mut self) -> ResultType<()> {
        if self.r#type == JobType::Printer {
            return Ok(());
        }
        self.data_stream.take();
        if let Some(pending) = self.pending_write.take() {
            tokio::task::spawn_blocking(move || -> ResultType<()> {
                remove_file_or_symlink_if_present(&pending.parent, OsStr::new(&pending.temp_name))?;
                remove_file_or_symlink_if_present(&pending.parent, &pending.digest_name)?;
                Ok(())
            })
            .await??;
            return Ok(());
        }

        let (base, name) = match &self.data_source {
            DataSource::FilePath(base) => {
                let file_num = self.file_num as usize;
                let Some(entry) = self.files.get(file_num) else {
                    return Ok(());
                };
                (base.clone(), entry.name.clone())
            }
            DataSource::MemoryCursor(_) => return Ok(()),
        };
        tokio::task::spawn_blocking(move || -> ResultType<()> {
            let (parent, final_name) = open_destination_parent(&base, &name, false)?;
            let digest_name = append_suffix(&final_name, ".digest");
            if let Ok(Some(digest)) = read_digest(&parent, &digest_name) {
                if validate_download_temp_name(&digest.temp_name).is_ok() {
                    remove_file_or_symlink_if_present(&parent, OsStr::new(&digest.temp_name))?;
                }
            }
            remove_file_or_symlink_if_present(&parent, &digest_name)?;
            remove_file_or_symlink_if_present(&parent, &append_suffix(&final_name, ".download"))?;
            Ok(())
        })
        .await??;
        Ok(())
    }

    #[inline]
    pub fn set_finished_size_on_resume(&mut self) {
        if self.is_resume && self.file_num > 0 {
            let finished_size: u64 = self
                .files
                .iter()
                .take(self.file_num as usize)
                .map(|file| file.size)
                .sum();
            self.finished_size = finished_size;
        }
    }

    pub async fn write(&mut self, block: FileTransferBlock) -> ResultType<()> {
        self.ensure_not_terminated()?;
        let result = self.write_block(block).await;
        if let Err(err) = &result {
            self.record_terminal_error(err);
        }
        result
    }

    async fn write_block(&mut self, block: FileTransferBlock) -> ResultType<()> {
        if block.id != self.id {
            bail!("Wrong id");
        }
        if block.file_num < 0 {
            bail!("wrong file number");
        }
        let file_num = usize::try_from(block.file_num).map_err(|_| anyhow!("wrong file number"))?;
        let is_file_backed = matches!(self.data_source, DataSource::FilePath(_));
        let starts_next_file = if is_file_backed {
            if file_num >= self.files.len() {
                bail!("wrong file number");
            }
            if block.file_num == self.write_progress.file_num {
                if self.write_progress.eof_seen {
                    bail!("file block received after end-of-file");
                }
                false
            } else {
                let next_file_num = self
                    .write_progress
                    .file_num
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("file number overflow"))?;
                if block.file_num != next_file_num {
                    bail!("out-of-order file number");
                }
                if !self.write_progress.eof_seen {
                    bail!("next file received before end-of-file");
                }
                true
            }
        } else {
            if block.file_num != self.write_progress.file_num {
                bail!("out-of-order file number");
            }
            false
        };

        let bytes_written = if starts_next_file {
            0
        } else {
            self.write_progress.bytes_written
        };
        let expected_block_id = if starts_next_file {
            0
        } else {
            self.write_progress.next_block_id
        };
        if block.blk_id != expected_block_id {
            bail!("out-of-order file block id");
        }
        let next_block_id = expected_block_id
            .checked_add(1)
            .ok_or_else(|| anyhow!("file block id overflow"))?;

        let remaining = if is_file_backed {
            self.files[file_num]
                .size
                .checked_sub(bytes_written)
                .ok_or_else(|| anyhow!("file payload exceeds declared size"))?
        } else {
            u64::MAX
        };
        let payload = if block.compressed {
            let limit = usize::try_from(remaining.min(MAX_DECOMPRESSED_SIZE as u64))
                .map_err(|_| anyhow!("remaining file budget is out of range"))?;
            let decompressed = decompress_with_limit(&block.data, limit)
                .map_err(|err| anyhow!("failed to decompress file block: {err}"))?;
            if decompressed.is_empty() {
                bail!("compressed file block cannot represent end-of-file");
            }
            Cow::Owned(decompressed)
        } else {
            Cow::Borrowed(block.data.as_ref())
        };
        let payload_len =
            u64::try_from(payload.len()).map_err(|_| anyhow!("file block length overflow"))?;
        let new_file_size = bytes_written
            .checked_add(payload_len)
            .ok_or_else(|| anyhow!("written file size overflow"))?;
        if is_file_backed && new_file_size > self.files[file_num].size {
            bail!("file payload exceeds declared size");
        }
        let eof_seen = payload.is_empty();
        if is_file_backed && eof_seen && new_file_size != self.files[file_num].size {
            bail!("end-of-file received before declared file size");
        }
        let new_finished_size = self
            .finished_size
            .checked_add(payload_len)
            .ok_or_else(|| anyhow!("finished file size overflow"))?;
        if is_file_backed && new_finished_size > self.total_size {
            bail!("transfer exceeds declared total size");
        }
        let wire_len =
            u64::try_from(block.data.len()).map_err(|_| anyhow!("wire block length overflow"))?;
        let new_transferred = self
            .transferred
            .checked_add(wire_len)
            .ok_or_else(|| anyhow!("transferred byte count overflow"))?;

        let should_open = is_file_backed
            && (starts_next_file
                || file_num != self.file_num as usize
                || self.data_stream.is_none());
        if should_open {
            if starts_next_file {
                self.finalize_pending_write().await?;
            }
            self.file_num = block.file_num;
            let (base, entry) = match &self.data_source {
                DataSource::FilePath(base) => (base.clone(), self.files[file_num].clone()),
                DataSource::MemoryCursor(_) => bail!("file transfer source changed unexpectedly"),
            };
            if self.r#type == JobType::Printer {
                self.data_stream = Some(DataStream::FileStream(File::create(base).await?));
            } else {
                let digest = self.digest.clone();
                let name = entry.name;
                let modified_time = entry.modified_time;
                let (file, pending) = tokio::task::spawn_blocking(move || {
                    prepare_new_write(&base, &name, &digest, modified_time)
                })
                .await??;
                self.data_stream = Some(DataStream::FileStream(File::from_std(file)));
                self.pending_write = Some(pending);
            }
        } else if let DataSource::MemoryCursor(cursor) = &self.data_source {
            if self.data_stream.is_none() {
                self.data_stream = Some(DataStream::BufStream(TokioBufStream::new(cursor.clone())));
            }
        }
        self.data_stream
            .as_mut()
            .ok_or(anyhow!("file is None"))?
            .write_all(&payload)
            .await?;
        self.finished_size = new_finished_size;
        self.transferred = new_transferred;
        self.write_progress = WriteProgress {
            file_num: block.file_num,
            bytes_written: new_file_size,
            next_block_id,
            eof_seen,
        };
        Ok(())
    }

    #[inline]
    pub fn join(p: &Path, name: &str) -> PathBuf {
        if name.is_empty() {
            p.to_path_buf()
        } else {
            p.join(name)
        }
    }

    /// Open the data stream for the current file.
    /// Returns Ok(true) if job is done, Ok(false) otherwise.
    async fn open_data_stream(&mut self) -> ResultType<bool> {
        self.ensure_not_terminated()?;
        let result = self.open_data_stream_inner().await;
        if let Err(err) = &result {
            self.record_terminal_error(err);
        }
        result
    }

    async fn open_data_stream_inner(&mut self) -> ResultType<bool> {
        let file_num =
            usize::try_from(self.file_num).map_err(|_| anyhow!("wrong initial file number"))?;
        match &mut self.data_source {
            DataSource::FilePath(p) => {
                if file_num >= self.files.len() {
                    // job done
                    self.data_stream.take();
                    return Ok(true);
                };
                if self.data_stream.is_none() {
                    match File::open(Self::join(p, &self.files[file_num].name)).await {
                        Ok(file) => {
                            self.data_stream = Some(DataStream::FileStream(file));
                            self.file_confirmed = false;
                            self.file_is_waiting = false;
                        }
                        Err(err) => {
                            self.file_confirmed = false;
                            self.file_is_waiting = false;
                            return Err(err.into());
                        }
                    }
                }
            }
            DataSource::MemoryCursor(c) => {
                if self.data_stream.is_none() {
                    let mut t = std::io::Cursor::new(Vec::new());
                    std::mem::swap(&mut t, c);
                    self.data_stream = Some(DataStream::BufStream(TokioBufStream::new(t)));
                }
            }
        }
        Ok(false)
    }

    /// Get current file's digest (last_modified, file_size) for overwrite detection.
    async fn get_current_digest(&self) -> ResultType<(u64, u64)> {
        let meta = match self.data_stream.as_ref().ok_or(anyhow!("file is None"))? {
            DataStream::FileStream(file) => file.metadata().await?,
            DataStream::BufStream(_) => bail!("No digest for buf stream"),
        };
        let last_modified = meta
            .modified()?
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs();
        Ok((last_modified, meta.len()))
    }

    async fn init_data_stream(&mut self, stream: &mut crate::Stream) -> ResultType<()> {
        self.ensure_not_terminated()?;
        let result = self.init_data_stream_inner(stream).await;
        if let Err(err) = &result {
            self.record_terminal_error(err);
        }
        result
    }

    async fn init_data_stream_inner(&mut self, stream: &mut crate::Stream) -> ResultType<()> {
        if self.open_data_stream().await? {
            return Ok(());
        }
        if self.r#type == JobType::Generic
            && self.enable_overwrite_detection
            && !self.file_confirmed()
            && !self.file_is_waiting()
        {
            self.send_current_digest(stream).await?;
            self.set_file_is_waiting(true);
        }
        Ok(())
    }

    /// Initialize data stream for CM (Connection Manager) scenario.
    /// Returns digest info (last_modified, file_size) if overwrite detection is enabled,
    /// so caller can send it via IPC instead of network stream.
    /// Returns Ok(None) if job is done or already initialized.
    pub async fn init_data_stream_for_cm(&mut self) -> ResultType<Option<(u64, u64)>> {
        self.ensure_not_terminated()?;
        let result = self.init_data_stream_for_cm_inner().await;
        if let Err(err) = &result {
            self.record_terminal_error(err);
        }
        result
    }

    async fn init_data_stream_for_cm_inner(&mut self) -> ResultType<Option<(u64, u64)>> {
        if self.open_data_stream().await? {
            return Ok(None);
        }
        // For overwrite detection, return digest info instead of sending via stream
        if self.r#type == JobType::Generic
            && self.enable_overwrite_detection
            && !self.file_confirmed()
            && !self.file_is_waiting()
        {
            let digest = self.get_current_digest().await?;
            self.set_file_is_waiting(true);
            return Ok(Some(digest));
        }
        Ok(None)
    }

    pub async fn read(&mut self) -> ResultType<Option<FileTransferBlock>> {
        self.ensure_not_terminated()?;
        let result = self.read_block().await;
        if let Err(err) = &result {
            self.record_terminal_error(err);
        }
        result
    }

    async fn read_block(&mut self) -> ResultType<Option<FileTransferBlock>> {
        if self.r#type == JobType::Generic
            && self.enable_overwrite_detection
            && !self.file_confirmed()
        {
            return Ok(None);
        }

        let file_num_i32 = self.file_num;
        let file_num = usize::try_from(file_num_i32).map_err(|_| anyhow!("wrong file number"))?;
        let block_id = self.next_read_block_id;
        let name = match &self.data_source {
            DataSource::FilePath(p) => {
                if file_num >= self.files.len() {
                    self.data_stream.take();
                    return Ok(None);
                };
                if self.files.len() == 1 && self.files[file_num].name.is_empty() {
                    p.file_name()
                        .map(|p| p.to_str().unwrap_or(""))
                        .unwrap_or("")
                } else {
                    &self.files[file_num].name
                }
            }
            DataSource::MemoryCursor(..) => "",
        };
        const BUF_SIZE: usize = 128 * 1024;
        let mut buf: Vec<u8> = vec![0; BUF_SIZE];
        let mut compressed = false;
        let mut offset: usize = 0;
        loop {
            match self
                .data_stream
                .as_mut()
                .ok_or(anyhow!("data stream is None"))?
                .read(&mut buf[offset..])
                .await
            {
                Err(err) => {
                    self.data_stream = None;
                    self.file_confirmed = false;
                    self.file_is_waiting = false;
                    return Err(err.into());
                }
                Ok(n) => {
                    offset += n;
                    if n == 0 || offset == BUF_SIZE {
                        break;
                    }
                }
            }
        }
        unsafe { buf.set_len(offset) };
        if offset == 0 {
            if matches!(self.data_source, DataSource::MemoryCursor(_)) {
                self.data_stream.take();
                return Ok(None);
            }
            self.file_num = self
                .file_num
                .checked_add(1)
                .ok_or_else(|| anyhow!("file number overflow"))?;
            self.data_stream = None;
            self.file_confirmed = false;
            self.file_is_waiting = false;
            self.next_read_block_id = 0;
        } else {
            let offset =
                u64::try_from(offset).map_err(|_| anyhow!("file block length overflow"))?;
            self.finished_size = self
                .finished_size
                .checked_add(offset)
                .ok_or_else(|| anyhow!("finished file size overflow"))?;
            if matches!(self.data_source, DataSource::FilePath(_)) && !is_compressed_file(name) {
                (buf, compressed) = compress_file_block_with(buf, compress);
            }
            let wire_len =
                u64::try_from(buf.len()).map_err(|_| anyhow!("wire block length overflow"))?;
            self.transferred = self
                .transferred
                .checked_add(wire_len)
                .ok_or_else(|| anyhow!("transferred byte count overflow"))?;
            self.next_read_block_id = self
                .next_read_block_id
                .checked_add(1)
                .ok_or_else(|| anyhow!("file block id overflow"))?;
        }
        Ok(Some(FileTransferBlock {
            id: self.id,
            file_num: file_num_i32,
            data: buf.into(),
            compressed,
            blk_id: block_id,
            ..Default::default()
        }))
    }

    // Only for generic job and file stream
    async fn send_current_digest(&mut self, stream: &mut Stream) -> ResultType<()> {
        let (last_modified, file_size) = self.get_current_digest().await?;
        let mut msg = Message::new();
        let mut resp = FileResponse::new();
        resp.set_digest(FileTransferDigest {
            id: self.id,
            file_num: self.file_num,
            last_modified,
            file_size,
            is_resume: self.is_resume,
            ..Default::default()
        });
        msg.set_file_response(resp);
        stream.send(&msg).await?;
        log::info!(
            "id: {}, file_num: {}, digest message is sent. waiting for confirm. msg: {:?}",
            self.id,
            self.file_num,
            msg
        );
        Ok(())
    }

    pub fn set_overwrite_strategy(&mut self, overwrite_strategy: Option<bool>) {
        self.default_overwrite_strategy = overwrite_strategy;
    }

    pub fn default_overwrite_strategy(&self) -> Option<bool> {
        self.default_overwrite_strategy
    }

    pub fn set_file_confirmed(&mut self, file_confirmed: bool) {
        log::info!("id: {}, file_confirmed: {}", self.id, file_confirmed);
        self.file_confirmed = file_confirmed;
        self.file_skipped = false;
    }

    pub fn set_file_is_waiting(&mut self, file_is_waiting: bool) {
        self.file_is_waiting = file_is_waiting;
    }

    #[inline]
    pub fn file_is_waiting(&self) -> bool {
        self.file_is_waiting
    }

    #[inline]
    pub fn file_confirmed(&self) -> bool {
        self.file_confirmed
    }

    /// Indicating whether the last file is skipped
    #[inline]
    pub fn file_skipped(&self) -> bool {
        self.file_skipped
    }

    /// Indicating whether the whole task is skipped
    #[inline]
    pub fn job_skipped(&self) -> bool {
        self.file_skipped() && self.files.len() == 1
    }

    /// Check whether the job is completed after `read` returns `None`
    /// This is a helper function which gives additional lifecycle when the job reads `None`.
    /// If returns `true`, it means we can delete the job automatically. `False` otherwise.
    ///
    /// [`Note`]
    /// Conditions:
    /// 1. Files are not waiting for confirmation by peers.
    #[inline]
    pub fn job_completed(&self) -> bool {
        self.terminal_error.is_none()
            && (!self.enable_overwrite_detection || (!self.file_confirmed && !self.file_is_waiting))
    }

    /// Get job error message, useful for getting status when job had finished
    pub fn job_error(&self) -> Option<String> {
        if let Some(err) = self.terminal_error.as_ref() {
            return Some(err.clone());
        }
        if self.job_skipped() {
            return Some("skipped".to_string());
        }
        None
    }

    pub fn set_file_skipped(&mut self) -> bool {
        if self.terminal_error.is_some() {
            return false;
        }
        if self.pending_write.is_some() {
            self.terminal_error = Some("cannot skip a file after writing has started".to_string());
            return false;
        }
        let Some(next_file_num) = self.file_num.checked_add(1) else {
            self.terminal_error = Some("file number overflow while skipping".to_string());
            return false;
        };
        log::debug!("skip file {} in job {}", self.file_num, self.id);
        self.data_stream.take();
        self.set_file_confirmed(false);
        self.set_file_is_waiting(false);
        self.file_num = next_file_num;
        if self.is_read_job {
            self.next_read_block_id = 0;
        } else {
            self.write_progress = WriteProgress::new(next_file_num);
        }
        self.file_skipped = true;
        true
    }

    async fn set_stream_offset(&mut self, file_num: usize, offset: u64) -> ResultType<()> {
        let (base, entry) = match &self.data_source {
            DataSource::FilePath(base) => {
                let entry = self
                    .files
                    .get(file_num)
                    .ok_or_else(|| anyhow!("wrong file number for resume"))?;
                (base.clone(), entry.clone())
            }
            DataSource::MemoryCursor(_) => bail!("memory transfers cannot be resumed"),
        };
        if offset > entry.size {
            bail!("resume offset exceeds declared file size");
        }
        let resumed_transferred = self
            .transferred
            .checked_add(offset)
            .ok_or_else(|| anyhow!("transferred byte count overflow"))?;
        let resumed_finished_size = self
            .finished_size
            .checked_add(offset)
            .ok_or_else(|| anyhow!("finished file size overflow"))?;
        if resumed_finished_size > self.total_size {
            bail!("resume offset exceeds declared total size");
        }
        if self.is_read_job {
            let path = Self::join(&base, &entry.name);
            let mut file = File::open(&path).await?;
            if offset > file.metadata().await?.len() {
                bail!("resume offset exceeds source file length");
            }
            let position = file.seek(std::io::SeekFrom::Start(offset)).await?;
            if position != offset {
                bail!("source resume seek returned the wrong position");
            }
            self.data_stream = Some(DataStream::FileStream(file));
            self.transferred = resumed_transferred;
            self.finished_size = resumed_finished_size;
            self.next_read_block_id = 0;
            return Ok(());
        }
        let digest = self.digest.clone();
        let name = entry.name;
        let modified_time = entry.modified_time;
        let (file, pending) = tokio::task::spawn_blocking(move || {
            open_resumed_write(&base, &name, &digest, modified_time)
        })
        .await??;
        let file_len = file.metadata()?.len();
        if offset > file_len {
            bail!("resume offset exceeds temporary file length");
        }
        let mut file = File::from_std(file);
        file.set_len(offset).await?;
        let position = file.seek(std::io::SeekFrom::Start(offset)).await?;
        if position != offset {
            bail!("destination resume seek returned the wrong position");
        }
        self.data_stream = Some(DataStream::FileStream(file));
        self.pending_write = Some(pending);
        self.transferred = resumed_transferred;
        self.finished_size = resumed_finished_size;
        self.file_num = i32::try_from(file_num).map_err(|_| anyhow!("wrong file number"))?;
        self.write_progress = WriteProgress {
            file_num: self.file_num,
            bytes_written: offset,
            next_block_id: 0,
            eof_seen: false,
        };
        Ok(())
    }

    pub async fn confirm(&mut self, r: &FileTransferSendConfirmRequest) -> bool {
        if self.ensure_not_terminated().is_err() {
            return false;
        }
        if self.file_num() != r.file_num {
            // This branch will always be hit if:
            // 1. `confirm()` is called in `ui_cm_interface.rs`
            // 2. Not resuming
            //
            // It is ok. Because `confirm()` in `ui_cm_interface.rs` is only used for resuming.
            log::info!("file num truncated, ignoring");
        } else {
            match r.union {
                Some(file_transfer_send_confirm_request::Union::Skip(s)) => {
                    if s {
                        self.set_file_skipped();
                    } else {
                        self.set_file_confirmed(true);
                    }
                }
                Some(file_transfer_send_confirm_request::Union::OffsetBytes(offset)) => {
                    self.set_file_confirmed(true);
                    // If offset is greater than 0, we need to seek to the offset
                    if offset > 0 {
                        if let Err(err) = self.set_stream_offset(r.file_num as usize, offset).await
                        {
                            log::warn!("Failed to resume file transfer: {err}");
                            self.record_terminal_error(&err);
                            return false;
                        }
                    }
                }
                _ => {}
            }
        }
        true
    }

    #[inline]
    pub fn gen_meta(&self) -> TransferJobMeta {
        TransferJobMeta {
            id: self.id,
            remote: self.remote.to_string(),
            to: self.data_source.to_meta(),
            file_num: self.file_num,
            show_hidden: self.show_hidden,
            is_remote: self.is_remote,
        }
    }
}

#[inline]
pub fn new_error<T: std::string::ToString>(id: i32, err: T, file_num: i32) -> Message {
    new_file_error(
        id,
        err,
        file_num,
        String::new(),
        FileErrorOperation::Transfer,
    )
}

#[inline]
pub fn new_listing_error<T: std::string::ToString>(
    path: String,
    err: T,
    operation: FileErrorOperation,
) -> Message {
    new_file_error(0, err, -1, path, operation)
}

fn new_file_error<T: std::string::ToString>(
    id: i32,
    err: T,
    file_num: i32,
    path: String,
    operation: FileErrorOperation,
) -> Message {
    let mut resp = FileResponse::new();
    resp.set_error(FileTransferError {
        id,
        error: err.to_string(),
        file_num,
        path,
        operation: operation.into(),
        ..Default::default()
    });
    let mut msg_out = Message::new();
    msg_out.set_file_response(resp);
    msg_out
}

#[inline]
pub fn new_dir(id: i32, path: String, files: Vec<FileEntry>) -> Message {
    let mut resp = FileResponse::new();
    resp.set_dir(FileDirectory {
        id,
        path,
        entries: files,
        ..Default::default()
    });
    let mut msg_out = Message::new();
    msg_out.set_file_response(resp);
    msg_out
}

#[inline]
pub fn new_block(block: FileTransferBlock) -> Message {
    let mut resp = FileResponse::new();
    resp.set_block(block);
    let mut msg_out = Message::new();
    msg_out.set_file_response(resp);
    msg_out
}

#[inline]
pub fn new_send_confirm(r: FileTransferSendConfirmRequest) -> Message {
    let mut msg_out = Message::new();
    let mut action = FileAction::new();
    action.set_send_confirm(r);
    msg_out.set_file_action(action);
    msg_out
}

#[inline]
pub fn new_receive(
    id: i32,
    path: String,
    file_num: i32,
    files: Vec<FileEntry>,
    total_size: u64,
) -> Message {
    let mut action = FileAction::new();
    action.set_receive(FileTransferReceiveRequest {
        id,
        path,
        files,
        file_num,
        total_size,
        ..Default::default()
    });
    let mut msg_out = Message::new();
    msg_out.set_file_action(action);
    msg_out
}

#[inline]
pub fn new_send(
    id: i32,
    r#type: JobType,
    path: String,
    file_num: i32,
    include_hidden: bool,
) -> Message {
    log::info!("new send: {}, id: {}", path, id);
    let mut action = FileAction::new();
    let t: file_transfer_send_request::FileType = r#type.into();
    action.set_send(FileTransferSendRequest {
        id,
        path,
        include_hidden,
        file_num,
        file_type: t.into(),
        ..Default::default()
    });
    let mut msg_out = Message::new();
    msg_out.set_file_action(action);
    msg_out
}

#[inline]
pub fn new_done(id: i32, file_num: i32) -> Message {
    let mut resp = FileResponse::new();
    resp.set_done(FileTransferDone {
        id,
        file_num,
        ..Default::default()
    });
    let mut msg_out = Message::new();
    msg_out.set_file_response(resp);
    msg_out
}

#[inline]
pub fn remove_job(id: i32, jobs: &mut Vec<TransferJob>) -> Option<TransferJob> {
    jobs.iter()
        .position(|x| x.id() == id)
        .map(|index| jobs.remove(index))
}

#[inline]
pub fn get_job(id: i32, jobs: &mut [TransferJob]) -> Option<&mut TransferJob> {
    jobs.iter_mut().find(|x| x.id() == id)
}

#[inline]
pub fn get_job_immutable(id: i32, jobs: &[TransferJob]) -> Option<&TransferJob> {
    jobs.iter().find(|x| x.id() == id)
}

async fn init_jobs(
    jobs: &mut [TransferJob],
    stream: &mut crate::Stream,
) -> ResultType<Vec<(i32, String)>> {
    let mut failed = Vec::new();
    for job in jobs.iter_mut() {
        if job.is_last_job {
            continue;
        }
        if let Err(err) = job.init_data_stream(stream).await {
            job.record_terminal_error(&err);
            let error = job.job_error().unwrap_or_else(|| err.to_string());
            stream
                .send(&new_error(job.id(), &error, job.file_num()))
                .await?;
            failed.push((job.id(), error));
        }
    }
    Ok(failed)
}

pub async fn handle_read_jobs(
    jobs: &mut Vec<TransferJob>,
    stream: &mut crate::Stream,
) -> ResultType<String> {
    let mut job_log = Default::default();
    for (id, error) in init_jobs(jobs, stream).await? {
        if let Some(job) = remove_job(id, jobs) {
            job_log = serialize_transfer_job(&job, false, false, &error);
        }
    }
    let mut finished = Vec::new();
    for job in jobs.iter_mut() {
        if job.is_last_job {
            continue;
        }
        match job.read().await {
            Err(err) => {
                let error = job.job_error().unwrap_or_else(|| err.to_string());
                job_log = serialize_transfer_job(job, false, false, &error);
                finished.push(job.id());
                stream
                    .send(&new_error(job.id(), error, job.file_num()))
                    .await?;
            }
            Ok(Some(block)) => {
                stream.send(&new_block(block)).await?;
            }
            Ok(None) => {
                if job.job_completed() {
                    job_log = serialize_transfer_job(job, true, false, "");
                    finished.push(job.id());
                    match job.job_error() {
                        Some(err) => {
                            job_log = serialize_transfer_job(job, false, false, &err);
                            stream
                                .send(&new_error(job.id(), err, job.file_num()))
                                .await?
                        }
                        None => stream.send(&new_done(job.id(), job.file_num())).await?,
                    }
                } else {
                    // waiting confirmation.
                }
            }
        }
        // Break to handle jobs one by one.
        break;
    }
    for id in finished {
        let _ = remove_job(id, jobs);
    }
    Ok(job_log)
}

fn remove_entry_or_ignore_not_found(
    path: &Path,
    remove: impl FnOnce() -> std::io::Result<()>,
) -> ResultType<()> {
    match remove() {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("failed to remove {}", path.display())),
    }
}

fn remove_open_empty_dir(directory: Dir, path: &Path) -> ResultType<()> {
    {
        let entries = directory
            .entries()
            .with_context(|| format!("failed to read directory {}", path.display()))?;
        for entry in entries {
            let entry = entry.with_context(|| {
                format!("failed to read an entry in directory {}", path.display())
            })?;
            let name = entry.file_name();
            let entry_path = path.join(&name);
            let metadata = match directory.symlink_metadata(&name) {
                Ok(metadata) => metadata,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                Err(err) => {
                    return Err(err).with_context(|| {
                        format!("failed to read metadata for {}", entry_path.display())
                    });
                }
            };
            if metadata.file_type().is_symlink() {
                remove_entry_or_ignore_not_found(&entry_path, || {
                    directory.remove_file_or_symlink(&name)
                })?;
            } else if metadata.is_dir() {
                let child = match directory.open_dir_nofollow(&name) {
                    Ok(child) => child,
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(err) => {
                        return Err(err).with_context(|| {
                            format!("failed to open directory {}", entry_path.display())
                        });
                    }
                };
                remove_open_empty_dir(child, &entry_path)?;
            }
        }
    }
    remove_entry_or_ignore_not_found(path, || directory.remove_open_dir())
}

fn remove_symlink_root(path: &Path) -> ResultType<()> {
    let name = path
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| anyhow!("symbolic link path has no file name: {}", path.display()))?;
    let parent_path = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = open_ambient_directory_nofollow(parent_path, false)
        .with_context(|| format!("failed to open parent directory for {}", path.display()))?;
    match parent.symlink_metadata(name) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            remove_entry_or_ignore_not_found(path, || parent.remove_file_or_symlink(name))
        }
        Ok(_) => bail!(
            "recursive removal root changed from a symbolic link: {}",
            path.display()
        ),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => {
            Err(err).with_context(|| format!("failed to read metadata for {}", path.display()))
        }
    }
}

pub fn remove_all_empty_dir(path: &Path) -> ResultType<()> {
    match open_ambient_directory_nofollow(path, false) {
        Ok(directory) => remove_open_empty_dir(directory, path),
        Err(open_err) => match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() => remove_symlink_root(path),
            Ok(_) => Err(open_err)
                .with_context(|| format!("failed to open directory {}", path.display())),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => {
                Err(err).with_context(|| format!("failed to read metadata for {}", path.display()))
            }
        },
    }
}

#[inline]
pub fn remove_file(file: &str) -> ResultType<()> {
    validate_fs_path_argument(file, "file path")?;
    std::fs::remove_file(get_path(file))?;
    Ok(())
}

#[inline]
pub fn create_dir(dir: &str) -> ResultType<()> {
    validate_fs_path_argument(dir, "directory path")?;
    std::fs::create_dir_all(get_path(dir))?;
    Ok(())
}

#[inline]
pub fn rename_file(path: &str, new_name: &str) -> ResultType<()> {
    validate_fs_path_argument(path, "path")?;
    if new_name.is_empty() {
        bail!("new file name cannot be empty");
    }
    validate_file_name_no_traversal(new_name)?;
    let path = std::path::Path::new(&path);
    if path.exists() {
        let dir = path
            .parent()
            .ok_or(anyhow!("Parent directoy of {path:?} not exists"))?;
        let new_path = dir.join(new_name);
        std::fs::rename(path, &new_path)?;
        Ok(())
    } else {
        bail!("{path:?} not exists");
    }
}

#[inline]
pub fn transform_windows_path(entries: &mut Vec<FileEntry>) {
    for entry in entries {
        entry.name = entry.name.replace('\\', "/");
    }
}

pub enum DigestCheckResult {
    IsSame,
    NeedConfirm(FileTransferDigest),
    NoSuchFile,
}

#[inline]
pub fn is_write_need_confirmation(
    is_resume: bool,
    file_path: &str,
    digest: &FileTransferDigest,
) -> ResultType<DigestCheckResult> {
    let (parent, final_name) = match open_destination_parent(Path::new(file_path), "", false) {
        Ok(location) => location,
        Err(err)
            if err
                .downcast_ref::<std::io::Error>()
                .is_some_and(|err| err.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(DigestCheckResult::NoSuchFile);
        }
        Err(err) => return Err(err),
    };
    if is_resume {
        let digest_name = append_suffix(&final_name, ".digest");
        if let Some(local_digest) = read_digest(&parent, &digest_name)? {
            let is_identical = local_digest.modified == digest.last_modified
                && local_digest.size == digest.file_size;
            if is_identical {
                validate_download_temp_name(&local_digest.temp_name)?;
                let download =
                    parent.open_with(&local_digest.temp_name, &nofollow_read_options())?;
                let download_metadata = download.metadata()?;
                if !download_metadata.is_file() {
                    bail!("transfer temporary path is not a regular file");
                }
                let transferred_size = download_metadata.len();
                if transferred_size > 0 {
                    return Ok(DigestCheckResult::NeedConfirm(FileTransferDigest {
                        id: digest.id,
                        file_num: digest.file_num,
                        last_modified: digest.last_modified,
                        file_size: digest.file_size,
                        is_identical,
                        transferred_size,
                        ..Default::default()
                    }));
                }
            }
        }
    }

    match parent.symlink_metadata(&final_name) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            bail!("destination file is a symbolic link")
        }
        Ok(metadata) if metadata.is_file() => {
            let modified_time = metadata.modified()?;
            let remote_mt = Duration::from_secs(digest.last_modified);
            let local_mt = modified_time.into_std().duration_since(UNIX_EPOCH)?;
            // [Note]
            // We decide to give the decision whether to override the existing file to users,
            // which obey the behavior of the file manager in our system.
            let mut is_identical = false;
            if remote_mt == local_mt && digest.file_size == metadata.len() {
                is_identical = true;
            }
            Ok(DigestCheckResult::NeedConfirm(FileTransferDigest {
                id: digest.id,
                file_num: digest.file_num,
                last_modified: local_mt.as_secs(),
                file_size: metadata.len(),
                is_identical,
                ..Default::default()
            }))
        }
        Ok(_) => Ok(DigestCheckResult::NoSuchFile),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(DigestCheckResult::NoSuchFile),
        Err(err) => Err(err.into()),
    }
}

pub fn serialize_transfer_jobs(jobs: &[TransferJob]) -> String {
    let mut v = vec![];
    for job in jobs {
        let value = serde_json::to_value(job).unwrap_or_default();
        v.push(value);
    }
    serde_json::to_string(&v).unwrap_or_default()
}

pub fn serialize_transfer_job(job: &TransferJob, done: bool, cancel: bool, error: &str) -> String {
    let mut value = serde_json::to_value(job).unwrap_or_default();
    value["done"] = json!(done);
    value["cancel"] = json!(cancel);
    value["error"] = json!(error);
    serde_json::to_string(&value).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compress::decompress;
    use protobuf::Message as _;

    #[test]
    fn file_transfer_protocol_version_requires_an_exact_match() {
        assert!(validate_file_transfer_protocol_version(FILE_TRANSFER_PROTOCOL_VERSION).is_ok());
        for unsupported in [0, 1, FILE_TRANSFER_PROTOCOL_VERSION + 1] {
            assert!(validate_file_transfer_protocol_version(unsupported).is_err());
        }

        let login = LoginRequest {
            file_transfer_protocol_version: FILE_TRANSFER_PROTOCOL_VERSION,
            ..Default::default()
        };
        let login = LoginRequest::parse_from_bytes(
            &login
                .write_to_bytes()
                .expect("serialize login file transfer capability"),
        )
        .expect("parse login file transfer capability");
        assert_eq!(
            login.file_transfer_protocol_version,
            FILE_TRANSFER_PROTOCOL_VERSION
        );

        let peer_info = PeerInfo {
            file_transfer_protocol_version: FILE_TRANSFER_PROTOCOL_VERSION,
            ..Default::default()
        };
        let peer_info = PeerInfo::parse_from_bytes(
            &peer_info
                .write_to_bytes()
                .expect("serialize peer file transfer capability"),
        )
        .expect("parse peer file transfer capability");
        assert_eq!(
            peer_info.file_transfer_protocol_version,
            FILE_TRANSFER_PROTOCOL_VERSION
        );
    }

    #[test]
    fn directory_listing_error_wire_round_trips_operation_and_path() {
        let message = new_listing_error(
            "/requested/path".to_owned(),
            "permission denied",
            FileErrorOperation::ReadEmptyDirs,
        );
        let message = Message::parse_from_bytes(
            &message
                .write_to_bytes()
                .expect("serialize structured directory error"),
        )
        .expect("parse structured directory error");
        let error = message.file_response().error();

        assert_eq!(error.id, 0);
        assert_eq!(error.file_num, -1);
        assert_eq!(error.path, "/requested/path");
        assert_eq!(error.error, "permission denied");
        assert_eq!(
            error.operation.enum_value(),
            Ok(FileErrorOperation::ReadEmptyDirs)
        );
    }

    struct TestTempDir {
        path: PathBuf,
        _owner: tempfile::TempDir,
    }

    impl TestTempDir {
        fn new(prefix: &str) -> Self {
            let owner = tempfile::Builder::new()
                .prefix(prefix)
                .tempdir()
                .expect("create owned test directory");
            Self {
                path: owner.path().to_path_buf(),
                _owner: owner,
            }
        }

        fn join(&self, path: &str) -> PathBuf {
            self.path.join(path)
        }
    }

    fn new_file_entry(name: &str) -> FileEntry {
        let mut entry = FileEntry::new();
        entry.name = name.to_string();
        entry
    }

    fn new_validation_job(id: i32) -> TransferJob {
        TransferJob::new_write(
            id,
            JobType::Generic,
            "/fake/remote".to_string(),
            DataSource::FilePath(std::env::temp_dir().join(format!("rustdesk_validation_{id}"))),
            0,
            false,
            true,
            false,
        )
    }

    fn new_write_job(id: i32, download_dir: PathBuf, name: &str) -> ResultType<TransferJob> {
        let mut entry = new_file_entry(name);
        entry.size = u64::MAX;
        let job = TransferJob::new_write(
            id,
            JobType::Generic,
            "/fake/remote".to_string(),
            DataSource::FilePath(download_dir),
            0,
            false,
            true,
            false,
        )
        .with_files(vec![entry])?;
        Ok(job)
    }

    fn new_sized_write_job(
        id: i32,
        download_dir: PathBuf,
        files: &[(&str, u64)],
    ) -> ResultType<TransferJob> {
        let entries = files
            .iter()
            .map(|(name, size)| {
                let mut entry = new_file_entry(name);
                entry.size = *size;
                entry
            })
            .collect();
        TransferJob::new_write(
            id,
            JobType::Generic,
            "/fake/remote".to_string(),
            DataSource::FilePath(download_dir),
            0,
            false,
            true,
            false,
        )
        .with_files(entries)
    }

    fn transfer_block(id: i32, file_num: i32, data: &[u8]) -> FileTransferBlock {
        FileTransferBlock {
            id,
            file_num,
            data: data.to_vec().into(),
            ..Default::default()
        }
    }

    fn sequenced_block(
        id: i32,
        file_num: i32,
        block_id: u32,
        data: &[u8],
        compressed: bool,
    ) -> FileTransferBlock {
        FileTransferBlock {
            id,
            file_num,
            blk_id: block_id,
            data: data.to_vec().into(),
            compressed,
            ..Default::default()
        }
    }

    fn transfer_digest(id: i32, file_size: u64, last_modified: u64) -> FileTransferDigest {
        FileTransferDigest {
            id,
            file_num: 0,
            file_size,
            last_modified,
            ..Default::default()
        }
    }

    fn stored_digest(downloads: &Path, name: &str) -> FileDigest {
        let content = std::fs::read_to_string(downloads.join(format!("{name}.digest")))
            .expect("read stored transfer digest");
        serde_json::from_str(&content).expect("parse stored transfer digest")
    }

    #[cfg(unix)]
    fn create_test_file_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
        std::os::unix::fs::symlink(target, link)
    }

    #[cfg(windows)]
    fn create_test_file_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
        std::os::windows::fs::symlink_file(target, link)
    }

    #[cfg(unix)]
    fn create_test_dir_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
        std::os::unix::fs::symlink(target, link)
    }

    #[cfg(windows)]
    fn create_test_dir_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
        std::os::windows::fs::symlink_dir(target, link)
    }

    fn assert_err_contains(err: anyhow::Error, expected: &str) {
        assert!(
            err.to_string().contains(expected),
            "expected error containing '{}', got: {}",
            expected,
            err
        );
    }

    #[test]
    fn path_traversal_e2e_write_rejects_relative_escape() {
        let tmp_root = TestTempDir::new("rustdesk_e2e_relative");
        let downloads = tmp_root.join("downloads");
        std::fs::create_dir_all(&downloads).expect("create downloads dir");

        let err = new_write_job(1, downloads, "../traversal_proof.txt")
            .expect_err("relative path traversal must be rejected");
        assert_err_contains(err, "path traversal");
        assert!(!tmp_root.join("traversal_proof.txt").exists());
    }

    #[test]
    fn path_traversal_e2e_write_rejects_absolute_path() {
        let tmp_root = TestTempDir::new("rustdesk_e2e_absolute");
        let downloads = tmp_root.join("downloads");
        let absolute_target = tmp_root.join("fake_ssh").join("authorized_keys");
        std::fs::create_dir_all(&downloads).expect("create downloads dir");

        let err = new_write_job(2, downloads, &absolute_target.to_string_lossy())
            .expect_err("absolute path must be rejected");
        assert_err_contains(err, "absolute path");
        assert!(!absolute_target.exists());
    }

    #[test]
    #[cfg_attr(windows, ignore = "requires symlink privilege to create test symlink")]
    fn path_traversal_e2e_write_rejects_symlink_escape() {
        let tmp_root = TestTempDir::new("rustdesk_e2e_symlink");
        let downloads = tmp_root.join("downloads");
        let outside = tmp_root.join("outside");
        let escaped_target = outside.join("escape.txt");
        std::fs::create_dir_all(&downloads).expect("create downloads dir");
        std::fs::create_dir_all(&outside).expect("create outside dir");

        let symlink_path = downloads.join("link");
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            symlink(&outside, &symlink_path).expect("create symlink for test");
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::symlink_dir;
            symlink_dir(&outside, &symlink_path).expect("create directory symlink for test");
        }

        let err = new_write_job(3, downloads, "link/escape.txt")
            .expect_err("symlink traversal must be rejected");
        assert_err_contains(err, "symlink");
        assert!(!escaped_target.exists());
    }

    #[cfg(any(unix, windows))]
    #[cfg_attr(windows, ignore = "requires Windows symbolic-link privilege")]
    #[tokio::test]
    async fn write_does_not_follow_preexisting_download_symlink() {
        let tmp_root = TestTempDir::new("camellia_download_symlink");
        let downloads = tmp_root.join("downloads");
        let sentinel = tmp_root.join("sentinel.txt");
        std::fs::create_dir_all(downloads.join("report.txt"))
            .expect("create destination directory which prevents legacy finalize");
        std::fs::write(&sentinel, b"sentinel must remain unchanged")
            .expect("create external sentinel");
        create_test_file_symlink(&sentinel, &downloads.join("report.txt.download"))
            .expect("create malicious download symlink");

        let mut job = new_write_job(106, downloads, "report.txt").expect("create write job");
        let result = job
            .write(FileTransferBlock {
                id: 106,
                file_num: 0,
                data: b"attacker-controlled payload".to_vec().into(),
                ..Default::default()
            })
            .await;

        assert_eq!(
            std::fs::read(&sentinel).expect("read external sentinel"),
            b"sentinel must remain unchanged"
        );
        assert!(result.is_err(), "a directory destination must be rejected");
    }

    #[cfg(any(unix, windows))]
    #[cfg_attr(windows, ignore = "requires Windows symbolic-link privilege")]
    #[tokio::test]
    async fn write_rejects_parent_symlink_added_after_file_list_validation() {
        let tmp_root = TestTempDir::new("camellia_parent_symlink_swap");
        let downloads = tmp_root.join("downloads");
        let outside = tmp_root.join("outside");
        std::fs::create_dir_all(&downloads).expect("create downloads directory");
        std::fs::create_dir_all(&outside).expect("create outside directory");
        let mut job =
            new_write_job(107, downloads.clone(), "nested/report.txt").expect("create write job");
        create_test_dir_symlink(&outside, &downloads.join("nested"))
            .expect("swap parent for a symlink");

        let result = job.write(transfer_block(107, 0, b"payload")).await;

        assert!(
            result.is_err(),
            "a symlink parent must be rejected at open time"
        );
        assert!(!outside.join("report.txt").exists());
        assert!(std::fs::read_dir(&outside)
            .expect("read outside directory")
            .next()
            .is_none());
    }

    #[cfg(any(unix, windows))]
    #[cfg_attr(windows, ignore = "requires Windows symbolic-link privilege")]
    #[tokio::test]
    async fn write_rejects_destination_root_swapped_for_symlink() {
        let tmp_root = TestTempDir::new("camellia_destination_root_swap");
        let downloads = tmp_root.join("downloads");
        let original_downloads = tmp_root.join("original-downloads");
        let outside = tmp_root.join("outside");
        std::fs::create_dir_all(&downloads).expect("create downloads directory");
        std::fs::create_dir_all(&outside).expect("create outside directory");
        let mut job =
            new_write_job(115, downloads.clone(), "report.txt").expect("create write job");
        std::fs::rename(&downloads, &original_downloads).expect("move authorized directory");
        create_test_dir_symlink(&outside, &downloads)
            .expect("replace destination root with symlink");

        let result = job.write(transfer_block(115, 0, b"payload")).await;

        assert!(
            result.is_err(),
            "a replaced destination root must be rejected at open time"
        );
        assert!(std::fs::read_dir(&outside)
            .expect("read outside directory")
            .next()
            .is_none());
        assert!(std::fs::read_dir(&original_downloads)
            .expect("read original destination directory")
            .next()
            .is_none());
    }

    #[tokio::test]
    async fn write_uses_unique_same_directory_temp_and_commits_atomically() {
        let tmp_root = TestTempDir::new("camellia_atomic_commit");
        let downloads = tmp_root.join("downloads");
        std::fs::create_dir_all(&downloads).expect("create downloads directory");
        std::fs::write(downloads.join("report.txt"), b"old contents")
            .expect("create old destination");
        let mut job = new_sized_write_job(108, downloads.clone(), &[("report.txt", 11)])
            .expect("create write job");
        job.files[0].modified_time = 1_700_000_000;
        job.set_digest(11, 1_700_000_000);

        job.write(transfer_block(108, 0, b"new payload"))
            .await
            .expect("write transfer payload");
        job.write(sequenced_block(108, 0, 1, b"", false))
            .await
            .expect("finish transfer payload");

        assert_eq!(
            std::fs::read(downloads.join("report.txt")).expect("read pre-commit destination"),
            b"old contents"
        );
        assert!(!downloads.join("report.txt.download").exists());
        let digest = stored_digest(&downloads, "report.txt");
        validate_download_temp_name(&digest.temp_name).expect("validate random temp name");
        assert!(downloads.join(&digest.temp_name).is_file());

        job.modify_time().await.expect("commit transfer");

        assert_eq!(
            std::fs::read(downloads.join("report.txt")).expect("read committed destination"),
            b"new payload"
        );
        assert!(!downloads.join(&digest.temp_name).exists());
        assert!(!downloads.join("report.txt.digest").exists());
    }

    #[tokio::test]
    async fn resume_reopens_only_recorded_regular_temp_without_truncation() {
        let tmp_root = TestTempDir::new("camellia_secure_resume");
        let downloads = tmp_root.join("downloads");
        std::fs::create_dir_all(&downloads).expect("create downloads directory");
        let modified = 1_700_000_001;
        let mut first = new_sized_write_job(109, downloads.clone(), &[("report.txt", 6)])
            .expect("create first job");
        first.files[0].modified_time = modified;
        first.set_digest(6, modified);
        first
            .write(transfer_block(109, 0, b"abc"))
            .await
            .expect("write first transfer segment");
        if let Some(DataStream::FileStream(file)) = first.data_stream.as_mut() {
            file.sync_all()
                .await
                .expect("settle partial transfer bytes");
        }
        let first_digest = stored_digest(&downloads, "report.txt");
        drop(first);
        assert_eq!(first_digest.size, 6);
        assert_eq!(first_digest.modified, modified);
        assert_eq!(
            std::fs::metadata(downloads.join(&first_digest.temp_name))
                .expect("inspect partial transfer")
                .len(),
            3
        );

        let digest = transfer_digest(110, 6, modified);
        let confirmation =
            is_write_need_confirmation(true, &get_string(&downloads.join("report.txt")), &digest)
                .expect("inspect resumable transfer");
        let DigestCheckResult::NeedConfirm(confirmation) = confirmation else {
            panic!("regular partial transfer must request resume confirmation");
        };
        assert_eq!(confirmation.transferred_size, 3);

        let mut resumed = new_sized_write_job(110, downloads.clone(), &[("report.txt", 6)])
            .expect("create resumed job");
        resumed.files[0].modified_time = modified;
        resumed.set_digest(6, modified);
        assert!(
            resumed
                .confirm(&FileTransferSendConfirmRequest {
                    id: 110,
                    file_num: 0,
                    union: Some(file_transfer_send_confirm_request::Union::OffsetBytes(3)),
                    ..Default::default()
                })
                .await,
            "resume open must succeed"
        );
        resumed
            .write(transfer_block(110, 0, b"def"))
            .await
            .expect("append resumed segment");
        resumed
            .write(sequenced_block(110, 0, 1, b"", false))
            .await
            .expect("finish resumed file");
        resumed
            .modify_time()
            .await
            .expect("commit resumed transfer");

        assert_eq!(
            std::fs::read(downloads.join("report.txt")).expect("read resumed destination"),
            b"abcdef"
        );
        assert!(!downloads.join(&first_digest.temp_name).exists());
        assert!(!downloads.join("report.txt.digest").exists());
    }

    #[tokio::test]
    async fn sender_resume_seeks_the_source_file_instead_of_receiver_staging() {
        let tmp_root = TestTempDir::new("camellia_sender_resume");
        let source = tmp_root.join("source.txt");
        std::fs::create_dir_all(&tmp_root.path).expect("create source directory");
        std::fs::write(&source, b"abcdef").expect("create source file");
        let mut job = TransferJob::new_read(
            116,
            JobType::Generic,
            "/fake/remote".to_string(),
            DataSource::FilePath(source),
            0,
            false,
            true,
            false,
        )
        .expect("create sending job");

        job.set_stream_offset(0, 3)
            .await
            .expect("seek sending source");
        let block = job
            .read()
            .await
            .expect("read resumed source")
            .expect("source must yield a block");
        let data = if block.compressed {
            decompress(&block.data).expect("decompress sender block")
        } else {
            block.data.to_vec()
        };

        assert_eq!(data, b"def");
        assert_eq!(block.blk_id, 0);
        assert_eq!(job.finished_size(), 6);
    }

    #[tokio::test]
    async fn cancel_removes_only_owned_temp_and_digest() {
        let tmp_root = TestTempDir::new("camellia_secure_cancel");
        let downloads = tmp_root.join("downloads");
        std::fs::create_dir_all(&downloads).expect("create downloads directory");
        let mut job =
            new_write_job(111, downloads.clone(), "report.txt").expect("create write job");
        job.write(transfer_block(111, 0, b"partial"))
            .await
            .expect("write partial transfer");
        let digest = stored_digest(&downloads, "report.txt");

        job.remove_download_file()
            .await
            .expect("cancel transfer artifacts");

        assert!(!downloads.join(&digest.temp_name).exists());
        assert!(!downloads.join("report.txt.digest").exists());
        assert!(!downloads.join("report.txt").exists());
    }

    #[cfg(any(unix, windows))]
    #[cfg_attr(windows, ignore = "requires Windows symbolic-link privilege")]
    #[tokio::test]
    async fn resume_and_final_commit_reject_symlink_replacements() {
        let tmp_root = TestTempDir::new("camellia_resume_symlink_swap");
        let downloads = tmp_root.join("downloads");
        let sentinel = tmp_root.join("sentinel.txt");
        std::fs::create_dir_all(&downloads).expect("create downloads directory");
        std::fs::write(&sentinel, b"sentinel").expect("create sentinel");
        let modified = 1_700_000_002;
        let malicious_temp = random_sidecar_name(DOWNLOAD_TEMP_PREFIX, DOWNLOAD_TEMP_SUFFIX);
        std::fs::write(
            downloads.join("resume.txt.digest"),
            serde_json::to_vec(&FileDigest {
                size: 8,
                modified,
                temp_name: malicious_temp.clone(),
            })
            .expect("serialize malicious digest"),
        )
        .expect("write malicious digest");
        create_test_file_symlink(&sentinel, &downloads.join(&malicious_temp))
            .expect("replace resume temp with symlink");
        let mut resume_job =
            new_write_job(112, downloads.clone(), "resume.txt").expect("create resume job");
        resume_job.files[0].modified_time = modified;
        resume_job.set_digest(8, modified);

        assert!(
            resume_job.set_stream_offset(0, 1).await.is_err(),
            "resume must reject a symlink temp"
        );
        assert_eq!(
            std::fs::read(&sentinel).expect("read sentinel after resume rejection"),
            b"sentinel"
        );

        let mut commit_job = new_sized_write_job(113, downloads.clone(), &[("commit.txt", 8)])
            .expect("create commit job");
        commit_job
            .write(transfer_block(113, 0, b"new data"))
            .await
            .expect("write commit candidate");
        commit_job
            .write(sequenced_block(113, 0, 1, b"", false))
            .await
            .expect("finish commit candidate");
        create_test_file_symlink(&sentinel, &downloads.join("commit.txt"))
            .expect("replace final target with symlink");

        assert!(
            commit_job.modify_time().await.is_err(),
            "commit must reject a symlink destination"
        );
        assert_eq!(
            std::fs::read(&sentinel).expect("read sentinel after commit rejection"),
            b"sentinel"
        );
    }

    #[cfg(any(unix, windows))]
    #[cfg_attr(windows, ignore = "requires Windows symbolic-link privilege")]
    #[tokio::test]
    async fn digest_symlink_is_replaced_without_following_it() {
        let tmp_root = TestTempDir::new("camellia_digest_symlink");
        let downloads = tmp_root.join("downloads");
        let sentinel = tmp_root.join("sentinel.txt");
        std::fs::create_dir_all(&downloads).expect("create downloads directory");
        std::fs::write(&sentinel, b"sentinel").expect("create sentinel");
        create_test_file_symlink(&sentinel, &downloads.join("report.txt.digest"))
            .expect("create digest symlink");
        let mut job = new_sized_write_job(114, downloads.clone(), &[("report.txt", 7)])
            .expect("create write job");

        job.write(transfer_block(114, 0, b"payload"))
            .await
            .expect("write through atomically replaced digest");
        job.write(sequenced_block(114, 0, 1, b"", false))
            .await
            .expect("finish digest replacement transfer");

        assert_eq!(
            std::fs::read(&sentinel).expect("read digest sentinel"),
            b"sentinel"
        );
        assert!(
            std::fs::symlink_metadata(downloads.join("report.txt.digest"))
                .expect("inspect replaced digest")
                .is_file()
        );
        job.modify_time().await.expect("commit transfer");
    }

    #[test]
    fn set_files_allows_single_empty_name_for_single_file_transfer() {
        let mut job = new_validation_job(101);
        assert!(job.set_files(vec![new_file_entry("")]).is_ok());
    }

    #[test]
    fn set_files_rejects_empty_name_in_multi_file_transfer() {
        let mut job = new_validation_job(102);
        let err = job
            .set_files(vec![new_file_entry(""), new_file_entry("ok.txt")])
            .expect_err("empty name in multi-file transfer must be rejected");
        assert_err_contains(err, "empty file name");
    }

    #[test]
    fn set_files_rejects_null_byte_name() {
        let mut job = new_validation_job(103);
        let err = job
            .set_files(vec![new_file_entry("bad\0name.txt")])
            .expect_err("null byte in file name must be rejected");
        assert_err_contains(err, "null bytes");
    }

    #[test]
    fn set_files_rejects_mixed_entries_when_one_is_traversal() {
        let mut job = new_validation_job(104);
        let err = job
            .set_files(vec![
                new_file_entry("safe/file.txt"),
                new_file_entry("../../escape.txt"),
            ])
            .expect_err("any traversal entry must reject the full file list");
        assert_err_contains(err, "path traversal");
    }

    #[test]
    fn set_files_rejects_total_size_overflow() {
        let mut job = new_validation_job(117);
        let mut original = new_file_entry("original.bin");
        original.size = 7;
        job.set_files(vec![original])
            .expect("set initial valid file list");
        let mut first = new_file_entry("first.bin");
        first.size = u64::MAX;
        let mut second = new_file_entry("second.bin");
        second.size = 1;

        let err = job
            .set_files(vec![first, second])
            .expect_err("declared total size overflow must be rejected");

        assert_err_contains(err, "total size overflow");
        assert_eq!(job.files().len(), 1);
        assert_eq!(job.files()[0].name, "original.bin");
        assert_eq!(job.total_size(), 7);
    }

    #[tokio::test]
    async fn write_rejects_payload_beyond_declared_file_size_before_opening_temp() {
        let tmp_root = TestTempDir::new("camellia_declared_file_budget");
        let downloads = tmp_root.join("downloads");
        std::fs::create_dir_all(&downloads).expect("create downloads directory");
        let mut job = new_sized_write_job(118, downloads.clone(), &[("report.txt", 3)])
            .expect("create sized write job");

        let result = job.write(sequenced_block(118, 0, 0, b"four", false)).await;

        assert!(result.is_err(), "oversized file payload must be rejected");
        assert_eq!(job.finished_size(), 0);
        assert_eq!(job.transferred(), 0);
        assert!(std::fs::read_dir(&downloads)
            .expect("read downloads directory")
            .next()
            .is_none());
    }

    #[tokio::test]
    async fn write_rejects_skipped_file_and_out_of_order_block_id() {
        let tmp_root = TestTempDir::new("camellia_file_block_sequence");
        let downloads = tmp_root.join("downloads");
        std::fs::create_dir_all(&downloads).expect("create downloads directory");
        let mut skipped = new_sized_write_job(
            119,
            downloads.clone(),
            &[("first.bin", 1), ("second.bin", 1)],
        )
        .expect("create multi-file write job");
        let mut reordered = new_sized_write_job(120, downloads.clone(), &[("ordered.bin", 1)])
            .expect("create sequenced write job");

        assert!(
            skipped
                .write(sequenced_block(119, 1, 0, b"b", false))
                .await
                .is_err(),
            "the first file cannot be skipped"
        );
        assert!(
            reordered
                .write(sequenced_block(120, 0, 1, b"a", false))
                .await
                .is_err(),
            "the first block id must be zero"
        );
        assert_eq!(skipped.finished_size(), 0);
        assert_eq!(reordered.finished_size(), 0);
    }

    #[tokio::test]
    async fn write_bounds_compressed_output_by_remaining_file_budget_and_propagates_errors() {
        let tmp_root = TestTempDir::new("camellia_compressed_file_budget");
        let downloads = tmp_root.join("downloads");
        std::fs::create_dir_all(&downloads).expect("create downloads directory");
        let compressed = zstd::encode_all(&b"abcde"[..], 0).expect("compress oversized payload");
        let mut oversized = new_sized_write_job(121, downloads.clone(), &[("oversized.bin", 4)])
            .expect("create compressed write job");
        let mut malformed = new_sized_write_job(122, downloads.clone(), &[("malformed.bin", 4)])
            .expect("create malformed write job");

        assert!(
            oversized
                .write(sequenced_block(121, 0, 0, &compressed, true))
                .await
                .is_err(),
            "decompressed output beyond the remaining file budget must fail"
        );
        assert!(
            malformed
                .write(sequenced_block(122, 0, 0, b"not-zstd", true))
                .await
                .is_err(),
            "malformed compressed data must not become an empty success"
        );
        assert_eq!(oversized.finished_size(), 0);
        assert_eq!(malformed.finished_size(), 0);
    }

    #[tokio::test]
    async fn write_accepts_complete_two_file_sequence_and_exact_compressed_budget() {
        let tmp_root = TestTempDir::new("camellia_complete_file_sequence");
        let downloads = tmp_root.join("downloads");
        std::fs::create_dir_all(&downloads).expect("create downloads directory");
        let mut job = new_sized_write_job(
            123,
            downloads.clone(),
            &[("first.bin", 3), ("second.bin", 2)],
        )
        .expect("create two-file write job");

        job.write(sequenced_block(123, 0, 0, b"ab", false))
            .await
            .expect("write first data block");
        job.write(sequenced_block(123, 0, 1, b"c", false))
            .await
            .expect("write second data block");
        job.write(sequenced_block(123, 0, 2, b"", false))
            .await
            .expect("write first file EOF");
        job.write(sequenced_block(123, 1, 0, b"de", false))
            .await
            .expect("write second file block");
        job.write(sequenced_block(123, 1, 1, b"", false))
            .await
            .expect("write second file EOF");
        job.modify_time().await.expect("commit final file");

        assert_eq!(std::fs::read(downloads.join("first.bin")).unwrap(), b"abc");
        assert_eq!(std::fs::read(downloads.join("second.bin")).unwrap(), b"de");
        assert_eq!(job.finished_size(), 5);
        assert_eq!(job.transferred(), 5);

        let compressed_downloads = tmp_root.join("compressed");
        std::fs::create_dir_all(&compressed_downloads)
            .expect("create compressed downloads directory");
        let compressed = zstd::encode_all(&b"four"[..], 0).expect("compress exact payload");
        let mut compressed_job =
            new_sized_write_job(124, compressed_downloads.clone(), &[("exact.bin", 4)])
                .expect("create exact compressed job");
        compressed_job
            .write(sequenced_block(124, 0, 0, &compressed, true))
            .await
            .expect("write exact compressed block");
        compressed_job
            .write(sequenced_block(124, 0, 1, b"", false))
            .await
            .expect("write compressed file EOF");
        compressed_job
            .modify_time()
            .await
            .expect("commit compressed file");
        assert_eq!(
            std::fs::read(compressed_downloads.join("exact.bin")).unwrap(),
            b"four"
        );
        assert_eq!(compressed_job.finished_size(), 4);
        assert_eq!(compressed_job.transferred(), compressed.len() as u64);
    }

    #[tokio::test]
    async fn write_rejects_duplicate_gap_early_eof_and_illegal_file_transitions() {
        let tmp_root = TestTempDir::new("camellia_rejected_file_sequences");
        let downloads = tmp_root.join("downloads");
        std::fs::create_dir_all(&downloads).expect("create downloads directory");

        let mut blocks = new_sized_write_job(125, downloads.clone(), &[("blocks.bin", 2)])
            .expect("create block sequence job");
        blocks
            .write(sequenced_block(125, 0, 0, b"a", false))
            .await
            .expect("write first block");
        assert!(
            blocks
                .write(sequenced_block(125, 0, 0, b"b", false))
                .await
                .is_err(),
            "duplicate block id must fail"
        );

        let mut gap = new_sized_write_job(137, downloads.clone(), &[("gap.bin", 2)])
            .expect("create block gap job");
        gap.write(sequenced_block(137, 0, 0, b"a", false))
            .await
            .expect("write first gap block");
        assert!(
            gap.write(sequenced_block(137, 0, 2, b"b", false))
                .await
                .is_err(),
            "block id gaps must fail"
        );

        let mut early_eof = new_sized_write_job(138, downloads.clone(), &[("early.bin", 2)])
            .expect("create early EOF job");
        early_eof
            .write(sequenced_block(138, 0, 0, b"a", false))
            .await
            .expect("write partial early EOF data");
        assert!(
            early_eof
                .write(sequenced_block(138, 0, 1, b"", false))
                .await
                .is_err(),
            "EOF before the declared size must fail"
        );

        let mut past_size = new_sized_write_job(139, downloads.clone(), &[("past-size.bin", 1)])
            .expect("create data-after-size job");
        past_size
            .write(sequenced_block(139, 0, 0, b"a", false))
            .await
            .expect("fill data-after-size job");
        assert!(
            past_size
                .write(sequenced_block(139, 0, 1, b"b", false))
                .await
                .is_err(),
            "data after the declared size must fail"
        );

        let mut duplicate_eof =
            new_sized_write_job(140, downloads.clone(), &[("duplicate-eof.bin", 1)])
                .expect("create duplicate EOF job");
        duplicate_eof
            .write(sequenced_block(140, 0, 0, b"a", false))
            .await
            .expect("fill duplicate EOF job");
        duplicate_eof
            .write(sequenced_block(140, 0, 1, b"", false))
            .await
            .expect("write first EOF");
        assert!(
            duplicate_eof
                .write(sequenced_block(140, 0, 2, b"", false))
                .await
                .is_err(),
            "duplicate EOF must fail"
        );

        let mut files = new_sized_write_job(
            126,
            downloads.clone(),
            &[("transition-a.bin", 1), ("transition-b.bin", 1)],
        )
        .expect("create file transition job");
        files
            .write(sequenced_block(126, 0, 0, b"a", false))
            .await
            .expect("fill first file");
        assert!(
            files
                .write(sequenced_block(126, 1, 0, b"b", false))
                .await
                .is_err(),
            "next file before EOF must fail"
        );

        let mut backward = new_sized_write_job(
            141,
            downloads.clone(),
            &[("backward-a.bin", 1), ("backward-b.bin", 1)],
        )
        .expect("create backward transition job");
        backward
            .write(sequenced_block(141, 0, 0, b"a", false))
            .await
            .expect("fill backward first file");
        backward
            .write(sequenced_block(141, 0, 1, b"", false))
            .await
            .expect("finish first file");
        backward
            .write(sequenced_block(141, 1, 0, b"b", false))
            .await
            .expect("advance exactly one file");
        assert!(
            backward
                .write(sequenced_block(141, 0, 2, b"", false))
                .await
                .is_err(),
            "backward file numbers must fail"
        );

        let mut skipped = new_sized_write_job(
            142,
            downloads.clone(),
            &[("skipped-a.bin", 1), ("skipped-b.bin", 1)],
        )
        .expect("create skipped transition job");
        assert!(
            skipped
                .write(sequenced_block(142, 3, 0, b"", false))
                .await
                .is_err(),
            "skipped file numbers must fail"
        );
    }

    #[tokio::test]
    async fn write_requires_explicit_eof_for_zero_size_files() {
        let tmp_root = TestTempDir::new("camellia_zero_size_file_sequence");
        let downloads = tmp_root.join("downloads");
        std::fs::create_dir_all(&downloads).expect("create downloads directory");
        let mut rejected =
            new_sized_write_job(143, downloads.clone(), &[("rejected-empty.bin", 0)])
                .expect("create rejected zero-size file job");
        assert!(
            rejected
                .write(sequenced_block(143, 0, 0, b"x", false))
                .await
                .is_err(),
            "a zero-size file cannot accept data"
        );

        let mut job =
            new_sized_write_job(127, downloads.clone(), &[("empty.bin", 0), ("one.bin", 1)])
                .expect("create zero-size file job");
        job.write(sequenced_block(127, 0, 0, b"", false))
            .await
            .expect("empty file must accept its explicit EOF");
        job.write(sequenced_block(127, 1, 0, b"x", false))
            .await
            .expect("write file after empty file");
        job.write(sequenced_block(127, 1, 1, b"", false))
            .await
            .expect("finish file after empty file");
        job.modify_time().await.expect("commit zero-size sequence");

        assert_eq!(std::fs::read(downloads.join("empty.bin")).unwrap(), b"");
        assert_eq!(std::fs::read(downloads.join("one.bin")).unwrap(), b"x");
        assert_eq!(job.finished_size(), 1);
    }

    #[tokio::test]
    async fn sender_assigns_contiguous_block_ids_including_eof() {
        const BLOCK_SIZE: usize = 128 * 1024;
        let tmp_root = TestTempDir::new("camellia_sender_block_ids");
        let source = tmp_root.join("source.bin");
        std::fs::create_dir_all(&tmp_root.path).expect("create source directory");
        std::fs::write(&source, vec![b'x'; BLOCK_SIZE + 1]).expect("create multi-block source");
        let mut job = TransferJob::new_read(
            128,
            JobType::Generic,
            "/fake/remote".to_string(),
            DataSource::FilePath(source),
            0,
            false,
            true,
            false,
        )
        .expect("create sender job");
        assert!(!job.open_data_stream().await.expect("open source stream"));

        let first = job.read().await.unwrap().expect("first data block");
        let second = job.read().await.unwrap().expect("second data block");
        let eof = job.read().await.unwrap().expect("EOF block");

        assert_eq!((first.file_num, first.blk_id), (0, 0));
        assert_eq!((second.file_num, second.blk_id), (0, 1));
        assert_eq!((eof.file_num, eof.blk_id), (0, 2));
        assert!(eof.data.is_empty());
        assert!(!eof.compressed);
        assert!(job.read().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn write_rejects_counter_and_block_id_overflow_before_opening_temp() {
        let tmp_root = TestTempDir::new("camellia_transfer_counter_overflow");
        let downloads = tmp_root.join("downloads");
        std::fs::create_dir_all(&downloads).expect("create downloads directory");

        let mut finished =
            new_sized_write_job(129, downloads.clone(), &[("finished.bin", u64::MAX)])
                .expect("create finished counter job");
        finished.finished_size = u64::MAX;
        assert!(
            finished
                .write(sequenced_block(129, 0, 0, b"x", false))
                .await
                .is_err(),
            "finished byte counter overflow must fail"
        );

        let mut transferred =
            new_sized_write_job(130, downloads.clone(), &[("transferred.bin", u64::MAX)])
                .expect("create transferred counter job");
        transferred.transferred = u64::MAX;
        assert!(
            transferred
                .write(sequenced_block(130, 0, 0, b"x", false))
                .await
                .is_err(),
            "wire byte counter overflow must fail"
        );

        let mut block_id =
            new_sized_write_job(131, downloads.clone(), &[("block-id.bin", u64::MAX)])
                .expect("create block id counter job");
        block_id.write_progress.next_block_id = u32::MAX;
        assert!(
            block_id
                .write(sequenced_block(131, 0, u32::MAX, b"x", false))
                .await
                .is_err(),
            "block id overflow must fail"
        );

        assert!(std::fs::read_dir(&downloads)
            .expect("read downloads directory")
            .next()
            .is_none());
    }

    #[tokio::test]
    async fn write_error_is_terminal_and_cannot_be_retried() {
        let tmp_root = TestTempDir::new("camellia_terminal_write_error");
        let downloads = tmp_root.join("downloads");
        std::fs::create_dir_all(&downloads).expect("create downloads directory");
        let mut job = new_sized_write_job(132, downloads.clone(), &[("report.bin", 4)])
            .expect("create write job");

        let first = job
            .write(sequenced_block(132, 0, 0, b"not-zstd", true))
            .await
            .expect_err("malformed compressed block must fail")
            .to_string();
        let repeated = job
            .write(sequenced_block(132, 0, 0, b"four", false))
            .await
            .expect_err("a later valid block must not clear the first terminal error");
        assert_eq!(job.job_error().as_deref(), Some(first.as_str()));
        assert!(repeated.to_string().contains(&first));
        assert!(std::fs::read_dir(&downloads)
            .expect("read downloads directory")
            .next()
            .is_none());
    }

    #[tokio::test]
    async fn incomplete_write_cannot_be_finalized_as_success() {
        let tmp_root = TestTempDir::new("camellia_incomplete_write_done");
        let downloads = tmp_root.join("downloads");
        std::fs::create_dir_all(&downloads).expect("create downloads directory");
        let mut job = new_sized_write_job(133, downloads.clone(), &[("report.bin", 4)])
            .expect("create write job");
        job.write(sequenced_block(133, 0, 0, b"fo", false))
            .await
            .expect("write partial block");

        assert!(
            job.modify_time().await.is_err(),
            "Done before exact size and EOF must fail"
        );
        assert!(job.job_error().is_some());
        assert!(!downloads.join("report.bin").exists());
    }

    #[tokio::test]
    async fn finalize_error_is_sticky_and_keeps_resume_ownership() {
        let tmp_root = TestTempDir::new("camellia_sticky_finalize_error");
        let downloads = tmp_root.join("downloads");
        std::fs::create_dir_all(&downloads).expect("create downloads directory");
        let mut job = new_sized_write_job(134, downloads.clone(), &[("report.bin", 4)])
            .expect("create write job");
        job.files[0].modified_time = u64::MAX;
        job.write(sequenced_block(134, 0, 0, b"four", false))
            .await
            .expect("write complete data");
        job.write(sequenced_block(134, 0, 1, b"", false))
            .await
            .expect("write EOF");
        let digest = stored_digest(&downloads, "report.bin");

        let first = job
            .modify_time()
            .await
            .expect_err("out-of-range mtime must fail finalization")
            .to_string();
        assert!(
            job.modify_time().await.is_err(),
            "a repeated Done must preserve the first finalization error"
        );
        assert_eq!(job.job_error().as_deref(), Some(first.as_str()));
        assert!(downloads.join(&digest.temp_name).is_file());
        assert!(downloads.join("report.bin.digest").is_file());
        assert!(!downloads.join("report.bin").exists());
        job.remove_download_file()
            .await
            .expect("terminal job must retain cleanup ownership");
        assert!(!downloads.join(&digest.temp_name).exists());
        assert!(!downloads.join("report.bin.digest").exists());
    }

    #[tokio::test]
    async fn sender_open_error_cannot_advance_into_completed_state() {
        let tmp_root = TestTempDir::new("camellia_terminal_sender_open_error");
        let source = tmp_root.join("source.bin");
        std::fs::create_dir_all(&tmp_root.path).expect("create source directory");
        std::fs::write(&source, b"payload").expect("create source file");
        let mut job = TransferJob::new_read(
            135,
            JobType::Generic,
            "/fake/remote".to_string(),
            DataSource::FilePath(source.clone()),
            0,
            false,
            true,
            false,
        )
        .expect("create sender job");
        std::fs::remove_file(source).expect("remove source before open");

        assert!(job.init_data_stream_for_cm().await.is_err());
        assert!(
            job.init_data_stream_for_cm().await.is_err(),
            "the first open error must remain terminal"
        );
        assert!(job.job_error().is_some());
        assert!(!job.job_completed());
        assert_eq!(job.file_num(), 0);
    }

    #[test]
    fn sender_compression_failure_falls_back_to_original_block() {
        let original = b"payload must remain intact".to_vec();
        let (data, compressed) = compress_file_block_with(original.clone(), |_| {
            Err(std::io::Error::other("injected compressor failure"))
        });

        assert_eq!(data, original);
        assert!(!compressed);
    }

    #[tokio::test]
    async fn receiver_skip_advances_sequence_without_overwriting_existing_file() {
        let tmp_root = TestTempDir::new("camellia_receiver_skip_sequence");
        let downloads = tmp_root.join("downloads");
        std::fs::create_dir_all(&downloads).expect("create downloads directory");
        std::fs::write(downloads.join("keep.bin"), b"old").expect("create skipped destination");
        let mut job =
            new_sized_write_job(136, downloads.clone(), &[("keep.bin", 1), ("write.bin", 1)])
                .expect("create receiver job");

        assert!(job.set_file_skipped());
        job.write(sequenced_block(136, 1, 0, b"x", false))
            .await
            .expect("write file after skipped destination");
        job.write(sequenced_block(136, 1, 1, b"", false))
            .await
            .expect("finish file after skipped destination");
        job.modify_time().await.expect("commit file after skip");

        assert_eq!(std::fs::read(downloads.join("keep.bin")).unwrap(), b"old");
        assert_eq!(std::fs::read(downloads.join("write.bin")).unwrap(), b"x");
    }

    #[test]
    fn resume_confirmation_preserves_offsets_above_u32() {
        let tmp_root = TestTempDir::new("camellia_large_resume_offset");
        let downloads = tmp_root.join("downloads");
        std::fs::create_dir_all(&downloads).expect("create downloads directory");
        let transferred_size = u64::from(u32::MAX) + 2;
        let declared_size = transferred_size + 1;
        let modified = 1_700_000_003;
        let temp_name = random_sidecar_name(DOWNLOAD_TEMP_PREFIX, DOWNLOAD_TEMP_SUFFIX);
        let partial = std::fs::File::create(downloads.join(&temp_name))
            .expect("create sparse partial transfer");
        partial
            .set_len(transferred_size)
            .expect("set sparse partial length");
        std::fs::write(
            downloads.join("large.bin.digest"),
            serde_json::to_vec(&FileDigest {
                size: declared_size,
                modified,
                temp_name,
            })
            .expect("serialize transfer digest"),
        )
        .expect("write transfer digest");
        let digest = transfer_digest(144, declared_size, modified);
        let result =
            is_write_need_confirmation(true, &get_string(&downloads.join("large.bin")), &digest)
                .expect("inspect large resumable transfer");
        let DigestCheckResult::NeedConfirm(confirmation) = result else {
            panic!("large partial transfer must request confirmation");
        };
        assert_eq!(confirmation.transferred_size, transferred_size);

        let request = FileTransferSendConfirmRequest {
            id: confirmation.id,
            file_num: confirmation.file_num,
            union: Some(file_transfer_send_confirm_request::Union::OffsetBytes(
                confirmation.transferred_size,
            )),
            ..Default::default()
        };

        assert_eq!(
            request.offset_bytes(),
            confirmation.transferred_size,
            "resume confirmation must not truncate the byte offset"
        );
    }

    #[test]
    fn resume_offset_wire_round_trips_four_gib_boundaries() {
        let offsets = [
            (1u64 << 32) - 1,
            1u64 << 32,
            (1u64 << 32) + 1,
            (8u64 << 30) + 17,
        ];

        for offset in offsets {
            let request = FileTransferSendConfirmRequest {
                id: 145,
                file_num: 0,
                union: Some(file_transfer_send_confirm_request::Union::OffsetBytes(
                    offset,
                )),
                ..Default::default()
            };
            let encoded = request.write_to_bytes().expect("serialize resume request");
            let decoded = FileTransferSendConfirmRequest::parse_from_bytes(&encoded)
                .expect("parse resume request");

            assert_eq!(decoded.offset_bytes(), offset);
        }
    }

    #[tokio::test]
    async fn receiver_resume_truncates_sparse_suffix_and_writes_above_four_gib() {
        let tmp_root = TestTempDir::new("camellia_sparse_receiver_resume");
        let downloads = tmp_root.join("downloads");
        std::fs::create_dir_all(&downloads).expect("create downloads directory");
        let offset = (1u64 << 32) + 1;
        let declared_size = offset + 1;
        let modified = 1_700_000_004;
        let temp_name = random_sidecar_name(DOWNLOAD_TEMP_PREFIX, DOWNLOAD_TEMP_SUFFIX);
        let partial = std::fs::File::create(downloads.join(&temp_name))
            .expect("create sparse receiver partial");
        partial
            .set_len(declared_size + 4096)
            .expect("create stale sparse suffix");
        std::fs::write(
            downloads.join("large.bin.digest"),
            serde_json::to_vec(&FileDigest {
                size: declared_size,
                modified,
                temp_name: temp_name.clone(),
            })
            .expect("serialize receiver digest"),
        )
        .expect("write receiver digest");
        let mut job = new_sized_write_job(146, downloads.clone(), &[("large.bin", declared_size)])
            .expect("create large receiver job");
        job.files[0].modified_time = modified;
        job.set_digest(declared_size, modified);

        job.set_stream_offset(0, offset)
            .await
            .expect("seek large receiver partial");
        assert_eq!(
            std::fs::metadata(downloads.join(&temp_name))
                .expect("inspect truncated receiver partial")
                .len(),
            offset
        );
        job.write(sequenced_block(146, 0, 0, b"x", false))
            .await
            .expect("write byte above four GiB");
        job.write(sequenced_block(146, 0, 1, b"", false))
            .await
            .expect("finish large receiver file");
        job.modify_time().await.expect("commit large receiver file");

        let final_path = downloads.join("large.bin");
        assert_eq!(
            std::fs::metadata(&final_path)
                .expect("inspect large final file")
                .len(),
            declared_size
        );
        let mut final_file = std::fs::File::open(final_path).expect("open large final file");
        std::io::Seek::seek(&mut final_file, std::io::SeekFrom::Start(offset))
            .expect("seek final byte");
        let mut last = [0u8; 1];
        std::io::Read::read_exact(&mut final_file, &mut last).expect("read final byte");
        assert_eq!(last, [b'x']);
    }

    #[tokio::test]
    async fn sender_resume_reads_from_sparse_offset_above_eight_gib() {
        let tmp_root = TestTempDir::new("camellia_sparse_sender_resume");
        let source = tmp_root.join("source.bin");
        std::fs::create_dir_all(&tmp_root.path).expect("create source directory");
        let offset = (8u64 << 30) + 17;
        let source_file = std::fs::File::create(&source).expect("create sparse source file");
        source_file
            .set_len(offset + 1)
            .expect("set sparse source length");
        let mut job = TransferJob::new_read(
            147,
            JobType::Generic,
            "/fake/remote".to_string(),
            DataSource::FilePath(source),
            0,
            false,
            true,
            false,
        )
        .expect("create sparse sender job");

        job.set_stream_offset(0, offset)
            .await
            .expect("seek sparse sender source");
        let data = job
            .read()
            .await
            .expect("read sparse source")
            .expect("read data block");
        let eof = job
            .read()
            .await
            .expect("read sparse source EOF")
            .expect("read EOF block");

        assert_eq!(data.blk_id, 0);
        assert_eq!(data.data.as_ref(), &[0]);
        assert_eq!(eof.blk_id, 1);
        assert!(eof.data.is_empty());
        assert_eq!(job.finished_size(), offset + 1);
    }

    #[cfg(windows)]
    #[test]
    fn set_files_rejects_unc_absolute_path() {
        let mut job = new_validation_job(105);
        let err = job
            .set_files(vec![new_file_entry("\\\\server\\share\\payload.txt")])
            .expect_err("UNC absolute path must be rejected");
        assert_err_contains(err, "absolute path");
    }

    #[cfg(not(windows))]
    #[test]
    fn set_files_allows_backslash_prefixed_name_on_unix() {
        let mut job = new_validation_job(105);
        assert!(job
            .set_files(vec![new_file_entry("\\\\server\\share\\payload.txt")])
            .is_ok());
    }

    #[test]
    fn remove_file_rejects_empty_path() {
        let err = remove_file("").expect_err("empty file path must be rejected");
        assert_err_contains(err, "cannot be empty");
    }

    #[test]
    fn remove_file_rejects_null_byte_path() {
        let err = remove_file("bad\0path").expect_err("null byte path must be rejected");
        assert_err_contains(err, "null bytes");
    }

    #[test]
    fn create_dir_rejects_empty_path() {
        let err = create_dir("").expect_err("empty directory path must be rejected");
        assert_err_contains(err, "cannot be empty");
    }

    #[test]
    fn create_dir_rejects_null_byte_path() {
        let err = create_dir("bad\0path").expect_err("null byte path must be rejected");
        assert_err_contains(err, "null bytes");
    }

    #[test]
    fn rename_file_rejects_invalid_new_name() {
        let tmp_root = TestTempDir::new("rustdesk_rename_invalid");
        let src = tmp_root.join("source.txt");
        std::fs::create_dir_all(&tmp_root.path).expect("create temp dir");
        std::fs::write(&src, b"content").expect("create source file");

        let src_str = src.to_string_lossy().to_string();

        let err_empty =
            rename_file(&src_str, "").expect_err("empty new file name must be rejected");
        assert_err_contains(err_empty, "cannot be empty");

        let err_traversal = rename_file(&src_str, "../escape.txt")
            .expect_err("traversal new file name must be rejected");
        assert_err_contains(err_traversal, "path traversal");

        let err_null = rename_file(&src_str, "bad\0name.txt")
            .expect_err("null byte in new file name must be rejected");
        assert_err_contains(err_null, "null bytes");

        #[cfg(windows)]
        {
            let err_abs = rename_file(&src_str, "C:\\Windows\\Temp\\payload.txt")
                .expect_err("absolute new file name must be rejected");
            assert_err_contains(err_abs, "absolute path");
        }
        #[cfg(not(windows))]
        {
            let err_abs = rename_file(&src_str, "/tmp/payload.txt")
                .expect_err("absolute new file name must be rejected");
            assert_err_contains(err_abs, "absolute path");
        }
    }

    #[test]
    fn rename_file_accepts_valid_new_name() {
        let tmp_root = TestTempDir::new("rustdesk_rename_ok");
        let src = tmp_root.join("rename_src.txt");
        let dst = tmp_root.join("renamed.txt");
        std::fs::create_dir_all(&tmp_root.path).expect("create temp dir");
        std::fs::write(&src, b"content").expect("create source file");

        let src_str = src.to_string_lossy().to_string();
        rename_file(&src_str, "renamed.txt").expect("rename should succeed");

        assert!(!src.exists());
        assert!(dst.exists());
    }

    #[test]
    fn recursive_directory_listing_propagates_entry_iteration_failure() {
        let tmp_root = TestTempDir::new("camellia_recursive_entry_failure");
        std::fs::create_dir_all(&tmp_root.path).expect("create listing root");
        let entries = std::iter::once(Err(std::io::Error::other(
            "synthetic directory iteration failure",
        )));

        let err = collect_directory_entries(&tmp_root.path, true, entries)
            .expect_err("an entry iteration error must fail the complete listing");
        assert!(
            err.to_string()
                .contains(&tmp_root.path.to_string_lossy().to_string()),
            "the failure must identify the directory being enumerated: {err}"
        );
    }

    #[test]
    fn recursive_directory_listing_propagates_disappeared_entry_path() {
        let tmp_root = TestTempDir::new("camellia_recursive_disappeared_entry");
        let disappearing = tmp_root.join("disappearing.txt");
        std::fs::create_dir_all(&tmp_root.path).expect("create listing root");
        std::fs::write(&disappearing, b"temporary").expect("create disappearing entry");
        let entry = std::fs::read_dir(&tmp_root.path)
            .expect("open listing root")
            .next()
            .expect("find disappearing entry")
            .expect("read disappearing entry");
        std::fs::remove_file(&disappearing).expect("remove entry before metadata lookup");

        let err = collect_directory_entries(&tmp_root.path, true, std::iter::once(Ok(entry)))
            .expect_err("a vanished entry must fail the complete listing");
        assert!(
            err.to_string().contains("disappearing.txt"),
            "the failure must identify the vanished entry: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn recursive_directory_listing_rejects_special_entry() {
        let tmp_root = TestTempDir::new("camellia_recursive_special_entry");
        std::fs::create_dir_all(&tmp_root.path).expect("create listing root");
        let socket_path = tmp_root.join("service.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&socket_path)
            .expect("create special directory entry");

        let err = read_dir(&tmp_root.path, true)
            .expect_err("an unsupported special entry must not be reported as a regular file");
        assert!(
            err.to_string().contains("service.sock"),
            "the failure must identify the unsupported entry: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn recursive_directory_listing_propagates_unreadable_child_path() {
        use std::os::unix::fs::PermissionsExt;

        let tmp_root = TestTempDir::new("camellia_recursive_unreadable_child");
        let blocked = tmp_root.join("blocked");
        std::fs::create_dir_all(&blocked).expect("create blocked child directory");
        std::fs::write(blocked.join("payload.txt"), b"must not disappear")
            .expect("create child payload");
        std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o000))
            .expect("make child unreadable");

        let result = get_recursive_files(&tmp_root.path.to_string_lossy(), true);
        std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o700))
            .expect("restore child permissions");

        let err = result.expect_err("an unreadable child must fail the complete listing");
        assert!(
            err.to_string().contains("blocked"),
            "the failure must identify the omitted child: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn recursive_empty_directory_listing_propagates_unreadable_child_path() {
        use std::os::unix::fs::PermissionsExt;

        let tmp_root = TestTempDir::new("camellia_recursive_empty_unreadable_child");
        let blocked = tmp_root.join("blocked");
        std::fs::create_dir_all(&blocked).expect("create blocked child directory");
        std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o000))
            .expect("make child unreadable");

        let result = get_empty_dirs_recursive(&tmp_root.path.to_string_lossy(), true);
        std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o700))
            .expect("restore child permissions");

        let err = result.expect_err("an unreadable child must fail the complete empty-dir scan");
        assert!(
            err.to_string().contains("blocked"),
            "the failure must identify the omitted child: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn recursive_directory_listing_rejects_symlink_root() {
        let tmp_root = TestTempDir::new("camellia_recursive_symlink_root");
        let target = tmp_root.join("target");
        let link = tmp_root.join("root-link");
        std::fs::create_dir_all(&target).expect("create symlink target directory");
        create_test_dir_symlink(&target, &link).expect("create recursive root symlink");

        let files_err = get_recursive_files(&link.to_string_lossy(), true)
            .expect_err("recursive file listing must reject a symlink root");
        assert!(files_err.to_string().contains("root-link"));

        let dirs_err = get_empty_dirs_recursive(&link.to_string_lossy(), true)
            .expect_err("recursive empty-dir listing must reject a symlink root");
        assert!(dirs_err.to_string().contains("root-link"));
    }

    #[test]
    fn recursive_empty_directory_removal_is_idempotent_for_not_found() {
        let owner = TestTempDir::new("camellia_remove_missing_empty_tree");
        let missing = owner.join("missing");
        assert!(!missing.exists());
        remove_all_empty_dir(&missing).expect("an already absent tree is an idempotent success");
    }

    #[test]
    fn recursive_empty_directory_removal_removes_valid_tree() {
        let tmp_root = TestTempDir::new("camellia_remove_valid_empty_tree");
        std::fs::create_dir_all(tmp_root.join("one/two/three")).expect("create nested empty tree");

        remove_all_empty_dir(&tmp_root.path).expect("remove a valid empty tree");
        assert!(!tmp_root.path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn recursive_empty_directory_removal_unlinks_symlink_without_following_target() {
        let tmp_root = TestTempDir::new("camellia_remove_directory_symlink");
        let removal_root = tmp_root.join("removal-root");
        let outside = tmp_root.join("outside");
        let sentinel = outside.join("sentinel.txt");
        std::fs::create_dir_all(&removal_root).expect("create removal root");
        std::fs::create_dir_all(&outside).expect("create symlink target");
        std::fs::write(&sentinel, b"outside must remain").expect("create outside sentinel");
        create_test_dir_symlink(&outside, &removal_root.join("outside-link"))
            .expect("create child directory symlink");

        remove_all_empty_dir(&removal_root).expect("unlink symlink and remove empty root");
        assert!(!removal_root.exists());
        assert_eq!(
            std::fs::read(&sentinel).expect("read outside sentinel"),
            b"outside must remain"
        );
    }

    #[cfg(unix)]
    #[test]
    fn recursive_empty_directory_removal_unlinks_symlink_root_without_following_target() {
        let tmp_root = TestTempDir::new("camellia_remove_root_symlink");
        let target = tmp_root.join("target");
        let target_empty_child = target.join("empty-child");
        let sentinel = target.join("sentinel.txt");
        let link = tmp_root.join("root-link");
        std::fs::create_dir_all(&target_empty_child).expect("create target empty child");
        std::fs::write(&sentinel, b"target must remain").expect("create target sentinel");
        create_test_dir_symlink(&target, &link).expect("create removal root symlink");

        remove_all_empty_dir(&link).expect("unlink the root symlink without traversing it");
        assert!(!link.is_symlink());
        assert!(target_empty_child.is_dir());
        assert_eq!(
            std::fs::read(&sentinel).expect("read target sentinel"),
            b"target must remain"
        );
    }

    #[test]
    fn recursive_empty_directory_removal_reports_non_empty_child() {
        let tmp_root = TestTempDir::new("camellia_remove_non_empty_child");
        let nested = tmp_root.join("nested");
        std::fs::create_dir_all(&nested).expect("create nested directory");
        std::fs::write(nested.join("payload.txt"), b"must remain").expect("create nested payload");

        let err = remove_all_empty_dir(&tmp_root.path)
            .expect_err("a non-empty child must prevent an overall success result");
        assert!(nested.join("payload.txt").is_file());
        assert!(
            err.to_string().contains("nested"),
            "the failure must identify the directory that remained: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn recursive_empty_directory_removal_propagates_symlink_unlink_failure() {
        use std::os::unix::fs::PermissionsExt;

        let tmp_root = TestTempDir::new("camellia_remove_symlink_failure");
        let outside = tmp_root.path.with_extension("outside");
        std::fs::write(&outside, b"outside must remain").expect("create outside target");
        std::fs::create_dir_all(&tmp_root.path).expect("create removal root");
        let link = tmp_root.join("outside-link");
        create_test_file_symlink(&outside, &link).expect("create child symlink");
        std::fs::set_permissions(&tmp_root.path, std::fs::Permissions::from_mode(0o500))
            .expect("make removal root non-writable");

        let result = remove_all_empty_dir(&tmp_root.path);
        std::fs::set_permissions(&tmp_root.path, std::fs::Permissions::from_mode(0o700))
            .expect("restore removal root permissions");

        let err = result.expect_err("a failed symlink unlink must prevent overall success");
        assert!(link.is_symlink());
        assert_eq!(
            std::fs::read(&outside).expect("read outside target"),
            b"outside must remain"
        );
        assert!(
            err.to_string().contains("outside-link"),
            "the failure must identify the symlink that remained: {err}"
        );
        std::fs::remove_file(outside).expect("remove outside target");
    }

    #[cfg(windows)]
    #[test]
    fn set_files_rejects_windows_drive_absolute_path() {
        let mut job = new_validation_job(106);
        let err = job
            .set_files(vec![new_file_entry("C:\\Windows\\Temp\\payload.txt")])
            .expect_err("drive-letter absolute path must be rejected");
        assert_err_contains(err, "absolute path");
    }

    #[cfg(windows)]
    #[test]
    fn set_files_rejects_windows_verbatim_drive_absolute_path() {
        let mut job = new_validation_job(1061);
        let err = job
            .set_files(vec![new_file_entry(r"\\?\C:\Windows\Temp\x.txt")])
            .expect_err("verbatim drive absolute path must be rejected");
        assert_err_contains(err, "absolute path");
    }
}
