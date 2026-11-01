use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs,
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    ops::{Deref, DerefMut},
    path::{Path, PathBuf},
    sync::{Mutex, RwLock},
    time::{Duration, Instant, SystemTime},
};

use anyhow::{anyhow, bail, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use bytes::Bytes;
use rand::RngExt;
use regex::Regex;
use serde as de;
use serde_derive::{Deserialize, Serialize};
use serde_json;
use sha2::{Digest, Sha256};

mod permanent_password;

pub use permanent_password::{
    compute_permanent_password_h1, decode_permanent_password_h1_from_storage,
    decode_preset_password_h1_from_storage, local_permanent_password_storage_is_usable_for_auth,
    preset_permanent_password_storage_is_usable_for_auth, ENCRYPT_MAX_LEN,
};
use permanent_password::{
    encode_permanent_password_encrypted_storage_from_h1,
    preset_permanent_password_storage_matches_plain, DEFAULT_SALT_LEN,
};

use crate::{
    compress::{compress, decompress},
    crypto::sign,
    log,
    password_security::{
        decrypt_local, decrypt_str, decrypt_vec, encrypt_local, encrypt_str, encrypt_vec,
        SecretStorageError,
    },
    ResultType,
};

pub const RENDEZVOUS_TIMEOUT: u64 = 12_000;
pub const CONNECT_TIMEOUT: u64 = 18_000;
pub const READ_TIMEOUT: u64 = 18_000;
// https://github.com/quic-go/quic-go/issues/525#issuecomment-294531351
// https://datatracker.ietf.org/doc/html/draft-hamilton-early-deployment-quic-00#section-6.10
// 15 seconds is recommended by quic, though oneSIP recommend 25 seconds,
// https://www.onsip.com/voip-resources/voip-fundamentals/what-is-nat-keepalive
pub const REG_INTERVAL: i64 = 15_000;
pub const COMPRESS_LEVEL: i32 = 3;
const SERIAL: i32 = 3;

#[cfg(target_os = "macos")]
lazy_static::lazy_static! {
    pub static ref ORG: RwLock<String> = RwLock::new("com.camellia.remote".to_owned());
}

type Size = (i32, i32, i32, i32);
type KeyPair = (Vec<u8>, Vec<u8>);

lazy_static::lazy_static! {
    static ref CONFIG: RwLock<Config> = RwLock::new(Config::load());
    static ref CONFIG2: RwLock<Config2> = RwLock::new(Config2::load());
    static ref LOCAL_CONFIG: RwLock<LocalConfig> = RwLock::new(LocalConfig::load());
    static ref STATUS: RwLock<Status> = RwLock::new(Status::load());
    static ref TRUSTED_DEVICES: RwLock<(Vec<TrustedDevice>, bool)> = Default::default();
    static ref ONLINE: Mutex<HashMap<String, i64>> = Default::default();
    pub static ref PROD_RENDEZVOUS_SERVER: RwLock<String> = RwLock::new("".to_owned());
    pub static ref EXE_RENDEZVOUS_SERVER: RwLock<String> = Default::default();
    pub static ref APP_NAME: RwLock<String> = RwLock::new("Camellia Remote".to_owned());
    static ref KEY_PAIR: Mutex<Option<KeyPair>> = Default::default();
    static ref USER_DEFAULT_CONFIG: RwLock<(UserDefaultConfig, Instant)> = RwLock::new((UserDefaultConfig::load(), Instant::now()));
    pub static ref NEW_STORED_PEER_CONFIG: Mutex<HashSet<String>> = Default::default();
    pub static ref DEFAULT_SETTINGS: RwLock<HashMap<String, String>> = Default::default();
    pub static ref OVERWRITE_SETTINGS: RwLock<HashMap<String, String>> = Default::default();
    pub static ref DEFAULT_DISPLAY_SETTINGS: RwLock<HashMap<String, String>> = Default::default();
    pub static ref OVERWRITE_DISPLAY_SETTINGS: RwLock<HashMap<String, String>> = Default::default();
    pub static ref DEFAULT_LOCAL_SETTINGS: RwLock<HashMap<String, String>> = Default::default();
    pub static ref OVERWRITE_LOCAL_SETTINGS: RwLock<HashMap<String, String>> = Default::default();
    pub static ref HARD_SETTINGS: RwLock<HashMap<String, String>> = Default::default();
    pub static ref BUILTIN_SETTINGS: RwLock<HashMap<String, String>> = Default::default();
}

#[cfg(target_os = "android")]
lazy_static::lazy_static! {
    pub static ref ANDROID_RUSTLS_PLATFORM_VERIFIER_INITIALIZED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
}

lazy_static::lazy_static! {
    pub static ref APP_DIR: RwLock<String> = Default::default();
}

#[cfg(any(target_os = "android", target_os = "ios"))]
lazy_static::lazy_static! {
    pub static ref APP_HOME_DIR: RwLock<String> = Default::default();
}

pub const LINK_DOCS_HOME: &str = match option_env!("CAMELLIA_REMOTE_DOCS_HOME_URL") {
    Some(value) => value,
    None => "",
};
pub const LINK_DOCS_X11_REQUIRED: &str = match option_env!("CAMELLIA_REMOTE_LINUX_DISPLAY_DOCS_URL")
{
    Some(value) => value,
    None => "",
};
pub const LINK_HEADLESS_LINUX_SUPPORT: &str = LINK_DOCS_X11_REQUIRED;

lazy_static::lazy_static! {
    pub static ref HELPER_URL: HashMap<&'static str, &'static str> = HashMap::from([
        ("camellia docs home", LINK_DOCS_HOME),
        ("camellia docs x11-required", LINK_DOCS_X11_REQUIRED),
        ("camellia x11 headless", LINK_HEADLESS_LINUX_SUPPORT),
        ]);
}

const NUM_CHARS: &[char] = &['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'];

const CHARS: &[char] = &[
    '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k',
    'm', 'n', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
];

lazy_static::lazy_static! {
    pub static ref RENDEZVOUS_SERVERS: RwLock<Vec<String>> = RwLock::new({
        let s = option_env!("RENDEZVOUS_SERVERS").unwrap_or_default();
        if s.is_empty() {
            Vec::new()
        } else {
            s
                .split(',')
                .map(str::trim)
                .filter(|x| !x.is_empty())
                .map(|x| x.to_owned())
                .collect()
        }
    });

    pub static ref RS_PUB_KEY: RwLock<String> = RwLock::new({
        let pk = option_env!("RS_PUB_KEY").unwrap_or_default();
        if pk.is_empty() {
            "".to_owned()
        } else {
            pk.to_owned()
        }
    });

    pub static ref API_SERVER: RwLock<String> = RwLock::new({
        let api = option_env!("API_SERVER").unwrap_or_default().trim();
        if api.is_empty() {
            "".to_owned()
        } else {
            api.to_owned()
        }
    });
}

pub const RENDEZVOUS_PORT: i32 = 21116;
pub const RELAY_PORT: i32 = 21117;
pub const WS_RENDEZVOUS_PORT: i32 = 21118;
pub const WS_RELAY_PORT: i32 = 21119;

#[inline]
pub fn is_service_ipc_postfix(postfix: &str) -> bool {
    // `_service` is a protected cross-user IPC channel used by the root service.
    //
    // On Linux Wayland, input injection is implemented via uinput in the root service process.
    // The user `--server` process must be able to connect to these uinput IPC channels, so they
    // must share the same IPC parent directory as `_service`.
    postfix == "_service" || postfix.starts_with("_uinput_")
}

// Keep Linux/macOS IPC parent directory rules in one place to avoid drift between
// `ipc_path()` and Unix `ipc_path_for_uid()`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[inline]
fn ipc_parent_dir_for_uid(uid: u32, postfix: &str) -> String {
    let app_name = APP_NAME.read().unwrap().clone();
    if is_service_ipc_postfix(postfix) {
        format!("/tmp/{app_name}-service")
    } else {
        format!("/tmp/{app_name}-{uid}")
    }
}

macro_rules! serde_field_string {
    ($default_func:ident, $de_func:ident, $default_expr:expr) => {
        fn $default_func() -> String {
            $default_expr
        }

        fn $de_func<'de, D>(deserializer: D) -> Result<String, D::Error>
        where
            D: de::Deserializer<'de>,
        {
            let s: String =
                de::Deserialize::deserialize(deserializer).unwrap_or(Self::$default_func());
            if s.is_empty() {
                return Ok(Self::$default_func());
            }
            Ok(s)
        }
    };
}

macro_rules! serde_field_bool {
    ($struct_name: ident, $field_name: literal, $func: ident, $default: literal) => {
        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
        pub struct $struct_name {
            #[serde(default = $default, rename = $field_name, deserialize_with = "deserialize_bool")]
            pub v: bool,
        }
        impl Default for $struct_name {
            fn default() -> Self {
                Self { v: Self::$func() }
            }
        }
        impl $struct_name {
            pub fn $func() -> bool {
                UserDefaultConfig::read($field_name) == "Y"
            }
        }
        impl Deref for $struct_name {
            type Target = bool;

            fn deref(&self) -> &Self::Target {
                &self.v
            }
        }
        impl DerefMut for $struct_name {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.v
            }
        }
    };
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NetworkType {
    Direct,
    ProxySocks,
}

#[derive(Default, Serialize, Deserialize, Clone, PartialEq)]
pub struct Config {
    #[serde(
        default,
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string"
    )]
    pub id: String, // use
    #[serde(default, deserialize_with = "deserialize_string")]
    enc_id: String, // store
    #[serde(default, deserialize_with = "deserialize_string")]
    password: String,
    #[serde(default, deserialize_with = "deserialize_string")]
    salt: String,
    #[serde(default, deserialize_with = "deserialize_keypair")]
    key_pair: KeyPair, // sk, pk
    #[serde(default, deserialize_with = "deserialize_bool")]
    key_confirmed: bool,
    #[serde(default, deserialize_with = "deserialize_hashmap_string_bool")]
    keys_confirmed: HashMap<String, bool>,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (sk_desc, pk_desc) = if self.key_pair.0.is_empty() {
            (
                "<empty>",
                if self.key_pair.1.is_empty() {
                    "<empty>"
                } else {
                    "<present>"
                },
            )
        } else {
            (
                "<redacted>",
                if self.key_pair.1.is_empty() {
                    "<empty>"
                } else {
                    "<present>"
                },
            )
        };
        f.debug_struct("Config")
            .field("id", &self.id)
            .field(
                "enc_id",
                &if self.enc_id.is_empty() {
                    "<empty>"
                } else {
                    "<redacted>"
                },
            )
            .field(
                "password",
                &if self.password.is_empty() {
                    "<empty>"
                } else {
                    "<redacted>"
                },
            )
            .field(
                "salt",
                &if self.salt.is_empty() {
                    "<empty>"
                } else {
                    "<redacted>"
                },
            )
            .field(
                "key_pair",
                &format_args!("(sk: {}, pk: {})", sk_desc, pk_desc),
            )
            .field("key_confirmed", &self.key_confirmed)
            .field("keys_confirmed", &self.keys_confirmed)
            .finish()
    }
}

#[derive(Debug, Default, PartialEq, Serialize, Deserialize, Clone)]
pub struct Socks5Server {
    #[serde(default, deserialize_with = "deserialize_string")]
    pub proxy: String,
    #[serde(default, deserialize_with = "deserialize_string")]
    pub username: String,
    #[serde(default, deserialize_with = "deserialize_string")]
    pub password: String,
}

const MANAGED_POLICY_MAX_OPTIONS: usize = 512;
const MANAGED_POLICY_MAX_ID_BYTES: usize = 128;
const MANAGED_POLICY_MAX_UUID_BYTES: usize = 344;
const MANAGED_POLICY_MAX_KEY_BYTES: usize = 512;
const MANAGED_POLICY_MAX_VALUE_BYTES: usize = 16 * 1024;
const MANAGED_POLICY_MAX_TOTAL_BYTES: usize = 64 * 1024;

#[derive(Debug, Default, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ManagedPolicy {
    #[serde(default, deserialize_with = "deserialize_string")]
    id: String,
    #[serde(default, deserialize_with = "deserialize_string")]
    uuid: String,
    #[serde(default)]
    generation: u64,
    #[serde(default, deserialize_with = "deserialize_string")]
    digest: String,
    #[serde(default)]
    options: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedPolicyTransition {
    Apply,
    Unchanged,
    RejectInvalid,
    RejectRollback,
    RejectConflict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedPolicyApplyResult {
    Applied,
    Unchanged,
    RejectedInvalid,
    RejectedRollback,
    RejectedConflict,
    StoreFailed,
}

impl ManagedPolicy {
    pub fn from_wire(
        id: String,
        uuid: String,
        generation: u64,
        digest: String,
        options: BTreeMap<String, String>,
    ) -> Option<Self> {
        let policy = Self {
            id,
            uuid,
            generation,
            digest,
            options,
        };
        policy.is_valid().then_some(policy)
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn uuid(&self) -> &str {
        &self.uuid
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn options(&self) -> &BTreeMap<String, String> {
        &self.options
    }

    pub fn canonical_digest(options: &BTreeMap<String, String>) -> Option<String> {
        let encoded = serde_json::to_vec(options).ok()?;
        if encoded.len() > MANAGED_POLICY_MAX_TOTAL_BYTES {
            return None;
        }
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let digest = Sha256::digest(encoded);
        Some(
            digest
                .iter()
                .flat_map(|byte| {
                    [
                        HEX[usize::from(*byte >> 4)] as char,
                        HEX[usize::from(*byte & 0x0f)] as char,
                    ]
                })
                .collect(),
        )
    }

    fn is_valid(&self) -> bool {
        !self.id.is_empty()
            && self.id.len() <= MANAGED_POLICY_MAX_ID_BYTES
            && !self.id.chars().any(|character| character < ' ')
            && !self.uuid.is_empty()
            && self.uuid.len() <= MANAGED_POLICY_MAX_UUID_BYTES
            && !self.uuid.chars().any(|character| character < ' ')
            && self.options.len() <= MANAGED_POLICY_MAX_OPTIONS
            && self.options.iter().all(|(key, value)| {
                !key.is_empty()
                    && key.chars().count() <= 128
                    && key.len() <= MANAGED_POLICY_MAX_KEY_BYTES
                    && value.chars().count() <= 4096
                    && value.len() <= MANAGED_POLICY_MAX_VALUE_BYTES
                    && !key.chars().any(|character| character < ' ')
            })
            && self.digest.len() == 64
            && self
                .digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            && Self::canonical_digest(&self.options).as_deref() == Some(self.digest.as_str())
    }

    pub fn transition_from(&self, current: &Self) -> ManagedPolicyTransition {
        if !self.is_valid() {
            return ManagedPolicyTransition::RejectInvalid;
        }
        if current.id.is_empty() || current.id != self.id || current.uuid != self.uuid {
            return ManagedPolicyTransition::Apply;
        }
        if self.generation < current.generation {
            return ManagedPolicyTransition::RejectRollback;
        }
        if self.generation == current.generation {
            return if self.digest == current.digest && self.options == current.options {
                ManagedPolicyTransition::Unchanged
            } else {
                ManagedPolicyTransition::RejectConflict
            };
        }
        ManagedPolicyTransition::Apply
    }
}

// more variable configs
#[derive(Debug, Default, Serialize, Deserialize, Clone, PartialEq)]
pub struct Config2 {
    #[serde(default, deserialize_with = "deserialize_string")]
    rendezvous_server: String,
    #[serde(default, deserialize_with = "deserialize_i32")]
    nat_type: i32,
    #[serde(default, deserialize_with = "deserialize_i32")]
    serial: i32,
    #[serde(default, deserialize_with = "deserialize_string")]
    unlock_pin: String,
    #[serde(default, deserialize_with = "deserialize_string")]
    trusted_devices: String,

    #[serde(default)]
    socks: Option<Socks5Server>,

    // the other scalar value must before this
    #[serde(default, deserialize_with = "deserialize_hashmap_string_string")]
    pub options: HashMap<String, String>,

    // Management-owned values are separate from user options so a tombstone
    // can reveal the previous user/default value without destructive merging.
    #[serde(default)]
    managed_policy: ManagedPolicy,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone, PartialEq)]
pub struct Resolution {
    pub w: i32,
    pub h: i32,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct PeerConfig {
    #[serde(default, deserialize_with = "deserialize_vec_u8")]
    pub password: Vec<u8>,
    #[serde(default, deserialize_with = "deserialize_size")]
    pub size: Size,
    #[serde(default, deserialize_with = "deserialize_size")]
    pub size_ft: Size,
    #[serde(default, deserialize_with = "deserialize_size")]
    pub size_pf: Size,
    #[serde(
        default = "PeerConfig::default_view_style",
        deserialize_with = "PeerConfig::deserialize_view_style",
        skip_serializing_if = "String::is_empty"
    )]
    pub view_style: String,
    // Image scroll style, scrolledge, scrollbar or scroll auto
    #[serde(
        default = "PeerConfig::default_scroll_style",
        deserialize_with = "PeerConfig::deserialize_scroll_style",
        skip_serializing_if = "String::is_empty"
    )]
    pub scroll_style: String,
    #[serde(
        default = "PeerConfig::default_edge_scroll_edge_thickness",
        deserialize_with = "PeerConfig::deserialize_edge_scroll_edge_thickness"
    )]
    pub edge_scroll_edge_thickness: i32,
    #[serde(
        default = "PeerConfig::default_image_quality",
        deserialize_with = "PeerConfig::deserialize_image_quality",
        skip_serializing_if = "String::is_empty"
    )]
    pub image_quality: String,
    #[serde(
        default = "PeerConfig::default_custom_image_quality",
        deserialize_with = "PeerConfig::deserialize_custom_image_quality",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub custom_image_quality: Vec<i32>,
    #[serde(flatten)]
    pub show_remote_cursor: ShowRemoteCursor,
    #[serde(flatten)]
    pub lock_after_session_end: LockAfterSessionEnd,
    #[serde(flatten)]
    pub terminal_persistent: TerminalPersistent,
    #[serde(flatten)]
    pub privacy_mode: PrivacyMode,
    #[serde(flatten)]
    pub allow_swap_key: AllowSwapKey,
    #[serde(default, deserialize_with = "deserialize_vec_i32_string_i32")]
    pub port_forwards: Vec<(i32, String, i32)>,
    #[serde(default, deserialize_with = "deserialize_i32")]
    pub direct_failures: i32,
    #[serde(flatten)]
    pub disable_audio: DisableAudio,
    #[serde(flatten)]
    pub disable_clipboard: DisableClipboard,
    #[serde(flatten)]
    pub enable_file_copy_paste: EnableFileCopyPaste,
    #[serde(flatten)]
    pub show_quality_monitor: ShowQualityMonitor,
    #[serde(flatten)]
    pub follow_remote_cursor: FollowRemoteCursor,
    #[serde(flatten)]
    pub follow_remote_window: FollowRemoteWindow,
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub keyboard_mode: String,
    #[serde(flatten)]
    pub view_only: ViewOnly,
    #[serde(flatten)]
    pub show_my_cursor: ShowMyCursor,
    #[serde(flatten)]
    pub sync_init_clipboard: SyncInitClipboard,
    // Mouse wheel or touchpad scroll mode
    #[serde(
        default = "PeerConfig::default_reverse_mouse_wheel",
        deserialize_with = "PeerConfig::deserialize_reverse_mouse_wheel",
        skip_serializing_if = "String::is_empty"
    )]
    pub reverse_mouse_wheel: String,
    #[serde(
        default = "PeerConfig::default_displays_as_individual_windows",
        deserialize_with = "PeerConfig::deserialize_displays_as_individual_windows",
        skip_serializing_if = "String::is_empty"
    )]
    pub displays_as_individual_windows: String,
    #[serde(
        default = "PeerConfig::default_use_all_my_displays_for_the_remote_session",
        deserialize_with = "PeerConfig::deserialize_use_all_my_displays_for_the_remote_session",
        skip_serializing_if = "String::is_empty"
    )]
    pub use_all_my_displays_for_the_remote_session: String,
    #[serde(
        rename = "trackpad-speed",
        default = "PeerConfig::default_trackpad_speed",
        deserialize_with = "PeerConfig::deserialize_trackpad_speed"
    )]
    pub trackpad_speed: i32,

    #[serde(
        default,
        deserialize_with = "deserialize_hashmap_resolutions",
        skip_serializing_if = "HashMap::is_empty"
    )]
    pub custom_resolutions: HashMap<String, Resolution>,

    // The other scalar value must before this
    #[serde(
        default,
        deserialize_with = "deserialize_hashmap_string_string",
        skip_serializing_if = "HashMap::is_empty"
    )]
    pub options: HashMap<String, String>, // not use delete to represent default values
    // Various data for flutter ui
    #[serde(default, deserialize_with = "deserialize_hashmap_string_string")]
    pub ui_flutter: HashMap<String, String>,
    #[serde(default)]
    pub info: PeerInfoSerde,
    #[serde(default)]
    pub transfer: TransferSerde,
}

impl Default for PeerConfig {
    fn default() -> Self {
        Self {
            password: Default::default(),
            size: Default::default(),
            size_ft: Default::default(),
            size_pf: Default::default(),
            view_style: Self::default_view_style(),
            scroll_style: Self::default_scroll_style(),
            edge_scroll_edge_thickness: Self::default_edge_scroll_edge_thickness(),
            image_quality: Self::default_image_quality(),
            custom_image_quality: Self::default_custom_image_quality(),
            show_remote_cursor: Default::default(),
            lock_after_session_end: Default::default(),
            terminal_persistent: Default::default(),
            privacy_mode: Default::default(),
            allow_swap_key: Default::default(),
            port_forwards: Default::default(),
            direct_failures: Default::default(),
            disable_audio: Default::default(),
            disable_clipboard: Default::default(),
            enable_file_copy_paste: Default::default(),
            show_quality_monitor: Default::default(),
            follow_remote_cursor: Default::default(),
            follow_remote_window: Default::default(),
            keyboard_mode: Default::default(),
            view_only: Default::default(),
            show_my_cursor: Default::default(),
            reverse_mouse_wheel: Self::default_reverse_mouse_wheel(),
            displays_as_individual_windows: Self::default_displays_as_individual_windows(),
            use_all_my_displays_for_the_remote_session:
                Self::default_use_all_my_displays_for_the_remote_session(),
            trackpad_speed: Self::default_trackpad_speed(),
            custom_resolutions: Default::default(),
            options: Self::default_options(),
            ui_flutter: Default::default(),
            info: Default::default(),
            transfer: Default::default(),
            sync_init_clipboard: Default::default(),
        }
    }
}

#[derive(Debug, PartialEq, Default, Serialize, Deserialize, Clone)]
pub struct PeerInfoSerde {
    #[serde(default, deserialize_with = "deserialize_string")]
    pub username: String,
    #[serde(default, deserialize_with = "deserialize_string")]
    pub hostname: String,
    #[serde(default, deserialize_with = "deserialize_string")]
    pub platform: String,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone, PartialEq)]
pub struct TransferSerde {
    #[serde(default, deserialize_with = "deserialize_vec_string")]
    pub write_jobs: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_vec_string")]
    pub read_jobs: Vec<String>,
}

#[inline]
pub fn get_online_state() -> i64 {
    *ONLINE.lock().unwrap().values().max().unwrap_or(&0)
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn patch(path: PathBuf) -> PathBuf {
    if let Some(_tmp) = path.to_str() {
        #[cfg(windows)]
        return _tmp
            .replace(
                "system32\\config\\systemprofile",
                "ServiceProfiles\\LocalService",
            )
            .into();
        #[cfg(target_os = "macos")]
        return _tmp.replace("Application Support", "Preferences").into();
        #[cfg(target_os = "linux")]
        {
            if _tmp == "/root" {
                if let Ok(user) = crate::platform::linux::run_cmds_trim_newline("whoami") {
                    if user != "root" {
                        let cmd = format!("getent passwd '{}' | awk -F':' '{{print $6}}'", user);
                        if let Ok(output) = crate::platform::linux::run_cmds_trim_newline(&cmd) {
                            return output.into();
                        }
                        return format!("/home/{user}").into();
                    }
                }
            }
        }
    }
    path
}

impl Config2 {
    fn load() -> Config2 {
        let mut config = Config::load_::<Config2>("2");
        let mut store = false;
        if let Some(mut socks) = config.socks {
            match decrypt_str(&socks.password) {
                Ok(password) => socks.password = password,
                Err(err) => {
                    log::error!("Clearing invalid SOCKS password storage: {err}");
                    socks.password.clear();
                    store = true;
                }
            }
            config.socks = Some(socks);
        }
        match decrypt_str(&config.unlock_pin) {
            Ok(unlock_pin) => config.unlock_pin = unlock_pin,
            Err(err) => {
                log::error!("Clearing invalid unlock PIN storage: {err}");
                config.unlock_pin.clear();
                store = true;
            }
        }
        if config.managed_policy != ManagedPolicy::default() && !config.managed_policy.is_valid() {
            log::error!("Clearing invalid persisted managed policy state");
            config.managed_policy = ManagedPolicy::default();
            store = true;
        }
        if store {
            config.store();
        }
        config
    }

    pub fn file() -> PathBuf {
        Config::file_("2")
    }

    fn try_store(&self) -> Result<()> {
        let mut config = self.clone();
        let stored = Config::load_::<Config2>("2");
        if let Some(mut socks) = config.socks {
            let stored_password = stored
                .socks
                .as_ref()
                .map(|socks| socks.password.as_str())
                .unwrap_or_default();
            let password =
                encrypted_storage_for_plaintext(&socks.password, stored_password, ENCRYPT_MAX_LEN)
                    .map_err(|err| anyhow!("Invalid SOCKS password storage: {err}"))?;
            socks.password = password;
            config.socks = Some(socks);
        }
        let unlock_pin = encrypted_storage_for_plaintext(
            &config.unlock_pin,
            &stored.unlock_pin,
            ENCRYPT_MAX_LEN,
        )
        .map_err(|err| anyhow!("Invalid unlock PIN storage: {err}"))?;
        config.unlock_pin = unlock_pin;
        Config::try_store_(&config, "2")
    }

    fn store(&self) {
        if let Err(err) = self.try_store() {
            log::error!("Refusing to store Config2: {err}");
        }
    }

    pub fn get() -> Config2 {
        return CONFIG2.read().unwrap().clone();
    }

    pub fn set(mut cfg: Config2) -> bool {
        let mut lock = CONFIG2.write().unwrap();
        cfg.managed_policy = lock.managed_policy.clone();
        if *lock == cfg {
            return false;
        }
        *lock = cfg;
        lock.store();
        true
    }
}

fn encrypted_storage_for_plaintext(
    plain: &str,
    stored: &str,
    max_len: usize,
) -> Result<String, SecretStorageError> {
    if decrypt_str(stored).is_ok_and(|stored_plain| stored_plain == plain) {
        return Ok(stored.to_owned());
    }
    encrypt_str(plain, max_len)
}

pub fn load_path<T: serde::Serialize + serde::de::DeserializeOwned + Default + std::fmt::Debug>(
    file: PathBuf,
) -> T {
    let cfg = match confy::load_path(&file) {
        Ok(config) => config,
        Err(err) => {
            if let confy::ConfyError::GeneralLoadError(err) = &err {
                if err.kind() == std::io::ErrorKind::NotFound {
                    return T::default();
                }
            }
            log::error!("Failed to load config '{}': {}", file.display(), err);
            T::default()
        }
    };
    cfg
}

pub fn store_path_durable<T: serde::Serialize>(
    path: impl AsRef<Path>,
    cfg: &T,
) -> crate::ResultType<()> {
    let path = path.as_ref();
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("Path has no parent directory: {:?}", path))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        builder.mode(0o700);
        let _ = builder.create(parent);
    }
    #[cfg(not(unix))]
    {
        let _ = fs::create_dir_all(parent);
    }

    let content = toml::to_string_pretty(cfg)
        .map_err(|err| anyhow!("Failed to serialize config to TOML: {err}"))?;

    let rand_id: u64 = rand::random();
    let temp_file_name = format!(
        ".{}_{}_{:x}.tmp",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("config"),
        std::process::id(),
        rand_id
    );
    let temp_path = parent.join(temp_file_name);

    let write_res = (|| -> std::io::Result<()> {
        #[cfg(unix)]
        let mut file = {
            use std::os::unix::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&temp_path)?
        };
        #[cfg(not(unix))]
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temp_path)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
        }

        use std::io::Write;
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
        drop(file);

        fs::rename(&temp_path, path)?;

        #[cfg(unix)]
        {
            if let Ok(dir) = fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    })();

    if let Err(e) = write_res {
        let _ = fs::remove_file(&temp_path);
        return Err(anyhow!("Failed to durably store config at {:?}: {e}", path));
    }

    Ok(())
}

#[inline]
pub fn store_path<T: serde::Serialize>(path: PathBuf, cfg: T) -> crate::ResultType<()> {
    store_path_durable(&path, &cfg)
}

impl Config {
    fn load_<T: serde::Serialize + serde::de::DeserializeOwned + Default + std::fmt::Debug>(
        suffix: &str,
    ) -> T {
        let file = Self::file_(suffix);
        if suffix.is_empty() {
            log::trace!("Loading main configuration from {}", file.display());
        }
        load_path(file)
    }

    fn store_<T: serde::Serialize>(config: &T, suffix: &str) {
        if let Err(err) = Self::try_store_(config, suffix) {
            log::error!("Failed to store {suffix} config: {err}");
        }
    }

    fn try_store_<T: serde::Serialize>(config: &T, suffix: &str) -> Result<()> {
        let file = Self::file_(suffix);
        store_path(file, config)
    }

    fn load() -> Config {
        let mut config = Config::load_::<Config>("");
        let mut store = false;
        if let Err(err) = Self::validate_permanent_password_storage(&config) {
            log::error!("Clearing invalid permanent password storage while loading config: {err}");
            config.password.clear();
            config.salt.clear();
            store = true;
        }
        let mut id_valid = false;
        match decrypt_str(&config.enc_id) {
            Ok(id) if !id.is_empty() => {
                config.id = id;
                id_valid = true;
            }
            Ok(_) => {}
            Err(err) => log::warn!("Stored device ID is invalid: {err}"),
        }
        if !id_valid {
            log::warn!("ID is invalid, generating new one");
            for _ in 0..3 {
                if let Some(id) = Config::gen_id() {
                    config.id = id;
                    store = true;
                    break;
                } else {
                    log::error!("Failed to generate new id");
                }
            }
        }
        if store {
            config.store();
        }
        config
    }

    fn validate_permanent_password_storage(config: &Config) -> Result<()> {
        if config.password.is_empty() {
            return Ok(());
        }

        Self::ensure_permanent_password_hash_salt(config)?;
        if decode_permanent_password_h1_from_storage(&config.password).is_none() {
            return Err(anyhow!(
                "Permanent password storage is not in the current format"
            ));
        }

        Ok(())
    }

    fn ensure_permanent_password_hash_salt(config: &Config) -> Result<()> {
        if config.salt.is_empty() {
            return Err(anyhow!(
                "Permanent password hash storage requires a non-empty salt"
            ));
        }
        Ok(())
    }

    fn ensure_permanent_password_salt(config: &mut Config) {
        if config.salt.is_empty() {
            config.salt = Config::get_auto_password(DEFAULT_SALT_LEN);
        }
    }

    fn prepare_config_for_store(config: &mut Config) {
        match Self::validate_permanent_password_storage(config) {
            Ok(_) => {}
            Err(err) => {
                log::error!(
                    "Clearing invalid permanent password storage before storing config: {err}"
                );
                config.password.clear();
                config.salt.clear();
            }
        }
    }

    pub fn try_store(&self) -> Result<()> {
        let mut config = self.clone();
        Self::prepare_config_for_store(&mut config);
        if config.key_pair.0.is_empty() {
            if let Some(kp) = KEY_PAIR.lock().unwrap().as_ref() {
                config.key_pair = kp.clone();
            }
        }
        if decrypt_str(&config.enc_id).as_deref() != Ok(config.id.as_str()) {
            let enc_id = encrypt_str(&config.id, ENCRYPT_MAX_LEN).map_err(|err| {
                anyhow!("Refusing to store config because the device ID cannot be encrypted: {err}")
            })?;
            config.enc_id = enc_id;
        }
        config.id = "".to_owned();
        Self::try_store_(&config, "")
    }

    fn store(&self) {
        if let Err(err) = self.try_store() {
            log::error!("Failed to store Config: {err}");
        }
    }

    pub fn file() -> PathBuf {
        Self::file_("")
    }

    fn file_(suffix: &str) -> PathBuf {
        let name = format!("{}{}", *APP_NAME.read().unwrap(), suffix);
        Config::with_extension(Self::path(name))
    }

    pub fn is_empty(&self) -> bool {
        (self.id.is_empty() && self.enc_id.is_empty()) || self.key_pair.0.is_empty()
    }

    /// Get the user's home directory for configuration purposes.
    ///
    /// # Security Note
    /// This function uses `dirs_next::home_dir()` which reads the `$HOME` environment
    /// variable on Unix systems. This is acceptable for user-space operations (config
    /// file storage, logging) where the user may intentionally redirect their home
    /// directory.
    ///
    /// **DO NOT use this function in privileged contexts** (e.g., code executed via
    /// `gtk_sudo` or system services running as root). For privileged operations on
    /// Linux, use `crate::platform::linux::get_home_dir_trusted()` which bypasses
    /// the `$HOME` environment variable and queries the system password database
    /// directly via `getpwuid`.
    ///
    /// Using `$HOME` in privileged contexts creates a confused-deputy vulnerability
    /// where an attacker can manipulate the environment variable to inject malicious
    /// paths into privileged operations.
    pub fn get_home() -> PathBuf {
        #[cfg(any(target_os = "android", target_os = "ios"))]
        return PathBuf::from(APP_HOME_DIR.read().unwrap().as_str());
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            if let Some(path) = dirs_next::home_dir() {
                patch(path)
            } else if let Ok(path) = std::env::current_dir() {
                path
            } else {
                std::env::temp_dir()
            }
        }
    }

    pub fn path<P: AsRef<Path>>(p: P) -> PathBuf {
        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            let mut path: PathBuf = APP_DIR.read().unwrap().clone().into();
            path.push(p);
            return path;
        }
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            #[cfg(not(target_os = "macos"))]
            let org = "".to_owned();
            #[cfg(target_os = "macos")]
            let org = ORG.read().unwrap().clone();
            // /var/root for root
            if let Some(project) =
                directories_next::ProjectDirs::from("", &org, &APP_NAME.read().unwrap())
            {
                let mut path = patch(project.config_dir().to_path_buf());
                path.push(p);
                return path;
            }
            "".into()
        }
    }

    /// Get the log directory path.
    ///
    /// # Security Note
    /// On macOS, this function uses `dirs_next::home_dir()` which reads the `$HOME`
    /// environment variable. On Linux/Android, it uses `Self::get_home()`.
    /// See [`Self::get_home()`] for security considerations regarding `$HOME` usage.
    #[allow(unreachable_code)]
    pub fn log_path() -> PathBuf {
        #[cfg(target_os = "macos")]
        {
            if let Some(path) = dirs_next::home_dir().as_mut() {
                path.push(format!("Library/Logs/{}", *APP_NAME.read().unwrap()));
                return path.clone();
            }
        }
        #[cfg(target_os = "linux")]
        {
            let mut path = Self::get_home();
            path.push(format!(".local/share/logs/{}", *APP_NAME.read().unwrap()));
            std::fs::create_dir_all(&path).ok();
            return path;
        }
        #[cfg(target_os = "android")]
        {
            let mut path = Self::get_home();
            path.push(format!("{}/Logs", *APP_NAME.read().unwrap()));
            std::fs::create_dir_all(&path).ok();
            return path;
        }
        if let Some(path) = Self::path("").parent() {
            let mut path: PathBuf = path.into();
            path.push("log");
            return path;
        }
        "".into()
    }

    pub fn ipc_path(postfix: &str) -> String {
        #[cfg(windows)]
        {
            // \\ServerName\pipe\PipeName
            // where ServerName is either the name of a remote computer or a period, to specify the local computer.
            // https://docs.microsoft.com/en-us/windows/win32/ipc/pipe-names
            format!(
                "\\\\.\\pipe\\{}\\query{}",
                *APP_NAME.read().unwrap(),
                postfix
            )
        }
        #[cfg(not(windows))]
        {
            #[cfg(target_os = "android")]
            use std::os::unix::fs::PermissionsExt;
            #[cfg(target_os = "android")]
            let mut path: PathBuf =
                format!("{}/{}", *APP_DIR.read().unwrap(), *APP_NAME.read().unwrap()).into();
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            let mut path: PathBuf = {
                let uid = unsafe { libc::geteuid() as u32 };
                ipc_parent_dir_for_uid(uid, postfix).into()
            };
            #[cfg(not(any(target_os = "android", target_os = "linux", target_os = "macos")))]
            let mut path: PathBuf = format!("/tmp/{}", *APP_NAME.read().unwrap()).into();
            // Android stores IPC sockets under app-controlled directories. Create the IPC parent
            // dir and enforce the expected mode here. On other Unix platforms, `ipc_path()` is
            // intentionally side-effect free (no mkdir/chmod); callers should enforce directory and
            // socket permissions at the IPC server boundary.
            #[cfg(target_os = "android")]
            {
                fs::create_dir_all(&path).ok();
                let path_mode = if is_service_ipc_postfix(postfix) {
                    0o0711
                } else {
                    0o0700
                };
                fs::set_permissions(&path, fs::Permissions::from_mode(path_mode)).ok();
            }
            path.push(format!("ipc{postfix}"));
            path.to_str().unwrap_or("").to_owned()
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub fn ipc_path_for_uid(uid: u32, postfix: &str) -> String {
        let parent = ipc_parent_dir_for_uid(uid, postfix);
        format!("{parent}/ipc{postfix}")
    }

    pub fn icon_path() -> PathBuf {
        let mut path = Self::path("icons");
        if fs::create_dir_all(&path).is_err() {
            path = std::env::temp_dir();
        }
        path
    }

    #[inline]
    pub fn get_any_listen_addr(is_ipv4: bool) -> SocketAddr {
        if is_ipv4 {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        }
    }

    pub fn get_rendezvous_server() -> String {
        let mut rendezvous_server = EXE_RENDEZVOUS_SERVER.read().unwrap().clone();
        if rendezvous_server.is_empty() {
            rendezvous_server = Self::get_option("custom-rendezvous-server");
        }
        if rendezvous_server.is_empty() {
            rendezvous_server = PROD_RENDEZVOUS_SERVER.read().unwrap().clone();
        }
        if rendezvous_server.is_empty() {
            rendezvous_server = CONFIG2.read().unwrap().rendezvous_server.clone();
        }
        if rendezvous_server.is_empty() {
            rendezvous_server = Self::get_rendezvous_servers()
                .drain(..)
                .next()
                .unwrap_or_default();
        }
        if !rendezvous_server.is_empty() && !rendezvous_server.contains(':') {
            rendezvous_server = format!("{rendezvous_server}:{RENDEZVOUS_PORT}");
        }
        rendezvous_server
    }

    pub fn get_rendezvous_servers() -> Vec<String> {
        let s = EXE_RENDEZVOUS_SERVER.read().unwrap().clone();
        if !s.is_empty() {
            return vec![s];
        }
        let s = Self::get_option("custom-rendezvous-server");
        if !s.is_empty() {
            return vec![s];
        }
        let s = PROD_RENDEZVOUS_SERVER.read().unwrap().clone();
        if !s.is_empty() {
            return vec![s];
        }
        let serial_obsolute = CONFIG2.read().unwrap().serial > SERIAL;
        if serial_obsolute {
            let ss: Vec<String> = Self::get_option("rendezvous-servers")
                .split(',')
                .filter(|x| x.contains('.'))
                .map(|x| x.to_owned())
                .collect();
            if !ss.is_empty() {
                return ss;
            }
        }
        return RENDEZVOUS_SERVERS.read().unwrap().clone();
    }

    pub fn reset_online() {
        *ONLINE.lock().unwrap() = Default::default();
    }

    pub fn update_latency(host: &str, latency: i64) {
        ONLINE.lock().unwrap().insert(host.to_owned(), latency);
        let mut host = "".to_owned();
        let mut delay = i64::MAX;
        for (tmp_host, tmp_delay) in ONLINE.lock().unwrap().iter() {
            if tmp_delay > &0 && tmp_delay < &delay {
                delay = *tmp_delay;
                host = tmp_host.to_string();
            }
        }
        if !host.is_empty() {
            let mut config = CONFIG2.write().unwrap();
            if host != config.rendezvous_server {
                log::debug!("Update rendezvous_server in config to {}", host);
                log::debug!("{:?}", *ONLINE.lock().unwrap());
                config.rendezvous_server = host;
                config.store();
            }
        }
    }

    pub fn set_id(id: &str) {
        let mut config = CONFIG.write().unwrap();
        if id == config.id {
            return;
        }
        config.id = id.into();
        config.store();
    }

    pub fn set_nat_type(nat_type: i32) {
        let mut config = CONFIG2.write().unwrap();
        if nat_type == config.nat_type {
            return;
        }
        config.nat_type = nat_type;
        config.store();
    }

    pub fn get_nat_type() -> i32 {
        CONFIG2.read().unwrap().nat_type
    }

    pub fn set_serial(serial: i32) {
        let mut config = CONFIG2.write().unwrap();
        if serial == config.serial {
            return;
        }
        config.serial = serial;
        config.store();
    }

    pub fn get_serial() -> i32 {
        std::cmp::max(CONFIG2.read().unwrap().serial, SERIAL)
    }

    #[cfg(any(target_os = "android", target_os = "ios"))]
    fn gen_id() -> Option<String> {
        Self::get_auto_id()
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    fn gen_id() -> Option<String> {
        let hostname_as_id = BUILTIN_SETTINGS
            .read()
            .unwrap()
            .get(keys::OPTION_ALLOW_HOSTNAME_AS_ID)
            .map(|v| option2bool(keys::OPTION_ALLOW_HOSTNAME_AS_ID, v))
            .unwrap_or(false);
        if hostname_as_id {
            match whoami::hostname() {
                Ok(h) => Some(h.replace(" ", "-")),
                Err(e) => {
                    log::warn!("Failed to get hostname, \"{}\", fallback to auto id", e);
                    Self::get_auto_id()
                }
            }
        } else {
            Self::get_auto_id()
        }
    }

    fn get_auto_id() -> Option<String> {
        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            return Some(
                rand::rng()
                    .random_range(1_000_000_000..2_000_000_000)
                    .to_string(),
            );
        }

        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            let mut id = 0u32;
            if let Ok(Some(ma)) = mac_address::get_mac_address() {
                for x in &ma.bytes()[2..] {
                    id = (id << 8) | (*x as u32);
                }
                id &= 0x1FFFFFFF;
                log::info!("Generated id {}", id);
                Some(id.to_string())
            } else {
                None
            }
        }
    }

    pub fn get_auto_password(length: usize) -> String {
        Self::get_auto_password_with_chars(length, CHARS)
    }

    pub fn get_auto_numeric_password(length: usize) -> String {
        Self::get_auto_password_with_chars(length, NUM_CHARS)
    }

    fn get_auto_password_with_chars(length: usize, chars: &[char]) -> String {
        let mut rng = rand::rng();
        (0..length)
            .map(|_| chars[rng.random_range(0..chars.len())])
            .collect()
    }

    pub fn get_key_confirmed() -> bool {
        CONFIG.read().unwrap().key_confirmed
    }

    pub fn set_key_confirmed(v: bool) {
        let mut config = CONFIG.write().unwrap();
        if config.key_confirmed == v {
            return;
        }
        config.key_confirmed = v;
        if !v {
            config.keys_confirmed = Default::default();
        }
        config.store();
    }

    pub fn get_host_key_confirmed(host: &str) -> bool {
        matches!(CONFIG.read().unwrap().keys_confirmed.get(host), Some(true))
    }

    pub fn set_host_key_confirmed(host: &str, v: bool) {
        if Self::get_host_key_confirmed(host) == v {
            return;
        }
        let mut config = CONFIG.write().unwrap();
        config.keys_confirmed.insert(host.to_owned(), v);
        config.store();
    }

    pub fn get_key_pair() -> KeyPair {
        // lock here to make sure no gen_keypair more than once
        // no use of CONFIG directly here to ensure no recursive calling in Config::load because of password dec which calling this function
        let mut lock = KEY_PAIR.lock().unwrap();
        if let Some(p) = lock.as_ref() {
            return p.clone();
        }
        let mut config = Config::load_::<Config>("");
        if config.key_pair.0.is_empty() {
            log::info!("Generated new keypair for id: {}", config.id);
            let (pk, sk) = sign::gen_keypair();
            let key_pair: KeyPair = (sk.0.to_vec(), pk.0.into());
            config.key_pair = key_pair.clone();
            let file = Config::file_("");
            if let Err(err) = store_path_durable(&file, &config) {
                log::error!(
                    "Failed to durably persist generated keypair to {}: {err}",
                    file.display()
                );
                return (Vec::new(), Vec::new());
            }
            log::info!("Successfully persisted new keypair to {}", file.display());
            *lock = Some(key_pair.clone());
            return key_pair;
        }
        *lock = Some(config.key_pair.clone());
        config.key_pair
    }

    #[cfg(test)]
    pub(crate) fn reset_key_pair_cache_for_test() {
        *KEY_PAIR.lock().unwrap() = None;
    }

    pub fn get_cached_pk() -> Option<Vec<u8>> {
        KEY_PAIR.lock().unwrap().clone().map(|k| k.1)
    }

    pub fn no_register_device() -> bool {
        BUILTIN_SETTINGS
            .read()
            .unwrap()
            .get(keys::OPTION_REGISTER_DEVICE)
            .map(|v| v == "N")
            .unwrap_or(false)
    }

    pub fn is_disable_change_permanent_password() -> bool {
        BUILTIN_SETTINGS
            .read()
            .unwrap()
            .get(keys::OPTION_DISABLE_CHANGE_PERMANENT_PASSWORD)
            .map(|v| v == "Y")
            .unwrap_or(false)
    }

    pub fn is_disable_change_id() -> bool {
        BUILTIN_SETTINGS
            .read()
            .unwrap()
            .get(keys::OPTION_DISABLE_CHANGE_ID)
            .map(|v| v == "Y")
            .unwrap_or(false)
    }

    pub fn is_disable_unlock_pin() -> bool {
        BUILTIN_SETTINGS
            .read()
            .unwrap()
            .get(keys::OPTION_DISABLE_UNLOCK_PIN)
            .map(|v| v == "Y")
            .unwrap_or(false)
    }

    pub fn get_id() -> String {
        let mut id = CONFIG.read().unwrap().id.clone();
        if id.is_empty() {
            if let Some(tmp) = Config::gen_id() {
                id = tmp;
                Config::set_id(&id);
            }
        }
        id
    }

    pub fn get_id_or(b: String) -> String {
        let a = CONFIG.read().unwrap().id.clone();
        if a.is_empty() {
            b
        } else {
            a
        }
    }

    pub fn get_options() -> HashMap<String, String> {
        let mut res = DEFAULT_SETTINGS.read().unwrap().clone();
        {
            let config = CONFIG2
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            res.extend(config.options.clone());
            res.extend(
                config
                    .managed_policy
                    .options
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone())),
            );
        }
        res.extend(OVERWRITE_SETTINGS.read().unwrap().clone());
        res
    }

    #[inline]
    fn purify_options(v: &mut HashMap<String, String>) {
        v.retain(|k, v| is_option_can_save(&OVERWRITE_SETTINGS, k, &DEFAULT_SETTINGS, v));
    }

    pub fn set_options(mut v: HashMap<String, String>) {
        Self::purify_options(&mut v);
        let mut config = CONFIG2.write().unwrap();
        // UI callers submit the effective map. Do not copy Management-owned
        // values into the user layer, and retain any user values hidden below
        // the managed layer so a future tombstone can reveal them.
        for key in config.managed_policy.options.keys() {
            if let Some(user_value) = config.options.get(key) {
                v.insert(key.clone(), user_value.clone());
            } else {
                v.remove(key);
            }
        }
        if config.options == v {
            return;
        }
        config.options = v;
        config.store();
    }

    pub fn get_option(k: &str) -> String {
        if let Some(value) = OVERWRITE_SETTINGS
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(k)
        {
            return value.clone();
        }
        let configured = {
            let config = CONFIG2
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            config
                .managed_policy
                .options
                .get(k)
                .or_else(|| config.options.get(k))
                .cloned()
        };
        configured
            .or_else(|| {
                DEFAULT_SETTINGS
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .get(k)
                    .cloned()
            })
            .unwrap_or_default()
    }

    pub fn get_managed_policy() -> ManagedPolicy {
        CONFIG2
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .managed_policy
            .clone()
    }

    pub fn apply_managed_policy(policy: ManagedPolicy) -> ManagedPolicyApplyResult {
        let mut config = CONFIG2
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match policy.transition_from(&config.managed_policy) {
            ManagedPolicyTransition::Unchanged => ManagedPolicyApplyResult::Unchanged,
            ManagedPolicyTransition::RejectInvalid => ManagedPolicyApplyResult::RejectedInvalid,
            ManagedPolicyTransition::RejectRollback => ManagedPolicyApplyResult::RejectedRollback,
            ManagedPolicyTransition::RejectConflict => ManagedPolicyApplyResult::RejectedConflict,
            ManagedPolicyTransition::Apply => {
                let mut next = config.clone();
                next.managed_policy = policy;
                if let Err(err) = next.try_store() {
                    log::error!("Failed to persist managed policy: {err}");
                    return ManagedPolicyApplyResult::StoreFailed;
                }
                *config = next;
                ManagedPolicyApplyResult::Applied
            }
        }
    }

    pub fn get_bool_option(k: &str) -> bool {
        option2bool(k, &Self::get_option(k))
    }

    pub fn set_option(k: String, v: String) {
        if CONFIG2
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .managed_policy
            .options
            .contains_key(&k)
        {
            return;
        }
        if !is_option_can_save(&OVERWRITE_SETTINGS, &k, &DEFAULT_SETTINGS, &v) {
            let mut config = CONFIG2.write().unwrap();
            if config.options.remove(&k).is_some() {
                config.store();
            }
            return;
        }
        let mut config = CONFIG2.write().unwrap();
        let v2 = if v.is_empty() { None } else { Some(&v) };
        if v2 != config.options.get(&k) {
            if v2.is_none() {
                config.options.remove(&k);
            } else {
                config.options.insert(k, v);
            }
            config.store();
        }
    }

    pub fn update_id() {
        // to-do: how about if one ip register a lot of ids?
        let id = Self::get_id();
        let mut rng = rand::rng();
        let new_id = rng.random_range(1_000_000_000..2_000_000_000).to_string();
        Config::set_id(&new_id);
        log::info!("id updated from {} to {}", id, new_id);
    }

    /// Sets the local permanent password.
    ///
    /// Returns `true` when the password is accepted or already matches the effective
    /// preset password. Returns `false` when changing the password is disabled or
    /// the new password cannot be prepared for storage.
    pub fn set_permanent_password(password: &str) -> bool {
        if Self::is_disable_change_permanent_password() {
            return false;
        }
        let (preset_storage, preset_salt) = Self::get_preset_password_storage_and_salt();
        if preset_permanent_password_storage_matches_plain(&preset_storage, &preset_salt, password)
            && CONFIG.read().unwrap().password.is_empty()
        {
            return true;
        }

        let mut config = CONFIG.write().unwrap();

        let stored = if password.is_empty() {
            Some(String::new())
        } else {
            Self::compute_permanent_password_storage_for_update(&mut config, password)
        };
        let Some(stored) = stored else {
            log::error!("Failed to compute permanent password storage; refusing update");
            return false;
        };
        if stored == config.password {
            return true;
        }
        config.password = stored;
        config.store();
        Self::clear_trusted_devices();
        true
    }

    fn compute_permanent_password_storage_for_update(
        config: &mut Config,
        password: &str,
    ) -> Option<String> {
        // Keep salt stable for user-initiated permanent password updates.
        // Salt should only change when service->user sync updates storage and salt as a pair.
        Self::ensure_permanent_password_salt(config);
        let h1 = compute_permanent_password_h1(password, &config.salt);
        encode_permanent_password_encrypted_storage_from_h1(&h1)
    }

    /// Returns the locally persisted permanent password storage and salt (NOT the hard/preset one).
    ///
    /// This function is side-effect free:
    /// - It does NOT call `get_salt()` (which may auto-generate salt).
    /// - It returns a consistent snapshot under a single lock.
    pub fn get_local_permanent_password_storage_and_salt() -> (String, String) {
        let config = CONFIG.read().unwrap();
        (config.password.clone(), config.salt.clone())
    }

    /// Persist permanent password storage and salt from service->user config sync.
    pub fn set_permanent_password_storage_for_sync(
        storage: &str,
        salt: &str,
    ) -> crate::ResultType<bool> {
        let mut config = CONFIG.write().unwrap();
        if !Self::apply_permanent_password_storage_for_sync(&mut config, storage, salt)? {
            return Ok(false);
        }

        config.store();
        Self::clear_trusted_devices();
        Ok(true)
    }

    fn apply_permanent_password_storage_for_sync(
        config: &mut Config,
        storage: &str,
        salt: &str,
    ) -> Result<bool> {
        if storage.is_empty() {
            if config.password.is_empty() && (salt.is_empty() || config.salt == salt) {
                return Ok(false);
            }
            config.password.clear();
            if !salt.is_empty() {
                config.salt = salt.to_owned();
            }
            return Ok(true);
        }
        if salt.is_empty() {
            return Err(anyhow!(
                "Refusing to persist permanent password storage without salt"
            ));
        }
        if decode_permanent_password_h1_from_storage(storage).is_none() {
            log::error!("Rejecting non-current permanent password storage sync payload");
            return Err(anyhow!("Invalid permanent password storage sync payload"));
        }
        if config.password == storage && config.salt == salt {
            return Ok(false);
        }

        config.password = storage.to_owned();
        config.salt = salt.to_owned();
        Ok(true)
    }

    pub fn has_permanent_password() -> bool {
        let (local_storage, local_salt) = Self::get_local_permanent_password_storage_and_salt();
        if !local_storage.is_empty() {
            return local_permanent_password_storage_is_usable_for_auth(
                &local_storage,
                &local_salt,
            );
        }
        Self::has_usable_preset_password()
    }

    fn has_usable_preset_password() -> bool {
        let (preset_storage, preset_salt) = Self::get_preset_password_storage_and_salt();
        preset_permanent_password_storage_is_usable_for_auth(&preset_storage, &preset_salt)
    }

    pub fn is_using_preset_password() -> bool {
        let (local_storage, _) = Self::get_local_permanent_password_storage_and_salt();
        local_storage.is_empty() && Self::has_usable_preset_password()
    }

    pub fn get_preset_password_storage_and_salt() -> (String, String) {
        let hard_settings = HARD_SETTINGS.read().unwrap();
        let storage = hard_settings.get("password").cloned().unwrap_or_default();
        let salt = hard_settings.get("salt").cloned().unwrap_or_default();
        (storage, salt)
    }

    pub fn get_effective_permanent_password_salt() -> String {
        let (local_storage, local_salt) = Self::get_local_permanent_password_storage_and_salt();
        if !local_storage.is_empty() {
            if local_permanent_password_storage_is_usable_for_auth(&local_storage, &local_salt) {
                return Self::get_salt();
            }
            return String::new();
        }
        let (preset_storage, preset_salt) = Self::get_preset_password_storage_and_salt();
        if preset_permanent_password_storage_is_usable_for_auth(&preset_storage, &preset_salt) {
            return preset_salt;
        }
        String::new()
    }

    pub fn has_local_permanent_password() -> bool {
        let (local_storage, local_salt) = Self::get_local_permanent_password_storage_and_salt();
        local_permanent_password_storage_is_usable_for_auth(&local_storage, &local_salt)
    }

    pub fn set_salt(salt: &str) {
        let mut config = CONFIG.write().unwrap();
        if salt == config.salt {
            return;
        }
        if !config.password.is_empty() {
            if config.salt.is_empty() {
                log::warn!("Salt is empty while current permanent password storage is present");
            } else {
                log::error!("Refusing to change salt without replacing permanent password storage");
                return;
            }
        }
        config.salt = salt.into();
        config.store();
    }

    pub fn get_salt() -> String {
        let config = CONFIG.read().unwrap();
        let mut salt = config.salt.clone();
        if salt.is_empty() {
            drop(config);
            salt = Config::get_auto_password(DEFAULT_SALT_LEN);
            Config::set_salt(&salt);
        }
        salt
    }

    pub fn set_socks(socks: Option<Socks5Server>) {
        if OVERWRITE_SETTINGS
            .read()
            .unwrap()
            .contains_key(keys::OPTION_PROXY_URL)
        {
            return;
        }

        let mut config = CONFIG2.write().unwrap();
        if config.socks == socks {
            return;
        }
        if config.socks.is_none() {
            let equal_to_default = |key: &str, value: &str| {
                DEFAULT_SETTINGS
                    .read()
                    .unwrap()
                    .get(key)
                    .is_some_and(|x| *x == value)
            };
            let contains_url = DEFAULT_SETTINGS
                .read()
                .unwrap()
                .get(keys::OPTION_PROXY_URL)
                .is_some();
            let url = equal_to_default(
                keys::OPTION_PROXY_URL,
                &socks.clone().unwrap_or_default().proxy,
            );
            let username = equal_to_default(
                keys::OPTION_PROXY_USERNAME,
                &socks.clone().unwrap_or_default().username,
            );
            let password = equal_to_default(
                keys::OPTION_PROXY_PASSWORD,
                &socks.clone().unwrap_or_default().password,
            );
            if contains_url && url && username && password {
                return;
            }
        }
        config.socks = socks;
        config.store();
    }

    #[inline]
    fn get_socks_from_custom_client_advanced_settings(
        settings: &HashMap<String, String>,
    ) -> Option<Socks5Server> {
        let url = settings.get(keys::OPTION_PROXY_URL)?;
        Some(Socks5Server {
            proxy: url.to_owned(),
            username: settings
                .get(keys::OPTION_PROXY_USERNAME)
                .map(|x| x.to_string())
                .unwrap_or_default(),
            password: settings
                .get(keys::OPTION_PROXY_PASSWORD)
                .map(|x| x.to_string())
                .unwrap_or_default(),
        })
    }

    pub fn get_socks() -> Option<Socks5Server> {
        Self::get_socks_from_custom_client_advanced_settings(&OVERWRITE_SETTINGS.read().unwrap())
            .or(CONFIG2.read().unwrap().socks.clone())
            .or(Self::get_socks_from_custom_client_advanced_settings(
                &DEFAULT_SETTINGS.read().unwrap(),
            ))
    }

    #[inline]
    pub fn is_proxy() -> bool {
        Self::get_network_type() != NetworkType::Direct
    }

    pub fn get_network_type() -> NetworkType {
        if OVERWRITE_SETTINGS
            .read()
            .unwrap()
            .get(keys::OPTION_PROXY_URL)
            .is_some()
        {
            return NetworkType::ProxySocks;
        }
        if CONFIG2.read().unwrap().socks.is_some() {
            return NetworkType::ProxySocks;
        }
        if DEFAULT_SETTINGS
            .read()
            .unwrap()
            .get(keys::OPTION_PROXY_URL)
            .is_some()
        {
            return NetworkType::ProxySocks;
        }
        NetworkType::Direct
    }

    pub fn get_unlock_pin() -> String {
        if Self::is_disable_unlock_pin() {
            return String::new();
        }
        CONFIG2.read().unwrap().unlock_pin.clone()
    }

    pub fn set_unlock_pin(pin: &str) {
        if Self::is_disable_unlock_pin() {
            return;
        }
        let mut config = CONFIG2.write().unwrap();
        if pin == config.unlock_pin {
            return;
        }
        config.unlock_pin = pin.to_string();
        config.store();
    }

    pub fn get_trusted_devices_json() -> String {
        serde_json::to_string(&Self::get_trusted_devices()).unwrap_or_default()
    }

    pub fn get_trusted_devices() -> Vec<TrustedDevice> {
        let (devices, synced) = TRUSTED_DEVICES.read().unwrap().clone();
        if synced {
            return devices;
        }
        let storage = CONFIG2.read().unwrap().trusted_devices.clone();
        let plaintext = match decrypt_str(&storage) {
            Ok(plaintext) => plaintext,
            Err(err) => {
                log::error!("Clearing invalid trusted-device storage: {err}");
                Self::set_trusted_devices(Vec::new());
                return Vec::new();
            }
        };
        let mut devices: Vec<TrustedDevice> = serde_json::from_str(&plaintext).unwrap_or_default();
        let len = devices.len();
        devices.retain(|d| !d.is_expired());
        if devices.len() != len {
            Self::set_trusted_devices(devices.clone());
        }
        *TRUSTED_DEVICES.write().unwrap() = (devices.clone(), true);
        devices
    }

    pub fn try_set_trusted_devices(mut trusted_devices: Vec<TrustedDevice>) -> ResultType<()> {
        trusted_devices.retain(|d| !d.is_expired());
        let devices = serde_json::to_string(&trusted_devices)
            .map_err(|err| anyhow!("Failed to serialize trusted devices: {err}"))?;
        let max_len = 1024 * 1024;
        if devices.len() > max_len {
            bail!("Trusted devices payload exceeds maximum allowed size ({max_len} bytes)");
        }
        let encrypted_devices = encrypt_str(&devices, max_len)
            .map_err(|err| anyhow!("Failed to encrypt trusted devices: {err}"))?;
        let mut config = CONFIG2
            .write()
            .map_err(|_| anyhow!("CONFIG2 lock poisoned"))?;
        let previous_encrypted = config.trusted_devices.clone();
        config.trusted_devices = encrypted_devices;
        if let Err(err) = config.try_store() {
            config.trusted_devices = previous_encrypted;
            bail!("Failed to persist trusted devices to storage: {err}");
        }
        if let Ok(mut cache) = TRUSTED_DEVICES.write() {
            *cache = (trusted_devices, true);
        }
        Ok(())
    }

    pub fn set_trusted_devices(trusted_devices: Vec<TrustedDevice>) {
        if let Err(err) = Self::try_set_trusted_devices(trusted_devices) {
            log::error!("Failed to set trusted devices: {err}");
        }
    }

    pub fn add_trusted_device(mut device: TrustedDevice) -> ResultType<()> {
        device.ensure_fingerprint();
        let mut devices = Self::get_trusted_devices();
        devices.retain(|d| {
            if !device.device_id.is_empty() && !d.device_id.is_empty() {
                d.device_id != device.device_id
            } else if !device.public_key_fingerprint.is_empty()
                && !d.public_key_fingerprint.is_empty()
            {
                d.public_key_fingerprint != device.public_key_fingerprint
            } else if !device.hwid.is_empty() && !d.hwid.is_empty() {
                d.hwid != device.hwid
            } else {
                true
            }
        });
        devices.push(device);
        Self::try_set_trusted_devices(devices)
    }

    pub fn remove_trusted_devices<S: AsRef<str>>(device_ids: &[S]) -> ResultType<()> {
        let mut devices = Self::get_trusted_devices();
        devices.retain(|d| !device_ids.iter().any(|id| id.as_ref() == d.device_id));
        Self::try_set_trusted_devices(devices)
    }

    pub fn remove_trusted_devices_by_hwid(hwids: &[Bytes]) -> ResultType<()> {
        let mut devices = Self::get_trusted_devices();
        devices.retain(|d| !hwids.contains(&d.hwid));
        Self::try_set_trusted_devices(devices)
    }

    pub fn try_clear_trusted_devices() -> ResultType<()> {
        Self::try_set_trusted_devices(Default::default())
    }

    pub fn clear_trusted_devices() {
        if let Err(err) = Self::try_clear_trusted_devices() {
            log::error!("Failed to clear trusted devices: {err}");
        }
    }

    pub fn get() -> Config {
        return CONFIG.read().unwrap().clone();
    }

    pub fn set(mut cfg: Config) -> bool {
        Self::prepare_config_for_store(&mut cfg);
        let mut lock = CONFIG.write().unwrap();
        if *lock == cfg {
            return false;
        }
        let permanent_credentials_changed = lock.password != cfg.password || lock.salt != cfg.salt;
        *lock = cfg;
        lock.store();
        // Drop CONFIG lock before acquiring KEY_PAIR lock to avoid potential deadlock.
        let new_key_pair = lock.key_pair.clone();
        drop(lock);
        Self::invalidate_key_pair_cache_if_changed(&new_key_pair);
        if permanent_credentials_changed {
            Self::clear_trusted_devices();
        }
        true
    }

    /// Invalidate KEY_PAIR cache if it differs from the new key_pair.
    /// Use None to invalidate the cache instead of Some(key_pair).
    /// If we use Some with an empty key_pair, get_key_pair() would always return
    /// the empty key_pair from cache without regenerating.
    /// By clearing the cache, get_key_pair() will reload and regenerate if needed.
    fn invalidate_key_pair_cache_if_changed(new_key_pair: &KeyPair) {
        if new_key_pair.0.is_empty() {
            return;
        }
        let mut key_pair_cache = KEY_PAIR.lock().unwrap();
        if let Some(cached) = key_pair_cache.as_ref() {
            if cached != new_key_pair {
                *key_pair_cache = None;
                log::info!("key pair cache invalidated");
            }
        }
    }

    fn with_extension(path: PathBuf) -> PathBuf {
        let ext = path.extension();
        if let Some(ext) = ext {
            let ext = format!("{}.toml", ext.to_string_lossy());
            path.with_extension(ext)
        } else {
            path.with_extension("toml")
        }
    }
}

const PEERS: &str = "peers";

impl PeerConfig {
    pub fn load(id: &str) -> PeerConfig {
        let _lock = CONFIG.read().unwrap();
        match confy::load_path(Self::path(id)) {
            Ok(config) => {
                let mut config: PeerConfig = config;
                let mut store = false;
                match decrypt_vec(&config.password) {
                    Ok(password) => config.password = password,
                    Err(err) => {
                        log::error!("Clearing invalid password storage for peer '{id}': {err}");
                        config.password.clear();
                        store = true;
                    }
                }
                for opt in ["rdp_password", "os-username", "os-password"] {
                    if let Some(v) = config.options.get_mut(opt) {
                        match decrypt_str(v) {
                            Ok(plaintext) => *v = plaintext,
                            Err(err) => {
                                log::error!(
                                    "Clearing invalid '{opt}' storage for peer '{id}': {err}"
                                );
                                v.clear();
                                store = true;
                            }
                        }
                    }
                }
                if store {
                    config.store_(id);
                }
                config
            }
            Err(err) => {
                if let confy::ConfyError::GeneralLoadError(err) = &err {
                    if err.kind() == std::io::ErrorKind::NotFound {
                        return Default::default();
                    }
                }
                log::error!("Failed to load peer config '{}': {}", id, err);
                Default::default()
            }
        }
    }

    pub fn store(&self, id: &str) {
        let _lock = CONFIG.read().unwrap();
        self.store_(id);
    }

    fn store_(&self, id: &str) {
        let mut config = self.clone();
        let Ok(password) = encrypt_vec(&config.password, ENCRYPT_MAX_LEN) else {
            log::error!("Refusing to store peer '{id}': password encryption failed");
            return;
        };
        config.password = password;
        for opt in ["rdp_password", "os-username", "os-password"] {
            if let Some(v) = config.options.get_mut(opt) {
                let Ok(storage) = encrypt_str(v, ENCRYPT_MAX_LEN) else {
                    log::error!("Refusing to store peer '{id}': '{opt}' encryption failed");
                    return;
                };
                *v = storage;
            }
        }
        if let Err(err) = store_path(Self::path(id), config) {
            log::error!("Failed to store config: {}", err);
        }
        NEW_STORED_PEER_CONFIG.lock().unwrap().insert(id.to_owned());
    }

    pub fn remove(id: &str) {
        fs::remove_file(Self::path(id)).ok();
    }

    fn path(id: &str) -> PathBuf {
        //If the id contains invalid chars, encode it
        let forbidden_paths = Regex::new(r".*[<>:/\\|\?\*].*");
        let path: PathBuf;
        if let Ok(forbidden_paths) = forbidden_paths {
            let id_encoded = if forbidden_paths.is_match(id) {
                "base64_".to_string() + BASE64.encode(id).as_str()
            } else {
                id.to_string()
            };
            path = [PEERS, id_encoded.as_str()].iter().collect();
        } else {
            log::warn!("Regex create failed: {:?}", forbidden_paths.err());
            // fallback for failing to create this regex.
            path = [PEERS, id.replace(":", "_").as_str()].iter().collect();
        }
        Config::with_extension(Config::path(path))
    }

    // The number of peers to load in the first round when showing the peers card list in the main window.
    // When there're too many peers, loading all of them at once will take a long time.
    // We can load them in two rouds, the first round loads the first 100 peers, and the second round loads the rest.
    // Then the UI will show the first 100 peers first, and the rest will be loaded and shown later.
    pub const BATCH_LOADING_COUNT: usize = 100;

    pub fn get_vec_id_modified_time_path(
        id_filters: &Option<Vec<String>>,
    ) -> Vec<(String, SystemTime, PathBuf)> {
        if let Ok(peers) = Config::path(PEERS).read_dir() {
            let mut vec_id_modified_time_path = peers
                .into_iter()
                .filter_map(|res| match res {
                    Ok(res) => {
                        let p = res.path();
                        if p.is_file()
                            && p.extension().map(|p| p.to_str().unwrap_or("")) == Some("toml")
                        {
                            Some(p)
                        } else {
                            None
                        }
                    }
                    _ => None,
                })
                .map(|p| {
                    let id = p
                        .file_stem()
                        .map(|p| p.to_str().unwrap_or(""))
                        .unwrap_or("")
                        .to_owned();

                    let id_decoded_string = if id.starts_with("base64_") && id.len() != 7 {
                        let id_decoded = BASE64.decode(&id[7..]).unwrap_or_default();
                        String::from_utf8_lossy(&id_decoded).as_ref().to_owned()
                    } else {
                        id
                    };
                    (id_decoded_string, p)
                })
                .filter(|(id, _)| {
                    let Some(filters) = id_filters else {
                        return true;
                    };
                    filters.contains(id)
                })
                .map(|(id, p)| {
                    let t = crate::get_modified_time(&p);
                    (id, t, p)
                })
                .collect::<Vec<_>>();
            vec_id_modified_time_path.sort_unstable_by_key(|item| std::cmp::Reverse(item.1));
            vec_id_modified_time_path
        } else {
            vec![]
        }
    }

    #[inline]
    async fn preload_file_async(path: PathBuf) {
        let _ = tokio::fs::File::open(path).await;
    }

    #[tokio::main(flavor = "current_thread")]
    async fn preload_peers_async() {
        let now = std::time::Instant::now();
        let vec_id_modified_time_path = Self::get_vec_id_modified_time_path(&None);
        let total_count = vec_id_modified_time_path.len();
        let mut futs = vec![];
        for (_, _, path) in vec_id_modified_time_path.into_iter() {
            futs.push(Self::preload_file_async(path));
            if futs.len() >= Self::BATCH_LOADING_COUNT {
                let first_load_start = std::time::Instant::now();
                futures::future::join_all(futs).await;
                if first_load_start.elapsed().as_millis() < 10 {
                    // No need to preload the rest if the first load is fast.
                    return;
                }
                futs = vec![];
            }
        }
        if !futs.is_empty() {
            futures::future::join_all(futs).await;
        }
        log::info!(
            "Preload peers done in {:?}, batch_count: {}, total: {}",
            now.elapsed(),
            Self::BATCH_LOADING_COUNT,
            total_count
        );
    }

    // We have to preload all peers in a background thread.
    // Because we find that opening files the first time after the system (Windows) booting will be very slow, up to 200~400ms.
    // The reason is that the Windows has "Microsoft Defender Antivirus Service" running in the background, which will scan the file when it's opened the first time.
    // So we have to preload all peers in a background thread to avoid the delay when opening the file the first time.
    // We can temporarily stop "Microsoft Defender Antivirus Service" or add the fold to the white list, to verify this. But don't do this in the release version.
    pub fn preload_peers() {
        std::thread::spawn(|| {
            Self::preload_peers_async();
        });
    }

    pub fn peers(id_filters: Option<Vec<String>>) -> Vec<(String, SystemTime, PeerConfig)> {
        let vec_id_modified_time_path = Self::get_vec_id_modified_time_path(&id_filters);
        Self::batch_peers(
            &vec_id_modified_time_path,
            0,
            Some(vec_id_modified_time_path.len()),
        )
        .0
    }

    pub fn batch_peers(
        all: &[(String, SystemTime, PathBuf)],
        from: usize,
        to: Option<usize>,
    ) -> (Vec<(String, SystemTime, PeerConfig)>, usize) {
        if from >= all.len() {
            return (vec![], 0);
        }

        let to = match to {
            Some(to) => to.min(all.len()),
            None => (from + Self::BATCH_LOADING_COUNT).min(all.len()),
        };

        // to <= from is unexpected, but we can just return an empty vec in this case.
        if to <= from {
            return (vec![], from);
        }

        let peers: Vec<_> = all[from..to]
            .iter()
            .map(|(id, t, p)| {
                let c = PeerConfig::load(id);
                if c.info.platform.is_empty() {
                    fs::remove_file(p).ok();
                }
                (id.clone(), *t, c)
            })
            .filter(|p| !p.2.info.platform.is_empty())
            .collect();
        (peers, to)
    }

    pub fn exists(id: &str) -> bool {
        Self::path(id).exists()
    }

    serde_field_string!(
        default_view_style,
        deserialize_view_style,
        UserDefaultConfig::read(keys::OPTION_VIEW_STYLE)
    );
    serde_field_string!(
        default_scroll_style,
        deserialize_scroll_style,
        UserDefaultConfig::read(keys::OPTION_SCROLL_STYLE)
    );
    serde_field_string!(
        default_image_quality,
        deserialize_image_quality,
        UserDefaultConfig::read(keys::OPTION_IMAGE_QUALITY)
    );
    serde_field_string!(
        default_reverse_mouse_wheel,
        deserialize_reverse_mouse_wheel,
        UserDefaultConfig::read(keys::OPTION_REVERSE_MOUSE_WHEEL)
    );
    serde_field_string!(
        default_displays_as_individual_windows,
        deserialize_displays_as_individual_windows,
        UserDefaultConfig::read(keys::OPTION_DISPLAYS_AS_INDIVIDUAL_WINDOWS)
    );
    serde_field_string!(
        default_use_all_my_displays_for_the_remote_session,
        deserialize_use_all_my_displays_for_the_remote_session,
        UserDefaultConfig::read(keys::OPTION_USE_ALL_MY_DISPLAYS_FOR_THE_REMOTE_SESSION)
    );

    fn default_custom_image_quality() -> Vec<i32> {
        let f: f64 = UserDefaultConfig::read(keys::OPTION_CUSTOM_IMAGE_QUALITY)
            .parse()
            .unwrap_or(50.0);
        vec![f as _]
    }

    fn deserialize_custom_image_quality<'de, D>(deserializer: D) -> Result<Vec<i32>, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let v: Vec<i32> = de::Deserialize::deserialize(deserializer)?;
        if v.len() == 1 && v[0] >= 10 && v[0] <= 0xFFF {
            Ok(v)
        } else {
            Ok(Self::default_custom_image_quality())
        }
    }

    fn default_options() -> HashMap<String, String> {
        let mut mp: HashMap<String, String> = Default::default();
        let _ = [
            keys::OPTION_CODEC_PREFERENCE,
            keys::OPTION_CUSTOM_FPS,
            keys::OPTION_ZOOM_CURSOR,
            keys::OPTION_I444,
            keys::OPTION_SWAP_LEFT_RIGHT_MOUSE,
            keys::OPTION_COLLAPSE_TOOLBAR,
        ]
        .map(|key| {
            mp.insert(key.to_owned(), UserDefaultConfig::read(key));
        });
        mp
    }

    fn default_trackpad_speed() -> i32 {
        UserDefaultConfig::read(keys::OPTION_TRACKPAD_SPEED)
            .parse()
            .unwrap_or(100)
    }

    fn deserialize_trackpad_speed<'de, D>(deserializer: D) -> Result<i32, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let v: i32 = de::Deserialize::deserialize(deserializer)?;
        if (10..=1000).contains(&v) {
            Ok(v)
        } else {
            Ok(Self::default_trackpad_speed())
        }
    }

    fn default_edge_scroll_edge_thickness() -> i32 {
        UserDefaultConfig::read(keys::OPTION_EDGE_SCROLL_EDGE_THICKNESS)
            .parse()
            .unwrap_or(100)
    }

    fn deserialize_edge_scroll_edge_thickness<'de, D>(deserializer: D) -> Result<i32, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let v: i32 = de::Deserialize::deserialize(deserializer)?;
        if (20..=150).contains(&v) {
            Ok(v)
        } else {
            Ok(Self::default_edge_scroll_edge_thickness())
        }
    }
}

serde_field_bool!(
    ShowRemoteCursor,
    "show_remote_cursor",
    default_show_remote_cursor,
    "ShowRemoteCursor::default_show_remote_cursor"
);
serde_field_bool!(
    FollowRemoteCursor,
    "follow_remote_cursor",
    default_follow_remote_cursor,
    "FollowRemoteCursor::default_follow_remote_cursor"
);

serde_field_bool!(
    FollowRemoteWindow,
    "follow_remote_window",
    default_follow_remote_window,
    "FollowRemoteWindow::default_follow_remote_window"
);
serde_field_bool!(
    ShowQualityMonitor,
    "show_quality_monitor",
    default_show_quality_monitor,
    "ShowQualityMonitor::default_show_quality_monitor"
);
serde_field_bool!(
    DisableAudio,
    "disable_audio",
    default_disable_audio,
    "DisableAudio::default_disable_audio"
);
serde_field_bool!(
    EnableFileCopyPaste,
    "enable-file-copy-paste",
    default_enable_file_copy_paste,
    "EnableFileCopyPaste::default_enable_file_copy_paste"
);
serde_field_bool!(
    DisableClipboard,
    "disable_clipboard",
    default_disable_clipboard,
    "DisableClipboard::default_disable_clipboard"
);
serde_field_bool!(
    LockAfterSessionEnd,
    "lock_after_session_end",
    default_lock_after_session_end,
    "LockAfterSessionEnd::default_lock_after_session_end"
);
serde_field_bool!(
    TerminalPersistent,
    "terminal-persistent",
    default_terminal_persistent,
    "TerminalPersistent::default_terminal_persistent"
);
serde_field_bool!(
    PrivacyMode,
    "privacy_mode",
    default_privacy_mode,
    "PrivacyMode::default_privacy_mode"
);

serde_field_bool!(
    AllowSwapKey,
    "allow_swap_key",
    default_allow_swap_key,
    "AllowSwapKey::default_allow_swap_key"
);

serde_field_bool!(
    ViewOnly,
    "view_only",
    default_view_only,
    "ViewOnly::default_view_only"
);

serde_field_bool!(
    ShowMyCursor,
    "show_my_cursor",
    default_show_my_cursor,
    "ShowMyCursor::default_show_my_cursor"
);

serde_field_bool!(
    SyncInitClipboard,
    "sync-init-clipboard",
    default_sync_init_clipboard,
    "SyncInitClipboard::default_sync_init_clipboard"
);

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct LocalConfig {
    #[serde(default, deserialize_with = "deserialize_string")]
    remote_id: String, // latest used one
    #[serde(default, deserialize_with = "deserialize_string")]
    kb_layout_type: String,
    #[serde(default, deserialize_with = "deserialize_size")]
    size: Size,
    #[serde(default, deserialize_with = "deserialize_vec_string")]
    pub fav: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_hashmap_string_string")]
    options: HashMap<String, String>,
    // Various data for flutter ui
    #[serde(default, deserialize_with = "deserialize_hashmap_string_string")]
    ui_flutter: HashMap<String, String>,
}

impl LocalConfig {
    fn load() -> LocalConfig {
        Config::load_::<LocalConfig>("_local")
    }

    fn store(&self) {
        Config::store_(self, "_local");
    }

    pub fn get_kb_layout_type() -> String {
        LOCAL_CONFIG.read().unwrap().kb_layout_type.clone()
    }

    pub fn set_kb_layout_type(kb_layout_type: String) {
        let mut config = LOCAL_CONFIG.write().unwrap();
        config.kb_layout_type = kb_layout_type;
        config.store();
    }

    pub fn get_size() -> Size {
        LOCAL_CONFIG.read().unwrap().size
    }

    pub fn set_size(x: i32, y: i32, w: i32, h: i32) {
        let mut config = LOCAL_CONFIG.write().unwrap();
        let size = (x, y, w, h);
        if size == config.size || size.2 < 300 || size.3 < 300 {
            return;
        }
        config.size = size;
        config.store();
    }

    pub fn set_remote_id(remote_id: &str) {
        let mut config = LOCAL_CONFIG.write().unwrap();
        if remote_id == config.remote_id {
            return;
        }
        config.remote_id = remote_id.into();
        config.store();
    }

    pub fn get_remote_id() -> String {
        LOCAL_CONFIG.read().unwrap().remote_id.clone()
    }

    pub fn set_fav(fav: Vec<String>) {
        let mut lock = LOCAL_CONFIG.write().unwrap();
        if lock.fav == fav {
            return;
        }
        lock.fav = fav;
        lock.store();
    }

    pub fn get_fav() -> Vec<String> {
        LOCAL_CONFIG.read().unwrap().fav.clone()
    }

    pub fn get_option(k: &str) -> String {
        get_or(
            &OVERWRITE_LOCAL_SETTINGS,
            &LOCAL_CONFIG.read().unwrap().options,
            &DEFAULT_LOCAL_SETTINGS,
            k,
        )
        .unwrap_or_default()
    }

    // Usually get_option should be used.
    pub fn get_option_from_file(k: &str) -> String {
        get_or(
            &OVERWRITE_LOCAL_SETTINGS,
            &Self::load().options,
            &DEFAULT_LOCAL_SETTINGS,
            k,
        )
        .unwrap_or_default()
    }

    pub fn get_bool_option(k: &str) -> bool {
        option2bool(k, &Self::get_option(k))
    }

    pub fn set_option(k: String, v: String) {
        if !is_option_can_save(&OVERWRITE_LOCAL_SETTINGS, &k, &DEFAULT_LOCAL_SETTINGS, &v) {
            let mut config = LOCAL_CONFIG.write().unwrap();
            if config.options.remove(&k).is_some() {
                config.store();
            }
            return;
        }
        let mut config = LOCAL_CONFIG.write().unwrap();
        // The custom client will explictly set "default" as the default language.
        let is_custom_client_default_lang = k == keys::OPTION_LANGUAGE && v == "default";
        if is_custom_client_default_lang {
            config.options.insert(k, "".to_owned());
            config.store();
            return;
        }
        let v2 = if v.is_empty() { None } else { Some(&v) };
        if v2 != config.options.get(&k) {
            if v2.is_none() {
                config.options.remove(&k);
            } else {
                config.options.insert(k, v);
            }
            config.store();
        }
    }

    pub fn get_flutter_option(k: &str) -> String {
        get_or(
            &OVERWRITE_LOCAL_SETTINGS,
            &LOCAL_CONFIG.read().unwrap().ui_flutter,
            &DEFAULT_LOCAL_SETTINGS,
            k,
        )
        .unwrap_or_default()
    }

    pub fn set_flutter_option(k: String, v: String) {
        let mut config = LOCAL_CONFIG.write().unwrap();
        let v2 = if v.is_empty() { None } else { Some(&v) };
        if v2 != config.ui_flutter.get(&k) {
            if v2.is_none() {
                config.ui_flutter.remove(&k);
            } else {
                config.ui_flutter.insert(k, v);
            }
            config.store();
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct DiscoveryPeer {
    #[serde(default, deserialize_with = "deserialize_string")]
    pub id: String,
    #[serde(default, deserialize_with = "deserialize_string")]
    pub username: String,
    #[serde(default, deserialize_with = "deserialize_string")]
    pub hostname: String,
    #[serde(default, deserialize_with = "deserialize_string")]
    pub platform: String,
    #[serde(default, deserialize_with = "deserialize_bool")]
    pub online: bool,
    #[serde(default, deserialize_with = "deserialize_hashmap_string_string")]
    pub ip_mac: HashMap<String, String>,
}

impl DiscoveryPeer {
    pub fn is_same_peer(&self, other: &DiscoveryPeer) -> bool {
        self.id == other.id && self.username == other.username
    }
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct LanPeers {
    #[serde(default, deserialize_with = "deserialize_vec_discoverypeer")]
    pub peers: Vec<DiscoveryPeer>,
}

impl LanPeers {
    pub fn load() -> LanPeers {
        let _lock = CONFIG.read().unwrap();
        match confy::load_path(Config::file_("_lan_peers")) {
            Ok(peers) => peers,
            Err(err) => {
                log::error!("Failed to load lan peers: {}", err);
                Default::default()
            }
        }
    }

    pub fn store(peers: &[DiscoveryPeer]) {
        let f = LanPeers {
            peers: peers.to_owned(),
        };
        if let Err(err) = store_path(Config::file_("_lan_peers"), f) {
            log::error!("Failed to store lan peers: {}", err);
        }
    }

    pub fn modify_time() -> crate::ResultType<u64> {
        let p = Config::file_("_lan_peers");
        Ok(fs::metadata(p)?
            .modified()?
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_millis() as _)
    }
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct UserDefaultConfig {
    #[serde(default, deserialize_with = "deserialize_hashmap_string_string")]
    options: HashMap<String, String>,
}

impl UserDefaultConfig {
    fn read(key: &str) -> String {
        let mut cfg = USER_DEFAULT_CONFIG.write().unwrap();
        // we do so, because default config may changed in another process, but we don't sync it
        // but no need to read every time, give a small interval to avoid too many redundant read waste
        if cfg.1.elapsed() > Duration::from_secs(1) {
            *cfg = (Self::load(), Instant::now());
        }
        cfg.0.get(key)
    }

    pub fn load() -> UserDefaultConfig {
        Config::load_::<UserDefaultConfig>("_default")
    }

    #[inline]
    fn store(&self) {
        Config::store_(self, "_default");
    }

    pub fn get(&self, key: &str) -> String {
        match key {
            #[cfg(any(target_os = "android", target_os = "ios"))]
            keys::OPTION_VIEW_STYLE => self.get_string(key, "adaptive", vec!["original"]),
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            keys::OPTION_VIEW_STYLE => self.get_string(key, "original", vec!["adaptive"]),
            keys::OPTION_SCROLL_STYLE => {
                self.get_string(key, "scrollauto", vec!["scrolledge", "scrollbar"])
            }
            keys::OPTION_IMAGE_QUALITY => {
                self.get_string(key, "balanced", vec!["best", "low", "custom"])
            }
            keys::OPTION_CODEC_PREFERENCE => {
                self.get_string(key, "auto", vec!["vp8", "vp9", "av1", "h264", "h265"])
            }
            keys::OPTION_CUSTOM_IMAGE_QUALITY => {
                self.get_num_string(key, 100.0, 10.0, 0xFFF as f64)
            }
            keys::OPTION_CUSTOM_FPS => self.get_num_string(key, 60.0, 5.0, 120.0),
            keys::OPTION_SHOW_REMOTE_CURSOR => self.get_string(key, "Y", vec!["", "N"]),
            keys::OPTION_ENABLE_FILE_COPY_PASTE => self.get_string(key, "Y", vec!["", "N"]),
            keys::OPTION_EDGE_SCROLL_EDGE_THICKNESS => self.get_num_string(key, 100, 20, 150),
            keys::OPTION_TRACKPAD_SPEED => self.get_num_string(key, 100, 10, 1000),
            _ => self
                .get_after(key)
                .map(|v| v.to_string())
                .unwrap_or_default(),
        }
    }

    pub fn set(&mut self, key: String, value: String) {
        if !is_option_can_save(
            &OVERWRITE_DISPLAY_SETTINGS,
            &key,
            &DEFAULT_DISPLAY_SETTINGS,
            &value,
        ) {
            if self.options.remove(&key).is_some() {
                self.store();
            }
            return;
        }
        if value.is_empty() {
            self.options.remove(&key);
        } else {
            self.options.insert(key, value);
        }
        self.store();
    }

    #[inline]
    fn get_string(&self, key: &str, default: &str, others: Vec<&str>) -> String {
        match self.get_after(key) {
            Some(option) => {
                if others.contains(&option.as_str()) {
                    option.to_owned()
                } else {
                    default.to_owned()
                }
            }
            None => default.to_owned(),
        }
    }

    #[inline]
    fn get_num_string<T>(&self, key: &str, default: T, min: T, max: T) -> String
    where
        T: ToString + std::str::FromStr + std::cmp::PartialOrd + std::marker::Copy,
    {
        match self.get_after(key) {
            Some(option) => {
                let v: T = option.parse().unwrap_or(default);
                if v >= min && v <= max {
                    v.to_string()
                } else {
                    default.to_string()
                }
            }
            None => default.to_string(),
        }
    }

    fn get_after(&self, k: &str) -> Option<String> {
        get_or(
            &OVERWRITE_DISPLAY_SETTINGS,
            &self.options,
            &DEFAULT_DISPLAY_SETTINGS,
            k,
        )
    }
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct AbPeer {
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub id: String,
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub hash: String,
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub username: String,
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub hostname: String,
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub platform: String,
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub alias: String,
    #[serde(default, deserialize_with = "deserialize_vec_string")]
    pub tags: Vec<String>,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct AbEntry {
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub guid: String,
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub name: String,
    #[serde(default, deserialize_with = "deserialize_vec_abpeer")]
    pub peers: Vec<AbPeer>,
    #[serde(default, deserialize_with = "deserialize_vec_string")]
    pub tags: Vec<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub tag_colors: String,
}

impl AbEntry {
    pub fn personal(&self) -> bool {
        self.guid.starts_with("personal-")
    }
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct Ab {
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub access_token: String,
    #[serde(default, deserialize_with = "deserialize_vec_abentry")]
    pub ab_entries: Vec<AbEntry>,
}

impl Ab {
    fn path() -> PathBuf {
        let filename = format!("{}_ab", APP_NAME.read().unwrap().clone());
        Config::path(filename)
    }

    pub fn store(json: String) {
        let data = match compress(json.as_bytes()) {
            Ok(data) => data,
            Err(err) => {
                log::error!("failed to compress address book data: {err}");
                return;
            }
        };
        let max_len = 64 * 1024 * 1024;
        if data.len() > max_len {
            // maxlen of function decompress
            log::error!("ab data too large, {} > {}", data.len(), max_len);
            return;
        }
        if let Ok(data) = encrypt_local(&data) {
            if let Ok(mut file) = std::fs::File::create(Self::path()) {
                file.write_all(&data).ok();
            }
        }
    }

    pub fn load() -> Ab {
        if let Ok(mut file) = std::fs::File::open(Self::path()) {
            let mut data = vec![];
            if file.read_to_end(&mut data).is_ok() {
                if let Ok(data) = decrypt_local(&data) {
                    if let Ok(data) = decompress(&data) {
                        if let Ok(ab) = serde_json::from_str::<Ab>(&String::from_utf8_lossy(&data))
                        {
                            return ab;
                        }
                    }
                }
            }
        };
        Self::remove();
        Ab::default()
    }

    pub fn remove() {
        std::fs::remove_file(Self::path()).ok();
    }
}

// use default value when field type is wrong
macro_rules! deserialize_default {
    ($func_name:ident, $return_type:ty) => {
        fn $func_name<'de, D>(deserializer: D) -> Result<$return_type, D::Error>
        where
            D: de::Deserializer<'de>,
        {
            Ok(de::Deserialize::deserialize(deserializer).unwrap_or_default())
        }
    };
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct GroupPeer {
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub id: String,
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub username: String,
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub hostname: String,
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub platform: String,
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub login_name: String,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct GroupUser {
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub name: String,
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub display_name: String,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct DeviceGroup {
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub name: String,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct Group {
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub access_token: String,
    #[serde(default, deserialize_with = "deserialize_vec_groupuser")]
    pub users: Vec<GroupUser>,
    #[serde(default, deserialize_with = "deserialize_vec_grouppeer")]
    pub peers: Vec<GroupPeer>,
    #[serde(default, deserialize_with = "deserialize_vec_devicegroup")]
    pub device_groups: Vec<DeviceGroup>,
}

impl Group {
    fn path() -> PathBuf {
        let filename = format!("{}_group", APP_NAME.read().unwrap().clone());
        Config::path(filename)
    }

    pub fn store(json: String) {
        let data = match compress(json.as_bytes()) {
            Ok(data) => data,
            Err(err) => {
                log::error!("failed to compress group data: {err}");
                return;
            }
        };
        let max_len = 64 * 1024 * 1024;
        if data.len() > max_len {
            // maxlen of function decompress
            return;
        }
        if let Ok(data) = encrypt_local(&data) {
            if let Ok(mut file) = std::fs::File::create(Self::path()) {
                file.write_all(&data).ok();
            }
        }
    }

    pub fn load() -> Self {
        if let Ok(mut file) = std::fs::File::open(Self::path()) {
            let mut data = vec![];
            if file.read_to_end(&mut data).is_ok() {
                if let Ok(data) = decrypt_local(&data) {
                    if let Ok(data) = decompress(&data) {
                        if let Ok(group) =
                            serde_json::from_str::<Self>(&String::from_utf8_lossy(&data))
                        {
                            return group;
                        }
                    }
                }
            }
        };
        Self::remove();
        Self::default()
    }

    pub fn remove() {
        std::fs::remove_file(Self::path()).ok();
    }
}

#[derive(Debug, Default, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct TrustedDevice {
    #[serde(default, alias = "id")]
    pub device_id: String,
    #[serde(default)]
    pub public_key: Bytes,
    #[serde(default)]
    pub public_key_fingerprint: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub platform: String,
    #[serde(default, alias = "time")]
    pub created_at: i64,
    #[serde(default)]
    pub last_used_at: i64,
    #[serde(default)]
    pub hwid: Bytes,
}

impl TrustedDevice {
    pub fn new(device_id: String, public_key: Bytes, name: String, platform: String) -> Self {
        let fingerprint = compute_public_key_fingerprint(&public_key);
        let now = crate::get_time();
        Self {
            device_id,
            public_key,
            public_key_fingerprint: fingerprint,
            name,
            platform,
            created_at: now,
            last_used_at: now,
            hwid: Bytes::new(),
        }
    }

    pub fn is_expired(&self) -> bool {
        const DAYS_90: i64 = 90 * 24 * 60 * 60 * 1000;
        let ts = if self.last_used_at > 0 {
            self.last_used_at
        } else {
            self.created_at
        };
        ts + DAYS_90 < crate::get_time()
    }

    #[inline]
    pub fn outdate(&self) -> bool {
        self.is_expired()
    }

    pub fn ensure_fingerprint(&mut self) {
        if self.public_key_fingerprint.is_empty() && !self.public_key.is_empty() {
            self.public_key_fingerprint = compute_public_key_fingerprint(&self.public_key);
        }
    }
}

pub fn compute_public_key_fingerprint(public_key: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(public_key);
    let mut out = String::with_capacity(hash.len() * 2);
    for byte in hash {
        use std::fmt::Write;
        let _ = write!(out, "{:02x}", byte);
    }
    out
}

pub fn create_device_proof_raw_payload(
    challenge: &[u8],
    target_host_id: &str,
    controller_id: &str,
    session_scope: &str,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(
        "camellia-trusted-device-v1\n".len()
            + challenge.len()
            + 1
            + target_host_id.len()
            + 1
            + controller_id.len()
            + 1
            + session_scope.len(),
    );
    payload.extend_from_slice(b"camellia-trusted-device-v1\n");
    payload.extend_from_slice(challenge);
    payload.push(b'\n');
    payload.extend_from_slice(target_host_id.as_bytes());
    payload.push(b'\n');
    payload.extend_from_slice(controller_id.as_bytes());
    payload.push(b'\n');
    payload.extend_from_slice(session_scope.as_bytes());
    payload
}

pub fn create_device_proof_payload(
    challenge: &[u8],
    target_host_id: &str,
    controller_id: &str,
    session_scope: &str,
) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let raw =
        create_device_proof_raw_payload(challenge, target_host_id, controller_id, session_scope);
    Sha256::digest(&raw).to_vec()
}

pub fn sign_device_proof(
    challenge: &[u8],
    target_host_id: &str,
    controller_id: &str,
    session_scope: &str,
    signing_secret_key: &crate::crypto::sign::SecretKey,
) -> Vec<u8> {
    let commitment =
        create_device_proof_payload(challenge, target_host_id, controller_id, session_scope);
    crate::crypto::sign::sign_detached(&commitment, signing_secret_key).to_vec()
}

pub fn verify_device_proof(
    challenge: &[u8],
    target_host_id: &str,
    controller_id: &str,
    session_scope: &str,
    device_signature: &[u8],
    device_public_key: &crate::crypto::sign::PublicKey,
) -> Result<(), crate::crypto::CryptoError> {
    let commitment =
        create_device_proof_payload(challenge, target_host_id, controller_id, session_scope);
    crate::crypto::sign::verify_detached(device_signature, &commitment, device_public_key)
}

deserialize_default!(deserialize_string, String);
deserialize_default!(deserialize_bool, bool);
deserialize_default!(deserialize_i32, i32);
deserialize_default!(deserialize_vec_u8, Vec<u8>);
deserialize_default!(deserialize_vec_string, Vec<String>);
deserialize_default!(deserialize_vec_i32_string_i32, Vec<(i32, String, i32)>);
deserialize_default!(deserialize_vec_discoverypeer, Vec<DiscoveryPeer>);
deserialize_default!(deserialize_vec_abpeer, Vec<AbPeer>);
deserialize_default!(deserialize_vec_abentry, Vec<AbEntry>);
deserialize_default!(deserialize_vec_groupuser, Vec<GroupUser>);
deserialize_default!(deserialize_vec_grouppeer, Vec<GroupPeer>);
deserialize_default!(deserialize_vec_devicegroup, Vec<DeviceGroup>);
deserialize_default!(deserialize_keypair, KeyPair);
deserialize_default!(deserialize_size, Size);
deserialize_default!(deserialize_hashmap_string_string, HashMap<String, String>);
deserialize_default!(deserialize_hashmap_string_bool,  HashMap<String, bool>);
deserialize_default!(deserialize_hashmap_resolutions, HashMap<String, Resolution>);

#[inline]
fn get_or(
    a: &RwLock<HashMap<String, String>>,
    b: &HashMap<String, String>,
    c: &RwLock<HashMap<String, String>>,
    k: &str,
) -> Option<String> {
    a.read()
        .unwrap()
        .get(k)
        .or(b.get(k))
        .or(c.read().unwrap().get(k))
        .cloned()
}

#[inline]
fn is_option_can_save(
    overwrite: &RwLock<HashMap<String, String>>,
    k: &str,
    defaults: &RwLock<HashMap<String, String>>,
    v: &str,
) -> bool {
    if overwrite.read().unwrap().contains_key(k)
        || defaults.read().unwrap().get(k).is_some_and(|x| x == v)
    {
        return false;
    }
    true
}

#[inline]
pub fn is_incoming_only() -> bool {
    HARD_SETTINGS
        .read()
        .unwrap()
        .get("conn-type")
        .is_some_and(|x| x == ("incoming"))
}

#[inline]
pub fn is_outgoing_only() -> bool {
    HARD_SETTINGS
        .read()
        .unwrap()
        .get("conn-type")
        .is_some_and(|x| x == ("outgoing"))
}

#[inline]
fn is_some_hard_opton(name: &str) -> bool {
    HARD_SETTINGS
        .read()
        .unwrap()
        .get(name)
        .is_some_and(|x| x == ("Y"))
}

#[inline]
pub fn is_disable_tcp_listen() -> bool {
    is_some_hard_opton("disable-tcp-listen")
}

#[inline]
pub fn is_disable_settings() -> bool {
    is_some_hard_opton("disable-settings")
}

#[inline]
pub fn is_disable_ab() -> bool {
    false
}

#[inline]
pub fn is_disable_account() -> bool {
    false
}

#[inline]
pub fn is_disable_installation() -> bool {
    is_some_hard_opton("disable-installation")
}

// This function must be kept the same as the Flutter implementation.
// flutter: flutter/lib/common.dart -> option2bool()
pub fn option2bool(option: &str, value: &str) -> bool {
    if option.starts_with("enable-") {
        value != "N"
    } else if option.starts_with("allow-")
        || option == "stop-service"
        || option == keys::OPTION_ENABLE_DIRECT_SERVER
        || option == "force-always-relay"
    {
        value == "Y"
    } else {
        value != "N"
    }
}

pub fn use_ws() -> bool {
    let option = keys::OPTION_ALLOW_WEBSOCKET;
    option2bool(option, &Config::get_option(option))
}

pub mod keys {
    pub const OPTION_VIEW_ONLY: &str = "view_only";
    pub const OPTION_SHOW_MONITORS_TOOLBAR: &str = "show_monitors_toolbar";
    pub const OPTION_COLLAPSE_TOOLBAR: &str = "collapse_toolbar";
    pub const OPTION_SHOW_REMOTE_CURSOR: &str = "show_remote_cursor";
    pub const OPTION_FOLLOW_REMOTE_CURSOR: &str = "follow_remote_cursor";
    pub const OPTION_FOLLOW_REMOTE_WINDOW: &str = "follow_remote_window";
    pub const OPTION_ZOOM_CURSOR: &str = "zoom-cursor";
    pub const OPTION_SHOW_QUALITY_MONITOR: &str = "show_quality_monitor";
    pub const OPTION_DISABLE_AUDIO: &str = "disable_audio";
    pub const OPTION_ENABLE_REMOTE_PRINTER: &str = "enable-remote-printer";
    pub const OPTION_ENABLE_FILE_COPY_PASTE: &str = "enable-file-copy-paste";
    pub const OPTION_DISABLE_CLIPBOARD: &str = "disable_clipboard";
    pub const OPTION_LOCK_AFTER_SESSION_END: &str = "lock_after_session_end";
    pub const OPTION_PRIVACY_MODE: &str = "privacy_mode";
    pub const OPTION_TOUCH_MODE: &str = "touch-mode";
    pub const OPTION_I444: &str = "i444";
    pub const OPTION_REVERSE_MOUSE_WHEEL: &str = "reverse_mouse_wheel";
    pub const OPTION_SWAP_LEFT_RIGHT_MOUSE: &str = "swap-left-right-mouse";
    pub const OPTION_DISPLAYS_AS_INDIVIDUAL_WINDOWS: &str = "displays_as_individual_windows";
    pub const OPTION_USE_ALL_MY_DISPLAYS_FOR_THE_REMOTE_SESSION: &str =
        "use_all_my_displays_for_the_remote_session";
    pub const OPTION_VIEW_STYLE: &str = "view_style";
    pub const OPTION_SCROLL_STYLE: &str = "scroll_style";
    pub const OPTION_EDGE_SCROLL_EDGE_THICKNESS: &str = "edge-scroll-edge-thickness";
    pub const OPTION_IMAGE_QUALITY: &str = "image_quality";
    pub const OPTION_CUSTOM_IMAGE_QUALITY: &str = "custom_image_quality";
    pub const OPTION_CUSTOM_FPS: &str = "custom-fps";
    pub const OPTION_CODEC_PREFERENCE: &str = "codec-preference";
    pub const OPTION_SYNC_INIT_CLIPBOARD: &str = "sync-init-clipboard";
    pub const OPTION_THEME: &str = "theme";
    pub const OPTION_LANGUAGE: &str = "lang";
    pub const OPTION_REMOTE_MENUBAR_DRAG_LEFT: &str = "remote-menubar-drag-left";
    pub const OPTION_REMOTE_MENUBAR_DRAG_RIGHT: &str = "remote-menubar-drag-right";
    pub const OPTION_HIDE_AB_TAGS_PANEL: &str = "hideAbTagsPanel";
    pub const OPTION_ENABLE_CONFIRM_CLOSING_TABS: &str = "enable-confirm-closing-tabs";
    pub const OPTION_ENABLE_OPEN_NEW_CONNECTIONS_IN_TABS: &str =
        "enable-open-new-connections-in-tabs";
    pub const OPTION_TEXTURE_RENDER: &str = "use-texture-render";
    pub const OPTION_ALLOW_D3D_RENDER: &str = "allow-d3d-render";
    pub const OPTION_SYNC_AB_WITH_RECENT_SESSIONS: &str = "sync-ab-with-recent-sessions";
    pub const OPTION_SYNC_AB_TAGS: &str = "sync-ab-tags";
    pub const OPTION_FILTER_AB_BY_INTERSECTION: &str = "filter-ab-by-intersection";
    pub const OPTION_ACCESS_MODE: &str = "access-mode";
    pub const OPTION_ENABLE_KEYBOARD: &str = "enable-keyboard";
    pub const OPTION_ENABLE_CLIPBOARD: &str = "enable-clipboard";
    pub const OPTION_ENABLE_FILE_TRANSFER: &str = "enable-file-transfer";
    pub const OPTION_ENABLE_CAMERA: &str = "enable-camera";
    pub const OPTION_ENABLE_TERMINAL: &str = "enable-terminal";
    pub const OPTION_TERMINAL_PERSISTENT: &str = "terminal-persistent";
    pub const OPTION_ENABLE_AUDIO: &str = "enable-audio";
    pub const OPTION_ENABLE_TUNNEL: &str = "enable-tunnel";
    pub const OPTION_ENABLE_REMOTE_RESTART: &str = "enable-remote-restart";
    pub const OPTION_ENABLE_RECORD_SESSION: &str = "enable-record-session";
    pub const OPTION_ENABLE_BLOCK_INPUT: &str = "enable-block-input";
    pub const OPTION_ENABLE_PRIVACY_MODE: &str = "enable-privacy-mode";
    pub const OPTION_ENABLE_PERM_CHANGE_IN_ACCEPT_WINDOW: &str =
        "enable-perm-change-in-accept-window";
    pub const OPTION_ALLOW_SCOPE_VIOLATION_CLOSE: &str = "allow-scope-violation-close";
    pub const OPTION_ALLOW_SCOPE_VIOLATION_ALARM: &str = "allow-scope-violation-alarm";
    pub const OPTION_ALLOW_REMOTE_CONFIG_MODIFICATION: &str = "allow-remote-config-modification";
    pub const OPTION_ALLOW_NUMERNIC_ONE_TIME_PASSWORD: &str = "allow-numeric-one-time-password";
    pub const OPTION_ENABLE_LAN_DISCOVERY: &str = "enable-lan-discovery";
    pub const OPTION_ENABLE_DIRECT_SERVER: &str = "enable-direct-server";
    pub const OPTION_DIRECT_ACCESS_PORT: &str = "direct-access-port";
    pub const OPTION_WHITELIST: &str = "whitelist";
    pub const OPTION_ID_WHITELIST: &str = "id-whitelist";
    pub const OPTION_ALLOW_AUTO_DISCONNECT: &str = "allow-auto-disconnect";
    pub const OPTION_AUTO_DISCONNECT_TIMEOUT: &str = "auto-disconnect-timeout";
    pub const OPTION_ALLOW_ONLY_CONN_WINDOW_OPEN: &str = "allow-only-conn-window-open";
    pub const OPTION_ALLOW_AUTO_RECORD_INCOMING: &str = "allow-auto-record-incoming";
    pub const OPTION_ALLOW_AUTO_RECORD_OUTGOING: &str = "allow-auto-record-outgoing";
    pub const OPTION_UPLOAD_RECORDINGS_TO_SERVER: &str = "upload-recordings-to-server";
    pub const OPTION_HIDE_RECORDING_BUTTON: &str = "hide-recording-button";
    pub const OPTION_WINDOWS_SERVICE_VIDEO_SAVE_DIRECTORY: &str =
        "windows-service-video-save-directory";
    pub const OPTION_VIDEO_SAVE_DIRECTORY: &str = "video-save-directory";
    pub const OPTION_ENABLE_ABR: &str = "enable-abr";
    pub const OPTION_ALLOW_REMOVE_WALLPAPER: &str = "allow-remove-wallpaper";
    pub const OPTION_ALLOW_ALWAYS_SOFTWARE_RENDER: &str = "allow-always-software-render";
    pub const OPTION_ALLOW_LINUX_HEADLESS: &str = "allow-linux-headless";
    pub const OPTION_ENABLE_HWCODEC: &str = "enable-hwcodec";
    pub const OPTION_APPROVE_MODE: &str = "approve-mode";
    pub const OPTION_VERIFICATION_METHOD: &str = "verification-method";
    pub const OPTION_TEMPORARY_PASSWORD_LENGTH: &str = "temporary-password-length";
    pub const OPTION_CUSTOM_RENDEZVOUS_SERVER: &str = "custom-rendezvous-server";
    pub const OPTION_API_SERVER: &str = "api-server";
    pub const OPTION_KEY: &str = "key";
    pub const OPTION_ALLOW_WEBSOCKET: &str = "allow-websocket";
    pub const OPTION_PRESET_ADDRESS_BOOK_NAME: &str = "preset-address-book-name";
    pub const OPTION_PRESET_ADDRESS_BOOK_TAG: &str = "preset-address-book-tag";
    pub const OPTION_PRESET_ADDRESS_BOOK_ALIAS: &str = "preset-address-book-alias";
    pub const OPTION_PRESET_ADDRESS_BOOK_PASSWORD: &str = "preset-address-book-password";
    pub const OPTION_PRESET_ADDRESS_BOOK_NOTE: &str = "preset-address-book-note";
    pub const OPTION_PRESET_DEVICE_USERNAME: &str = "preset-device-username";
    pub const OPTION_PRESET_DEVICE_NAME: &str = "preset-device-name";
    pub const OPTION_PRESET_NOTE: &str = "preset-note";
    pub const OPTION_ENABLE_DIRECTX_CAPTURE: &str = "enable-directx-capture";
    pub const OPTION_ENABLE_ANDROID_SOFTWARE_ENCODING_HALF_SCALE: &str =
        "enable-android-software-encoding-half-scale";
    pub const OPTION_ENABLE_TRUSTED_DEVICES: &str = "enable-trusted-devices";
    pub const OPTION_AV1_TEST: &str = "av1-test";
    pub const OPTION_TRACKPAD_SPEED: &str = "trackpad-speed";
    pub const OPTION_REGISTER_DEVICE: &str = "register-device";
    pub const OPTION_RELAY_SERVER: &str = "relay-server";
    pub const OPTION_ICE_SERVERS: &str = "ice-servers";
    /// Maximum number of files allowed during a single file transfer request.
    ///
    /// Key: `file-transfer-max-files`.
    /// Unit: number of files (not bytes).
    ///
    /// Behaviour:
    /// - If set to a positive integer N, at most N files are allowed, subject to
    ///   the consumer's hard safety ceiling.
    /// - If unset, zero, negative, non-integer, or overflowing, the consumer's
    ///   safe built-in default is used.
    pub const OPTION_FILE_TRANSFER_MAX_FILES: &str = "file-transfer-max-files";
    pub const OPTION_DISABLE_UDP: &str = "disable-udp";
    pub const OPTION_SHOW_VIRTUAL_MOUSE: &str = "show-virtual-mouse";
    // joystick is the virtual mouse.
    // So `OPTION_SHOW_VIRTUAL_MOUSE` should also be set if `OPTION_SHOW_VIRTUAL_JOYSTICK` is set.
    pub const OPTION_SHOW_VIRTUAL_JOYSTICK: &str = "show-virtual-joystick";
    pub const OPTION_ENABLE_FLUTTER_HTTP_ON_RUST: &str = "enable-flutter-http-on-rust";
    pub const OPTION_ALLOW_ASK_FOR_NOTE: &str = "allow-ask-for-note";

    // built-in options
    pub const OPTION_DISPLAY_NAME: &str = "display-name";
    pub const OPTION_AVATAR: &str = "avatar";
    pub const OPTION_PRESET_DEVICE_GROUP_NAME: &str = "preset-device-group-name";
    pub const OPTION_PRESET_USERNAME: &str = "preset-user-name";
    pub const OPTION_PRESET_STRATEGY_NAME: &str = "preset-strategy-name";
    pub const OPTION_REMOVE_PRESET_PASSWORD_WARNING: &str = "remove-preset-password-warning";
    pub const OPTION_HIDE_SECURITY_SETTINGS: &str = "hide-security-settings";
    pub const OPTION_HIDE_NETWORK_SETTINGS: &str = "hide-network-settings";
    pub const OPTION_HIDE_SERVER_SETTINGS: &str = "hide-server-settings";
    pub const OPTION_HIDE_PROXY_SETTINGS: &str = "hide-proxy-settings";
    pub const OPTION_HIDE_REMOTE_PRINTER_SETTINGS: &str = "hide-remote-printer-settings";
    pub const OPTION_HIDE_WEBSOCKET_SETTINGS: &str = "hide-websocket-settings";
    pub const OPTION_HIDE_STOP_SERVICE: &str = "hide-stop-service";
    pub const OPTION_ALLOW_COMMAND_LINE_SETTINGS_WHEN_SETTINGS_DISABLED: &str =
        "allow-command-line-settings-when-settings-disabled";

    // Connection punch-through options
    pub const OPTION_ENABLE_UDP_PUNCH: &str = "enable-udp-punch";
    pub const OPTION_ENABLE_IPV6_PUNCH: &str = "enable-ipv6-punch";
    pub const OPTION_HIDE_USERNAME_ON_CARD: &str = "hide-username-on-card";
    pub const OPTION_HIDE_HELP_CARDS: &str = "hide-help-cards";
    pub const OPTION_DEFAULT_CONNECT_PASSWORD: &str = "default-connect-password";
    pub const OPTION_HIDE_TRAY: &str = "hide-tray";
    pub const OPTION_ONE_WAY_CLIPBOARD_REDIRECTION: &str = "one-way-clipboard-redirection";
    pub const OPTION_ALLOW_LOGON_SCREEN_PASSWORD: &str = "allow-logon-screen-password";
    pub const OPTION_ALLOW_DEEP_LINK_PASSWORD: &str = "allow-deep-link-password";
    pub const OPTION_ALLOW_DEEP_LINK_SERVER_SETTINGS: &str = "allow-deep-link-server-settings";
    pub const OPTION_ONE_WAY_FILE_TRANSFER: &str = "one-way-file-transfer";
    pub const OPTION_ALLOW_HTTPS_21114: &str = "allow-https-21114";
    pub const OPTION_USE_RAW_TCP_FOR_API: &str = "use-raw-tcp-for-api";
    pub const OPTION_ALLOW_HOSTNAME_AS_ID: &str = "allow-hostname-as-id";
    pub const OPTION_HIDE_POWERED_BY_ME: &str = "hide-powered-by-me";
    pub const OPTION_MAIN_WINDOW_ALWAYS_ON_TOP: &str = "main-window-always-on-top";
    pub const OPTION_DISABLE_CHANGE_PERMANENT_PASSWORD: &str = "disable-change-permanent-password";
    pub const OPTION_DISABLE_CHANGE_ID: &str = "disable-change-id";
    pub const OPTION_DISABLE_UNLOCK_PIN: &str = "disable-unlock-pin";

    // flutter local options
    pub const OPTION_FLUTTER_REMOTE_MENUBAR_STATE: &str = "remoteMenubarState";
    pub const OPTION_FLUTTER_PEER_SORTING: &str = "peer-sorting";
    pub const OPTION_FLUTTER_PEER_TAB_INDEX: &str = "peer-tab-index";
    pub const OPTION_FLUTTER_PEER_TAB_ORDER: &str = "peer-tab-order";
    pub const OPTION_FLUTTER_PEER_TAB_VISIBLE: &str = "peer-tab-visible";
    pub const OPTION_FLUTTER_PEER_CARD_UI_TYLE: &str = "peer-card-ui-type";
    pub const OPTION_FLUTTER_CURRENT_AB_NAME: &str = "current-ab-name";
    pub const OPTION_ALLOW_REMOTE_CM_MODIFICATION: &str = "allow-remote-cm-modification";

    pub const OPTION_PRINTER_INCOMING_JOB_ACTION: &str = "printer-incomming-job-action";
    pub const OPTION_PRINTER_ALLOW_AUTO_PRINT: &str = "allow-printer-auto-print";
    pub const OPTION_PRINTER_SELECTED_NAME: &str = "printer-selected-name";

    // android floating window options
    pub const OPTION_DISABLE_FLOATING_WINDOW: &str = "disable-floating-window";
    pub const OPTION_FLOATING_WINDOW_SIZE: &str = "floating-window-size";
    pub const OPTION_FLOATING_WINDOW_UNTOUCHABLE: &str = "floating-window-untouchable";
    pub const OPTION_FLOATING_WINDOW_TRANSPARENCY: &str = "floating-window-transparency";
    pub const OPTION_FLOATING_WINDOW_SVG: &str = "floating-window-svg";

    // android keep screen on
    pub const OPTION_KEEP_SCREEN_ON: &str = "keep-screen-on";

    // Server-side: keep host system awake during incoming sessions (Security setting)
    pub const OPTION_KEEP_AWAKE_DURING_INCOMING_SESSIONS: &str =
        "keep-awake-during-incoming-sessions";

    // Client-side: keep client system awake during outgoing sessions (General setting)
    pub const OPTION_KEEP_AWAKE_DURING_OUTGOING_SESSIONS: &str =
        "keep-awake-during-outgoing-sessions";

    pub const OPTION_DISABLE_DISCOVERY_PANEL: &str = "disable-discovery-panel";
    pub const OPTION_PRE_ELEVATE_SERVICE: &str = "pre-elevate-service";

    // proxy settings
    // The following options are not real keys, they are just used for custom client advanced settings.
    // The real keys are in Config2::socks.
    pub const OPTION_PROXY_URL: &str = "proxy-url";
    pub const OPTION_PROXY_USERNAME: &str = "proxy-username";
    pub const OPTION_PROXY_PASSWORD: &str = "proxy-password";

    // DEFAULT_DISPLAY_SETTINGS, OVERWRITE_DISPLAY_SETTINGS
    pub const KEYS_DISPLAY_SETTINGS: &[&str] = &[
        OPTION_VIEW_ONLY,
        OPTION_SHOW_MONITORS_TOOLBAR,
        OPTION_COLLAPSE_TOOLBAR,
        OPTION_SHOW_REMOTE_CURSOR,
        OPTION_FOLLOW_REMOTE_CURSOR,
        OPTION_FOLLOW_REMOTE_WINDOW,
        OPTION_ZOOM_CURSOR,
        OPTION_SHOW_QUALITY_MONITOR,
        OPTION_DISABLE_AUDIO,
        OPTION_ENABLE_FILE_COPY_PASTE,
        OPTION_DISABLE_CLIPBOARD,
        OPTION_LOCK_AFTER_SESSION_END,
        OPTION_PRIVACY_MODE,
        OPTION_TOUCH_MODE,
        OPTION_I444,
        OPTION_REVERSE_MOUSE_WHEEL,
        OPTION_SWAP_LEFT_RIGHT_MOUSE,
        OPTION_DISPLAYS_AS_INDIVIDUAL_WINDOWS,
        OPTION_USE_ALL_MY_DISPLAYS_FOR_THE_REMOTE_SESSION,
        OPTION_VIEW_STYLE,
        OPTION_TERMINAL_PERSISTENT,
        OPTION_SCROLL_STYLE,
        OPTION_EDGE_SCROLL_EDGE_THICKNESS,
        OPTION_IMAGE_QUALITY,
        OPTION_CUSTOM_IMAGE_QUALITY,
        OPTION_CUSTOM_FPS,
        OPTION_CODEC_PREFERENCE,
        OPTION_SYNC_INIT_CLIPBOARD,
        OPTION_TRACKPAD_SPEED,
    ];
    // DEFAULT_LOCAL_SETTINGS, OVERWRITE_LOCAL_SETTINGS
    pub const KEYS_LOCAL_SETTINGS: &[&str] = &[
        OPTION_THEME,
        OPTION_LANGUAGE,
        OPTION_ENABLE_CONFIRM_CLOSING_TABS,
        OPTION_ENABLE_OPEN_NEW_CONNECTIONS_IN_TABS,
        OPTION_TEXTURE_RENDER,
        OPTION_ALLOW_D3D_RENDER,
        OPTION_SYNC_AB_WITH_RECENT_SESSIONS,
        OPTION_SYNC_AB_TAGS,
        OPTION_FILTER_AB_BY_INTERSECTION,
        OPTION_REMOTE_MENUBAR_DRAG_LEFT,
        OPTION_REMOTE_MENUBAR_DRAG_RIGHT,
        OPTION_HIDE_AB_TAGS_PANEL,
        OPTION_FLUTTER_REMOTE_MENUBAR_STATE,
        OPTION_FLUTTER_PEER_SORTING,
        OPTION_FLUTTER_PEER_TAB_INDEX,
        OPTION_FLUTTER_PEER_TAB_ORDER,
        OPTION_FLUTTER_PEER_TAB_VISIBLE,
        OPTION_FLUTTER_PEER_CARD_UI_TYLE,
        OPTION_FLUTTER_CURRENT_AB_NAME,
        OPTION_DISABLE_FLOATING_WINDOW,
        OPTION_FLOATING_WINDOW_SIZE,
        OPTION_FLOATING_WINDOW_UNTOUCHABLE,
        OPTION_FLOATING_WINDOW_TRANSPARENCY,
        OPTION_FLOATING_WINDOW_SVG,
        OPTION_KEEP_SCREEN_ON,
        // Client-side: keep client system awake during outgoing sessions (General setting)
        OPTION_KEEP_AWAKE_DURING_OUTGOING_SESSIONS,
        OPTION_DISABLE_DISCOVERY_PANEL,
        OPTION_PRE_ELEVATE_SERVICE,
        OPTION_ALLOW_REMOTE_CM_MODIFICATION,
        OPTION_ALLOW_AUTO_RECORD_OUTGOING,
        OPTION_HIDE_RECORDING_BUTTON,
        OPTION_VIDEO_SAVE_DIRECTORY,
        OPTION_ENABLE_UDP_PUNCH,
        OPTION_ENABLE_IPV6_PUNCH,
        OPTION_TOUCH_MODE,
        OPTION_SHOW_VIRTUAL_MOUSE,
        OPTION_SHOW_VIRTUAL_JOYSTICK,
        OPTION_ENABLE_FLUTTER_HTTP_ON_RUST,
        OPTION_ALLOW_ASK_FOR_NOTE,
    ];
    // DEFAULT_SETTINGS, OVERWRITE_SETTINGS
    pub const KEYS_SETTINGS: &[&str] = &[
        OPTION_ACCESS_MODE,
        OPTION_ENABLE_KEYBOARD,
        OPTION_ENABLE_CLIPBOARD,
        OPTION_ENABLE_FILE_TRANSFER,
        OPTION_ENABLE_CAMERA,
        OPTION_ENABLE_TERMINAL,
        OPTION_ENABLE_REMOTE_PRINTER,
        OPTION_ENABLE_AUDIO,
        OPTION_ENABLE_TUNNEL,
        OPTION_ENABLE_REMOTE_RESTART,
        OPTION_ENABLE_RECORD_SESSION,
        OPTION_ENABLE_BLOCK_INPUT,
        OPTION_ENABLE_PRIVACY_MODE,
        OPTION_ALLOW_SCOPE_VIOLATION_CLOSE,
        OPTION_ALLOW_SCOPE_VIOLATION_ALARM,
        OPTION_ALLOW_REMOTE_CONFIG_MODIFICATION,
        OPTION_ALLOW_NUMERNIC_ONE_TIME_PASSWORD,
        OPTION_ENABLE_LAN_DISCOVERY,
        OPTION_ENABLE_DIRECT_SERVER,
        OPTION_DIRECT_ACCESS_PORT,
        OPTION_WHITELIST,
        OPTION_ID_WHITELIST,
        OPTION_ALLOW_AUTO_DISCONNECT,
        OPTION_AUTO_DISCONNECT_TIMEOUT,
        OPTION_ALLOW_ONLY_CONN_WINDOW_OPEN,
        OPTION_ALLOW_AUTO_RECORD_INCOMING,
        OPTION_UPLOAD_RECORDINGS_TO_SERVER,
        OPTION_WINDOWS_SERVICE_VIDEO_SAVE_DIRECTORY,
        OPTION_ENABLE_ABR,
        OPTION_ALLOW_REMOVE_WALLPAPER,
        OPTION_ALLOW_ALWAYS_SOFTWARE_RENDER,
        OPTION_ALLOW_LINUX_HEADLESS,
        OPTION_ENABLE_HWCODEC,
        OPTION_APPROVE_MODE,
        OPTION_VERIFICATION_METHOD,
        OPTION_TEMPORARY_PASSWORD_LENGTH,
        OPTION_PROXY_URL,
        OPTION_PROXY_USERNAME,
        OPTION_PROXY_PASSWORD,
        OPTION_CUSTOM_RENDEZVOUS_SERVER,
        OPTION_API_SERVER,
        OPTION_KEY,
        OPTION_ALLOW_WEBSOCKET,
        OPTION_PRESET_ADDRESS_BOOK_NAME,
        OPTION_PRESET_ADDRESS_BOOK_TAG,
        OPTION_PRESET_ADDRESS_BOOK_ALIAS,
        OPTION_PRESET_ADDRESS_BOOK_PASSWORD,
        OPTION_PRESET_ADDRESS_BOOK_NOTE,
        OPTION_PRESET_DEVICE_USERNAME,
        OPTION_PRESET_DEVICE_NAME,
        OPTION_PRESET_NOTE,
        OPTION_ENABLE_DIRECTX_CAPTURE,
        OPTION_ENABLE_ANDROID_SOFTWARE_ENCODING_HALF_SCALE,
        OPTION_ENABLE_TRUSTED_DEVICES,
        OPTION_RELAY_SERVER,
        OPTION_ICE_SERVERS,
        OPTION_DISABLE_UDP,
        OPTION_KEEP_AWAKE_DURING_INCOMING_SESSIONS,
    ];

    // BUILDIN_SETTINGS
    pub const KEYS_BUILDIN_SETTINGS: &[&str] = &[
        OPTION_DISPLAY_NAME,
        OPTION_AVATAR,
        OPTION_PRESET_DEVICE_GROUP_NAME,
        OPTION_PRESET_USERNAME,
        OPTION_PRESET_STRATEGY_NAME,
        OPTION_REMOVE_PRESET_PASSWORD_WARNING,
        OPTION_HIDE_SECURITY_SETTINGS,
        OPTION_HIDE_NETWORK_SETTINGS,
        OPTION_HIDE_SERVER_SETTINGS,
        OPTION_HIDE_PROXY_SETTINGS,
        OPTION_HIDE_REMOTE_PRINTER_SETTINGS,
        OPTION_HIDE_WEBSOCKET_SETTINGS,
        OPTION_HIDE_STOP_SERVICE,
        OPTION_HIDE_USERNAME_ON_CARD,
        OPTION_HIDE_HELP_CARDS,
        OPTION_DEFAULT_CONNECT_PASSWORD,
        OPTION_HIDE_TRAY,
        OPTION_ONE_WAY_CLIPBOARD_REDIRECTION,
        OPTION_ALLOW_LOGON_SCREEN_PASSWORD,
        OPTION_ALLOW_DEEP_LINK_PASSWORD,
        OPTION_ALLOW_DEEP_LINK_SERVER_SETTINGS,
        OPTION_ONE_WAY_FILE_TRANSFER,
        OPTION_ALLOW_HTTPS_21114,
        OPTION_ALLOW_HOSTNAME_AS_ID,
        OPTION_REGISTER_DEVICE,
        OPTION_HIDE_POWERED_BY_ME,
        OPTION_MAIN_WINDOW_ALWAYS_ON_TOP,
        OPTION_FILE_TRANSFER_MAX_FILES,
        OPTION_DISABLE_CHANGE_PERMANENT_PASSWORD,
        OPTION_DISABLE_CHANGE_ID,
        OPTION_DISABLE_UNLOCK_PIN,
        OPTION_USE_RAW_TCP_FOR_API,
        OPTION_ENABLE_PERM_CHANGE_IN_ACCEPT_WINDOW,
        OPTION_ALLOW_COMMAND_LINE_SETTINGS_WHEN_SETTINGS_DISABLED,
    ];
}

pub fn common_load<
    T: serde::Serialize + serde::de::DeserializeOwned + Default + std::fmt::Debug,
>(
    suffix: &str,
) -> T {
    Config::load_::<T>(suffix)
}

pub fn common_store<T: serde::Serialize>(config: &T, suffix: &str) {
    Config::store_(config, suffix);
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct Status {
    #[serde(default, deserialize_with = "deserialize_hashmap_string_string")]
    values: HashMap<String, String>,
}

impl Status {
    fn load() -> Status {
        Config::load_::<Status>("_status")
    }

    fn store(&self) {
        Config::store_(self, "_status");
    }

    pub fn get(k: &str) -> String {
        STATUS
            .read()
            .unwrap()
            .values
            .get(k)
            .cloned()
            .unwrap_or_default()
    }

    pub fn set(k: &str, v: String) {
        if Self::get(k) == v {
            return;
        }

        let mut st = STATUS.write().unwrap();
        st.values.insert(k.to_owned(), v);
        st.store();
    }
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::{permanent_password::PERMANENT_PASSWORD_ENC_VERSION, *};
    use crate::password_security::SECRET_STORAGE_VERSION;
    use std::{
        ffi::OsString,
        sync::{
            atomic::{AtomicUsize, Ordering},
            MutexGuard,
        },
    };

    static CONFIG_STATE_TEST_LOCK: Mutex<()> = Mutex::new(());
    static CONFIG_PATH_TEST_ID: AtomicUsize = AtomicUsize::new(0);

    struct ConfigStateTestGuard {
        original_config: Config,
        original_config2: Config2,
        original_hard_settings: HashMap<String, String>,
        original_default_settings: HashMap<String, String>,
        original_overwrite_settings: HashMap<String, String>,
        original_trusted_devices: (Vec<TrustedDevice>, bool),
        original_key_pair: Option<KeyPair>,
    }

    struct ConfigPathTestGuard {
        original_app_name: String,
        original_home: Option<OsString>,
        original_xdg_config_home: Option<OsString>,
        path: PathBuf,
    }

    impl ConfigStateTestGuard {
        fn new(config: Config, hard_settings: HashMap<String, String>) -> Self {
            let original_config = Config::get();
            let original_config2 = CONFIG2.read().unwrap().clone();
            let original_hard_settings = HARD_SETTINGS.read().unwrap().clone();
            let original_default_settings = DEFAULT_SETTINGS.read().unwrap().clone();
            let original_overwrite_settings = OVERWRITE_SETTINGS.read().unwrap().clone();
            let original_trusted_devices = TRUSTED_DEVICES.read().unwrap().clone();
            let original_key_pair = KEY_PAIR.lock().unwrap().clone();
            *CONFIG.write().unwrap() = config;
            *CONFIG2.write().unwrap() = Config2::default();
            *HARD_SETTINGS.write().unwrap() = hard_settings;
            *TRUSTED_DEVICES.write().unwrap() = Default::default();
            Self {
                original_config,
                original_config2,
                original_hard_settings,
                original_default_settings,
                original_overwrite_settings,
                original_trusted_devices,
                original_key_pair,
            }
        }
    }

    impl Drop for ConfigStateTestGuard {
        fn drop(&mut self) {
            *CONFIG.write().unwrap() = self.original_config.clone();
            *CONFIG2.write().unwrap() = self.original_config2.clone();
            *HARD_SETTINGS.write().unwrap() = self.original_hard_settings.clone();
            *DEFAULT_SETTINGS.write().unwrap() = self.original_default_settings.clone();
            *OVERWRITE_SETTINGS.write().unwrap() = self.original_overwrite_settings.clone();
            *TRUSTED_DEVICES.write().unwrap() = self.original_trusted_devices.clone();
            *KEY_PAIR.lock().unwrap() = self.original_key_pair.clone();
        }
    }

    impl ConfigPathTestGuard {
        fn new() -> Self {
            let id = CONFIG_PATH_TEST_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "camellia-hbb-common-config-test-{}-{id}",
                std::process::id()
            ));
            fs::remove_dir_all(&path).ok();
            fs::create_dir_all(&path).unwrap();
            let original_home = std::env::var_os("HOME");
            let original_xdg_config_home = std::env::var_os("XDG_CONFIG_HOME");
            let original_app_name = APP_NAME.read().unwrap().clone();
            std::env::set_var("HOME", &path);
            std::env::set_var("XDG_CONFIG_HOME", path.join("config"));
            *APP_NAME.write().unwrap() = format!("CamelliaTest{id}");
            Self {
                original_app_name,
                original_home,
                original_xdg_config_home,
                path,
            }
        }
    }

    impl Drop for ConfigPathTestGuard {
        fn drop(&mut self) {
            *APP_NAME.write().unwrap() = self.original_app_name.clone();
            if let Some(value) = &self.original_home {
                std::env::set_var("HOME", value);
            } else {
                std::env::remove_var("HOME");
            }
            if let Some(value) = &self.original_xdg_config_home {
                std::env::set_var("XDG_CONFIG_HOME", value);
            } else {
                std::env::remove_var("XDG_CONFIG_HOME");
            }
            fs::remove_dir_all(&self.path).ok();
        }
    }

    fn lock_config_state_for_test() -> MutexGuard<'static, ()> {
        CONFIG_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn with_config_and_hard_settings<R>(
        config: Config,
        hard_settings: HashMap<String, String>,
        test: impl FnOnce() -> R,
    ) -> R {
        let _guard = lock_config_state_for_test();
        let _path_guard = ConfigPathTestGuard::new();
        let _state_guard = ConfigStateTestGuard::new(config, hard_settings);
        test()
    }

    fn managed_policy(
        id: &str,
        uuid: &str,
        generation: u64,
        options: BTreeMap<String, String>,
    ) -> ManagedPolicy {
        let digest = ManagedPolicy::canonical_digest(&options).unwrap();
        ManagedPolicy::from_wire(id.to_owned(), uuid.to_owned(), generation, digest, options)
            .unwrap()
    }

    #[test]
    fn test_managed_policy_digest_matches_management_canonical_json() {
        let options = BTreeMap::from([
            ("unicode".to_owned(), "雪/é".to_owned()),
            ("quote".to_owned(), "a\"b\n".to_owned()),
            ("approve-mode".to_owned(), "password".to_owned()),
        ]);

        assert_eq!(
            ManagedPolicy::canonical_digest(&options).as_deref(),
            Some("b9d80ff3556f4b8cdc0ced84602f15c4bc6ed89b6d003bb58a99f7936e051c24")
        );
        assert!(ManagedPolicy::from_wire(
            "123456789".to_owned(),
            "deployment-uuid".to_owned(),
            1,
            "0".repeat(64),
            options.clone(),
        )
        .is_none());
        assert!(ManagedPolicy::from_wire(
            "x".repeat(MANAGED_POLICY_MAX_ID_BYTES + 1),
            "deployment-uuid".to_owned(),
            1,
            ManagedPolicy::canonical_digest(&options).unwrap(),
            options.clone(),
        )
        .is_none());
        assert!(ManagedPolicy::from_wire(
            "123456789".to_owned(),
            "x".repeat(MANAGED_POLICY_MAX_UUID_BYTES + 1),
            1,
            ManagedPolicy::canonical_digest(&options).unwrap(),
            options.clone(),
        )
        .is_none());

        let oversized = BTreeMap::from([(
            "key".to_owned(),
            "v".repeat(MANAGED_POLICY_MAX_VALUE_BYTES + 1),
        )]);
        assert!(ManagedPolicy::canonical_digest(&oversized).is_some());
        assert!(ManagedPolicy::from_wire(
            "123456789".to_owned(),
            "deployment-uuid".to_owned(),
            1,
            ManagedPolicy::canonical_digest(&oversized).unwrap(),
            oversized,
        )
        .is_none());
    }

    #[test]
    fn test_managed_policy_transition_rejects_rollback_and_conflict() {
        let current = managed_policy(
            "123456789",
            "deployment-uuid",
            8,
            BTreeMap::from([("approve-mode".to_owned(), "password".to_owned())]),
        );

        assert_eq!(
            current.transition_from(&ManagedPolicy::default()),
            ManagedPolicyTransition::Apply
        );
        assert_eq!(
            current.transition_from(&current),
            ManagedPolicyTransition::Unchanged
        );
        assert_eq!(
            managed_policy("123456789", "deployment-uuid", 7, BTreeMap::new())
                .transition_from(&current),
            ManagedPolicyTransition::RejectRollback
        );
        assert_eq!(
            managed_policy("123456789", "deployment-uuid", 8, BTreeMap::new())
                .transition_from(&current),
            ManagedPolicyTransition::RejectConflict
        );
        assert_eq!(
            managed_policy("123456789", "deployment-uuid", 9, BTreeMap::new())
                .transition_from(&current),
            ManagedPolicyTransition::Apply
        );
        assert_eq!(
            managed_policy("new-id", "deployment-uuid", 0, BTreeMap::new())
                .transition_from(&current),
            ManagedPolicyTransition::Apply
        );
        assert_eq!(
            managed_policy("123456789", "new-uuid", 0, BTreeMap::new()).transition_from(&current),
            ManagedPolicyTransition::Apply
        );

        let mut invalid = current;
        invalid.digest = "f".repeat(64);
        assert_eq!(
            invalid.transition_from(&ManagedPolicy::default()),
            ManagedPolicyTransition::RejectInvalid
        );
    }

    #[test]
    fn test_managed_policy_layer_precedence_persistence_and_tombstone() {
        let _guard = lock_config_state_for_test();
        let _path_guard = ConfigPathTestGuard::new();
        let _state_guard = ConfigStateTestGuard::new(Config::default(), HashMap::new());
        *DEFAULT_SETTINGS.write().unwrap() = HashMap::from([
            ("managed-default".to_owned(), "default".to_owned()),
            ("overwrite".to_owned(), "default".to_owned()),
        ]);
        *OVERWRITE_SETTINGS.write().unwrap() =
            HashMap::from([("overwrite".to_owned(), "built-in".to_owned())]);
        CONFIG2.write().unwrap().options = HashMap::from([
            ("managed-default".to_owned(), "user".to_owned()),
            ("user-only".to_owned(), "user-only-value".to_owned()),
        ]);

        let applied = managed_policy(
            "123456789",
            "deployment-uuid",
            1,
            BTreeMap::from([
                ("managed-default".to_owned(), "managed".to_owned()),
                ("managed-only".to_owned(), "managed-only-value".to_owned()),
                ("overwrite".to_owned(), "managed".to_owned()),
            ]),
        );
        assert_eq!(
            Config::apply_managed_policy(applied.clone()),
            ManagedPolicyApplyResult::Applied
        );
        assert_eq!(Config::get_option("managed-default"), "managed");
        assert_eq!(Config::get_option("managed-only"), "managed-only-value");
        assert_eq!(Config::get_option("user-only"), "user-only-value");
        assert_eq!(Config::get_option("overwrite"), "built-in");
        assert_eq!(
            Config::load_::<Config2>("2").managed_policy,
            applied,
            "managed policy must be durable before apply returns"
        );

        Config::set_option("managed-default".to_owned(), "attempted-change".to_owned());
        let mut submitted_effective = Config::get_options();
        submitted_effective.insert("managed-default".to_owned(), "second-attempt".to_owned());
        Config::set_options(submitted_effective);
        assert_eq!(
            CONFIG2
                .read()
                .unwrap()
                .options
                .get("managed-default")
                .map(String::as_str),
            Some("user")
        );

        let tombstone = managed_policy("123456789", "deployment-uuid", 2, BTreeMap::new());
        assert_eq!(
            Config::apply_managed_policy(tombstone.clone()),
            ManagedPolicyApplyResult::Applied
        );
        assert_eq!(Config::get_option("managed-default"), "user");
        assert_eq!(Config::get_option("managed-only"), "");
        assert_eq!(Config::get_option("overwrite"), "built-in");
        assert_eq!(
            Config::apply_managed_policy(applied),
            ManagedPolicyApplyResult::RejectedRollback
        );

        *CONFIG2.write().unwrap() = Config2::load();
        assert_eq!(Config::get_managed_policy(), tombstone);
        assert_eq!(Config::get_option("managed-default"), "user");
    }

    #[test]
    fn test_managed_policy_store_failure_does_not_publish_memory_state() {
        let _guard = lock_config_state_for_test();
        let path_guard = ConfigPathTestGuard::new();
        let _state_guard = ConfigStateTestGuard::new(Config::default(), HashMap::new());
        let config_file = Config2::file();
        let config_parent = config_file.parent().unwrap();
        fs::create_dir_all(config_parent.parent().unwrap()).unwrap();
        fs::write(config_parent, b"not-a-directory").unwrap();

        let policy = managed_policy(
            "123456789",
            "deployment-uuid",
            1,
            BTreeMap::from([("approve-mode".to_owned(), "password".to_owned())]),
        );
        assert_eq!(
            Config::apply_managed_policy(policy),
            ManagedPolicyApplyResult::StoreFailed
        );
        assert_eq!(Config::get_managed_policy(), ManagedPolicy::default());
        assert_eq!(Config::get_option("approve-mode"), "");

        drop(path_guard);
    }

    #[test]
    fn test_serialize() {
        let cfg: Config = Default::default();
        let res = toml::to_string_pretty(&cfg);
        assert!(res.is_ok());
        let cfg: PeerConfig = Default::default();
        let res = toml::to_string_pretty(&cfg);
        assert!(res.is_ok());
    }

    #[test]
    fn generated_passwords_preserve_length_and_alphabet() {
        for length in [0, 1, 6, 32, 256] {
            let password = Config::get_auto_password(length);
            assert_eq!(password.chars().count(), length);
            assert!(password.chars().all(|value| CHARS.contains(&value)));
            let numeric = Config::get_auto_numeric_password(length);
            assert_eq!(numeric.chars().count(), length);
            assert!(numeric.chars().all(|value| NUM_CHARS.contains(&value)));
        }
    }

    #[test]
    fn toml_roundtrip_preserves_peer_options_and_escaped_values() {
        let mut config = PeerConfig::default();
        config.options.insert("empty".into(), String::new());
        config
            .options
            .insert("quoted.key".into(), "line\n\"value\"".into());
        let encoded = toml::to_string_pretty(&config).unwrap();
        let decoded: PeerConfig = toml::from_str(&encoded).unwrap();
        assert_eq!(decoded.options, config.options);
        assert_eq!(
            toml::from_str::<toml::Value>(&encoded).unwrap(),
            toml::Value::try_from(&decoded).unwrap()
        );
    }

    #[test]
    fn test_hbbs_00_hashed_preset_password_storage_matches_plain_with_salt() {
        let salt = "salt123";
        let h1 = compute_permanent_password_h1("p@ssw0rd", salt);
        let storage = "00".to_owned() + &BASE64.encode(h1);
        let hard_settings = HashMap::from([
            ("password".to_owned(), storage),
            ("salt".to_owned(), salt.to_owned()),
        ]);

        with_config_and_hard_settings(Config::default(), hard_settings, || {
            assert!(Config::has_permanent_password());
            assert!(Config::has_usable_preset_password());
            assert!(Config::is_using_preset_password());
            assert_eq!(Config::get_effective_permanent_password_salt(), salt);
        });
    }

    #[test]
    fn test_preset_hash_without_salt_is_rejected() {
        let h1 = compute_permanent_password_h1("p@ssw0rd", "salt123");
        let storage = "00".to_owned() + &BASE64.encode(h1);
        let hard_settings = HashMap::from([("password".to_owned(), storage.clone())]);

        let mut config = Config::default();
        config.salt = "local1".to_owned();

        with_config_and_hard_settings(config, hard_settings, || {
            assert!(!Config::has_permanent_password());
            assert!(!Config::has_usable_preset_password());
            assert!(!Config::is_using_preset_password());
            assert_eq!(Config::get_effective_permanent_password_salt(), "");
        });
    }

    #[test]
    fn test_local_hashed_permanent_password_without_salt_is_not_reported_as_set() {
        let h1 = compute_permanent_password_h1("p@ssw0rd", "salt123");
        let mut config = Config::default();
        config.password = encode_permanent_password_encrypted_storage_from_h1(&h1).unwrap();

        with_config_and_hard_settings(config, HashMap::new(), || {
            assert!(!Config::has_permanent_password());
            assert!(!Config::has_local_permanent_password());
            assert!(!Config::is_using_preset_password());
        });
    }

    #[test]
    fn test_invalid_local_hashed_password_does_not_generate_effective_salt() {
        let h1 = compute_permanent_password_h1("p@ssw0rd", "salt123");
        let mut config = Config::default();
        config.password = encode_permanent_password_encrypted_storage_from_h1(&h1).unwrap();

        with_config_and_hard_settings(config, HashMap::new(), || {
            assert_eq!(Config::get_effective_permanent_password_salt(), "");
            assert_eq!(
                Config::get_local_permanent_password_storage_and_salt().1,
                ""
            );
        });
    }

    #[test]
    fn test_plaintext_preset_is_rejected() {
        let mut config = Config::default();
        config.salt = "local1".to_owned();
        let hard_settings = HashMap::from([("password".to_owned(), "preset-password".to_owned())]);

        with_config_and_hard_settings(config, hard_settings, || {
            assert_eq!(Config::get_effective_permanent_password_salt(), "");
            assert!(!Config::has_permanent_password());
            assert!(!Config::is_using_preset_password());
        });
    }

    #[test]
    fn test_malformed_preset_password_with_salt_is_not_usable() {
        for storage in ["01secret", "00not-a-valid-hash"] {
            let hard_settings = HashMap::from([
                ("password".to_owned(), storage.to_owned()),
                ("salt".to_owned(), "preset-salt".to_owned()),
            ]);

            with_config_and_hard_settings(Config::default(), hard_settings, || {
                assert_eq!(Config::get_effective_permanent_password_salt(), "");
                assert_eq!(
                    Config::get_local_permanent_password_storage_and_salt().1,
                    ""
                );
                assert!(!Config::has_permanent_password());
                assert!(!Config::is_using_preset_password());
            });
        }
    }

    #[test]
    fn test_validation_rejects_noncurrent_plaintext_permanent_password() {
        let mut cfg = Config::default();
        cfg.password = "p@ssw0rd".to_owned();
        cfg.salt = "".to_owned();
        assert!(Config::validate_permanent_password_storage(&cfg).is_err());
        assert_eq!(cfg.password, "p@ssw0rd");
        assert!(cfg.salt.is_empty());
    }

    #[test]
    fn test_validation_rejects_general_encrypted_permanent_password() {
        let mut cfg = Config::default();
        cfg.password = encrypt_str("noncurrent-secret", ENCRYPT_MAX_LEN).unwrap();
        cfg.salt = "salt123".to_owned();
        assert!(Config::validate_permanent_password_storage(&cfg).is_err());
    }

    #[test]
    fn test_validation_rejects_corrupted_general_encrypted_permanent_password_storage() {
        let encrypted_storage = encrypt_str("noncurrent-secret", ENCRYPT_MAX_LEN).unwrap();
        let mut invalid_payload = BASE64
            .decode(&encrypted_storage.as_bytes()[SECRET_STORAGE_VERSION.len()..])
            .unwrap();
        *invalid_payload.last_mut().unwrap() ^= 1;

        let mut cfg = Config::default();
        cfg.password = SECRET_STORAGE_VERSION.to_owned() + &BASE64.encode(invalid_payload);
        cfg.salt = "salt123".to_owned();

        assert!(Config::validate_permanent_password_storage(&cfg).is_err());
    }

    #[test]
    fn test_validation_rejects_current_permanent_password_without_salt() {
        let mut cfg = Config::default();
        let h1 = compute_permanent_password_h1("p@ssw0rd", "salt123");
        cfg.password = encode_permanent_password_encrypted_storage_from_h1(&h1).unwrap();
        let original_password = cfg.password.clone();

        assert!(Config::validate_permanent_password_storage(&cfg).is_err());
        assert_eq!(cfg.password, original_password);
        assert!(cfg.salt.is_empty());
    }

    #[test]
    fn test_set_sanitizes_invalid_permanent_password_storage_in_memory_and_on_disk() {
        let mut cfg = Config::default();
        let invalid_payload = crate::password_security::encrypt_local(b"not-a-hash").unwrap();
        cfg.password = PERMANENT_PASSWORD_ENC_VERSION.to_owned() + &BASE64.encode(invalid_payload);
        cfg.salt = "salt123".to_owned();
        cfg.id = "123456789".to_owned();

        with_config_and_hard_settings(Config::default(), HashMap::new(), || {
            assert!(Config::set(cfg));

            let updated = Config::get();
            assert!(updated.password.is_empty());
            assert!(updated.salt.is_empty());
            assert_eq!(updated.id, "123456789");
            let stored = Config::load_::<Config>("");
            assert!(stored.password.is_empty());
            assert!(stored.salt.is_empty());
        });
    }

    #[test]
    fn test_store_keeps_existing_enc_id_when_id_is_unchanged() {
        let mut cfg = Config::default();
        cfg.id = "123456789".to_owned();
        cfg.enc_id = encrypt_str(&cfg.id, ENCRYPT_MAX_LEN).unwrap();
        let original_enc_id = cfg.enc_id.clone();

        with_config_and_hard_settings(Config::default(), HashMap::new(), || {
            assert!(Config::set(cfg));

            assert_eq!(Config::load().enc_id, original_enc_id);
            assert_eq!(Config::get().id, "123456789");
        });
    }

    #[test]
    fn test_store_rewrites_enc_id_when_id_changes() {
        let original_id = "123456789";
        let updated_id = "987654321";
        let mut cfg = Config::default();
        cfg.id = updated_id.to_owned();
        let original_enc_id = encrypt_str(original_id, ENCRYPT_MAX_LEN).unwrap();
        cfg.enc_id = original_enc_id.clone();

        with_config_and_hard_settings(Config::default(), HashMap::new(), || {
            assert!(Config::set(cfg));

            let stored = Config::load().enc_id;
            let stored_id = decrypt_str(&stored).unwrap();
            assert_ne!(stored, original_enc_id);
            assert_eq!(stored_id, updated_id);
            assert_eq!(Config::get().id, updated_id);
        });
    }

    #[test]
    fn test_config2_store_keeps_existing_unlock_pin_when_pin_is_unchanged() {
        let _guard = lock_config_state_for_test();
        let _path_guard = ConfigPathTestGuard::new();
        let pin = "123456";
        let original_unlock_pin = encrypt_str(pin, ENCRYPT_MAX_LEN).unwrap();
        let mut cfg = Config2 {
            unlock_pin: original_unlock_pin.clone(),
            ..Default::default()
        };
        Config::store_(&cfg, "2");
        cfg.unlock_pin = decrypt_str(&cfg.unlock_pin).unwrap();
        cfg.nat_type = 1;

        cfg.store();

        let stored = Config::load_::<Config2>("2");
        assert_eq!(stored.unlock_pin, original_unlock_pin);
    }

    #[test]
    fn test_set_clears_noncurrent_plaintext_permanent_password() {
        let mut cfg = Config::default();
        cfg.password = "noncurrent-secret".to_owned();
        cfg.salt = "salt123".to_owned();

        with_config_and_hard_settings(Config::default(), HashMap::new(), || {
            assert!(!Config::set(cfg));

            let updated = Config::get();
            assert!(updated.password.is_empty());
            assert!(updated.salt.is_empty());
        });
    }

    #[test]
    fn test_set_invalidates_trusted_devices_only_when_permanent_credentials_change() {
        let initial_salt = format!("password-salt-{}", std::process::id());
        let initial_h1 = compute_permanent_password_h1("initial-password", &initial_salt);
        let mut config = Config {
            password: encode_permanent_password_encrypted_storage_from_h1(&initial_h1).unwrap(),
            salt: initial_salt.clone(),
            ..Default::default()
        };
        with_config_and_hard_settings(config.clone(), HashMap::new(), || {
            let trusted_device = TrustedDevice {
                device_id: "trusted-device".to_owned(),
                public_key: Bytes::from(vec![1u8; 32]),
                public_key_fingerprint: "fingerprint".to_owned(),
                name: "Test device".to_owned(),
                platform: "test".to_owned(),
                created_at: crate::get_time(),
                last_used_at: crate::get_time(),
                hwid: Bytes::from(vec![1, 2, 3, 4]),
            };
            Config::set_trusted_devices(vec![trusted_device.clone()]);

            config.key_confirmed = true;
            assert!(Config::set(config.clone()));
            assert_eq!(Config::get_trusted_devices().len(), 1);

            let replacement_h1 =
                compute_permanent_password_h1("replacement-password", &initial_salt);
            config.password =
                encode_permanent_password_encrypted_storage_from_h1(&replacement_h1).unwrap();
            assert!(Config::set(config.clone()));
            assert!(Config::get_trusted_devices().is_empty());

            Config::set_trusted_devices(vec![trusted_device]);
            config.salt = format!("replacement-salt-{}", std::process::id());
            let resalted_h1 = compute_permanent_password_h1("replacement-password", &config.salt);
            config.password =
                encode_permanent_password_encrypted_storage_from_h1(&resalted_h1).unwrap();
            assert!(Config::set(config));
            assert!(Config::get_trusted_devices().is_empty());
        });
    }

    #[test]
    fn test_set_clears_invalid_current_prefixed_permanent_password() {
        let mut cfg = Config::default();
        cfg.password = "01not-current-storage".to_owned();
        cfg.salt = "salt123".to_owned();

        with_config_and_hard_settings(Config::default(), HashMap::new(), || {
            assert!(!Config::set(cfg));

            let updated = Config::get();
            assert!(updated.password.is_empty());
            assert!(updated.salt.is_empty());
        });
    }

    #[test]
    fn test_validation_rejects_current_prefixed_non_hash_payload() {
        let mut cfg = Config::default();
        let plain = "01".to_owned() + &BASE64.encode([42u8; 24]);
        cfg.password = plain.clone();
        cfg.salt = "salt123".to_owned();

        assert!(Config::validate_permanent_password_storage(&cfg).is_err());
        assert_eq!(cfg.password, plain);
        assert_eq!(cfg.salt, "salt123");
    }

    #[test]
    fn test_permanent_password_sync_treats_same_encrypted_hash_as_unchanged() {
        let mut cfg = Config::default();
        cfg.salt = "salt123".to_owned();
        let h1 = compute_permanent_password_h1("p@ssw0rd", &cfg.salt);
        let encrypted_hash_storage =
            encode_permanent_password_encrypted_storage_from_h1(&h1).unwrap();
        cfg.password = encrypted_hash_storage.clone();
        Config::validate_permanent_password_storage(&cfg).unwrap();

        assert!(!Config::apply_permanent_password_storage_for_sync(
            &mut cfg,
            &encrypted_hash_storage,
            "salt123"
        )
        .unwrap());
    }

    #[test]
    fn test_permanent_password_sync_stores_incoming_encrypted_hash_when_local_empty() {
        let salt = "salt123";
        let h1 = compute_permanent_password_h1("p@ssw0rd", salt);
        let incoming = encode_permanent_password_encrypted_storage_from_h1(&h1).unwrap();
        let mut cfg = Config::default();

        assert!(
            Config::apply_permanent_password_storage_for_sync(&mut cfg, &incoming, salt).unwrap()
        );
        assert_eq!(cfg.password, incoming);
        assert_eq!(cfg.salt, salt);
    }

    #[test]
    fn test_permanent_password_sync_rejects_non_current_storage_payloads() {
        let invalid_payload = vec![42u8; crate::crypto::secretbox::MACBYTES + 1];
        let invalid_storage =
            PERMANENT_PASSWORD_ENC_VERSION.to_owned() + &BASE64.encode(invalid_payload);
        let encrypted_noncurrent_plaintext =
            encrypt_str("noncurrent-secret", ENCRYPT_MAX_LEN).unwrap();

        let encrypted = crate::password_security::encrypt_local(b"not-a-hash").unwrap();
        let encrypted_non_hash =
            PERMANENT_PASSWORD_ENC_VERSION.to_owned() + &BASE64.encode(encrypted);
        for storage in [
            "00secret",
            &encrypted_noncurrent_plaintext,
            &invalid_storage,
            "01invalid",
            &encrypted_non_hash,
        ] {
            let mut cfg = Config::default();
            assert!(Config::apply_permanent_password_storage_for_sync(
                &mut cfg, storage, "salt123"
            )
            .is_err());
            assert!(cfg.password.is_empty());
            assert!(cfg.salt.is_empty());
        }

        let mut cfg = Config::default();
        cfg.password = invalid_storage.clone();
        cfg.salt = "salt123".to_owned();
        assert!(Config::apply_permanent_password_storage_for_sync(
            &mut cfg,
            &invalid_storage,
            "salt123"
        )
        .is_err());
        assert_eq!(cfg.password, invalid_storage);
        assert_eq!(cfg.salt, "salt123");
    }

    #[test]
    fn test_permanent_password_sync_rejects_non_empty_storage_without_salt() {
        let mut cfg = Config::default();
        let h1 = compute_permanent_password_h1("p@ssw0rd", "salt123");
        let incoming = encode_permanent_password_encrypted_storage_from_h1(&h1).unwrap();

        assert!(
            Config::apply_permanent_password_storage_for_sync(&mut cfg, &incoming, "").is_err()
        );
        assert!(cfg.password.is_empty());
        assert!(cfg.salt.is_empty());
    }

    #[test]
    fn test_permanent_password_sync_empty_storage_clears_existing_password() {
        let salt = "salt123";
        let h1 = compute_permanent_password_h1("p@ssw0rd", salt);
        let mut cfg = Config::default();
        cfg.password = encode_permanent_password_encrypted_storage_from_h1(&h1).unwrap();
        cfg.salt = salt.to_owned();

        assert!(Config::apply_permanent_password_storage_for_sync(&mut cfg, "", "").unwrap());
        assert!(cfg.password.is_empty());
        assert_eq!(cfg.salt, salt);
    }

    #[test]
    fn test_permanent_password_sync_empty_storage_uses_incoming_salt() {
        let old_salt = "old-salt";
        let h1 = compute_permanent_password_h1("p@ssw0rd", old_salt);
        let mut cfg = Config::default();
        cfg.password = encode_permanent_password_encrypted_storage_from_h1(&h1).unwrap();
        cfg.salt = old_salt.to_owned();

        assert!(
            Config::apply_permanent_password_storage_for_sync(&mut cfg, "", "new-salt").unwrap()
        );
        assert!(cfg.password.is_empty());
        assert_eq!(cfg.salt, "new-salt");
    }

    #[test]
    fn test_overwrite_settings() {
        let _guard = lock_config_state_for_test();
        DEFAULT_SETTINGS
            .write()
            .unwrap()
            .insert("b".to_string(), "a".to_string());
        DEFAULT_SETTINGS
            .write()
            .unwrap()
            .insert("c".to_string(), "a".to_string());
        CONFIG2
            .write()
            .unwrap()
            .options
            .insert("a".to_string(), "b".to_string());
        CONFIG2
            .write()
            .unwrap()
            .options
            .insert("b".to_string(), "b".to_string());
        OVERWRITE_SETTINGS
            .write()
            .unwrap()
            .insert("b".to_string(), "c".to_string());
        OVERWRITE_SETTINGS
            .write()
            .unwrap()
            .insert("c".to_string(), "f".to_string());
        OVERWRITE_SETTINGS
            .write()
            .unwrap()
            .insert("d".to_string(), "c".to_string());
        let mut res: HashMap<String, String> = Default::default();
        res.insert("b".to_owned(), "c".to_string());
        res.insert("d".to_owned(), "c".to_string());
        res.insert("c".to_owned(), "a".to_string());
        Config::purify_options(&mut res);
        assert!(res.is_empty());
        res.insert("b".to_owned(), "c".to_string());
        res.insert("d".to_owned(), "c".to_string());
        res.insert("c".to_owned(), "a".to_string());
        res.insert("f".to_owned(), "a".to_string());
        Config::purify_options(&mut res);
        assert!(res.len() == 1);
        res.insert("b".to_owned(), "c".to_string());
        res.insert("d".to_owned(), "c".to_string());
        res.insert("c".to_owned(), "a".to_string());
        res.insert("f".to_owned(), "a".to_string());
        res.insert("e".to_owned(), "d".to_string());
        Config::purify_options(&mut res);
        assert!(res.len() == 2);
        res.insert("b".to_owned(), "c".to_string());
        res.insert("d".to_owned(), "c".to_string());
        res.insert("c".to_owned(), "a".to_string());
        res.insert("f".to_owned(), "a".to_string());
        res.insert("c".to_owned(), "d".to_string());
        res.insert("d".to_owned(), "cc".to_string());
        Config::purify_options(&mut res);
        DEFAULT_SETTINGS
            .write()
            .unwrap()
            .insert("f".to_string(), "c".to_string());
        Config::purify_options(&mut res);
        assert!(res.len() == 2);
        DEFAULT_SETTINGS
            .write()
            .unwrap()
            .insert("f".to_string(), "a".to_string());
        Config::purify_options(&mut res);
        assert!(res.len() == 1);
        let res = Config::get_options();
        assert!(res["a"] == "b");
        assert!(res["c"] == "f");
        assert!(res["b"] == "c");
        assert!(res["d"] == "c");
        assert!(Config::get_option("a") == "b");
        assert!(Config::get_option("c") == "f");
        assert!(Config::get_option("b") == "c");
        assert!(Config::get_option("d") == "c");
        DEFAULT_SETTINGS.write().unwrap().clear();
        OVERWRITE_SETTINGS.write().unwrap().clear();
        CONFIG2.write().unwrap().options.clear();

        DEFAULT_LOCAL_SETTINGS
            .write()
            .unwrap()
            .insert("b".to_string(), "a".to_string());
        DEFAULT_LOCAL_SETTINGS
            .write()
            .unwrap()
            .insert("c".to_string(), "a".to_string());
        LOCAL_CONFIG
            .write()
            .unwrap()
            .options
            .insert("a".to_string(), "b".to_string());
        LOCAL_CONFIG
            .write()
            .unwrap()
            .options
            .insert("b".to_string(), "b".to_string());
        OVERWRITE_LOCAL_SETTINGS
            .write()
            .unwrap()
            .insert("b".to_string(), "c".to_string());
        OVERWRITE_LOCAL_SETTINGS
            .write()
            .unwrap()
            .insert("d".to_string(), "c".to_string());
        assert!(LocalConfig::get_option("a") == "b");
        assert!(LocalConfig::get_option("c") == "a");
        assert!(LocalConfig::get_option("b") == "c");
        assert!(LocalConfig::get_option("d") == "c");
        DEFAULT_LOCAL_SETTINGS.write().unwrap().clear();
        OVERWRITE_LOCAL_SETTINGS.write().unwrap().clear();
        LOCAL_CONFIG.write().unwrap().options.clear();

        DEFAULT_DISPLAY_SETTINGS
            .write()
            .unwrap()
            .insert("b".to_string(), "a".to_string());
        DEFAULT_DISPLAY_SETTINGS
            .write()
            .unwrap()
            .insert("c".to_string(), "a".to_string());
        USER_DEFAULT_CONFIG
            .write()
            .unwrap()
            .0
            .options
            .insert("a".to_string(), "b".to_string());
        USER_DEFAULT_CONFIG
            .write()
            .unwrap()
            .0
            .options
            .insert("b".to_string(), "b".to_string());
        OVERWRITE_DISPLAY_SETTINGS
            .write()
            .unwrap()
            .insert("b".to_string(), "c".to_string());
        OVERWRITE_DISPLAY_SETTINGS
            .write()
            .unwrap()
            .insert("d".to_string(), "c".to_string());
        assert!(UserDefaultConfig::read("a") == "b");
        assert!(UserDefaultConfig::read("c") == "a");
        assert!(UserDefaultConfig::read("b") == "c");
        assert!(UserDefaultConfig::read("d") == "c");
        DEFAULT_DISPLAY_SETTINGS.write().unwrap().clear();
        OVERWRITE_DISPLAY_SETTINGS.write().unwrap().clear();
        LOCAL_CONFIG.write().unwrap().options.clear();
    }

    #[test]
    fn test_config_deserialize() {
        let wrong_type_str = r#"
        id = true
        enc_id = []
        password = 1
        salt = "123456"
        key_pair = {}
        key_confirmed = "1"
        keys_confirmed = 1
        "#;
        let cfg = toml::from_str::<Config>(wrong_type_str);
        assert_eq!(
            cfg,
            Ok(Config {
                salt: "123456".to_string(),
                ..Default::default()
            })
        );

        let wrong_field_str = r#"
        hello = "world"
        key_confirmed = true
        "#;
        let cfg = toml::from_str::<Config>(wrong_field_str);
        assert_eq!(
            cfg,
            Ok(Config {
                key_confirmed: true,
                ..Default::default()
            })
        );
    }

    #[test]
    fn test_peer_config_deserialize() {
        let default_peer_config = toml::from_str::<PeerConfig>("").unwrap();
        // test custom_resolution
        {
            let wrong_type_str = r#"
            view_style = "adaptive"
            scroll_style = "scrollbar"
            custom_resolutions = true
            "#;
            let mut cfg_to_compare = default_peer_config.clone();
            cfg_to_compare.view_style = "adaptive".to_string();
            cfg_to_compare.scroll_style = "scrollbar".to_string();
            let cfg = toml::from_str::<PeerConfig>(wrong_type_str);
            assert_eq!(cfg, Ok(cfg_to_compare), "Failed to test wrong_type_str");

            let wrong_type_str = r#"
            view_style = "adaptive"
            scroll_style = "scrollbar"
            [custom_resolutions.0]
            w = "1920"
            h = 1080
            "#;
            let mut cfg_to_compare = default_peer_config.clone();
            cfg_to_compare.view_style = "adaptive".to_string();
            cfg_to_compare.scroll_style = "scrollbar".to_string();
            let cfg = toml::from_str::<PeerConfig>(wrong_type_str);
            assert_eq!(cfg, Ok(cfg_to_compare), "Failed to test wrong_type_str");

            let wrong_field_str = r#"
            [custom_resolutions.0]
            w = 1920
            h = 1080
            hello = "world"
            [ui_flutter]
            "#;
            let mut cfg_to_compare = default_peer_config.clone();
            cfg_to_compare.custom_resolutions =
                HashMap::from([("0".to_string(), Resolution { w: 1920, h: 1080 })]);
            let cfg = toml::from_str::<PeerConfig>(wrong_field_str);
            assert_eq!(cfg, Ok(cfg_to_compare), "Failed to test wrong_field_str");
        }
    }

    #[test]
    fn test_store_load() {
        let _guard = lock_config_state_for_test();
        let _path_guard = ConfigPathTestGuard::new();
        let peerconfig_id = "123456789";
        let cfg: PeerConfig = Default::default();
        cfg.store(peerconfig_id);
        assert_eq!(PeerConfig::load(peerconfig_id), cfg);

        #[cfg(not(windows))]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                // ignore file type information by masking with 0o777 (see https://stackoverflow.com/a/50045872)
                fs::metadata(PeerConfig::path(peerconfig_id))
                    .expect("reading metadata failed")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn test_uinput_ipc_path_is_shared_across_uids() {
        let _guard = lock_config_state_for_test();
        const ROOT_UID: u32 = 0;
        const USER_UID: u32 = 1000;

        let path_root = Config::ipc_path_for_uid(ROOT_UID, "_uinput_keyboard");
        let path_user = Config::ipc_path_for_uid(USER_UID, "_uinput_keyboard");
        assert_eq!(path_root, path_user);

        let app_name = APP_NAME.read().unwrap().clone();
        assert!(
            path_root.starts_with(&format!("/tmp/{app_name}-service/")),
            "uinput service IPC path must use the shared service namespace"
        );

        let non_service_root = Config::ipc_path_for_uid(ROOT_UID, "");
        let non_service_user = Config::ipc_path_for_uid(USER_UID, "");
        assert_ne!(non_service_root, non_service_user);
    }

    #[test]
    fn test_log_002_config_debug_redaction() {
        let mut cfg = Config::default();
        cfg.id = "device_test_id_12345".to_string();
        cfg.enc_id = "ENC_ID_CANARY_SECRET_DATA".to_string();
        cfg.password = "PASSWORD_CANARY_HASH_DATA".to_string();
        cfg.salt = "SALT_CANARY_RANDOM_BITS".to_string();
        cfg.key_pair = (
            b"PRIVATE_KEY_CANARY_32_BYTES_OF_RAW_ENTROPY!".to_vec(),
            b"PUBLIC_KEY_CANARY_32_BYTES_OF_PUBLIC_DATA!".to_vec(),
        );
        cfg.key_confirmed = true;
        cfg.keys_confirmed
            .insert("peer_host_test".to_string(), true);

        let debug_output = format!("{:?}", cfg);

        // Assert sensitive secrets are NEVER leaked in Debug formatting
        assert!(
            !debug_output.contains("PRIVATE_KEY_CANARY"),
            "Private key was leaked in Debug output!"
        );
        assert!(
            !debug_output.contains("PASSWORD_CANARY"),
            "Password was leaked in Debug output!"
        );
        assert!(
            !debug_output.contains("SALT_CANARY"),
            "Salt was leaked in Debug output!"
        );
        assert!(
            !debug_output.contains("ENC_ID_CANARY"),
            "Encrypted ID was leaked in Debug output!"
        );

        // Assert redaction markers are present
        assert!(
            debug_output.contains("<redacted>"),
            "Redaction marker missing from Debug output!"
        );

        // Assert non-secret fields remain visible for diagnostics
        assert!(
            debug_output.contains("device_test_id_12345"),
            "ID should remain visible!"
        );
        assert!(
            debug_output.contains("key_confirmed: true"),
            "Key confirmed status should remain visible!"
        );
    }

    #[test]
    fn test_config_001_durable_keypair_persistence() {
        let _guard = lock_config_state_for_test();
        let _path_guard = ConfigPathTestGuard::new();
        Config::reset_key_pair_cache_for_test();

        let config_file = Config::file_("");
        assert!(
            !config_file.exists(),
            "Config file must not exist before test"
        );

        // Calling get_key_pair() should generate and durably persist
        let key_pair = Config::get_key_pair();
        assert!(
            !key_pair.0.is_empty(),
            "Generated secret key must not be empty"
        );
        assert!(
            !key_pair.1.is_empty(),
            "Generated public key must not be empty"
        );

        // The file must now exist on disk
        assert!(
            config_file.exists(),
            "Config file must exist after get_key_pair"
        );

        // Verify file permissions on Unix (0600)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = fs::metadata(&config_file).expect("File metadata must be accessible");
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(
                mode, 0o600,
                "Config file permissions must be 0600, got {:o}",
                mode
            );
        }

        // Read directly from disk without using in-memory cache
        let raw_disk_config = Config::load_::<Config>("");
        assert_eq!(
            raw_disk_config.key_pair, key_pair,
            "Persisted keypair on disk must match the returned keypair"
        );

        // Verify that subsequent get_key_pair() returns the cached keypair
        let cached_key_pair = Config::get_key_pair();
        assert_eq!(
            cached_key_pair, key_pair,
            "Cached keypair must match generated keypair"
        );
    }

    #[test]
    fn test_config_001_fail_closed_when_persistence_fails() {
        let _guard = lock_config_state_for_test();
        let path_guard = ConfigPathTestGuard::new();
        Config::reset_key_pair_cache_for_test();

        // Make the directory read-only so write will fail
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let config_dir = path_guard.path.join("config");
            fs::create_dir_all(&config_dir).ok();
            fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o400)).ok();

            let key_pair = Config::get_key_pair();
            // Persistence failed, so it must fail closed: return empty keypair and NOT cache
            assert!(
                key_pair.0.is_empty() && key_pair.1.is_empty(),
                "Must fail closed by returning empty keypair when persistence fails"
            );
            assert!(
                KEY_PAIR.lock().unwrap().is_none(),
                "Must NOT cache unpersisted keypair in KEY_PAIR lock"
            );

            // Restore permissions for cleanup
            fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o700)).ok();
        }
    }

    #[test]
    fn test_config_004_key_pair_cache_invalidation_across_platforms() {
        let _guard = lock_config_state_for_test();
        let _path_guard = ConfigPathTestGuard::new();
        Config::reset_key_pair_cache_for_test();

        // 1. Initial keypair generation and caching
        let initial_key_pair = Config::get_key_pair();
        assert_eq!(
            KEY_PAIR.lock().unwrap().as_ref(),
            Some(&initial_key_pair),
            "KEY_PAIR must be cached after get_key_pair"
        );

        // 2. Generate a new, different keypair
        let (new_pk, new_sk) = sign::gen_keypair();
        let replacement_key_pair: KeyPair = (new_sk.0.to_vec(), new_pk.0.into());
        assert_ne!(initial_key_pair, replacement_key_pair);

        // 3. Update configuration via Config::set with the replacement keypair
        let mut new_config = Config::get();
        new_config.key_pair = replacement_key_pair.clone();
        let changed = Config::set(new_config);
        assert!(changed, "Config::set must return true when config changed");

        // 4. Assert KEY_PAIR cache was invalidated (must be None) on all platforms!
        assert!(
            KEY_PAIR.lock().unwrap().is_none(),
            "KEY_PAIR cache must be invalidated after Config::set with different keypair"
        );

        // 5. Subsequent call to get_key_pair() should reload and return the new replacement keypair
        let reloaded_key_pair = Config::get_key_pair();
        assert_eq!(
            reloaded_key_pair, replacement_key_pair,
            "get_key_pair must return newly synced keypair, not stale cached keypair"
        );
        assert_eq!(
            KEY_PAIR.lock().unwrap().as_ref(),
            Some(&replacement_key_pair),
            "KEY_PAIR cache must now hold the new keypair"
        );
    }

    #[test]
    fn test_auth_002_protobuf_login_response_and_auth2fa_wire_contracts() {
        use crate::message_proto::{login_response, Auth2FA, LoginResponse};
        use protobuf::Message as _;

        // 1. Verify LoginResponse with challenge and target_id fields
        let mut login_resp = LoginResponse::new();
        login_resp.union = Some(login_response::Union::Error("2FA Required".to_string()));
        login_resp.enable_trusted_devices = true;
        let host_challenge = vec![0x42u8; 32];
        login_resp.challenge = Bytes::copy_from_slice(&host_challenge);
        login_resp.challenge_expires_at = 1730000000;
        login_resp.target_id = "camellia-host-peer-01".to_string();

        let encoded = login_resp.write_to_bytes().expect("protobuf write failed");
        let decoded = LoginResponse::parse_from_bytes(&encoded).expect("protobuf parse failed");

        assert!(decoded.enable_trusted_devices);
        assert_eq!(decoded.challenge.as_ref(), &host_challenge[..]);
        assert_eq!(decoded.challenge_expires_at, 1730000000);
        assert_eq!(decoded.target_id, "camellia-host-peer-01");
        match decoded.union {
            Some(login_response::Union::Error(err)) => assert_eq!(err, "2FA Required"),
            _ => panic!("Expected error union variant"),
        }

        // 2. Verify Auth2FA with challenge, device_pk, device_signature, device_id, trust_this_device
        let mut auth_2fa = Auth2FA::new();
        auth_2fa.code = "123456".to_string();
        auth_2fa.hwid = Bytes::from_static(b"legacy-hwid-metadata");
        auth_2fa.challenge = Bytes::copy_from_slice(&host_challenge);
        let dummy_pk = vec![0x07u8; 32];
        auth_2fa.device_pk = Bytes::copy_from_slice(&dummy_pk);
        let dummy_sig = vec![0xaau8; 64];
        auth_2fa.device_signature = Bytes::copy_from_slice(&dummy_sig);
        auth_2fa.device_id = "camellia-controller-peer-01".to_string();
        auth_2fa.trust_this_device = true;

        let encoded_auth = auth_2fa.write_to_bytes().expect("auth2fa write failed");
        let decoded_auth = Auth2FA::parse_from_bytes(&encoded_auth).expect("auth2fa parse failed");

        assert_eq!(decoded_auth.code, "123456");
        assert_eq!(decoded_auth.hwid.as_ref(), b"legacy-hwid-metadata");
        assert_eq!(decoded_auth.challenge.as_ref(), &host_challenge[..]);
        assert_eq!(decoded_auth.device_pk.as_ref(), &dummy_pk[..]);
        assert_eq!(decoded_auth.device_signature.as_ref(), &dummy_sig[..]);
        assert_eq!(decoded_auth.device_id, "camellia-controller-peer-01");
        assert!(decoded_auth.trust_this_device);
    }

    #[test]
    fn test_auth_002_trusted_device_lifecycle_fingerprint_and_expiration() {
        let pk = [0x5au8; 32];
        let computed_fp = compute_public_key_fingerprint(&pk);
        assert_eq!(computed_fp.len(), 64);
        // Verify lowercase hexadecimal representation
        assert!(computed_fp
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));

        let mut device = TrustedDevice::new(
            "controller-dev-01".to_string(),
            Bytes::copy_from_slice(&pk),
            "Camellia Remote Controller".to_string(),
            "Linux".to_string(),
        );

        assert_eq!(device.device_id, "controller-dev-01");
        assert_eq!(device.public_key_fingerprint, computed_fp);
        assert_eq!(device.name, "Camellia Remote Controller");
        assert_eq!(device.platform, "Linux");
        assert!(!device.is_expired(), "Fresh device must not be expired");
        assert!(!device.outdate(), "outdate alias must match is_expired");

        // Fast-forward last_used_at past 90 days
        const DAYS_91_MS: i64 = 91 * 24 * 60 * 60 * 1000;
        device.last_used_at = crate::get_time() - DAYS_91_MS;
        assert!(device.is_expired(), "Device beyond 90 days must be expired");
        assert!(device.outdate());

        // Fast-forward created_at when last_used_at is 0
        device.last_used_at = 0;
        device.created_at = crate::get_time() - DAYS_91_MS;
        assert!(
            device.is_expired(),
            "Fallback to created_at must expire after 90 days"
        );
    }

    #[test]
    fn test_auth_002_trusted_device_backward_compatible_serde() {
        // Test legacy JSON with "id" and "time"
        let legacy_json = r#"{"id":"legacy-dev-01","time":1700000000000,"name":"Legacy Device","platform":"windows","hwid":[1,2,3,4]}"#;
        let deserialized: TrustedDevice =
            serde_json::from_str(legacy_json).expect("Deserialization failed");

        assert_eq!(deserialized.device_id, "legacy-dev-01");
        assert_eq!(deserialized.created_at, 1700000000000);
        assert_eq!(deserialized.name, "Legacy Device");
        assert_eq!(deserialized.platform, "windows");
        assert_eq!(deserialized.hwid.as_ref(), &[1, 2, 3, 4]);
        assert!(deserialized.public_key.is_empty());
        assert!(deserialized.public_key_fingerprint.is_empty());

        // Test modern JSON round-trip
        let modern_device = TrustedDevice {
            device_id: "modern-dev-02".to_string(),
            public_key: Bytes::from_static(&[0x07; 32]),
            public_key_fingerprint: "0123456789abcdef".to_string(),
            name: "Modern Controller".to_string(),
            platform: "macos".to_string(),
            created_at: 1710000000000,
            last_used_at: 1715000000000,
            hwid: Bytes::from_static(&[5, 6, 7, 8]),
        };

        let serialized = serde_json::to_string(&modern_device).expect("Serialization failed");
        let roundtrip: TrustedDevice =
            serde_json::from_str(&serialized).expect("Deserialization failed");
        assert_eq!(roundtrip, modern_device);
    }

    #[test]
    fn test_auth_002_add_and_remove_trusted_devices() {
        let _guard = lock_config_state_for_test();
        let _path_guard = ConfigPathTestGuard::new();

        Config::clear_trusted_devices();
        assert!(Config::get_trusted_devices().is_empty());

        let dev1 = TrustedDevice {
            device_id: "controller-peer-01".to_string(),
            public_key: Bytes::from_static(&[0x11; 32]),
            public_key_fingerprint: "fp-01".to_string(),
            name: "Work Laptop".to_string(),
            platform: "linux".to_string(),
            created_at: crate::get_time(),
            last_used_at: crate::get_time(),
            hwid: Bytes::new(),
        };

        let dev2 = TrustedDevice {
            device_id: "controller-peer-02".to_string(),
            public_key: Bytes::from_static(&[0x22; 32]),
            public_key_fingerprint: "fp-02".to_string(),
            name: "Home Desktop".to_string(),
            platform: "windows".to_string(),
            created_at: crate::get_time(),
            last_used_at: crate::get_time(),
            hwid: Bytes::new(),
        };

        assert!(Config::add_trusted_device(dev1.clone()).is_ok());
        assert!(Config::add_trusted_device(dev2.clone()).is_ok());

        let devices = Config::get_trusted_devices();
        assert_eq!(devices.len(), 2);
        assert!(devices.iter().any(|d| d.device_id == "controller-peer-01"));
        assert!(devices.iter().any(|d| d.device_id == "controller-peer-02"));

        // Deduplication update
        let mut updated_dev1 = dev1.clone();
        updated_dev1.name = "Work Laptop (Renamed)".to_string();
        assert!(Config::add_trusted_device(updated_dev1).is_ok());
        let devices = Config::get_trusted_devices();
        assert_eq!(devices.len(), 2, "Deduplication must keep list count at 2");
        let found = devices
            .iter()
            .find(|d| d.device_id == "controller-peer-01")
            .unwrap();
        assert_eq!(found.name, "Work Laptop (Renamed)");

        // Removal by device ID slice (&[String] and &[&str])
        assert!(Config::remove_trusted_devices(&["controller-peer-01"]).is_ok());
        let devices = Config::get_trusted_devices();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].device_id, "controller-peer-02");

        // Removal of second device
        let to_remove = vec!["controller-peer-02".to_string()];
        assert!(Config::remove_trusted_devices(&to_remove).is_ok());
        assert!(Config::get_trusted_devices().is_empty());
    }

    #[test]
    fn test_auth_002_add_trusted_device_fail_closed_persistence() {
        let _guard = lock_config_state_for_test();
        let path_guard = ConfigPathTestGuard::new();

        Config::clear_trusted_devices();
        assert!(Config::get_trusted_devices().is_empty());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let config_dir = path_guard.path.join("config");
            fs::create_dir_all(&config_dir).ok();
            fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o400)).ok();

            let device = TrustedDevice {
                device_id: "controller-peer-99".to_string(),
                public_key: Bytes::from_static(&[0x99; 32]),
                public_key_fingerprint: "fp-99".to_string(),
                name: "Attacker / Failing Device".to_string(),
                platform: "linux".to_string(),
                created_at: crate::get_time(),
                last_used_at: crate::get_time(),
                hwid: Bytes::new(),
            };

            let res = Config::add_trusted_device(device);
            assert!(
                res.is_err(),
                "Config::add_trusted_device must return error when disk store fails"
            );

            // Fail-closed invariant: in-memory cache must NOT be updated if disk write fails!
            let cached_devices = Config::get_trusted_devices();
            assert!(
                cached_devices.is_empty(),
                "In-memory trusted devices cache must NOT contain unpersisted device"
            );

            // Restore permissions for cleanup
            fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o700)).ok();
        }
    }

    #[test]
    fn test_auth_002_device_proof_canonical_payload_and_cryptographic_verification() {
        let (public_key, secret_key) = crate::crypto::sign::gen_keypair();
        let challenge = [0x33u8; 32];
        let target_host_id = "camellia-host-target-01";
        let controller_id = "camellia-controller-client-01";
        let session_scope = "remote-desktop";

        // 1. Verify canonical raw payload commitment domain separation
        let raw = create_device_proof_raw_payload(
            &challenge,
            target_host_id,
            controller_id,
            session_scope,
        );
        assert!(raw.starts_with(b"camellia-trusted-device-v1\n"));
        let raw_str = String::from_utf8_lossy(&raw);
        assert!(raw_str.contains(target_host_id));
        assert!(raw_str.contains(controller_id));
        assert!(raw_str.starts_with("camellia-trusted-device-v1\n"));
        assert!(
            !raw_str.contains(concat!("rust", "desk")),
            "Must strictly comply with Camellia Remote branding"
        );

        // 2. Sign device proof
        let signature = sign_device_proof(
            &challenge,
            target_host_id,
            controller_id,
            session_scope,
            &secret_key,
        );
        assert_eq!(signature.len(), 64);

        // 3. Verify valid device proof
        let verify_result = verify_device_proof(
            &challenge,
            target_host_id,
            controller_id,
            session_scope,
            &signature,
            &public_key,
        );
        assert!(
            verify_result.is_ok(),
            "Valid device proof signature must verify successfully"
        );

        // 4. Verify rejection of tampered challenge
        let mut tampered_challenge = challenge;
        tampered_challenge[0] ^= 0xff;
        let tampered_res = verify_device_proof(
            &tampered_challenge,
            target_host_id,
            controller_id,
            session_scope,
            &signature,
            &public_key,
        );
        assert!(
            tampered_res.is_err(),
            "Tampered challenge must fail verification"
        );

        // 5. Verify rejection of mismatched target host ID (replay prevention)
        let wrong_host = "camellia-host-target-02";
        let wrong_host_res = verify_device_proof(
            &challenge,
            wrong_host,
            controller_id,
            session_scope,
            &signature,
            &public_key,
        );
        assert!(
            wrong_host_res.is_err(),
            "Signature tied to target host 01 must fail on target host 02"
        );

        // 6. Verify rejection of mismatched controller ID
        let wrong_controller = "camellia-controller-client-02";
        let wrong_ctrl_res = verify_device_proof(
            &challenge,
            target_host_id,
            wrong_controller,
            session_scope,
            &signature,
            &public_key,
        );
        assert!(
            wrong_ctrl_res.is_err(),
            "Signature tied to controller 01 must fail on controller 02"
        );

        // 7. Verify rejection of mismatched session scope
        let wrong_scope = "file-transfer";
        let wrong_scope_res = verify_device_proof(
            &challenge,
            target_host_id,
            controller_id,
            wrong_scope,
            &signature,
            &public_key,
        );
        assert!(
            wrong_scope_res.is_err(),
            "Signature for remote-desktop must fail on file-transfer"
        );

        // 8. Verify rejection with wrong public key
        let (other_public, _) = crate::crypto::sign::gen_keypair();
        let wrong_pk_res = verify_device_proof(
            &challenge,
            target_host_id,
            controller_id,
            session_scope,
            &signature,
            &other_public,
        );
        assert!(
            wrong_pk_res.is_err(),
            "Verification with different public key must fail"
        );
    }
}
