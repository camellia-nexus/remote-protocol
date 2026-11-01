pub mod compress;
pub mod crypto;
pub mod platform;
pub mod protos;
pub use bytes;
use config::Config;
pub use futures;
pub use protobuf;
pub use protos::message as message_proto;
pub use protos::rendezvous as rendezvous_proto;
use std::{
    fs::File,
    io::{self, BufRead},
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    path::Path,
    time::{self, SystemTime, UNIX_EPOCH},
};
pub use tokio;
pub use tokio_util;
pub mod proxy;
pub mod socket_client;
pub mod tcp;
pub mod udp;
pub use env_logger;
pub use log;
pub mod bytes_codec;
pub use anyhow::{self, bail};
pub use futures_util;
pub mod config;
pub mod fs;
pub mod mem;
pub use lazy_static;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub use mac_address;
pub use rand;
pub use regex;
pub use tokio_socks;
pub use tokio_socks::IntoTargetAddr;
pub use tokio_socks::TargetAddr;
pub mod password_security;
pub use chrono;
pub use directories_next;
pub use libc;
pub mod keyboard;
pub use base64;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub use machine_uid;
pub use serde_derive;
pub use serde_json;
pub use sha2;
pub use sysinfo;
pub use thiserror;
pub use toml;
pub use uuid;
pub mod fingerprint;
pub use flexi_logger;
pub mod endpoint;
pub mod stream;
pub mod websocket;
pub use endpoint::{EndpointError, EndpointHost, ParsedEndpoint};
#[cfg(any(target_os = "android", target_os = "ios"))]
pub use rustls_platform_verifier;
pub use stream::Stream;
pub use whoami;
pub mod tls;
pub mod verifier;
pub use libloading;
#[cfg(target_os = "linux")]
pub use users;
#[cfg(target_os = "linux")]
pub use x11;

pub type SessionID = uuid::Uuid;

#[inline]
pub async fn sleep(sec: f32) {
    tokio::time::sleep(time::Duration::from_secs_f32(sec)).await;
}

#[macro_export]
macro_rules! allow_err {
    ($e:expr) => {
        if let Err(err) = $e {
            log::debug!(
                "{:?}, {}:{}:{}:{}",
                err,
                module_path!(),
                file!(),
                line!(),
                column!()
            );
        } else {
        }
    };

    ($e:expr, $($arg:tt)*) => {
        if let Err(err) = $e {
            log::debug!(
                "{:?}, {}, {}:{}:{}:{}",
                err,
                format_args!($($arg)*),
                module_path!(),
                file!(),
                line!(),
                column!()
            );
        } else {
        }
    };
}

#[inline]
pub fn timeout<T: std::future::Future>(ms: u64, future: T) -> tokio::time::Timeout<T> {
    tokio::time::timeout(std::time::Duration::from_millis(ms), future)
}

pub type ResultType<F, E = anyhow::Error> = anyhow::Result<F, E>;

/// Certain router and firewalls scan the packet and if they
/// find an IP address belonging to their pool that they use to do the NAT mapping/translation, so here we mangle the ip address
pub struct AddrMangle();

#[inline]
pub fn try_into_v4(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) if !addr.ip().is_loopback() => {
            if let Some(v4) = v6.ip().to_ipv4() {
                SocketAddr::new(IpAddr::V4(v4), addr.port())
            } else {
                addr
            }
        }
        _ => addr,
    }
}

impl AddrMangle {
    pub fn encode(addr: SocketAddr) -> Vec<u8> {
        // not work with [:1]:<port>
        let addr = try_into_v4(addr);
        match addr {
            SocketAddr::V4(addr_v4) => {
                let tm = (SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or(std::time::Duration::ZERO)
                    .as_micros() as u32) as u128;
                let ip = u32::from_le_bytes(addr_v4.ip().octets()) as u128;
                let port = addr.port() as u128;
                let v = ((ip + tm) << 49) | (tm << 17) | (port + (tm & 0xFFFF));
                let bytes = v.to_le_bytes();
                let mut n_padding = 0;
                for i in bytes.iter().rev() {
                    if i == &0u8 {
                        n_padding += 1;
                    } else {
                        break;
                    }
                }
                bytes[..(16 - n_padding)].to_vec()
            }
            SocketAddr::V6(addr_v6) => {
                let mut x = addr_v6.ip().octets().to_vec();
                let port: [u8; 2] = addr_v6.port().to_le_bytes();
                x.push(port[0]);
                x.push(port[1]);
                x
            }
        }
    }

    pub fn try_decode(bytes: &[u8]) -> Option<SocketAddr> {
        use std::convert::TryInto;

        if bytes.len() == 18 {
            let tmp: [u8; 2] = bytes[16..].try_into().ok()?;
            let port = u16::from_le_bytes(tmp);
            let tmp: [u8; 16] = bytes[..16].try_into().ok()?;
            let ip = std::net::Ipv6Addr::from(tmp);
            return Some(SocketAddr::new(IpAddr::V6(ip), port));
        }
        if bytes.is_empty() || bytes.len() > 16 || (bytes.len() < 16 && bytes.last() == Some(&0)) {
            return None;
        }
        let mut padded = [0u8; 16];
        padded[..bytes.len()].copy_from_slice(bytes);
        let number = u128::from_le_bytes(padded);
        let tm = (number >> 17) & (u32::MAX as u128);
        let ip = (number >> 49).checked_sub(tm)?;
        if ip > u32::MAX as u128 {
            return None;
        }
        let port = (number & 0x1FFFF).checked_sub(tm & 0xFFFF)?;
        if port > u16::MAX as u128 {
            return None;
        }
        Some(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::from((ip as u32).to_le_bytes()),
            port as u16,
        )))
    }

    pub fn decode(bytes: &[u8]) -> SocketAddr {
        Self::try_decode(bytes).unwrap_or_else(|| Config::get_any_listen_addr(false))
    }
}

pub fn get_version_from_url(url: &str) -> String {
    let n = url.chars().count();
    let a = url.chars().rev().position(|x| x == '-');
    if let Some(a) = a {
        let b = url.chars().rev().position(|x| x == '.');
        if let Some(b) = b {
            if a > b {
                if url
                    .chars()
                    .skip(n - b)
                    .collect::<String>()
                    .parse::<i32>()
                    .is_ok()
                {
                    return url.chars().skip(n - a).collect();
                } else {
                    return url.chars().skip(n - a).take(a - b - 1).collect();
                }
            } else {
                return url.chars().skip(n - a).collect();
            }
        }
    }
    "".to_owned()
}

pub fn gen_version() {
    println!("cargo:rerun-if-changed=Cargo.toml");
    use std::io::prelude::*;
    let mut file = File::create("./src/version.rs").unwrap();
    for line in read_lines("Cargo.toml").unwrap().map_while(Result::ok) {
        let ab: Vec<&str> = line.split('=').map(|x| x.trim()).collect();
        if ab.len() == 2 && ab[0] == "version" {
            file.write_all(format!("pub const VERSION: &str = {};\n", ab[1]).as_bytes())
                .ok();
            break;
        }
    }
    // generate build date
    let build_date = format!("{}", chrono::Local::now().format("%Y-%m-%d %H:%M"));
    file.write_all(
        format!("#[allow(dead_code)]\npub const BUILD_DATE: &str = \"{build_date}\";\n").as_bytes(),
    )
    .ok();
    file.sync_all().ok();
}

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

pub fn is_valid_custom_id(id: &str) -> bool {
    regex::Regex::new(r"^[A-Za-z][A-Za-z0-9_-]{5,15}$")
        .unwrap()
        .is_match(id)
}

// Support 1.1.10-1, the number after - is a patch version.
pub fn get_version_number(v: &str) -> i64 {
    let mut versions = v.split('-');

    let mut n = 0;

    // The first part is the version number.
    // 1.1.10 -> 1001100, 1.2.3 -> 1001030, multiple the last number by 10
    // to leave space for patch version.
    if let Some(v) = versions.next() {
        let mut last = 0;
        for x in v.split('.') {
            last = x.parse::<i64>().unwrap_or(0);
            n = n * 1000 + last;
        }
        n -= last;
        n += last * 10;
    }

    if let Some(v) = versions.next() {
        n += v.parse::<i64>().unwrap_or(0);
    }

    // Ignore the rest

    n
}

pub fn get_modified_time(path: &std::path::Path) -> SystemTime {
    std::fs::metadata(path)
        .map(|m| m.modified().unwrap_or(UNIX_EPOCH))
        .unwrap_or(UNIX_EPOCH)
}

pub fn get_created_time(path: &std::path::Path) -> SystemTime {
    std::fs::metadata(path)
        .map(|m| m.created().unwrap_or(UNIX_EPOCH))
        .unwrap_or(UNIX_EPOCH)
}

pub fn get_exe_time() -> SystemTime {
    std::env::current_exe().map_or(UNIX_EPOCH, |path| {
        let m = get_modified_time(&path);
        let c = get_created_time(&path);
        if m > c {
            m
        } else {
            c
        }
    })
}

/// Known cases where machine_uid::get() may fail:
/// - Windows shutdown: "The media is write protected. (os error 19)"
/// - macOS (hard to reproduce, reproduced at login screen): "No matching IOPlatformUUID in `ioreg -rd1 -c IOPlatformExpertDevice` command"
pub fn get_uuid() -> Vec<u8> {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        use std::sync::atomic::{AtomicUsize, Ordering};

        static CACHED_MACHINE_UID: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
        // Throttle only applies to the fallback machine UID lookup log below,
        // not the Once::call_once retry logs.
        static LOG_COUNT: AtomicUsize = AtomicUsize::new(0);

        // Only macOS needs retry logic here because:
        // - macOS: in testing, only one failure occurred when reading at 50ms intervals, so retry helps
        // - Windows: failures during shutdown are persistent, retrying is pointless
        #[cfg(target_os = "macos")]
        {
            static INIT: std::sync::Once = std::sync::Once::new();
            INIT.call_once(|| {
                // Keep in sync with upstream handling:
                // https://github.com/rustdesk/rustdesk/blob/85db6779828349b23ca3eba91cc7cd36c5337797/src/common.rs#L822
                let is_root = match whoami::username() {
                    Ok(username) => username.trim_end_matches('\0') == "root",
                    Err(error) => {
                        log::warn!(
                            "Failed to determine the current macOS user for machine UID retries: \
                             {error}"
                        );
                        false
                    }
                };
                let max_retries = if is_root { 16 } else { 8 };
                for i in 0..max_retries {
                    match machine_uid::get() {
                        Ok(id) => {
                            let _ = CACHED_MACHINE_UID.set(id.into_bytes());
                            return;
                        }
                        Err(e) => {
                            log::error!("Failed to get machine uid in macOS retry #{i}: {e}");
                        }
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
            });
        }

        if let Some(uid) = CACHED_MACHINE_UID.get() {
            return uid.clone();
        }

        match machine_uid::get() {
            Ok(id) => {
                let uid = id.into_bytes();
                let _ = CACHED_MACHINE_UID.set(uid.clone());
                return uid;
            }
            Err(e) => {
                if LOG_COUNT
                    .try_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
                        (count < 30).then_some(count + 1)
                    })
                    .is_ok()
                {
                    log::error!("Failed to get machine uid: {e}");
                }
            }
        }
    }
    Config::get_key_pair().1
}

#[inline]
pub fn get_time() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0) as _
}

#[inline]
pub fn is_ipv4_str(id: &str) -> bool {
    endpoint::is_ipv4_str(id)
}

#[inline]
pub fn is_ipv6_str(id: &str) -> bool {
    endpoint::is_ipv6_str(id)
}

#[inline]
pub fn is_ip_str(id: &str) -> bool {
    endpoint::is_ip_str(id)
}

#[inline]
pub fn is_domain_port_str(id: &str) -> bool {
    endpoint::is_domain_port_str(id)
}

pub fn init_log(_is_async: bool, _name: &str) -> Option<flexi_logger::LoggerHandle> {
    static INIT: std::sync::Once = std::sync::Once::new();
    #[allow(unused_mut)]
    let mut logger_holder: Option<flexi_logger::LoggerHandle> = None;
    INIT.call_once(|| {
        #[cfg(debug_assertions)]
        {
            use env_logger::*;
            init_from_env(Env::default().filter_or(
                DEFAULT_FILTER_ENV,
                "info,reqwest=warn,rustls=warn,webrtc-sctp=warn,webrtc=warn",
            ));
        }
        #[cfg(not(debug_assertions))]
        {
            // https://docs.rs/flexi_logger/latest/flexi_logger/error_info/index.html#write
            // though async logger more efficient, but it also causes more problems, disable it for now
            let mut path = config::Config::log_path();
            #[cfg(target_os = "android")]
            if !config::Config::get_home().exists() {
                return;
            }
            if !_name.is_empty() {
                path.push(_name);
            }
            use flexi_logger::*;
            if let Ok(x) = Logger::try_with_env_or_str(
                "debug,reqwest=warn,rustls=warn,webrtc-sctp=warn,webrtc=warn",
            ) {
                logger_holder = x
                    .log_to_file(FileSpec::default().directory(path))
                    .write_mode(if _is_async {
                        WriteMode::Async
                    } else {
                        WriteMode::Direct
                    })
                    .format(opt_format)
                    .rotate(
                        Criterion::Age(Age::Day),
                        Naming::Timestamps,
                        Cleanup::KeepLogFiles(31),
                    )
                    .start()
                    .ok();
            }
        }
    });
    logger_holder
}

pub fn time_based_rand() -> u32 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let mut x = nanos as u64;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;

    (x % 32768) as u32
}

#[cfg(test)]
mod test {
    use super::*;
    use protobuf::Message as _;

    #[test]
    fn clipboard_file_contents_wire_preserves_native_unsigned_fields() {
        let request = message_proto::CliprdrFileContentsRequest {
            stream_id: u32::MAX,
            list_index: u32::MAX - 1,
            dw_flags: 2,
            n_position_low: u32::MAX,
            n_position_high: u32::MAX,
            cb_requested: u32::MAX,
            have_clip_data_id: true,
            clip_data_id: u32::MAX - 2,
            ..Default::default()
        };
        let encoded = request.write_to_bytes().unwrap();
        let decoded =
            message_proto::CliprdrFileContentsRequest::parse_from_bytes(&encoded).unwrap();
        assert_eq!(decoded.stream_id, u32::MAX);
        assert_eq!(decoded.list_index, u32::MAX - 1);
        assert_eq!(decoded.n_position_low, u32::MAX);
        assert_eq!(decoded.n_position_high, u32::MAX);
        assert_eq!(decoded.cb_requested, u32::MAX);
        assert_eq!(decoded.clip_data_id, u32::MAX - 2);

        let response = message_proto::CliprdrFileContentsResponse {
            msg_flags: u32::MAX,
            stream_id: u32::MAX - 3,
            requested_data: vec![1, 2, 3].into(),
            ..Default::default()
        };
        let encoded = response.write_to_bytes().unwrap();
        let decoded =
            message_proto::CliprdrFileContentsResponse::parse_from_bytes(&encoded).unwrap();
        assert_eq!(decoded.msg_flags, u32::MAX);
        assert_eq!(decoded.stream_id, u32::MAX - 3);
        assert_eq!(decoded.requested_data.as_ref(), &[1, 2, 3]);
    }

    #[test]
    fn test_mangle() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 16, 32), 21116));
        assert_eq!(addr, AddrMangle::decode(&AddrMangle::encode(addr)));

        let addr = "[2001:db8::1]:8080".parse::<SocketAddr>().unwrap();
        assert_eq!(addr, AddrMangle::decode(&AddrMangle::encode(addr)));

        let addr = "[2001:db8:ff::1111]:80".parse::<SocketAddr>().unwrap();
        assert_eq!(addr, AddrMangle::decode(&AddrMangle::encode(addr)));
    }

    #[test]
    fn malformed_mangled_addresses_are_rejected_without_panicking() {
        assert!(AddrMangle::try_decode(&[]).is_none());
        assert!(AddrMangle::try_decode(&[0]).is_none());
        assert!(AddrMangle::try_decode(&[1, 0]).is_none());
        assert!(AddrMangle::try_decode(&[0xff; 17]).is_none());
        assert!(AddrMangle::try_decode(&[0xff; 16]).is_none());
    }

    #[test]
    fn test_allow_err() {
        allow_err!(Err("test err") as Result<(), &str>);
        allow_err!(
            Err("test err with msg") as Result<(), &str>,
            "prompt {}",
            "failed"
        );
    }

    #[test]
    fn test_ipv6() {
        assert!(!is_ipv6_str("1:2:3"));
        assert!(!is_ipv6_str("[ab:2:3]:12"));
        assert!(!is_ipv6_str("[ABEF:2a:3]:12"));
        assert!(!is_ipv6_str("[ABEG:2a:3]:12"));
        assert!(!is_ipv6_str("1[ab:2:3]:12"));
        assert!(!is_ipv6_str("1.1.1.1"));
        assert!(is_ip_str("1.1.1.1"));
        assert!(!is_ipv6_str("1:2:"));
        assert!(is_ipv6_str("1:2::0"));
        assert!(is_ipv6_str("[1:2::0]:1"));
        assert!(!is_ipv6_str("[1:2::0]:"));
        assert!(!is_ipv6_str("1:2::0]:1"));
        assert!(is_ipv6_str("::1"));
        assert!(is_ipv6_str("fe80::1"));
        assert!(is_ipv6_str("[::1]:8080"));
        assert!(is_ipv6_str("[::1]:65535"));
        assert!(!is_ipv6_str("[::1]:0"));
        assert!(!is_ipv6_str("[::1]:65536"));
    }

    #[test]
    fn test_ipv4() {
        assert!(is_ipv4_str("1.2.3.4"));
        assert!(is_ipv4_str("1.2.3.4:90"));
        assert!(is_ipv4_str("192.168.0.1"));
        assert!(is_ipv4_str("0.0.0.0"));
        assert!(is_ipv4_str("255.255.255.255"));
        assert!(!is_ipv4_str("256.0.0.0"));
        assert!(!is_ipv4_str("256.256.256.256"));
        assert!(!is_ipv4_str("1:2:"));
        assert!(!is_ipv4_str("192.168.0.256"));
        assert!(!is_ipv4_str("192.168.0.1/24"));
        assert!(!is_ipv4_str("192.168.0."));
        assert!(!is_ipv4_str("192.168..1"));
        assert!(!is_ipv4_str("1.2.3.4:0"));
        assert!(!is_ipv4_str("1.2.3.4:65536"));
        assert!(is_ipv4_str("1.2.3.4:1"));
        assert!(is_ipv4_str("1.2.3.4:65535"));
    }

    #[test]
    fn test_hostname_port() {
        assert!(!is_domain_port_str("a:12"));
        assert!(!is_domain_port_str("a.b.c:12"));
        assert!(is_domain_port_str("test.com:12"));
        assert!(is_domain_port_str("test-UPPER.com:12"));
        assert!(is_domain_port_str("some-other.domain.com:12"));
        assert!(!is_domain_port_str("under_score:12"));
        assert!(!is_domain_port_str("a@bc:12"));
        assert!(!is_domain_port_str("1.1.1.1:12"));
        assert!(!is_domain_port_str("1.2.3:12"));
        assert!(!is_domain_port_str("1.2.3.45:12"));
        assert!(!is_domain_port_str("a.b.c:123456"));
        assert!(!is_domain_port_str("---:12"));
        assert!(!is_domain_port_str(".:12"));
        // NET-008: Strict port range validation (reject port 0 and >65535)
        assert!(!is_domain_port_str("test.com:0"));
        assert!(!is_domain_port_str("test.com:98989"));
        assert!(!is_domain_port_str("test.com:65536"));
        assert!(is_domain_port_str("test.com:1"));
        assert!(is_domain_port_str("test.com:65535"));
    }

    #[test]
    fn test_mangle2() {
        let addr = "[::ffff:127.0.0.1]:8080".parse().unwrap();
        let addr_v4 = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(AddrMangle::decode(&AddrMangle::encode(addr)), addr_v4);
        assert_eq!(
            AddrMangle::decode(&AddrMangle::encode("[::127.0.0.1]:8080".parse().unwrap())),
            addr_v4
        );
        assert_eq!(AddrMangle::decode(&AddrMangle::encode(addr_v4)), addr_v4);
        let addr_v6 = "[ef::fe]:8080".parse().unwrap();
        assert_eq!(AddrMangle::decode(&AddrMangle::encode(addr_v6)), addr_v6);
        let addr_v6 = "[::1]:8080".parse().unwrap();
        assert_eq!(AddrMangle::decode(&AddrMangle::encode(addr_v6)), addr_v6);
    }

    #[test]
    fn test_get_version_number() {
        assert_eq!(get_version_number("1.1.10"), 1001100);
        assert_eq!(get_version_number("1.1.10-1"), 1001101);
        assert_eq!(get_version_number("1.1.11-1"), 1001111);
        assert_eq!(get_version_number("1.2.3"), 1002030);
    }

    #[test]
    fn custom_id_uses_the_shared_ascii_contract() {
        for id in ["Device01", "device_01", "device-000000001"] {
            assert!(is_valid_custom_id(id), "{}", id);
        }
        for id in [
            "123456",
            "short",
            "abcdefghijklmnopq",
            "device 01",
            "Device设备01",
            "device/01",
        ] {
            assert!(!is_valid_custom_id(id), "{}", id);
        }
    }
}
