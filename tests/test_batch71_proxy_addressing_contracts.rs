//! Contract tests for Batch 71: Protocol Network Addressing, Proxy Authority & DNS Resilience
//! Covers:
//! - NET-002: HTTP/HTTPS proxy IPv6 authority parsing, bracketed host extraction, and zone-id rejection
//! - RES-003: Asynchronous, bounded DNS resolution without blocking executor threads
//! - PROTO-001: Safe, typed address decoding preventing silent `[::]:0` wildcard fallback

#![deny(warnings)]

use camellia_remote_protocol::{
    config::Socks5Server,
    proxy::{parse_host_and_port, IntoProxyScheme, Proxy, ProxyError},
    socket_client::test_if_valid_server,
    tcp::FramedStream,
    AddrMangle, AddressDecodeError,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

#[test]
fn test_net002_ipv6_bracketed_proxy_authority_parsing() {
    // Bracketed IPv6 with explicit port
    let (host, port) = parse_host_and_port("[::1]:8080", 80).expect("failed to parse [::1]:8080");
    assert_eq!(host, "::1");
    assert_eq!(port, 8080);

    // Bracketed IPv6 without port -> uses default port
    let (host, port) = parse_host_and_port("[::1]", 80).expect("failed to parse [::1]");
    assert_eq!(host, "::1");
    assert_eq!(port, 80);

    // Bare IPv6 without brackets -> uses default port
    let (host, port) = parse_host_and_port("::1", 3128).expect("failed to parse bare ::1");
    assert_eq!(host, "::1");
    assert_eq!(port, 3128);

    // Full 128-bit IPv6 address with port
    let (host, port) = parse_host_and_port("[2001:db8:85a3::8a2e:370:7334]:443", 80)
        .expect("failed to parse full IPv6");
    assert_eq!(host, "2001:db8:85a3::8a2e:370:7334");
    assert_eq!(port, 443);

    // IPv4 address with port
    let (host, port) = parse_host_and_port("192.168.1.1:8080", 80).expect("failed to parse IPv4");
    assert_eq!(host, "192.168.1.1");
    assert_eq!(port, 8080);

    // Hostname with port
    let (host, port) =
        parse_host_and_port("proxy.camellia.local:8080", 80).expect("failed to parse host:port");
    assert_eq!(host, "proxy.camellia.local");
    assert_eq!(port, 8080);

    // Hostname without port -> uses default port
    let (host, port) =
        parse_host_and_port("proxy.camellia.local", 443).expect("failed to parse hostname");
    assert_eq!(host, "proxy.camellia.local");
    assert_eq!(port, 443);
}

#[test]
fn test_net002_ipv6_zone_index_rejected_fail_closed() {
    // Zone indices like %eth0 or %1 must be rejected per NET-002 specification
    let res = parse_host_and_port("[fe80::1%eth0]:8080", 80);
    assert!(res.is_err(), "zone index in bracketed IPv6 must fail");
    match res {
        Err(ProxyError::AddressResolutionFailed(msg)) => {
            assert!(msg.contains("zone index is not permitted"), "msg: {msg}");
        }
        other => panic!("unexpected error variant: {:?}", other),
    }

    let res = parse_host_and_port("fe80::1%eth0", 80);
    assert!(res.is_err(), "zone index in bare IPv6 must fail");
    match res {
        Err(ProxyError::AddressResolutionFailed(msg)) => {
            assert!(msg.contains("zone index is not permitted"), "msg: {msg}");
        }
        other => panic!("unexpected error variant: {:?}", other),
    }
}

#[test]
fn test_net002_mismatched_brackets_and_invalid_ips_rejected() {
    // Missing closing bracket
    let res = parse_host_and_port("[::1:8080", 80);
    assert!(res.is_err());

    // Non-IP content inside brackets
    let res = parse_host_and_port("[not-an-ip]:8080", 80);
    assert!(res.is_err());

    // Invalid port number (> 65535)
    let res = parse_host_and_port("[::1]:99999", 80);
    assert!(res.is_err());

    // Invalid trailing characters after bracket
    let res = parse_host_and_port("[::1]invalid:8080", 80);
    assert!(res.is_err());

    // Empty host
    let res = parse_host_and_port("", 80);
    assert!(res.is_err());
}

#[test]
fn test_net002_get_domain_and_append_default_port() {
    // Verify get_domain returns clean hostname/IP without brackets or ports (preventing TLS SNI "[")
    let scheme = "http://[::1]:8080"
        .into_proxy_scheme()
        .expect("parse scheme");
    let domain = scheme.get_domain().expect("get domain");
    assert_eq!(domain, "::1", "domain must not be '[' or contain port");

    let scheme = "https://[2001:db8::1]:8443"
        .into_proxy_scheme()
        .expect("parse scheme");
    let domain = scheme.get_domain().expect("get domain");
    assert_eq!(domain, "2001:db8::1");

    let scheme = "http://proxy.corp.example.com:3128"
        .into_proxy_scheme()
        .expect("parse scheme");
    let domain = scheme.get_domain().expect("get domain");
    assert_eq!(domain, "proxy.corp.example.com");

    // Verify get_host_and_port adds default port only when missing
    let scheme = "http://[::1]".into_proxy_scheme().expect("parse scheme");
    let host_port = scheme.get_host_and_port().expect("get host port");
    assert_eq!(host_port, "[::1]:80");

    let scheme = "https://[::1]".into_proxy_scheme().expect("parse scheme");
    let host_port = scheme.get_host_and_port().expect("get host port");
    assert_eq!(host_port, "[::1]:443");

    let scheme = "http://[::1]:8080"
        .into_proxy_scheme()
        .expect("parse scheme");
    let host_port = scheme.get_host_and_port().expect("get host port");
    assert_eq!(host_port, "[::1]:8080");

    let scheme = "http://proxy.example.com"
        .into_proxy_scheme()
        .expect("parse scheme");
    let host_port = scheme.get_host_and_port().expect("get host port");
    assert_eq!(host_port, "proxy.example.com:80");
}

#[tokio::test]
async fn test_res003_socket_addrs_ip_literal_resolves_without_blocking_executor() {
    // IP literals must resolve immediately without DNS network round-trips
    let scheme = "http://[::1]:9090"
        .into_proxy_scheme()
        .expect("parse scheme");
    let addr = scheme.socket_addrs().await.expect("socket_addrs");
    assert_eq!(
        addr,
        SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9090, 0, 0))
    );

    let scheme = "http://127.0.0.1:9090"
        .into_proxy_scheme()
        .expect("parse scheme");
    let addr = scheme.socket_addrs().await.expect("socket_addrs");
    assert_eq!(
        addr,
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9090))
    );
}

#[test]
fn test_proto001_addr_mangle_try_decode_addr_contracts() {
    // IPv4 roundtrip
    let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 42)), 21116);
    let encoded = AddrMangle::encode(v4);
    let decoded = AddrMangle::try_decode_addr(&encoded).expect("v4 decode must succeed");
    assert_eq!(decoded, v4);

    // IPv6 roundtrip
    let v6 = SocketAddr::new(
        IpAddr::V6("2001:db8:abcd:ef01::1".parse::<Ipv6Addr>().unwrap()),
        21118,
    );
    let encoded = AddrMangle::encode(v6);
    let decoded = AddrMangle::try_decode_addr(&encoded).expect("v6 decode must succeed");
    assert_eq!(decoded, v6);

    // Empty bytes must return AddressDecodeError::Empty, NOT [::]:0
    let empty_res = AddrMangle::try_decode_addr(&[]);
    assert_eq!(empty_res, Err(AddressDecodeError::Empty));
    assert!(AddrMangle::try_decode(&[]).is_none());

    // Corrupted 1-byte input must return AddressDecodeError::Malformed, NOT [::]:0
    let corrupt_1 = [0x42u8];
    assert_eq!(
        AddrMangle::try_decode_addr(&corrupt_1),
        Err(AddressDecodeError::Malformed)
    );
    assert!(AddrMangle::try_decode(&corrupt_1).is_none());

    // Corrupted 17-byte input (between valid 16-byte v4 and 18-byte v6) must fail
    let corrupt_17 = [0x55u8; 17];
    assert_eq!(
        AddrMangle::try_decode_addr(&corrupt_17),
        Err(AddressDecodeError::Malformed)
    );
    assert!(AddrMangle::try_decode(&corrupt_17).is_none());

    // 19-byte input (longer than 18-byte v6) must fail
    let corrupt_19 = [0x55u8; 19];
    assert_eq!(
        AddrMangle::try_decode_addr(&corrupt_19),
        Err(AddressDecodeError::Malformed)
    );
    assert!(AddrMangle::try_decode(&corrupt_19).is_none());
}

#[test]
fn test_proto001_addr_mangle_try_decode_optional_addr_contracts() {
    // Empty bytes must return Ok(None) representing absent optional field
    let empty_res = AddrMangle::try_decode_optional_addr(&[]);
    assert_eq!(empty_res, Ok(None));

    // Valid IPv4 returns Ok(Some(SocketAddr))
    let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 42)), 21116);
    let enc_v4 = AddrMangle::encode(v4);
    assert_eq!(AddrMangle::try_decode_optional_addr(&enc_v4), Ok(Some(v4)));

    // Valid IPv6 returns Ok(Some(SocketAddr))
    let v6 = SocketAddr::new(
        IpAddr::V6("2001:db8:abcd:ef01::1".parse::<Ipv6Addr>().unwrap()),
        21118,
    );
    let enc_v6 = AddrMangle::encode(v6);
    assert_eq!(AddrMangle::try_decode_optional_addr(&enc_v6), Ok(Some(v6)));

    // Corrupted inputs must fail-closed with Err(AddressDecodeError::Malformed)
    let corrupt_1 = [0x42u8];
    assert_eq!(
        AddrMangle::try_decode_optional_addr(&corrupt_1),
        Err(AddressDecodeError::Malformed)
    );

    let corrupt_17 = [0x55u8; 17];
    assert_eq!(
        AddrMangle::try_decode_optional_addr(&corrupt_17),
        Err(AddressDecodeError::Malformed)
    );

    let corrupt_19 = [0x55u8; 19];
    assert_eq!(
        AddrMangle::try_decode_optional_addr(&corrupt_19),
        Err(AddressDecodeError::Malformed)
    );
}

#[test]
fn test_res003_socks5_url_parsing_is_non_blocking_and_deferred() {
    // SOCKS5 URL parsing must succeed instantly without blocking executor threads for DNS resolution
    let scheme = "socks5://unresolvable.invalid:1080"
        .into_proxy_scheme()
        .expect("parsing unresolvable socks5 URL must be non-blocking");
    assert_eq!(
        scheme.get_domain().expect("get domain"),
        "unresolvable.invalid"
    );
    assert_eq!(
        scheme.get_host_and_port().expect("get host port"),
        "unresolvable.invalid:1080"
    );

    // Bracketed IPv6 SOCKS5 URL
    let scheme = "socks5://user:secret@[2001:db8::1]:1080"
        .into_proxy_scheme()
        .expect("parsing bracketed IPv6 socks5 URL must succeed");
    assert_eq!(scheme.get_domain().expect("get domain"), "2001:db8::1");
    assert_eq!(
        scheme.get_host_and_port().expect("get host port"),
        "[2001:db8::1]:1080"
    );

    // IPv4 SOCKS5 URL with credentials
    let scheme = "socks5://user:pass@192.0.2.1:1080"
        .into_proxy_scheme()
        .expect("parsing IPv4 socks5 URL must succeed");
    assert_eq!(scheme.get_domain().expect("get domain"), "192.0.2.1");
    assert_eq!(
        scheme.get_host_and_port().expect("get host port"),
        "192.0.2.1:1080"
    );
}

#[tokio::test]
async fn test_res003_resolve_host_addrs_ip_literal_and_multicandidate() {
    let scheme = "socks5://[::1]:1080"
        .into_proxy_scheme()
        .expect("parse scheme");
    let addrs = scheme
        .resolve_host_addrs("::1", 1080, std::time::Duration::from_millis(500))
        .await
        .expect("resolve ::1 literal");
    assert_eq!(
        addrs,
        vec![SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 1080)]
    );

    let scheme = "http://127.0.0.1:8080"
        .into_proxy_scheme()
        .expect("parse scheme");
    let addrs = scheme
        .resolve_host_addrs("127.0.0.1", 8080, std::time::Duration::from_millis(500))
        .await
        .expect("resolve 127.0.0.1 literal");
    assert_eq!(
        addrs,
        vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080)]
    );
}

#[test]
fn test_res003_test_if_valid_server_ip_fastpath_and_bounded_timeout() {
    // Valid IP literals return empty string immediately without DNS resolution
    assert_eq!(test_if_valid_server("127.0.0.1:21116", false), "");
    assert_eq!(test_if_valid_server("[::1]:21116", false), "");

    // Unspecified IP literals fail closed
    let v4_unspec = test_if_valid_server("0.0.0.0:21116", false);
    assert!(
        v4_unspec.contains("unspecified"),
        "0.0.0.0 must be rejected as unspecified, got: {v4_unspec}"
    );

    let v6_unspec = test_if_valid_server("[::]:21116", false);
    assert!(
        v6_unspec.contains("unspecified"),
        "[::] must be rejected as unspecified, got: {v6_unspec}"
    );

    // Non-existent domain must fail or time out within 3500ms
    let start = std::time::Instant::now();
    let res = test_if_valid_server("nonexistent.unresolvable.invalid:21116", false);
    let elapsed = start.elapsed();
    assert!(
        elapsed < std::time::Duration::from_millis(3500),
        "DNS resolution took too long: {elapsed:?}"
    );
    assert!(!res.is_empty(), "Unresolvable domain must return an error");
}

#[tokio::test]
async fn test_res003_proxy_connect_timeout_enforcement() {
    // Spawn a dummy TCP listener that accepts connection but never replies
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind dummy listener");
    let local_port = listener.local_addr().expect("local addr").port();

    let server_task = tokio::spawn(async move {
        if let Ok((_stream, _)) = listener.accept().await {
            // Keep connection open without responding
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    });

    let proxy_conf = Socks5Server {
        proxy: format!("http://127.0.0.1:{local_port}"),
        username: "".to_string(),
        password: "".to_string(),
    };
    let proxy = Proxy::from_conf(&proxy_conf, Some(150)).expect("proxy from conf");

    let start = std::time::Instant::now();
    let connect_res = proxy.connect("example.com:80", None).await;
    let elapsed = start.elapsed();

    assert!(connect_res.is_err(), "stalling proxy must time out");
    assert!(
        elapsed < std::time::Duration::from_millis(600),
        "connect timeout exceeded 600ms: {elapsed:?}"
    );

    server_task.abort();
}

#[tokio::test]
async fn test_res003_framed_stream_connect_loopback() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let server_task = tokio::spawn(async move {
        if let Ok((_stream, _)) = listener.accept().await {
            // Accepted
        }
    });

    let target = format!("127.0.0.1:{port}");
    let framed = FramedStream::new(&target, None, 1000)
        .await
        .expect("FramedStream::new should connect to local listener");
    assert!(framed.local_addr().port() > 0);

    server_task.abort();
}
