//! Contract tests for Batch 71: Protocol Network Addressing, Proxy Authority & DNS Resilience
//! Covers:
//! - NET-002: HTTP/HTTPS proxy IPv6 authority parsing, bracketed host extraction, and zone-id rejection
//! - RES-003: Asynchronous, bounded DNS resolution without blocking executor threads
//! - PROTO-001: Safe, typed address decoding preventing silent `[::]:0` wildcard fallback

#![deny(warnings)]

use camellia_remote_protocol::{
    proxy::{parse_host_and_port, IntoProxyScheme, ProxyError},
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
