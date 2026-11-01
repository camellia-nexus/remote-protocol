use crate::{
    config::{Config, NetworkType},
    tcp::FramedStream,
    udp::FramedSocket,
    websocket::{self, check_ws, is_ws_endpoint},
    ResultType, Stream,
};
use anyhow::Context;
use std::{net::SocketAddr, sync::Arc};
use tokio::net::{ToSocketAddrs, UdpSocket};
use tokio_socks::{IntoTargetAddr, TargetAddr};

use crate::endpoint::ParsedEndpoint;

#[inline]
pub fn check_port<T: std::string::ToString>(host: T, port: i32) -> String {
    let host_str = host.to_string();
    let Ok(ep) = ParsedEndpoint::parse(&host_str) else {
        return host_str;
    };
    if let Some(existing_port) = ep.port {
        return format!("{}:{}", ep.raw_host, existing_port);
    }
    if (1..=65535).contains(&port) {
        format!("{}:{}", ep.raw_host, port)
    } else {
        host_str
    }
}

#[inline]
pub fn increase_port<T: std::string::ToString>(host: T, offset: i32) -> String {
    let host_str = host.to_string();
    let Ok(ep) = ParsedEndpoint::parse(&host_str) else {
        return host_str;
    };
    let Some(current_port) = ep.port else {
        return host_str;
    };
    let new_port = match (current_port as u32).checked_add_signed(offset) {
        Some(p) if (1..=65535).contains(&p) => p as u16,
        _ => return host_str,
    };
    format!("{}:{}", ep.raw_host, new_port)
}

#[inline]
pub fn split_host_port<T: std::string::ToString>(host: T) -> Option<(String, i32)> {
    let host_str = host.to_string();
    let ep = ParsedEndpoint::parse(&host_str).ok()?;
    let port = ep.port?;
    Some((ep.raw_host, port as i32))
}

pub fn test_if_valid_server(host: &str, test_with_proxy: bool) -> String {
    let ep = match ParsedEndpoint::parse(host) {
        Ok(ep) => ep,
        Err(err) => return err.to_string(),
    };
    let port = ep.port.unwrap_or(crate::config::RENDEZVOUS_PORT as u16);
    let target = format!("{}:{}", ep.raw_host, port);

    use std::net::ToSocketAddrs;
    if test_with_proxy && NetworkType::ProxySocks == Config::get_network_type() {
        test_if_valid_server_for_proxy_(&target)
    } else {
        match target.to_socket_addrs() {
            Err(err) => err.to_string(),
            Ok(_) => "".to_owned(),
        }
    }
}

#[inline]
pub fn test_if_valid_server_for_proxy_(host: &str) -> String {
    // `&host.into_target_addr()` is defined in `tokio-socs`, but is a common pattern for testing,
    // it can be used for both `socks` and `http` proxy.
    match &host.into_target_addr() {
        Err(err) => err.to_string(),
        Ok(_) => "".to_owned(),
    }
}

pub trait IsResolvedSocketAddr {
    fn resolve(&self) -> Option<&SocketAddr>;
}

impl IsResolvedSocketAddr for SocketAddr {
    fn resolve(&self) -> Option<&SocketAddr> {
        Some(self)
    }
}

impl IsResolvedSocketAddr for String {
    fn resolve(&self) -> Option<&SocketAddr> {
        None
    }
}

impl IsResolvedSocketAddr for &str {
    fn resolve(&self) -> Option<&SocketAddr> {
        None
    }
}

// This function checks if the target is a websocket endpoint and connects accordingly.
#[inline]
pub async fn connect_tcp<
    't,
    T: IntoTargetAddr<'t> + ToSocketAddrs + IsResolvedSocketAddr + std::fmt::Display,
>(
    target: T,
    ms_timeout: u64,
) -> ResultType<crate::Stream> {
    let target_str = check_ws(&target.to_string());
    if is_ws_endpoint(&target_str) {
        let proxy = Config::get_socks();
        return Ok(Stream::WebSocket(
            websocket::WsFramedStream::new(target_str, None, proxy.as_ref(), ms_timeout).await?,
        ));
    }
    connect_tcp_local(target, None, ms_timeout).await
}

// This function connects directly to the target without checking for websocket endpoints.
pub async fn connect_tcp_local<
    't,
    T: IntoTargetAddr<'t> + ToSocketAddrs + IsResolvedSocketAddr + std::fmt::Display,
>(
    target: T,
    local: Option<SocketAddr>,
    ms_timeout: u64,
) -> ResultType<Stream> {
    if let Some(conf) = Config::get_socks() {
        return Ok(Stream::Tcp(
            FramedStream::connect(target, local, &conf, ms_timeout).await?,
        ));
    }

    if let Some(target_addr) = target.resolve() {
        if let Some(local_addr) = local {
            if local_addr.is_ipv6() && target_addr.is_ipv4() {
                let resolved_target = query_nip_io(target_addr).await?;
                return Ok(Stream::Tcp(
                    FramedStream::new(resolved_target, Some(local_addr), ms_timeout).await?,
                ));
            }
        }
    }

    Ok(Stream::Tcp(
        FramedStream::new(target, local, ms_timeout).await?,
    ))
}

#[inline]
pub fn is_ipv4(target: &TargetAddr<'_>) -> bool {
    match target {
        TargetAddr::Ip(addr) => addr.is_ipv4(),
        _ => true,
    }
}

#[inline]
pub async fn query_nip_io(addr: &SocketAddr) -> ResultType<SocketAddr> {
    tokio::net::lookup_host(format!("{}.nip.io:{}", addr.ip(), addr.port()))
        .await?
        .find(|x| x.is_ipv6())
        .context("Failed to get ipv6 from nip.io")
}

#[inline]
pub fn ipv4_to_ipv6(addr: String, ipv4: bool) -> String {
    if !ipv4 && crate::is_ipv4_str(&addr) {
        if let Some(ip) = addr.split(':').next() {
            return addr.replace(ip, &format!("{ip}.nip.io"));
        }
    }
    addr
}

async fn test_target(target: &str) -> ResultType<SocketAddr> {
    if let Ok(Ok(s)) = super::timeout(1000, tokio::net::TcpStream::connect(target)).await {
        if let Ok(addr) = s.peer_addr() {
            return Ok(addr);
        }
    }
    tokio::net::lookup_host(target)
        .await?
        .next()
        .context(format!("Failed to look up host for {target}"))
}

#[inline]
pub async fn new_direct_udp_for(target: &str) -> ResultType<(Arc<UdpSocket>, SocketAddr)> {
    let peer_addr = test_target(target).await?;
    let local_addr = Config::get_any_listen_addr(peer_addr.is_ipv4());
    let socket = UdpSocket::bind(local_addr).await?;
    Ok((Arc::new(socket), peer_addr))
}

#[inline]
pub async fn new_udp_for(
    target: &str,
    ms_timeout: u64,
) -> ResultType<(FramedSocket, TargetAddr<'static>)> {
    let (ipv4, target) = if NetworkType::Direct == Config::get_network_type() {
        let addr = test_target(target).await?;
        (addr.is_ipv4(), addr.into_target_addr()?)
    } else {
        (true, target.into_target_addr()?)
    };
    Ok((
        new_udp(Config::get_any_listen_addr(ipv4), ms_timeout).await?,
        target.to_owned(),
    ))
}

async fn new_udp<T: ToSocketAddrs>(local: T, ms_timeout: u64) -> ResultType<FramedSocket> {
    match Config::get_socks() {
        None => Ok(FramedSocket::new(local).await?),
        Some(conf) => {
            let socket = FramedSocket::new_proxy(
                conf.proxy.as_str(),
                local,
                conf.username.as_str(),
                conf.password.as_str(),
                ms_timeout,
            )
            .await?;
            Ok(socket)
        }
    }
}

pub async fn rebind_udp_for(
    target: &str,
) -> ResultType<Option<(FramedSocket, TargetAddr<'static>)>> {
    if Config::get_network_type() != NetworkType::Direct {
        return Ok(None);
    }
    let addr = test_target(target).await?;
    let v4 = addr.is_ipv4();
    Ok(Some((
        FramedSocket::new(Config::get_any_listen_addr(v4)).await?,
        addr.into_target_addr()?.to_owned(),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_to_ipv6_mapping() {
        assert_eq!(ipv4_to_ipv6("1.1.1.1".to_owned(), true), "1.1.1.1");
        assert_eq!(ipv4_to_ipv6("1.1.1.1".to_owned(), false), "1.1.1.1.nip.io");
        assert_eq!(
            ipv4_to_ipv6("1.1.1.1:8080".to_owned(), false),
            "1.1.1.1.nip.io:8080"
        );
        assert_eq!(
            ipv4_to_ipv6("remote.example.com".to_owned(), false),
            "remote.example.com"
        );
    }

    #[test]
    fn test_nat64() {
        test_nat64_async();
    }

    // Whether nip.io yields an AAAA record depends on the resolver and on
    // whether the network runs DNS64, so only the invariant is asserted here:
    // a successful lookup must return an IPv6 address.
    #[tokio::main(flavor = "current_thread")]
    async fn test_nat64_async() {
        if let Ok(addr) = query_nip_io(&"1.1.1.1:80".parse().unwrap()).await {
            assert!(addr.is_ipv6());
            assert_eq!(addr.port(), 80);
        }
    }

    #[test]
    fn test_test_if_valid_server() {
        assert!(!test_if_valid_server("a", false).is_empty());
        // on Linux, "1" is resolved to "0.0.0.1"
        assert!(test_if_valid_server("1.1.1.1", false).is_empty());
        assert!(test_if_valid_server("1.1.1.1:1", false).is_empty());
        assert!(test_if_valid_server("127.0.0.1", false).is_empty());
        assert!(test_if_valid_server("127.0.0.1:1", false).is_empty());

        // with proxy
        // `:0` indicates `let host = check_port(host, 0);` is called.
        assert!(test_if_valid_server_for_proxy_("a:0").is_empty());
        assert!(test_if_valid_server_for_proxy_("1.1.1.1:0").is_empty());
        assert!(test_if_valid_server_for_proxy_("1.1.1.1:1").is_empty());
        assert!(test_if_valid_server_for_proxy_("abc.com:0").is_empty());
        assert!(test_if_valid_server_for_proxy_("abcd.com:1").is_empty());

        // NET-008: Strict validation rejects invalid endpoints and out-of-range ports
        assert!(!test_if_valid_server("1:2:3", false).is_empty());
        assert!(!test_if_valid_server("test.com:0", false).is_empty());
        assert!(!test_if_valid_server("test.com:98989", false).is_empty());
        assert!(!test_if_valid_server("1.1.1.1:0", false).is_empty());
        assert!(!test_if_valid_server("1.1.1.1:65536", false).is_empty());
    }

    #[test]
    fn test_check_port() {
        assert_eq!(check_port("[1::2]:12", 32), "[1::2]:12");
        assert_eq!(check_port("1::2", 32), "[1::2]:32");
        assert_eq!(check_port("z1:2", 32), "z1:2");
        assert_eq!(check_port("1.1.1.1", 32), "1.1.1.1:32");
        assert_eq!(check_port("1.1.1.1:32", 32), "1.1.1.1:32");
        assert_eq!(check_port("test.com:32", 0), "test.com:32");
        assert_eq!(increase_port("[1::2]:12", 1), "[1::2]:13");
        assert_eq!(increase_port("1.2.2.4:12", 1), "1.2.2.4:13");
        assert_eq!(increase_port("1.2.2.4", 1), "1.2.2.4");
        assert_eq!(increase_port("test.com", 1), "test.com");
        assert_eq!(increase_port("test.com:13", 4), "test.com:17");
        assert_eq!(increase_port("1:13", 4), "1:13");
        assert_eq!(increase_port("22:1:13", 4), "22:1:13");
        assert_eq!(increase_port("z1:2", 1), "z1:3");
        // NET-008: Checked port arithmetic boundary validation (1..=65535)
        assert_eq!(increase_port("[::1]:65535", 1), "[::1]:65535");
        assert_eq!(increase_port("test.com:1", -1), "test.com:1");
        assert_eq!(increase_port("test.com:1", -2), "test.com:1");
        assert_eq!(increase_port("1.2.3.4:21116", 1), "1.2.3.4:21117");
        assert_eq!(increase_port("[::1]:21116", -1), "[::1]:21115");
    }
}
