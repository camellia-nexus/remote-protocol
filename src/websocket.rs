use crate::{
    config::{
        keys::OPTION_RELAY_SERVER, use_ws, Config, Socks5Server, RELAY_PORT, RENDEZVOUS_PORT,
    },
    crypto::secretbox::Key,
    protobuf::Message,
    socket_client::split_host_port,
    tcp::{DynTcpStream, Encrypt, FramedStream},
    tls::TlsType,
    ResultType,
};
use anyhow::bail;
use bytes::{Bytes, BytesMut};
use futures::{SinkExt, StreamExt};
use std::{io::Error, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{net::TcpStream, time::timeout};
use tokio_tungstenite::{
    client_async_tls_with_config,
    tungstenite::{
        self,
        client::IntoClientRequest,
        protocol::{Message as WsMessage, Role},
    },
    Connector, MaybeTlsStream, WebSocketStream,
};

pub struct WsFramedStream {
    stream: WebSocketStream<MaybeTlsStream<DynTcpStream>>,
    addr: SocketAddr,
    encrypt: Option<Encrypt>,
    send_timeout: u64,
}

impl WsFramedStream {
    #[inline]
    fn get_connector(tls_type: &TlsType) -> ResultType<Option<Connector>> {
        match tls_type {
            TlsType::Plain => Ok(Some(Connector::Plain)),
            TlsType::Rustls => {
                // Failure to build the selected verifier is not permission to
                // switch trust policy via tungstenite's default connector.
                Ok(Some(Connector::Rustls(Arc::new(
                    crate::verifier::client_config()?,
                ))))
            }
        }
    }

    async fn connect(
        url: &str,
        local_addr: Option<SocketAddr>,
        proxy_conf: Option<&Socks5Server>,
        ms_timeout: u64,
    ) -> ResultType<(WebSocketStream<MaybeTlsStream<DynTcpStream>>, SocketAddr)> {
        let tls_type = TlsType::for_url(url)?;
        timeout(
            Duration::from_millis(ms_timeout),
            Self::try_connect(url, local_addr, proxy_conf, ms_timeout, tls_type),
        )
        .await?
    }

    async fn try_connect(
        url: &str,
        local_addr: Option<SocketAddr>,
        proxy_conf: Option<&Socks5Server>,
        ms_timeout: u64,
        tls_type: TlsType,
    ) -> ResultType<(WebSocketStream<MaybeTlsStream<DynTcpStream>>, SocketAddr)> {
        let ws_config = None;
        let request = url.into_client_request().map_err(Error::other)?;
        if !matches!(request.uri().scheme_str(), Some("ws" | "wss")) {
            bail!("Invalid WebSocket URL scheme");
        }
        let host = request
            .uri()
            .host()
            .ok_or_else(|| Error::other("Missing WebSocket host"))?;
        let port = request
            .uri()
            .port_u16()
            .unwrap_or(if tls_type == TlsType::Rustls { 443 } else { 80 });
        let host = host
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
            .unwrap_or(host);
        let connector = Self::get_connector(&tls_type)?;
        // Pick exactly one route. Retain BufStream/TLS tunnel buffering when
        // removing only the unused protobuf codec, then layer destination TLS
        // and WebSocket on top (including TLS-inside-HTTPS-proxy TLS).
        let transport = match proxy_conf {
            Some(proxy) => {
                FramedStream::connect((host, port), local_addr, proxy, ms_timeout).await?
            }
            None => {
                let target = match host.parse::<std::net::IpAddr>() {
                    Ok(ip) => SocketAddr::new(ip, port).to_string(),
                    Err(_) => format!("{host}:{port}"),
                };
                FramedStream::new(target, local_addr, ms_timeout).await?
            }
        };
        let addr = transport.local_addr();
        let transport = transport.0.into_inner();
        match client_async_tls_with_config(request, transport, ws_config, connector).await {
            Ok((ws_stream, _)) => Ok((ws_stream, addr)),
            Err(e) => {
                log::error!(
                    "WebSocket connection failed with tls_type {:?}: {:?}",
                    tls_type,
                    e
                );
                if let tungstenite::Error::Http(response) = &e {
                    if response.status().is_redirection() {
                        bail!(
                            "WebSocket connection failed ({}). The server may not support WebSocket.",
                            e
                        )
                    }
                }
                bail!("WebSocket error: {}", e)
            }
        }
    }

    pub async fn new<T: AsRef<str>>(
        url: T,
        local_addr: Option<SocketAddr>,
        proxy_conf: Option<&Socks5Server>,
        ms_timeout: u64,
    ) -> ResultType<Self> {
        let (stream, addr) =
            Self::connect(url.as_ref(), local_addr, proxy_conf, ms_timeout).await?;

        let ws = Self {
            stream,
            addr,
            encrypt: None,
            send_timeout: ms_timeout,
        };

        Ok(ws)
    }

    #[inline]
    pub fn set_raw(&mut self) {
        self.encrypt = None;
    }

    #[inline]
    pub async fn from_tcp_stream(stream: TcpStream, addr: SocketAddr) -> ResultType<Self> {
        let ws_stream = WebSocketStream::from_raw_socket(
            MaybeTlsStream::Plain(DynTcpStream(Box::new(stream))),
            Role::Client,
            None,
        )
        .await;

        Ok(Self {
            stream: ws_stream,
            addr,
            encrypt: None,
            send_timeout: 0,
        })
    }

    #[inline]
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    #[inline]
    pub fn set_send_timeout(&mut self, ms: u64) {
        self.send_timeout = ms;
    }

    #[inline]
    pub fn set_key(&mut self, key: Key, role: crate::tcp::CipherRole) {
        self.encrypt = Some(Encrypt::new(key, role));
    }

    #[inline]
    pub fn is_secured(&self) -> bool {
        self.encrypt.is_some()
    }

    #[inline]
    pub fn is_tls(&self) -> bool {
        matches!(self.stream.get_ref(), MaybeTlsStream::Rustls(_))
    }

    #[inline]
    pub async fn send(&mut self, msg: &impl Message) -> ResultType<()> {
        self.send_raw(msg.write_to_bytes()?).await
    }

    #[inline]
    pub async fn send_raw(&mut self, msg: Vec<u8>) -> ResultType<()> {
        let mut msg = msg;
        if let Some(key) = self.encrypt.as_mut() {
            msg = key.enc(&msg)?;
        }
        self.send_bytes(Bytes::from(msg)).await
    }

    pub async fn send_bytes(&mut self, bytes: Bytes) -> ResultType<()> {
        let msg = WsMessage::Binary(bytes);
        if self.send_timeout > 0 {
            timeout(
                Duration::from_millis(self.send_timeout),
                self.stream.send(msg),
            )
            .await??
        } else {
            self.stream.send(msg).await?
        };
        Ok(())
    }

    async fn close_after_protocol_error(&mut self) {
        if let Err(err) = self.stream.close(None).await {
            log::debug!("Failed to close WebSocket after protocol error: {err}");
        }
    }

    #[inline]
    pub async fn next(&mut self) -> Option<Result<BytesMut, Error>> {
        while let Some(msg) = self.stream.next().await {
            let msg = match msg {
                Ok(msg) => msg,
                Err(e) => {
                    log::error!("{}", e);
                    return Some(Err(Error::other(format!(
                        "WebSocket protocol error: {}",
                        e
                    ))));
                }
            };

            match msg {
                WsMessage::Binary(data) => {
                    let mut bytes = BytesMut::from(&data[..]);
                    if let Some(key) = self.encrypt.as_mut() {
                        if let Err(err) = key.dec(&mut bytes) {
                            self.close_after_protocol_error().await;
                            return Some(Err(err));
                        }
                    }
                    return Some(Ok(bytes));
                }
                WsMessage::Text(text) => {
                    if self.encrypt.is_some() {
                        self.close_after_protocol_error().await;
                        return Some(Err(Error::new(
                            std::io::ErrorKind::InvalidData,
                            "encrypted WebSocket received an unauthenticated text frame",
                        )));
                    }
                    let bytes = BytesMut::from(text.as_bytes());
                    return Some(Ok(bytes));
                }
                WsMessage::Close(_) => {
                    return None;
                }
                _ => {
                    continue;
                }
            }
        }

        None
    }

    #[inline]
    pub async fn next_timeout(&mut self, ms: u64) -> Option<Result<BytesMut, Error>> {
        timeout(Duration::from_millis(ms), self.next())
            .await
            .unwrap_or_default()
    }
}

pub fn is_ws_endpoint(endpoint: &str) -> bool {
    endpoint.starts_with("ws://") || endpoint.starts_with("wss://")
}

/**
 * Core function to convert an endpoint to WebSocket format
 *
 * Converts between different address formats:
 * 1. IPv4 address with/without port -> ws://ipv4:port
 * 2. IPv6 address with/without port -> ws://[ipv6]:port
 * 3. Domain with/without port -> ws(s)://domain/ws/path
 *
 * @param endpoint The endpoint to convert
 * @return The converted WebSocket endpoint
 */
pub fn check_ws(endpoint: &str) -> String {
    if !use_ws() {
        return endpoint.to_string();
    }

    if endpoint.is_empty() {
        return endpoint.to_string();
    }

    if is_ws_endpoint(endpoint) {
        return endpoint.to_string();
    }

    let Some((endpoint_host, endpoint_port)) = split_host_port(endpoint) else {
        debug_assert!(false, "endpoint doesn't have port");
        return endpoint.to_string();
    };

    let custom_rendezvous_server = Config::get_rendezvous_server();
    let relay_server = Config::get_option(OPTION_RELAY_SERVER);
    let rendezvous_port = split_host_port(&custom_rendezvous_server)
        .map(|(_, p)| p)
        .unwrap_or(RENDEZVOUS_PORT);
    let relay_port = split_host_port(&relay_server)
        .map(|(_, p)| p)
        .unwrap_or(RELAY_PORT);

    let (relay, dst_port) = if endpoint_port == rendezvous_port {
        // rendezvous
        (false, endpoint_port + 2)
    } else if endpoint_port == rendezvous_port - 1 {
        // online
        (false, endpoint_port + 3)
    } else if endpoint_port == relay_port || endpoint_port == rendezvous_port + 1 {
        // relay
        // https://github.com/rustdesk/rustdesk/blob/6ffbcd1375771f2482ec4810680623a269be70f1/src/rendezvous_mediator.rs#L615
        // https://github.com/rustdesk/rustdesk-server/blob/235a3c326ceb665e941edb50ab79faa1208f7507/src/relay_server.rs#L83, based on relay port.
        (true, endpoint_port + 2)
    } else {
        // fallback relay
        // for controlling side, relay server is passed from the controlled side, not related to local config.
        (true, endpoint_port + 2)
    };

    let (address, is_domain) = if crate::is_ip_str(endpoint) {
        (format!("{}:{}", endpoint_host, dst_port), false)
    } else {
        let domain_path = if relay { "/ws/relay" } else { "/ws/id" };
        (format!("{}{}", endpoint_host, domain_path), true)
    };
    let protocol = if is_domain {
        let api_server = Config::get_option("api-server");
        if api_server.starts_with("https") {
            "wss"
        } else {
            "ws"
        }
    } else {
        "ws"
    };
    format!("{}://{}", protocol, address)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        keys, Config, EXE_RENDEZVOUS_SERVER, PROD_RENDEZVOUS_SERVER, RENDEZVOUS_SERVERS,
    };
    use std::sync::Mutex;
    use tokio::net::TcpListener;

    static WEBSOCKET_CONFIG_TEST_LOCK: Mutex<()> = Mutex::new(());

    struct WebsocketConfigGuard {
        rendezvous_servers: Vec<String>,
        prod_rendezvous_server: String,
        exe_rendezvous_server: String,
    }

    impl WebsocketConfigGuard {
        fn new() -> Self {
            let rendezvous_servers = RENDEZVOUS_SERVERS.read().unwrap().clone();
            let prod_rendezvous_server = PROD_RENDEZVOUS_SERVER.read().unwrap().clone();
            let exe_rendezvous_server = EXE_RENDEZVOUS_SERVER.read().unwrap().clone();

            RENDEZVOUS_SERVERS.write().unwrap().clear();
            PROD_RENDEZVOUS_SERVER.write().unwrap().clear();
            EXE_RENDEZVOUS_SERVER.write().unwrap().clear();

            Self {
                rendezvous_servers,
                prod_rendezvous_server,
                exe_rendezvous_server,
            }
        }
    }

    impl Drop for WebsocketConfigGuard {
        fn drop(&mut self) {
            *RENDEZVOUS_SERVERS.write().unwrap() = self.rendezvous_servers.clone();
            *PROD_RENDEZVOUS_SERVER.write().unwrap() = self.prod_rendezvous_server.clone();
            *EXE_RENDEZVOUS_SERVER.write().unwrap() = self.exe_rendezvous_server.clone();
        }
    }

    #[tokio::test]
    async fn configured_proxy_failure_must_not_open_a_direct_websocket() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let direct = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = direct.local_addr().unwrap();
        // A listening but nonresponsive proxy makes the chosen route fail its
        // deadline. It must never cause a connection to the direct endpoint.
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = Socks5Server {
            proxy: format!("http://{}", proxy_listener.local_addr().unwrap()),
            ..Default::default()
        };
        let direct_connections = Arc::new(AtomicUsize::new(0));
        let observed = direct_connections.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = direct.accept().await.unwrap();
            observed.fetch_add(1, Ordering::SeqCst);
            tokio_tungstenite::accept_async(stream).await.unwrap()
        });
        let result =
            WsFramedStream::new(format!("ws://{destination}/ws/id"), None, Some(&proxy), 250).await;
        server.abort();
        let _ = server.await;
        assert!(
            result.is_err(),
            "configured proxy was bypassed for a direct WebSocket"
        );
        assert_eq!(direct_connections.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn http_proxy_tunnel_preserves_target_path_and_keeps_auth_out_of_websocket() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        struct CheckProxyUpgrade;
        impl tungstenite::handshake::server::Callback for CheckProxyUpgrade {
            fn on_request(
                self,
                request: &tungstenite::handshake::server::Request,
                response: tungstenite::handshake::server::Response,
            ) -> Result<
                tungstenite::handshake::server::Response,
                tungstenite::handshake::server::ErrorResponse,
            > {
                assert_eq!(
                    request.uri().path_and_query().unwrap().as_str(),
                    "/ws/relay?test=1"
                );
                assert_eq!(request.headers()["host"], "unresolved.invalid");
                assert!(!request.headers().contains_key("proxy-authorization"));
                Ok(response)
            }
        }
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = Socks5Server {
            proxy: format!("http://{}", listener.local_addr().unwrap()),
            username: "test-user".to_owned(),
            password: "NET006-test-only".to_owned(),
        };
        let server = tokio::spawn(async move {
            let (mut stream, peer) = listener.accept().await.unwrap();
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                assert!(header.len() < 4096);
                header.push(stream.read_u8().await.unwrap());
            }
            let header = String::from_utf8(header).unwrap();
            assert!(header.starts_with("CONNECT unresolved.invalid:80 HTTP/1.1\r\n"));
            assert!(header.contains("Proxy-Authorization: Basic "));
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
            let mut websocket = tokio_tungstenite::accept_hdr_async(stream, CheckProxyUpgrade)
                .await
                .unwrap();
            websocket
                .send(WsMessage::Binary(b"through-http-proxy".to_vec().into()))
                .await
                .unwrap();
            peer
        });
        let mut stream = WsFramedStream::new(
            "ws://unresolved.invalid/ws/relay?test=1",
            Some("127.0.0.1:0".parse().unwrap()),
            Some(&proxy),
            2000,
        )
        .await
        .unwrap();
        let received = stream.next_timeout(1000).await.unwrap().unwrap();
        assert_eq!(&received[..], b"through-http-proxy");
        assert_eq!(stream.local_addr(), server.await.unwrap());
        assert!(!stream.is_tls());
    }

    #[tokio::test]
    async fn socks_proxy_resolves_destination_remotely_with_and_without_authentication() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for authenticate in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy = Socks5Server {
                proxy: format!("socks5://{}", listener.local_addr().unwrap()),
                username: if authenticate { "test-user" } else { "" }.to_owned(),
                password: if authenticate { "NET006-test-only" } else { "" }.to_owned(),
            };
            let server = tokio::spawn(async move {
                let (mut stream, peer) = listener.accept().await.unwrap();
                assert_eq!(stream.read_u8().await.unwrap(), 5);
                let method_count = stream.read_u8().await.unwrap() as usize;
                let mut methods = vec![0; method_count];
                stream.read_exact(&mut methods).await.unwrap();
                let method = if authenticate { 2 } else { 0 };
                assert!(methods.contains(&method));
                stream.write_all(&[5, method]).await.unwrap();
                if authenticate {
                    assert_eq!(stream.read_u8().await.unwrap(), 1);
                    let length = stream.read_u8().await.unwrap() as usize;
                    let mut username = vec![0; length];
                    stream.read_exact(&mut username).await.unwrap();
                    let length = stream.read_u8().await.unwrap() as usize;
                    let mut password = vec![0; length];
                    stream.read_exact(&mut password).await.unwrap();
                    assert_eq!(username, b"test-user");
                    assert_eq!(password, b"NET006-test-only");
                    stream.write_all(&[1, 0]).await.unwrap();
                }
                let mut head = [0; 4];
                stream.read_exact(&mut head).await.unwrap();
                assert_eq!(head, [5, 1, 0, 3]);
                let length = stream.read_u8().await.unwrap() as usize;
                let mut target = vec![0; length];
                stream.read_exact(&mut target).await.unwrap();
                assert_eq!(target, b"unresolved.invalid");
                assert_eq!(stream.read_u16().await.unwrap(), 80);
                stream
                    .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 80])
                    .await
                    .unwrap();
                let mut websocket = tokio_tungstenite::accept_async(stream).await.unwrap();
                websocket
                    .send(WsMessage::Binary(b"through-socks-proxy".to_vec().into()))
                    .await
                    .unwrap();
                peer
            });
            let mut stream =
                WsFramedStream::new("ws://unresolved.invalid/ws/id", None, Some(&proxy), 2000)
                    .await
                    .unwrap();
            assert_eq!(
                &stream.next_timeout(1000).await.unwrap().unwrap()[..],
                b"through-socks-proxy"
            );
            assert_eq!(stream.local_addr(), server.await.unwrap());
        }
    }

    #[tokio::test]
    async fn websocket_must_honor_incompatible_explicit_local_binding() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        let result = WsFramedStream::new(
            format!("ws://{target}/ws/id"),
            Some("[::1]:0".parse().unwrap()),
            None,
            250,
        )
        .await;
        assert!(
            result.is_err(),
            "explicit IPv6 binding must not silently become an IPv4 route"
        );
        assert!(timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err());
    }

    fn test_key() -> Key {
        Key([0x5a; crate::crypto::secretbox::KEYBYTES])
    }

    async fn websocket_pair() -> (WsFramedStream, WebSocketStream<MaybeTlsStream<TcpStream>>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener must bind");
        let addr = listener.local_addr().expect("listener address must exist");
        let client = TcpStream::connect(addr)
            .await
            .expect("test client must connect");
        let (server, _) = listener.accept().await.expect("test server must accept");
        let client = WsFramedStream::from_tcp_stream(client, addr)
            .await
            .expect("client websocket must initialize");
        let server =
            WebSocketStream::from_raw_socket(MaybeTlsStream::Plain(server), Role::Server, None)
                .await;
        (client, server)
    }

    async fn assert_peer_received_close(peer: &mut WebSocketStream<MaybeTlsStream<TcpStream>>) {
        let message = timeout(Duration::from_secs(1), peer.next())
            .await
            .expect("close frame must arrive before timeout")
            .expect("websocket stream must yield close")
            .expect("close frame must be valid");
        assert!(matches!(message, WsMessage::Close(_)));
    }

    #[tokio::test]
    async fn unencrypted_websocket_accepts_text_during_handshake() {
        let (mut receiver, mut sender) = websocket_pair().await;
        sender
            .send(WsMessage::Text("handshake".into()))
            .await
            .expect("text frame must send");

        let bytes = receiver
            .next()
            .await
            .expect("stream must yield text")
            .expect("unencrypted text must be accepted");
        assert_eq!(&bytes[..], b"handshake");
    }

    #[tokio::test]
    async fn secured_websocket_rejects_text_and_closes() {
        let (mut receiver, mut sender) = websocket_pair().await;
        receiver.set_key(test_key(), crate::tcp::CipherRole::Responder);
        sender
            .send(WsMessage::Text("unauthenticated".into()))
            .await
            .expect("text frame must send");

        let error = receiver
            .next()
            .await
            .expect("stream must yield protocol error")
            .expect_err("secured text must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_peer_received_close(&mut sender).await;
    }

    #[tokio::test]
    async fn secured_websocket_rejects_short_binary_and_closes() {
        let (mut receiver, mut sender) = websocket_pair().await;
        receiver.set_key(test_key(), crate::tcp::CipherRole::Responder);
        sender
            .send(WsMessage::Binary(vec![0x41].into()))
            .await
            .expect("binary frame must send");

        let error = receiver
            .next()
            .await
            .expect("stream must yield authentication error")
            .expect_err("short encrypted frame must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_peer_received_close(&mut sender).await;
    }

    #[tokio::test]
    async fn secured_websocket_accepts_authenticated_binary() {
        let (mut receiver, mut sender) = websocket_pair().await;
        let mut encryptor = Encrypt::new(test_key(), crate::tcp::CipherRole::Initiator);
        let ciphertext = encryptor
            .enc(b"authenticated")
            .expect("payload must encrypt");
        receiver.set_key(test_key(), crate::tcp::CipherRole::Responder);
        sender
            .send(WsMessage::Binary(ciphertext.into()))
            .await
            .expect("binary frame must send");

        let bytes = receiver
            .next()
            .await
            .expect("stream must yield binary")
            .expect("authenticated binary must decrypt");
        assert_eq!(&bytes[..], b"authenticated");
    }

    #[test]
    fn test_check_ws() {
        let _lock = WEBSOCKET_CONFIG_TEST_LOCK.lock().unwrap();
        let _guard = WebsocketConfigGuard::new();

        // enable websocket
        Config::set_option(keys::OPTION_ALLOW_WEBSOCKET.to_string(), "Y".to_string());

        // not set custom-rendezvous-server
        Config::set_option("custom-rendezvous-server".to_string(), "".to_string());
        Config::set_option("relay-server".to_string(), "".to_string());
        Config::set_option("api-server".to_string(), "".to_string());
        assert_eq!(check_ws("127.0.0.1:21115"), "ws://127.0.0.1:21118");
        assert_eq!(check_ws("127.0.0.1:21116"), "ws://127.0.0.1:21118");
        assert_eq!(check_ws("127.0.0.1:21117"), "ws://127.0.0.1:21119");
        assert_eq!(
            check_ws("remote.example.com:21115"),
            "ws://remote.example.com/ws/id"
        );
        assert_eq!(
            check_ws("remote.example.com:21116"),
            "ws://remote.example.com/ws/id"
        );
        assert_eq!(
            check_ws("remote.example.com:21117"),
            "ws://remote.example.com/ws/relay"
        );
        // set relay-server without port
        Config::set_option("relay-server".to_string(), "127.0.0.1".to_string());
        Config::set_option(
            "api-server".to_string(),
            "https://api.example.com".to_string(),
        );
        assert_eq!(
            check_ws("[0:0:0:0:0:0:0:1]:21115"),
            "ws://[0:0:0:0:0:0:0:1]:21118"
        );
        assert_eq!(
            check_ws("[0:0:0:0:0:0:0:1]:21116"),
            "ws://[0:0:0:0:0:0:0:1]:21118"
        );
        assert_eq!(
            check_ws("[0:0:0:0:0:0:0:1]:21117"),
            "ws://[0:0:0:0:0:0:0:1]:21119"
        );
        assert_eq!(
            check_ws("remote.example.com:21115"),
            "wss://remote.example.com/ws/id"
        );
        assert_eq!(
            check_ws("remote.example.com:21116"),
            "wss://remote.example.com/ws/id"
        );
        assert_eq!(
            check_ws("remote.example.com:21117"),
            "wss://remote.example.com/ws/relay"
        );
        // set relay-server with default port
        Config::set_option("relay-server".to_string(), "127.0.0.1:21117".to_string());
        assert_eq!(check_ws("127.0.0.1:21115"), "ws://127.0.0.1:21118");
        assert_eq!(check_ws("127.0.0.1:21116"), "ws://127.0.0.1:21118");
        assert_eq!(check_ws("127.0.0.1:21117"), "ws://127.0.0.1:21119");
        // set relay-server with custom port
        Config::set_option("relay-server".to_string(), "127.0.0.1:34567".to_string());
        assert_eq!(
            check_ws("remote.example.com:21115"),
            "wss://remote.example.com/ws/id"
        );
        assert_eq!(
            check_ws("remote.example.com:21116"),
            "wss://remote.example.com/ws/id"
        );
        assert_eq!(
            check_ws("remote.example.com:34567"),
            "wss://remote.example.com/ws/relay"
        );

        // set custom-rendezvous-server without port
        Config::set_option(
            "custom-rendezvous-server".to_string(),
            "127.0.0.1".to_string(),
        );
        Config::set_option("relay-server".to_string(), "".to_string());
        Config::set_option("api-server".to_string(), "".to_string());
        assert_eq!(check_ws("127.0.0.1:21115"), "ws://127.0.0.1:21118");
        assert_eq!(check_ws("127.0.0.1:21116"), "ws://127.0.0.1:21118");
        assert_eq!(check_ws("127.0.0.1:21117"), "ws://127.0.0.1:21119");
        // set relay-server without port
        Config::set_option("relay-server".to_string(), "127.0.0.1".to_string());
        assert_eq!(check_ws("127.0.0.1:21115"), "ws://127.0.0.1:21118");
        assert_eq!(check_ws("127.0.0.1:21116"), "ws://127.0.0.1:21118");
        assert_eq!(check_ws("127.0.0.1:21117"), "ws://127.0.0.1:21119");
        // set relay-server with default port
        Config::set_option("relay-server".to_string(), "127.0.0.1:21117".to_string());
        assert_eq!(check_ws("127.0.0.1:21115"), "ws://127.0.0.1:21118");
        assert_eq!(check_ws("127.0.0.1:21116"), "ws://127.0.0.1:21118");
        assert_eq!(check_ws("127.0.0.1:21117"), "ws://127.0.0.1:21119");
        // set relay-server with custom port
        Config::set_option("relay-server".to_string(), "127.0.0.1:34567".to_string());
        assert_eq!(check_ws("127.0.0.1:21115"), "ws://127.0.0.1:21118");
        assert_eq!(check_ws("127.0.0.1:21116"), "ws://127.0.0.1:21118");
        assert_eq!(check_ws("127.0.0.1:34567"), "ws://127.0.0.1:34569");

        // set custom-rendezvous-server without default port
        Config::set_option(
            "custom-rendezvous-server".to_string(),
            "127.0.0.1".to_string(),
        );
        Config::set_option("relay-server".to_string(), "".to_string());
        Config::set_option("api-server".to_string(), "".to_string());
        assert_eq!(check_ws("127.0.0.1:21115"), "ws://127.0.0.1:21118");
        assert_eq!(check_ws("127.0.0.1:21116"), "ws://127.0.0.1:21118");
        assert_eq!(check_ws("127.0.0.1:21117"), "ws://127.0.0.1:21119");
        // set relay-server without port
        Config::set_option("relay-server".to_string(), "127.0.0.1".to_string());
        assert_eq!(check_ws("127.0.0.1:21115"), "ws://127.0.0.1:21118");
        assert_eq!(check_ws("127.0.0.1:21116"), "ws://127.0.0.1:21118");
        assert_eq!(check_ws("127.0.0.1:21117"), "ws://127.0.0.1:21119");
        // set relay-server with default port
        Config::set_option("relay-server".to_string(), "127.0.0.1:21117".to_string());
        assert_eq!(check_ws("127.0.0.1:21115"), "ws://127.0.0.1:21118");
        assert_eq!(check_ws("127.0.0.1:21116"), "ws://127.0.0.1:21118");
        assert_eq!(check_ws("127.0.0.1:21117"), "ws://127.0.0.1:21119");
        // set relay-server with custom port
        Config::set_option("relay-server".to_string(), "127.0.0.1:34567".to_string());
        assert_eq!(check_ws("127.0.0.1:21115"), "ws://127.0.0.1:21118");
        assert_eq!(check_ws("127.0.0.1:21116"), "ws://127.0.0.1:21118");
        assert_eq!(check_ws("127.0.0.1:34567"), "ws://127.0.0.1:34569");

        // set custom-rendezvous-server with custom port
        Config::set_option(
            "custom-rendezvous-server".to_string(),
            "127.0.0.1:23456".to_string(),
        );
        Config::set_option("relay-server".to_string(), "".to_string());
        Config::set_option("api-server".to_string(), "".to_string());
        assert_eq!(check_ws("127.0.0.1:23455"), "ws://127.0.0.1:23458");
        assert_eq!(check_ws("127.0.0.1:23456"), "ws://127.0.0.1:23458");
        assert_eq!(check_ws("127.0.0.1:23457"), "ws://127.0.0.1:23459");
        // set relay-server without port
        Config::set_option("relay-server".to_string(), "127.0.0.1".to_string());
        assert_eq!(check_ws("127.0.0.1:23455"), "ws://127.0.0.1:23458");
        assert_eq!(check_ws("127.0.0.1:23456"), "ws://127.0.0.1:23458");
        assert_eq!(check_ws("127.0.0.1:21117"), "ws://127.0.0.1:21119");
        // set relay-server with default port
        Config::set_option("relay-server".to_string(), "127.0.0.1:21117".to_string());
        assert_eq!(check_ws("127.0.0.1:23455"), "ws://127.0.0.1:23458");
        assert_eq!(check_ws("127.0.0.1:23456"), "ws://127.0.0.1:23458");
        assert_eq!(check_ws("127.0.0.1:21117"), "ws://127.0.0.1:21119");
        // set relay-server with custom port
        Config::set_option("relay-server".to_string(), "127.0.0.1:34567".to_string());
        assert_eq!(check_ws("127.0.0.1:23455"), "ws://127.0.0.1:23458");
        assert_eq!(check_ws("127.0.0.1:23456"), "ws://127.0.0.1:23458");
        assert_eq!(check_ws("127.0.0.1:34567"), "ws://127.0.0.1:34569");
    }
}
