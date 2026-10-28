use std::{
    io::Error as IoError,
    net::{SocketAddr, ToSocketAddrs},
};

use base64::{engine::general_purpose, Engine};
use http::uri::Authority;
use httparse::{Error as HttpParseError, Response, EMPTY_HEADER};
use thiserror::Error as ThisError;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufStream};
use tokio_rustls::{client::TlsStream as RustlsTlsStream, TlsConnector as RustlsTlsConnector};
use tokio_socks::{tcp::Socks5Stream, IntoTargetAddr, TargetAddr};
use tokio_util::codec::Framed;
use url::Url;

use crate::{
    bytes_codec::BytesCodec,
    config::Socks5Server,
    tcp::{DynTcpStream, FramedStream},
    ResultType,
};

#[derive(Debug, ThisError)]
pub enum ProxyError {
    #[error("IO Error: {0}")]
    IoError(#[from] IoError),
    #[error("Target parse error: {0}")]
    TargetParseError(String),
    #[error("HTTP parse error: {0}")]
    HttpParseError(#[from] HttpParseError),
    #[error("The maximum response header length is exceeded: {0}")]
    MaximumResponseHeaderLengthExceeded(usize),
    #[error("The end of file is reached")]
    EndOfFile,
    #[error("The url is error: {0}")]
    UrlBadScheme(String),
    #[error("The url parse error: {0}")]
    UrlParseScheme(#[from] url::ParseError),
    #[error("No HTTP code was found in the response")]
    NoHttpCode,
    #[error("The HTTP code is not equal 200: {0}")]
    HttpCode200(u16),
    #[error("The proxy address resolution failed: {0}")]
    AddressResolutionFailed(String),
    #[error("Invalid HTTP CONNECT target authority")]
    InvalidTargetAuthority,
}

const MAXIMUM_RESPONSE_HEADER_LENGTH: usize = 4096;
/// The maximum HTTP Headers, which can be parsed.
const MAXIMUM_RESPONSE_HEADERS: usize = 16;
const DEFINE_TIME_OUT: u64 = 600;
const MAX_CONNECT_HOST_INPUT_LENGTH: usize = 1024;

#[derive(Debug, Clone)]
struct ConnectAuthority(Authority);

impl ConnectAuthority {
    fn from_target(target_addr: &TargetAddr<'_>) -> Result<Self, ProxyError> {
        let authority = match target_addr {
            TargetAddr::Ip(addr) => addr.to_string(),
            TargetAddr::Domain(name, port) => {
                let host = normalize_connect_host(name)?;
                format!("{host}:{port}")
            }
        };
        authority
            .parse::<Authority>()
            .map(Self)
            .map_err(|_| ProxyError::InvalidTargetAuthority)
    }

    fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

fn normalize_connect_host(host: &str) -> Result<String, ProxyError> {
    if host.is_empty()
        || host.len() > MAX_CONNECT_HOST_INPUT_LENGTH
        || host.chars().any(|c| c.is_control() || c.is_whitespace())
        || host
            .chars()
            .any(|c| matches!(c, '@' | '/' | '\\' | '?' | '#' | '%'))
    {
        return Err(ProxyError::InvalidTargetAuthority);
    }

    match url::Host::parse(host).map_err(|_| ProxyError::InvalidTargetAuthority)? {
        url::Host::Domain(domain) => {
            validate_ascii_domain(&domain)?;
            Ok(domain.to_ascii_lowercase())
        }
        url::Host::Ipv4(addr) => Ok(addr.to_string()),
        url::Host::Ipv6(addr) => Ok(format!("[{addr}]")),
    }
}

fn validate_ascii_domain(domain: &str) -> Result<(), ProxyError> {
    if !domain.is_ascii() {
        return Err(ProxyError::InvalidTargetAuthority);
    }
    let domain = domain.strip_suffix('.').unwrap_or(domain);
    if domain.is_empty() || domain.len() > 253 {
        return Err(ProxyError::InvalidTargetAuthority);
    }

    for label in domain.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(ProxyError::InvalidTargetAuthority);
        }
    }
    Ok(())
}

pub trait IntoUrl {
    // Besides parsing as a valid `Url`, the `Url` must be a valid
    // `http::Uri`, in that it makes sense to use in a network request.
    fn into_url(self) -> Result<Url, ProxyError>;

    fn as_str(&self) -> &str;
}

impl IntoUrl for Url {
    fn into_url(self) -> Result<Url, ProxyError> {
        if self.has_host() {
            Ok(self)
        } else {
            Err(ProxyError::UrlBadScheme(self.to_string()))
        }
    }

    fn as_str(&self) -> &str {
        self.as_ref()
    }
}

impl IntoUrl for &str {
    fn into_url(self) -> Result<Url, ProxyError> {
        Url::parse(self)
            .map_err(ProxyError::UrlParseScheme)?
            .into_url()
    }

    fn as_str(&self) -> &str {
        self
    }
}

impl IntoUrl for &String {
    fn into_url(self) -> Result<Url, ProxyError> {
        (&**self).into_url()
    }

    fn as_str(&self) -> &str {
        self.as_ref()
    }
}

impl IntoUrl for String {
    fn into_url(self) -> Result<Url, ProxyError> {
        (&*self).into_url()
    }

    fn as_str(&self) -> &str {
        self.as_ref()
    }
}

#[derive(Clone)]
pub struct Auth {
    user_name: String,
    password: String,
}

impl Auth {
    fn get_proxy_authorization(&self) -> String {
        format!(
            "Proxy-Authorization: Basic {}\r\n",
            self.get_basic_authorization()
        )
    }

    pub fn get_basic_authorization(&self) -> String {
        let authorization = format!("{}:{}", self.user_name, self.password);
        general_purpose::STANDARD.encode(authorization.as_bytes())
    }

    pub fn username(&self) -> &str {
        &self.user_name
    }

    pub fn password(&self) -> &str {
        &self.password
    }
}

#[derive(Clone)]
pub enum ProxyScheme {
    Http {
        auth: Option<Auth>,
        host: String,
    },
    Https {
        auth: Option<Auth>,
        host: String,
    },
    Socks5 {
        addr: SocketAddr,
        auth: Option<Auth>,
        remote_dns: bool,
    },
}

impl ProxyScheme {
    pub fn maybe_auth(&self) -> Option<&Auth> {
        match self {
            ProxyScheme::Http { auth, .. }
            | ProxyScheme::Https { auth, .. }
            | ProxyScheme::Socks5 { auth, .. } => auth.as_ref(),
        }
    }

    fn socks5(addr: SocketAddr) -> Result<Self, ProxyError> {
        Ok(ProxyScheme::Socks5 {
            addr,
            auth: None,
            remote_dns: false,
        })
    }

    fn http(host: &str) -> Result<Self, ProxyError> {
        Ok(ProxyScheme::Http {
            auth: None,
            host: host.to_string(),
        })
    }
    fn https(host: &str) -> Result<Self, ProxyError> {
        Ok(ProxyScheme::Https {
            auth: None,
            host: host.to_string(),
        })
    }

    fn set_basic_auth<T: Into<String>, U: Into<String>>(&mut self, username: T, password: U) {
        let auth = Auth {
            user_name: username.into(),
            password: password.into(),
        };
        match self {
            ProxyScheme::Http { auth: a, .. } => *a = Some(auth),
            ProxyScheme::Https { auth: a, .. } => *a = Some(auth),
            ProxyScheme::Socks5 { auth: a, .. } => *a = Some(auth),
        }
    }

    fn parse(url: Url) -> Result<Self, ProxyError> {
        use url::Position;

        // Resolve URL to a host and port
        let to_addr = || {
            let addrs = url.socket_addrs(|| match url.scheme() {
                "socks5" => Some(1080),
                _ => None,
            })?;
            addrs
                .into_iter()
                .next()
                .ok_or(ProxyError::UrlParseScheme(url::ParseError::EmptyHost))
        };

        let mut scheme: Self = match url.scheme() {
            "http" => Self::http(&url[Position::BeforeHost..Position::AfterPort])?,
            "https" => Self::https(&url[Position::BeforeHost..Position::AfterPort])?,
            "socks5" => Self::socks5(to_addr()?)?,
            e => return Err(ProxyError::UrlBadScheme(e.to_string())),
        };

        if let Some(pwd) = url.password() {
            let username = url.username();
            scheme.set_basic_auth(username, pwd);
        }

        Ok(scheme)
    }
    pub async fn socket_addrs(&self) -> Result<SocketAddr, ProxyError> {
        log::trace!("Resolving socket address");
        match self {
            ProxyScheme::Http { host, .. } => self.resolve_host(host, 80).await,
            ProxyScheme::Https { host, .. } => self.resolve_host(host, 443).await,
            ProxyScheme::Socks5 { addr, .. } => Ok(*addr),
        }
    }

    async fn resolve_host(&self, host: &str, default_port: u16) -> Result<SocketAddr, ProxyError> {
        let (host_str, port) = match host.split_once(':') {
            Some((h, p)) => (h, p.parse::<u16>().ok()),
            None => (host, None),
        };
        let addr = (host_str, port.unwrap_or(default_port))
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| ProxyError::AddressResolutionFailed(host.to_string()))?;
        Ok(addr)
    }

    pub fn get_domain(&self) -> Result<String, ProxyError> {
        match self {
            ProxyScheme::Http { host, .. } | ProxyScheme::Https { host, .. } => {
                let domain = host
                    .split(':')
                    .next()
                    .ok_or_else(|| ProxyError::AddressResolutionFailed(host.clone()))?;
                Ok(domain.to_string())
            }
            ProxyScheme::Socks5 { addr, .. } => match addr {
                SocketAddr::V4(addr_v4) => Ok(addr_v4.ip().to_string()),
                SocketAddr::V6(addr_v6) => Ok(addr_v6.ip().to_string()),
            },
        }
    }
    pub fn get_host_and_port(&self) -> Result<String, ProxyError> {
        match self {
            ProxyScheme::Http { host, .. } => Ok(self.append_default_port(host, 80)),
            ProxyScheme::Https { host, .. } => Ok(self.append_default_port(host, 443)),
            ProxyScheme::Socks5 { addr, .. } => Ok(format!("{}", addr)),
        }
    }
    fn append_default_port(&self, host: &str, default_port: u16) -> String {
        if host.contains(':') {
            host.to_string()
        } else {
            format!("{}:{}", host, default_port)
        }
    }
}

pub trait IntoProxyScheme {
    fn into_proxy_scheme(self) -> Result<ProxyScheme, ProxyError>;
}

impl<S: IntoUrl> IntoProxyScheme for S {
    fn into_proxy_scheme(self) -> Result<ProxyScheme, ProxyError> {
        // validate the URL
        let url = match self.as_str().into_url() {
            Ok(ok) => ok,
            Err(e) => {
                match e {
                    // If the string does not contain protocol headers, try to parse it using the socks5 protocol
                    ProxyError::UrlParseScheme(_source) => {
                        let try_this = format!("socks5://{}", self.as_str());
                        try_this.into_url()?
                    }
                    _ => {
                        return Err(e);
                    }
                }
            }
        };
        ProxyScheme::parse(url)
    }
}

impl IntoProxyScheme for ProxyScheme {
    fn into_proxy_scheme(self) -> Result<ProxyScheme, ProxyError> {
        Ok(self)
    }
}

#[derive(Clone)]
pub struct Proxy {
    pub intercept: ProxyScheme,
    ms_timeout: u64,
}

impl Proxy {
    pub fn new<U: IntoProxyScheme>(proxy_scheme: U, ms_timeout: u64) -> Result<Self, ProxyError> {
        Ok(Self {
            intercept: proxy_scheme.into_proxy_scheme()?,
            ms_timeout,
        })
    }

    pub fn is_http_or_https(&self) -> bool {
        !matches!(self.intercept, ProxyScheme::Socks5 { .. })
    }

    pub fn from_conf(conf: &Socks5Server, ms_timeout: Option<u64>) -> Result<Self, ProxyError> {
        let mut proxy;
        match ms_timeout {
            None => {
                proxy = Self::new(&conf.proxy, DEFINE_TIME_OUT)?;
            }
            Some(time_out) => {
                proxy = Self::new(&conf.proxy, time_out)?;
            }
        }

        if !conf.password.is_empty() && !conf.username.is_empty() {
            proxy = proxy.basic_auth(&conf.username, &conf.password);
        }
        Ok(proxy)
    }

    pub async fn proxy_addrs(&self) -> Result<SocketAddr, ProxyError> {
        self.intercept.socket_addrs().await
    }

    fn basic_auth(mut self, username: &str, password: &str) -> Proxy {
        self.intercept.set_basic_auth(username, password);
        self
    }

    async fn new_stream(
        &self,
        local: SocketAddr,
        proxy: SocketAddr,
    ) -> ResultType<tokio::net::TcpStream> {
        let stream = super::timeout(
            self.ms_timeout,
            crate::tcp::new_socket(local, true)?.connect(proxy),
        )
        .await??;
        stream.set_nodelay(true).ok();
        Ok(stream)
    }

    pub async fn connect<'t, T>(
        &self,
        target: T,
        local_addr: Option<SocketAddr>,
    ) -> ResultType<FramedStream>
    where
        T: IntoTargetAddr<'t>,
    {
        let target_addr = target
            .into_target_addr()
            .map_err(|e| ProxyError::TargetParseError(e.to_string()))?;
        let connect_authority = match &self.intercept {
            ProxyScheme::Http { .. } | ProxyScheme::Https { .. } => {
                Some(ConnectAuthority::from_target(&target_addr)?)
            }
            ProxyScheme::Socks5 { .. } => None,
        };

        log::trace!("Connect to proxy server");
        let proxy = self.proxy_addrs().await?;

        let local = if let Some(addr) = local_addr {
            addr
        } else {
            crate::config::Config::get_any_listen_addr(proxy.is_ipv4())
        };

        let stream = self.new_stream(local, proxy).await?;
        let addr = stream.local_addr()?;

        match self.intercept {
            ProxyScheme::Http { .. } => {
                log::trace!("Connect to remote http proxy server: {}", proxy);
                let authority = connect_authority
                    .as_ref()
                    .ok_or(ProxyError::InvalidTargetAuthority)?;
                let stream = super::timeout(
                    self.ms_timeout,
                    self.http_connect_authority(stream, authority),
                )
                .await??;
                Ok(FramedStream(
                    Framed::new(DynTcpStream(Box::new(stream)), BytesCodec::for_session()),
                    addr,
                    None,
                    0,
                ))
            }
            ProxyScheme::Https { .. } => {
                log::trace!("Connect to remote https proxy server: {}", proxy);
                let authority = connect_authority
                    .as_ref()
                    .ok_or(ProxyError::InvalidTargetAuthority)?;
                // There is already exactly one connected socket. A lazy or
                // eager "fallback" here is unnecessary and would consume a
                // second proxy connection before TLS/CONNECT can proceed.
                let stream = super::timeout(
                    self.ms_timeout,
                    self.https_connect_rustls_authority(stream, authority),
                )
                .await??;
                Ok(FramedStream(
                    Framed::new(DynTcpStream(Box::new(stream)), BytesCodec::for_session()),
                    addr,
                    None,
                    0,
                ))
            }
            ProxyScheme::Socks5 { .. } => {
                log::trace!("Connect to remote socket5 proxy server: {}", proxy);
                let stream = if let Some(auth) = self.intercept.maybe_auth() {
                    super::timeout(
                        self.ms_timeout,
                        Socks5Stream::connect_with_password_and_socket(
                            stream,
                            target_addr,
                            &auth.user_name,
                            &auth.password,
                        ),
                    )
                    .await??
                } else {
                    super::timeout(
                        self.ms_timeout,
                        Socks5Stream::connect_with_socket(stream, target_addr),
                    )
                    .await??
                };
                Ok(FramedStream(
                    Framed::new(DynTcpStream(Box::new(stream)), BytesCodec::for_session()),
                    addr,
                    None,
                    0,
                ))
            }
        }
    }

    pub async fn https_connect_rustls<'a, Input>(
        &self,
        io: Input,
        target_addr: &TargetAddr<'a>,
    ) -> Result<BufStream<RustlsTlsStream<Input>>, ProxyError>
    where
        Input: AsyncRead + AsyncWrite + Unpin,
    {
        let authority = ConnectAuthority::from_target(target_addr)?;
        self.https_connect_rustls_authority(io, &authority).await
    }

    async fn https_connect_rustls_authority<Input>(
        &self,
        io: Input,
        authority: &ConnectAuthority,
    ) -> Result<BufStream<RustlsTlsStream<Input>>, ProxyError>
    where
        Input: AsyncRead + AsyncWrite + Unpin,
    {
        use std::convert::TryFrom;

        let url_domain = self.intercept.get_domain()?;
        let domain = rustls_pki_types::ServerName::try_from(url_domain.as_str())
            .map_err(|e| ProxyError::AddressResolutionFailed(e.to_string()))?
            .to_owned();
        let client_config = crate::verifier::client_config()
            .map_err(|e| ProxyError::IoError(std::io::Error::other(e)))?;
        let tls_connector = RustlsTlsConnector::from(std::sync::Arc::new(client_config));
        let stream = tls_connector.connect(domain, io).await?;
        self.http_connect_authority(stream, authority).await
    }

    pub async fn http_connect<'a, Input>(
        &self,
        io: Input,
        target_addr: &TargetAddr<'a>,
    ) -> Result<BufStream<Input>, ProxyError>
    where
        Input: AsyncRead + AsyncWrite + Unpin,
    {
        let authority = ConnectAuthority::from_target(target_addr)?;
        self.http_connect_authority(io, &authority).await
    }

    async fn http_connect_authority<Input>(
        &self,
        io: Input,
        authority: &ConnectAuthority,
    ) -> Result<BufStream<Input>, ProxyError>
    where
        Input: AsyncRead + AsyncWrite + Unpin,
    {
        let mut stream = BufStream::new(io);
        let request = self.make_request(authority);
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;
        recv_and_check_response(&mut stream).await?;
        Ok(stream)
    }

    fn make_request(&self, authority: &ConnectAuthority) -> String {
        let authority = authority.as_str();
        let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");

        if let Some(auth) = self.intercept.maybe_auth() {
            request = format!("{}{}", request, auth.get_proxy_authorization());
        }

        request.push_str("\r\n");
        request
    }
}

async fn get_response<IO>(stream: &mut BufStream<IO>) -> Result<String, ProxyError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    use tokio::io::AsyncBufReadExt;
    let mut response = String::new();

    loop {
        if stream.read_line(&mut response).await? == 0 {
            return Err(ProxyError::EndOfFile);
        }

        if MAXIMUM_RESPONSE_HEADER_LENGTH < response.len() {
            return Err(ProxyError::MaximumResponseHeaderLengthExceeded(
                response.len(),
            ));
        }

        if response.ends_with("\r\n\r\n") {
            return Ok(response);
        }
    }
}

async fn recv_and_check_response<IO>(stream: &mut BufStream<IO>) -> Result<(), ProxyError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let response_string = get_response(stream).await?;

    let mut response_headers = [EMPTY_HEADER; MAXIMUM_RESPONSE_HEADERS];
    let mut response = Response::new(&mut response_headers);
    let response_bytes = response_string.into_bytes();
    response.parse(&response_bytes)?;

    match response.code {
        Some(code) => {
            if code == 200 {
                Ok(())
            } else {
                Err(ProxyError::HttpCode200(code))
            }
        }
        None => Err(ProxyError::NoHttpCode),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn https_proxy_uses_only_one_tcp_connection_even_when_tls_fails() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = listener.local_addr().unwrap();
        let (stop, mut stopped) = tokio::sync::oneshot::channel();
        let observed = tokio::spawn(async move {
            let mut connections = Vec::new();
            loop {
                tokio::select! {
                    connection = listener.accept() => connections.push(connection.unwrap().0),
                    _ = &mut stopped => break,
                }
            }
            connections.len()
        });
        let proxy = Proxy::new(format!("https://{proxy_address}"), 250).unwrap();
        assert!(proxy
            .connect(("unresolved.invalid", 80), None)
            .await
            .is_err());
        stop.send(()).unwrap();
        assert_eq!(
            observed.await.unwrap(),
            1,
            "a supplied stream must never evaluate a second connection fallback"
        );
    }

    async fn captured_connect_request(
        proxy: &Proxy,
        target: TargetAddr<'_>,
    ) -> (Result<(), ProxyError>, Vec<u8>) {
        let (client, mut peer) = tokio::io::duplex(4096);
        let capture = async move {
            let mut request = Vec::new();
            let read_request = async {
                let mut chunk = [0; 512];
                loop {
                    let n = peer.read(&mut chunk).await?;
                    if n == 0 {
                        break;
                    }
                    request.extend_from_slice(&chunk[..n]);
                    if request.ends_with(b"\r\n\r\n") || request.len() >= 4096 {
                        break;
                    }
                }
                std::io::Result::Ok(())
            };
            match crate::timeout(100, read_request).await {
                Ok(Ok(())) if !request.is_empty() => {
                    peer.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
                    request
                }
                _ => Vec::new(),
            }
        };

        let (result, request) = tokio::join!(proxy.http_connect(client, &target), capture);
        (result.map(|_| ()), request)
    }

    #[tokio::test]
    async fn http_connect_rejects_invalid_authorities_before_writing() {
        let proxy = Proxy::new("http://127.0.0.1:8080", 1_000).unwrap();
        let invalid_hosts = [
            "target.example\r\nX-Injected: yes",
            "target.example\n\nGET /smuggled HTTP/1.1",
            "target.example with-space",
            "target.example\twith-tab",
            "target.example\0with-nul",
            "target.example\u{a0}with-unicode-space",
            "user@target.example",
            "target.example/path",
            "target.example\\path",
            "target.example?query",
            "target.example#fragment",
            "-leading-hyphen.example",
            "trailing-hyphen-.example",
            "empty..label.example",
            "invalid_label.example",
        ];

        for host in invalid_hosts {
            let target = TargetAddr::Domain(Cow::Borrowed(host), 443);
            let (result, request) = captured_connect_request(&proxy, target).await;
            assert!(
                matches!(result, Err(ProxyError::InvalidTargetAuthority)),
                "invalid authority was accepted"
            );
            assert!(request.is_empty(), "invalid authority reached proxy I/O");
        }

        for host in [
            format!("{}.example", "a".repeat(64)),
            vec!["a".repeat(63); 4].join("."),
            "a".repeat(MAX_CONNECT_HOST_INPUT_LENGTH + 1),
        ] {
            let target = TargetAddr::Domain(Cow::Borrowed(&host), 443);
            let (result, request) = captured_connect_request(&proxy, target).await;
            assert!(matches!(result, Err(ProxyError::InvalidTargetAuthority)));
            assert!(request.is_empty(), "invalid authority reached proxy I/O");
        }
    }

    #[tokio::test]
    async fn http_connect_writes_canonical_authority_form_only() {
        let credential = uuid::Uuid::new_v4().to_string();
        let proxy = Proxy::new("http://127.0.0.1:8080", 1_000)
            .unwrap()
            .basic_auth("proxy-user", &credential);
        let authorization = general_purpose::STANDARD.encode(format!("proxy-user:{credential}"));
        let cases = [
            (
                TargetAddr::Domain(Cow::Borrowed("Example.COM"), 443),
                "example.com:443",
            ),
            (
                TargetAddr::Domain(Cow::Borrowed("bücher.example"), 8443),
                "xn--bcher-kva.example:8443",
            ),
            (
                TargetAddr::Domain(Cow::Borrowed("example.com."), 443),
                "example.com.:443",
            ),
            (
                TargetAddr::Ip("192.0.2.10:80".parse().unwrap()),
                "192.0.2.10:80",
            ),
            (
                TargetAddr::Ip("[2001:db8::1]:443".parse().unwrap()),
                "[2001:db8::1]:443",
            ),
        ];

        for (target, authority) in cases {
            let (result, request) = captured_connect_request(&proxy, target).await;
            result.unwrap();
            let expected = format!(
                "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\
                 Proxy-Authorization: Basic {authorization}\r\n\r\n"
            );
            assert_eq!(request, expected.as_bytes());
        }
    }

    #[tokio::test]
    async fn proxy_connect_validates_target_before_proxy_resolution() {
        let proxy = Proxy::new("http://unresolvable.invalid:8080", 30_000).unwrap();
        let target = TargetAddr::Domain(Cow::Borrowed("target.example\r\nX-Injected: yes"), 443);

        let error = match proxy.connect(target, None).await {
            Ok(_) => panic!("invalid authority was accepted"),
            Err(error) => error,
        };
        assert!(matches!(
            error.downcast_ref::<ProxyError>(),
            Some(ProxyError::InvalidTargetAuthority)
        ));
    }

    #[tokio::test]
    async fn https_connect_validates_target_before_tls_handshake() {
        let proxy = Proxy::new("https://proxy.example:443", 30_000).unwrap();
        let target = TargetAddr::Domain(Cow::Borrowed("target.example\nsmuggled"), 443);
        let (client, _peer) = tokio::io::duplex(64);

        assert!(matches!(
            proxy.https_connect_rustls(client, &target).await,
            Err(ProxyError::InvalidTargetAuthority)
        ));
    }
}
