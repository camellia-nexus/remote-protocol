use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
    task::JoinSet,
    time::{sleep, Instant},
};
use tokio_rustls::{rustls, TlsAcceptor};

struct Pki {
    certificate: rustls_pki_types::CertificateDer<'static>,
    server: Arc<rustls::ServerConfig>,
}

impl Pki {
    fn new(names: &[&str]) -> Self {
        let rcgen::CertifiedKey { cert, signing_key } = rcgen::generate_simple_self_signed(
            names
                .iter()
                .map(|name| name.to_string())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let key = rustls_pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der());
        let certificate = cert.der().clone();
        let server = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![certificate.clone()], key.into())
        .unwrap();
        Self {
            certificate,
            server: Arc::new(server),
        }
    }
}

fn client_policy(authorities: &[&Pki]) -> Arc<ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    for authority in authorities {
        roots.add(authority.certificate.clone()).unwrap();
    }
    Arc::new(
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

#[derive(Clone, Copy, Debug)]
enum Mode {
    Http,
    Https,
    Socks,
}

impl Mode {
    fn scheme(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
            Self::Socks => "socks5",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Stall {
    None,
    ProxyTls,
    Tunnel,
    DestinationTls,
    Upgrade,
}

struct Plan {
    mode: Mode,
    wss: bool,
    authenticate: bool,
    reject_auth: bool,
    stall: Stall,
    phase_delay: Duration,
    ipv6: bool,
    destination_host: Option<&'static str>,
    timeout_ms: u64,
    proxy_tls: Arc<rustls::ServerConfig>,
    destination_tls: Arc<rustls::ServerConfig>,
    client_tls: Arc<ClientConfig>,
}

impl Plan {
    fn new(mode: Mode, wss: bool, authenticate: bool, authority: &Pki) -> Self {
        Self {
            mode,
            wss,
            authenticate,
            reject_auth: false,
            stall: Stall::None,
            phase_delay: Duration::ZERO,
            ipv6: false,
            destination_host: None,
            timeout_ms: 2000,
            proxy_tls: authority.server.clone(),
            destination_tls: authority.server.clone(),
            client_tls: client_policy(&[authority]),
        }
    }

    fn authority(&self, target: SocketAddr) -> String {
        match self.destination_host {
            Some(host) => format!("{host}:{}", target.port()),
            None => target.to_string(),
        }
    }
}

#[derive(Default)]
struct Observed {
    direct_tcp: AtomicUsize,
    proxy_tcp: AtomicUsize,
    proxy_tls: AtomicUsize,
    tunnels: AtomicUsize,
    destination_tls: AtomicUsize,
    upgrades: AtomicUsize,
}

async fn phase(plan: &Plan, stage: Stall) {
    if plan.stall == stage {
        std::future::pending::<()>().await;
    }
    if !plan.phase_delay.is_zero() {
        sleep(plan.phase_delay).await;
    }
}

async fn negotiate(io: &mut DynTcpStream, plan: &Plan, target: SocketAddr) -> ResultType<()> {
    match plan.mode {
        Mode::Http | Mode::Https => {
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                assert!(header.len() < 4096);
                header.push(io.read_u8().await?);
            }
            let header = String::from_utf8(header)?;
            assert!(header.starts_with(&format!("CONNECT {} HTTP/1.1\r\n", plan.authority(target))));
            let auth = format!(
                "Proxy-Authorization: Basic {}\r\n",
                STANDARD.encode(b"net006-test:not-a-real-secret")
            );
            assert_eq!(header.contains(&auth), plan.authenticate);
            if plan.reject_auth {
                io.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                    .await?;
                io.flush().await?;
                bail!("test proxy rejected authentication");
            }
            phase(plan, Stall::Tunnel).await;
            io.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
            io.flush().await?;
        }
        Mode::Socks => {
            assert_eq!(io.read_u8().await?, 5);
            let mut methods = vec![0; io.read_u8().await? as usize];
            io.read_exact(&mut methods).await?;
            let method = if plan.authenticate { 2 } else { 0 };
            assert!(methods.contains(&method));
            io.write_all(&[5, method]).await?;
            if plan.authenticate {
                assert_eq!(io.read_u8().await?, 1);
                let mut user = vec![0; io.read_u8().await? as usize];
                io.read_exact(&mut user).await?;
                let mut password = vec![0; io.read_u8().await? as usize];
                io.read_exact(&mut password).await?;
                assert_eq!(user, b"net006-test");
                assert_eq!(password, b"not-a-real-secret");
                io.write_all(&[1, u8::from(plan.reject_auth)]).await?;
                io.flush().await?;
                if plan.reject_auth {
                    bail!("test SOCKS proxy rejected authentication");
                }
            }
            assert_eq!(io.read_u8().await?, 5);
            assert_eq!(io.read_u8().await?, 1);
            assert_eq!(io.read_u8().await?, 0);
            let host = match io.read_u8().await? {
                1 => {
                    let mut ip = [0; 4];
                    io.read_exact(&mut ip).await?;
                    std::net::Ipv4Addr::from(ip).to_string()
                }
                4 => {
                    let mut ip = [0; 16];
                    io.read_exact(&mut ip).await?;
                    format!("[{}]", std::net::Ipv6Addr::from(ip))
                }
                3 => {
                    let mut name = vec![0; io.read_u8().await? as usize];
                    io.read_exact(&mut name).await?;
                    String::from_utf8(name)?
                }
                _ => bail!("test proxy received an invalid destination address"),
            };
            assert_eq!(
                format!("{host}:{}", io.read_u16().await?),
                plan.authority(target)
            );
            phase(plan, Stall::Tunnel).await;
            io.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 80]).await?;
            io.flush().await?;
        }
    }
    Ok(())
}

struct CheckUpgrade {
    authority: String,
}

impl tungstenite::handshake::server::Callback for CheckUpgrade {
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
            "/ws/relay?probe=1"
        );
        assert_eq!(request.headers()["host"].to_str().unwrap(), self.authority);
        assert!(!request.headers().contains_key("proxy-authorization"));
        Ok(response)
    }
}

async fn serve(
    stream: TcpStream,
    plan: &Plan,
    target: SocketAddr,
    observed: &Observed,
) -> ResultType<()> {
    let mut io = DynTcpStream(Box::new(stream));
    if matches!(plan.mode, Mode::Https) {
        phase(plan, Stall::ProxyTls).await;
        io = DynTcpStream(Box::new(
            TlsAcceptor::from(plan.proxy_tls.clone()).accept(io).await?,
        ));
        observed.proxy_tls.fetch_add(1, Ordering::SeqCst);
    }
    negotiate(&mut io, plan, target).await?;
    observed.tunnels.fetch_add(1, Ordering::SeqCst);
    if plan.wss {
        phase(plan, Stall::DestinationTls).await;
        let tls = TlsAcceptor::from(plan.destination_tls.clone())
            .accept(io)
            .await?;
        if let Some(host) = plan.destination_host {
            assert_eq!(tls.get_ref().1.server_name(), Some(host));
        }
        io = DynTcpStream(Box::new(tls));
        observed.destination_tls.fetch_add(1, Ordering::SeqCst);
    }
    phase(plan, Stall::Upgrade).await;
    let mut websocket = tokio_tungstenite::accept_hdr_async(
        io,
        CheckUpgrade {
            authority: plan.authority(target),
        },
    )
    .await?;
    observed.upgrades.fetch_add(1, Ordering::SeqCst);
    websocket
        .send(WsMessage::Binary(b"from-selected-proxy".to_vec().into()))
        .await?;
    let message = websocket
        .next()
        .await
        .ok_or_else(|| Error::other("test client closed before echo"))??;
    assert_eq!(message, WsMessage::Binary(b"echo".to_vec().into()));
    Ok(())
}

struct Outcome {
    connected: bool,
    timed_out: bool,
    elapsed: Duration,
    observed: Arc<Observed>,
}

async fn exercise(plan: Plan) -> Outcome {
    let direct = TcpListener::bind(if plan.ipv6 { "[::1]:0" } else { "127.0.0.1:0" })
        .await
        .unwrap();
    let target = direct.local_addr().unwrap();
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_address = proxy.local_addr().unwrap();
    let config = Socks5Server {
        proxy: format!("{}://{proxy_address}", plan.mode.scheme()),
        username: if plan.authenticate { "net006-test" } else { "" }.to_owned(),
        password: if plan.authenticate {
            "not-a-real-secret"
        } else {
            ""
        }
        .to_owned(),
    };
    let observed = Arc::new(Observed::default());
    let mut tasks = JoinSet::new();
    let observer = observed.clone();
    tasks.spawn(async move {
        while let Ok((stream, _)) = direct.accept().await {
            observer.direct_tcp.fetch_add(1, Ordering::SeqCst);
            drop(stream);
        }
    });
    let (first, received) = oneshot::channel();
    let observer = observed.clone();
    tasks.spawn(async move {
        let mut first = Some(first);
        while let Ok((stream, peer)) = proxy.accept().await {
            observer.proxy_tcp.fetch_add(1, Ordering::SeqCst);
            if let Some(sender) = first.take() {
                let _ = sender.send((stream, peer));
            }
        }
    });
    let (finished, completion) = oneshot::channel();
    let observer = observed.clone();
    let policy = plan.client_tls.clone();
    let wss = plan.wss;
    let timeout_ms = plan.timeout_ms;
    let authority = plan.authority(target);
    tasks.spawn(async move {
        let (stream, peer) = received.await.unwrap();
        let result = serve(stream, &plan, target, &observer).await;
        let _ = finished.send((result.map_err(|error| error.to_string()), peer));
    });
    let start = Instant::now();
    let result = WsFramedStream::new_with_tls_config(
        &format!(
            "{}://{authority}/ws/relay?probe=1",
            if wss { "wss" } else { "ws" }
        ),
        Some("127.0.0.1:0".parse().unwrap()),
        Some(&config),
        timeout_ms,
        Some(policy),
    )
    .await;
    let elapsed = start.elapsed();
    let timed_out = result.as_ref().err().is_some_and(|error| {
        error
            .downcast_ref::<tokio::time::error::Elapsed>()
            .is_some()
    });
    let connected = result.is_ok();
    if let Ok(mut stream) = result {
        assert_eq!(stream.is_tls(), wss);
        assert_eq!(
            &stream.next_timeout(1000).await.unwrap().unwrap()[..],
            b"from-selected-proxy"
        );
        stream.send_raw(b"echo".to_vec()).await.unwrap();
        let (server, peer) = timeout(Duration::from_secs(2), completion)
            .await
            .unwrap()
            .unwrap();
        assert!(server.is_ok(), "{server:?}");
        assert_eq!(stream.local_addr(), peer);
    }
    tokio::task::yield_now().await;
    tasks.shutdown().await;
    assert_eq!(
        observed.direct_tcp.load(Ordering::SeqCst),
        0,
        "a failed or successful selected route must never fall back to the direct endpoint"
    );
    assert_eq!(
        observed.proxy_tcp.load(Ordering::SeqCst),
        1,
        "one attempt must own exactly one proxy socket"
    );
    Outcome {
        connected,
        timed_out,
        elapsed,
        observed,
    }
}

#[tokio::test]
async fn actual_tls_matrix_covers_http_https_socks_ws_wss_and_authentication() {
    let authority = Pki::new(&["127.0.0.1", "::1"]);
    for mode in [Mode::Http, Mode::Https, Mode::Socks] {
        for wss in [false, true] {
            for authenticate in [false, true] {
                let outcome = exercise(Plan::new(mode, wss, authenticate, &authority)).await;
                assert!(outcome.connected, "{mode:?} wss={wss} auth={authenticate}");
                assert_eq!(outcome.observed.tunnels.load(Ordering::SeqCst), 1);
                assert_eq!(
                    outcome.observed.destination_tls.load(Ordering::SeqCst),
                    usize::from(wss)
                );
                assert_eq!(
                    outcome.observed.proxy_tls.load(Ordering::SeqCst),
                    usize::from(matches!(mode, Mode::Https))
                );
                assert_eq!(outcome.observed.upgrades.load(Ordering::SeqCst), 1);
            }
        }
    }
}

#[tokio::test]
async fn destination_dns_and_sni_stay_distinct_from_the_proxy_identity() {
    let proxy = Pki::new(&["127.0.0.1"]);
    let destination = Pki::new(&["unresolved.invalid"]);
    for mode in [Mode::Http, Mode::Https, Mode::Socks] {
        let mut plan = Plan::new(mode, true, true, &proxy);
        plan.destination_tls = destination.server.clone();
        plan.destination_host = Some("unresolved.invalid");
        plan.client_tls = client_policy(&[&proxy, &destination]);
        assert!(exercise(plan).await.connected, "{mode:?}");
    }
}

#[tokio::test]
async fn ipv6_destination_authority_survives_every_proxy_transport() {
    let authority = Pki::new(&["127.0.0.1", "::1"]);
    for mode in [Mode::Http, Mode::Https, Mode::Socks] {
        let mut plan = Plan::new(mode, true, true, &authority);
        plan.ipv6 = true;
        assert!(exercise(plan).await.connected, "{mode:?}");
    }
}

#[tokio::test]
async fn untrusted_or_wrong_name_certificates_on_either_tls_layer_never_bypass_the_proxy() {
    let authority = Pki::new(&["127.0.0.1"]);
    let wrong_name = Pki::new(&["wrong.invalid"]);
    let untrusted = Pki::new(&["127.0.0.1"]);
    for proxy_layer in [false, true] {
        for bad in [&wrong_name, &untrusted] {
            let mut plan = Plan::new(Mode::Https, true, false, &authority);
            // Trust the wrong-name certificate, but not the untrusted one, so
            // hostname and issuer failures are independently exercised.
            plan.client_tls = client_policy(&[&authority, &wrong_name]);
            if proxy_layer {
                plan.proxy_tls = bad.server.clone();
            } else {
                plan.destination_tls = bad.server.clone();
            }
            let outcome = exercise(plan).await;
            assert!(!outcome.connected);
            assert_eq!(outcome.observed.upgrades.load(Ordering::SeqCst), 0);
        }
    }
}

#[tokio::test]
async fn proxy_authentication_denial_never_switches_to_a_direct_route() {
    let authority = Pki::new(&["127.0.0.1"]);
    for mode in [Mode::Http, Mode::Https, Mode::Socks] {
        let mut plan = Plan::new(mode, true, true, &authority);
        plan.reject_auth = true;
        let outcome = exercise(plan).await;
        assert!(!outcome.connected);
        assert_eq!(outcome.observed.upgrades.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn one_deadline_covers_each_handshake_phase_and_their_accumulated_time() {
    let authority = Pki::new(&["127.0.0.1"]);
    for stall in [
        Stall::ProxyTls,
        Stall::Tunnel,
        Stall::DestinationTls,
        Stall::Upgrade,
        Stall::None,
    ] {
        let mut plan = Plan::new(Mode::Https, true, false, &authority);
        plan.timeout_ms = 120;
        plan.stall = stall;
        if stall == Stall::None {
            plan.phase_delay = Duration::from_millis(50);
        }
        let outcome = exercise(plan).await;
        assert!(!outcome.connected, "{stall:?}");
        assert!(outcome.timed_out, "{stall:?}");
        assert!(
            outcome.elapsed < Duration::from_millis(500),
            "{stall:?}: {:?}",
            outcome.elapsed
        );
    }
}

#[test]
fn missing_tls_policy_never_selects_a_default_verifier() {
    assert!(WsFramedStream::get_connector(&TlsType::Rustls, None).is_err());
    let authority = Pki::new(&["127.0.0.1"]);
    let configured = client_policy(&[&authority]);
    match WsFramedStream::get_connector(&TlsType::Rustls, Some(configured.clone())).unwrap() {
        Some(Connector::Rustls(actual)) => assert!(Arc::ptr_eq(&actual, &configured)),
        _ => panic!("configured policy must not become a different connector"),
    }
}

#[test]
fn handshake_errors_do_not_retain_peer_headers_or_body_in_any_debug_chain() {
    let response = tungstenite::http::Response::builder()
        .status(403)
        .header("set-cookie", "PRIVATE-COOKIE")
        .body(Some(b"PRIVATE-BODY".to_vec()))
        .unwrap();
    let error = handshake_error(tungstenite::Error::Http(Box::new(response)));
    for rendered in [
        error.to_string(),
        format!("{error:?}"),
        format!("{error:#}"),
    ] {
        assert!(rendered.contains("403"));
        assert!(!rendered.contains("PRIVATE"));
    }
}
