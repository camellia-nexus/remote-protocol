use crate::crypto::{
    box_,
    secretbox::{self, Key, Nonce},
};
use crate::{bail, bytes_codec::BytesCodec, config::Socks5Server, proxy::Proxy, ResultType};
use anyhow::Context as AnyhowCtx;
use bytes::{BufMut, Bytes, BytesMut};
use futures::{SinkExt, StreamExt};
use protobuf::Message;
use std::{
    io::{self, Error},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    ops::{Deref, DerefMut},
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{lookup_host, TcpListener, TcpSocket, ToSocketAddrs},
};
use tokio_socks::IntoTargetAddr;
use tokio_util::codec::Framed;

pub trait TcpStreamTrait: AsyncRead + AsyncWrite + Unpin {}
pub struct DynTcpStream(pub Box<dyn TcpStreamTrait + Send + Sync>);

/// The role in the session-key exchange. The initiator creates and seals the
/// symmetric key; the responder opens it. Roles are part of the implicit nonce
/// domain and must never be guessed from socket direction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CipherRole {
    Initiator,
    Responder,
}

#[derive(Clone, Copy)]
enum CipherDirection {
    InitiatorToResponder,
    ResponderToInitiator,
}

impl CipherRole {
    fn send_direction(self) -> CipherDirection {
        match self {
            Self::Initiator => CipherDirection::InitiatorToResponder,
            Self::Responder => CipherDirection::ResponderToInitiator,
        }
    }

    fn receive_direction(self) -> CipherDirection {
        match self {
            Self::Initiator => CipherDirection::ResponderToInitiator,
            Self::Responder => CipherDirection::InitiatorToResponder,
        }
    }
}

#[derive(Clone)]
pub struct Encrypt {
    key: Key,
    send_seq: u64,
    receive_seq: u64,
    role: CipherRole,
}

/// Version byte sealed together with every newly generated session key.
/// Changing the nonce domain or key-envelope format requires a new version.
pub const SESSION_CIPHER_VERSION: u8 = 1;
const SESSION_NONCE_DOMAIN: &[u8; 15] = b"camellia-rem-v1";

pub struct FramedStream(
    pub Framed<DynTcpStream, BytesCodec>,
    pub SocketAddr,
    pub Option<Encrypt>,
    pub u64,
);

impl Deref for FramedStream {
    type Target = Framed<DynTcpStream, BytesCodec>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for FramedStream {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Deref for DynTcpStream {
    type Target = Box<dyn TcpStreamTrait + Send + Sync>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for DynTcpStream {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

pub(crate) fn new_socket(
    addr: std::net::SocketAddr,
    reuse: bool,
) -> Result<TcpSocket, std::io::Error> {
    let socket = match addr {
        std::net::SocketAddr::V4(..) => TcpSocket::new_v4()?,
        std::net::SocketAddr::V6(..) => TcpSocket::new_v6()?,
    };
    if reuse {
        // windows has no reuse_port, but its reuse_address
        // almost equals to unix's reuse_port + reuse_address,
        // though may introduce nondeterministic behavior
        // illumos has no support for SO_REUSEPORT
        #[cfg(all(unix, not(target_os = "illumos")))]
        socket.set_reuseport(true).ok();
        socket.set_reuseaddr(true).ok();
    }
    socket.bind(addr)?;
    Ok(socket)
}

impl FramedStream {
    pub async fn new<T: ToSocketAddrs + std::fmt::Display>(
        remote_addr: T,
        local_addr: Option<SocketAddr>,
        ms_timeout: u64,
    ) -> ResultType<Self> {
        let connect_future = async {
            let addrs_stream = lookup_host(&remote_addr)
                .await
                .context(format!("DNS lookup failed for {remote_addr}"))?;
            let addrs: Vec<SocketAddr> = addrs_stream.collect();
            if addrs.is_empty() {
                bail!("Failed to resolve {remote_addr}: no addresses returned");
            }

            let mut last_err = None;
            for candidate in addrs {
                let local = if let Some(addr) = local_addr {
                    addr
                } else {
                    crate::config::Config::get_any_listen_addr(candidate.is_ipv4())
                };

                let socket = match new_socket(local, true) {
                    Ok(s) => s,
                    Err(err) => {
                        last_err = Some(anyhow::Error::new(err));
                        continue;
                    }
                };

                match socket.connect(candidate).await {
                    Ok(stream) => {
                        stream.set_nodelay(true).ok();
                        let addr = stream.local_addr()?;
                        return Ok(Self(
                            Framed::new(DynTcpStream(Box::new(stream)), BytesCodec::for_session()),
                            addr,
                            None,
                            0,
                        ));
                    }
                    Err(err) => {
                        last_err = Some(anyhow::Error::new(err));
                    }
                }
            }

            if let Some(err) = last_err {
                bail!("Failed to connect to {remote_addr}: {err}");
            } else {
                bail!("Failed to connect to {remote_addr}");
            }
        };

        super::timeout(ms_timeout, connect_future)
            .await
            .map_err(|_| {
                anyhow::anyhow!("Connection to {remote_addr} timed out after {ms_timeout}ms")
            })?
    }

    pub async fn connect<'t, T>(
        target: T,
        local_addr: Option<SocketAddr>,
        proxy_conf: &Socks5Server,
        ms_timeout: u64,
    ) -> ResultType<Self>
    where
        T: IntoTargetAddr<'t>,
    {
        let proxy = Proxy::from_conf(proxy_conf, Some(ms_timeout))?;
        proxy.connect::<T>(target, local_addr).await
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.1
    }

    pub fn set_send_timeout(&mut self, ms: u64) {
        self.3 = ms;
    }

    pub fn from(stream: impl TcpStreamTrait + Send + Sync + 'static, addr: SocketAddr) -> Self {
        Self::from_with_max_packet_length(
            stream,
            addr,
            crate::bytes_codec::SESSION_MAX_PACKET_LENGTH,
        )
    }

    pub fn from_with_max_packet_length(
        stream: impl TcpStreamTrait + Send + Sync + 'static,
        addr: SocketAddr,
        max_packet_length: usize,
    ) -> Self {
        Self(
            Framed::new(
                DynTcpStream(Box::new(stream)),
                BytesCodec::with_max_packet_length(max_packet_length),
            ),
            addr,
            None,
            0,
        )
    }

    pub fn set_raw(&mut self) {
        self.0.codec_mut().set_raw();
        self.2 = None;
    }

    pub fn is_secured(&self) -> bool {
        self.2.is_some()
    }

    #[inline]
    pub async fn send(&mut self, msg: &impl Message) -> ResultType<()> {
        self.send_raw(msg.write_to_bytes()?).await
    }

    #[inline]
    pub async fn send_raw(&mut self, msg: Vec<u8>) -> ResultType<()> {
        let mut msg = msg;
        if let Some(key) = self.2.as_mut() {
            msg = key.enc(&msg)?;
        }
        self.send_bytes(bytes::Bytes::from(msg)).await?;
        Ok(())
    }

    #[inline]
    pub async fn send_bytes(&mut self, bytes: Bytes) -> ResultType<()> {
        if self.3 > 0 {
            super::timeout(self.3, self.0.send(bytes)).await??;
        } else {
            self.0.send(bytes).await?;
        }
        Ok(())
    }

    #[inline]
    pub async fn next(&mut self) -> Option<Result<BytesMut, Error>> {
        let mut res = self.0.next().await;
        if let Some(Ok(bytes)) = res.as_mut() {
            if let Some(key) = self.2.as_mut() {
                if let Err(err) = key.dec(bytes) {
                    return Some(Err(err));
                }
            }
        }
        res
    }

    #[inline]
    pub async fn next_timeout(&mut self, ms: u64) -> Option<Result<BytesMut, Error>> {
        super::timeout(ms, self.next()).await.unwrap_or_default()
    }

    pub fn set_key(&mut self, key: Key, role: CipherRole) {
        self.2 = Some(Encrypt::new(key, role));
    }

    fn get_nonce(seqnum: u64, direction: CipherDirection) -> Nonce {
        let mut nonce = Nonce([0u8; secretbox::NONCEBYTES]);
        nonce.0[..std::mem::size_of_val(&seqnum)].copy_from_slice(&seqnum.to_le_bytes());
        nonce.0[8..23].copy_from_slice(SESSION_NONCE_DOMAIN);
        nonce.0[23] = match direction {
            CipherDirection::InitiatorToResponder => 0x49,
            CipherDirection::ResponderToInitiator => 0x52,
        };
        nonce
    }
}

const DEFAULT_BACKLOG: u32 = 128;

pub async fn new_listener<T: ToSocketAddrs>(addr: T, reuse: bool) -> ResultType<TcpListener> {
    if !reuse {
        Ok(TcpListener::bind(addr).await?)
    } else {
        let addr = super::timeout(5000, lookup_host(&addr))
            .await
            .map_err(|_| anyhow::anyhow!("DNS resolution timed out for listener address"))??
            .next()
            .context("could not resolve to any address")?;
        new_socket(addr, true)?
            .listen(DEFAULT_BACKLOG)
            .map_err(anyhow::Error::msg)
    }
}

pub async fn listen_any(port: u16) -> ResultType<TcpListener> {
    if let Ok(mut socket) = TcpSocket::new_v6() {
        #[cfg(unix)]
        {
            // illumos has no support for SO_REUSEPORT
            #[cfg(not(target_os = "illumos"))]
            socket.set_reuseport(true).ok();
            socket.set_reuseaddr(true).ok();
            use std::os::unix::io::{FromRawFd, IntoRawFd};
            let raw_fd = socket.into_raw_fd();
            let sock2 = unsafe { socket2::Socket::from_raw_fd(raw_fd) };
            sock2.set_only_v6(false).ok();
            socket = unsafe { TcpSocket::from_raw_fd(sock2.into_raw_fd()) };
        }
        #[cfg(windows)]
        {
            use std::os::windows::prelude::{FromRawSocket, IntoRawSocket};
            let raw_socket = socket.into_raw_socket();
            let sock2 = unsafe { socket2::Socket::from_raw_socket(raw_socket) };
            sock2.set_only_v6(false).ok();
            socket = unsafe { TcpSocket::from_raw_socket(sock2.into_raw_socket()) };
        }
        if socket
            .bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port))
            .is_ok()
        {
            if let Ok(l) = socket.listen(DEFAULT_BACKLOG) {
                return Ok(l);
            }
        }
    }
    Ok(new_socket(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
        true,
    )?
    .listen(DEFAULT_BACKLOG)?)
}

impl Unpin for DynTcpStream {}

impl AsyncRead for DynTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.0), cx, buf)
    }
}

impl AsyncWrite for DynTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.0), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.0), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.0), cx)
    }
}

impl<R: AsyncRead + AsyncWrite + Unpin> TcpStreamTrait for R {}

impl Encrypt {
    pub fn new(key: Key, role: CipherRole) -> Self {
        Self {
            key,
            send_seq: 0,
            receive_seq: 0,
            role,
        }
    }

    pub fn dec(&mut self, bytes: &mut BytesMut) -> Result<(), Error> {
        if bytes.len() < secretbox::MACBYTES {
            return Err(Error::new(
                io::ErrorKind::InvalidData,
                "encrypted frame is shorter than its authentication tag",
            ));
        }
        let seqnum = self
            .receive_seq
            .checked_add(1)
            .ok_or_else(|| Error::new(io::ErrorKind::InvalidData, "receive sequence exhausted"))?;
        let nonce = FramedStream::get_nonce(seqnum, self.role.receive_direction());
        match secretbox::open(bytes, &nonce, &self.key) {
            Ok(res) => {
                self.receive_seq = seqnum;
                bytes.clear();
                bytes.put_slice(&res);
                Ok(())
            }
            Err(_) => Err(Error::new(
                io::ErrorKind::InvalidData,
                "decryption authentication failed",
            )),
        }
    }

    pub fn enc(&mut self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let seqnum = self
            .send_seq
            .checked_add(1)
            .ok_or_else(|| Error::other("send sequence exhausted"))?;
        let nonce = FramedStream::get_nonce(seqnum, self.role.send_direction());
        let ciphertext = secretbox::seal(data, &nonce, &self.key)
            .map_err(|_| Error::other("encryption error"))?;
        self.send_seq = seqnum;
        Ok(ciphertext)
    }

    pub fn encode_session_key(key: &Key) -> Vec<u8> {
        let mut envelope = Vec::with_capacity(secretbox::KEYBYTES + 1);
        envelope.push(SESSION_CIPHER_VERSION);
        envelope.extend_from_slice(&key.0);
        envelope
    }

    pub fn decode(
        symmetric_data: &[u8],
        their_pk_b: &[u8],
        our_sk_b: &box_::SecretKey,
    ) -> ResultType<Key> {
        if their_pk_b.len() != box_::PUBLICKEYBYTES {
            anyhow::bail!("Handshake failed: pk length {}", their_pk_b.len());
        }
        let nonce = box_::Nonce([0u8; box_::NONCEBYTES]);
        let mut pk_ = [0u8; box_::PUBLICKEYBYTES];
        pk_[..].copy_from_slice(their_pk_b);
        let their_pk_b = box_::PublicKey(pk_);
        let key_envelope = box_::open(symmetric_data, &nonce, &their_pk_b, our_sk_b)
            .map_err(|_| anyhow::anyhow!("Handshake failed: box decryption failure"))?;
        if key_envelope.len() != secretbox::KEYBYTES + 1 {
            anyhow::bail!("Handshake failed: invalid session-key envelope length");
        }
        if key_envelope[0] != SESSION_CIPHER_VERSION {
            anyhow::bail!(
                "Handshake failed: unsupported session cipher version {}",
                key_envelope[0]
            );
        }
        let mut key = [0u8; secretbox::KEYBYTES];
        key.copy_from_slice(&key_envelope[1..]);
        Ok(Key(key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> Key {
        Key([0x5a; secretbox::KEYBYTES])
    }

    #[test]
    fn opposite_directions_do_not_reuse_the_same_key_nonce_pair() {
        let client_plaintext = b"known client request";
        let server_plaintext = b"secret server reply!";
        assert_eq!(client_plaintext.len(), server_plaintext.len());

        let mut client = Encrypt::new(test_key(), CipherRole::Initiator);
        let mut server = Encrypt::new(test_key(), CipherRole::Responder);
        let client_ciphertext = client.enc(client_plaintext).expect("client encryption");
        let server_ciphertext = server.enc(server_plaintext).expect("server encryption");

        let ciphertext_xor = client_ciphertext[secretbox::MACBYTES..]
            .iter()
            .zip(&server_ciphertext[secretbox::MACBYTES..])
            .map(|(left, right)| left ^ right)
            .collect::<Vec<_>>();
        let plaintext_xor = client_plaintext
            .iter()
            .zip(server_plaintext)
            .map(|(left, right)| left ^ right)
            .collect::<Vec<_>>();

        assert_ne!(
            ciphertext_xor, plaintext_xor,
            "opposite directions reused the SecretBox keystream"
        );
    }

    #[test]
    fn opposite_roles_decrypt_both_directions() {
        let mut initiator = Encrypt::new(test_key(), CipherRole::Initiator);
        let mut responder = Encrypt::new(test_key(), CipherRole::Responder);

        let mut request = BytesMut::from(
            initiator
                .enc(b"request")
                .expect("initiator encryption")
                .as_slice(),
        );
        responder.dec(&mut request).expect("responder decryption");
        assert_eq!(&request[..], b"request");

        let mut response = BytesMut::from(
            responder
                .enc(b"response")
                .expect("responder encryption")
                .as_slice(),
        );
        initiator.dec(&mut response).expect("initiator decryption");
        assert_eq!(&response[..], b"response");
    }

    #[test]
    fn same_roles_cannot_decrypt_each_other() {
        let mut sender = Encrypt::new(test_key(), CipherRole::Initiator);
        let mut wrong_role_receiver = Encrypt::new(test_key(), CipherRole::Initiator);
        let ciphertext = sender.enc(b"role-bound").expect("sender encryption");
        let mut frame = BytesMut::from(ciphertext.as_slice());

        assert!(wrong_role_receiver.dec(&mut frame).is_err());
        assert_eq!(wrong_role_receiver.receive_seq, 0);
    }

    #[test]
    fn sequence_exhaustion_fails_without_wrapping() {
        let mut encryptor = Encrypt::new(test_key(), CipherRole::Initiator);
        encryptor.send_seq = u64::MAX;
        assert!(encryptor.enc(b"must not wrap").is_err());
        assert_eq!(encryptor.send_seq, u64::MAX);

        let mut decryptor = Encrypt::new(test_key(), CipherRole::Responder);
        decryptor.receive_seq = u64::MAX;
        let mut frame = BytesMut::from(vec![0u8; secretbox::MACBYTES].as_slice());
        assert!(decryptor.dec(&mut frame).is_err());
        assert_eq!(decryptor.receive_seq, u64::MAX);
    }

    #[test]
    fn legacy_unversioned_session_key_envelope_is_rejected() {
        let (responder_pk, responder_sk) = box_::gen_keypair();
        let (initiator_pk, initiator_sk) = box_::gen_keypair();
        let nonce = box_::Nonce([0u8; box_::NONCEBYTES]);
        let legacy = box_::seal(&test_key().0, &nonce, &responder_pk, &initiator_sk)
            .expect("legacy key envelope encryption");

        let error = match Encrypt::decode(&legacy, &initiator_pk.0, &responder_sk) {
            Ok(_) => panic!("unversioned key envelope must fail closed"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("envelope length"));
    }

    #[test]
    fn versioned_session_key_envelope_round_trips() {
        let (responder_pk, responder_sk) = box_::gen_keypair();
        let (initiator_pk, initiator_sk) = box_::gen_keypair();
        let nonce = box_::Nonce([0u8; box_::NONCEBYTES]);
        let envelope = Encrypt::encode_session_key(&test_key());
        let sealed = box_::seal(&envelope, &nonce, &responder_pk, &initiator_sk)
            .expect("session key envelope encryption");

        let decoded = Encrypt::decode(&sealed, &initiator_pk.0, &responder_sk)
            .expect("versioned key envelope must decode");
        assert_eq!(decoded.0, test_key().0);
    }

    #[test]
    fn decryption_rejects_unauthenticated_frames_without_advancing_sequence() {
        for len in 0..=secretbox::MACBYTES {
            let mut decryptor = Encrypt::new(test_key(), CipherRole::Responder);
            let mut frame = BytesMut::from(vec![0x41; len].as_slice());

            assert!(decryptor.dec(&mut frame).is_err(), "length {len}");
            assert_eq!(decryptor.receive_seq, 0, "length {len}");
        }
    }

    #[test]
    fn decryption_accepts_authenticated_empty_plaintext_at_mac_boundary() {
        let mut encryptor = Encrypt::new(test_key(), CipherRole::Initiator);
        let mut decryptor = Encrypt::new(test_key(), CipherRole::Responder);
        let ciphertext = encryptor.enc(&[]).expect("empty plaintext must encrypt");
        assert_eq!(ciphertext.len(), secretbox::MACBYTES);

        let mut frame = BytesMut::from(ciphertext.as_slice());
        decryptor
            .dec(&mut frame)
            .expect("authenticated empty plaintext must decrypt");

        assert!(frame.is_empty());
        assert_eq!(decryptor.receive_seq, 1);
    }

    #[test]
    fn failed_authentication_does_not_consume_the_expected_nonce() {
        let mut encryptor = Encrypt::new(test_key(), CipherRole::Initiator);
        let ciphertext = encryptor
            .enc(b"authenticated payload")
            .expect("payload must encrypt");
        let mut tampered = ciphertext.clone();
        tampered[0] ^= 0x80;

        let mut decryptor = Encrypt::new(test_key(), CipherRole::Responder);
        let mut tampered_frame = BytesMut::from(tampered.as_slice());
        assert!(decryptor.dec(&mut tampered_frame).is_err());
        assert_eq!(decryptor.receive_seq, 0);

        let mut valid_frame = BytesMut::from(ciphertext.as_slice());
        decryptor
            .dec(&mut valid_frame)
            .expect("the expected nonce must remain available after rejection");
        assert_eq!(&valid_frame[..], b"authenticated payload");
        assert_eq!(decryptor.receive_seq, 1);
    }
}
