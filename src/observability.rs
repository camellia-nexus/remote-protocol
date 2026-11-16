//! Structured observability and correlation wire schema module (LOG-014).
//!
//! Provides:
//! - Standardized `StructuredEvent` schema for JSON log emission across remote-protocol,
//!   remote-server, and remote-client.
//! - Fail-closed validation and sanitization for distributed correlation IDs (`trace_id`, `attempt_id`).
//! - PII pseudonymization helpers (`hash_peer_id`, `mask_ip`, `mask_socket_addr`).
//! - Zero-allocation hot-path sampler (`HotPathSampler`) for frame capture, encoding, and render loops.
//! - Custom `flexi_logger` format function `structured_opt_format` emitting single-line JSON
//!   for structured events and sanitized line output for conventional logs.

use std::{
    net::{IpAddr, SocketAddr},
    sync::atomic::{AtomicU64, Ordering},
};

use chrono::Utc;
use serde_derive::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::protos::rendezvous::CorrelationContext;

/// The canonical schema version for structured events.
pub const STRUCTURED_SCHEMA_VERSION: &str = "1.0.0";

/// Target name used by structured event log emissions.
pub const STRUCTURED_LOG_TARGET: &str = "structured_event";

/// Check if a trace ID conforms to `^[0-9a-fA-F]{16,64}$`.
pub fn is_valid_trace_id(id: &str) -> bool {
    let len = id.len();
    (16..=64).contains(&len) && id.chars().all(|c| c.is_ascii_hexdigit())
}

/// Check if an attempt ID conforms to `^[0-9a-fA-F]{8,32}$`.
pub fn is_valid_attempt_id(id: &str) -> bool {
    let len = id.len();
    (8..=32).contains(&len) && id.chars().all(|c| c.is_ascii_hexdigit())
}

/// Generate a fresh 32-character lowercase hex W3C/UUID trace ID.
pub fn generate_trace_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

/// Generate a fresh 16-character lowercase hex attempt/span ID.
pub fn generate_attempt_id() -> String {
    let val: u64 = rand::random();
    format!("{val:016x}")
}

/// Validate and sanitize an incoming trace ID, failing closed to a newly generated ID
/// if empty, overlong, malformed, or containing invalid characters.
pub fn validate_trace_id(raw: &str) -> String {
    let trimmed = raw.trim();
    if is_valid_trace_id(trimmed) {
        trimmed.to_ascii_lowercase()
    } else {
        generate_trace_id()
    }
}

/// Validate and sanitize an incoming attempt ID, failing closed to a newly generated ID
/// if empty, overlong, malformed, or containing invalid characters.
pub fn validate_attempt_id(raw: &str) -> String {
    let trimmed = raw.trim();
    if is_valid_attempt_id(trimmed) {
        trimmed.to_ascii_lowercase()
    } else {
        generate_attempt_id()
    }
}

/// Compute a 16-character lowercase hex pseudonym of a peer ID using SHA-256.
/// Guarantees that raw peer IDs are never emitted directly into production logs.
pub fn hash_peer_id(peer_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(peer_id.as_bytes());
    let digest = hasher.finalize();
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(16);
    for &b in &digest[..8] {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Mask an IP address to preserve privacy while retaining operational routing diagnostics.
///
/// IPv4 `192.168.1.50` -> `192.168.1.***`
/// IPv6 `2001:db8:85a3::8a2e:370:7334` -> `2001:db8:85a3:***:***`
pub fn mask_ip(ip: impl Into<IpAddr>) -> String {
    match ip.into() {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            format!("{}.{}.{}.***", octets[0], octets[1], octets[2])
        }
        IpAddr::V6(ipv6) => {
            let segments = ipv6.segments();
            format!(
                "{:x}:{:x}:{:x}:***:***",
                segments[0], segments[1], segments[2]
            )
        }
    }
}

/// Mask a socket address to preserve privacy while retaining port diagnostic visibility.
///
/// `192.168.1.50:21116` -> `192.168.1.***:21116`
pub fn mask_socket_addr(addr: impl Into<SocketAddr>) -> String {
    let addr = addr.into();
    format!("{}:{}", mask_ip(addr.ip()), addr.port())
}

/// Mask a raw endpoint string, either as socket addr or IP.
pub fn mask_endpoint_str(raw: &str) -> String {
    let trimmed = raw.trim();
    if let Ok(socket_addr) = trimmed.parse::<SocketAddr>() {
        mask_socket_addr(socket_addr)
    } else if let Ok(ip) = trimmed.parse::<IpAddr>() {
        mask_ip(ip)
    } else {
        trimmed.to_string()
    }
}

/// Helper extension trait for manipulating protobuf `CorrelationContext`.
pub trait CorrelationContextExt {
    /// Create a new CorrelationContext with fresh cryptographically random IDs.
    fn new_random() -> Self;

    /// Create a CorrelationContext with fail-closed validation and sanitization.
    fn new_validated(raw_trace_id: &str, raw_attempt_id: &str, session_id: Option<u64>) -> Self;

    /// Sanitize trace_id and attempt_id in-place.
    fn sanitize_in_place(&mut self);
}

impl CorrelationContextExt for CorrelationContext {
    fn new_random() -> Self {
        let mut ctx = CorrelationContext::new();
        ctx.trace_id = generate_trace_id();
        ctx.attempt_id = generate_attempt_id();
        ctx.session_id = 0;
        ctx
    }

    fn new_validated(raw_trace_id: &str, raw_attempt_id: &str, session_id: Option<u64>) -> Self {
        let mut ctx = CorrelationContext::new();
        ctx.trace_id = validate_trace_id(raw_trace_id);
        ctx.attempt_id = validate_attempt_id(raw_attempt_id);
        ctx.session_id = session_id.unwrap_or(0);
        ctx
    }

    fn sanitize_in_place(&mut self) {
        self.trace_id = validate_trace_id(&self.trace_id);
        self.attempt_id = validate_attempt_id(&self.attempt_id);
    }
}

/// Structured cross-system event schema (LOG-014).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StructuredEvent {
    /// Schema specification version, fixed to "1.0.0".
    pub schema_version: String,

    /// RFC 3339 UTC microsecond timestamp.
    pub timestamp: String,

    /// Originating subsystem ("remote-protocol", "remote-server", "remote-client").
    pub service: String,

    /// Log severity level ("INFO", "WARN", "ERROR", "DEBUG", "TRACE").
    pub level: String,

    /// Standardized event name (e.g. "PEER_REGISTER", "PUNCH_HOLE_REQ", "RELAY_ATTACH", "AUTH_RESULT").
    pub event: String,

    /// Validated 16-64 hex lowercase correlation trace ID.
    pub trace_id: String,

    /// Validated 8-32 hex lowercase attempt/span ID.
    pub attempt_id: String,

    /// Optional numeric session sequence ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<u64>,

    /// Connection lifecycle stage ("rendezvous", "direct", "relay", "auth", "streaming").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,

    /// Outcome result code ("ok", "failed", "timeout", "refused").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,

    /// Pseudonymized first 16 characters of SHA-256(peer_id).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_id_hash: Option<String>,

    /// Masked endpoint string (e.g. "192.168.1.***:21116").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_masked: Option<String>,

    /// Elapsed duration in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,

    /// Machine-readable error or rejection reason code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,

    /// Typed attributes for event-specific metadata.
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub attributes: serde_json::Map<String, serde_json::Value>,
}

impl StructuredEvent {
    /// Create a new StructuredEvent with fail-closed validation of trace_id and attempt_id.
    pub fn new(
        service: impl Into<String>,
        level: impl Into<String>,
        event: impl Into<String>,
        trace_id: &str,
        attempt_id: &str,
    ) -> Self {
        let valid_trace = validate_trace_id(trace_id);
        let valid_attempt = validate_attempt_id(attempt_id);
        let now_str = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
        Self {
            schema_version: STRUCTURED_SCHEMA_VERSION.to_string(),
            timestamp: now_str,
            service: service.into(),
            level: level.into(),
            event: event.into(),
            trace_id: valid_trace,
            attempt_id: valid_attempt,
            session_id: None,
            stage: None,
            result: None,
            peer_id_hash: None,
            endpoint_masked: None,
            duration_ms: None,
            error_code: None,
            attributes: serde_json::Map::new(),
        }
    }

    /// Construct a StructuredEvent seeded from a protobuf CorrelationContext.
    pub fn from_correlation(
        service: impl Into<String>,
        level: impl Into<String>,
        event: impl Into<String>,
        ctx: &CorrelationContext,
    ) -> Self {
        let mut evt = Self::new(service, level, event, &ctx.trace_id, &ctx.attempt_id);
        if ctx.session_id > 0 {
            evt.session_id = Some(ctx.session_id);
        }
        evt
    }

    /// Extract a protobuf CorrelationContext from this StructuredEvent.
    pub fn to_correlation_context(&self) -> CorrelationContext {
        let mut ctx = CorrelationContext::new();
        ctx.trace_id = self.trace_id.clone();
        ctx.attempt_id = self.attempt_id.clone();
        if let Some(sid) = self.session_id {
            ctx.session_id = sid;
        }
        ctx
    }

    /// Attach session ID.
    pub fn with_session_id(mut self, session_id: u64) -> Self {
        self.session_id = Some(session_id);
        self
    }

    /// Attach lifecycle stage.
    pub fn with_stage(mut self, stage: impl Into<String>) -> Self {
        self.stage = Some(stage.into());
        self
    }

    /// Attach outcome result.
    pub fn with_result(mut self, result: impl Into<String>) -> Self {
        self.result = Some(result.into());
        self
    }

    /// Attach peer ID, which is automatically hashed with SHA-256 (first 16 chars).
    pub fn with_peer_id(mut self, peer_id: &str) -> Self {
        self.peer_id_hash = Some(hash_peer_id(peer_id));
        self
    }

    /// Attach pre-hashed peer ID pseudonym.
    pub fn with_peer_id_hash(mut self, hash: impl Into<String>) -> Self {
        self.peer_id_hash = Some(hash.into());
        self
    }

    /// Attach masked socket address endpoint.
    pub fn with_endpoint(mut self, addr: impl Into<SocketAddr>) -> Self {
        self.endpoint_masked = Some(mask_socket_addr(addr));
        self
    }

    /// Attach masked endpoint string.
    pub fn with_endpoint_masked(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint_masked = Some(mask_endpoint_str(&endpoint.into()));
        self
    }

    /// Attach execution duration in milliseconds.
    pub fn with_duration_ms(mut self, duration_ms: u64) -> Self {
        self.duration_ms = Some(duration_ms);
        self
    }

    /// Attach machine-readable error code.
    pub fn with_error_code(mut self, code: impl Into<String>) -> Self {
        self.error_code = Some(code.into());
        self
    }

    /// Insert a custom typed attribute.
    pub fn with_attribute(
        mut self,
        key: impl Into<String>,
        value: impl Into<serde_json::Value>,
    ) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }

    /// Serialize this StructuredEvent into a compact single-line JSON string.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Emit this StructuredEvent through `log` targeting `STRUCTURED_LOG_TARGET`.
    pub fn emit(&self) {
        let json_line = match self.to_json() {
            Ok(j) => j,
            Err(e) => {
                log::error!(target: STRUCTURED_LOG_TARGET, "Failed to serialize StructuredEvent: {e}");
                return;
            }
        };
        match self.level.to_ascii_uppercase().as_str() {
            "DEBUG" => log::debug!(target: STRUCTURED_LOG_TARGET, "{json_line}"),
            "WARN" => log::warn!(target: STRUCTURED_LOG_TARGET, "{json_line}"),
            "ERROR" => log::error!(target: STRUCTURED_LOG_TARGET, "{json_line}"),
            "TRACE" => log::trace!(target: STRUCTURED_LOG_TARGET, "{json_line}"),
            _ => log::info!(target: STRUCTURED_LOG_TARGET, "{json_line}"),
        }
    }
}

/// Zero-allocation rate limiter and metric aggregator for high-frequency hot paths
/// (e.g. video capture, encoding, and rendering loops).
///
/// In accordance with LOG-014: per-frame span emission is forbidden; metrics must
/// be aggregated over time intervals (e.g. 1000ms) with zero heap allocations.
#[derive(Debug, Default)]
pub struct HotPathSampler {
    interval_ms: u64,
    last_emit_ms: AtomicU64,
    sample_count: AtomicU64,
}

impl HotPathSampler {
    /// Create a new sampler with the specified aggregation window in milliseconds.
    pub const fn new(interval_ms: u64) -> Self {
        Self {
            interval_ms,
            last_emit_ms: AtomicU64::new(0),
            sample_count: AtomicU64::new(0),
        }
    }

    /// Record a sample tick. Returns `Some(total_samples_in_interval)` only when the
    /// aggregation interval has elapsed.
    ///
    /// Performs strictly zero heap allocations on the hot path.
    #[inline]
    pub fn record_sample(&self, current_time_ms: u64) -> Option<u64> {
        self.sample_count.fetch_add(1, Ordering::Relaxed);
        let last = self.last_emit_ms.load(Ordering::Relaxed);
        if current_time_ms.saturating_sub(last) >= self.interval_ms
            && self
                .last_emit_ms
                .compare_exchange_weak(last, current_time_ms, Ordering::SeqCst, Ordering::Relaxed)
                .is_ok()
        {
            let count = self.sample_count.swap(0, Ordering::SeqCst);
            return Some(count);
        }
        None
    }

    /// Current accumulated sample count.
    #[inline]
    pub fn current_count(&self) -> u64 {
        self.sample_count.load(Ordering::Relaxed)
    }
}

/// Sanitize plain text log messages by stripping control characters and normalizing
/// whitespace to prevent log-injection / CRLF header injection attacks.
pub fn sanitize_plain_log_message(msg: &str) -> String {
    let mut cleaned = String::with_capacity(msg.len());
    for c in msg.chars() {
        if c == '\r' || c == '\n' || ((c as u32) < 0x20 && c != '\t') {
            cleaned.push(' ');
        } else {
            cleaned.push(c);
        }
    }
    cleaned
}

/// Format function for `flexi_logger::Logger`.
///
/// Emits compact single-line JSON if structured event metadata is detected (by target or payload),
/// otherwise emits a clean, sanitized line format with timestamp, level, location, and message.
pub fn structured_opt_format(
    w: &mut dyn std::io::Write,
    now: &mut flexi_logger::DeferredNow,
    record: &log::Record,
) -> Result<(), std::io::Error> {
    let args_str = record.args().to_string();

    let is_structured = record.target() == STRUCTURED_LOG_TARGET
        || record.target().starts_with("structured")
        || args_str.starts_with("{\"schema_version\":");

    if is_structured {
        let trimmed = args_str.trim();
        // If JSON contains unescaped newlines or whitespace, compact it safely
        if trimmed.contains('\n') || trimmed.contains('\r') {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) {
                if let Ok(compact) = serde_json::to_string(&val) {
                    return write!(w, "{compact}");
                }
            }
        }
        write!(w, "{trimmed}")
    } else {
        let sanitized = sanitize_plain_log_message(&args_str);
        write!(
            w,
            "[{}] {} [{}:{}] {}",
            now.format(flexi_logger::TS_DASHES_BLANK_COLONS_DOT_BLANK),
            record.level(),
            record.file().unwrap_or("<unnamed>"),
            record.line().unwrap_or(0),
            sanitized
        )
    }
}

/// Flush log buffers to persistent storage.
pub fn flush_log() {
    crate::flush_log();
}
