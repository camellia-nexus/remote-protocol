//! Contract test suite for LOG-014 Phase 1: Protocol Wire Schema & Structured Logging.
//!
//! Validates:
//! 1. Protobuf Wire Schema: CorrelationContext attached and serialized across all 10 messages.
//! 2. Round-trip validation: valid trace/attempt IDs preserved; invalid/overlong/malicious IDs sanitized.
//! 3. StructuredEvent JSON compliance: single-line compact JSON, required fields, omitted optional fields.
//! 4. PII pseudonymization & masking: peer ID SHA-256 prefix and IP/socket masking.
//! 5. Logger formatting: structured_opt_format handling of structured JSON and sanitized plain logs.
//! 6. Zero-allocation invariant on hot paths verified via counting allocator.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use camellia_remote_protocol::{
    generate_attempt_id, generate_trace_id, hash_peer_id, is_valid_attempt_id, is_valid_trace_id,
    mask_ip, mask_socket_addr,
    message_proto::{LoginRequest, LoginResponse},
    observability::{sanitize_plain_log_message, structured_opt_format},
    protobuf::Message,
    rendezvous_proto::{
        CorrelationContext, FetchLocalAddr, LocalAddr, PunchHole, PunchHoleRequest,
        PunchHoleResponse, PunchHoleSent, RelayResponse, RequestRelay,
    },
    validate_attempt_id, validate_trace_id, CorrelationContextExt, HotPathSampler, StructuredEvent,
};

// Thread-local tracking allocator to strictly enforce zero-allocation invariant on hot paths
// even in multi-threaded test runner environments.
struct TrackingAlloc;

thread_local! {
    static TRACK_THIS_THREAD: Cell<bool> = const { Cell::new(false) };
    static THREAD_ALLOCS: Cell<usize> = const { Cell::new(0) };
}

unsafe impl GlobalAlloc for TrackingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        TRACK_THIS_THREAD.with(|tracking| {
            if tracking.get() {
                THREAD_ALLOCS.with(|count| {
                    count.set(count.get() + 1);
                });
            }
        });
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static GLOBAL: TrackingAlloc = TrackingAlloc;

// ============================================================================
// 1. Protobuf Wire Schema Tests
// ============================================================================

#[test]
fn test_correlation_context_serialization_rendezvous_messages() {
    let mut ctx = CorrelationContext::new();
    ctx.trace_id = "4bf92f3577b34da6a3ce929d0e0e4736".to_string();
    ctx.attempt_id = "00f067aa0ba902b7".to_string();
    ctx.session_id = 42;

    // 1. PunchHoleRequest
    let mut req = PunchHoleRequest::new();
    req.id = "peer-alpha".to_string();
    req.correlation = ::protobuf::MessageField::some(ctx.clone());
    let bytes = req
        .write_to_bytes()
        .expect("PunchHoleRequest serialization");
    let decoded = PunchHoleRequest::parse_from_bytes(&bytes).expect("deserialization");
    assert!(decoded.correlation.is_some());
    let c = decoded.correlation.as_ref().unwrap();
    assert_eq!(c.trace_id, ctx.trace_id);
    assert_eq!(c.attempt_id, ctx.attempt_id);
    assert_eq!(c.session_id, 42);

    // 2. PunchHole
    let mut ph = PunchHole::new();
    ph.relay_server = "relay.example.com".to_string();
    ph.correlation = ::protobuf::MessageField::some(ctx.clone());
    let bytes = ph.write_to_bytes().expect("PunchHole serialization");
    let decoded = PunchHole::parse_from_bytes(&bytes).expect("deserialization");
    assert_eq!(decoded.correlation.as_ref().unwrap().trace_id, ctx.trace_id);

    // 3. PunchHoleSent
    let mut ps = PunchHoleSent::new();
    ps.id = "peer-alpha".to_string();
    ps.correlation = ::protobuf::MessageField::some(ctx.clone());
    let bytes = ps.write_to_bytes().expect("PunchHoleSent serialization");
    let decoded = PunchHoleSent::parse_from_bytes(&bytes).expect("deserialization");
    assert_eq!(decoded.correlation.as_ref().unwrap().trace_id, ctx.trace_id);

    // 4. PunchHoleResponse
    let mut pr = PunchHoleResponse::new();
    pr.relay_server = "relay.example.com".to_string();
    pr.correlation = ::protobuf::MessageField::some(ctx.clone());
    let bytes = pr
        .write_to_bytes()
        .expect("PunchHoleResponse serialization");
    let decoded = PunchHoleResponse::parse_from_bytes(&bytes).expect("deserialization");
    assert_eq!(
        decoded.correlation.as_ref().unwrap().attempt_id,
        ctx.attempt_id
    );

    // 5. RequestRelay
    let mut rr = RequestRelay::new();
    rr.id = "peer-alpha".to_string();
    rr.correlation = ::protobuf::MessageField::some(ctx.clone());
    let bytes = rr.write_to_bytes().expect("RequestRelay serialization");
    let decoded = RequestRelay::parse_from_bytes(&bytes).expect("deserialization");
    assert_eq!(decoded.correlation.as_ref().unwrap().session_id, 42);

    // 6. RelayResponse
    let mut resp = RelayResponse::new();
    resp.relay_server = "relay.example.com".to_string();
    resp.correlation = ::protobuf::MessageField::some(ctx.clone());
    let bytes = resp.write_to_bytes().expect("RelayResponse serialization");
    let decoded = RelayResponse::parse_from_bytes(&bytes).expect("deserialization");
    assert_eq!(decoded.correlation.as_ref().unwrap().trace_id, ctx.trace_id);

    // 7. FetchLocalAddr
    let mut fla = FetchLocalAddr::new();
    fla.relay_server = "relay.example.com".to_string();
    fla.correlation = ::protobuf::MessageField::some(ctx.clone());
    let bytes = fla.write_to_bytes().expect("FetchLocalAddr serialization");
    let decoded = FetchLocalAddr::parse_from_bytes(&bytes).expect("deserialization");
    assert_eq!(
        decoded.correlation.as_ref().unwrap().attempt_id,
        ctx.attempt_id
    );

    // 8. LocalAddr
    let mut la = LocalAddr::new();
    la.id = "peer-alpha".to_string();
    la.correlation = ::protobuf::MessageField::some(ctx.clone());
    let bytes = la.write_to_bytes().expect("LocalAddr serialization");
    let decoded = LocalAddr::parse_from_bytes(&bytes).expect("deserialization");
    assert_eq!(decoded.correlation.as_ref().unwrap().trace_id, ctx.trace_id);
}

#[test]
fn test_correlation_context_serialization_message_proto() {
    let mut ctx = CorrelationContext::new();
    ctx.trace_id = "0123456789abcdef0123456789abcdef".to_string();
    ctx.attempt_id = "fedcba9876543210".to_string();
    ctx.session_id = 999;

    // 9. LoginRequest
    let mut lr = LoginRequest::new();
    lr.username = "test-user".to_string();
    lr.my_id = "peer-1".to_string();
    lr.correlation = ::protobuf::MessageField::some(ctx.clone());
    let bytes = lr.write_to_bytes().expect("LoginRequest serialization");
    let decoded = LoginRequest::parse_from_bytes(&bytes).expect("LoginRequest deserialization");
    assert!(decoded.correlation.is_some());
    let c = decoded.correlation.as_ref().unwrap();
    assert_eq!(c.trace_id, ctx.trace_id);
    assert_eq!(c.attempt_id, ctx.attempt_id);
    assert_eq!(c.session_id, 999);

    // 10. LoginResponse
    let mut lresp = LoginResponse::new();
    lresp.target_id = "peer-2".to_string();
    lresp.correlation = ::protobuf::MessageField::some(ctx.clone());
    let bytes = lresp.write_to_bytes().expect("LoginResponse serialization");
    let decoded = LoginResponse::parse_from_bytes(&bytes).expect("LoginResponse deserialization");
    assert!(decoded.correlation.is_some());
    let c = decoded.correlation.as_ref().unwrap();
    assert_eq!(c.trace_id, ctx.trace_id);
    assert_eq!(c.attempt_id, ctx.attempt_id);
    assert_eq!(c.session_id, 999);
}

// ============================================================================
// 2. ID Validation, Sanitization, and Fail-Closed Round-Trip Tests
// ============================================================================

#[test]
fn test_valid_ids_preserved_and_normalized() {
    // Test fresh generation helpers
    let fresh_trace = generate_trace_id();
    assert_eq!(fresh_trace.len(), 32);
    assert!(is_valid_trace_id(&fresh_trace));

    let fresh_attempt = generate_attempt_id();
    assert_eq!(fresh_attempt.len(), 16);
    assert!(is_valid_attempt_id(&fresh_attempt));
    let valid_trace = "4bf92f3577b34da6a3ce929d0e0e4736";
    assert!(is_valid_trace_id(valid_trace));
    assert_eq!(validate_trace_id(valid_trace), valid_trace);

    // Valid uppercase hex normalized to lowercase
    let upper_trace = "4BF92F3577B34DA6A3CE929D0E0E4736";
    assert!(is_valid_trace_id(upper_trace));
    assert_eq!(validate_trace_id(upper_trace), valid_trace);

    // Valid 16-hex lower and upper bounds for trace ID (16 to 64 hex)
    let min_trace = "0123456789abcdef";
    assert_eq!(validate_trace_id(min_trace), min_trace);
    let max_trace = "a".repeat(64);
    assert_eq!(validate_trace_id(&max_trace), max_trace);

    // Valid 16-hex attempt ID
    let valid_attempt = "00f067aa0ba902b7";
    assert!(is_valid_attempt_id(valid_attempt));
    assert_eq!(validate_attempt_id(valid_attempt), valid_attempt);

    // Valid attempt ID bounds (8 to 32 hex)
    let min_attempt = "12345678";
    assert_eq!(validate_attempt_id(min_attempt), min_attempt);
    let max_attempt = "f".repeat(32);
    assert_eq!(validate_attempt_id(&max_attempt), max_attempt);
}

#[test]
fn test_invalid_trace_ids_fail_closed_to_fresh_uuid() {
    let overlong = "a".repeat(65);
    let test_cases = vec![
        "",                                     // empty
        "   ",                                  // whitespace
        "123",                                  // too short (<16)
        "1234567890abcdefg",                    // invalid hex char 'g'
        overlong.as_str(),                      // too long (>64)
        "4bf92f3577b34da6\r\nFAKE LOG INJECT",  // control chars
        "4bf92f35-77b3-4da6-a3ce-929d0e0e4736", // hyphens are rejected
    ];

    for invalid in test_cases {
        let sanitized = validate_trace_id(invalid);
        assert_ne!(sanitized, invalid);
        assert_eq!(sanitized.len(), 32);
        assert!(
            is_valid_trace_id(&sanitized),
            "Sanitized trace ID must be valid: {sanitized}"
        );
    }
}

#[test]
fn test_invalid_attempt_ids_fail_closed_to_fresh_id() {
    let overlong = "f".repeat(33);
    let test_cases = vec![
        "",                      // empty
        "   ",                   // whitespace
        "1234567",               // too short (<8)
        "12345678z",             // invalid char 'z'
        overlong.as_str(),       // too long (>32)
        "00f067aa\r\nINJECTION", // control chars
    ];

    for invalid in test_cases {
        let sanitized = validate_attempt_id(invalid);
        assert_ne!(sanitized, invalid);
        assert_eq!(sanitized.len(), 16);
        assert!(
            is_valid_attempt_id(&sanitized),
            "Sanitized attempt ID must be valid: {sanitized}"
        );
    }
}

#[test]
fn test_correlation_context_ext_sanitization() {
    let mut ctx = CorrelationContext::new();
    ctx.trace_id = "malicious\r\ninjection".to_string();
    ctx.attempt_id = "short".to_string();
    ctx.sanitize_in_place();

    assert_eq!(ctx.trace_id.len(), 32);
    assert!(is_valid_trace_id(&ctx.trace_id));
    assert_eq!(ctx.attempt_id.len(), 16);
    assert!(is_valid_attempt_id(&ctx.attempt_id));

    let random_ctx = CorrelationContext::new_random();
    assert_eq!(random_ctx.trace_id.len(), 32);
    assert_eq!(random_ctx.attempt_id.len(), 16);
    assert_eq!(random_ctx.session_id, 0);
}

// ============================================================================
// 3. StructuredEvent JSON Output Compliance & Round-Trip Tests
// ============================================================================

#[test]
fn test_structured_event_json_compliance_single_line() {
    let evt = StructuredEvent::new(
        "remote-server",
        "INFO",
        "PEER_REGISTER",
        "4bf92f3577b34da6a3ce929d0e0e4736",
        "00f067aa0ba902b7",
    )
    .with_session_id(101)
    .with_stage("rendezvous")
    .with_result("ok")
    .with_peer_id("987654321")
    .with_endpoint(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        21116,
    ))
    .with_duration_ms(25)
    .with_error_code("NONE")
    .with_attribute("transport", "tcp")
    .with_attribute("retry_count", 0);

    let json_str = evt.to_json().expect("to_json serialization");

    // Single-line compliance
    assert!(!json_str.contains('\n'), "JSON must not contain newlines");
    assert!(
        !json_str.contains('\r'),
        "JSON must not contain carriage returns"
    );

    // Required fields check
    assert!(json_str.contains("\"schema_version\":\"1.0.0\""));
    assert!(json_str.contains("\"service\":\"remote-server\""));
    assert!(json_str.contains("\"level\":\"INFO\""));
    assert!(json_str.contains("\"event\":\"PEER_REGISTER\""));
    assert!(json_str.contains("\"trace_id\":\"4bf92f3577b34da6a3ce929d0e0e4736\""));
    assert!(json_str.contains("\"attempt_id\":\"00f067aa0ba902b7\""));
    assert!(json_str.contains("\"session_id\":101"));
    assert!(json_str.contains("\"stage\":\"rendezvous\""));
    assert!(json_str.contains("\"result\":\"ok\""));
    assert!(json_str.contains("\"endpoint_masked\":\"192.168.1.***:21116\""));
    assert!(json_str.contains("\"duration_ms\":25"));
    assert!(json_str.contains("\"error_code\":\"NONE\""));
    assert!(json_str.contains("\"transport\":\"tcp\""));

    // Raw peer ID must NOT appear in output; only peer_id_hash
    assert!(!json_str.contains("987654321"));
    assert!(json_str.contains(&format!(
        "\"peer_id_hash\":\"{}\"",
        hash_peer_id("987654321")
    )));

    // Full round-trip deserialization
    let decoded: StructuredEvent =
        serde_json::from_str(&json_str).expect("deserialization from JSON");
    assert_eq!(evt, decoded);
}

#[test]
fn test_structured_event_omits_none_fields() {
    let evt = StructuredEvent::new(
        "remote-protocol",
        "WARN",
        "PUNCH_HOLE_TIMEOUT",
        "4bf92f3577b34da6a3ce929d0e0e4736",
        "00f067aa0ba902b7",
    );

    let json_str = evt.to_json().expect("to_json");

    assert!(!json_str.contains("session_id"));
    assert!(!json_str.contains("stage"));
    assert!(!json_str.contains("result"));
    assert!(!json_str.contains("peer_id_hash"));
    assert!(!json_str.contains("endpoint_masked"));
    assert!(!json_str.contains("duration_ms"));
    assert!(!json_str.contains("error_code"));
    assert!(!json_str.contains("attributes"));

    // Deserialization still works with empty optional fields
    let decoded: StructuredEvent = serde_json::from_str(&json_str).expect("from_str");
    assert_eq!(evt, decoded);
    assert_eq!(decoded.session_id, None);
    assert_eq!(decoded.stage, None);
    assert!(decoded.attributes.is_empty());
}

#[test]
fn test_correlation_context_and_structured_event_interop() {
    let ctx = CorrelationContext::new_validated(
        "4bf92f3577b34da6a3ce929d0e0e4736",
        "00f067aa0ba902b7",
        Some(77),
    );

    let evt = StructuredEvent::from_correlation("remote-client", "INFO", "LOGIN_REQUEST", &ctx);
    assert_eq!(evt.trace_id, ctx.trace_id);
    assert_eq!(evt.attempt_id, ctx.attempt_id);
    assert_eq!(evt.session_id, Some(77));

    let back_ctx = evt.to_correlation_context();
    assert_eq!(back_ctx.trace_id, ctx.trace_id);
    assert_eq!(back_ctx.attempt_id, ctx.attempt_id);
    assert_eq!(back_ctx.session_id, 77);
}

// ============================================================================
// 4. PII Masking and Pseudonymization Tests
// ============================================================================

#[test]
fn test_hash_peer_id_pseudonymization() {
    let peer1 = "123456789";
    let peer2 = "123456780";
    let hash1 = hash_peer_id(peer1);
    let hash2 = hash_peer_id(peer2);

    assert_eq!(hash1.len(), 16);
    assert_eq!(hash2.len(), 16);
    assert_ne!(hash1, hash2);
    assert!(hash1.chars().all(|c| c.is_ascii_hexdigit()));

    // Deterministic hashing
    assert_eq!(hash_peer_id(peer1), hash1);
}

#[test]
fn test_ip_and_socket_masking() {
    // IPv4
    let ipv4 = IpAddr::V4(Ipv4Addr::new(10, 0, 15, 204));
    assert_eq!(mask_ip(ipv4), "10.0.15.***");

    // IPv6
    let ipv6 = IpAddr::V6(Ipv6Addr::new(
        0x2001, 0x0db8, 0x85a3, 0, 0, 0x8a2e, 0x0370, 0x7334,
    ));
    assert_eq!(mask_ip(ipv6), "2001:db8:85a3:***:***");

    // SocketAddr
    let socket = SocketAddr::new(ipv4, 21118);
    assert_eq!(mask_socket_addr(socket), "10.0.15.***:21118");
}

// ============================================================================
// 5. Logger Format & Injection Prevention Tests
// ============================================================================

#[test]
fn test_plain_log_sanitization_prevents_injection() {
    let dirty = "User logged in\r\n[2026-11-16] ERROR [inject.rs:1] FAKE ERROR";
    let sanitized = sanitize_plain_log_message(dirty);
    assert!(!sanitized.contains('\r'));
    assert!(!sanitized.contains('\n'));
    assert_eq!(
        sanitized,
        "User logged in  [2026-11-16] ERROR [inject.rs:1] FAKE ERROR"
    );
}

#[test]
fn test_structured_opt_format_routing() {
    // 1. Structured event formatting
    let evt = StructuredEvent::new(
        "remote-protocol",
        "INFO",
        "TEST_EVENT",
        "4bf92f3577b34da6a3ce929d0e0e4736",
        "00f067aa0ba902b7",
    );
    let json_str = evt.to_json().unwrap();

    let structured_args = format_args!("{json_str}");
    let record = log::Record::builder()
        .args(structured_args)
        .level(log::Level::Info)
        .target("structured_event")
        .build();

    let mut buf = Vec::new();
    let mut now = flexi_logger::DeferredNow::new();
    structured_opt_format(&mut buf, &mut now, &record).expect("format structured");
    let out = String::from_utf8(buf).expect("utf8");

    // Output must be compact single line JSON directly
    assert!(out.starts_with("{\"schema_version\":\"1.0.0\""));
    assert!(!out.contains('\n'));

    // 2. Plain unstructured log formatting
    let plain_args = format_args!("Standard debug statement");
    let plain_record = log::Record::builder()
        .args(plain_args)
        .level(log::Level::Debug)
        .target("my_module")
        .file(Some("src/test.rs"))
        .line(Some(42))
        .build();

    let mut buf2 = Vec::new();
    structured_opt_format(&mut buf2, &mut now, &plain_record).expect("format plain");
    let out2 = String::from_utf8(buf2).expect("utf8");

    assert!(out2.contains("DEBUG [src/test.rs:42] Standard debug statement"));
}

// ============================================================================
// 6. Zero-Allocation Invariant on Hot Paths (LOG-014 Specification)
// ============================================================================

#[test]
fn test_hot_path_zero_allocation_invariant() {
    let sampler = HotPathSampler::new(1000);

    // Warm up sampler and TLS
    let _ = sampler.record_sample(0);
    TRACK_THIS_THREAD.with(|t| t.set(false));
    THREAD_ALLOCS.with(|c| c.set(0));

    // Enable thread-local allocation tracking
    TRACK_THIS_THREAD.with(|t| t.set(true));

    // Simulate 10,000 video frame ticks (60fps = ~16ms per tick)
    let mut time_ms = 16;
    let mut emit_count = 0;
    for _ in 0..10_000 {
        if let Some(_samples) = sampler.record_sample(time_ms) {
            emit_count += 1;
        }
        time_ms += 16;
    }

    // Disable tracking
    TRACK_THIS_THREAD.with(|t| t.set(false));
    let hot_path_allocs = THREAD_ALLOCS.with(|c| c.get());

    assert_eq!(
        hot_path_allocs, 0,
        "HotPathSampler must have strictly zero heap allocations during hot-path execution!"
    );
    assert!(
        emit_count > 0,
        "Sampler must emit aggregated counts over intervals"
    );
}
