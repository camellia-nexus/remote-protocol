//! Deterministic mutation coverage for protocol boundaries.
//!
//! This is intentionally dependency-free so the required job can run on every
//! supported Rust toolchain.  The scheduled workflow may increase the fixed
//! corpus, but never accepts an unbounded input, iteration count, or runtime.

use camellia_remote_protocol::{
    bytes::BytesMut,
    bytes_codec::BytesCodec,
    compress::{compress, decompress},
    protobuf::Message,
    rendezvous_proto::RendezvousMessage,
};
use std::{panic::AssertUnwindSafe, time::Instant};
use tokio_util::codec::{Decoder, Encoder};

const ITERATIONS: usize = 4_096;
const MAX_INPUT: usize = 4 * 1024;
const MAX_PACKET: usize = 64 * 1024;
const MAX_RUNTIME_MS: u128 = 10_000;

fn mutate(seed: u64, index: usize) -> Vec<u8> {
    let mut state = seed
        .wrapping_add(index as u64)
        .wrapping_mul(0x9e37_79b9_7f4a_7c15);
    let len = (state as usize % MAX_INPUT).min(MAX_INPUT);
    let mut output = Vec::with_capacity(len);
    for _ in 0..len {
        state ^= state << 7;
        state ^= state >> 9;
        state = state.wrapping_mul(0x2545_f491_4f6c_dd1d);
        output.push((state >> 24) as u8);
    }
    output
}

#[test]
fn bounded_mutations_never_panic_or_exceed_budget() {
    let started = Instant::now();
    for index in 0..ITERATIONS {
        let input = mutate(0x6361_6d65_6c6c_6961, index);
        let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
            let _ = RendezvousMessage::parse_from_bytes(&input);

            let mut codec = BytesCodec::new();
            codec.set_max_packet_length(MAX_PACKET);
            let mut frame = BytesMut::from(input.as_slice());
            let _ = codec.decode(&mut frame);

            // Compression must either round-trip bounded data or fail closed.
            let _ = decompress(&input);
            if let Ok(compressed) = compress(&input) {
                if !compressed.is_empty() {
                    assert_eq!(decompress(&compressed).unwrap(), input);
                }
            }
        }));
        assert!(result.is_ok(), "mutation {index} panicked");
    }
    assert!(
        started.elapsed().as_millis() <= MAX_RUNTIME_MS,
        "deterministic mutation budget exceeded: {} ms",
        started.elapsed().as_millis()
    );
}

#[test]
fn codec_roundtrip_holds_at_frame_boundaries() {
    for length in [0, 1, 0x3f, 0x40, 0x3fff, 0x4000, 0x3fffff] {
        let payload = vec![length as u8; length];
        let mut codec = BytesCodec::new();
        let mut encoded = BytesMut::new();
        codec
            .encode(payload.clone().into(), &mut encoded)
            .expect("boundary payload must encode");
        let decoded = codec
            .decode(&mut encoded)
            .expect("boundary payload must decode")
            .expect("complete frame");
        assert_eq!(decoded.as_ref(), payload.as_slice());
    }
}

#[test]
fn codec_roundtrip_holds_across_deterministic_fragmentation() {
    for index in 0..512 {
        let payload = mutate(0x6672_6167_6d65_6e74, index);
        let mut encoder = BytesCodec::new();
        let mut encoded = BytesMut::new();
        encoder
            .encode(payload.clone().into(), &mut encoded)
            .expect("bounded payload must encode");

        let chunk_size = index % 31 + 1;
        let mut decoder = BytesCodec::new();
        let mut received = BytesMut::new();
        let mut decoded = None;
        for chunk in encoded.chunks(chunk_size) {
            received.extend_from_slice(chunk);
            if let Some(frame) = decoder.decode(&mut received).expect("fragment must decode") {
                assert!(
                    decoded.replace(frame).is_none(),
                    "one input produced multiple frames"
                );
            }
        }
        assert_eq!(
            decoded.expect("complete fragmented frame").as_ref(),
            payload
        );
        assert!(received.is_empty());
    }
}

#[test]
fn codec_rejects_declared_length_above_policy_before_payload_arrives() {
    let mut codec = BytesCodec::new();
    codec.set_max_packet_length(MAX_PACKET);
    let mut header = BytesMut::new();
    header.extend_from_slice(&(((MAX_PACKET + 1) as u32) << 2 | 0x03).to_le_bytes());
    let error = codec
        .decode(&mut header)
        .expect_err("oversized frame must be rejected");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert_eq!(
        header.len(),
        4,
        "rejected input must not advance parser state"
    );
}

#[test]
fn protobuf_seed_corpus_accepts_valid_roundtrips() {
    let message = RendezvousMessage::new();
    let encoded = message.write_to_bytes().expect("empty message encodes");
    assert!(RendezvousMessage::parse_from_bytes(&encoded).is_ok());
}
