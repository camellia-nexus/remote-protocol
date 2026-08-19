#![no_main]

use camellia_remote_protocol::{
    bytes::BytesMut,
    bytes_codec::BytesCodec,
    compress::{compress, decompress},
    protobuf::Message,
    rendezvous_proto::RendezvousMessage,
    tokio_util::codec::Decoder,
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT: usize = 64 * 1024;
const MAX_FRAMES: usize = 32;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }

    let _ = RendezvousMessage::parse_from_bytes(data);
    let _ = decompress(data);

    let compressed = compress(data);
    if let Ok(compressed) = compressed {
        if !compressed.is_empty() {
            assert_eq!(decompress(&compressed).unwrap(), data);
        }
    }

    let mut codec = BytesCodec::new();
    codec.set_max_packet_length(MAX_INPUT);
    let mut input = BytesMut::from(data);
    for _ in 0..MAX_FRAMES {
        match codec.decode(&mut input) {
            Ok(Some(frame)) => {
                let _ = RendezvousMessage::parse_from_bytes(&frame);
            }
            Ok(None) | Err(_) => break,
        }
    }
});
