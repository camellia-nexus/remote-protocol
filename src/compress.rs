use std::{
    cell::RefCell,
    io::{self, Read},
};
use zstd::bulk::Compressor;

pub(crate) const MAX_DECOMPRESSED_SIZE: usize = 256 * 1024 * 1024;

/// Maximum allowed decompressed byte budget for terminal responses (128 KiB).
/// Normal chunks are 4 KiB and replay buffer default is 8 KiB. Capping at 128 KiB
/// prevents compression bomb memory exhaustion while allowing full output chunks.
pub const MAX_TERMINAL_DECOMPRESSED_SIZE: usize = 128 * 1024;

// The library supports regular compression levels from 1 up to ZSTD_maxCLevel(),
// which is currently 22. Levels >= 20
// Default level is ZSTD_CLEVEL_DEFAULT==3.
// value 0 means default, which is controlled by ZSTD_CLEVEL_DEFAULT
thread_local! {
    static COMPRESSOR: RefCell<io::Result<Compressor<'static>>> = RefCell::new(Compressor::new(crate::config::COMPRESS_LEVEL));
}

pub fn compress(data: &[u8]) -> io::Result<Vec<u8>> {
    COMPRESSOR.with(|c| {
        let mut compressor = c.try_borrow_mut().map_err(|_| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "file compressor is already borrowed",
            )
        })?;
        match &mut *compressor {
            Ok(compressor) => compressor.compress(data),
            Err(err) => Err(io::Error::new(err.kind(), err.to_string())),
        }
    })
}

pub fn decompress(data: &[u8]) -> io::Result<Vec<u8>> {
    decompress_with_limit(data, MAX_DECOMPRESSED_SIZE)
}

pub fn decompress_with_limit(data: &[u8], limit: usize) -> io::Result<Vec<u8>> {
    let decoder = zstd::Decoder::new(data)?;
    let mut output = Vec::new();
    decoder
        .take(limit.saturating_add(1) as u64)
        .read_to_end(&mut output)?;
    if output.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "decompressed data exceeds size limit",
        ));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_data_larger_than_limit() {
        let compressed = zstd::encode_all(&vec![0u8; 1025][..], 0).unwrap();
        assert!(decompress_with_limit(&compressed, 1024).is_err());
    }

    #[test]
    fn test_res026_terminal_decompression_limit_and_bomb_rejection() {
        assert_eq!(MAX_TERMINAL_DECOMPRESSED_SIZE, 128 * 1024);

        // Payload within terminal limit
        let payload = vec![b'x'; MAX_TERMINAL_DECOMPRESSED_SIZE];
        let compressed = zstd::encode_all(&payload[..], 0).unwrap();
        let decompressed =
            decompress_with_limit(&compressed, MAX_TERMINAL_DECOMPRESSED_SIZE).unwrap();
        assert_eq!(decompressed.len(), MAX_TERMINAL_DECOMPRESSED_SIZE);

        // Compression bomb: highly compressible 1 MiB payload into tiny compressed frame
        let bomb = vec![0u8; 1024 * 1024]; // 1 MiB zeros
        let compressed_bomb = zstd::encode_all(&bomb[..], 0).unwrap();
        let result = decompress_with_limit(&compressed_bomb, MAX_TERMINAL_DECOMPRESSED_SIZE);
        assert!(
            result.is_err(),
            "Decompression exceeding MAX_TERMINAL_DECOMPRESSED_SIZE must fail closed"
        );
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err
            .to_string()
            .contains("decompressed data exceeds size limit"));
    }

    #[test]
    fn accepts_data_at_limit() {
        let input = vec![0u8; 1024];
        let compressed = zstd::encode_all(&input[..], 0).unwrap();
        assert_eq!(
            decompress_with_limit(&compressed, input.len()).unwrap(),
            input
        );
    }

    #[test]
    fn compressor_contention_must_not_be_reported_as_empty_success() {
        COMPRESSOR.with(|compressor| {
            let _borrow = compressor.borrow_mut();
            assert!(
                compress(b"payload must not disappear").is_err(),
                "compressor contention must not become a successful empty payload"
            );
        });
    }

    #[test]
    fn modern_frame_wire_fixture_and_limits_remain_stable() {
        // Standard single-segment frame, five content bytes, final raw block.
        // A fixed frame proves decoding independently from the current encoder.
        let encoded = b"\x28\xb5\x2f\xfd\x20\x05\x29\x00\x00hello";
        assert_eq!(decompress_with_limit(encoded, 5).unwrap(), b"hello");
        assert!(decompress_with_limit(encoded, 4).is_err());
        for end in 1..encoded.len() {
            assert!(decompress_with_limit(&encoded[..end], 5).is_err());
        }
    }

    #[test]
    fn malformed_legacy_frames_fail_without_returning_partial_output() {
        // Remote has never emitted these pre-modern zstd formats. Legacy
        // decoder support is deliberately not part of the product dependency.
        for magic in [0x24, 0x25, 0x26, 0x27] {
            let corrupt_legacy = [magic, 0xb5, 0x2f, 0xfd, 0, 0];
            assert!(decompress_with_limit(&corrupt_legacy, 1024).is_err());
        }
    }

    #[test]
    fn reused_bulk_compressor_isolates_each_job_on_each_thread() {
        let workers: Vec<_> = (0..8)
            .map(|thread| {
                std::thread::spawn(move || {
                    for job in 0..64 {
                        let content =
                            format!("isolated-compression-test-thread-{thread}-job-{job}")
                                .repeat(job + 1);
                        let compressed = compress(content.as_bytes()).unwrap();
                        assert_eq!(
                            decompress_with_limit(&compressed, content.len()).unwrap(),
                            content.as_bytes()
                        );
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
    }

    #[test]
    fn patched_output_buffer_initializes_the_gap_before_publishing_length() {
        // RUSTSEC-2026-0397: exercise the reviewed fixed safe-API contract. Do
        // not run this memory read against the old unsound implementation.
        let mut bytes = Vec::with_capacity(32);
        bytes.extend_from_slice(b"kept");
        {
            let output = zstd::zstd_safe::OutBuffer::around_pos(&mut bytes, 12);
            assert_eq!(output.pos(), 12);
        }
        assert_eq!(&bytes[..4], b"kept");
        assert_eq!(&bytes[4..], &[0; 8]);
    }
}
