# Dynamic boundary testing

The normal Required suite discovers `tests/dynamic_input_contract.rs`. It uses
fixed seeds and bounded inputs to exercise protobuf messages, framing,
compression, length limits, and fragmented delivery on every supported Rust
test platform.

The scheduled `Dynamic Boundaries` workflow adds Linux x86_64 checks that are
too expensive for each pull request:

- `cargo-fuzz 0.13.2` with ASan/libFuzzer on the production frame and message
  parsers for five minutes;
- Miri with strict provenance on the aligned-buffer ownership tests.

Both jobs use `nightly-2026-08-15`; fuzz dependencies have an independent lock
file. Fuzz input is limited to 64 KiB and 32 decoded frames. Committed seeds are
copied to a private runner-temporary corpus so fuzzing cannot change the source
checkout.

Only a crashing input is uploaded, for seven days. The target reads no
environment variables, credentials, raw logs, addresses, or user data, and the
artifact is bounded to 64 KiB. ASan and Miri here cover Linux x86_64 only;
platform FFI and Windows/macOS behavior remain the responsibility of their
platform suites.
