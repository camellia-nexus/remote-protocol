from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/dynamic-boundaries.yml"
FUZZ_MANIFEST = ROOT / "fuzz/Cargo.toml"
FUZZ_LOCK = ROOT / "fuzz/Cargo.lock"
FUZZ_TARGET = ROOT / "fuzz/fuzz_targets/frame_and_messages.rs"
DOCUMENTATION = ROOT / "docs/dynamic-boundary-testing.md"


def require(text, markers, description):
    missing = [marker for marker in markers if marker not in text]
    if missing:
        raise SystemExit(f"{description} is incomplete: {missing}")


workflow = WORKFLOW.read_text(encoding="utf-8")
require(
    workflow,
    (
        "NIGHTLY_TOOLCHAIN: nightly-2026-08-15",
        "cargo install cargo-fuzz --version 0.13.2 --locked",
        "fetch --locked --manifest-path fuzz/Cargo.toml",
        '"$RUNNER_TEMP/protocol-fuzz-corpus"',
        'cp -- fuzz/corpus/frame_and_messages/* "$RUNNER_TEMP/protocol-fuzz-corpus/"',
        "-max_len=65536",
        "-max_total_time=300",
        "-rss_limit_mb=2048",
        "-runs=1000000",
        "-seed=20260819",
        "-timeout=5",
        "retention-days: 7",
        "miri test --lib mem::tests -- --test-threads=1",
        "MIRIFLAGS: -Zmiri-strict-provenance",
    ),
    "Protocol dynamic boundary workflow",
)
for forbidden in ("continue-on-error:", "|| true", "pull_request_target:"):
    if forbidden in workflow:
        raise SystemExit(f"Protocol dynamic boundary workflow contains forbidden marker: {forbidden}")
if workflow.count("timeout-minutes: 10") != 2 or workflow.count("timeout-minutes: 15") != 1:
    raise SystemExit("Protocol dynamic boundary job timeouts drifted")

require(FUZZ_MANIFEST.read_text(encoding="utf-8"), ('libfuzzer-sys = "0.4"',), "Protocol fuzz manifest")
require(FUZZ_LOCK.read_text(encoding="utf-8"), ('name = "libfuzzer-sys"',), "Protocol fuzz lock")
require(
    FUZZ_TARGET.read_text(encoding="utf-8"),
    (
        "const MAX_INPUT: usize = 64 * 1024;",
        "const MAX_FRAMES: usize = 32;",
        "let _ = decompress(data);",
        "assert_eq!(decompress(&compressed).unwrap(), data);",
    ),
    "Protocol fuzz target",
)
require(
    DOCUMENTATION.read_text(encoding="utf-8"),
    (
        "normal Required suite",
        "nightly-2026-08-15",
        "64 KiB",
        "seven days",
        "reads no",
        "Linux x86_64 only",
    ),
    "Protocol dynamic boundary documentation",
)
print("Protocol dynamic boundary policy passed")
