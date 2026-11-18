# Camellia performance evidence contract

`performance_contract.py` is the shared, dependency-free collector and gate for Remote repositories. It separates correctness from noisy timing claims:

- a scenario command writes exactly one `camellia-performance-observation-v1` document to the path in `CAMELLIA_PERFORMANCE_OBSERVATION_FILE`;
- `collect` discards explicit warmups, runs 5–60 bounded samples, fingerprints the runner class/toolchain/OS/architecture/CPU count/memory plus hashed CPU-model and kernel/collector environment material, and creates a non-overwriting `camellia-performance-evidence-v1` file;
- `collect-pair` runs control and candidate samples in alternating order on one runner identity, so first-run cache and thermal drift do not consistently favor one revision; commands are direct argv separated by `:::` and never pass through a shell;
- base and candidate must be collected in the same job and have byte-equivalent runner identity;
- `compare` rejects different scenarios, metric sets, units, directions, runners, and insufficient samples; excessive median absolute deviation writes an explicit `inconclusive` comparison and exits 4, deterministic budget failures write `fail` and exit 3, and neither can be treated as a pass;
- comparison output authenticates both canonical input documents by SHA-256 and is also created without overwrite.

PR smoke scenarios use generous budgets to stop only obvious regressions. Scheduled and release scenarios use fixed runner classes, larger sample sets, and separate policy files. A shared GitHub runner label alone is not proof of comparability: base and candidate use one fingerprint and paired, alternating samples on the same allocated machine. Excessive noise is an artifact-backed inconclusive failure rather than a pass. Ten minutes is the maximum final soak duration; longer duration is not a substitute for scenario coverage.

Main pushes and the weekly workflow run 15 paired samples with five seconds of bounded work per observation. A release dispatch requires an explicit exact control SHA and runs five A/B pairs with 60 seconds per observation and no extra warmup: the measured control-plus-candidate workload is therefore exactly ten minutes. Every scenario rejects a requested per-observation duration outside canonical `1..60`; build/setup time is not mislabeled as soak time. PR, scheduled, and release policies are distinct committed files, with progressively tighter noise and regression budgets.

The collector suppresses scenario stdout/stderr so secrets and unbounded logs cannot enter evidence. On timeout it terminates the POSIX process group (or the direct process on other platforms) and applies a bounded kill fallback. Scenario observations and policies must contain metrics only, never hostnames, usernames, paths, IP addresses, tokens, raw hardware serials, or workload payloads.

Use `validate-observation FILE --scenario NAME` for a single scenario emission, `validate-policy FILE` for a budget, and `validate FILE` only for a complete evidence document. The distinct commands prevent a valid observation from being mistaken for a malformed evidence bundle during local harness development.

Every comparison is provenance evidence, not a portable absolute benchmark: it binds exact control/candidate revisions, the committed policy, hashes of both evidence inputs, and one authenticated runner fingerprint. Consumer repositories pin this contract by an exact submodule commit or a single-line lock file, and must expose their real codec/database/toolchain version in the runner toolchain token. Reverting the collector or a performance workflow never turns missing evidence into a pass; affected releases must run the same versioned scenario and ten-minute maximum manually until an equivalent fail-closed gate is restored.
