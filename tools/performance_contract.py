#!/usr/bin/env python3
"""Collect and compare bounded Camellia performance evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import pathlib
import platform
import re
import signal
import statistics
import subprocess
import tempfile
from typing import Any

EVIDENCE_SCHEMA = "camellia-performance-evidence-v1"
OBSERVATION_SCHEMA = "camellia-performance-observation-v1"
POLICY_SCHEMA = "camellia-performance-policy-v1"
COMPARISON_SCHEMA = "camellia-performance-comparison-v1"
MAX_DOCUMENT_BYTES = 1_048_576
MAX_METRICS = 64
MIN_SAMPLES = 5
MAX_SAMPLES = 60
REPOSITORIES = {
    "remote-client",
    "remote-management-server",
    "remote-protocol",
    "remote-server",
}
TIERS = {"pr-smoke", "scheduled", "release"}
UNITS = {
    "bytes",
    "bytes_per_second",
    "count",
    "db",
    "ms",
    "ns",
    "ratio",
    "requests_per_second",
    "s",
    "us",
}
TOKEN_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
REVISION_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


class ContractError(ValueError):
    """The evidence is malformed, incomparable, noisy, or over budget."""


def _reject_constant(value: str) -> None:
    raise ContractError(f"non-finite JSON number is forbidden: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ContractError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def load_document(path: pathlib.Path) -> Any:
    if path.is_symlink() or not path.is_file():
        raise ContractError(f"document is missing, not regular, or symlinked: {path}")
    size = path.stat().st_size
    if size <= 0 or size > MAX_DOCUMENT_BYTES:
        raise ContractError(
            f"document size is outside 1..{MAX_DOCUMENT_BYTES} bytes: {path}"
        )
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except UnicodeError as exc:
        raise ContractError(f"document is not UTF-8: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ContractError(f"document is not strict JSON: {path}") from exc


def _exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError(f"{label} must be an object")
    observed = set(value)
    if observed != expected:
        raise ContractError(
            f"{label} keys differ: missing={sorted(expected - observed)} extra={sorted(observed - expected)}"
        )
    return value


def _token(value: Any, label: str) -> str:
    if not isinstance(value, str) or not TOKEN_RE.fullmatch(value):
        raise ContractError(f"{label} is not a canonical token")
    return value


def _number(
    value: Any, label: str, *, minimum: float = 0.0, maximum: float = 1e18
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ContractError(f"{label} must be numeric")
    result = float(value)
    if not math.isfinite(result) or result < minimum or result > maximum:
        raise ContractError(f"{label} is non-finite or outside its bound")
    return result


def _positive_integer(value: Any, label: str, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 1
        or value > maximum
    ):
        raise ContractError(f"{label} must be an integer in 1..{maximum}")
    return value


def validate_runner(value: Any) -> dict[str, Any]:
    runner = _exact_keys(
        value,
        {
            "arch",
            "class",
            "cpu_model_digest",
            "cpu_logical",
            "environment_digest",
            "fingerprint",
            "memory_bytes",
            "os",
            "toolchain",
        },
        "runner",
    )
    _token(runner["class"], "runner.class")
    _token(runner["os"], "runner.os")
    _token(runner["arch"], "runner.arch")
    for name in ("cpu_model_digest", "environment_digest"):
        if not isinstance(runner[name], str) or not DIGEST_RE.fullmatch(runner[name]):
            raise ContractError(f"runner.{name} must be a SHA-256 digest")
    _positive_integer(runner["cpu_logical"], "runner.cpu_logical", 65_536)
    _positive_integer(runner["memory_bytes"], "runner.memory_bytes", 1 << 60)
    _token(runner["toolchain"], "runner.toolchain")
    if not isinstance(runner["fingerprint"], str) or not DIGEST_RE.fullmatch(
        runner["fingerprint"]
    ):
        raise ContractError("runner.fingerprint must be a SHA-256 digest")
    material = {key: runner[key] for key in runner if key != "fingerprint"}
    if runner["fingerprint"] != digest_document(material):
        raise ContractError(
            "runner.fingerprint does not authenticate the runner fields"
        )
    return runner


def validate_observation(value: Any, expected_scenario: str) -> dict[str, Any]:
    observation = _exact_keys(value, {"metrics", "scenario", "schema"}, "observation")
    if observation["schema"] != OBSERVATION_SCHEMA:
        raise ContractError("unknown observation schema")
    if observation["scenario"] != expected_scenario:
        raise ContractError("observation scenario differs from the requested scenario")
    metrics = observation["metrics"]
    if not isinstance(metrics, dict) or not 1 <= len(metrics) <= MAX_METRICS:
        raise ContractError("observation metrics must be a bounded non-empty object")
    for name, raw in metrics.items():
        _token(name, "metric name")
        metric = _exact_keys(
            raw, {"direction", "unit", "value"}, f"observation metric {name}"
        )
        if metric["unit"] not in UNITS:
            raise ContractError(f"metric {name} has an unsupported unit")
        if metric["direction"] not in {"higher", "lower"}:
            raise ContractError(f"metric {name} has an unsupported direction")
        _number(metric["value"], f"metric {name} value")
    return observation


def validate_evidence(value: Any) -> dict[str, Any]:
    evidence = _exact_keys(
        value,
        {"metrics", "repository", "revision", "runner", "scenario", "schema", "tier"},
        "evidence",
    )
    if evidence["schema"] != EVIDENCE_SCHEMA:
        raise ContractError("unknown evidence schema")
    if evidence["repository"] not in REPOSITORIES:
        raise ContractError("unknown repository")
    if not isinstance(evidence["revision"], str) or not REVISION_RE.fullmatch(
        evidence["revision"]
    ):
        raise ContractError("revision must be an exact lowercase Git SHA")
    _token(evidence["scenario"], "scenario")
    if evidence["tier"] not in TIERS:
        raise ContractError("unknown evidence tier")
    validate_runner(evidence["runner"])
    metrics = evidence["metrics"]
    if not isinstance(metrics, dict) or not 1 <= len(metrics) <= MAX_METRICS:
        raise ContractError("evidence metrics must be a bounded non-empty object")
    for name, raw in metrics.items():
        _token(name, "metric name")
        metric = _exact_keys(
            raw, {"direction", "samples", "unit"}, f"evidence metric {name}"
        )
        if metric["unit"] not in UNITS:
            raise ContractError(f"metric {name} has an unsupported unit")
        if metric["direction"] not in {"higher", "lower"}:
            raise ContractError(f"metric {name} has an unsupported direction")
        samples = metric["samples"]
        if (
            not isinstance(samples, list)
            or not MIN_SAMPLES <= len(samples) <= MAX_SAMPLES
        ):
            raise ContractError(
                f"metric {name} requires {MIN_SAMPLES}..{MAX_SAMPLES} samples"
            )
        for index, sample in enumerate(samples):
            _number(sample, f"metric {name} sample {index}")
    return evidence


def validate_policy(value: Any) -> dict[str, Any]:
    policy = _exact_keys(
        value,
        {"max_relative_mad", "metrics", "min_samples", "scenario", "schema"},
        "policy",
    )
    if policy["schema"] != POLICY_SCHEMA:
        raise ContractError("unknown policy schema")
    _token(policy["scenario"], "policy scenario")
    _positive_integer(policy["min_samples"], "policy.min_samples", MAX_SAMPLES)
    if policy["min_samples"] < MIN_SAMPLES:
        raise ContractError(f"policy.min_samples must be at least {MIN_SAMPLES}")
    _number(policy["max_relative_mad"], "policy.max_relative_mad", maximum=1.0)
    metrics = policy["metrics"]
    if not isinstance(metrics, dict) or not 1 <= len(metrics) <= MAX_METRICS:
        raise ContractError("policy metrics must be a bounded non-empty object")
    for name, raw in metrics.items():
        _token(name, "policy metric name")
        metric = _exact_keys(
            raw,
            {
                "absolute_max",
                "absolute_min",
                "direction",
                "max_regression_percent",
                "unit",
            },
            f"policy metric {name}",
        )
        if metric["unit"] not in UNITS or metric["direction"] not in {
            "higher",
            "lower",
        }:
            raise ContractError(
                f"policy metric {name} has an unsupported unit or direction"
            )
        _number(
            metric["max_regression_percent"],
            f"policy metric {name} regression",
            maximum=100.0,
        )
        for bound in ("absolute_min", "absolute_max"):
            if metric[bound] is not None:
                _number(metric[bound], f"policy metric {name} {bound}")
        if (
            metric["absolute_min"] is not None
            and metric["absolute_max"] is not None
            and float(metric["absolute_min"]) > float(metric["absolute_max"])
        ):
            raise ContractError(f"policy metric {name} has inverted absolute bounds")
    return policy


def digest_document(value: Any) -> str:
    canonical = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode()
    return hashlib.sha256(canonical).hexdigest()


def _digest_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _cpu_model_digest() -> str:
    candidates: list[str] = []
    cpuinfo = pathlib.Path("/proc/cpuinfo")
    try:
        if cpuinfo.is_file() and not cpuinfo.is_symlink():
            for line in cpuinfo.read_text(
                encoding="utf-8", errors="strict"
            ).splitlines():
                key, separator, value = line.partition(":")
                if separator and key.strip().lower() in {
                    "cpu model",
                    "hardware",
                    "model name",
                }:
                    normalized = " ".join(value.lower().split())
                    if normalized:
                        candidates.append(normalized)
    except (OSError, UnicodeError):
        pass
    processor = " ".join(platform.processor().lower().split())
    if processor:
        candidates.append(processor)
    material = sorted(set(candidates)) or ["unavailable"]
    return _digest_text("\n".join(material))


def _environment_digest() -> str:
    material = {
        "kernel_release": platform.release().lower(),
        "python_implementation": platform.python_implementation().lower(),
        "python_version": platform.python_version(),
    }
    return digest_document(material)


def runner_identity(runner_class: str, toolchain: str) -> dict[str, Any]:
    cpu_logical = os.cpu_count() or 1
    memory_bytes = 1
    if hasattr(os, "sysconf"):
        try:
            memory_bytes = int(os.sysconf("SC_PAGE_SIZE")) * int(
                os.sysconf("SC_PHYS_PAGES")
            )
        except (OSError, ValueError):
            memory_bytes = 1
    runner: dict[str, Any] = {
        "arch": _token(platform.machine().lower(), "runner arch"),
        "class": _token(runner_class, "runner class"),
        "cpu_model_digest": _cpu_model_digest(),
        "cpu_logical": _positive_integer(cpu_logical, "runner cpu count", 65_536),
        "environment_digest": _environment_digest(),
        "memory_bytes": _positive_integer(memory_bytes, "runner memory", 1 << 60),
        "os": _token(platform.system().lower(), "runner OS"),
        "toolchain": _token(toolchain, "runner toolchain"),
    }
    runner["fingerprint"] = digest_document(runner)
    return runner


def write_exclusive(path: pathlib.Path, value: Any) -> None:
    if path.is_symlink() or path.exists():
        raise ContractError(f"refusing to overwrite evidence: {path}")
    parent = path.parent
    if not parent.is_dir() or parent.is_symlink():
        raise ContractError(f"evidence parent is missing or symlinked: {parent}")
    payload = (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    )
    encoded = payload.encode()
    if len(encoded) > MAX_DOCUMENT_BYTES:
        raise ContractError("generated evidence exceeds the document budget")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=parent)
    temporary = pathlib.Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.link(temporary, path)
    except FileExistsError as exc:
        raise ContractError(f"refusing to overwrite evidence: {path}") from exc
    finally:
        temporary.unlink(missing_ok=True)


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGTERM)
        else:
            process.terminate()
        process.wait(timeout=5)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        if process.poll() is None:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
            process.wait(timeout=5)


def run_observation(
    command: list[str], scenario: str, timeout_seconds: int
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(
        prefix="camellia-performance-observation-"
    ) as temporary_dir:
        observation_path = pathlib.Path(temporary_dir) / "observation.json"
        environment = os.environ.copy()
        environment["CAMELLIA_PERFORMANCE_OBSERVATION_FILE"] = str(observation_path)
        process = subprocess.Popen(
            command,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=os.name == "posix",
        )
        try:
            status = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired as exc:
            _stop_process(process)
            raise ContractError(
                f"observation command exceeded {timeout_seconds} seconds"
            ) from exc
        if status != 0:
            raise ContractError(f"observation command failed with exit status {status}")
        return validate_observation(load_document(observation_path), scenario)


def collect(args: argparse.Namespace) -> dict[str, Any]:
    if not args.command:
        raise ContractError("collect requires a command after --")
    _validate_collection_args(args)
    scenario = _token(args.scenario, "scenario")
    for _ in range(args.warmups):
        run_observation(args.command, scenario, args.timeout_seconds)
    observations = [
        run_observation(args.command, scenario, args.timeout_seconds)
        for _ in range(args.iterations)
    ]
    return _evidence_from_observations(
        args,
        observations,
        runner_identity(args.runner_class, args.toolchain),
    )


def _evidence_from_observations(
    args: argparse.Namespace,
    observations: list[dict[str, Any]],
    runner: dict[str, Any],
) -> dict[str, Any]:
    scenario = _token(args.scenario, "scenario")
    first_metrics = observations[0]["metrics"]
    metric_names = set(first_metrics)
    metrics: dict[str, Any] = {}
    for name in sorted(metric_names):
        unit = first_metrics[name]["unit"]
        direction = first_metrics[name]["direction"]
        samples: list[float] = []
        for observation in observations:
            if set(observation["metrics"]) != metric_names:
                raise ContractError("observation metric set changed between iterations")
            metric = observation["metrics"][name]
            if metric["unit"] != unit or metric["direction"] != direction:
                raise ContractError(
                    f"metric {name} unit or direction changed between iterations"
                )
            samples.append(float(metric["value"]))
        metrics[name] = {"direction": direction, "samples": samples, "unit": unit}
    evidence = {
        "metrics": metrics,
        "repository": args.repository,
        "revision": args.revision,
        "runner": runner,
        "scenario": scenario,
        "schema": EVIDENCE_SCHEMA,
        "tier": args.tier,
    }
    return validate_evidence(evidence)


def _validate_collection_args(args: argparse.Namespace) -> None:
    _positive_integer(args.iterations, "iterations", MAX_SAMPLES)
    if args.iterations < MIN_SAMPLES:
        raise ContractError(f"iterations must be at least {MIN_SAMPLES}")
    if not isinstance(args.warmups, int) or not 0 <= args.warmups <= 10:
        raise ContractError("warmups must be in 0..10")
    _positive_integer(args.timeout_seconds, "timeout_seconds", 3600)
    _token(args.scenario, "scenario")


def collect_pair(
    args: argparse.Namespace,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not args.control_command or not args.candidate_command:
        raise ContractError("collect-pair requires control and candidate commands")
    _validate_collection_args(args)
    if args.control_revision == args.candidate_revision:
        raise ContractError("control and candidate revisions must differ")
    if not REVISION_RE.fullmatch(args.control_revision) or not REVISION_RE.fullmatch(
        args.candidate_revision
    ):
        raise ContractError("revisions must be exact lowercase Git SHAs")
    scenario = _token(args.scenario, "scenario")
    runner = runner_identity(args.runner_class, args.toolchain)
    measured: dict[str, list[dict[str, Any]]] = {"control": [], "candidate": []}

    def run_round(index: int, *, keep: bool) -> None:
        order = (
            ("control", args.control_command),
            ("candidate", args.candidate_command),
        )
        if index % 2:
            order = tuple(reversed(order))
        for role, command in order:
            observation = run_observation(command, scenario, args.timeout_seconds)
            if keep:
                measured[role].append(observation)

    for index in range(args.warmups):
        run_round(index, keep=False)
    for index in range(args.iterations):
        run_round(index, keep=True)

    control_args = argparse.Namespace(**vars(args))
    control_args.revision = args.control_revision
    candidate_args = argparse.Namespace(**vars(args))
    candidate_args.revision = args.candidate_revision
    return (
        _evidence_from_observations(control_args, measured["control"], runner),
        _evidence_from_observations(candidate_args, measured["candidate"], runner),
    )


def _relative_mad(values: list[float]) -> tuple[float, float]:
    median = statistics.median(values)
    mad = statistics.median(abs(value - median) for value in values)
    return median, mad / max(abs(median), 1e-12)


def compare(
    control: dict[str, Any], candidate: dict[str, Any], policy: dict[str, Any]
) -> dict[str, Any]:
    validate_evidence(control)
    validate_evidence(candidate)
    validate_policy(policy)
    for field in ("repository", "scenario", "tier"):
        if control[field] != candidate[field]:
            raise ContractError(f"control and candidate {field} differ")
    if control["revision"] == candidate["revision"]:
        raise ContractError("control and candidate revisions must differ")
    if control["runner"] != candidate["runner"]:
        raise ContractError("control and candidate runner fingerprints differ")
    if policy["scenario"] != candidate["scenario"]:
        raise ContractError("policy scenario differs from evidence")
    if set(control["metrics"]) != set(candidate["metrics"]) or set(
        candidate["metrics"]
    ) != set(policy["metrics"]):
        raise ContractError("control, candidate, and policy metric sets differ")

    results: dict[str, Any] = {}
    failures: list[str] = []
    inconclusive: list[str] = []
    for name in sorted(candidate["metrics"]):
        control_metric = control["metrics"][name]
        candidate_metric = candidate["metrics"][name]
        metric_policy = policy["metrics"][name]
        if (
            control_metric["unit"] != candidate_metric["unit"]
            or control_metric["unit"] != metric_policy["unit"]
        ):
            raise ContractError(f"metric {name} units differ")
        if (
            control_metric["direction"] != candidate_metric["direction"]
            or control_metric["direction"] != metric_policy["direction"]
        ):
            raise ContractError(f"metric {name} directions differ")
        minimum = policy["min_samples"]
        if (
            len(control_metric["samples"]) < minimum
            or len(candidate_metric["samples"]) < minimum
        ):
            raise ContractError(f"metric {name} has fewer than {minimum} samples")
        control_median, control_noise = _relative_mad(
            [float(value) for value in control_metric["samples"]]
        )
        candidate_median, candidate_noise = _relative_mad(
            [float(value) for value in candidate_metric["samples"]]
        )
        noise_limit = float(policy["max_relative_mad"])
        noisy = control_noise > noise_limit or candidate_noise > noise_limit
        allowed = float(metric_policy["max_regression_percent"]) / 100.0
        direction = metric_policy["direction"]
        if direction == "lower":
            regression = candidate_median > control_median * (1.0 + allowed)
        else:
            regression = candidate_median < control_median * (1.0 - allowed)
        absolute_min = metric_policy["absolute_min"]
        absolute_max = metric_policy["absolute_max"]
        if absolute_min is not None and candidate_median < float(absolute_min):
            regression = True
        if absolute_max is not None and candidate_median > float(absolute_max):
            regression = True
        if noisy:
            inconclusive.append(name)
        elif regression:
            failures.append(name)
        change_percent = (
            0.0
            if control_median == 0.0
            else (candidate_median / control_median - 1.0) * 100.0
        )
        results[name] = {
            "candidate_median": candidate_median,
            "candidate_relative_mad": candidate_noise,
            "change_percent": change_percent,
            "control_median": control_median,
            "control_relative_mad": control_noise,
            "direction": direction,
            "status": ("inconclusive" if noisy else "fail" if regression else "pass"),
            "unit": metric_policy["unit"],
        }
    result = {
        "candidate_digest": digest_document(candidate),
        "candidate_revision": candidate["revision"],
        "control_digest": digest_document(control),
        "control_revision": control["revision"],
        "metrics": results,
        "repository": candidate["repository"],
        "runner_fingerprint": candidate["runner"]["fingerprint"],
        "scenario": candidate["scenario"],
        "schema": COMPARISON_SCHEMA,
        "status": ("inconclusive" if inconclusive else "fail" if failures else "pass"),
        "tier": candidate["tier"],
    }
    return result


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command_name", required=True)
    validate_command = commands.add_parser("validate")
    validate_command.add_argument("evidence", type=pathlib.Path)
    observation_command = commands.add_parser("validate-observation")
    observation_command.add_argument("observation", type=pathlib.Path)
    observation_command.add_argument("--scenario", required=True)
    policy_command = commands.add_parser("validate-policy")
    policy_command.add_argument("policy", type=pathlib.Path)
    compare_command = commands.add_parser("compare")
    compare_command.add_argument("control", type=pathlib.Path)
    compare_command.add_argument("candidate", type=pathlib.Path)
    compare_command.add_argument("policy", type=pathlib.Path)
    compare_command.add_argument("--output", required=True, type=pathlib.Path)
    collect_command = commands.add_parser("collect")
    collect_command.add_argument(
        "--repository", required=True, choices=sorted(REPOSITORIES)
    )
    collect_command.add_argument("--revision", required=True)
    collect_command.add_argument("--scenario", required=True)
    collect_command.add_argument("--tier", required=True, choices=sorted(TIERS))
    collect_command.add_argument("--runner-class", required=True)
    collect_command.add_argument("--toolchain", required=True)
    collect_command.add_argument("--iterations", type=int, default=5)
    collect_command.add_argument("--warmups", type=int, default=1)
    collect_command.add_argument("--timeout-seconds", type=int, default=120)
    collect_command.add_argument("--output", required=True, type=pathlib.Path)
    collect_command.add_argument("command", nargs=argparse.REMAINDER)
    pair_command = commands.add_parser("collect-pair")
    pair_command.add_argument(
        "--repository", required=True, choices=sorted(REPOSITORIES)
    )
    pair_command.add_argument("--control-revision", required=True)
    pair_command.add_argument("--candidate-revision", required=True)
    pair_command.add_argument("--scenario", required=True)
    pair_command.add_argument("--tier", required=True, choices=sorted(TIERS))
    pair_command.add_argument("--runner-class", required=True)
    pair_command.add_argument("--toolchain", required=True)
    pair_command.add_argument("--iterations", type=int, default=5)
    pair_command.add_argument("--warmups", type=int, default=1)
    pair_command.add_argument("--timeout-seconds", type=int, default=120)
    pair_command.add_argument("--control-output", required=True, type=pathlib.Path)
    pair_command.add_argument("--candidate-output", required=True, type=pathlib.Path)
    pair_command.add_argument("commands", nargs=argparse.REMAINDER)
    return root


def _pair_commands(value: list[str]) -> tuple[list[str], list[str]]:
    commands = value[1:] if value and value[0] == "--" else value
    if commands.count(":::") != 1:
        raise ContractError("collect-pair commands require exactly one ::: separator")
    separator = commands.index(":::")
    control = commands[:separator]
    candidate = commands[separator + 1 :]
    if not control or not candidate:
        raise ContractError("collect-pair requires two non-empty commands")
    return control, candidate


def main() -> int:
    args = parser().parse_args()
    status = 0
    try:
        if args.command_name == "validate":
            validate_evidence(load_document(args.evidence))
        elif args.command_name == "validate-observation":
            validate_observation(
                load_document(args.observation), _token(args.scenario, "scenario")
            )
        elif args.command_name == "validate-policy":
            validate_policy(load_document(args.policy))
        elif args.command_name == "compare":
            result = compare(
                validate_evidence(load_document(args.control)),
                validate_evidence(load_document(args.candidate)),
                validate_policy(load_document(args.policy)),
            )
            write_exclusive(args.output, result)
            if result["status"] == "fail":
                print(
                    "performance budget failed for metrics: "
                    + ",".join(
                        name
                        for name, metric in result["metrics"].items()
                        if metric["status"] == "fail"
                    ),
                    file=os.sys.stderr,
                )
                status = 3
        elif args.command_name == "collect":
            command = args.command
            if command and command[0] == "--":
                command = command[1:]
            args.command = command
            write_exclusive(args.output, collect(args))
        else:
            args.control_command, args.candidate_command = _pair_commands(args.commands)
            control, candidate = collect_pair(args)
            if args.control_output == args.candidate_output:
                raise ContractError("control and candidate outputs must differ")
            for output in (args.control_output, args.candidate_output):
                if output.is_symlink() or output.exists():
                    raise ContractError(f"refusing to overwrite evidence: {output}")
                if not output.parent.is_dir() or output.parent.is_symlink():
                    raise ContractError(
                        f"evidence parent is missing or symlinked: {output.parent}"
                    )
            write_exclusive(args.control_output, control)
            write_exclusive(args.candidate_output, candidate)
    except (ContractError, OSError) as exc:
        print(f"performance contract error: {exc}", file=os.sys.stderr)
        return 2
    if args.command_name == "compare" and result["status"] == "inconclusive":
        print(
            "performance comparison is inconclusive for metrics: "
            + ",".join(
                name
                for name, metric in result["metrics"].items()
                if metric["status"] == "inconclusive"
            ),
            file=os.sys.stderr,
        )
        return 4
    return status


if __name__ == "__main__":
    raise SystemExit(main())
