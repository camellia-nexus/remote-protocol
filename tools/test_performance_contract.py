#!/usr/bin/env python3

import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import time
import unittest
from argparse import Namespace

MODULE_PATH = pathlib.Path(__file__).with_name("performance_contract.py")
SPEC = importlib.util.spec_from_file_location("performance_contract", MODULE_PATH)
contract = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(contract)


class PerformanceContractTests(unittest.TestCase):
    def setUp(self):
        self.runner = contract.runner_identity("fixed-linux-x64", "rust-1.97.1")

    def evidence(self, revision, samples, *, runner=None):
        return {
            "metrics": {
                "latency_ms": {"direction": "lower", "samples": samples, "unit": "ms"},
                "quality_ratio": {
                    "direction": "higher",
                    "samples": [0.95] * len(samples),
                    "unit": "ratio",
                },
            },
            "repository": "remote-protocol",
            "revision": revision,
            "runner": runner or self.runner,
            "scenario": "protocol-codec-smoke-v1",
            "schema": contract.EVIDENCE_SCHEMA,
            "tier": "pr-smoke",
        }

    @staticmethod
    def policy():
        return {
            "max_relative_mad": 0.1,
            "metrics": {
                "latency_ms": {
                    "absolute_max": 20.0,
                    "absolute_min": None,
                    "direction": "lower",
                    "max_regression_percent": 10.0,
                    "unit": "ms",
                },
                "quality_ratio": {
                    "absolute_max": 1.0,
                    "absolute_min": 0.9,
                    "direction": "higher",
                    "max_regression_percent": 5.0,
                    "unit": "ratio",
                },
            },
            "min_samples": 5,
            "scenario": "protocol-codec-smoke-v1",
            "schema": contract.POLICY_SCHEMA,
        }

    def test_comparison_accepts_stable_candidate_and_authenticates_inputs(self):
        control = self.evidence("a" * 40, [10.0, 10.1, 9.9, 10.0, 10.05])
        candidate = self.evidence("b" * 40, [10.2, 10.1, 10.0, 10.2, 10.1])
        result = contract.compare(control, candidate, self.policy())
        self.assertEqual(result["status"], "pass")
        self.assertEqual(
            result["candidate_digest"], contract.digest_document(candidate)
        )

    def test_regression_noise_and_runner_mismatch_fail_closed(self):
        control = self.evidence("a" * 40, [10.0] * 5)
        failed = contract.compare(
            control, self.evidence("b" * 40, [12.0] * 5), self.policy()
        )
        self.assertEqual(failed["status"], "fail")
        self.assertEqual(failed["metrics"]["latency_ms"]["status"], "fail")
        inconclusive = contract.compare(
            control,
            self.evidence("b" * 40, [5.0, 10.0, 15.0, 20.0, 25.0]),
            self.policy(),
        )
        self.assertEqual(inconclusive["status"], "inconclusive")
        self.assertEqual(
            inconclusive["metrics"]["latency_ms"]["status"], "inconclusive"
        )
        other_runner = contract.runner_identity("other-linux-x64", "rust-1.97.1")
        with self.assertRaisesRegex(contract.ContractError, "runner"):
            contract.compare(
                control,
                self.evidence("b" * 40, [10.0] * 5, runner=other_runner),
                self.policy(),
            )

    def test_strict_json_duplicate_nonfinite_size_and_overwrite_are_rejected(self):
        with tempfile.TemporaryDirectory(
            prefix="camellia-performance-contract-"
        ) as temporary:
            root = pathlib.Path(temporary)
            duplicate = root / "duplicate.json"
            duplicate.write_text('{"schema":"a","schema":"b"}')
            with self.assertRaisesRegex(contract.ContractError, "duplicate"):
                contract.load_document(duplicate)
            nonfinite = root / "nonfinite.json"
            nonfinite.write_text('{"value":NaN}')
            with self.assertRaisesRegex(contract.ContractError, "non-finite"):
                contract.load_document(nonfinite)
            oversized = root / "oversized.json"
            oversized.write_bytes(b"x" * (contract.MAX_DOCUMENT_BYTES + 1))
            with self.assertRaisesRegex(contract.ContractError, "size"):
                contract.load_document(oversized)
            output = root / "evidence.json"
            contract.write_exclusive(output, {"status": "first"})
            with self.assertRaisesRegex(contract.ContractError, "overwrite"):
                contract.write_exclusive(output, {"status": "second"})
            self.assertEqual(json.loads(output.read_text()), {"status": "first"})

    def test_observation_requires_exact_schema_and_bounded_metric(self):
        valid = {
            "metrics": {
                "latency_ms": {"direction": "lower", "unit": "ms", "value": 1.25}
            },
            "scenario": "protocol-codec-smoke-v1",
            "schema": contract.OBSERVATION_SCHEMA,
        }
        self.assertEqual(contract.validate_observation(valid, valid["scenario"]), valid)
        invalid = json.loads(json.dumps(valid))
        invalid["metrics"]["latency_ms"]["value"] = float("inf")
        with self.assertRaises(contract.ContractError):
            contract.validate_observation(invalid, valid["scenario"])

        with tempfile.TemporaryDirectory(
            prefix="camellia-performance-validation-cli-"
        ) as temporary:
            root = pathlib.Path(temporary)
            observation = root / "observation.json"
            policy = root / "policy.json"
            observation.write_text(json.dumps(valid), encoding="utf-8")
            policy.write_text(json.dumps(self.policy()), encoding="utf-8")
            for arguments in (
                (
                    "validate-observation",
                    str(observation),
                    "--scenario",
                    valid["scenario"],
                ),
                ("validate-policy", str(policy)),
            ):
                process = subprocess.run(
                    [sys.executable, str(MODULE_PATH), *arguments],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(process.returncode, 0, process.stderr)

    def test_collector_runs_warmups_and_emits_valid_evidence(self):
        emitter = """
import json, os, pathlib
pathlib.Path(os.environ['CAMELLIA_PERFORMANCE_OBSERVATION_FILE']).write_text(json.dumps({
    'schema': 'camellia-performance-observation-v1',
    'scenario': 'protocol-codec-smoke-v1',
    'metrics': {'latency_ms': {'unit': 'ms', 'direction': 'lower', 'value': 1.25}},
}))
"""
        args = Namespace(
            command=[sys.executable, "-c", emitter],
            iterations=5,
            repository="remote-protocol",
            revision="a" * 40,
            runner_class="fixed-linux-x64",
            scenario="protocol-codec-smoke-v1",
            tier="pr-smoke",
            timeout_seconds=5,
            toolchain="python-test",
            warmups=1,
        )
        evidence = contract.collect(args)
        self.assertEqual(evidence["metrics"]["latency_ms"]["samples"], [1.25] * 5)
        self.assertEqual(contract.validate_evidence(evidence), evidence)

    def test_paired_collector_alternates_order_and_shares_runner(self):
        emitter = """
import json, os, pathlib, sys
role, log = sys.argv[1:]
with pathlib.Path(log).open('a', encoding='utf-8') as output:
    output.write(role + '\\n')
pathlib.Path(os.environ['CAMELLIA_PERFORMANCE_OBSERVATION_FILE']).write_text(json.dumps({
    'schema': 'camellia-performance-observation-v1',
    'scenario': 'protocol-codec-smoke-v1',
    'metrics': {'latency_ms': {'unit': 'ms', 'direction': 'lower', 'value': 1.25}},
}))
"""
        with tempfile.TemporaryDirectory(
            prefix="camellia-performance-pair-"
        ) as temporary:
            log = pathlib.Path(temporary) / "order.log"
            args = Namespace(
                candidate_command=[
                    sys.executable,
                    "-c",
                    emitter,
                    "candidate",
                    str(log),
                ],
                candidate_revision="b" * 40,
                control_command=[sys.executable, "-c", emitter, "control", str(log)],
                control_revision="a" * 40,
                iterations=5,
                repository="remote-protocol",
                runner_class="fixed-linux-x64",
                scenario="protocol-codec-smoke-v1",
                tier="pr-smoke",
                timeout_seconds=5,
                toolchain="python-test",
                warmups=1,
            )
            control, candidate = contract.collect_pair(args)
            self.assertEqual(control["runner"], candidate["runner"])
            self.assertEqual(control["metrics"]["latency_ms"]["samples"], [1.25] * 5)
            self.assertEqual(
                log.read_text(encoding="utf-8").splitlines(),
                [
                    "control",
                    "candidate",
                    "control",
                    "candidate",
                    "candidate",
                    "control",
                    "control",
                    "candidate",
                    "candidate",
                    "control",
                    "control",
                    "candidate",
                ],
            )

    def test_compare_cli_publishes_fail_and_inconclusive_without_overwrite(self):
        with tempfile.TemporaryDirectory(
            prefix="camellia-performance-cli-"
        ) as temporary:
            root = pathlib.Path(temporary)
            control = self.evidence("a" * 40, [10.0] * 5)
            failed = self.evidence("b" * 40, [12.0] * 5)
            noisy = self.evidence("b" * 40, [5.0, 10.0, 15.0, 20.0, 25.0])
            paths = {
                "control": root / "control.json",
                "failed": root / "failed.json",
                "noisy": root / "noisy.json",
                "policy": root / "policy.json",
            }
            for name, document in (
                ("control", control),
                ("failed", failed),
                ("noisy", noisy),
                ("policy", self.policy()),
            ):
                paths[name].write_text(json.dumps(document), encoding="utf-8")

            failed_output = root / "failed-comparison.json"
            failed_process = subprocess.run(
                [
                    sys.executable,
                    str(MODULE_PATH),
                    "compare",
                    str(paths["control"]),
                    str(paths["failed"]),
                    str(paths["policy"]),
                    "--output",
                    str(failed_output),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(failed_process.returncode, 3)
            self.assertEqual(json.loads(failed_output.read_text())["status"], "fail")

            noisy_output = root / "noisy-comparison.json"
            noisy_process = subprocess.run(
                [
                    sys.executable,
                    str(MODULE_PATH),
                    "compare",
                    str(paths["control"]),
                    str(paths["noisy"]),
                    str(paths["policy"]),
                    "--output",
                    str(noisy_output),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(noisy_process.returncode, 4)
            self.assertEqual(
                json.loads(noisy_output.read_text())["status"], "inconclusive"
            )

            sentinel = root / "existing.json"
            sentinel.write_text('{"preserve":true}\n', encoding="utf-8")
            collision = subprocess.run(
                [
                    sys.executable,
                    str(MODULE_PATH),
                    "compare",
                    str(paths["control"]),
                    str(paths["noisy"]),
                    str(paths["policy"]),
                    "--output",
                    str(sentinel),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(collision.returncode, 2)
            self.assertEqual(sentinel.read_text(), '{"preserve":true}\n')

    @unittest.skipUnless(
        sys.platform != "win32", "process-group timeout assertion is POSIX-specific"
    )
    def test_observation_timeout_terminates_descendants(self):
        with tempfile.TemporaryDirectory(
            prefix="camellia-performance-timeout-"
        ) as temporary:
            sentinel = pathlib.Path(temporary) / "descendant-survived"
            child = f"import time,pathlib; time.sleep(1.5); pathlib.Path({str(sentinel)!r}).write_text('bad')"
            parent = (
                "import subprocess,sys,time; "
                f"subprocess.Popen([sys.executable, '-c', {child!r}]); time.sleep(10)"
            )
            with self.assertRaisesRegex(contract.ContractError, "exceeded"):
                contract.run_observation(
                    [sys.executable, "-c", parent], "protocol-codec-smoke-v1", 1
                )
            time.sleep(0.7)
            self.assertFalse(sentinel.exists())


if __name__ == "__main__":
    unittest.main()
