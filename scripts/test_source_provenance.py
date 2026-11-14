from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


SCRIPT_PATH = Path(__file__).parent / "validate_source_provenance.py"
SPEC = importlib.util.spec_from_file_location("validate_source_provenance", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
PROVENANCE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PROVENANCE
SPEC.loader.exec_module(PROVENANCE)

REPOSITORY = Path(__file__).resolve().parent.parent
COMMIT = "a" * 40


def canonical_document(commit: object = COMMIT) -> dict[str, object]:
    return {
        "schema_version": 1,
        "component": "camellia-remote-protocol",
        "source_repository": "https://github.com/XavierAlpha/hbb_common",
        "source_commit": commit,
        "history_policy": "fresh-root-snapshot",
        "license": "AGPL-3.0-only",
    }


class SourceProvenanceTests(unittest.TestCase):
    def test_repository_matches_provenance(self) -> None:
        PROVENANCE.validate_repository(REPOSITORY, expected_component="camellia-remote-protocol")

    def test_accepts_exact_canonical_source(self) -> None:
        PROVENANCE.validate_document(
            canonical_document(),
            expected_component="camellia-remote-protocol",
        )

    def test_rejects_missing_or_invalid_schema_version(self) -> None:
        for bad_schema in (2, 0, "1", None):
            doc = {**canonical_document(), "schema_version": bad_schema}
            with self.subTest(schema_version=bad_schema):
                with self.assertRaises(PROVENANCE.ProvenanceError):
                    PROVENANCE.validate_document(doc)

    def test_rejects_invalid_or_mismatched_component(self) -> None:
        doc = {**canonical_document(), "component": "unknown-component"}
        with self.assertRaises(PROVENANCE.ProvenanceError):
            PROVENANCE.validate_document(doc)

        with self.assertRaises(PROVENANCE.ProvenanceError):
            PROVENANCE.validate_document(
                canonical_document(),
                expected_component="camellia-remote-client",
            )

    def test_rejects_malformed_source_repository(self) -> None:
        bad_urls = (
            "http://github.com/user/repo",
            "git@github.com:user/repo.git",
            "https://gitlab.com/user/repo",
            "https://github.com/user",
            "https://github.com/user/repo/extra",
            "https://user:pass@github.com/user/repo",
            "https://github.com/user/../repo",
        )
        for bad_url in bad_urls:
            doc = {**canonical_document(), "source_repository": bad_url}
            with self.subTest(bad_url=bad_url):
                with self.assertRaises(PROVENANCE.ProvenanceError):
                    PROVENANCE.validate_document(doc)

    def test_rejects_malformed_source_commit(self) -> None:
        bad_commits = (
            "123456",
            "A" * 40,
            "g" * 40,
            COMMIT[:39],
            COMMIT + "a",
            12345,
        )
        for bad_commit in bad_commits:
            doc = {**canonical_document(), "source_commit": bad_commit}
            with self.subTest(bad_commit=bad_commit):
                with self.assertRaises(PROVENANCE.ProvenanceError):
                    PROVENANCE.validate_document(doc)

    def test_rejects_invalid_history_policy_or_license(self) -> None:
        doc_bad_policy = {**canonical_document(), "history_policy": "full-linear-import"}
        with self.assertRaises(PROVENANCE.ProvenanceError):
            PROVENANCE.validate_document(doc_bad_policy)

        doc_bad_license = {**canonical_document(), "license": "MIT"}
        with self.assertRaises(PROVENANCE.ProvenanceError):
            PROVENANCE.validate_document(doc_bad_license)

    def test_rejects_unknown_fields(self) -> None:
        doc = {**canonical_document(), "unexpected_extra_field": "injected"}
        with self.assertRaises(PROVENANCE.ProvenanceError):
            PROVENANCE.validate_document(doc)


if __name__ == "__main__":
    unittest.main()
