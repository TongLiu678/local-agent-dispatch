"""Provider-free tests for the durable checkpoint receipt contract."""

from __future__ import annotations

import copy
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.checkpoint_receipt import (  # noqa: E402
    CheckpointError,
    resume_eligibility,
    validate_checkpoint,
    write_checkpoint,
)


def _digest(letter: str) -> str:
    return "sha256:" + letter * 64


def _payload(attempt: str = "a1", **overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "run_id": "r1",
        "job_id": "j1",
        "attempt_id": attempt,
        "packet_digest": _digest("a"),
        "capsule_digest": _digest("b"),
        "progress_digest": _digest("c"),
        "owner_digest": _digest("d"),
        "fence_token": 3,
        "validator_state": {"status": "running", "validated_items": 2},
        "artifact_manifest": [{"path": "results/partial.json", "bytes": 12, "digest": _digest("e")}],
    }
    payload.update(overrides)
    return payload


class CheckpointReceiptTests(unittest.TestCase):
    def test_write_and_validate_is_atomic_and_prompt_free(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            receipt = write_checkpoint(root, _payload())
            report = validate_checkpoint(receipt, expected_attempt_id="a1")
            self.assertTrue(report["valid"])
            self.assertTrue((root / "checkpoints" / "checkpoint-00000000000000000001.json").exists())
            self.assertNotIn("prompt", receipt)
            self.assertNotIn("argv", receipt)

    def test_partial_checkpoint_and_artifact_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            receipt = write_checkpoint(pathlib.Path(temporary), _payload())
            self.assertTrue(validate_checkpoint(receipt, expected_attempt_id="a1")["valid"])
            tampered = copy.deepcopy(receipt)
            tampered["state_digest"] = _digest("f")
            with self.assertRaises(CheckpointError):
                validate_checkpoint(tampered, expected_attempt_id="a1")

            bad = _payload(artifact_manifest=[{"path": "../escape", "bytes": 1}])
            with self.assertRaises(CheckpointError):
                write_checkpoint(pathlib.Path(temporary) / "bad", bad)

    def test_resume_requires_matching_packet_capsule_and_fence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            checkpoint = write_checkpoint(pathlib.Path(temporary), _payload())
            denied = resume_eligibility(
                checkpoint,
                packet_digest=_digest("b"),
                capsule_digest=_digest("c"),
                active_fence=3,
            )
            self.assertFalse(denied["allowed"])
            self.assertIn("packet_digest_mismatch", denied["reasons"])
            self.assertIn("capsule_digest_mismatch", denied["reasons"])

            allowed = resume_eligibility(
                checkpoint,
                packet_digest=_digest("a"),
                capsule_digest=_digest("b"),
                active_fence=3,
            )
            self.assertTrue(allowed["allowed"], allowed)

    def test_hash_chain_requires_adjacent_sequence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            first = write_checkpoint(root, _payload())
            second = write_checkpoint(root, _payload(sequence=2, progress_digest=_digest("f")))
            self.assertEqual(1, first["sequence"])
            self.assertEqual(first["state_digest"], second["previous_checkpoint_digest"])
            with self.assertRaises(CheckpointError):
                write_checkpoint(root, _payload(sequence=4, progress_digest=_digest("1")))

    def test_sensitive_fields_and_absolute_artifacts_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(CheckpointError):
                write_checkpoint(pathlib.Path(temporary), _payload(prompt="do not persist"))
            with self.assertRaises(CheckpointError):
                write_checkpoint(pathlib.Path(temporary), _payload(artifact_manifest=[{"path": "/tmp/x"}]))


if __name__ == "__main__":
    unittest.main()
