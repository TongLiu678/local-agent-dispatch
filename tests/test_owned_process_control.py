from __future__ import annotations

import datetime as dt
import importlib.util
import json
import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location(
    "owned_process_control", SCRIPTS / "owned_process_control.py"
)
assert SPEC and SPEC.loader
CONTROL = importlib.util.module_from_spec(SPEC)
sys.modules.setdefault("owned_process_control", CONTROL)
SPEC.loader.exec_module(CONTROL)


NOW = dt.datetime(2026, 8, 16, 12, 0, tzinfo=dt.timezone.utc)
IDENTITY = {
    "pid": 321,
    "start_time": "boot-12345",
    "process_group": 321,
    "run_id": "run-owned-1",
    "fence": "fence-7",
}


def observed(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {**IDENTITY, "owned_by_dispatch": True}
    value.update(overrides)
    return value


def lease(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        **IDENTITY,
        "owner_id": "controller-a",
        "status": "active",
        "lease_expires_at_utc": "2026-08-16T12:05:00Z",
    }
    value.update(overrides)
    return value


class OwnedProcessControlTests(unittest.TestCase):
    def test_complete_identity_and_live_lease_pause_then_resume(self) -> None:
        backend = CONTROL.FakeProcessControl()
        paused = CONTROL.pause_owned(
            observed=observed(),
            expected=IDENTITY,
            lease=lease(),
            owner_id="controller-a",
            backend=backend,
            now=NOW,
        )
        self.assertEqual("paused", paused["status"])
        self.assertEqual(1, len(backend.calls))
        self.assertEqual("pause", backend.calls[0]["action"])
        self.assertFalse(paused["os_signal_sent"])
        self.assertFalse(paused["automatic_signal"])

        resumed = CONTROL.resume_owned(
            observed=observed(),
            expected=IDENTITY,
            lease=lease(),
            owner_id="controller-a",
            backend=backend,
            now=NOW,
        )
        self.assertEqual("resumed", resumed["status"])
        self.assertEqual(["pause", "resume"], [row["action"] for row in backend.calls])
        self.assertEqual((), backend.paused_identity_digests)

    def test_every_identity_field_mismatch_blocks_without_backend_call(self) -> None:
        replacements: dict[str, object] = {
            "pid": 322,
            "start_time": "boot-99999",
            "process_group": 322,
            "run_id": "run-other",
            "fence": "fence-8",
        }
        for field, replacement in replacements.items():
            with self.subTest(field=field):
                backend = CONTROL.FakeProcessControl()
                result = CONTROL.pause_owned(
                    observed=observed(**{field: replacement}),
                    expected=IDENTITY,
                    lease=lease(),
                    owner_id="controller-a",
                    backend=backend,
                    now=NOW,
                )
                self.assertEqual("blocked", result["status"])
                self.assertEqual([], backend.calls)
                self.assertIn(f"identity_{field}_mismatch", result["reasons"])

    def test_unowned_process_is_never_passed_to_fake_backend(self) -> None:
        backend = CONTROL.FakeProcessControl()
        result = CONTROL.pause_owned(
            observed=observed(owned_by_dispatch=False),
            expected=IDENTITY,
            lease=lease(),
            owner_id="controller-a",
            backend=backend,
            now=NOW,
        )
        self.assertEqual("blocked", result["status"])
        self.assertIn("ownership_not_proven", result["reasons"])
        self.assertEqual([], backend.calls)

    def test_missing_or_expired_lease_blocks_without_backend_call(self) -> None:
        cases = (
            ("missing", None, "lease_owner_missing"),
            ("expired", lease(lease_expires_at_utc="2026-08-16T11:59:59Z"), "lease_expired"),
            ("released", lease(status="released"), "lease_not_active"),
            ("wrong_owner", lease(owner_id="controller-b"), "lease_owner_mismatch"),
            ("missing_identity", lease(process_group=None), "lease_identity_incomplete"),
        )
        for label, lease_value, reason in cases:
            with self.subTest(label=label):
                backend = CONTROL.FakeProcessControl()
                result = CONTROL.pause_owned(
                    observed=observed(),
                    expected=IDENTITY,
                    lease=lease_value,
                    owner_id="controller-a",
                    backend=backend,
                    now=NOW,
                )
                self.assertEqual("blocked", result["status"])
                self.assertIn(reason, result["reasons"])
                self.assertEqual([], backend.calls)

    def test_resume_stale_fence_and_missing_pause_do_not_call_backend(self) -> None:
        backend = CONTROL.FakeProcessControl()
        paused = CONTROL.pause_owned(
            observed=observed(),
            expected=IDENTITY,
            lease=lease(),
            owner_id="controller-a",
            backend=backend,
            now=NOW,
        )
        self.assertEqual("paused", paused["status"])

        stale = CONTROL.resume_owned(
            observed=observed(),
            expected=IDENTITY,
            lease=lease(fence="fence-6"),
            owner_id="controller-a",
            backend=backend,
            now=NOW,
        )
        self.assertEqual("blocked", stale["status"])
        self.assertIn("lease_identity_fence_mismatch", stale["reasons"])
        self.assertEqual(1, len(backend.calls))

        other_backend = CONTROL.FakeProcessControl()
        missing = CONTROL.resume_owned(
            observed=observed(),
            expected=IDENTITY,
            lease=lease(),
            owner_id="controller-a",
            backend=other_backend,
            now=NOW,
        )
        self.assertEqual("blocked", missing["status"])
        self.assertIn("lane_not_paused", missing["reasons"])
        self.assertEqual([], other_backend.calls)

    def test_receipt_is_redacted_and_never_copies_prompt_argv_or_credential(self) -> None:
        backend = CONTROL.FakeProcessControl()
        result = CONTROL.pause_owned(
            observed=observed(
                argv=["codex", "--prompt", "PRIVATE_PROMPT"],
                prompt="PRIVATE_PROMPT",
                credential="PRIVATE_TOKEN",
            ),
            expected=IDENTITY,
            lease=lease(credential="PRIVATE_TOKEN"),
            owner_id="controller-a",
            backend=backend,
            now=NOW,
        )
        serialized = json.dumps(result, sort_keys=True)
        self.assertEqual("paused", result["status"])
        self.assertNotIn("PRIVATE_PROMPT", serialized)
        self.assertNotIn("PRIVATE_TOKEN", serialized)
        self.assertNotIn("--prompt", serialized)
        self.assertNotIn("fence-7", serialized)
        self.assertNotIn("argv", serialized)
        self.assertNotIn("credential", serialized)
        self.assertTrue(result["identity_digest"].startswith("sha256:"))


if __name__ == "__main__":
    unittest.main()
