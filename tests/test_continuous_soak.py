"""Deterministic provider-free virtual soak tests."""

from __future__ import annotations

import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from continuous_soak import ContinuousSoakError, run_virtual_soak  # noqa: E402


class ContinuousSoakTests(unittest.TestCase):
    def test_virtual_24h_is_byte_stable_and_provider_free(self) -> None:
        first = run_virtual_soak(seed=11)
        second = run_virtual_soak(seed=11)
        self.assertEqual(first, second)
        self.assertTrue(first["ok"], first["invariant_failures"])
        self.assertFalse(first["provider_execution"])
        self.assertFalse(first["network_execution"])
        self.assertEqual(24 * 60 * 60, first["horizon_seconds"])
        self.assertEqual(24, first["segment_count"])
        self.assertEqual("E1_provider_free_virtual_only", first["evidence_ceiling"])

    def test_custom_fault_schedule_is_recorded_without_real_execution(self) -> None:
        report = run_virtual_soak(
            seed=3,
            horizon_seconds=3600,
            faults=[{"fault": "lost_ack", "t": 60.0, "target": "worker-a"}],
        )
        self.assertTrue(report["ok"], report["invariant_failures"])
        self.assertEqual(1, report["segment_count"])
        self.assertTrue(any(row.get("kind") == "ack_lost" for row in report["event_trace"]))

    def test_terminal_duplicate_delivery_is_suppressed(self) -> None:
        # This seed places the injected duplicate after j-3 has reached a
        # terminal state.  A receipt-backed replay must record the duplicate
        # without creating a second irreversible effect.
        report = run_virtual_soak(seed=20260901)
        self.assertTrue(report["ok"], report["invariant_failures"])
        self.assertEqual(0, report["outcome"]["violations"]["duplicate_effect"])
        self.assertGreaterEqual(
            report["outcome"]["violations"]["duplicate_delivery_suppressed"], 1
        )
        self.assertTrue(
            any(
                row.get("kind") == "duplicate_delivery_suppressed"
                and row.get("receipt_state") == "terminal"
                for row in report["event_trace"]
            )
        )

    def test_real_clock_mode_is_hard_gated(self) -> None:
        with self.assertRaises(ContinuousSoakError):
            run_virtual_soak(horizon_seconds=3599)


if __name__ == "__main__":
    unittest.main()
