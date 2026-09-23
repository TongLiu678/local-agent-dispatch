"""Provider-free deterministic 24-hour virtual fault replay tests."""

from __future__ import annotations

import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from remote_fault_replay import ReplayError, replay  # noqa: E402


class RemoteFaultReplayTests(unittest.TestCase):
    def test_default_24h_replay_is_provider_free_and_successful(self):
        first = replay()
        second = replay()
        self.assertTrue(first["ok"])
        self.assertTrue(first["provider_execution"] is False)
        self.assertTrue(first["network_execution"] is False)
        self.assertEqual(24 * 60 * 60, first["virtual_horizon_seconds"])
        self.assertEqual(first, second)
        self.assertEqual(1, first["final"]["effect_count"])
        self.assertEqual(1, first["final"]["stale_fence_rejections"])
        self.assertEqual("eligible_for_next_fault_gate", first["decision"])

    def test_replay_covers_restart_disconnect_duplicate_and_terminal_events(self):
        report = replay()
        events = {row["event"] for row in report["events"]}
        self.assertTrue({
            "disconnect", "controller_restart", "worker_restart",
            "duplicate_receive", "terminal_complete", "reconcile_terminal",
        } <= events)

    def test_malformed_or_non_monotonic_schedule_fails_closed(self):
        with self.assertRaises(ReplayError):
            replay(schedule=[{"at_seconds": 0, "event": "enqueue"}, {"at_seconds": -1, "event": "receive"}])
        with self.assertRaises(ReplayError):
            replay(schedule=[{"at_seconds": 0, "event": "unknown"}])

    def test_horizon_is_bounded(self):
        with self.assertRaises(ReplayError):
            replay(horizon_seconds=3599)
        with self.assertRaises(ReplayError):
            replay(horizon_seconds=8 * 24 * 60 * 60)


if __name__ == "__main__":
    unittest.main()
