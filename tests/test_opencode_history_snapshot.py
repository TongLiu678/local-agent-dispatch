from __future__ import annotations

import importlib.util
import pathlib
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "opencode_history_snapshot", ROOT / "scripts" / "opencode_history_snapshot.py"
)
assert SPEC and SPEC.loader
history = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(history)


STATS_A = """
OVERVIEW
Sessions 2
Messages 10
Days 30
COST & TOKENS
Total Cost $1.00
Input 10K
Output 2K
MODEL USAGE
opencode-go/deepseek-v4-flash
Messages 10
Input Tokens 10K
Output Tokens 2K
Cost $1.00
"""


STATS_B = """
OVERVIEW
Sessions 3
Messages 20
Days 30
COST & TOKENS
Total Cost $2.00
Input 20K
Output 4K
MODEL USAGE
opencode-go/kimi-k2.7-code
Messages 20
Input Tokens 20K
Output Tokens 4K
Cost $2.00
"""


class HistorySnapshotTests(unittest.TestCase):
    def test_explicit_contexts_are_aggregated_and_duplicate_db_is_not_double_counted(self):
        with tempfile.TemporaryDirectory() as tmp:
            roots = [pathlib.Path(tmp) / "lane-a", pathlib.Path(tmp) / "lane-b"]
            calls = []

            def fake_run(argv, timeout, *, env_overrides=None):
                calls.append((argv, env_overrides or {}))
                if "db" in argv:
                    # Both contexts intentionally report the same database.
                    return {"ok": True, "returncode": 0, "stdout": "/srv/shared/opencode.db\n", "stderr": "", "timed_out": False}
                stdout = STATS_A if len([x for x in calls if "stats" in x[0]]) == 1 else STATS_B
                return {"ok": True, "returncode": 0, "stdout": stdout, "stderr": "", "timed_out": False}

            with mock.patch.object(history._SNAPSHOT, "run_readonly", side_effect=fake_run):
                result = history.collect_history(
                    "opencode",
                    roots,
                    labels=["lane-a", "lane-b"],
                )

            self.assertEqual(2, len(result["contexts"]))
            self.assertEqual(1, result["aggregate"]["deduplicated_context_count"])
            self.assertEqual("lane-a", result["contexts"][1]["duplicate_of_context"])
            self.assertEqual(
                ["opencode-go/deepseek-v4-flash"],
                [row["model_id"] for row in result["aggregate"]["opencode_go_models"]],
            )
            self.assertEqual("unknown", result["quota"]["state"])
            self.assertTrue(all("XDG_DATA_HOME" in env for _, env in calls))

    def test_separate_contexts_preserve_model_history_without_claiming_balance(self):
        with tempfile.TemporaryDirectory() as tmp:
            roots = [pathlib.Path(tmp) / "a", pathlib.Path(tmp) / "b"]
            db_paths = iter(["/srv/EXAMPLE_001\n", "/srv/EXAMPLE_002\n"])
            stats = iter([STATS_A, STATS_B])

            def fake_run(argv, timeout, *, env_overrides=None):
                if "db" in argv:
                    out = next(db_paths)
                else:
                    out = next(stats)
                return {"ok": True, "returncode": 0, "stdout": out, "stderr": "", "timed_out": False}

            with mock.patch.object(history._SNAPSHOT, "run_readonly", side_effect=fake_run):
                result = history.collect_history("opencode", roots)

            self.assertEqual(2, result["aggregate"]["deduplicated_context_count"])
            models = {row["model_id"] for row in result["aggregate"]["opencode_go_models"]}
            self.assertEqual(
                {"opencode-go/deepseek-v4-flash", "opencode-go/kimi-k2.7-code"},
                models,
            )
            self.assertFalse(result["security"]["credential_file_read"])
            self.assertFalse(result["security"]["model_prompt_sent"])

    def test_no_roots_uses_current_context_and_rejects_label_mismatch(self):
        with mock.patch.object(history._SNAPSHOT, "run_readonly") as run:
            run.side_effect = [
                {"ok": True, "returncode": 0, "stdout": "/tmp/a.db\n", "stderr": "", "timed_out": False},
                {"ok": True, "returncode": 0, "stdout": STATS_A, "stderr": "", "timed_out": False},
            ]
            result = history.collect_history("opencode", [])
        self.assertEqual("current-environment", result["contexts"][0]["context_id"])
        with self.assertRaises(ValueError):
            history.collect_history("opencode", ["/tmp/a"], labels=["a", "b"])

    def test_include_current_keeps_explicit_runtime_labels_aligned(self):
        calls = []

        def fake_run(argv, timeout, *, env_overrides=None):
            calls.append((argv, env_overrides))
            if "db" in argv:
                return {
                    "ok": True,
                    "returncode": 0,
                    "stdout": f"/srv/{len(calls)}.db\n",
                    "stderr": "",
                    "timed_out": False,
                }
            return {
                "ok": True,
                "returncode": 0,
                "stdout": STATS_A,
                "stderr": "",
                "timed_out": False,
            }

        with mock.patch.object(history._SNAPSHOT, "run_readonly", side_effect=fake_run):
            result = history.collect_history(
                "opencode",
                ["/tmp/server-runtime"],
                include_current=True,
                labels=["server-runtime"],
            )
        self.assertEqual(
            ["current-environment", "server-runtime"],
            [row["context_id"] for row in result["contexts"]],
        )
        self.assertEqual(2, result["aggregate"]["deduplicated_context_count"])

    def test_history_stats_probe_does_not_use_pure_context(self):
        calls = []

        def fake_run(argv, timeout, *, env_overrides=None):
            calls.append((list(argv), dict(env_overrides or {})))
            if "db" in argv:
                return {
                    "ok": True,
                    "returncode": 0,
                    "stdout": "/srv/EXAMPLE_003\n",
                    "stderr": "",
                    "timed_out": False,
                }
            return {
                "ok": True,
                "returncode": 0,
                "stdout": "OVERVIEW\nSessions 2\nMessages 3\nCOST & TOKENS\nTotal Cost $0.10\nMODEL USAGE\nopencode-go/kimi-k2.7-code\n",
                "stderr": "",
                "timed_out": False,
            }

        with mock.patch.object(history._SNAPSHOT, "run_readonly", side_effect=fake_run):
            result = history.collect_history("opencode", ["/tmp/server-runtime"])

        stats_calls = [row for row in calls if "stats" in row[0]]
        self.assertEqual(1, len(stats_calls))
        self.assertNotIn("--pure", stats_calls[0][0])
        self.assertEqual(2, result["aggregate"]["overview"]["sessions"])


if __name__ == "__main__":
    unittest.main()
