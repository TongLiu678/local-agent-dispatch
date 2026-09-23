from __future__ import annotations

import json
import pathlib
import re
import sys
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import server_local_model_scan as scan  # noqa: E402


class ServerLocalModelScanTests(unittest.TestCase):
    def test_remote_scanner_has_no_private_fixed_worktree_or_raw_process_args(self):
        self.assertNotIn("/private-server-root", scan.REMOTE_SCANNER)
        self.assertNotIn("/root/EXAMPLE_001", scan.REMOTE_SCANNER)
        self.assertNotIn("ps -eo pid=,args=", scan.REMOTE_SCANNER)
        self.assertIn("LAD_PROBE_PROJECT", scan.REMOTE_SCANNER)
        self.assertIn("LAD_PROBE_OPENCODE_BIN", scan.REMOTE_SCANNER)
        self.assertIn("LAD_PROBE_OPENCODE_AUTH_ROOT", scan.REMOTE_SCANNER)
        self.assertIn("downloads/opencode-npm-extract/package/bin/opencode", scan.REMOTE_SCANNER)
        self.assertIn("bounded_absolute_candidate", scan.REMOTE_SCANNER)
        self.assertIn("runtime_command_evidence", scan.REMOTE_SCANNER)

    def test_server_recipes_use_injected_paths_and_route_identity(self):
        for name in (
            "deploy_server_local_qwen25_awq.sh",
            "server_local_agentic_smoke.sh",
            "wait_for_server_local_smoke.sh",
            "codex_large_download_guard.sh",
        ):
            text = (ROOT / "scripts" / name).read_text(encoding="utf-8")
            self.assertNotIn("/private-server-root", text, name)
            self.assertNotIn("/private-server-bin", text, name)
        deploy = (ROOT / "scripts" / "deploy_server_local_qwen25_awq.sh").read_text(encoding="utf-8")
        self.assertIn("LAD_EXPECTED_EGRESS", deploy)

    def test_provider_canary_scopes_antigravity_credentials_per_project(self):
        canary = (ROOT / "scripts" / "remote_provider_canary_runner.sh").read_text(encoding="utf-8")
        self.assertIn('EXPECTED_EGRESS="${LAD_EXPECTED_EGRESS:-}"', canary)
        self.assertIn('"state":"expected_egress_missing"', canary)
        literal_addresses = set(re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", canary))
        self.assertLessEqual(literal_addresses, {"127.0.0.1"})
        self.assertIn("LAD_ANTIGRAVITY_HOME", canary)
        self.assertIn("LAD_ANTIGRAVITY_BIN", canary)
        self.assertIn('"XDG_CONFIG_HOME=$ANTIGRAVITY_HOME/.config"', canary)
        self.assertIn("agy_env=(env", canary)
        self.assertIn('timeout 30s "${agy_env[@]}" "$ANTIGRAVITY_BIN" models', canary)
        self.assertNotIn("timeout 30s agy models", canary)

    def test_declared_project_path_is_passed_to_local_probe(self):
        payload = {"runtime_commands": {}, "python_modules": [], "active_processes": [], "listeners": [], "apis": [], "model_directories": []}

        class Completed:
            returncode = 0
            stdout = json.dumps(payload)
            stderr = ""

        with mock.patch.object(scan.subprocess, "run", return_value=Completed()) as run:
            host_id, row = scan.scan_host(
                {"host_id": "local", "transport": "local", "project_path": "/srv/project"},
                2,
            )
        self.assertEqual("local", host_id)
        self.assertTrue(row["reachable"])
        script = run.call_args.kwargs["input"]
        self.assertIn("LAD_PROBE_PROJECT", script)
        self.assertIn("/srv/project", script)

    def test_declared_opencode_context_is_passed_without_credentials(self):
        payload = {
            "runtime_commands": {},
            "runtime_command_evidence": {},
            "runtime_context": {"mode": "inherited_environment"},
            "python_modules": [],
            "active_processes": [],
            "listeners": [],
            "apis": [],
            "model_directories": [],
        }

        class Completed:
            returncode = 0
            stdout = json.dumps(payload)
            stderr = ""

        with mock.patch.object(scan.subprocess, "run", return_value=Completed()) as run:
            host_id, row = scan.scan_host(
                {
                    "host_id": "bjb2",
                    "transport": "local",
                    "project_path": "/srv/project",
                    "opencode_bin": "/srv/opencode/bin/opencode",
                    "runtime_root": "/srv/lad/runtime-01",
                    "opencode_auth_root": "/srv/opencode-data",
                },
                2,
            )
        self.assertEqual("bjb2", host_id)
        script = run.call_args.kwargs["input"]
        self.assertIn("LAD_PROBE_OPENCODE_BIN", script)
        self.assertIn("/srv/opencode/bin/opencode", script)
        self.assertIn("LAD_PROBE_RUNTIME_ROOT", script)
        self.assertIn("/srv/lad/runtime-01", script)
        self.assertIn("LAD_PROBE_OPENCODE_AUTH_ROOT", script)
        self.assertIn("/srv/opencode-data", script)
        self.assertNotIn("auth.json", script)
        self.assertEqual("/srv/opencode/bin/opencode", row["opencode_bin"])
        self.assertEqual("/srv/lad/runtime-01", row["runtime_root"])
        self.assertEqual("/srv/opencode-data", row["opencode_auth_root"])

    def test_project_path_rejects_control_characters(self):
        with self.assertRaises(ValueError):
            scan.scan_host({"host_id": "bad", "transport": "local", "project_path": "/srv/EXAMPLE_002\nrun"}, 2)


if __name__ == "__main__":
    unittest.main()
