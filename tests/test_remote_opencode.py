from __future__ import annotations

import json
import os
import pathlib
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import remote_opencode_client as client  # noqa: E402


def _write_executable(path: pathlib.Path, script: str) -> None:
    """Keep fake provider executables runnable on PBS compute-node PATHs."""
    path.write_text(
        script.replace("#!/usr/bin/env python3", f"#!{sys.executable}", 1),
        encoding="utf-8",
    )
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


class RemoteOpenCodeTests(unittest.TestCase):
    def test_remote_runner_reads_stdin_and_publishes_only_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            fake = root / "fake-opencode.py"
            capture = root / "argv.json"
            _write_executable(
                fake,
                "#!/usr/bin/env python3\n"
                "import json, os, sys\n"
                "path=os.environ['CAPTURE']\n"
                "pathlib=None\n"
                "open(path, 'w').write(json.dumps(sys.argv[1:]))\n"
                "print(json.dumps({'type':'text','part':{'text':'remote answer'}}))\n",
            )
            env = dict(os.environ, CAPTURE=str(capture))
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "opencode_remote_run.py"),
                    "--cwd",
                    str(root),
                    "--model",
                    "opencode-go/deepseek-v4-flash",
                    "--result-source",
                    "out/result.md",
                    "--opencode-bin",
                    str(fake),
                ],
                input="private task text",
                text=True,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            summary = json.loads(result.stdout)
            self.assertEqual("completed", summary["status"])
            self.assertEqual("remote answer\n", (root / "out/result.md").read_text())
            self.assertNotIn("private task text", capture.read_text())

    def test_remote_runner_accepts_current_top_level_text_event(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            fake = root / "fake-opencode.py"
            _write_executable(
                fake,
                "#!/usr/bin/env python3\n"
                "import json\n"
                "print(json.dumps({'type':'text','text':'current wire answer'}))\n",
            )
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "opencode_remote_run.py"),
                    "--cwd", str(root),
                    "--model", "opencode-go/deepseek-v4-flash",
                    "--result-source", "out/result.md",
                    "--opencode-bin", str(fake),
                ],
                input="task",
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            summary = json.loads(result.stdout)
            self.assertEqual("completed", summary["status"])
            self.assertEqual("current wire answer\n", (root / "out/result.md").read_text())

    def test_remote_runner_rejects_result_escape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "opencode_remote_run.py"),
                    "--cwd",
                    str(root),
                    "--model",
                    "opencode-go/deepseek-v4-flash",
                    "--result-source",
                    "../outside.txt",
                ],
                input="x",
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(2, result.returncode)
            self.assertIn("escapes cwd", result.stderr)

    def test_client_dry_run_does_not_open_ssh(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            prompt = root / "task.md"
            prompt.write_text("small task", encoding="utf-8")
            inventory = {
                "hosts": [
                    {
                        "host_id": "remote-b",
                        "transport": "ssh",
                        "hostname": "remote-b.example.test",
                        "user": "runner",
                        "port": 2223,
                        "project_path": "/srv/local-agent-dispatch",
                        "opencode_runner": "/srv/local-agent-dispatch/scripts/opencode_remote_run.py",
                        "opencode_bin": "/srv/local-agent-dispatch/.opencode/bin/opencode",
                    }
                ]
            }
            report = client.request(
                inventory,
                host_id="remote-b",
                prompt_file=prompt,
                cwd="remote-workspace",
                result_source="out/result.md",
                model="opencode-go/deepseek-v4-flash",
            )
            self.assertTrue(report["dry_run"])
            self.assertFalse(report["provider_execution"])
            self.assertEqual(len("small task"), report["prompt_bytes"])
            self.assertIn("command_digest", report)

    def test_client_ignores_local_control_plane_host_in_shared_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            prompt = root / "task.md"
            prompt.write_text("small task", encoding="utf-8")
            inventory = {
                "hosts": [
                    {
                        "host_id": "local_mac",
                        "transport": "local",
                        "project_path": "/srv/example/project",
                    },
                    {
                        "host_id": "remote-b",
                        "transport": "ssh",
                        "hostname": "remote-b.example.test",
                        "user": "runner",
                        "port": 2223,
                        "project_path": "/srv/local-agent-dispatch",
                        "opencode_runner": "/srv/local-agent-dispatch/scripts/opencode_remote_run.py",
                    },
                ]
            }
            report = client.request(
                inventory,
                host_id="remote-b",
                prompt_file=prompt,
                cwd="remote-workspace",
                result_source="out/result.md",
                model="opencode-go/deepseek-v4-flash",
                variant="max",
            )
            self.assertTrue(report["dry_run"])
            self.assertEqual("remote-b", report["host_id"])

    def test_client_ignores_ssh_host_without_remote_wrapper(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            prompt = root / "task.md"
            prompt.write_text("small task", encoding="utf-8")
            inventory = {
                "hosts": [
                    {
                        "host_id": "westd-without-wrapper",
                        "transport": "ssh",
                        "hostname": "westd.example.test",
                        "user": "runner",
                        "port": 2223,
                        "project_path": "/srv/project",
                    },
                    {
                        "host_id": "remote-b",
                        "transport": "ssh",
                        "hostname": "remote-b.example.test",
                        "user": "runner",
                        "port": 2224,
                        "project_path": "/srv/project",
                        "opencode_runner": "/srv/project/run.py",
                    },
                ]
            }
            report = client.request(
                inventory,
                host_id="remote-b",
                prompt_file=prompt,
                cwd="workspace",
                result_source="out/result.md",
                model="opencode-go/deepseek-v4-flash",
            )
            self.assertTrue(report["dry_run"])
            with self.assertRaises(client.RemoteOpenCodeError):
                client.request(
                    inventory,
                    host_id="westd-without-wrapper",
                    prompt_file=prompt,
                    cwd="workspace",
                    result_source="out/result.md",
                    model="opencode-go/deepseek-v4-flash",
                )

    def test_client_rejects_non_go_model(self) -> None:
        with self.assertRaises(client.RemoteOpenCodeError):
            client.build_command(
                {
                    "hostname": "remote-b.example.test",
                    "user": "runner",
                    "port": 2223,
                    "project_path": "/srv/project",
                    "opencode_runner": "/srv/project/scripts/opencode_remote_run.py",
                },
                cwd=".",
                result_source="out/result.md",
                model="gpt-5",
                variant=None,
                opencode_bin="opencode",
                timeout=60,
                auto_approve=False,
            )

    def test_client_isolates_remote_opencode_state_per_lane(self) -> None:
        host = {
            "hostname": "remote-b.example.test",
            "user": "runner",
            "port": 2223,
            "project_path": "/srv/project",
            "opencode_runner": "/srv/project/scripts/opencode_remote_run.py",
            "runtime_root": "/srv/lad-lanes/agent-01",
        }
        command = client.build_command(
            host,
            cwd="workspace",
            result_source="out/result.md",
            model="opencode-go/deepseek-v4-flash",
            variant="max",
            opencode_bin="/srv/project/.opencode/bin/opencode",
            timeout=60,
            auto_approve=False,
        )
        self.assertIn("env", command)
        self.assertIn("HOME=/srv/lad-lanes/agent-01/home", command)
        self.assertIn("XDG_DATA_HOME=/srv/lad-lanes/agent-01/data", command)
        self.assertIn("XDG_CACHE_HOME=/srv/lad-lanes/agent-01/cache", command)
        self.assertIn("TMPDIR=/srv/lad-lanes/agent-01/tmp", command)
        self.assertEqual(command[command.index("python3")], "python3")

    def test_client_separates_lane_state_from_server_auth_data_root(self) -> None:
        host = {
            "hostname": "remote-b.example.test",
            "user": "runner",
            "port": 2223,
            "project_path": "/srv/project",
            "opencode_runner": "/srv/project/scripts/opencode_remote_run.py",
            "runtime_root": "/srv/lad-lanes/agent-02",
            "opencode_auth_root": "/srv/opencode-server-home/.local/share",
        }
        command = client.build_command(
            host,
            cwd="workspace",
            result_source="out/result.md",
            model="opencode-go/deepseek-v4-flash",
            variant="max",
            opencode_bin="/srv/project/.opencode/bin/opencode",
            timeout=60,
            auto_approve=False,
            opencode_auth_root=host["opencode_auth_root"],
        )
        self.assertIn("XDG_DATA_HOME=/srv/lad-lanes/agent-02/data", command)
        self.assertIn("HOME=/srv/lad-lanes/agent-02/home", command)
        self.assertIn("--auth-data-root", command)
        self.assertIn("/srv/opencode-server-home/.local/share", command)
        self.assertNotIn("auth.json", " ".join(command))

    def test_client_can_pin_distinct_runtime_root_per_lane(self) -> None:
        host = {
            "hostname": "remote-b.example.test",
            "user": "runner",
            "port": 2223,
            "project_path": "/srv/project",
            "opencode_runner": "/srv/project/scripts/opencode_remote_run.py",
            "runtime_root": "/srv/lad-lanes",
        }
        command = client.build_command(
            host,
            cwd="workspace",
            result_source="out/result.md",
            model="opencode-go/deepseek-v4-flash",
            variant="max",
            opencode_bin="/srv/project/.opencode/bin/opencode",
            timeout=60,
            auto_approve=False,
            runtime_root_override="wave-v4/lane-05",
        )
        self.assertIn("HOME=/srv/lad-lanes/wave-v4/lane-05/home", command)
        with self.assertRaises(client.RemoteOpenCodeError):
            client.build_command(
                host,
                cwd="workspace",
                result_source="out/result.md",
                model="opencode-go/deepseek-v4-flash",
                variant="max",
                opencode_bin="/srv/project/.opencode/bin/opencode",
                timeout=60,
                auto_approve=False,
                runtime_root_override="/tmp/escape",
            )

    def test_remote_runner_links_auth_without_copying_credential_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            auth_root = root / "server-data"
            source = auth_root / "opencode" / "auth.json"
            source.parent.mkdir(parents=True)
            source.write_text('{"type":"api","key":"DO-NOT-COPY"}\n', encoding="utf-8")
            fake = root / "fake-opencode.py"
            _write_executable(
                fake,
                "#!/usr/bin/env python3\n"
                "import json\n"
                "print(json.dumps({'type':'text','part':{'text':'linked answer'}}))\n",
            )
            lane_data = root / "lane-data"
            env = dict(os.environ, XDG_DATA_HOME=str(lane_data))
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "opencode_remote_run.py"),
                    "--cwd", str(root),
                    "--model", "opencode-go/deepseek-v4-flash",
                    "--result-source", "out/result.md",
                    "--opencode-bin", str(fake),
                    "--auth-data-root", str(auth_root),
                ],
                input="task",
                text=True,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            summary = json.loads(result.stdout)
            link = lane_data / "opencode" / "auth.json"
            self.assertTrue(link.is_symlink())
            self.assertEqual(source.resolve(), link.resolve())
            self.assertEqual("linked", summary["auth_link"]["state"])
            self.assertNotIn("DO-NOT-COPY", json.dumps(summary))

    def test_inventory_preserves_auth_root_without_reading_credentials(self) -> None:
        inventory = {
            "hosts": [
                {
                    "host_id": "remote-b",
                    "transport": "ssh",
                    "hostname": "remote-b.example.test",
                    "user": "runner",
                    "port": 2223,
                    "project_path": "/srv/project",
                    "opencode_runner": "/srv/project/run.py",
                    "opencode_auth_root": "/srv/opencode-data",
                }
            ]
        }
        parsed = client.load_opencode_inventory_from_mapping(inventory)
        self.assertEqual("/srv/opencode-data", parsed["remote-b"]["opencode_auth_root"])

    def test_embedded_inventory_uses_same_path_and_transport_gates(self) -> None:
        with self.assertRaises(client.RemoteOpenCodeError):
            client.load_opencode_inventory_from_mapping(
                {
                    "hosts": [
                        {
                            "host_id": "remote-b",
                            "transport": "ssh",
                            "hostname": "remote-b.example.test",
                            "user": "runner",
                            "port": 2223,
                            "project_path": "/srv/project with space",
                            "opencode_runner": "/srv/project/run.py",
                        }
                    ]
                }
            )


if __name__ == "__main__":
    unittest.main()
