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

import remote_worker_client as client  # noqa: E402
import desktop_split_placement as split  # noqa: E402
from remote_envelope import build_envelope  # noqa: E402
try:  # unittest discover imports this file as tests.test_*
    from tests.test_desktop_split_placement import _inputs as _split_inputs  # type: ignore
    from tests.test_desktop_split_placement import NOW as _SPLIT_NOW  # type: ignore
except ImportError:  # direct ``PYTHONPATH=tests`` invocation
    from test_desktop_split_placement import _inputs as _split_inputs  # type: ignore
    from test_desktop_split_placement import NOW as _SPLIT_NOW  # type: ignore


def _packet(root: pathlib.Path) -> dict:
    return {
        "schema_version": 1,
        "packet_id": "packet-transport",
        "job_id": "job-transport",
        "workspace": str(root),
        "execution_host": "remote-a",
        "workload_host": "remote-b",
        "workload_wrapper": "declared-wrapper",
        "write_scope": "src",
        "required_artifacts": ["out/result.json"],
        "validation_required": True,
        "validation_argv": ["python3", "-m", "unittest"],
        "api_key": "must-never-cross-the-redaction-boundary",
        "attempts": [
            {
                "attempt_id": "attempt-transport",
                "adapter": "server_local",
                "transport": "ssh",
                "model": "local/fake",
                "execution_host": "remote-a",
                "workload_host": "remote-b",
                "prompt_file": "TASK.md",
                "prompt": "private prompt must not be sent as a field",
                "argv": ["provider", "--prompt", "private prompt"],
            }
        ],
    }


def _inventory(root: pathlib.Path, script: pathlib.Path) -> dict:
    return {
        "hosts": [
            {
                "host_id": "remote-a",
                "transport": "ssh",
                "hostname": "remote-a.example.test",
                "user": "runner",
                "port": 2222,
                "worker_script": str(script),
                "project_path": str(root),
                "spool_path": str(root / "spool"),
            },
            {
                "host_id": "remote-b",
                "transport": "ssh",
                "hostname": "remote-b.example.test",
                "user": "runner",
                "port": 2223,
                "worker_script": str(script),
                "project_path": str(root),
                "spool_path": str(root / "spool-remote-b"),
            },
        ]
    }


def _fake_ssh(path: pathlib.Path) -> None:
    # This fake has the same pipe shape as ssh: it receives a target and a
    # remote argv, then executes the fixed local worker script without a shell.
    script = """#!/usr/bin/env python3
import json
import os
import subprocess
import sys

args = sys.argv[1:]
if os.environ.get('FAKE_SSH_ARGS'):
    with open(os.environ['FAKE_SSH_ARGS'], 'w', encoding='utf-8') as handle:
        json.dump(args, handle)
data = sys.stdin.buffer.read()
if os.environ.get('FAKE_SSH_CAPTURE'):
    with open(os.environ['FAKE_SSH_CAPTURE'], 'ab') as handle:
        handle.write(data)
if os.environ.get('FAKE_SSH_FAIL'):
    sys.stderr.write('private prompt argv token should not be returned\\n')
    raise SystemExit(19)
try:
    index = args.index('python3')
except ValueError:
    sys.stderr.write('missing fixed python3 command\\n')
    raise SystemExit(18)
completed = subprocess.run(
    [sys.executable, *args[index + 1:]],
    input=data,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    check=False,
)
sys.stdout.buffer.write(completed.stdout)
sys.stderr.buffer.write(completed.stderr)
raise SystemExit(completed.returncode)
"""
    # PBS compute-node PATHs are intentionally not treated as a runtime
    # contract.  Use the active interpreter for this local fake transport so
    # provider-free replay is portable on login and compute nodes alike.
    path.write_text(script.replace("#!/usr/bin/env python3", f"#!{sys.executable}", 1), encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def _desktop_split_packet(
    *, local_workspace: str = "/workspace/project", remote_root: str = "/srv/project"
) -> dict:
    assignment, local_host, workload_host, route, resource = _split_inputs()
    assignment["local_workspace"] = local_workspace
    assignment["remote_workspace"] = remote_root + "/split-job"
    assignment["receipt_path"] = remote_root + "/split-job/.lad/receipts/split-attempt.json"
    assignment["remote_required_artifacts"] = [remote_root + "/split-job/artifacts/result.json"]
    assignment["remote_result_source_path"] = remote_root + "/split-job/artifacts/result.json"
    local_host["project_path"] = local_workspace
    workload_host["project_path"] = remote_root
    route["project_path"] = remote_root
    resource["storage"]["mount_path"] = remote_root
    resource["storage"]["workspace_path"] = remote_root + "/split-job"
    resource["write_scope_path"] = remote_root + "/split-job/src"
    report = split.build_desktop_split_contract(
        assignment, local_host, workload_host, route, resource, now_utc=_SPLIT_NOW
    )
    if not report["valid"]:
        raise AssertionError(report)
    packet = {
        "schema_version": 1,
        "packet_id": "packet-desktop-split-client",
        "job_id": "split-job",
        "workspace": local_workspace,
        "write_scope": "src",
        "required_artifacts": ["artifacts/result.json"],
        "validation_required": True,
        "validation_argv": ["python3", "-m", "unittest"],
        "attempts": [
            {
                "attempt_id": "split-attempt",
                "adapter": "codex",
                "transport": "local",
                "model": "gpt-5.3-codex-spark",
            }
        ],
    }
    return split.attach_desktop_split_contract(packet, report)


class RemoteWorkerClientTests(unittest.TestCase):
    def test_bootstrap_is_bounded_and_dry_run_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            fake = root / "ssh-fake.py"
            _fake_ssh(fake)
            inventory = _inventory(root, ROOT / "scripts" / "remote_worker.py")
            transport = client.RemoteWorkerClient(inventory, ssh_executable=str(fake))
            report = transport.bootstrap(host_id="remote-a", source_root=ROOT)
            self.assertTrue(report["dry_run"])
            self.assertFalse(report["executed"])
            self.assertFalse(report["provider_execution"])
            self.assertEqual("fixed_worker_bundle", report["stdin_transport"])
            self.assertGreater(report["bytes"], 0)
            self.assertLessEqual(report["bytes"], 4 * 1024 * 1024)
            self.assertTrue(
                all(set(row) == {"path", "bytes", "sha256"} for row in report["files"])
            )
            self.assertNotIn("content_b64", json.dumps(report))

    def test_inventory_can_pin_project_local_worker_interpreter(self) -> None:
        """Older compute nodes may not expose ``python3`` on their PATH."""
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            inventory = _inventory(root, ROOT / "scripts" / "remote_worker.py")
            inventory["hosts"][0]["worker_python"] = (
                "/data/EXAMPLE_001/environments/py312/bin/python"
            )
            transport = client.RemoteWorkerClient(inventory)
            host = transport.hosts["remote-a"]
            command = client._command(
                host,
                "bootstrap",
                timeout=30,
            )
            self.assertEqual(
                "/data/EXAMPLE_001/environments/py312/bin/python", command[-2]
            )
            command = client._command(
                host,
                "envelope-status",
                timeout=30,
                request_id="request-1",
            )
            self.assertEqual(
                "/data/EXAMPLE_001/environments/py312/bin/python",
                command[command.index(str(host["worker_script"])) - 1],
            )

    def test_legacy_rsa_ssh_compatibility_is_explicit_and_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            inventory = _inventory(root, ROOT / "scripts" / "remote_worker.py")
            inventory["hosts"][0]["ssh_legacy_rsa"] = True
            transport = client.RemoteWorkerClient(inventory)
            host = transport.hosts["remote-a"]
            command = client._command(host, "bootstrap", timeout=30)
            self.assertIn("HostKeyAlgorithms=+ssh-rsa", command)
            self.assertIn("PubkeyAcceptedAlgorithms=+ssh-rsa", command)

            inventory["hosts"][0]["ssh_legacy_rsa"] = "true"
            with self.assertRaises(client.ClientError):
                client.RemoteWorkerClient(inventory)

    def test_inventory_rejects_shell_syntax_in_worker_interpreter(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            inventory = _inventory(root, ROOT / "scripts" / "remote_worker.py")
            inventory["hosts"][0]["worker_python"] = "python3;touch"
            with self.assertRaises(client.ClientError):
                client.RemoteWorkerClient(inventory)

    def test_bootstrap_installs_schema_bundle_before_real_worker_call(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as remote_tmp:
            root = pathlib.Path(tmp)
            remote_root = pathlib.Path(remote_tmp) / "worker-root"
            remote_root.mkdir()
            fake = root / "ssh-fake.py"
            _fake_ssh(fake)
            inventory = _inventory(root, ROOT / "scripts" / "remote_worker.py")
            host = inventory["hosts"][0]
            host["worker_script"] = str(remote_root / "scripts" / "remote_worker.py")
            host["schema_dir"] = str(remote_root / "schemas")
            host["project_path"] = str(remote_root)
            host["spool_path"] = str(remote_root / "spool")
            transport = client.RemoteWorkerClient(inventory, ssh_executable=str(fake))
            installed = transport.bootstrap(host_id="remote-a", source_root=ROOT, execute=True)
            self.assertEqual("bootstrapped", installed["remote"]["status"])
            self.assertTrue((remote_root / "scripts" / "dispatch_schema.py").is_file())
            self.assertTrue((remote_root / "scripts" / "portable_file_lock.py").is_file())
            self.assertTrue((remote_root / "schemas" / "task_packet.schema.json").is_file())
            envelope = build_envelope(
                request_id="req-bootstrap",
                source_id="controller-a",
                target_id="remote-a",
                operation="execute.prepared",
                packet_digest="a" * 64,
                payload_summary={
                    "job_id": "job-bootstrap",
                    "packet_id": "packet-bootstrap",
                    "model": "opencode-go/deepseek-v4-flash",
                    "variant": "max",
                    "write_scope": "out",
                },
            )
            received = transport.envelope_receive(
                host_id="remote-a", envelope=envelope, execute=True
            )
            self.assertEqual("accepted", received["remote"]["status"])

    def test_envelope_transport_is_dry_run_by_default_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            fake = root / "ssh-fake.py"
            _fake_ssh(fake)
            inventory = _inventory(root, ROOT / "scripts" / "remote_worker.py")
            envelope = build_envelope(
                request_id="req-envelope",
                source_id="controller-a",
                target_id="remote-a",
                operation="execute.prepared",
                packet_digest="a" * 64,
                payload_summary={
                    "job_id": "job-envelope",
                    "packet_id": "packet-envelope",
                    "model": "opencode-go/deepseek-v4-flash",
                    "variant": "max",
                    "execution_host": "remote-a",
                    "workload_host": "remote-b",
                    "write_scope": "out",
                },
            )
            transport = client.RemoteWorkerClient(inventory, ssh_executable=str(fake))
            dry = transport.envelope_receive(host_id="remote-a", envelope=envelope)
            self.assertTrue(dry["dry_run"])
            self.assertEqual("redacted_envelope", dry["stdin_transport"])
            self.assertEqual("opencode-go/deepseek-v4-flash", dry["model"])
            self.assertEqual("max", dry["variant"])

            received = transport.envelope_receive(
                host_id="remote-a", envelope=envelope, execute=True
            )
            self.assertEqual("accepted", received["remote"]["status"])
            duplicate = transport.envelope_receive(
                host_id="remote-a", envelope=envelope, execute=True
            )
            self.assertTrue(duplicate["remote"]["duplicate"])
            completed = transport.envelope_complete(
                host_id="remote-a",
                request_id="req-envelope",
                result_digest="b" * 64,
                execute=True,
            )
            self.assertEqual("completed", completed["remote"]["status"])
            status = transport.envelope_status(
                host_id="remote-a",
                request_id="req-envelope",
                execute=True,
            )
            self.assertEqual("completed", status["remote"]["status"])
            self.assertFalse(status["remote"]["provider_execution"])

    def test_envelope_transport_requires_exact_model_and_variant(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            inventory = _inventory(root, ROOT / "scripts" / "remote_worker.py")
            transport = client.RemoteWorkerClient(inventory)
            for key in ("model", "variant"):
                summary = {
                    "job_id": "job-envelope",
                    "packet_id": "packet-envelope",
                    "model": "opencode-go/deepseek-v4-flash",
                    "variant": "max",
                    "write_scope": "out",
                }
                summary[key] = ""
                envelope = build_envelope(
                    request_id="req-envelope",
                    source_id="controller-a",
                    target_id="remote-a",
                    operation="execute.prepared",
                    packet_digest="a" * 64,
                    payload_summary=summary,
                )
                # build_envelope accepts arbitrary summary values; transport
                # applies the execution-specific exact model/variant gate.
                with self.assertRaises(client.ClientError):
                    transport.envelope_receive(host_id="remote-a", envelope=envelope)

            gemini = build_envelope(
                request_id="req-gemini-null",
                source_id="controller-a",
                target_id="remote-a",
                operation="execute.prepared",
                packet_digest="a" * 64,
                payload_summary={
                    "job_id": "job-gemini-null",
                    "packet_id": "packet-gemini-null",
                    "provider": "antigravity",
                    "pool_id": "antigravity.gemini",
                    "model": "gemini-3.6-flash-high",
                    "variant": None,
                    "write_scope": "out",
                },
            )
            accepted = transport.envelope_receive(
                host_id="remote-a", envelope=gemini
            )
            self.assertTrue(accepted["dry_run"])
            self.assertIsNone(accepted["variant"])

            wrong_null = dict(gemini)
            wrong_summary = dict(gemini["payload_summary"])
            wrong_summary["provider"] = "codex"
            wrong_null["payload_summary"] = wrong_summary
            with self.assertRaises(client.ClientError):
                transport.envelope_receive(host_id="remote-a", envelope=wrong_null)

    def test_dry_run_is_default_and_packet_stays_on_stdin(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            fake = root / "ssh-fake.py"
            _fake_ssh(fake)
            inventory = _inventory(root, ROOT / "scripts" / "remote_worker.py")
            packet = _packet(root)
            capture = root / "captured-input"
            args_path = root / "ssh-args.json"
            old_capture = os.environ.get("FAKE_SSH_CAPTURE")
            old_args = os.environ.get("FAKE_SSH_ARGS")
            os.environ["FAKE_SSH_CAPTURE"] = str(capture)
            os.environ["FAKE_SSH_ARGS"] = str(args_path)
            try:
                transport = client.RemoteWorkerClient(inventory, ssh_executable=str(fake))
                dry = transport.prepare(host_id="remote-a", packet=packet)
                self.assertTrue(dry["dry_run"])
                self.assertFalse(capture.exists())
                self.assertEqual("remote-a", dry["execution_host"])
                self.assertEqual("remote-b", dry["workload_host"])
                self.assertTrue(dry["placement"]["split_placement"])
                self.assertEqual(3, dry["redactions_applied"])

                prepared = transport.prepare(host_id="remote-a", packet=packet, execute=True)
                self.assertFalse(prepared["dry_run"])
                self.assertEqual("prepared", prepared["remote"]["status"])
                sent = json.loads(capture.read_text(encoding="utf-8"))
                sent_text = json.dumps(sent, ensure_ascii=False)
                self.assertEqual("packet-transport", sent["packet_id"])
                self.assertNotIn("private prompt", sent_text)
                self.assertNotIn('"argv":', sent_text)
                self.assertNotIn("--prompt", sent_text)
                self.assertNotIn("api_key", sent_text)

                ssh_args = json.loads(args_path.read_text(encoding="utf-8"))
                self.assertNotIn("sh", ssh_args)
                self.assertNotIn("-c", ssh_args)
                self.assertIn("python3", ssh_args)
                self.assertIn("-", ssh_args)
                # The packet is not interpolated into any SSH argument.
                self.assertNotIn("private prompt", json.dumps(ssh_args))
            finally:
                if old_capture is None:
                    os.environ.pop("FAKE_SSH_CAPTURE", None)
                else:
                    os.environ["FAKE_SSH_CAPTURE"] = old_capture
                if old_args is None:
                    os.environ.pop("FAKE_SSH_ARGS", None)
                else:
                    os.environ["FAKE_SSH_ARGS"] = old_args

    def test_desktop_split_prepare_targets_remote_workload_not_local_cli(self) -> None:
        """A local-authenticated CLI may project only the workload to SSH."""
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            inventory = {
                "hosts": [
                    {
                        "host_id": "local_mac",
                        "transport": "local",
                        "project_path": "/workspace/project",
                    },
                    {
                        "host_id": "remote_gpu",
                        "transport": "ssh",
                        "hostname": "remote-gpu.example.test",
                        "user": "runner",
                        "port": 2222,
                        "worker_script": "/srv/project/scripts/remote_worker.py",
                        "project_path": "/srv/project",
                        "spool_path": "/srv/project/.lad/spool",
                    },
                ]
            }
            transport = client.RemoteWorkerClient(inventory)
            report = transport.prepare(
                host_id="remote_gpu", packet=_desktop_split_packet()
            )
            self.assertTrue(report["dry_run"])
            self.assertEqual("local_mac", report["execution_host"])
            self.assertEqual("remote_gpu", report["workload_host"])
            self.assertEqual("local", report["placement"]["execution_transport"])
            self.assertEqual("ssh", report["placement"]["workload_transport"])
            self.assertTrue(report["placement"]["split_placement"])
            self.assertEqual("remote_gpu", report["host_id"])

    def test_desktop_split_prepare_execute_maps_only_workload_paths(self) -> None:
        """The SSH leg receives a confined packet, never a local workspace."""
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            local_root = root / "local"
            remote_root = root / "remote"
            local_root.mkdir()
            (remote_root / "split-job" / "src").mkdir(parents=True)
            fake = root / "ssh-fake.py"
            capture = root / "captured.json"
            _fake_ssh(fake)
            old_capture = os.environ.get("FAKE_SSH_CAPTURE")
            os.environ["FAKE_SSH_CAPTURE"] = str(capture)
            try:
                packet = _desktop_split_packet(
                    local_workspace=str(local_root), remote_root=str(remote_root)
                )
                inventory = {
                    "hosts": [
                        {
                            "host_id": "local_mac",
                            "transport": "local",
                            "project_path": str(local_root),
                        },
                        {
                            "host_id": "remote_gpu",
                            "transport": "ssh",
                            "hostname": "remote-gpu.example.test",
                            "user": "runner",
                            "port": 2222,
                            "worker_script": str(ROOT / "scripts" / "remote_worker.py"),
                            "project_path": str(remote_root),
                            "spool_path": str(remote_root / ".lad" / "spool"),
                        },
                    ]
                }
                transport = client.RemoteWorkerClient(
                    inventory, ssh_executable=str(fake)
                )
                result = transport.prepare(
                    host_id="remote_gpu", packet=packet, execute=True
                )
                self.assertEqual("prepared", result["remote"]["status"])
                sent = json.loads(capture.read_text(encoding="utf-8"))
                self.assertEqual(str(remote_root), sent["workspace"])
                self.assertNotIn(str(local_root), json.dumps(sent))
                self.assertEqual("local_mac", result["execution_host"])
                self.assertEqual("remote_gpu", result["workload_host"])
            finally:
                if old_capture is None:
                    os.environ.pop("FAKE_SSH_CAPTURE", None)
                else:
                    os.environ["FAKE_SSH_CAPTURE"] = old_capture

    def test_prepare_maps_local_absolute_paths_into_remote_project_root(self) -> None:
        """A real SSH target must not receive the Mac workspace path."""
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as remote_tmp:
            root = pathlib.Path(tmp)
            remote_root = pathlib.Path(remote_tmp)
            (root / "src").mkdir()
            (remote_root / "src").mkdir()
            fake = root / "ssh-fake.py"
            _fake_ssh(fake)
            inventory = _inventory(root, ROOT / "scripts" / "remote_worker.py")
            for host in inventory["hosts"]:
                host["project_path"] = str(remote_root)
                host["spool_path"] = str(remote_root / "spool" / host["host_id"])
            capture = root / "mapped-packet.json"
            old_capture = os.environ.get("FAKE_SSH_CAPTURE")
            os.environ["FAKE_SSH_CAPTURE"] = str(capture)
            try:
                transport = client.RemoteWorkerClient(inventory, ssh_executable=str(fake))
                prepared = transport.prepare(host_id="remote-a", packet=_packet(root), execute=True)
                self.assertEqual("prepared", prepared["remote"]["status"])
                sent = json.loads(capture.read_text(encoding="utf-8"))
                self.assertEqual(str(remote_root), sent["workspace"])
                self.assertNotEqual(str(root), sent["workspace"])
                self.assertNotIn(str(root), json.dumps(sent))
            finally:
                if old_capture is None:
                    os.environ.pop("FAKE_SSH_CAPTURE", None)
                else:
                    os.environ["FAKE_SSH_CAPTURE"] = old_capture

    def test_prepare_fake_execute_and_resume_handoff_preserve_split_placement(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            fake = root / "ssh-fake.py"
            _fake_ssh(fake)
            inventory = _inventory(root, ROOT / "scripts" / "remote_worker.py")
            packet = _packet(root)
            transport = client.RemoteWorkerClient(inventory, ssh_executable=str(fake))
            transport.prepare(host_id="remote-a", packet=packet, execute=True)
            result = transport.fake_execute(
                host_id="remote-a",
                job_id="job-transport",
                owner="continuation-worker",
                packet=packet,
                execute=True,
            )
            self.assertEqual("completed", result["remote"]["status"])
            self.assertEqual("remote-a", result["execution_host"])
            self.assertEqual("remote-b", result["workload_host"])
            handoff_path = root / "handoff.json"
            handoff = transport.handoff(
                host_id="remote-a",
                job_id="job-transport",
                packet=packet,
                execute=True,
                output=handoff_path,
            )
            self.assertEqual("completed", handoff["remote"]["status"])
            self.assertFalse(handoff["remote"]["resume_allowed"])
            self.assertEqual("review_artifacts", handoff["remote"]["next_action"])
            self.assertTrue(handoff_path.is_file())
            handoff_text = handoff_path.read_text(encoding="utf-8")
            self.assertNotIn("private prompt", handoff_text)
            self.assertNotIn("argv", handoff_text)
            self.assertNotIn("lease_token", handoff_text)
            resumed = transport.resume(host_id="remote-a", job_id="job-transport", execute=True)
            self.assertEqual("completed", resumed["remote"]["status"])
            self.assertFalse(resumed["remote"]["recovery"]["performed"])

    def test_fake_service_transport_is_explicit_and_provider_free(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            fake = root / "ssh-fake.py"
            _fake_ssh(fake)
            inventory = _inventory(root, ROOT / "scripts" / "remote_worker.py")
            packet = _packet(root)
            transport = client.RemoteWorkerClient(inventory, ssh_executable=str(fake))

            dry = transport.fake_service(
                host_id="remote-a",
                job_id="job-transport",
                owner="server-service",
            )
            self.assertTrue(dry["dry_run"])
            self.assertFalse(dry["executed"])
            self.assertEqual("fake-service", dry["operation"])
            self.assertTrue(dry["chat_independent"])
            self.assertFalse(dry["provider_execution"])
            self.assertEqual("provider_free_fixture", dry["service_boundary"])

            transport.prepare(host_id="remote-a", packet=packet, execute=True)
            result = transport.fake_service(
                host_id="remote-a",
                job_id="job-transport",
                owner="server-service",
                packet=packet,
                poll_seconds=0.01,
                max_idle_rounds=3,
                execute=True,
            )
            self.assertEqual("completed", result["remote"]["status"])
            self.assertFalse(result["remote"]["provider_execution"])
            self.assertEqual("remote-a", result["execution_host"])
            self.assertEqual("remote-b", result["workload_host"])

    def test_status_recover_and_handoff_are_supported_without_packet_input(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            fake = root / "ssh-fake.py"
            _fake_ssh(fake)
            transport = client.RemoteWorkerClient(
                _inventory(root, ROOT / "scripts" / "remote_worker.py"),
                ssh_executable=str(fake),
            )
            transport.prepare(host_id="remote-a", packet=_packet(root), execute=True)
            status = transport.status(host_id="remote-a", job_id="job-transport", execute=True)
            self.assertEqual(1, len(status["remote"]["jobs"]))
            recovered = transport.recover(host_id="remote-a", job_id="job-transport", execute=True)
            self.assertEqual("prepared", recovered["remote"]["jobs"][0]["status"])
            # The transport still opens stdin as a pipe, but only sends an
            # empty payload for operations that do not consume a task packet.
            self.assertEqual("empty", status["stdin_transport"])

    def test_process_identity_transport_binds_token_in_command_not_stdin(self) -> None:
        """The liveness witness is bounded and the lease fence stays out of stdin."""
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            inventory = _inventory(root, ROOT / "scripts" / "remote_worker.py")
            captured: dict[str, object] = {}

            def runner(argv, **kwargs):
                captured["argv"] = list(argv)
                captured["stdin"] = kwargs.get("input", b"")
                return subprocess.CompletedProcess(
                    argv,
                    0,
                    b'{"status":"observed"}',
                    b"",
                )

            transport = client.RemoteWorkerClient(inventory, runner=runner)
            lease_token = "a" * 32
            identity = {
                "pid": 321,
                "start_time": "boot-12345",
                "process_group": 321,
                "run_id": "run-identity",
                "owned_by_dispatch": True,
                "liveness_state": "alive",
                "observed_at_utc": "2026-08-16T12:00:00Z",
                "ttl_seconds": 300,
            }
            report = transport.record_process_identity(
                host_id="remote-a",
                job_id="job-transport",
                owner="worker-a",
                lease_token=lease_token,
                process_identity=identity,
                execute=True,
            )
            self.assertEqual("observed", report["remote"]["status"])
            self.assertEqual("process_identity", report["stdin_transport"])
            stdin = bytes(captured["stdin"])
            self.assertNotIn(lease_token.encode("utf-8"), stdin)
            self.assertNotIn(b"fence", stdin)
            argv = [str(value) for value in captured["argv"]]
            self.assertIn("--lease-token", argv)
            self.assertIn(lease_token, argv)
            self.assertNotIn(lease_token, json.dumps(report, sort_keys=True))

    def test_process_identity_transport_rejects_secret_or_argv_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            transport = client.RemoteWorkerClient(
                _inventory(root, ROOT / "scripts" / "remote_worker.py")
            )
            identity = {
                "pid": 321,
                "start_time": "boot-12345",
                "process_group": 321,
                "run_id": "run-identity",
                "owned_by_dispatch": True,
                "liveness_state": "exited",
                "observed_at_utc": "2026-08-16T12:00:00Z",
                "ttl_seconds": 300,
                "argv": ["provider", "--secret", "should-not-cross"],
            }
            with self.assertRaises(client.ClientError):
                transport.record_process_identity(
                    host_id="remote-a",
                    job_id="job-transport",
                    owner="worker-a",
                    lease_token="a" * 32,
                    process_identity=identity,
                )

    def test_remote_stderr_is_reduced_to_digest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            fake = root / "ssh-fake.py"
            _fake_ssh(fake)
            transport = client.RemoteWorkerClient(
                _inventory(root, ROOT / "scripts" / "remote_worker.py"),
                ssh_executable=str(fake),
            )
            old = os.environ.get("FAKE_SSH_FAIL")
            os.environ["FAKE_SSH_FAIL"] = "1"
            try:
                with self.assertRaises(client.ClientError) as raised:
                    transport.status(host_id="remote-a", job_id="job-transport", execute=True)
            finally:
                if old is None:
                    os.environ.pop("FAKE_SSH_FAIL", None)
                else:
                    os.environ["FAKE_SSH_FAIL"] = old
            message = str(raised.exception)
            self.assertNotIn("private prompt", message)
            self.assertNotIn("argv", message)
            self.assertNotIn("token should", message)
            self.assertIn("sha256", message)

    def test_inventory_rejects_unsafe_port_and_remote_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            script = ROOT / "scripts" / "remote_worker.py"
            bad_port = _inventory(root, script)
            bad_port["hosts"][0]["port"] = 70000
            with self.assertRaises(client.ClientError):
                client.RemoteWorkerClient(bad_port)
            bad_path = _inventory(root, script)
            bad_path["hosts"][0]["spool_path"] = "/srv/lad/../escape"
            with self.assertRaises(client.ClientError):
                client.RemoteWorkerClient(bad_path)
            local = {"hosts": [_inventory(root, script)["hosts"][0]]}
            local["hosts"][0]["transport"] = "local"
            with self.assertRaises(client.ClientError):
                client.RemoteWorkerClient(local)

    def test_mixed_controller_and_ssh_inventory_selects_ssh_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            script = ROOT / "scripts" / "remote_worker.py"
            inventory = _inventory(root, script)
            inventory["hosts"].insert(
                0,
                {
                    "host_id": "local_mac",
                    "transport": "local",
                    "project_path": str(root),
                },
            )
            transport = client.RemoteWorkerClient(inventory)
            report = transport.status(host_id="remote-a")
            self.assertTrue(report["dry_run"])
            self.assertEqual("remote-a", report["host_id"])


if __name__ == "__main__":
    unittest.main()
