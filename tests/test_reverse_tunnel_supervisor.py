from __future__ import annotations

import json
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
import sys

sys.path.insert(0, str(ROOT / "scripts"))

from reverse_tunnel_supervisor import (  # noqa: E402
    SupervisorError,
    ReverseTunnelSupervisor,
    build_ssh_argv,
)


class _FakeProcess:
    pid = 4242
    returncode = 0

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        return self.returncode

    def terminate(self):
        self.returncode = -15

    def kill(self):
        self.returncode = -9


class ReverseTunnelSupervisorTests(unittest.TestCase):
    def test_build_ssh_argv_is_fixed_loopback_reverse_forward(self) -> None:
        argv = build_ssh_argv(
            ssh_executable="ssh",
            ssh_config="/etc/lad/central_ssh_config",
            identity_file="/etc/lad/central_ed25519",
            target="central-via-air-tailnet",
            central_port=29176,
            worker_port=29175,
        )
        self.assertEqual("ssh", argv[0])
        self.assertIn("-N", argv)
        self.assertIn("-T", argv)
        self.assertIn("-o", argv)
        self.assertIn("BatchMode=yes", argv)
        self.assertIn("ExitOnForwardFailure=yes", argv)
        self.assertIn("127.0.0.1:29176:127.0.0.1:29175", argv)
        self.assertEqual("central-via-air-tailnet", argv[-1])
        self.assertNotIn("sh", argv)

    def test_build_ssh_argv_rejects_injection_and_non_loopback_ports(self) -> None:
        with self.assertRaises(SupervisorError):
            build_ssh_argv(
                ssh_executable="ssh;touch",
                ssh_config="/etc/lad/config",
                identity_file="/etc/lad/key",
                target="central",
                central_port=29176,
                worker_port=29175,
            )
        with self.assertRaises(SupervisorError):
            build_ssh_argv(
                ssh_executable="ssh",
                ssh_config="/etc/lad/config",
                identity_file="/etc/lad/key",
                target="central;touch",
                central_port=29176,
                worker_port=29175,
            )
        with self.assertRaises(SupervisorError):
            build_ssh_argv(
                ssh_executable="ssh",
                ssh_config="/etc/lad/config",
                identity_file="/etc/lad/key",
                target="central",
                central_port=0,
                worker_port=29175,
            )

    def test_supervisor_records_bounded_child_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            captured = {}

            def spawn(argv, **kwargs):
                captured["argv"] = list(argv)
                captured["kwargs"] = kwargs
                return _FakeProcess()

            supervisor = ReverseTunnelSupervisor(
                ["ssh", "-N", "-T", "-R", "127.0.0.1:29176:127.0.0.1:29175", "central"],
                status_path=root / "status.json",
                log_path=root / "tunnel.log",
                max_attempts=1,
                restart_backoff_seconds=0,
                popen_factory=spawn,
            )
            result = supervisor.run()
            self.assertEqual("failed", result["state"])
            self.assertEqual(1, result["attempts"])
            self.assertEqual(["ssh", "-N", "-T", "-R", "127.0.0.1:29176:127.0.0.1:29175", "central"], captured["argv"])
            self.assertTrue(captured["kwargs"]["start_new_session"])
            stored = json.loads((root / "status.json").read_text(encoding="utf-8"))
            self.assertEqual("failed", stored["state"])
            self.assertNotIn("argv", stored)
            self.assertNotIn("identity_file", stored)


if __name__ == "__main__":
    unittest.main()
