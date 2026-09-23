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

import pbs_worker_wrapper as wrapper  # noqa: E402
import remote_worker as worker  # noqa: E402


def _packet(root: pathlib.Path, job_id: str = "pbs-job") -> dict:
    return {
        "schema_version": 1,
        "packet_id": f"packet-{job_id}",
        "job_id": job_id,
        "workspace": str(root),
        "write_scope": "src",
        "required_artifacts": ["out/result.json"],
        "validation_required": True,
        "validation_argv": ["python3", "-m", "unittest"],
        "attempts": [
            {
                "attempt_id": "attempt-1",
                "adapter": "server_local",
                "transport": "local",
                "model": "local/fake",
                "prompt_file": "TASK.md",
                "argv": ["provider", "--model", "local/fake"],
            }
        ],
    }


def _fake_qsub(path: pathlib.Path, capture: pathlib.Path) -> None:
    path.write_text(
        f"""#!{sys.executable}
import json, os, pathlib, sys
pathlib.Path(os.environ['FAKE_QSUB_CAPTURE']).write_text(json.dumps({{'argv': sys.argv[1:], 'stdin': sys.stdin.read()}}))
print('5555.node1')
""",
        encoding="utf-8",
    )
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


class PBSWorkerWrapperTests(unittest.TestCase):
    def test_run_writes_provider_free_receipt_and_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            spool = root / "spool"
            worker.prepare_job(_packet(root), spool, root)
            run_root = root / "run"
            env = os.environ.copy()
            env["PBS_JOBID"] = "5554.node1"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "pbs_worker_wrapper.py"),
                    "run",
                    "--python",
                    sys.executable,
                    "--worker-script",
                    str(ROOT / "scripts" / "remote_worker.py"),
                    "--spool",
                    str(spool),
                    "--job-id",
                    "pbs-job",
                    "--owner",
                    "pbs-test",
                    "--run-root",
                    str(run_root),
                    "--poll-seconds",
                    "0.01",
                    "--max-idle-rounds",
                    "1",
                ],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            receipt = json.loads((run_root / "receipt.json").read_text(encoding="utf-8"))
            self.assertTrue(receipt["ok"])
            self.assertEqual("completed", receipt["status"])
            self.assertFalse(receipt["provider_execution"])
            self.assertFalse(receipt["network_execution"])
            self.assertEqual("5554.node1", receipt["pbs_job_id"])
            self.assertFalse((run_root / ".receipt.json.partial").exists())
            self.assertTrue((root / "out" / "result.json").is_file())
            self.assertEqual(2, len(receipt["artifacts"]))
            self.assertTrue(all(row["exists"] for row in receipt["artifacts"]))
            receipt_text = (run_root / "receipt.json").read_text(encoding="utf-8")
            self.assertNotIn("prompt", receipt_text)
            self.assertNotIn("argv", receipt_text)

    def test_run_uses_job_specific_node_local_tmp_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            spool = root / "spool"
            worker.prepare_job(_packet(root), spool, root)
            run_root = root / "durable-run"
            node_tmp = root / "node-local-tmp"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "pbs_worker_wrapper.py"),
                    "run",
                    "--python", sys.executable,
                    "--worker-script", str(ROOT / "scripts" / "remote_worker.py"),
                    "--spool", str(spool),
                    "--job-id", "pbs-job",
                    "--owner", "pbs-tmp-test",
                    "--run-root", str(run_root),
                    "--tmp-root", str(node_tmp),
                    "--poll-seconds", "0.01",
                    "--max-idle-rounds", "1",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            receipt = json.loads((run_root / "receipt.json").read_text(encoding="utf-8"))
            self.assertEqual(str((node_tmp / "pbs-job").resolve()), receipt["tmp_root"])
            self.assertTrue((node_tmp / "pbs-job").is_dir())
            self.assertFalse((run_root / "tmp").exists())

    def test_submit_uses_fixed_qsub_argv_and_persists_submission_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            fake_qsub = root / "qsub"
            capture = root / "qsub-capture.json"
            _fake_qsub(fake_qsub, capture)
            run_root = root / "run"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "pbs_worker_wrapper.py"),
                    "submit",
                    "--python",
                    sys.executable,
                    "--worker-script",
                    str(ROOT / "scripts" / "remote_worker.py"),
                    "--spool",
                    str(root / "spool"),
                    "--job-id",
                    "submit-job",
                    "--owner",
                    "submit-test",
                    "--run-root",
                    str(run_root),
                    "--qsub",
                    str(fake_qsub),
                    "--queue",
                    "workq",
                    "--nodes",
                    "1",
                    "--ppn",
                    "1",
                ],
                env={**os.environ, "FAKE_QSUB_CAPTURE": str(capture)},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            submission = json.loads((run_root / "submission.json").read_text(encoding="utf-8"))
            self.assertEqual("5555.node1", submission["pbs_job_id"])
            self.assertEqual("accepted", submission["status"])
            self.assertFalse(submission["provider_execution"])
            self.assertFalse(submission["network_execution"])
            captured = json.loads(capture.read_text(encoding="utf-8"))
            self.assertEqual(
                ["-q", "workq", "-N", "lad-submit-job", "-l", "nodes=1:ppn=1", "-o", str(run_root.resolve() / "stdout"), "-e", str(run_root.resolve() / "stderr")],
                captured["argv"],
            )
            self.assertIn("pbs_worker_wrapper.py run", captured["stdin"])
            self.assertIn(
                f" -B {(ROOT / 'scripts' / 'pbs_worker_wrapper.py').resolve()} run",
                captured["stdin"],
            )
            self.assertNotIn("--tmp-root", captured["stdin"])
            self.assertNotIn("--execute", captured["stdin"])
            self.assertNotIn("provider", captured["stdin"])

    def test_submit_carries_explicit_tmp_root_into_batch_script(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            fake_qsub = root / "qsub"
            capture = root / "qsub-capture.json"
            _fake_qsub(fake_qsub, capture)
            run_root = root / "run"
            node_tmp = root / "node-tmp"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "pbs_worker_wrapper.py"),
                    "submit",
                    "--python", sys.executable,
                    "--worker-script", str(ROOT / "scripts" / "remote_worker.py"),
                    "--spool", str(root / "spool"),
                    "--job-id", "tmp-submit-job",
                    "--owner", "submit-tmp-test",
                    "--run-root", str(run_root),
                    "--tmp-root", str(node_tmp),
                    "--qsub", str(fake_qsub),
                    "--queue", "workq",
                    "--nodes", "1",
                    "--ppn", "1",
                ],
                env={**os.environ, "FAKE_QSUB_CAPTURE": str(capture)},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            captured = json.loads(capture.read_text(encoding="utf-8"))
            self.assertIn(f"--tmp-root {node_tmp.resolve()}", captured["stdin"])

    def test_submit_is_idempotent_when_run_root_already_has_same_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            fake_qsub = root / "qsub"
            capture = root / "qsub-capture.json"
            _fake_qsub(fake_qsub, capture)
            common = [
                sys.executable,
                str(ROOT / "scripts" / "pbs_worker_wrapper.py"),
                "submit",
                "--python", sys.executable,
                "--worker-script", str(ROOT / "scripts" / "remote_worker.py"),
                "--spool", str(root / "spool"),
                "--job-id", "idempotent-job",
                "--owner", "submit-test",
                "--run-root", str(root / "run"),
                "--qsub", str(fake_qsub),
                "--request-id", "idempotent-job:attempt-1",
                "--idempotency-key", "idempotent-job:attempt-1",
                "--payload-digest", "a" * 64,
            ]
            env = {**os.environ, "FAKE_QSUB_CAPTURE": str(capture)}
            first = subprocess.run(common, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
            capture.unlink()
            second = subprocess.run(common, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
            self.assertEqual(0, first.returncode, first.stderr)
            self.assertEqual(0, second.returncode, second.stderr)
            self.assertTrue(json.loads(second.stdout)["idempotent"])
            self.assertFalse(capture.exists(), "idempotent replay must not invoke qsub")

    def test_status_reads_submission_then_terminal_worker_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            fake_qsub = root / "qsub"
            capture = root / "qsub-capture.json"
            _fake_qsub(fake_qsub, capture)
            run_root = root / "run"
            command = [
                sys.executable, str(ROOT / "scripts" / "pbs_worker_wrapper.py"), "submit",
                "--python", sys.executable, "--worker-script", str(ROOT / "scripts" / "remote_worker.py"),
                "--spool", str(root / "spool"), "--job-id", "status-job", "--owner", "status-test",
                "--run-root", str(run_root), "--qsub", str(fake_qsub),
                "--request-id", "status-job:attempt-1", "--payload-digest", "b" * 64,
            ]
            env = {**os.environ, "FAKE_QSUB_CAPTURE": str(capture)}
            submitted = subprocess.run(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
            self.assertEqual(0, submitted.returncode, submitted.stderr)
            status = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "pbs_worker_wrapper.py"), "status",
                 "--job-id", "status-job", "--owner", "status-test", "--run-root", str(run_root),
                 "--request-id", "status-job:attempt-1", "--payload-digest", "b" * 64],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
            )
            self.assertEqual(0, status.returncode, status.stderr)
            self.assertEqual("accepted", json.loads(status.stdout)["status"])

            worker_receipt = {
                "schema_version": "1.0",
                "receipt_type": "local-agent-dispatch.pbs-worker",
                "provider_execution": False,
                "network_execution": False,
                "pbs_job_id": "5555.node1",
                "host": "node1",
                "job_id": "status-job",
                "owner_digest": wrapper._digest_text("status-test"),
                "request_id": "status-job:attempt-1",
                "payload_digest": "b" * 64,
                "run_root": str(run_root.resolve()),
                "status": "completed",
                "worker_result_sha256": "d" * 64,
            }
            (run_root / "receipt.json").write_text(json.dumps(worker_receipt), encoding="utf-8")
            terminal = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "pbs_worker_wrapper.py"), "status",
                 "--job-id", "status-job", "--owner", "status-test", "--run-root", str(run_root),
                 "--request-id", "status-job:attempt-1", "--payload-digest", "b" * 64],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
            )
            self.assertEqual(0, terminal.returncode, terminal.stderr)
            self.assertEqual("completed", json.loads(terminal.stdout)["status"])
            self.assertEqual("d" * 64, json.loads(terminal.stdout)["result_digest"])

    def test_status_rehashes_worker_artifact_and_blocks_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            spool = root / "spool"
            worker.prepare_job(_packet(root), spool, root)
            run_root = root / "run"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "pbs_worker_wrapper.py"),
                    "run",
                    "--python", sys.executable,
                    "--worker-script", str(ROOT / "scripts" / "remote_worker.py"),
                    "--spool", str(spool),
                    "--job-id", "pbs-job",
                    "--owner", "pbs-status-test",
                    "--run-root", str(run_root),
                    "--poll-seconds", "0.01",
                    "--max-idle-rounds", "1",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            command = [
                sys.executable,
                str(ROOT / "scripts" / "pbs_worker_wrapper.py"),
                "status",
                "--job-id", "pbs-job",
                "--owner", "pbs-status-test",
                "--run-root", str(run_root),
            ]
            status = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
            self.assertEqual(0, status.returncode, status.stderr)
            payload = json.loads(status.stdout)
            self.assertTrue(payload["validation"]["ok"])
            self.assertEqual("pbs_worker_wrapper.artifact_rehash_v1", payload["validation"]["validator"])
            self.assertEqual("out/result.json", payload["artifact_manifest"][0]["path"])

            (root / "out" / "result.json").write_text("tampered\n", encoding="utf-8")
            tampered = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
            self.assertEqual(0, tampered.returncode, tampered.stderr)
            blocked = json.loads(tampered.stdout)
            self.assertEqual("completed", blocked["status"])
            self.assertFalse(blocked["validation"]["ok"])
            self.assertEqual("artifact_manifest_mismatch", blocked["validation"]["reason"])

    def test_unsafe_job_id_is_rejected_before_pbs_submission(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            fake_qsub = root / "qsub"
            _fake_qsub(fake_qsub, root / "capture")
            completed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "pbs_worker_wrapper.py"),
                    "submit",
                    "--worker-script",
                    str(ROOT / "scripts" / "remote_worker.py"),
                    "--spool",
                    str(root / "spool"),
                    "--job-id",
                    "bad/job",
                    "--owner",
                    "test",
                    "--run-root",
                    str(root / "run"),
                    "--qsub",
                    str(fake_qsub),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(2, completed.returncode)
            self.assertIn("job-id is invalid", completed.stderr)


if __name__ == "__main__":
    unittest.main()
