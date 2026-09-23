from __future__ import annotations

import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch


ROOT = pathlib.Path(__file__).resolve().parents[1]


def load_controller():
    spec = importlib.util.spec_from_file_location(
        "controller_reliability_under_test", ROOT / "scripts" / "continuity_controller.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


continuity = load_controller()


def make_job(root: pathlib.Path, validation: list[str] | None) -> tuple[dict, dict, pathlib.Path]:
    workspace = root / "workspace"
    workspace.mkdir()
    run_dir = root / "run"
    run_dir.mkdir()
    runtime = root / "runtime-state.json"
    result = workspace / "result.txt"
    script = (
        "import pathlib; pathlib.Path('result.txt').write_text('artifact\\n', encoding='utf-8')"
    )
    attempt = {
        "attempt_id": "command-1",
        "adapter": "command",
        "transport": "local",
        "argv": [sys.executable, "-c", script],
        "result_source_path": str(result),
        "output_path": str(result),
        "pool_id": "codex.spark",
        "provider": "codex",
        "model": "gpt-5.3-codex-spark",
        "runtime_state_path": str(runtime),
    }
    job = {
        "job_id": "reliability-job",
        "workspace": str(workspace),
        "required_artifacts": [str(result)],
        "attempts": [attempt],
    }
    if validation is not None:
        job["validation_argv"] = validation
    state = {
        "schema_version": 1,
        "workspace": str(workspace),
        "inventory": str(root / "hosts.json"),
        "runtime_state": str(runtime),
        "jobs": [job],
    }
    (root / "hosts.json").write_text('{"hosts": []}\n', encoding="utf-8")
    continuity.atomic_write(run_dir / "state.json", state)
    return job, state, run_dir


class ControllerReliabilityTests(unittest.TestCase):
    def test_portable_lock_lazy_load_is_thread_safe(self):
        previous = continuity._portable_file_lock
        continuity._portable_file_lock = None
        self.addCleanup(setattr, continuity, "_portable_file_lock", previous)
        barrier = threading.Barrier(10)
        modules = []
        errors = []

        def load_once():
            barrier.wait()
            try:
                modules.append(continuity._load_portable_file_lock())
            except BaseException as exc:  # captured for an assertion in the test thread
                errors.append(exc)

        threads = [threading.Thread(target=load_once) for _ in range(10)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)
        self.assertFalse(errors)
        self.assertEqual(10, len(modules))
        self.assertEqual(1, len({id(module) for module in modules}))
        self.assertTrue(hasattr(modules[0], "exclusive_file_lock"))

    def test_blank_provider_stdout_is_not_published_as_fresh_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = pathlib.Path(tmp)
            target = workspace / "answer.md"
            with self.assertRaisesRegex(RuntimeError, "provider stdout is empty"):
                continuity.publish_attempt_output(
                    "\n", str(target), None, workspace, None
                )
            self.assertFalse(target.exists())

    def test_provider_stdout_is_published_atomically(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = pathlib.Path(tmp)
            target = workspace / "answer.md"
            published = continuity.publish_attempt_output(
                "bounded answer\n", str(target), None, workspace, None
            )
            self.assertEqual(target.resolve(), published)
            self.assertEqual("bounded answer\n", target.read_text(encoding="utf-8"))
            self.assertEqual([], list(workspace.glob(".answer.md.*.tmp")))

    def test_local_admission_failure_is_classified_as_resource(self):
        self.assertEqual(
            "resource",
            continuity.classify(
                "continuity controller: LocalLaunchAdmissionError: "
                "local launch blocked before child creation: free_bytes_below_floor"
            ),
        )

    def test_resource_failure_only_falls_back_to_declared_ssh_attempt(self):
        local = {"transport": "local"}
        local_model = {"transport": "local", "model": "gpt-5.6-luna"}
        remote = {"transport": "ssh", "host_id": "remote-a"}
        self.assertTrue(continuity.resource_fallback_available("resource", 0, [local, remote]))
        self.assertFalse(continuity.resource_fallback_available("resource", 0, [local, local_model]))
        self.assertFalse(continuity.resource_fallback_available("quota", 0, [local, remote]))

    def test_server_openai_base_url_is_loopback_only(self):
        self.assertEqual(
            "http://127.0.0.1:8000/v1",
            continuity.validate_loopback_base_url("http://127.0.0.1:8000/v1/"),
        )
        for value in (
            "https://example.invalid/v1",
            "http://user:pass@127.0.0.1:8000/v1",
            "file:///tmp/model",
        ):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    continuity.validate_loopback_base_url(value)

    def test_server_openai_ssh_writes_remote_result_and_uses_remote_artifacts(self):
        """SSH-local inference must not inspect or publish a local artifact."""
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            prompt = workspace / "task.md"
            prompt.write_text("return a bounded answer\n", encoding="utf-8")
            host = {
                "host_id": "remote",
                "transport": "ssh",
                "hostname": "example.invalid",
                "user": "root",
                "port": 2222,
                "project_path": "/srv/local-agent-dispatch",
            }
            attempt = {
                "attempt_id": "remote-openai",
                "adapter": "server_openai",
                "transport": "ssh",
                "host_id": "remote",
                "model": "qwen2.5-coder-14b-awq",
                "base_url": "http://127.0.0.1:8000/v1",
                "prompt_file": str(prompt),
                "remote_workspace": "/srv/local-agent-dispatch/job-1",
                "remote_result_source_path": "out/result.txt",
                "result_source_path": "out/result.txt",
            }
            job = {
                "job_id": "remote-job",
                "workspace": str(workspace),
                "remote_workspace": "/srv/local-agent-dispatch/job-1",
                "required_artifacts": ["out/result.txt"],
            }
            argv, cwd, output_path, stdin_payload = continuity.build_attempt(
                job,
                attempt,
                {"workspace": str(workspace)},
                {"remote": host},
            )
            self.assertIsNone(cwd)
            self.assertIsNone(output_path)
            self.assertIsNotNone(stdin_payload)
            self.assertIn("/srv/local-agent-dispatch/job-1/out/result.txt", stdin_payload or "")
            self.assertIn("python3 -", argv)
            self.assertNotIn(str(prompt.read_text(encoding="utf-8")), json.dumps(argv))

    def test_remote_artifact_observation_rejects_escape_before_ssh(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            job = {"required_artifacts": ["../outside.txt"], "remote_workspace": "/srv/project/job"}
            attempt = {"workspace": "/srv/project/job", "transport": "ssh"}
            host = {"project_path": "/srv/project", "hostname": "example.invalid", "user": "root", "port": 22}
            with patch.object(continuity.subprocess, "run") as runner:
                facts = continuity.remote_artifact_facts(job, attempt, host)
            runner.assert_not_called()
            self.assertEqual("../outside.txt", facts[0]["path"])
            self.assertIn("unsafe path", facts[0]["error"])

    def test_generic_ssh_command_and_validation_confine_remote_workspace(self):
        """Generic SSH execution must never cd outside the server project root."""
        host = {
            "host_id": "remote",
            "transport": "ssh",
            "hostname": "example.invalid",
            "user": "root",
            "port": 2222,
            "project_path": "/srv/project",
        }
        job = {
            "job_id": "remote-generic",
            # This is controller-local metadata and must not become remote cwd.
            "workspace": "/controller/workspace",
            "validation_argv": ["python3", "-m", "unittest"],
        }
        attempt = {
            "attempt_id": "remote-generic-attempt",
            "adapter": "command",
            "transport": "ssh",
            "host_id": "remote",
            "argv": ["python3", "-c", "print('ok')"],
            "workspace": "/controller/workspace",
            "model": "server/local",
        }
        with self.assertRaisesRegex(ValueError, "remote_workspace escapes"):
            continuity.build_attempt(job, attempt, {"workspace": job["workspace"]}, {"remote": host})
        with self.assertRaisesRegex(ValueError, "remote_workspace escapes"):
            continuity.build_validation(job, attempt, {"workspace": job["workspace"]}, {"remote": host})

        # A packet with no explicit remote workspace safely defaults to the
        # declared server project root rather than the local controller path.
        attempt.pop("workspace")
        argv, cwd, _output, stdin_payload = continuity.build_attempt(
            job, attempt, {"workspace": job["workspace"]}, {"remote": host}
        )
        self.assertIsNone(cwd)
        self.assertIn("/srv/project", argv[-1])
        self.assertIn("cd \"$remote_cwd\"", stdin_payload or "")
        validation_argv, validation_cwd, validation_stdin = continuity.build_validation(
            job, attempt, {"workspace": job["workspace"]}, {"remote": host}
        )
        self.assertIsNone(validation_cwd)
        self.assertIn("/srv/project", validation_argv[-1])
        self.assertIn("cd \"$remote_cwd\"", validation_stdin or "")

    def test_generic_ssh_remote_workspace_rejects_parent_traversal(self):
        host = {
            "host_id": "remote",
            "transport": "ssh",
            "hostname": "example.invalid",
            "user": "root",
            "port": 2222,
            "project_path": "/srv/project",
        }
        job = {"job_id": "remote-traversal", "remote_workspace": "../outside"}
        attempt = {
            "attempt_id": "remote-traversal-attempt",
            "adapter": "command",
            "transport": "ssh",
            "host_id": "remote",
            "argv": ["python3", "-c", "print('must not run')"],
            "model": "server/local",
        }
        with self.assertRaisesRegex(ValueError, "unsafe path component"):
            continuity.build_attempt(job, attempt, {"workspace": "/controller"}, {"remote": host})
        with self.assertRaisesRegex(ValueError, "unsafe path component"):
            continuity.build_validation(
                {**job, "validation_argv": ["python3", "-m", "unittest"]},
                attempt,
                {"workspace": "/controller"},
                {"remote": host},
            )

    def test_controller_lease_is_exclusive_and_released(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = pathlib.Path(tmp)
            with continuity.controller_lease(run_dir, owner_id="first"):
                lease = json.loads((run_dir / "controller.lease.json").read_text(encoding="utf-8"))
                self.assertEqual("first", lease["owner_id"])
                with self.assertRaisesRegex(RuntimeError, "already held"):
                    with continuity.controller_lease(run_dir, owner_id="second"):
                        pass
            self.assertFalse((run_dir / "controller.lease.json").exists())
            with continuity.controller_lease(run_dir, owner_id="second"):
                self.assertTrue((run_dir / "controller.lease.json").exists())

    def test_validation_is_required_for_completion(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            job, state, run_dir = make_job(
                root,
                [sys.executable, "-c", "import sys; sys.exit(0)"],
            )
            continuity.run_job(run_dir, job, state, {})
            self.assertEqual("completed", job["status"])
            self.assertTrue(job["validation"]["ok"])

    def test_validation_failure_blocks_completion(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            job, state, run_dir = make_job(
                root,
                [sys.executable, "-c", "print('validation failed'); import sys; sys.exit(3)"],
            )
            continuity.run_job(run_dir, job, state, {})
            self.assertEqual("failed", job["status"])
            self.assertEqual("execution", job["error"])
            self.assertIn("validation failed", (run_dir / "logs" / "reliability-job.command-1.log").read_text())

    def test_validation_required_without_validator_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            job, state, run_dir = make_job(root, None)
            job["validation_required"] = True
            continuity.run_job(run_dir, job, state, {})
            self.assertEqual("failed", job["status"])
            self.assertIn("validation", job["last_validation"]["error"])

    def test_touch_without_content_change_is_not_a_fresh_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            job, state, run_dir = make_job(
                root, [sys.executable, "-c", "import sys; sys.exit(0)"]
            )
            result = pathlib.Path(job["required_artifacts"][0])
            result.write_text("old content\n", encoding="utf-8")
            job["attempts"][0]["argv"] = [
                sys.executable,
                "-c",
                "import pathlib; pathlib.Path('result.txt').touch()",
            ]
            continuity.run_job(run_dir, job, state, {})
            self.assertEqual("failed", job["status"])
            self.assertFalse(job["artifact_freshness_verified"])

    def test_accept_existing_artifact_requires_independent_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            job, state, run_dir = make_job(root, None)
            result = pathlib.Path(job["required_artifacts"][0])
            result.write_text("pre-existing\n", encoding="utf-8")
            job["accept_existing_artifacts"] = True
            job["attempts"][0]["argv"] = [sys.executable, "-c", "print('worker did not touch artifact')"]
            continuity.run_job(run_dir, job, state, {})
            self.assertEqual("failed", job["status"])
            self.assertFalse(job["artifact_freshness_verified"])

            # A passed validator is the only supported way to explicitly
            # accept a durable artifact that predates this attempt.
            job["status"] = "queued"
            job["attempt_history"] = []
            job["validation_argv"] = [sys.executable, "-c", "import sys; sys.exit(0)"]
            job["attempts"][0]["result_source_path"] = None
            job["attempts"][0]["output_path"] = None
            continuity.run_job(run_dir, job, state, {})
            self.assertEqual("completed", job["status"])
            self.assertTrue(job["artifact_freshness_verified"])

    def test_path_traversal_and_symlink_escape_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            outside = root / "outside"
            outside.mkdir()
            (workspace / "link").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "escapes workspace"):
                continuity.resolve_path("../outside/result.txt", workspace)
            with self.assertRaisesRegex(ValueError, "escapes workspace"):
                continuity.resolve_path("link/result.txt", workspace)

    def test_enqueue_is_rejected_while_controller_owns_run_lease(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            run_dir = root / "run"
            run_dir.mkdir()
            inventory = root / "hosts.json"
            inventory.write_text('{"hosts": []}\n', encoding="utf-8")
            runtime = root / "runtime-state.json"
            job = {
                "schema_version": 1,
                "job_id": "long-job",
                "status": "queued",
                "workspace": str(workspace),
                "attempts": [{
                    "attempt_id": "sleep",
                    "adapter": "command",
                    "transport": "local",
                    "argv": [sys.executable, "-c", "import time; time.sleep(4)"],
                    "pool_id": "codex.spark",
                    "provider": "codex",
                    "model": "gpt-5.3-codex-spark",
                    "runtime_state_path": str(runtime),
                }],
            }
            state = {
                "schema_version": 1,
                "workspace": str(workspace),
                "inventory": str(inventory),
                "runtime_state": str(runtime),
                "jobs": [job],
            }
            continuity.atomic_write(run_dir / "state.json", state)
            job_file = root / "new-job.json"
            job_file.write_text(json.dumps({"schema_version": 1, "job_id": "new-job"}), encoding="utf-8")
            script = ROOT / "scripts" / "continuity_controller.py"
            process = subprocess.Popen(
                [sys.executable, str(script), "run", "--run-dir", str(run_dir), "--once"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                # A Torque worker may start Python and create the lease on a
                # shared filesystem under scheduler load.  Keep the readiness
                # bound finite, but allow the remote startup jitter observed
                # on the central cluster instead of treating it as a lease
                # correctness failure.
                deadline = time.time() + 15
                while not (run_dir / "controller.lease.json").exists() and time.time() < deadline:
                    time.sleep(0.02)
                self.assertTrue((run_dir / "controller.lease.json").exists())
                enqueue = subprocess.run(
                    [sys.executable, str(script), "enqueue", "--run-dir", str(run_dir), "--job-file", str(job_file)],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(2, enqueue.returncode)
                self.assertIn("controller lease is already held", enqueue.stdout)
            finally:
                process.wait(timeout=20)
                if process.stdout:
                    process.stdout.close()
                if process.stderr:
                    process.stderr.close()
            final_state = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
            self.assertEqual(["long-job"], [row["job_id"] for row in final_state["jobs"]])


if __name__ == "__main__":
    unittest.main()
