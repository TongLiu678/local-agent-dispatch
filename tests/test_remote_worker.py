from __future__ import annotations

import json
import hashlib
import io
import pathlib
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import remote_worker as worker  # noqa: E402
from remote_envelope import build_envelope  # noqa: E402


def packet(root: pathlib.Path, *, job_id: str = "server-job") -> dict:
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
                "argv": ["provider", "--model", "local/fake", "--prompt-file", "TASK.md"],
            }
        ],
    }


def envelope(
    *,
    request_id: str = "request-recovery",
    packet_digest: str = "a" * 64,
    target_id: str = "worker-b",
    model: str = "local/fake",
    variant: str | None = "max",
    provider: str | None = None,
    pool_id: str | None = None,
) -> dict:
    """Build a small exact-model envelope for provider-free fault tests."""
    summary = {
        "job_id": "job-recovery",
        "packet_id": "packet-recovery",
        "attempt_id": "attempt-recovery",
        "model": model,
        "variant": variant,
        "execution_host": "controller-a",
        "workload_host": target_id,
        "write_scope": "out",
        "required_artifact_count": 1,
        "validation_required": True,
    }
    if provider is not None:
        summary["provider"] = provider
    if pool_id is not None:
        summary["pool_id"] = pool_id
    return build_envelope(
        request_id=request_id,
        source_id="controller-a",
        target_id=target_id,
        operation="execute.prepared",
        packet_digest=packet_digest,
        payload_summary=summary,
    )


class RemoteWorkerTests(unittest.TestCase):
    def _process_identity(
        self,
        lease: dict,
        *,
        fence: str | None = None,
        liveness_state: str = "exited",
        observed_at_utc: str | None = None,
    ) -> dict:
        return {
            "pid": 321,
            "start_time": "boot-12345",
            "process_group": 321,
            "run_id": "run-recovery",
            "fence": fence or lease["lease_token"],
            "owned_by_dispatch": True,
            "liveness_state": liveness_state,
            "observed_at_utc": observed_at_utc or worker._utc_now(),
            "ttl_seconds": 300,
        }

    def test_verified_recovery_requires_fresh_exited_process_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            spool = root / "spool"
            worker.prepare_job(packet(root, job_id="verified-recovery"), spool, root)
            claimed = worker.claim_job(spool, "verified-recovery", "worker-a", lease_seconds=1)
            recorded = worker.record_process_identity(
                spool,
                "verified-recovery",
                "worker-a",
                claimed["lease_token"],
                self._process_identity(claimed["lease"], fence=claimed["lease_token"]),
            )
            self.assertEqual("exited", recorded["process_identity"]["liveness_state"])
            expiry = worker._parse_time(claimed["lease"]["expires_at"])
            with patch.object(worker.time, "time", return_value=expiry + 1.0):
                handoff = worker.recover_and_handoff(
                    spool, "verified-recovery", require_process_identity=True
                )
            self.assertEqual("recoverable", handoff["status"])
            self.assertTrue(handoff["resume_allowed"])
            self.assertEqual("claim_with_new_owner", handoff["next_action"])
            self.assertEqual("verified", handoff["recovery"]["liveness"])

    def test_verified_recovery_blocks_when_identity_is_missing_or_alive(self):
        for state in ("missing", "alive"):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as tmp:
                root = pathlib.Path(tmp)
                (root / "src").mkdir()
                job_id = f"verified-{state}"
                spool = root / "spool"
                worker.prepare_job(packet(root, job_id=job_id), spool, root)
                claimed = worker.claim_job(spool, job_id, "worker-a", lease_seconds=1)
                if state == "alive":
                    worker.record_process_identity(
                        spool,
                        job_id,
                        "worker-a",
                        claimed["lease_token"],
                        self._process_identity(
                            claimed["lease"],
                            fence=claimed["lease_token"],
                            liveness_state="alive",
                        ),
                    )
                expiry = worker._parse_time(claimed["lease"]["expires_at"])
                with patch.object(worker.time, "time", return_value=expiry + 1.0):
                    handoff = worker.recover_and_handoff(
                        spool, job_id, require_process_identity=True
                    )
                self.assertEqual("recovery_review", handoff["status"])
                self.assertFalse(handoff["resume_allowed"])
                self.assertEqual("review_process_liveness", handoff["next_action"])
                self.assertEqual("process_liveness_unverified", handoff["recovery"]["reason"])

    def test_process_identity_record_is_fenced_and_redacted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            spool = root / "spool"
            worker.prepare_job(packet(root, job_id="identity-fence"), spool, root)
            claimed = worker.claim_job(spool, "identity-fence", "worker-a", lease_seconds=90)
            with self.assertRaisesRegex(worker.WorkerError, "lease fence mismatch"):
                worker.record_process_identity(
                    spool,
                    "identity-fence",
                    "worker-a",
                    "deadbeef",
                    self._process_identity(claimed["lease"], fence=claimed["lease_token"]),
                )
            recorded = worker.record_process_identity(
                spool,
                "identity-fence",
                "worker-a",
                claimed["lease_token"],
                {
                    **self._process_identity(
                        claimed["lease"], fence=claimed["lease_token"]
                    ),
                    "argv": ["codex", "PRIVATE_PROMPT"],
                    "credential": "PRIVATE_TOKEN",
                },
            )
            serialized = json.dumps(recorded, sort_keys=True)
            self.assertNotIn("PRIVATE_PROMPT", serialized)
            self.assertNotIn("PRIVATE_TOKEN", serialized)
            self.assertNotIn("lease_token", serialized)
            self.assertNotIn("pid", recorded["process_identity"])

    def test_envelope_restart_reconciles_pending_acceptance_and_terminal_receipt(self):
        """A controller/worker restart must not duplicate an accepted effect."""
        with tempfile.TemporaryDirectory() as tmp:
            spool = pathlib.Path(tmp) / "spool"
            gemini_spool = pathlib.Path(tmp) / "gemini-spool"
            gemini = envelope(
                request_id="request-gemini-null",
                model="gemini-3.6-flash-high",
                variant=None,
                provider="antigravity",
                pool_id="antigravity.gemini",
            )
            accepted_gemini = worker.receive_envelope(gemini_spool, gemini)
            self.assertEqual("accepted", accepted_gemini["status"])
            self.assertIsNone(accepted_gemini["envelope"]["variant"])
            bad_null = envelope(
                request_id="request-invalid-null",
                model="local/fake",
                variant=None,
            )
            with self.assertRaisesRegex(worker.WorkerError, "exact variant"):
                worker.receive_envelope(gemini_spool, bad_null)

            task = envelope()
            queued = worker._envelope_store(spool).enqueue(task)
            self.assertEqual("pending", queued["status"])
            self.assertEqual(["request-recovery"], [
                row["request_id"] for row in worker.pending_envelopes(spool)["envelopes"]
            ])

            # The worker accepts the outbox copy, then the process disappears
            # before its accepted receipt reaches the controller.  Deleting
            # the receipt models that crash window; the inbox envelope itself
            # remains durable and must be reconciled on the next process.
            accepted = worker.receive_envelope(spool, task)
            self.assertFalse(accepted["duplicate"])
            receipt_path = spool / "envelopes" / "receipts" / "request-recovery.json"
            receipt_path.unlink()
            self.assertEqual("pending", worker.envelope_status(spool, "request-recovery")["status"])
            self.assertEqual("pending", worker.pending_envelopes(spool)["envelopes"][0]["status"])

            replayed_accept = worker.receive_envelope(spool, task)
            self.assertTrue(replayed_accept["duplicate"])
            self.assertEqual("accepted", replayed_accept["status"])
            self.assertEqual(0, replayed_accept["receipt"]["effect_count"])

            # A crash after terminal receipt persistence but before the
            # response is also safe: a fresh controller observes the receipt,
            # and a retry is a duplicate with no additional effect.
            completed = worker.complete_envelope(
                spool,
                "request-recovery",
                result_digest="b" * 64,
            )
            self.assertFalse(completed["duplicate"])
            restarted = worker.envelope_status(spool, "request-recovery")
            self.assertEqual("completed", restarted["status"])
            replayed_complete = worker.complete_envelope(
                spool,
                "request-recovery",
                result_digest="b" * 64,
            )
            self.assertTrue(replayed_complete["duplicate"])
            self.assertEqual(1, replayed_complete["receipt"]["effect_count"])
            self.assertEqual([], worker.pending_envelopes(spool)["envelopes"])
            self.assertFalse(restarted["provider_execution"])

    def test_envelope_identity_fence_rejects_changed_packet_and_split_brain_copies(self):
        """Same request id is idempotent only when the complete identity agrees."""
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            spool = root / "spool"
            original = envelope()
            worker._envelope_store(spool).enqueue(original)

            changed_packet = envelope(packet_digest="c" * 64)
            with self.assertRaisesRegex(worker.WorkerError, "different envelope identity"):
                worker.receive_envelope(spool, changed_packet)

            worker.receive_envelope(spool, original)
            outbox_path = spool / "envelopes" / "outbox" / "request-recovery.json"
            durable = json.loads(outbox_path.read_text(encoding="utf-8"))
            durable["packet_digest"] = "d" * 64
            outbox_path.write_text(json.dumps(durable), encoding="utf-8")

            # A controller crash or partial restore must not let status or
            # pending reconciliation silently choose one divergent copy.
            with self.assertRaisesRegex(worker.WorkerError, "different envelope identity"):
                worker.envelope_status(spool, "request-recovery")
            with self.assertRaisesRegex(worker.WorkerError, "different envelope identity"):
                worker.pending_envelopes(spool)

    def test_validate_and_prepare_redact_prompt_and_raw_argv(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            report = worker.validate_packet(packet(root), root)
            self.assertEqual("server-job", report["job_id"])
            self.assertNotIn("argv", json.dumps(report))
            self.assertNotIn("TASK.md", json.dumps(report))
            manifest = worker.prepare_job(packet(root), root / "spool", root)
            self.assertEqual("prepared", manifest["status"])
            persisted = (root / "spool" / "jobs" / "server-job" / "manifest.json").read_text()
            events = (root / "spool" / "jobs" / "server-job" / "events.jsonl").read_text()
            self.assertNotIn("argv", persisted)
            self.assertNotIn("TASK.md", persisted)
            self.assertNotIn("argv", events)

    def test_lease_heartbeat_and_expired_lease_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            spool = root / "spool"
            worker.prepare_job(packet(root), spool, root)
            first = worker.claim_job(spool, "server-job", "worker-a", lease_seconds=1)
            self.assertEqual("running", first["status"])
            self.assertTrue(first["lease_token"])
            with self.assertRaises(worker.WorkerError):
                worker.claim_job(spool, "server-job", "worker-b", lease_seconds=1)
            refreshed = worker.heartbeat(spool, "server-job", "worker-a", first["lease_token"], lease_seconds=2)
            self.assertEqual("running", refreshed["status"])
            time.sleep(2.1)
            recovered = worker.recover_jobs(spool, "server-job")
            self.assertEqual("recoverable", recovered[0]["status"])
            self.assertIsNone(recovered[0]["lease"])
            second = worker.claim_job(spool, "server-job", "worker-b", lease_seconds=2)
            self.assertEqual("running", second["status"])
            with self.assertRaises(worker.WorkerError):
                worker.heartbeat(spool, "server-job", "worker-a", first["lease_token"])

    def test_atomic_resume_reconciles_expired_lease_and_emits_audit(self):
        """Reconnect gets one fenced recovery + handoff snapshot."""
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            spool = root / "spool"
            worker.prepare_job(packet(root, job_id="atomic-resume"), spool, root)
            first = worker.claim_job(spool, "atomic-resume", "chat-worker", lease_seconds=1)
            expiry = worker._parse_time(first["lease"]["expires_at"])
            with patch.object(worker.time, "time", return_value=expiry + 1.0):
                handoff = worker.recover_and_handoff(spool, "atomic-resume")
            self.assertEqual("recoverable", handoff["status"])
            self.assertTrue(handoff["resume_allowed"])
            self.assertEqual("claim_with_new_owner", handoff["next_action"])
            self.assertEqual({"performed": True, "reason": "expired"}, handoff["recovery"])
            self.assertIsNone(handoff["lease"])
            self.assertIn("lease_recovered", [event["event_type"] for event in handoff["events"]])
            self.assertNotIn("lease_token", json.dumps(handoff))

    def test_provider_free_durable_cycle_recovery_artifact_gate_and_handoff(self):
        """Exercise prepare -> claim -> heartbeat -> recover -> resume -> complete."""
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            spool = root / "spool"
            prepared = worker.prepare_job(packet(root), spool, root)
            first = worker.claim_job(spool, "server-job", "worker-a", lease_seconds=1)
            refreshed = worker.heartbeat(
                spool,
                "server-job",
                "worker-a",
                first["lease_token"],
                lease_seconds=2,
            )

            # Avoid a real sleep: recovery observes the same clock used by the
            # lease fence and therefore deterministically sees the lease expire.
            expiry = worker._parse_time(refreshed["lease"]["expires_at"])
            with patch.object(worker.time, "time", return_value=expiry + 1.0):
                recovered = worker.recover_jobs(spool, "server-job")
            self.assertEqual("recoverable", recovered[0]["status"])
            self.assertIsNone(recovered[0]["lease"])

            resumed = worker.claim_job(spool, "server-job", "worker-b", lease_seconds=90)
            with self.assertRaisesRegex(worker.WorkerError, "lease fence mismatch"):
                worker.heartbeat(spool, "server-job", "worker-a", first["lease_token"])

            result = worker.run_fake_job(
                spool,
                "server-job",
                "worker-b",
                lease_token=resumed["lease_token"],
                artifact_text="provider-free fixture\n",
            )
            self.assertEqual("completed", result["status"])
            self.assertEqual("completed", result["manifest"]["status"])
            self.assertTrue(result["manifest"]["artifact_freshness_verified"])
            artifact = root / "out/result.json"
            self.assertTrue(artifact.is_file())
            expected_digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
            self.assertEqual(expected_digest, result["artifact_manifest"][0]["sha256"])
            self.assertIsNotNone(result["heartbeat"])

            handoff = worker.resume_handoff(spool, "server-job")
            self.assertEqual(prepared["packet_digest"], handoff["packet_digest"])
            self.assertFalse(handoff["resume_required"])
            self.assertFalse(handoff["resume_allowed"])
            self.assertEqual("review_artifacts", handoff["next_action"])
            event_types = [event["event_type"] for event in handoff["events"]]
            for event_type in ("prepared", "lease_acquired", "heartbeat", "lease_recovered", "job_completed"):
                self.assertIn(event_type, event_types)
            # Handoffs are safe to persist or pass to a later controller: the
            # original prompt/argv never crosses the boundary.
            self.assertNotIn("argv", json.dumps(handoff))
            self.assertNotIn("prompt", json.dumps(handoff))

    def test_fake_executor_and_resume_handoff_cli_are_local_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            packet_path = root / "packet.json"
            packet_path.write_text(json.dumps(packet(root)), encoding="utf-8")
            spool = root / "spool"
            self.assertEqual(
                0,
                worker.main(
                    [
                        "prepare",
                        "--packet",
                        str(packet_path),
                        "--project-root",
                        str(root),
                        "--spool",
                        str(spool),
                    ]
                ),
            )
            # CLI output is intentionally ignored here; this assertion only
            # proves the bounded fake seam can be driven without a provider.
            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    0,
                    worker.main(
                        [
                            "fake-execute",
                            "--spool",
                            str(spool),
                            "--job-id",
                            "server-job",
                            "--owner",
                            "ci-fake",
                        ]
                    ),
                )
            handoff_path = root / "handoff.json"
            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    0,
                    worker.main(
                        [
                            "resume-handoff",
                            "--spool",
                            str(spool),
                            "--job-id",
                            "server-job",
                            "--output",
                            str(handoff_path),
                        ]
                    ),
                )
            payload = json.loads(handoff_path.read_text(encoding="utf-8"))
            self.assertEqual("completed", payload["status"])
            self.assertTrue((root / "out/result.json").is_file())
            self.assertFalse((spool / "jobs" / "server-job" / "provider.log").exists())

    def test_artifact_manifest_hashes_files_and_confines_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            (root / "out").mkdir()
            (root / "out/result.json").write_text('{"ok":true}\n')
            spool = root / "spool"
            worker.prepare_job(packet(root), spool, root)
            before = worker.status(spool, "server-job")["jobs"][0]["artifact_manifest"][0]
            self.assertEqual("present", before["status"])
            (root / "out/result.json").write_text('{"ok":false}\n')
            observed = worker.observe_artifacts(spool, "server-job")
            after = observed["observed_artifact_manifest"][0]
            self.assertEqual("present", after["status"])
            self.assertNotEqual(before["sha256"], after["sha256"])
            with self.assertRaisesRegex(worker.WorkerError, "lease.*required"):
                worker.record_artifacts(spool, "server-job")
            bad = packet(root, job_id="escape")
            bad["required_artifacts"] = ["../outside.txt"]
            with self.assertRaises(worker.WorkerError):
                worker.validate_packet(bad, root)

    def test_secret_or_inline_prompt_packets_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            capture_envelope = {
                "schema_version": 1,
                "capture": "bounded-task-capture",
                "estimate": {"metrics": {"input_tokens": {"p50": 1}}},
            }
            with self.assertRaisesRegex(
                worker.WorkerError,
                "task capture envelope must pass through plan_packet_bridge",
            ):
                worker.validate_packet(capture_envelope, root)
            bad_secret = packet(root, job_id="secret")
            bad_secret["metadata"] = {"api_key": "do-not-store"}
            with self.assertRaises(worker.WorkerError):
                worker.validate_packet(bad_secret, root)
            bad_prompt = packet(root, job_id="prompt")
            bad_prompt["attempts"][0]["prompt"] = "private user request"
            with self.assertRaises(worker.WorkerError):
                worker.validate_packet(bad_prompt, root)

    def test_top_level_paths_are_confined_like_attempt_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            bad = packet(root, job_id="top-level-escape")
            bad["output_path"] = "../outside.txt"
            with self.assertRaisesRegex(worker.WorkerError, "output_path escapes project root"):
                worker.validate_packet(bad, root)

            outside = pathlib.Path(tmp).parent / f"outside-{root.name}.txt"
            outside.write_text("outside\n", encoding="utf-8")
            try:
                link = root / "linked-output"
                link.symlink_to(outside)
                bad_link = packet(root, job_id="symlink-escape")
                bad_link["output_path"] = "linked-output"
                with self.assertRaisesRegex(worker.WorkerError, "output_path escapes project root"):
                    worker.validate_packet(bad_link, root)
            finally:
                outside.unlink(missing_ok=True)

    def test_short_lease_timestamp_keeps_subsecond_precision(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            spool = root / "spool"
            worker.prepare_job(packet(root, job_id="micro-lease"), spool, root)
            claimed = worker.claim_job(spool, "micro-lease", "worker-a", lease_seconds=1)
            self.assertIn(".", str(claimed["lease"]["expires_at"]))

    def test_cli_validate_prepare_status_and_recover_are_dry_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            packet_path = root / "packet.json"
            packet_path.write_text(json.dumps(packet(root)))
            self.assertEqual(0, worker.main(["validate", "--packet", str(packet_path), "--project-root", str(root)]))
            self.assertEqual(0, worker.main(["prepare", "--packet", str(packet_path), "--project-root", str(root), "--spool", str(root / "spool")]))
            self.assertEqual(0, worker.main(["status", "--spool", str(root / "spool")]))
            self.assertEqual(0, worker.main(["recover", "--spool", str(root / "spool")]))
            # The contract has no execute subcommand and should not create a
            # provider log, process, network request, or raw prompt artifact.
            self.assertFalse((root / "spool" / "jobs" / "server-job" / "provider.log").exists())

    def test_fake_service_is_chat_independent_and_recovers_named_job(self):
        """A separate process can continue one authorized fixture job."""
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            spool = root / "spool"
            job = packet(root, job_id="service-job")
            prepared = worker.prepare_job(job, spool, root)
            self.assertEqual("prepared", prepared["status"])

            # Simulate the originating controller disappearing after its lease
            # was acquired.  The independent service must reconcile the lease
            # before claiming the same named job.
            first = worker.claim_job(spool, "service-job", "chat-worker", lease_seconds=1)
            expiry = worker._parse_time(first["lease"]["expires_at"])
            with patch.object(worker.time, "time", return_value=expiry + 1.0):
                recovered = worker.recover_jobs(spool, "service-job")
            self.assertEqual("recoverable", recovered[0]["status"])

            script = ROOT / "scripts" / "remote_worker.py"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(script),
                    "fake-service",
                    "--spool",
                    str(spool),
                    "--job-id",
                    "service-job",
                    "--owner",
                    "server-service",
                    "--poll-seconds",
                    "0.01",
                    "--max-idle-rounds",
                    "3",
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            payload = json.loads(completed.stdout)
            self.assertEqual("fake", payload["service"])
            self.assertFalse(payload["provider_execution"])
            self.assertEqual("completed", payload["status"])
            self.assertEqual("completed", worker.status(spool, "service-job")["jobs"][0]["status"])
            self.assertTrue((root / "out/result.json").is_file())
            self.assertNotIn("prompt", json.dumps(payload))


if __name__ == "__main__":
    unittest.main()
