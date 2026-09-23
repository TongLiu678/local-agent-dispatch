from __future__ import annotations

import hashlib
import io
import json
import pathlib
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from sqlite_store import SQLiteStore  # noqa: E402
import terminal_receipt_export  # noqa: E402
from terminal_receipt_export import export_terminal_receipt  # noqa: E402


def digest(value: object) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def file_digest(path: pathlib.Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def packet(fence: int) -> dict[str, object]:
    resource_body = {
        "schema_version": "0.1.0", "kind": "resource_request",
        "request_id": "request:one", "project_id": "project-alpha",
        "task_profile_digest": digest("task"), "cpu_cores": 1,
        "memory_bytes": 1, "disk_bytes": 1, "gpu_count": 0,
        "minimum_gpu_memory_bytes": 0, "maximum_wall_seconds": 60,
        "output_path_digest": digest("artifact"),
    }
    resource = {**resource_body, "request_digest": digest(resource_body)}
    quota_body = {
        "schema_version": "0.1.0", "kind": "quota_snapshot_receipt",
        "snapshot_id": "quota:one", "project_id": "project-alpha",
        "provider": "fixture", "exact_model": "fixture-model",
        "quota_kind": "not_applicable_zero_model", "pool_id": "pool:fixture",
        "remaining_units": 0, "reserved_units": 0,
        "reset_at": "2026-08-20T00:00:00Z", "observed_at": "2026-08-16T00:00:00Z",
        "maximum_age_seconds": 3600, "source_reference": "source:one",
        "source_receipt_digest": digest("source"),
    }
    quota = {**quota_body, "snapshot_digest": digest(quota_body)}
    binding_body = {
        "schema_version": "cpslab_lad_binding/0.1.0", "kind": "lad_packet_binding",
        "task_profile_digest": digest("task"), "agent_instance_digest": digest("agent"),
        "cps_recipe_digest": digest("recipe"), "route_manifest_digest": digest("route"),
        "lane_profile_digest": digest("lane"), "resource_request_digest": resource["request_digest"],
        "quota_snapshot_digest": quota["snapshot_digest"], "builder_backend_evidence_digest": digest("builder"),
        "worktree_lease_digest": digest("lease"), "worktree_fence": fence,
        "plan_digest": digest("plan"), "assignment_digest": digest("assignment"),
        "adapter_digest": digest("adapter"),
    }
    binding = {**binding_body, "binding_digest": digest(binding_body)}
    body = {
        "schema_version": "lad_task_packet/2.0.0", "kind": "foundry_task_packet",
        "job_id": "job:one", "exact_model": "fixture-model", "exact_effort": "bounded",
        "execution_host_digest": digest("execution-host"), "workload_host_digest": digest("workload-host"),
        "resource_request": resource, "quota_snapshot": quota, "write_scope": ["artifacts/"],
        "validation_command": ["python3", "-m", "unittest"], "artifact_path": "artifacts/result.json",
        "result_path": "artifacts/result.json", "plan_digest": binding["plan_digest"],
        "assignment_digest": binding["assignment_digest"], "foundry_binding": binding,
    }
    return {**body, "packet_digest": digest(body)}


class TerminalReceiptExportTests(unittest.TestCase):
    def _setup(self, root: pathlib.Path) -> tuple[pathlib.Path, str, int, pathlib.Path]:
        db = root / "dispatch.sqlite3"
        artifact = root / "artifacts" / "result.json"
        artifact.parent.mkdir()
        artifact.write_text('{"ok":true}\n', encoding="utf-8")
        with SQLiteStore(db) as store:
            lease = store.acquire_controller_lease("controller-1", ttl_seconds=60)
            payload = packet(int(lease["fence_token"]))
            payload.update({
                "workspace": str(root),
                "required_artifacts": ["artifacts/result.json"],
                "validation_required": True,
                "attempts": [{"attempt_id": "attempt:one", "model": "fixture-model", "adapter": "fixture", "transport": "local"}],
                "model_profile_digest": digest("model"),
            })
            store.create_job("job:one", payload, owner_id="controller-1", fence_token=lease["fence_token"])
            store.reserve_resources("job:one", "controller-1", lease["fence_token"], payload["resource_request"], admission={"allowed": True})
            claim = store.claim_job("job:one", "controller-1", lease["fence_token"], require_reservation=True)
            assert claim
            manifest = [{"path": "artifacts/result.json", "exists": True, "size": artifact.stat().st_size, "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest()}]
            store.complete_job("job:one", claim["attempt"]["attempt_id"], "controller-1", lease["fence_token"], success=True, artifact_manifest=manifest, validation={"ok": True, "returncode": 0, "command": ["python3", "-m", "unittest"]})
            return db, str(claim["attempt"]["attempt_id"]), int(lease["fence_token"]), artifact

    def test_export_is_strict_and_rehashes_validated_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            db, attempt_id, fence, artifact = self._setup(pathlib.Path(tmp))
            receipt = export_terminal_receipt(db, attempt_id, owner_id="controller-1", fence_token=fence)
            self.assertEqual({
                "schema_version", "kind", "run_id", "attempt_id", "state", "plan_digest", "packet_digest",
                "foundry_binding_digest", "agent_instance_digest", "resource_request_digest", "quota_snapshot_digest",
                "lane_profile_digest", "model_profile_digest", "execution_host_digest", "workload_host_digest",
                "worktree_lease_digest", "worktree_fence", "artifact_digest", "validation_command_digest",
                "validation_exit_code", "settlement_receipt_digest", "terminal_cause_kind",
                "terminal_cause_receipt_digest", "started_at", "completed_at", "receipt_digest",
            }, set(receipt))
            self.assertEqual("completed", receipt["state"])
            self.assertEqual(file_digest(artifact), receipt["artifact_digest"])
            self.assertEqual(receipt["receipt_digest"], digest({key: value for key, value in receipt.items() if key != "receipt_digest"}))

    def test_replaced_artifact_and_stale_fence_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            db, attempt_id, fence, artifact = self._setup(root)
            artifact.write_text('{"tampered":true}\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "artifact"):
                export_terminal_receipt(db, attempt_id, owner_id="controller-1", fence_token=fence)
            with SQLiteStore(db) as store:
                store.release_controller_lease("controller-1", fence)
                new_lease = store.acquire_controller_lease("controller-2", ttl_seconds=60)
            with self.assertRaisesRegex(ValueError, "lease|fence"):
                export_terminal_receipt(db, attempt_id, owner_id="controller-1", fence_token=fence)
            self.assertGreater(new_lease["fence_token"], fence)

    def test_cli_emits_only_json_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            db, attempt_id, fence, _artifact = self._setup(pathlib.Path(tmp))
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(0, terminal_receipt_export.main([
                    "--db", str(db), "--attempt-id", attempt_id,
                    "--owner-id", "controller-1", "--fence-token", str(fence),
                ]))
            document = json.loads(output.getvalue())
            self.assertEqual("lad_attempt_receipt", document["kind"])
            self.assertNotIn("prompt", output.getvalue().lower())
            self.assertNotIn("argv", output.getvalue().lower())


if __name__ == "__main__":
    unittest.main()
