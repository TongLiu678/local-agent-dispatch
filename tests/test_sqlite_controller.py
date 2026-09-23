from __future__ import annotations

import json
import hashlib
import pathlib
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from typing import Any, Mapping
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "sqlite_controller.py"
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))
from sqlite_controller import (  # noqa: E402
    SQLiteController,
    build_transport_envelope,
    validate_capacity_receipt,
    validate_quota_snapshot_receipt,
)
from sqlite_store import FencingError, SQLiteStore  # noqa: E402
import remote_cli_placement as remote_cli  # noqa: E402


def _remote_cli_packet() -> dict:
    now = "2026-08-15T08:00:00+00:00"
    assignment = {
        "job_id": "sol-job",
        "attempt_id": "sol-attempt",
        "pool_id": "codex.luna",
        "provider": "codex",
        "model": "gpt-5.6-sol",
        "variant": "max",
        "execution_host": "westd",
        "execution_transport": "ssh",
        "workload_host": "westd",
        "workload_transport": "ssh",
        "remote_workspace": "/srv/project/sol-job",
        "write_scope": "src",
        "receipt_path": "/srv/project/sol-job/.lad/receipts/sol-attempt.json",
        "remote_cli_wrapper": {
            "name": "codex-sol-wrapper",
            "version": "0.1.0",
            "sha256": "a" * 64,
            "mode": "dry-run",
        },
    }
    host = {
        "host_id": "westd",
        "transport": "ssh",
        "project_path": "/srv/project",
        "remote_cli": {
            "name": "codex",
            "path": "/usr/local/bin/codex",
            "version": "0.147.0",
            "install_state": "installed",
            "auth": {
                "state": "authenticated",
                "scope": "remote_host",
                "host_id": "westd",
                "observed_at_utc": now,
                "ttl_seconds": 600,
                "source": "codex login status",
            },
        },
    }
    route = {
        "provider": "racknerd",
        "kind": "execution",
        "status": "verified",
        "verified": True,
        "target_host_id": "westd",
        "egress_ip": "192.0.2.44",
        "observed_at_utc": now,
        "ttl_seconds": 300,
        "source": "codex-racknerd-route verify",
    }
    report = remote_cli.build_remote_cli_contract(assignment, host, route, now_utc=now)
    assert report["valid"], report
    packet = {
        "schema_version": 1,
        "packet_id": "packet-sol",
        "job_id": "sol-job",
        "pool_id": "codex.luna",
        "provider": "codex",
        "model": "gpt-5.6-sol",
        "variant": "max",
        "workspace": "/controller/staging",
        "write_scope": "src",
        "required_artifacts": ["/srv/project/sol-job/result.json"],
        "validation_required": True,
        "validation_argv": ["python3", "-c", "pass"],
        "execution_host": "westd",
        "workload_host": "westd",
        "execution_transport": "ssh",
        "workload_transport": "ssh",
        "attempts": [{
            "attempt_id": "sol-attempt",
            "adapter": "placeholder",
            "transport": "ssh",
            "model": "gpt-5.6-sol",
        }],
    }
    return remote_cli.attach_remote_cli_contract(packet, report)


def _reseal_remote_contract(contract: dict) -> None:
    unsigned = {key: value for key, value in contract.items() if key != "contract_digest"}
    contract["contract_digest"] = hashlib.sha256(
        json.dumps(unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _local_effect_packet(
    workspace: pathlib.Path,
    job_id: str,
    attempt_id: str,
    *,
    pid: str | None = None,
) -> dict[str, object]:
    """Build a tiny local packet for controller fence/recovery replay tests."""

    relative_artifact = f"out/{job_id}/effect.log"
    command = (
        "from pathlib import Path; "
        f"path = Path({relative_artifact!r}); path.parent.mkdir(parents=True, exist_ok=True); "
        "path.open('a', encoding='utf-8').write('effect\\n')"
    )
    attempt: dict[str, object] = {
        "attempt_id": attempt_id,
        "adapter": "command",
        "transport": "local",
        "argv": [sys.executable, "-c", command],
        "model": "local/fake",
        "pool_id": "fake.local",
        "provider": "fake",
    }
    if pid is not None:
        attempt["pid"] = pid
    return {
        "schema_version": 1,
        "packet_id": f"packet-{job_id}",
        "job_id": job_id,
        "workspace": str(workspace),
        "write_scope": f"out/{job_id}",
        "required_artifacts": [relative_artifact],
        "validation_required": True,
        "validation_argv": [sys.executable, "-c", "import sys; sys.exit(0)"],
        "attempts": [attempt],
    }


class SQLiteControllerTests(unittest.TestCase):
    def test_controller_blocks_shared_sqlite_storage_before_open(self):
        blocked = {
            "allowed": False,
            "reasons": ["sqlite:shared_filesystem:nfs4"],
        }
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch(
                "sqlite_controller.local_resource_admission.check_sqlite_storage",
                return_value=blocked,
            ):
                with self.assertRaisesRegex(
                    RuntimeError, "shared_filesystem:nfs4"
                ):
                    SQLiteController(pathlib.Path(tmp) / "dispatch.sqlite3")

    def test_capacity_boolean_cannot_replace_strict_receipt(self):
        request = {"resource_request_digest": "sha256:" + "a" * 64}
        with self.assertRaisesRegex(ValueError, "capacity receipt"):
            validate_capacity_receipt(True, request=request)

    def test_capacity_receipt_digest_and_freshness_are_rechecked(self):
        def digest(value):
            return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        body = {
            "schema_version": "0.1.0", "kind": "server_capacity_receipt",
            "host_identity_digest": digest("host"), "project_path_digest": digest("project"),
            "output_path_digest": digest("output"), "runtime_digest": digest("runtime"),
            "resource_request_digest": digest("request"), "available_disk_bytes": 100,
            "required_disk_bytes": 1, "available_memory_bytes": 100, "required_memory_bytes": 1,
            "gpu_inventory_digest": digest("gpu"), "writable_probe_digest": digest("writable"),
            "observed_at": "2026-08-15T00:00:00Z", "maximum_age_seconds": 60,
        }
        receipt = {**body, "receipt_digest": digest(body)}
        self.assertTrue(validate_capacity_receipt(receipt, request={"resource_request_digest": digest("request")}, now_utc="2026-08-15T00:00:30Z")["valid"])
        receipt["available_disk_bytes"] = 0
        with self.assertRaisesRegex(ValueError, "self-digest"):
            validate_capacity_receipt(receipt, request={"resource_request_digest": digest("request")}, now_utc="2026-08-15T00:00:30Z")

    def test_quota_snapshot_receipt_is_exact_fresh_and_bound(self):
        def digest(value):
            return "sha256:" + hashlib.sha256(
                json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()

        body = {
            "schema_version": "0.1.0",
            "kind": "quota_snapshot_receipt",
            "snapshot_id": "quota:job-1",
            "project_id": "project-alpha",
            "provider": "fixture-provider",
            "exact_model": "fixture-model@2026-08-15",
            "quota_kind": "token",
            "pool_id": "pool:fixture",
            "remaining_units": 10,
            "reserved_units": 2,
            "reset_at": "2026-08-17T00:00:00Z",
            "observed_at": "2026-08-15T00:00:00Z",
            "maximum_age_seconds": 3600,
            "source_reference": "source:fixture-1",
            "source_receipt_digest": digest("source:fixture-1"),
        }
        receipt = {**body, "snapshot_digest": digest(body)}
        report = validate_quota_snapshot_receipt(
            receipt,
            expected_digest=receipt["snapshot_digest"],
            expected_provider="fixture-provider",
            expected_model="fixture-model@2026-08-15",
            expected_pool_id="pool:fixture",
            now_utc="2026-08-15T00:00:30Z",
        )
        self.assertTrue(report["valid"])
        self.assertEqual(receipt["snapshot_digest"], report["snapshot_digest"])

        receipt["remaining_units"] = 0
        with self.assertRaisesRegex(ValueError, "snapshot self-digest"):
            validate_quota_snapshot_receipt(receipt, now_utc="2026-08-15T00:00:30Z")

    def test_quota_snapshot_receipt_stale_or_transplanted_is_rejected(self):
        def digest(value):
            return "sha256:" + hashlib.sha256(
                json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()

        body = {
            "schema_version": "0.1.0", "kind": "quota_snapshot_receipt",
            "snapshot_id": "quota:job-2", "project_id": "project-alpha",
            "provider": "fixture-provider", "exact_model": "fixture-model",
            "quota_kind": "token", "pool_id": "pool:fixture",
            "remaining_units": 10, "reserved_units": 0,
            "reset_at": "2026-08-17T00:00:00Z",
            "observed_at": "2026-08-15T00:00:00Z", "maximum_age_seconds": 60,
            "source_reference": "source:fixture-2",
            "source_receipt_digest": digest("source:fixture-2"),
        }
        receipt = {**body, "snapshot_digest": digest(body)}
        with self.assertRaisesRegex(ValueError, "stale"):
            validate_quota_snapshot_receipt(receipt, now_utc="2026-08-15T00:02:00Z")
        with self.assertRaisesRegex(ValueError, "provider binding"):
            validate_quota_snapshot_receipt(
                receipt,
                expected_provider="other-provider",
                now_utc="2026-08-15T00:00:30Z",
            )

    def test_launch_quota_recheck_blocks_before_child(self):
        def digest(value):
            return "sha256:" + hashlib.sha256(
                json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            packet = _local_effect_packet(workspace, "quota-drift", "attempt-quota-drift")
            packet["provider"] = "fixture-provider"
            packet["pool_id"] = "fake.local"
            packet["quota_snapshot"] = {
                "schema_version": "0.1.0", "kind": "quota_snapshot_receipt",
                "snapshot_id": "quota:quota-drift", "project_id": "project-alpha",
                "provider": "fixture-provider", "exact_model": "local/fake",
                "quota_kind": "token", "pool_id": "fake.local",
                "remaining_units": 10, "reserved_units": 0,
                "reset_at": "2099-01-01T00:00:00Z",
                "observed_at": "2026-08-15T00:00:00Z", "maximum_age_seconds": 3600,
                "source_reference": "source:quota-drift",
                "source_receipt_digest": digest("source:quota-drift"),
            }
            quota_body = dict(packet["quota_snapshot"])
            packet["quota_snapshot"]["snapshot_digest"] = digest(quota_body)
            controller = SQLiteController(root / "dispatch.sqlite3", workspace=workspace)
            controller.enqueue(packet)
            with SQLiteStore(root / "dispatch.sqlite3") as store:
                with store.controller_lease("quota-drift-owner", ttl_seconds=90) as lease:
                    claim = store.claim_next_job(
                        "quota-drift-owner", int(lease["fence_token"]), lease_ttl_seconds=90
                    )
                    self.assertIsNotNone(claim)
                    assert claim is not None
                    claim["job"]["payload"]["quota_snapshot"]["remaining_units"] = 0
                    with mock.patch("sqlite_controller.continuity._load_process_group_run") as runner:
                        result = controller._execute_claim(
                            store,
                            claim,
                            "quota-drift-owner",
                            int(lease["fence_token"]),
                        )
                    self.assertFalse(runner.called)
                    self.assertEqual("failed", result["status"])
    def test_codex_sol_policy_accepts_only_exact_sol_route(self):
        packet = {
            "model_policy": "codex-sol-max",
            "attempts": [{
                "pool_id": "codex.luna",
                "provider": "codex",
                "model": "gpt-5.6-sol",
                "variant": "max",
            }],
        }
        SQLiteController._validate_model_policy(packet)
        packet["attempts"][0]["model"] = "gpt-5.6-luna"
        with self.assertRaisesRegex(ValueError, "exact model allow-list"):
            SQLiteController._validate_model_policy(packet)

    def test_dual_model_policy_accepts_only_exact_spark_or_gemini_route(self):
        base = {
            "model_policy": "codex-spark-antigravity-gemini",
            "attempts": [{
                "pool_id": "codex.spark",
                "provider": "codex",
                "model": "gpt-5.3-codex-spark",
                "variant": "xhigh",
            }],
        }
        SQLiteController._validate_model_policy(base)
        base["attempts"][0] = {
            "pool_id": "antigravity.gemini",
            "provider": "antigravity",
            "model": "gemini-3.6-flash-high",
            "variant": None,
        }
        SQLiteController._validate_model_policy(base)
        base["attempts"][0]["model"] = "gemini-3.1-pro-high"
        with self.assertRaisesRegex(ValueError, "exact model allow-list"):
            SQLiteController._validate_model_policy(base)

    def test_codex_only_packet_rejects_non_codex_model_before_db_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            db = root / "dispatch.sqlite3"
            controller = SQLiteController(db)
            packet = {
                "schema_version": 1,
                "packet_id": "packet-policy-reject",
                "job_id": "policy-reject",
                "workspace": str(root),
                "write_scope": "out/policy-reject",
                "required_artifacts": [str(root / "out.txt")],
                "validation_required": True,
                "validation_argv": [sys.executable, "-c", "import sys; sys.exit(0)"],
                "model_policy": "codex-luna-max",
                "attempts": [{
                    "attempt_id": "attempt-policy-reject",
                    "adapter": "command",
                    "transport": "local",
                    "argv": [sys.executable, "-c", "print('no')"],
                    "model": "opencode-go/deepseek-v4-flash",
                    "variant": "max",
                    "pool_id": "opencode.go",
                    "provider": "opencode",
                }],
            }
            with self.assertRaisesRegex(ValueError, "codex-luna-max"):
                controller.enqueue(packet)
            self.assertFalse(db.exists())

    def test_remote_packet_envelope_is_exact_model_variant_and_metadata_only(self):
        packet = {
            "schema_version": 1,
            "packet_id": "packet-remote",
            "job_id": "job-remote",
            "model": "opencode-go/deepseek-v4-flash",
            "variant": "max",
            "write_scope": ".lad/jobs/job-remote",
            "required_artifacts": ["/srv/project/out/result.json"],
            "validation_required": True,
            "resource_request": {"ram_gib": 2, "cpu_cores": 1},
            "execution_host": "remote-a",
            "workload_host": "remote-a",
            "execution_transport": "ssh",
            "workload_transport": "ssh",
            "attempts": [{
                "attempt_id": "attempt-remote",
                "adapter": "server_local",
                "transport": "ssh",
                "host_id": "remote-a",
                "provider": "server_local",
                "pool_id": "server_local.remote-a",
                "model": "opencode-go/deepseek-v4-flash",
                "variant": "max",
            }],
        }
        envelope = build_transport_envelope(packet)
        self.assertEqual("execute.prepared", envelope["operation"])
        self.assertEqual("max", envelope["payload_summary"]["variant"])
        self.assertNotIn("prompt", json.dumps(envelope))
        packet["attempts"][0].pop("variant")
        packet.pop("variant")
        with self.assertRaises(ValueError):
            build_transport_envelope(packet)

    def test_remote_gemini_envelope_preserves_explicit_null_variant(self):
        packet = {
            "schema_version": 1,
            "packet_id": "packet-gemini",
            "job_id": "job-gemini",
            "model": "gemini-3.6-flash-high",
            "variant": None,
            "provider": "antigravity",
            "pool_id": "antigravity.gemini",
            "write_scope": ".lad/jobs/job-gemini",
            "required_artifacts": ["/srv/project/out/gemini.json"],
            "validation_required": True,
            "execution_host": "westd",
            "workload_host": "westd",
            "execution_transport": "ssh",
            "workload_transport": "ssh",
            "attempts": [{
                "attempt_id": "attempt-gemini",
                "adapter": "remote_cli",
                "transport": "ssh",
                "host_id": "westd",
                "provider": "antigravity",
                "pool_id": "antigravity.gemini",
                "model": "gemini-3.6-flash-high",
                "variant": None,
            }],
        }
        envelope = build_transport_envelope(packet)
        self.assertIsNone(envelope["payload_summary"]["variant"])
        self.assertEqual("antigravity.gemini", envelope["payload_summary"]["pool_id"])

        split_packet = {
            "schema_version": 1,
            "packet_id": "packet-split-gemini",
            "job_id": "job-split-gemini",
            "model": "gemini-3.6-flash-high",
            "variant": None,
            "provider": "antigravity",
            "pool_id": "antigravity.gemini",
            "execution_host": "local_mac",
            "workload_host": "remote_gpu",
            "execution_transport": "local",
            "workload_transport": "ssh",
            "desktop_split_placement": {"contract_digest": "a" * 64},
            "attempts": [{
                "attempt_id": "attempt-split-gemini",
                "adapter": "antigravity",
                "transport": "local",
                "host_id": "local_mac",
                "provider": "antigravity",
                "pool_id": "antigravity.gemini",
                "model": "gemini-3.6-flash-high",
                "variant": None,
            }],
        }
        split_envelope = build_transport_envelope(split_packet)
        self.assertEqual("remote_gpu", split_envelope["target_id"])
        self.assertEqual("remote_gpu", split_envelope["payload_summary"]["host_id"])
        self.assertIsNone(split_envelope["payload_summary"]["variant"])

    def test_remote_cli_ingress_rejects_tampered_digest_and_confined_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            controller = SQLiteController(root / "dispatch.sqlite3")
            packet = _remote_cli_packet()
            packet["remote_cli_placement"]["model"] = "gpt-5.6-luna"
            with self.assertRaisesRegex(ValueError, "contract digest mismatch"):
                controller.enqueue_remote(packet)
            self.assertFalse((root / "dispatch.sqlite3").exists())

            packet = _remote_cli_packet()
            contract = packet["remote_cli_placement"]
            contract["receipt"]["path"] = "/srv/other/receipt.json"
            _reseal_remote_contract(contract)
            with self.assertRaisesRegex(ValueError, "receipt.path escapes"):
                controller.enqueue_remote(packet)
            self.assertFalse((root / "dispatch.sqlite3").exists())

    def test_required_cgroup_evidence_blocks_sqlite_claim_and_records_diagnostic(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            controller = SQLiteController(root / "dispatch.sqlite3", workspace=workspace)
            packet = {
                "schema_version": 1,
                "packet_id": "packet-cgroup-unknown",
                "job_id": "cgroup-unknown",
                "workspace": str(workspace),
                "write_scope": "out/cgroup-unknown",
                "required_artifacts": ["out/result.txt"],
                "validation_required": True,
                "validation_argv": [sys.executable, "-c", "import sys; sys.exit(0)"],
                "resource_reservation_required": True,
                "resource_request": {
                    "host_id": "local_mac",
                    "ram_gib": 2,
                    "cpu_cores": 1,
                },
                "attempts": [{
                    "attempt_id": "attempt-cgroup-unknown",
                    "adapter": "command",
                    "transport": "local",
                    "argv": [sys.executable, "-c", "print('should not run')"],
                    "model": "local/fake",
                    "pool_id": "fake.local",
                    "provider": "fake",
                }],
            }
            controller.enqueue(packet)
            unknown_ram = {
                "total_bytes": 32 * 1024**3,
                "available_bytes": 24 * 1024**3,
                "swap_total_bytes": 0,
                "swap_used_bytes": 0,
                "pressure_state": "normal",
                "cgroup_required": True,
                "cgroup_memory_evidence_status": "unknown",
            }
            with mock.patch(
                "sqlite_controller.governor.observe_local",
                return_value=(unknown_ram, []),
            ):
                result = controller.run(once=True, max_lanes=1)
            self.assertEqual([], result["results"])
            blocked = [
                row for row in result["reservation_diagnostics"]
                if row.get("job_id") == "cgroup-unknown"
            ]
            self.assertEqual(1, len(blocked))
            self.assertEqual("blocked", blocked[0]["status"])
            self.assertIn("cgroup_memory_evidence_unknown", blocked[0]["admission"]["evidence_block_reasons"])
            with SQLiteStore(root / "dispatch.sqlite3") as store:
                self.assertEqual("queued", store.get_job("cgroup-unknown")["status"])
                self.assertEqual([], store.list_reservations(statuses=("active",)))

    def test_explicit_local_disk_request_is_gated_before_claim(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            controller = SQLiteController(root / "dispatch.sqlite3", workspace=workspace)
            packet = {
                "schema_version": 1,
                "packet_id": "packet-disk-low",
                "job_id": "disk-low",
                "workspace": str(workspace),
                "write_scope": "out/disk-low",
                "required_artifacts": ["out/result.txt"],
                "validation_required": True,
                "validation_argv": [sys.executable, "-c", "import sys; sys.exit(0)"],
                "resource_reservation_required": True,
                "resource_request": {
                    "host_id": "local_mac",
                    "ram_gib": 1,
                    "cpu_cores": 1,
                    "new_disk_gib": 2,
                },
                "attempts": [{
                    "attempt_id": "attempt-disk-low",
                    "adapter": "command",
                    "transport": "local",
                    "argv": [sys.executable, "-c", "print('must not run')"],
                    "model": "gpt-5.6-luna",
                    "pool_id": "codex.luna",
                    "provider": "codex",
                }],
            }
            controller.enqueue(packet)
            disk_report = {
                "allowed": True,
                "filesystems": [{
                    "path": str(workspace), "probe_path": str(workspace),
                    "evidence": "complete", "free_bytes": 512 * 1024**2,
                    "total_bytes": 10 * 1024**3, "free_percent": 5.0,
                }],
            }
            with mock.patch.object(
                controller,
                "_local_disk_evidence",
                return_value=(
                    {
                        "allowed": False,
                        "decision": "block",
                        "reason": "local_disk_capacity_exceeded",
                        "source": "resource_admission",
                        "requested_disk_gib": 2.0,
                        "usable_disk_gib": 0.25,
                        "report": disk_report,
                    },
                    None,
                ),
            ), mock.patch(
                "sqlite_controller.governor.observe_local",
                return_value=({
                    "total_bytes": 32 * 1024**3,
                    "available_bytes": 24 * 1024**3,
                    "swap_total_bytes": 0,
                    "swap_used_bytes": 0,
                    "pressure_state": "normal",
                }, []),
            ):
                result = controller.run(once=True, max_lanes=1)
            self.assertEqual([], result["results"])
            blocked = [row for row in result["reservation_diagnostics"] if row.get("job_id") == "disk-low"]
            self.assertEqual(1, len(blocked))
            self.assertEqual("blocked", blocked[0]["status"])
            self.assertEqual("local_disk_capacity_exceeded", blocked[0]["admission"]["reason"])
            self.assertIn("disk_admission", blocked[0]["admission"])
            with SQLiteStore(root / "dispatch.sqlite3") as store:
                self.assertEqual("queued", store.get_job("disk-low")["status"])
                self.assertEqual([], store.list_reservations(statuses=("active",)))

    def test_local_reservations_are_aggregated_before_multi_lane_claim(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            controller = SQLiteController(root / "dispatch.sqlite3", workspace=workspace)

            def packet(index: int) -> dict[str, object]:
                name = f"reserved-{index}.txt"
                return {
                    "schema_version": 1,
                    "packet_id": f"packet-reserved-{index}",
                    "job_id": f"reserved-{index}",
                    "workspace": str(workspace),
                    "write_scope": f"out/{index}",
                    "required_artifacts": [f"out/{name}"],
                    "validation_required": True,
                    "validation_argv": [
                        sys.executable,
                        "-c",
                        f"import pathlib,sys; sys.exit(0 if pathlib.Path('out/{name}').is_file() else 2)",
                    ],
                    "resource_reservation_required": True,
                    "resource_request": {
                        "host_id": "local_mac",
                        "ram_gib": 8,
                        "cpu_cores": 1,
                    },
                    "attempts": [{
                        "attempt_id": f"reserved-attempt-{index}",
                        "adapter": "command",
                        "transport": "local",
                        "argv": [
                            sys.executable,
                            "-c",
                            f"import pathlib; pathlib.Path('out').mkdir(exist_ok=True); pathlib.Path('out/{name}').write_text('ok\\n')",
                        ],
                        "model": "local/fake",
                        "pool_id": "fake.local",
                        "provider": "fake",
                    }],
                }

            controller.enqueue(packet(0))
            controller.enqueue(packet(1))
            ram = {
                "total_bytes": 32 * 1024**3,
                "available_bytes": 16 * 1024**3,
                "swap_total_bytes": 2 * 1024**3,
                "swap_used_bytes": 0,
                "pressure_state": "normal",
            }
            with mock.patch("sqlite_controller.governor.observe_local", return_value=(ram, [])):
                result = controller.run(once=True, max_lanes=2)
            self.assertEqual(1, len(result["results"]))
            self.assertEqual("completed", result["results"][0]["status"])
            self.assertEqual(1, sum(row["status"] == "blocked" for row in result["reservation_diagnostics"]))
            with SQLiteStore(root / "dispatch.sqlite3") as store:
                self.assertEqual("queued", store.get_job("reserved-1")["status"])

    def test_long_running_lane_keeps_controller_lease_heartbeat_alive(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            artifact = workspace / "heartbeat.txt"
            controller = SQLiteController(
                root / "heartbeat.sqlite3",
                workspace=workspace,
                heartbeat_interval_seconds=0.1,
            )
            packet = {
                "schema_version": 1,
                "packet_id": "packet-heartbeat",
                "job_id": "heartbeat-job",
                "workspace": str(workspace),
                "write_scope": "out/heartbeat",
                "required_artifacts": [str(artifact)],
                "validation_required": True,
                "validation_argv": [sys.executable, "-c", "import sys; sys.exit(0)"],
                "attempts": [{
                    "attempt_id": "heartbeat-attempt",
                    "adapter": "command",
                    "transport": "local",
                    "argv": [
                        sys.executable,
                        "-c",
                        "import pathlib,time; time.sleep(1.2); pathlib.Path('heartbeat.txt').write_text('ok\\n')",
                    ],
                    "model": "local/fake",
                    "pool_id": "fake.local",
                    "provider": "fake",
                }],
            }
            controller.enqueue(packet)
            result: dict[str, object] = {}

            def run() -> None:
                result.update(controller.run(once=True, owner_id="heartbeat-owner"))

            thread = threading.Thread(target=run)
            thread.start()
            db = root / "heartbeat.sqlite3"
            deadline = time.time() + 5
            first_heartbeat = None
            while time.time() < deadline and first_heartbeat is None:
                if db.exists():
                    with SQLiteStore(db) as store:
                        leases = store.snapshot()["leases"]
                        if leases:
                            first_heartbeat = leases[0]["heartbeat_at_utc"]
                if first_heartbeat is None:
                    time.sleep(0.02)
            self.assertIsNotNone(first_heartbeat)
            with SQLiteStore(db) as store:
                first_job_lease = None
                first_attempt_lease = None
                deadline = time.time() + 5
                while time.time() < deadline:
                    snapshot = store.snapshot()
                    if snapshot["jobs"] and snapshot["attempts"]:
                        first_job_lease = snapshot["jobs"][0]["lease_expires_at_utc"]
                        first_attempt_lease = snapshot["attempts"][0]["lease_expires_at_utc"]
                        break
                    time.sleep(0.02)
                self.assertIsNotNone(first_job_lease)
                self.assertIsNotNone(first_attempt_lease)
            time.sleep(0.35)
            with SQLiteStore(db) as store:
                snapshot = store.snapshot()
                current = snapshot["leases"][0]
            self.assertNotEqual(first_heartbeat, current["heartbeat_at_utc"])
            self.assertEqual("active", current["status"])
            self.assertNotEqual(first_job_lease, snapshot["jobs"][0]["lease_expires_at_utc"])
            self.assertNotEqual(first_attempt_lease, snapshot["attempts"][0]["lease_expires_at_utc"])
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive())
            self.assertEqual("completed", result["results"][0]["status"])

    def test_fenced_heartbeat_is_reported_as_completion_error_without_success(self):
        """A lost heartbeat cannot become a fabricated terminal success."""
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            db = root / "dispatch.sqlite3"
            controller = SQLiteController(db, workspace=workspace, heartbeat_interval_seconds=0.05)
            packet = _local_effect_packet(workspace, "heartbeat-fence", "attempt-heartbeat-fence")
            controller.enqueue(packet)

            with (
                mock.patch.object(
                    SQLiteStore,
                    "job_lease_heartbeat",
                    side_effect=FencingError("heartbeat fence lost"),
                ),
                mock.patch.object(
                    SQLiteStore,
                    "complete_job",
                    side_effect=FencingError("completion fence lost"),
                ),
            ):
                result = controller.run(once=True, owner_id="heartbeat-fence-owner")

            lane = result["results"][0]
            self.assertEqual("failed", lane["status"])
            self.assertFalse(lane["success"])
            self.assertEqual("FencingError", lane["completion_error"])
            self.assertFalse((workspace / "out/heartbeat-fence/effect.log").exists())
            with SQLiteStore(db) as store:
                self.assertEqual("running", store.get_job("heartbeat-fence")["status"])
                self.assertEqual(
                    "running",
                    store.list_attempts("heartbeat-fence")[0]["status"],
                )
                event_types = [event["event_type"] for event in store.list_events("heartbeat-fence")]
                self.assertNotIn("job_completed", event_types)
                self.assertNotIn("job_failed", event_types)

    def test_completion_fence_has_one_effect_and_recovery_requires_dead_liveness(self):
        """Unknown handoff blocks; confirmed-dead handoff alone becomes retryable."""
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            db = root / "dispatch.sqlite3"
            controller = SQLiteController(db, workspace=workspace)
            fenced = _local_effect_packet(workspace, "completion-fence", "attempt-completion-fence")
            controller.enqueue(fenced)

            # The child performs its side effect once, but the controller fence
            # is lost before the durable completion transaction can commit.
            with mock.patch.object(
                SQLiteStore,
                "complete_job",
                side_effect=FencingError("completion fence lost"),
            ):
                result = controller.run(once=True, owner_id="completion-fence-owner")
            lane = result["results"][0]
            self.assertEqual("failed", lane["status"])
            self.assertEqual("FencingError", lane["completion_error"])
            effect = workspace / "out/completion-fence/effect.log"
            self.assertEqual(["effect"], effect.read_text(encoding="utf-8").splitlines())

            # Create a second claimed row whose explicit PID will be used to
            # distinguish the safe unknown handoff from confirmed-dead retry.
            dead = _local_effect_packet(
                workspace,
                "confirmed-dead",
                "attempt-confirmed-dead",
                pid="424242",
            )
            controller.enqueue(dead)
            expired = "1970-01-01T00:00:00+00:00"
            with SQLiteStore(db) as store:
                with store.controller_lease("dead-owner", ttl_seconds=30) as lease:
                    claim = store.claim_job(
                        "confirmed-dead",
                        "dead-owner",
                        int(lease["fence_token"]),
                        lease_ttl_seconds=30,
                    )
                    self.assertIsNotNone(claim)
                store.connection.execute(
                    "UPDATE jobs SET lease_expires_at_utc = ? WHERE status = 'running'",
                    (expired,),
                )
                store.connection.execute(
                    "UPDATE attempts SET lease_expires_at_utc = ? WHERE status = 'running'",
                    (expired,),
                )
                store.connection.commit()

            # The fenced completion row has no PID breadcrumb and must be
            # blocked.  The second row is admitted to retry only because its
            # exact PID is deterministically observed dead.
            with mock.patch("sqlite_controller.os.kill", side_effect=ProcessLookupError):
                resumed = controller.resume(owner_id="recovery-owner")
            self.assertEqual(2, resumed["recovered"])
            with SQLiteStore(db) as store:
                unknown = store.get_job("completion-fence")
                dead_row = store.get_job("confirmed-dead")
                self.assertEqual("blocked", unknown["status"])
                self.assertEqual("recovery_liveness_unknown", unknown["error_class"])
                self.assertEqual("retry", dead_row["status"])
                self.assertEqual("controller_restarted", dead_row["error_class"])
                self.assertEqual(
                    "job_recovery_blocked",
                    store.list_events("completion-fence")[-1]["event_type"],
                )
                self.assertEqual(
                    "job_recovered",
                    store.list_events("confirmed-dead")[-1]["event_type"],
                )
                self.assertEqual("abandoned", store.list_attempts("completion-fence")[0]["status"])
                self.assertEqual("abandoned", store.list_attempts("confirmed-dead")[0]["status"])
            # Resume only reconciles; it must not execute the retry or repeat
            # the side effect from the fenced first attempt.
            self.assertEqual(["effect"], effect.read_text(encoding="utf-8").splitlines())

    def test_run_claims_and_completes_two_independent_lanes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            controller = SQLiteController(root / "dispatch.sqlite3", workspace=workspace)
            for index in range(2):
                name = f"lane-{index}.txt"
                packet = {
                    "schema_version": 1,
                    "packet_id": f"packet-{index}",
                    "job_id": f"lane-{index}",
                    "workspace": str(workspace),
                    "write_scope": f"out/{index}",
                    "required_artifacts": [f"out/{name}"],
                    "validation_required": True,
                    "validation_argv": [
                        sys.executable,
                        "-c",
                        f"import pathlib,sys; sys.exit(0 if pathlib.Path('out/{name}').is_file() else 2)",
                    ],
                    "attempts": [{
                        "attempt_id": f"attempt-{index}",
                        "adapter": "command",
                        "transport": "local",
                        "argv": [
                            sys.executable,
                            "-c",
                            f"import pathlib,time; time.sleep(.1); pathlib.Path('out/{name}').parent.mkdir(exist_ok=True); pathlib.Path('out/{name}').write_text('ok\\n')",
                        ],
                        "model": "gpt-5.3-codex-spark",
                        "pool_id": "codex.spark",
                        "provider": "codex",
                    }],
                }
                controller.enqueue(packet)
            result = controller.run(once=True, max_lanes=2)
            self.assertEqual(2, len(result["results"]))
            self.assertEqual({"completed"}, {row["status"] for row in result["results"]})
            self.assertTrue((workspace / "out/lane-0.txt").is_file())
            self.assertTrue((workspace / "out/lane-1.txt").is_file())

    def test_transient_failure_is_backed_off_before_retry_lane_claim(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            controller = SQLiteController(root / "backoff.sqlite3", workspace=workspace)
            packet = {
                "schema_version": 1,
                "packet_id": "packet-backoff",
                "job_id": "backoff-job",
                "workspace": str(workspace),
                "write_scope": "out/backoff",
                "required_artifacts": ["out/result.txt"],
                "validation_required": True,
                "validation_argv": [sys.executable, "-c", "import sys; sys.exit(0)"],
                "attempts": [
                    {
                        "attempt_id": "backoff-first",
                        "adapter": "command",
                        "transport": "local",
                        "argv": [
                            sys.executable,
                            "-c",
                            "print('connection timed out'); raise SystemExit(7)",
                        ],
                        "model": "local/fake",
                        "pool_id": "fake.local",
                        "provider": "fake",
                        "fallback_on": ["network"],
                        "retry_backoff_seconds": 30,
                    },
                    {
                        "attempt_id": "backoff-second",
                        "adapter": "command",
                        "transport": "local",
                        "argv": [
                            sys.executable,
                            "-c",
                            "import pathlib; pathlib.Path('out').mkdir(); pathlib.Path('out/result.txt').write_text('ok\\n')",
                        ],
                        "model": "local/fake",
                        "pool_id": "fake.local",
                        "provider": "fake",
                    },
                ],
            }
            controller.enqueue(packet)
            first = controller.run(once=True)
            self.assertEqual("retry", first["results"][0]["status"])
            self.assertGreaterEqual(first["results"][0]["retry_delay_seconds"], 30)
            immediate = controller.run(once=True)
            self.assertEqual([], immediate["results"])
            with SQLiteStore(root / "backoff.sqlite3") as store:
                self.assertEqual("retry", store.get_job("backoff-job")["status"])

    def test_one_lane_exception_is_terminal_and_does_not_drop_sibling(self):
        """A broken lane is recorded while an independent lane still finishes."""
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            controller = SQLiteController(root / "dispatch.sqlite3", workspace=workspace)

            def packet(job_id: str, filename: str) -> dict[str, object]:
                return {
                    "schema_version": 1,
                    "packet_id": f"packet-{job_id}",
                    "job_id": job_id,
                    "workspace": str(workspace),
                    "write_scope": f"out/{job_id}",
                    "required_artifacts": [f"out/{filename}"],
                    "validation_required": True,
                    "validation_argv": [
                        sys.executable,
                        "-c",
                        f"import pathlib,sys; sys.exit(0 if pathlib.Path('out/{filename}').is_file() else 7)",
                    ],
                    "attempts": [{
                        "attempt_id": f"attempt-{job_id}",
                        "adapter": "command",
                        "transport": "local",
                        "argv": [
                            sys.executable,
                            "-c",
                            f"import pathlib; pathlib.Path('out/{filename}').parent.mkdir(exist_ok=True); pathlib.Path('out/{filename}').write_text('ok\\n')",
                        ],
                        "model": "local/fake",
                        "pool_id": "fake.local",
                        "provider": "fake",
                    }],
                }

            controller.enqueue(packet("lane-fails", "fails.txt"))
            controller.enqueue(packet("lane-succeeds", "succeeds.txt"))
            original = controller._execute_claim

            def flaky(store, claim, owner_id, fence_token):
                if (claim.get("job") or {}).get("job_id") == "lane-fails":
                    raise RuntimeError("synthetic lane failure")
                return original(store, claim, owner_id, fence_token)

            controller._execute_claim = flaky
            result = controller.run(once=True, max_lanes=2)
            self.assertEqual(2, len(result["results"]))
            by_job = {row["job_id"]: row for row in result["results"]}
            self.assertEqual("failed", by_job["lane-fails"]["status"])
            self.assertEqual("controller", by_job["lane-fails"]["error_class"])
            self.assertEqual("completed", by_job["lane-succeeds"]["status"])
            self.assertTrue((workspace / "out/succeeds.txt").is_file())
            with SQLiteStore(root / "dispatch.sqlite3") as store:
                snapshot = store.snapshot()
            statuses = {row["job_id"]: row["status"] for row in snapshot["jobs"]}
            self.assertEqual({"lane-fails": "failed", "lane-succeeds": "completed"}, statuses)
            self.assertTrue(any(row["event_type"] == "job_failed" for row in snapshot["events"]))

    def test_enqueue_requeues_failed_job_from_an_approved_replan(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            artifact = workspace / "out" / "replanned.txt"
            controller = SQLiteController(root / "dispatch.sqlite3", workspace=workspace)
            first = {
                "schema_version": 1,
                "packet_id": "packet-replan-first",
                "job_id": "replan-controller-job",
                "workspace": str(workspace),
                "write_scope": "out/replan-controller-job",
                "required_artifacts": ["out/replanned.txt"],
                "validation_required": True,
                "validation_argv": [sys.executable, "-c", "import sys; sys.exit(0)"],
                "attempts": [{
                    "attempt_id": "attempt-first",
                    "adapter": "command",
                    "transport": "local",
                    "argv": [sys.executable, "-c", "print('rate limit'); raise SystemExit(7)"],
                    "model": "gpt-5.3-codex-spark",
                    "pool_id": "codex.spark",
                    "provider": "codex",
                }],
            }
            controller.enqueue(first)
            failed = controller.run(once=True)
            self.assertEqual("failed", failed["results"][0]["status"])

            replanned = dict(first)
            replanned["packet_id"] = "packet-replan-second"
            replanned["attempts"] = [{
                **first["attempts"][0],
                "attempt_id": "attempt-second",
                "argv": [
                    sys.executable,
                    "-c",
                    "import pathlib; pathlib.Path('out').mkdir(); pathlib.Path('out/replanned.txt').write_text('ok\\n')",
                ],
            }]
            queued = controller.enqueue(replanned)
            self.assertEqual("queued", queued["status"])
            completed = controller.run(once=True)
            self.assertEqual("completed", completed["results"][0]["status"])
            self.assertTrue(artifact.is_file())
            with SQLiteStore(root / "dispatch.sqlite3") as store:
                job = store.get_job("replan-controller-job")
                self.assertEqual("completed", job["status"])
                self.assertEqual(2, job["attempt_count"])
                self.assertTrue(any(e["event_type"] == "job_requeued" for e in store.list_events("replan-controller-job")))

    def test_future_retry_wake_avoids_tight_idle_polling(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            db = root / "dispatch.sqlite3"
            with SQLiteStore(db) as store:
                lease = store.acquire_controller_lease("seed-owner", ttl_seconds=30)
                store.create_job("future-retry", {"kind": "fake"})
                claim = store.claim_job(
                    "future-retry", "seed-owner", lease["fence_token"], lease_ttl_seconds=30
                )
                assert claim
                store.complete_job(
                    "future-retry",
                    claim["attempt"]["attempt_id"],
                    "seed-owner",
                    lease["fence_token"],
                    success=False,
                    error_class="network",
                    retryable=True,
                    retry_at_utc="2099-01-01T00:10:00Z",
                )
                store.release_controller_lease("seed-owner", lease["fence_token"])
            sleeps: list[float] = []
            controller = SQLiteController(db, workspace=workspace)
            result = controller.run(
                max_idle_rounds=2,
                poll_seconds=0.01,
                idle_backoff_seconds=0.25,
                sleep_fn=sleeps.append,
            )
            self.assertTrue(result["ok"])
            self.assertEqual(1, len(sleeps))
            self.assertGreaterEqual(sleeps[0], 0.25)

    def test_replan_feedback_wake_is_bounded_while_queue_is_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            db = root / "dispatch.sqlite3"
            sleeps: list[float] = []
            controller = SQLiteController(db, workspace=workspace)
            result = controller.run(
                max_idle_rounds=2,
                poll_seconds=0.01,
                idle_backoff_seconds=0.25,
                replan_feedback={
                    "replan_at_utc": "2099-01-01T00:10:00Z",
                    "replan_reason": "blocked_pool_quota_reset",
                    "quota_reset_pool_id": "codex.spark",
                },
                sleep_fn=sleeps.append,
            )
            self.assertTrue(result["ok"])
            self.assertEqual(1, len(sleeps))
            self.assertGreaterEqual(sleeps[0], 0.25)
            self.assertEqual([], result["replan_diagnostics"])

    def test_due_replan_feedback_is_audited_once_per_feedback_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            db = root / "dispatch.sqlite3"
            controller = SQLiteController(db, workspace=workspace)
            result = controller.run(
                max_idle_rounds=3,
                poll_seconds=0.01,
                idle_backoff_seconds=0.05,
                replan_feedback={
                    "replan_at_utc": "2000-01-01T00:00:00Z",
                    "replan_reason": "resource_pressure",
                },
                sleep_fn=lambda _seconds: None,
            )
            self.assertTrue(result["ok"])
            self.assertEqual(2, len(result["replan_diagnostics"]))
            with SQLiteStore(db) as store:
                events = [event for event in store.list_events() if event["event_type"] == "replan_due"]
            self.assertEqual(1, len(events))
            self.assertEqual("resource_pressure", events[0]["payload"]["replan_reason"])

    def test_replan_feedback_loader_is_reread_without_restarting_controller(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            db = root / "dispatch.sqlite3"
            calls: list[int] = []
            feedbacks = [
                {"replan_at_utc": "2099-01-01T00:10:00Z", "replan_reason": "future"},
                {"replan_at_utc": "2000-01-01T00:00:00Z", "replan_reason": "now"},
            ]

            def load_feedback() -> Mapping[str, Any] | None:
                calls.append(1)
                return feedbacks[min(len(calls) - 1, len(feedbacks) - 1)]

            controller = SQLiteController(db, workspace=workspace)
            result = controller.run(
                max_idle_rounds=3,
                poll_seconds=0.01,
                idle_backoff_seconds=0.05,
                replan_feedback_loader=load_feedback,
                sleep_fn=lambda _seconds: None,
            )
            self.assertTrue(result["ok"])
            self.assertEqual(2, len(calls))
            self.assertTrue(any(row["schedule"]["reason"] == "replan_due" for row in result["replan_diagnostics"]))

    def test_replan_feedback_watcher_audits_due_signal_during_active_claim(self):
        """A long lane cannot hide a quota reset until provider completion."""
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            db = root / "dispatch.sqlite3"
            controller = SQLiteController(
                db,
                workspace=workspace,
                heartbeat_interval_seconds=0.05,
            )
            controller.enqueue(_local_effect_packet(workspace, "active-replan", "active-replan-attempt"))
            entered = threading.Event()
            due = threading.Event()
            release = threading.Event()
            calls: list[int] = []
            feedbacks = [
                {"replan_at_utc": "2099-01-01T00:10:00Z", "replan_reason": "future"},
                {
                    "replan_at_utc": "2000-01-01T00:00:00Z",
                    "replan_reason": "blocked_pool_quota_reset",
                    "quota_reset_pool_id": "codex.spark",
                },
            ]

            def load_feedback() -> Mapping[str, Any] | None:
                calls.append(1)
                value = feedbacks[min(len(calls) - 1, len(feedbacks) - 1)]
                if len(calls) >= 2:
                    due.set()
                return value

            original = controller._execute_claim

            def blocking_execute(store, claim, owner_id, fence_token):
                entered.set()
                self.assertTrue(due.wait(3))
                self.assertTrue(release.wait(3))
                return original(store, claim, owner_id, fence_token)

            controller._execute_claim = blocking_execute
            result_holder: dict[str, Any] = {}

            def run() -> None:
                result_holder.update(
                    controller.run(
                        once=True,
                        poll_seconds=0.05,
                        idle_backoff_seconds=0.1,
                        replan_feedback_loader=load_feedback,
                    )
                )

            thread = threading.Thread(target=run)
            thread.start()
            self.assertTrue(entered.wait(3))
            self.assertTrue(due.wait(3))
            release.set()
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive())
            self.assertTrue(result_holder["ok"])
            active_rows = [
                row for row in result_holder["replan_diagnostics"]
                if row.get("observation_mode") == "active"
                and row.get("schedule", {}).get("reason") == "replan_due"
            ]
            self.assertTrue(active_rows)
            with SQLiteStore(db) as store:
                events = [event for event in store.list_events() if event["event_type"] == "replan_due"]
            self.assertEqual(1, len(events))
            payload = events[0]["payload"]
            self.assertEqual("quota_reset", payload["trigger_source"])
            self.assertEqual("active", payload["observation_mode"])
            self.assertEqual(["active-replan"], payload["active_job_ids"])

    def test_cli_enqueue_run_and_status_use_transactional_backend(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            result = workspace / "result.txt"
            packet = {
                "schema_version": 1,
                "packet_id": "packet-sqlite-e2e",
                "job_id": "sqlite-e2e",
                "workspace": str(workspace),
                "write_scope": "artifacts/sqlite-e2e",
                "required_artifacts": [str(result)],
                "validation_required": True,
                "validation_argv": [sys.executable, "-c", "import pathlib,sys; sys.exit(0 if pathlib.Path('result.txt').read_text() == 'done\\n' else 7)"],
                "attempts": [{
                    "attempt_id": "packet-attempt",
                    "adapter": "command",
                    "transport": "local",
                    "argv": [sys.executable, "-c", "import pathlib; pathlib.Path('result.txt').write_text('done\\n')"],
                    "result_source_path": str(result),
                    "output_path": str(result),
                    "model": "gpt-5.3-codex-spark",
                    "pool_id": "codex.spark",
                    "provider": "codex",
                }],
            }
            packet_path = root / "packet.json"
            db_path = root / "dispatch.sqlite3"
            packet_path.write_text(json.dumps(packet), encoding="utf-8")

            enqueue = subprocess.run(
                [sys.executable, str(SCRIPT), "enqueue", "--db", str(db_path), "--job-file", str(packet_path)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(0, enqueue.returncode, enqueue.stdout + enqueue.stderr)
            run = subprocess.run(
                [sys.executable, str(SCRIPT), "run", "--db", str(db_path), "--workspace", str(workspace), "--once"],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(0, run.returncode, run.stdout + run.stderr)
            run_payload = json.loads(run.stdout)
            self.assertEqual("sqlite", run_payload["backend"])
            self.assertEqual("completed", run_payload["results"][0]["status"])
            self.assertTrue(run_payload["results"][0]["validation"]["ok"])
            self.assertEqual("done\n", result.read_text(encoding="utf-8"))

            status = subprocess.run(
                [sys.executable, str(SCRIPT), "status", "--db", str(db_path)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(0, status.returncode, status.stdout + status.stderr)
            snapshot = json.loads(status.stdout)["snapshot"]
            self.assertEqual("completed", snapshot["jobs"][0]["status"])
            self.assertTrue(any(row["event_type"] == "job_completed" for row in snapshot["events"]))

    def test_cli_enqueue_enforces_modern_packet_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            packet_path = root / "bad-packet.json"
            db_path = root / "dispatch.sqlite3"
            packet_path.write_text(
                json.dumps({"schema_version": 1, "packet_id": "bad", "job_id": "bad"}),
                encoding="utf-8",
            )
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "enqueue", "--db", str(db_path), "--job-file", str(packet_path)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(2, result.returncode)
            self.assertIn("task packet", result.stdout)
            if db_path.exists():
                from sqlite_store import SQLiteStore
                with SQLiteStore(db_path) as store:
                    self.assertEqual([], store.snapshot()["jobs"])


if __name__ == "__main__":
    unittest.main()
