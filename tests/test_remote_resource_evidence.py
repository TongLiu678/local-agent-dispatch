from __future__ import annotations

import datetime as dt
import pathlib
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from remote_resource_evidence import (  # noqa: E402
    GIB,
    derive_remote_resource_evidence,
    validate_remote_resource_evidence,
)
from sqlite_controller import SQLiteController  # noqa: E402
from sqlite_store import SQLiteStore  # noqa: E402


NOW = "2026-08-14T01:00:00+00:00"


def _packet() -> dict[str, object]:
    return {
        "schema_version": 1,
        "packet_id": "packet-remote-evidence",
        "job_id": "job-remote-evidence",
        # The controller's local workspace is deliberately different from
        # the target mount.  Remote admission must use remote_workspace.
        # Use a public-safe controller path; this must remain distinct from
        # the target mount without resembling a real user's home directory.
        "workspace": "/workspace/controller/staging/job-remote-evidence",
        "remote_workspace": "/srv/project/job-remote-evidence",
        "write_scope": "out/job",
        "required_artifacts": ["/srv/project/job-remote-evidence/out/job/result.json"],
        "validation_required": True,
        "validation_argv": [sys.executable, "-c", "import sys; sys.exit(0)"],
        "resource_reservation_required": True,
        "resource_request": {
            "host_id": "westd",
            "pool_id": "server_local.westd",
            "cpu_cores": 1,
            "ram_gib": 2,
            "gpu_count": 0,
            "vram_gib_per_gpu": 0,
            "new_disk_gib": 1,
            "write_scope": "out/job",
        },
        "pool_id": "server_local.westd",
        "execution_host": "westd",
        "workload_host": "westd",
        "execution_transport": "ssh",
        "workload_transport": "ssh",
        "attempts": [{
            "attempt_id": "attempt-remote-evidence",
            "adapter": "server_local",
            "transport": "ssh",
            "host_id": "westd",
            "provider": "server_local",
            "pool_id": "server_local.westd",
            "model": "server/local",
            "variant": "bounded",
            "workspace": "/srv/project/job-remote-evidence",
        }],
    }


def _evidence() -> dict[str, object]:
    return {
        "schema_version": 1,
        "host_id": "westd",
        "observed_at_utc": NOW,
        "ttl_seconds": 1800,
        "cgroup": {
            "status": "complete",
            "max_bytes": 16 * GIB,
            "current_bytes": 4 * GIB,
            "available_bytes": 12 * GIB,
        },
        "psi": {"some_avg10": 1.5},
        "storage": {
            "mount_path": "/srv/project",
            "workspace_path": "/srv/project/job-remote-evidence",
            "writable": True,
            "total_bytes": 100 * GIB,
            "free_bytes": 10 * GIB,
        },
        "route": {
            "kind": "workload",
            "status": "direct",
            "verified": True,
            "target_host_id": "westd",
        },
        "capacity": {
            "cpu_cores": 8,
            "ram_gib": 12,
            "gpu_count": 0,
            "vram_gib_per_gpu": 0,
            "new_disk_gib": 10,
        },
        "write_scope_path": "/srv/project/job-remote-evidence/out/job",
        # A producer may include diagnostics, but the persisted report must
        # never echo arbitrary evidence fields into the reservation ledger.
        "secret_token": "must-not-be-persisted",
    }


class RemoteResourceEvidenceTests(unittest.TestCase):
    def test_derive_requires_explicit_verified_route_and_complete_probe(self):
        host = {
            "host_id": "westd",
            "transport": "ssh",
            "reachable": True,
            "project_path": "/srv/project",
            "last_probed_at_utc": NOW,
            "cgroup_memory_evidence_status": "complete",
            "cgroup_memory_max_bytes": 16 * GIB,
            "cgroup_memory_current_bytes": 4 * GIB,
            "cgroup_memory_available_bytes": 12 * GIB,
            "psi_some_avg10": 1.5,
            "logical_cpu_cores": 8,
            "estimated_idle_cpu_cores": 6,
            "gpu_count": 0,
            "storage_paths": [{
                "path": "/srv",
                "mount_path": "/srv",
                "writable": True,
                "disk_total_gib": 100,
                "disk_free_gib": 20,
            }],
            "route_evidence": {
                "provider": "racknerd",
                "kind": "workload",
                "status": "verified",
                "verified": True,
                "target_host_id": "westd",
            },
        }
        evidence = derive_remote_resource_evidence(
            host,
            workspace_path="/srv/project/job",
            write_scope="out/job",
        )
        self.assertIsNotNone(evidence)
        assert evidence is not None
        self.assertEqual("direct", evidence["route"]["status"])
        self.assertEqual("/srv/project/job/out/job", evidence["write_scope_path"])
        self.assertEqual(6.0, evidence["capacity"]["cpu_cores"])
        self.assertEqual(12.0, evidence["capacity"]["ram_gib"])
        self.assertNotIn("provider", repr(evidence))

        host.pop("route_evidence")
        self.assertIsNone(
            derive_remote_resource_evidence(
                host,
                workspace_path="/srv/project/job",
                write_scope="out/job",
            )
        )
        host["route_evidence"] = {
            "kind": "workload",
            "status": "direct",
            "verified": True,
            "target_host_id": "westd",
        }
        host["storage_paths"][0].pop("mount_path")
        self.assertIsNone(
            derive_remote_resource_evidence(
                host,
                workspace_path="/srv/project/job",
                write_scope="out/job",
            )
        )

    def test_derive_prefers_the_most_specific_workspace_mount(self):
        host = {
            "host_id": "westd",
            "transport": "ssh",
            "reachable": True,
            "project_path": "/srv/project",
            "last_probed_at_utc": NOW,
            "cgroup_memory_evidence_status": "complete",
            "cgroup_memory_max_bytes": 16 * GIB,
            "cgroup_memory_current_bytes": 4 * GIB,
            "cgroup_memory_available_bytes": 12 * GIB,
            "psi_some_avg10": 1.5,
            "estimated_idle_cpu_cores": 6,
            "gpu_count": 0,
            "storage_paths": [
                {
                    "mount_path": "/",
                    "writable": True,
                    "disk_total_gib": 1000,
                    "disk_free_gib": 900,
                },
                {
                    "mount_path": "/srv/project",
                    "writable": True,
                    "disk_total_gib": 100,
                    "disk_free_gib": 2,
                },
            ],
            "route_evidence": {
                "kind": "workload",
                "status": "direct",
                "verified": True,
                "target_host_id": "westd",
            },
        }

        evidence = derive_remote_resource_evidence(
            host,
            workspace_path="/srv/project/job",
            write_scope="out/job",
        )
        self.assertIsNotNone(evidence)
        assert evidence is not None
        self.assertEqual("/srv/project", evidence["storage"]["mount_path"])
        self.assertEqual(2.0, evidence["capacity"]["new_disk_gib"])

    def test_valid_evidence_binds_host_paths_route_and_capacity(self):
        packet = _packet()
        report = validate_remote_resource_evidence(
            _evidence(), packet=packet, request=packet["resource_request"], now_utc=NOW
        )
        self.assertTrue(report["valid"], report)
        self.assertEqual("admit", report["decision"])
        self.assertEqual("westd", report["summary"]["host_id"])
        self.assertEqual(8.0, report["capacity"]["host"]["cpu_cores"])
        self.assertNotIn("secret_token", repr(report))

    def test_missing_evidence_fails_closed(self):
        report = validate_remote_resource_evidence(
            None, packet=_packet(), request=_packet()["resource_request"], now_utc=NOW
        )
        self.assertFalse(report["valid"])
        self.assertEqual("block", report["decision"])
        self.assertEqual(["remote_resource_evidence_missing"], report["reasons"])

    def test_stale_or_future_observation_is_rejected(self):
        packet = _packet()
        stale = _evidence()
        stale["observed_at_utc"] = "2026-08-13T23:00:00+00:00"
        stale["ttl_seconds"] = 60
        report = validate_remote_resource_evidence(
            stale, packet=packet, request=packet["resource_request"], now_utc=NOW
        )
        self.assertIn("remote_resource_evidence_stale", report["reasons"])

        future = _evidence()
        future["observed_at_utc"] = "2026-08-14T01:05:00+00:00"
        report = validate_remote_resource_evidence(
            future, packet=packet, request=packet["resource_request"], now_utc=NOW
        )
        self.assertIn("remote_resource_evidence_future", report["reasons"])

    def test_mismatched_route_scope_and_capacity_are_rejected(self):
        packet = _packet()
        evidence = _evidence()
        evidence["route"] = {**evidence["route"], "target_host_id": "bjb2"}
        evidence["write_scope_path"] = "/srv/project/job-remote-evidence/other"
        evidence["capacity"] = {**evidence["capacity"], "ram_gib": 1}
        report = validate_remote_resource_evidence(
            evidence, packet=packet, request=packet["resource_request"], now_utc=NOW
        )
        self.assertFalse(report["valid"])
        self.assertIn("remote_route_target_mismatch", report["reasons"])
        self.assertIn("remote_write_scope_mismatch", report["reasons"])
        self.assertIn("remote_request_ram_gib_exceeds_evidence", report["reasons"])

    def test_malformed_request_capacity_fails_closed_before_sqlite_normalization(self):
        packet = _packet()
        request = {**packet["resource_request"], "ram_gib": "not-a-number"}
        report = validate_remote_resource_evidence(
            _evidence(), packet=packet, request=request, now_utc=NOW
        )
        self.assertFalse(report["valid"])
        self.assertIn("remote_request_ram_gib_invalid", report["reasons"])

    def test_root_mount_is_allowed_when_workspace_is_concrete(self):
        packet = _packet()
        evidence = _evidence()
        evidence["storage"] = {**evidence["storage"], "mount_path": "/"}
        report = validate_remote_resource_evidence(
            evidence, packet=packet, request=packet["resource_request"], now_utc=NOW
        )
        self.assertTrue(report["valid"], report)
        self.assertEqual("/", report["summary"]["storage"]["mount_path"])

    def test_missing_psi_mount_and_inconsistent_cgroup_block(self):
        packet = _packet()
        evidence = _evidence()
        evidence.pop("psi")
        evidence["storage"] = {**evidence["storage"], "writable": False}
        evidence["cgroup"] = {**evidence["cgroup"], "available_bytes": 1}
        report = validate_remote_resource_evidence(
            evidence, packet=packet, request=packet["resource_request"], now_utc=NOW
        )
        self.assertFalse(report["valid"])
        self.assertIn("remote_psi_evidence_missing", report["reasons"])
        self.assertIn("remote_writable_path_not_writable", report["reasons"])
        self.assertIn("remote_cgroup_bounds_invalid", report["reasons"])

    def test_controller_blocks_remote_claim_without_evidence_and_records_reason(self):
        packet = _packet()
        packet.pop("remote_resource_evidence", None)
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            db = root / "dispatch.sqlite3"
            controller = SQLiteController(db, workspace=root / "local-staging")
            controller.enqueue(packet)
            result = controller.run(once=True, max_lanes=1)
            self.assertEqual([], result["results"])
            blocked = [
                row for row in result["reservation_diagnostics"]
                if row.get("job_id") == packet["job_id"]
            ]
            self.assertEqual(1, len(blocked), result)
            self.assertEqual("blocked", blocked[0]["status"])
            admission = blocked[0]["admission"]
            self.assertEqual("remote_resource_evidence_missing", admission["reason"])
            self.assertIn("remote_resource_evidence_missing", admission["evidence_block_reasons"])
            with SQLiteStore(db) as store:
                self.assertEqual("queued", store.get_job(packet["job_id"])["status"])
                self.assertEqual([], store.list_reservations(statuses=("active",)))

    def test_controller_admits_only_after_valid_evidence_and_persists_redacted_summary(self):
        packet = _packet()
        evidence = _evidence()
        # The packet schema rejects secret-like fields before ingress.  The
        # producer's bounded contract itself is still tested above with an
        # unknown field to ensure the returned report is redacted.
        evidence.pop("secret_token")
        # The controller validates against its live clock.  Keep this
        # admission fixture fresh while the pure validator tests above retain
        # their fixed timestamp for stale/future assertions.
        evidence["observed_at_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
        packet["remote_resource_evidence"] = evidence
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            db = root / "dispatch.sqlite3"
            controller = SQLiteController(db, workspace=root / "local-staging")
            controller.enqueue(packet)
            with SQLiteStore(db) as store:
                with store.controller_lease("evidence-test", ttl_seconds=90) as lease:
                    diagnostics = controller._ensure_reservations(
                        store,
                        "evidence-test",
                        int(lease["fence_token"]),
                        max_lanes=1,
                    )
                self.assertEqual("reserved", diagnostics[0]["status"])
                reservation = store.list_reservations(statuses=("active",))[0]
                admission = reservation["admission"]
                self.assertTrue(admission["allowed"])
                self.assertEqual("westd", admission["evidence_summary"]["host_id"])
                self.assertNotIn("secret_token", repr(admission))


if __name__ == "__main__":
    unittest.main()
