from __future__ import annotations

import copy
import pathlib
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import desktop_split_placement as split  # noqa: E402
import plan_packet_bridge as bridge  # noqa: E402
from sqlite_controller import SQLiteController  # noqa: E402
from sqlite_store import SQLiteStore  # noqa: E402


NOW = "2026-08-15T08:00:00+00:00"
GIB = 1024**3


def _wrapper(name: str) -> dict[str, str]:
    return {"name": name, "version": "0.1.0", "sha256": "a" * 64, "mode": "dry-run"}


def _inputs() -> tuple[dict, dict, dict, dict, dict]:
    assignment = {
        "job_id": "split-job",
        "attempt_id": "split-attempt",
        "pool_id": "codex.spark",
        "provider": "codex",
        "model": "gpt-5.3-codex-spark",
        "variant": "xhigh",
        "execution_host": "local_mac",
        "execution_transport": "local",
        "workload_host": "remote_gpu",
        "workload_transport": "ssh",
        "local_workspace": "/workspace/project",
        "remote_workspace": "/srv/project/split-job",
        "write_scope": "src",
        "receipt_path": "/srv/project/split-job/.lad/receipts/split-attempt.json",
        "remote_required_artifacts": ["/srv/project/split-job/artifacts/result.json"],
        "remote_result_source_path": "/srv/project/split-job/artifacts/result.json",
        "workload_wrapper": _wrapper("remote-workload-wrapper"),
        "remote_validator": {**_wrapper("remote-validator"), "argv": ["python3", "-m", "unittest"]},
        "resource_request": {"cpu_cores": 1, "ram_gib": 1, "new_disk_gib": 0.1},
    }
    local_host = {
        "host_id": "local_mac",
        "transport": "local",
        "desktop_cli": {
            "name": "codex",
            "path": "/opt/codex/bin/codex",
            "version": "0.146.0",
            "install_state": "installed",
            "auth": {
                "state": "authenticated",
                "scope": "local_desktop",
                "host_id": "local_mac",
                "observed_at_utc": NOW,
                "ttl_seconds": 600,
                "source": "desktop-auth-status",
            },
        },
    }
    workload_host = {
        "host_id": "remote_gpu",
        "transport": "ssh",
        "reachable": True,
        "project_path": "/srv/project",
    }
    route = {
        "provider": "racknerd",
        "kind": "workload",
        "status": "verified",
        "verified": True,
        "target_host_id": "remote_gpu",
        "egress_ip": "192.0.2.44",
        "observed_at_utc": NOW,
        "ttl_seconds": 300,
        "source": "codex-racknerd-route verify",
        "project_path": "/srv/project",
    }
    resource = {
        "schema_version": 1,
        "host_id": "remote_gpu",
        "observed_at_utc": NOW,
        "ttl_seconds": 600,
        "cgroup": {
            "status": "complete",
            "max_bytes": 8 * GIB,
            "current_bytes": 2 * GIB,
            "available_bytes": 6 * GIB,
        },
        "psi": {"some_avg10": 0.0},
        "storage": {
            "mount_path": "/srv",
            "workspace_path": "/srv/project/split-job",
            "writable": True,
            "total_bytes": 100 * GIB,
            "free_bytes": 50 * GIB,
        },
        "route": {
            "kind": "workload",
            "status": "direct",
            "verified": True,
            "target_host_id": "remote_gpu",
        },
        "capacity": {
            "cpu_cores": 4,
            "ram_gib": 6,
            "gpu_count": 0,
            "vram_gib_per_gpu": 0,
            "new_disk_gib": 50,
        },
        "write_scope_path": "/srv/project/split-job/src",
    }
    return assignment, local_host, workload_host, route, resource


class DesktopSplitPlacementTests(unittest.TestCase):
    def test_exact_spark_contract_is_provider_free_and_validated(self):
        values = _inputs()
        report = split.build_desktop_split_contract(*values, now_utc=NOW)
        self.assertTrue(report["valid"], report)
        self.assertEqual("admit", report["decision"])
        self.assertFalse(report["provider_execution"])
        contract = report["contract"]
        self.assertEqual("local", contract["execution_transport"])
        self.assertEqual("ssh", contract["workload_transport"])
        self.assertEqual("local_desktop", contract["desktop_cli"]["auth"]["scope"])
        self.assertEqual("remote_gpu", contract["remote_resource_evidence"]["host_id"])
        self.assertEqual("src", contract["write_scope"])

    def test_redacted_route_evidence_does_not_require_egress_ip(self):
        assignment, local_host, workload_host, route, resource = _inputs()
        route.pop("egress_ip")
        route["status"] = "direct"
        report = split.build_desktop_split_contract(
            assignment, local_host, workload_host, route, resource, now_utc=NOW
        )
        self.assertTrue(report["valid"], report)
        self.assertNotIn("egress_ip", report["contract"]["route_evidence"])
        split.validate_desktop_split_placement_packet(
            split.attach_desktop_split_contract(
                {
                    "schema_version": 1,
                    "packet_id": "packet-route-redacted",
                    "job_id": "split-job",
                    "workspace": "/workspace/project",
                    "write_scope": "src",
                    "required_artifacts": ["artifacts/result.json"],
                    "validation_required": True,
                    "validation_argv": ["python3", "-m", "unittest"],
                    "attempts": [{
                        "attempt_id": "split-attempt",
                        "adapter": "codex",
                        "transport": "local",
                        "model": "gpt-5.3-codex-spark",
                    }],
                },
                report,
            )
        )

    def test_exact_gemini_contract_keeps_null_variant(self):
        assignment, local_host, workload_host, route, resource = _inputs()
        assignment.update(
            pool_id="antigravity.gemini",
            provider="antigravity",
            model="gemini-3.6-flash-high",
            variant=None,
        )
        local_host["desktop_cli"]["name"] = "agy"
        report = split.build_desktop_split_contract(
            assignment, local_host, workload_host, route, resource, now_utc=NOW
        )
        self.assertTrue(report["valid"], report)
        self.assertEqual("gemini-3.6-flash-high", report["contract"]["model"])
        self.assertIsNone(report["contract"]["variant"])

    def test_attach_keeps_desktop_execution_and_remote_artifact_boundary(self):
        values = _inputs()
        report = split.build_desktop_split_contract(*values, now_utc=NOW)
        packet = {
            "schema_version": 1,
            "packet_id": "packet-split",
            "job_id": "split-job",
            "pool_id": "codex.spark",
            "provider": "codex",
            "model": "gpt-5.3-codex-spark",
            "variant": "xhigh",
            "workspace": "/workspace/project",
            "write_scope": "src",
            "required_artifacts": ["/srv/project/split-job/artifacts/result.json"],
            "validation_required": True,
            "validation_argv": ["python3", "-m", "unittest"],
            "attempts": [{
                "attempt_id": "split-attempt",
                "adapter": "codex",
                "transport": "local",
                "model": "gpt-5.3-codex-spark",
            }],
        }
        projected = split.attach_desktop_split_contract(packet, report)
        self.assertEqual("local", projected["execution_transport"])
        self.assertEqual("ssh", projected["workload_transport"])
        self.assertEqual("remote_gpu", projected["workload_host"])
        self.assertEqual("remote-workload-wrapper", projected["workload_wrapper"])
        self.assertEqual("/workspace/project", projected["workspace"])
        self.assertIn("desktop_split_placement", projected)
        self.assertFalse(projected["provider_execution"])
        self.assertEqual("local", projected["attempts"][0]["transport"])
        split.validate_desktop_split_placement_packet(projected)

    def test_desktop_prompt_file_is_bound_to_local_workspace(self):
        values = _inputs()
        report = split.build_desktop_split_contract(*values, now_utc=NOW)
        packet = {
            "schema_version": 1,
            "packet_id": "packet-split-prompt-boundary",
            "job_id": "split-job",
            "workspace": "/workspace/project",
            "write_scope": "src",
            "required_artifacts": ["/srv/project/split-job/artifacts/result.json"],
            "validation_required": True,
            "validation_argv": ["python3", "-m", "unittest"],
            "attempts": [{
                "attempt_id": "split-attempt",
                "adapter": "codex",
                "transport": "local",
                "model": "gpt-5.3-codex-spark",
                "prompt_file": "/other/local-workspace/prompt.md",
            }],
        }
        with self.assertRaisesRegex(split.DesktopSplitPlacementError, "prompt_file.*escapes"):
            split.attach_desktop_split_contract(packet, report)

    def test_self_consistent_contract_cannot_bypass_path_or_sqlite_ingress(self):
        values = _inputs()
        report = split.build_desktop_split_contract(*values, now_utc=NOW)
        packet = {
            "schema_version": 1,
            "packet_id": "packet-split-ingress",
            "job_id": "split-job",
            "pool_id": "codex.spark",
            "provider": "codex",
            "model": "gpt-5.3-codex-spark",
            "variant": "xhigh",
            "workspace": "/workspace/project",
            "write_scope": "src",
            "required_artifacts": ["/srv/project/split-job/artifacts/result.json"],
            "validation_required": True,
            "validation_argv": ["python3", "-m", "unittest"],
            "attempts": [{
                "attempt_id": "split-attempt",
                "adapter": "codex",
                "transport": "local",
                "model": "gpt-5.3-codex-spark",
            }],
        }
        projected = split.attach_desktop_split_contract(packet, report)
        with tempfile.TemporaryDirectory() as tmp:
            row = SQLiteController(
                pathlib.Path(tmp) / "dispatch.sqlite3", enforce_reservations=False
            ).enqueue(projected)
            self.assertEqual("queued", row["status"])

        # Recompute the self-digest to model a forged producer packet.  The
        # ingress must still reject the unsafe path and not trust the digest
        # as proof that the contract went through the builder.
        forged = copy.deepcopy(projected)
        contract = forged["desktop_split_placement"]
        contract["write_scope"] = "../../etc"
        contract["write_scope_path"] = "/srv/project/split-job/../../etc"
        contract["contract_digest"] = split._digest(
            {key: value for key, value in contract.items() if key != "contract_digest"}
        )
        forged["write_scope"] = "../../etc"
        forged["attempts"][0]["write_scope"] = "../../etc"
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "unsafe path component"):
                SQLiteController(
                    pathlib.Path(tmp) / "dispatch.sqlite3", enforce_reservations=False
                ).enqueue(forged)

    def test_location_or_model_is_not_silently_fallbacked(self):
        assignment, local_host, workload_host, route, resource = _inputs()
        assignment["model"] = "gemini-3.1-pro-high"
        report = split.build_desktop_split_contract(
            assignment, local_host, workload_host, route, resource, now_utc=NOW
        )
        self.assertFalse(report["valid"])
        self.assertIn("exact approved model", report["reasons"][0])

        assignment, local_host, workload_host, route, resource = _inputs()
        assignment["workload_wrapper"]["mode"] = "execute"
        report = split.build_desktop_split_contract(
            assignment, local_host, workload_host, route, resource, now_utc=NOW
        )
        self.assertFalse(report["valid"])
        self.assertIn("mode must be dry-run", report["reasons"][0])

    def test_missing_or_stale_remote_evidence_blocks(self):
        assignment, local_host, workload_host, route, resource = _inputs()
        resource["storage"]["writable"] = False
        report = split.build_desktop_split_contract(
            assignment, local_host, workload_host, route, resource, now_utc=NOW
        )
        self.assertFalse(report["valid"])
        self.assertIn("remote_writable_path_not_writable", report["reasons"][0])

        assignment, local_host, workload_host, route, resource = _inputs()
        resource["observed_at_utc"] = "2026-08-14T00:00:00+00:00"
        report = split.build_desktop_split_contract(
            assignment, local_host, workload_host, route, resource, now_utc=NOW
        )
        self.assertFalse(report["valid"])
        self.assertIn("stale", report["reasons"][0])

    def test_path_and_inline_prompt_fail_closed(self):
        assignment, local_host, workload_host, route, resource = _inputs()
        assignment["remote_workspace"] = "/srv/other/job"
        report = split.build_desktop_split_contract(
            assignment, local_host, workload_host, route, resource, now_utc=NOW
        )
        self.assertFalse(report["valid"])
        self.assertIn("escapes remote project_path", report["reasons"][0])

        assignment, local_host, workload_host, route, resource = _inputs()
        assignment["prompt"] = "must not be persisted"
        report = split.build_desktop_split_contract(
            assignment, local_host, workload_host, route, resource, now_utc=NOW
        )
        self.assertFalse(report["valid"])
        self.assertIn("inline prompt", report["reasons"][0])

    def test_contract_digest_tampering_is_rejected(self):
        values = _inputs()
        report = split.build_desktop_split_contract(*values, now_utc=NOW)
        packet = {"attempts": [{"attempt_id": "split-attempt"}]}
        tampered = copy.deepcopy(report["contract"])
        tampered["model"] = "other-model"
        with self.assertRaisesRegex(split.DesktopSplitPlacementError, "digest mismatch"):
            split.attach_desktop_split_contract(packet, tampered)

    def test_bridge_accepts_only_explicit_split_contract_and_preserves_boundary(self):
        with __import__("tempfile").TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            assignment, local_host, workload_host, route, resource = _inputs()
            local_workspace = root / "workspace"
            local_workspace.mkdir()
            prompt = local_workspace / "prompt.md"
            prompt.write_text("bounded prompt fixture", encoding="utf-8")
            assignment["local_workspace"] = str(local_workspace)
            report = split.build_desktop_split_contract(
                assignment, local_host, workload_host, route, resource, now_utc=NOW
            )
            state = {
                "schema_version": 1,
                "workspace": str(local_workspace),
                "hosts": {
                    "local_mac": {"host_id": "local_mac", "transport": "local"},
                    "remote_gpu": {
                        "host_id": "remote_gpu", "transport": "ssh",
                        "reachable": True, "project_path": "/srv/project",
                    },
                },
            }
            job = {
                "job_id": "split-job",
                "workspace": str(local_workspace),
                "prompt_file": str(prompt),
                "write_scope": "src",
                "workload_wrapper": "remote-workload-wrapper",
                "desktop_split_contract": report,
            }
            registry = {
                "codex.spark": {
                    "provider": "codex", "adapter": "command", "transport": "local",
                    "supports_split_placement": True,
                    "argv": ["python3", "-c", "print('{model}')"],
                }
            }
            packet = bridge.assignment_to_packet(
                assignment, job, state, registry, plan_digest="a" * 64,
            )
            self.assertEqual("local", packet["execution_transport"])
            self.assertEqual("ssh", packet["workload_transport"])
            self.assertEqual("local_mac", packet["execution_host"])
            self.assertEqual("remote_gpu", packet["workload_host"])
            self.assertIn("desktop_split_placement", packet)
            self.assertEqual("split-attempt", packet["attempts"][0]["attempt_id"])
            self.assertFalse(packet["provider_execution"])
            result = bridge.enqueue_packets(
                {"mode": "enqueue-ready", "ok": True, "packets": [packet]},
                root / "dispatch.sqlite3",
            )
            self.assertTrue(result["ok"], result)
            self.assertTrue(result["jobs"][0]["transport_outbox"])
            with SQLiteStore(root / "dispatch.sqlite3") as store:
                outbox = store.list_transport_outbox(statuses=("pending",))
                self.assertEqual(1, len(outbox))
                self.assertEqual("remote_gpu", outbox[0]["envelope"]["target_id"])


if __name__ == "__main__":
    unittest.main()
