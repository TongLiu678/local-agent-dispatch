import json
import pathlib
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import hardware_fit_planner as fit  # noqa: E402


def host(host_id, transport, *, cpu=8, ram=32, disk=100, gpu=None, reachable=True):
    gpu = gpu or []
    return {
        "host_id": host_id,
        "transport": transport,
        "reachable": reachable,
        "project_path_exists": True,
        "project_path_writable": True,
        "logical_cpu_cores": cpu,
        "estimated_idle_cpu_cores": cpu,
        "memory_total_gib": ram,
        "memory_available_gib": ram,
        "disk_total_gib": disk + 20,
        "disk_free_gib": disk,
        "gpu_count": len(gpu),
        "gpus": gpu,
        "commands": {"python3": "/usr/bin/python3"},
        "python": {"version": "3.11.9"},
        "tags": ["remote"] if transport == "ssh" else ["local"],
    }


class HardwareFitPlannerTests(unittest.TestCase):
    def test_zero_observed_idle_cpu_is_not_treated_as_unknown(self):
        job = {
            "job_id": "busy-host",
            "task_type": "code",
            "resources": {"cpu_cores": 1, "ram_gib": 1},
        }
        busy = host("busy", "ssh", cpu=8, ram=32, disk=100)
        busy["estimated_idle_cpu_cores"] = 0
        estimate = fit.resource_estimate(job)
        eligible, _score, _reasons, _route, rejected = fit.host_fit(
            job, estimate, "busy", busy
        )
        self.assertFalse(eligible)
        self.assertIn("insufficient_idle_cpu", rejected)

    def test_host_summary_preserves_non_root_storage_evidence(self):
        remote = host("remote", "ssh", cpu=16, ram=64, disk=100)
        remote.update(
            project_path="/workspace/project",
            best_storage_path="/data/project",
            best_writable_storage_path="/workspace/project",
            storage_paths=[
                {
                    "path": "/workspace/project",
                    "exists": True,
                    "writable": True,
                    "disk_total_gib": 550.0,
                    "disk_free_gib": 100.0,
                },
                {
                    "path": "/data/project",
                    "exists": True,
                    "writable": False,
                    "disk_total_gib": 10240.0,
                    "disk_free_gib": 5000.0,
                },
            ],
            storage_discovery={"common_mounts_scanned": True},
        )
        report = fit.build_report(
            {"local_system": {}, "compute_hosts": {"remote": remote}},
            [{"job_id": "storage-audit"}],
            pathlib.Path("/tmp/project"),
        )
        summary = report["hosts"]["remote"]
        self.assertEqual("/workspace/project", summary["best_writable_storage_path"])
        self.assertEqual("/data/project", summary["best_storage_path"])
        self.assertTrue(summary["storage_discovery"]["common_mounts_scanned"])
        self.assertEqual(2, len(summary["storage_paths"]))

    def test_server_first_job_reports_required_config_and_remote_fit(self):
        preflight = {
            "schema_version": 1,
            "scanned_at_utc": "2026-08-11T00:00:00Z",
            "local_system": {
                "ok": True,
                "os": {"name": "Darwin"},
                "arch": "arm64",
                "cpu": {"logical_cores": 10, "physical_cores": 10},
                "ram": {"total_gib": 32, "available_gib": 9},
                "disks": {"workspace": {"exists": True, "writable": True, "total_bytes": 500 * 1024**3, "free_bytes": 5 * 1024**3}},
                "accelerators": [{"type": "gpu", "name": "Apple M4", "core_count": 10, "unified_memory": True}],
                "python": {"version": "3.14.6"},
            },
            "compute_hosts": {
                "local_system": host("local_system", "local", cpu=10, ram=9, disk=5),
                "remote_gpu": host(
                    "remote_gpu",
                    "ssh",
                    cpu=32,
                    ram=96,
                    disk=200,
                    gpu=[{"name": "RTX", "vram_total_gib": 32, "vram_free_gib": 31, "utilization_percent": 2}],
                ),
            },
        }
        jobs = [{
            "job_id": "train-1",
            "task_type": "code",
            "difficulty": 3,
            "resources": {
                "download_gib": 2,
                "environment_gib": 2,
                "temporary_gib": 4,
                "cache_gib": 2,
                "output_gib": 1,
                "ram_gib": 16,
                "cpu_cores": 8,
                "gpu_count": 1,
                "vram_gib": 24,
                "compute_minutes": 30,
                "full_model": True,
            },
            "data_source": "public",
            "data_location": "remote_gpu",
        }]
        report = fit.build_report(preflight, jobs, pathlib.Path("/tmp/project"))
        row = report["jobs"][0]
        self.assertTrue(row["estimate"]["server_first"])
        self.assertEqual(8, row["required_server_config"]["min_cpu_cores"])
        self.assertEqual("run_server", row["decision"]["action"])
        self.assertEqual("remote_gpu", row["decision"]["selected_host"])
        self.assertTrue(row["decision"]["server_eligible"])

    def test_local_only_job_does_not_get_server_recommendation(self):
        preflight = {
            "local_system": {"ok": True, "os": {"name": "Darwin"}, "arch": "arm64", "cpu": {"logical_cores": 4, "load_1m": 0.0, "load_source": "fixture"}, "ram": {"total_gib": 8, "available_gib": 4}, "disks": {"workspace": {"exists": True, "writable": True, "total_bytes": 100 * 1024**3, "free_bytes": 50 * 1024**3}}, "accelerators": []},
            "compute_hosts": {"local_system": host("local_system", "local", cpu=4, ram=4, disk=50), "remote": host("remote", "ssh", cpu=32)},
        }
        report = fit.build_report(preflight, [{"job_id": "gui", "requires_local_gui": True}], pathlib.Path("/tmp/project"))
        self.assertEqual("run_local", report["jobs"][0]["decision"]["action"])
        self.assertFalse(report["jobs"][0]["decision"]["server_eligible"])

    def test_missing_runtime_and_footprint_are_a_pilot_gate(self):
        preflight = {
            "local_system": {},
            "compute_hosts": {
                "local": host("local", "local"),
                "remote": host("remote", "ssh"),
            },
        }
        report = fit.build_report(
            preflight,
            [{"job_id": "unknown-runtime", "task_type": "code", "resources": {"cpu_cores": 1, "ram_gib": 1}}],
            pathlib.Path("/tmp/project"),
        )
        row = report["jobs"][0]
        self.assertEqual("pilot_first", row["decision"]["action"])
        self.assertTrue(row["estimate"]["pilot_required"])

    def test_cli_writes_read_only_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            preflight = root / "preflight.json"
            jobs = root / "jobs.json"
            output = root / "fit.json"
            preflight.write_text(json.dumps({"local_system": {}, "compute_hosts": {}}), encoding="utf-8")
            jobs.write_text(json.dumps({"jobs": [{"job_id": "small"}]}), encoding="utf-8")
            self.assertEqual(0, fit.main(["--preflight", str(preflight), "--jobs", str(jobs), "--workspace", str(root), "--output", str(output)]))
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertTrue(payload["read_only"])
            self.assertEqual("small", payload["jobs"][0]["job_id"])


if __name__ == "__main__":
    unittest.main()
