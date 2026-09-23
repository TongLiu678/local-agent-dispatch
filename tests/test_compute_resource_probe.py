from __future__ import annotations

import pathlib
import json
import sys
import unittest
from unittest.mock import patch


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import compute_resource_probe as probe  # noqa: E402
import server_local_model_scan as model_scan  # noqa: E402


class ComputeResourceProbeTests(unittest.TestCase):
    def test_probe_inventory_accepts_compute_hosts_mapping(self):
        seen = []

        def fake_probe_host(host, timeout, *, verify_racknerd_route=False):
            seen.append((host, timeout, verify_racknerd_route))
            return host["host_id"], {
                "host_id": host["host_id"],
                "transport": host.get("transport"),
                "reachable": True,
            }

        payload = {
            "compute_hosts": {
                "remote-a": {
                    "transport": "ssh",
                    "hostname": "example.test",
                    "user": "root",
                    "port": 22,
                    "project_path": "/srv/project",
                }
            }
        }
        with patch.object(probe, "probe_host", side_effect=fake_probe_host):
            report = probe.probe_inventory(payload, timeout=7.0, workers=1)

        self.assertEqual(["remote-a"], list(report["compute_hosts"]))
        self.assertEqual("remote-a", seen[0][0]["host_id"])
        self.assertEqual(7.0, seen[0][1])
        self.assertFalse(seen[0][2])

    def test_probe_inventory_prefers_hosts_list_over_compute_hosts_mapping(self):
        seen = []

        def fake_probe_host(host, timeout, *, verify_racknerd_route=False):
            seen.append(host["host_id"])
            return host["host_id"], {"host_id": host["host_id"], "reachable": True}

        payload = {
            "hosts": [{"host_id": "authoritative", "transport": "local"}],
            "compute_hosts": {"stale": {"transport": "local"}},
        }
        with patch.object(probe, "probe_host", side_effect=fake_probe_host):
            report = probe.probe_inventory(payload, timeout=3.0, workers=1)

        self.assertEqual(["authoritative"], seen)
        self.assertEqual(["authoritative"], list(report["compute_hosts"]))

    def test_model_scan_inventory_accepts_compute_hosts_mapping(self):
        inventory = {
            "compute_hosts": {
                "remote-a": {
                    "transport": "ssh",
                    "hostname": "example.test",
                    "user": "root",
                    "port": 22,
                    "project_path": "/srv/project",
                }
            }
        }
        with patch.object(model_scan, "load_json", return_value=inventory), patch.object(
            model_scan, "scan_host", return_value=("remote-a", {"host_id": "remote-a", "apis": []})
        ):
            # Call the normalization path without launching a subprocess.
            args = model_scan.parse_args(["--inventory", "inventory.json"])
            loaded = model_scan.load_json(args.inventory)
            hosts = loaded.get("hosts")
            if hosts is None:
                hosts = loaded.get("compute_hosts")
            normalized = [
                {**dict(value), "host_id": str(value.get("host_id") or key)}
                for key, value in hosts.items()
            ]
        self.assertEqual(["remote-a"], [row["host_id"] for row in normalized])

    def test_default_timeout_allows_slow_read_only_mount_inventory(self):
        args = probe.parse_args(["--inventory", "-"])
        self.assertEqual(20.0, args.timeout)

    def test_parse_output_keeps_project_compatibility_and_all_storage_mounts(self):
        payload = probe.parse_output(
            "\n".join(
                [
                    "META|container|Linux|x86_64",
                    "DISK|/workspace|1|590558003200|181999000000|1",
                    "DISK|/data|1|15360000000000|6000000000000|0",
                    "GPU|0,RTX 5090,32768,30000,10,595.0",
                    "CMD|codex|/usr/local/bin/codex",
                    "CMD|agy|/usr/local/bin/agy",
                    "CMD|opencode|/opt/opencode/bin/opencode",
                ]
            )
        )
        self.assertEqual(2, len(payload["disks"]))
        self.assertEqual("/workspace", payload["best_writable_storage_path"])
        self.assertEqual("/data", payload["best_storage_path"])
        self.assertGreater(payload["disk_free_gib"], 169.0)
        self.assertTrue(payload["project_path_writable"])
        self.assertEqual("/usr/local/bin/codex", payload["commands"]["codex"])
        self.assertEqual("/usr/local/bin/agy", payload["commands"]["agy"])
        self.assertEqual("/opt/opencode/bin/opencode", payload["commands"]["opencode"])

    def test_parse_output_projects_legacy_torque_command_discovery(self):
        payload = probe.parse_output(
            "\n".join(
                [
                    "META|node1|Linux|x86_64",
                    "CMD|qstat|/opt/torque-2.5.2/bin/qstat",
                    "CMD|qsub|/opt/torque-2.5.2/bin/qsub",
                    "CMD|pbsnodes|/opt/torque-2.5.2/bin/pbsnodes",
                ]
            )
        )
        self.assertEqual(
            {
                "status": "discovered",
                "backend": "torque-pbs",
                "present_commands": ["pbsnodes", "qstat", "qsub"],
                "required_commands": ["pbsnodes", "qstat", "qsub"],
                "source": "compute_resource_probe.command_discovery",
            },
            payload["scheduler_command_evidence"],
        )

    def test_scheduler_command_discovery_is_partial_and_not_verified(self):
        payload = probe.parse_output("CMD|qstat|/opt/torque-2.5.2/bin/qstat\n")
        self.assertEqual("partial", payload["scheduler_command_evidence"]["status"])
        self.assertEqual(["qstat"], payload["scheduler_command_evidence"]["present_commands"])
        self.assertNotEqual("verified", payload["scheduler_command_evidence"]["status"])

    def test_remote_probe_discovers_legacy_torque_paths_without_path_assumption(self):
        self.assertIn("/opt/torque-2.5.2/bin/qstat", probe.REMOTE_PROBE)
        self.assertIn("/opt/torque-2.5.2/bin/qsub", probe.REMOTE_PROBE)
        self.assertIn("/opt/torque-2.5.2/bin/pbsnodes", probe.REMOTE_PROBE)

    def test_ssh_argv_enables_legacy_rsa_only_when_explicitly_allowed(self):
        base = {
            "hostname": "cluster.example",
            "user": "runner",
            "port": 2222,
        }
        ordinary = probe.ssh_argv(base, timeout=5)
        self.assertNotIn("HostKeyAlgorithms=+ssh-rsa", ordinary)
        legacy = probe.ssh_argv({**base, "ssh_legacy_rsa": True}, timeout=5)
        self.assertIn("HostKeyAlgorithms=+ssh-rsa", legacy)
        self.assertIn("PubkeyAcceptedAlgorithms=+ssh-rsa", legacy)

    def test_parse_output_keeps_bounded_remote_clock_sample(self):
        payload = probe.parse_output(
            "META|compute-01|Linux|x86_64\nKERNEL|5.15.0-25-generic\nCLOCK|1788210000\n"
        )
        self.assertEqual(1788210000, payload["clock_epoch_seconds"])
        self.assertEqual("date_epoch", payload["clock_source"])
        self.assertEqual("5.15.0-25-generic", payload["kernel_release"])
        self.assertNotIn("clock_skew", json.dumps(payload))

    def test_parse_output_keeps_bounded_ntp_sync_status(self):
        synchronized = probe.parse_output("META|node1|Linux|x86_64\nNTPSYNC|synchronised\n")
        self.assertEqual("synchronized", synchronized["time_sync_evidence"]["status"])
        unsynchronized = probe.parse_output("META|compute-01|Linux|x86_64\nNTPSYNC|unsynchronised\n")
        self.assertEqual("unsynchronized", unsynchronized["time_sync_evidence"]["status"])
        self.assertEqual("ntpstat", unsynchronized["time_sync_evidence"]["source"])

    def test_remote_probe_collects_only_ntp_sync_summary(self):
        self.assertIn("ntpstat", probe.REMOTE_PROBE)
        self.assertIn("NTPSYNC|", probe.REMOTE_PROBE)

    def test_parse_output_rejects_unsafe_kernel_release(self):
        payload = probe.parse_output("META|compute-01|Linux|x86_64\nKERNEL|5.15.0/evil\n")
        self.assertNotIn("kernel_release", payload)

    def test_parse_output_keeps_declared_runtime_interpreter_evidence(self):
        payload = probe.parse_output(
            "META|compute-01|Linux|x86_64\n"
            "RUNTIME_PYTHON|verified|/data/EXAMPLE_002/lt_work/envs/py312/bin/python|3.12.4\n"
        )
        self.assertEqual(
            {
                "status": "verified",
                "path": "/data/EXAMPLE_002/lt_work/envs/py312/bin/python",
                "version": "3.12.4",
                "source": "declared_inventory",
            },
            payload["runtime_python"],
        )

    @patch.object(probe.subprocess, "run")
    def test_probe_host_passes_nested_pbs_interpreter_to_remote_probe(self, runner):
        runner.return_value = probe.subprocess.CompletedProcess(
            ["ssh"],
            0,
            stdout=(
                "META|compute-01|Linux|x86_64\n"
                "RUNTIME_PYTHON|verified|/data/EXAMPLE_002/lt_work/envs/py312/bin/python|3.12.4\n"
                "DISK|/srv/project|1|1000000000|900000000|1\n"
            ),
            stderr="",
        )
        _, result = probe.probe_host(
            {
                "host_id": "compute-01",
                "transport": "ssh",
                "hostname": "example.invalid",
                "user": "REMOTE_USER",
                "port": 22,
                "project_path": "/srv/project",
                "discover_storage": False,
                "pbs": {"python": "/data/EXAMPLE_002/lt_work/envs/py312/bin/python"},
            },
            timeout=5,
        )
        self.assertEqual("verified", result["runtime_python"]["status"])
        self.assertIn(
            "__LAD_RUNTIME_PYTHON__=/data/EXAMPLE_002/lt_work/envs/py312/bin/python",
            " ".join(str(item) for item in runner.call_args.args[0]),
        )

    def test_parse_output_preserves_psi_and_real_mount_point(self):
        payload = probe.parse_output(
            "\n".join(
                [
                    "META|container|Linux|x86_64",
                    "MEM|1000000000|500000000|procfs_legacy_estimate",
                    "PSI|2.5",
                    "DISK|/workspace/project|1|590558003200|181999000000|1|/workspace",
                ]
            )
        )
        self.assertIn("procfs_legacy_estimate", probe.REMOTE_PROBE)
        self.assertEqual("procfs_legacy_estimate", payload["memory_source"])
        self.assertEqual(2.5, payload["psi_some_avg10"])
        self.assertEqual("proc_pressure_memory", payload["psi_source"])
        self.assertEqual("/workspace", payload["disks"][0]["mount_path"])

    def test_parse_output_classifies_external_network_without_retaining_addresses(self):
        payload = probe.parse_output(
            "\n".join(
                [
                    "META|node17|Linux|x86_64",
                    "NET|github.com|1|1",
                    "NET|opencode.ai|1|1",
                ]
            )
        )
        evidence = payload["external_network_evidence"]
        self.assertEqual("verified", evidence["status"])
        self.assertTrue(evidence["targets"]["github.com"]["https_reachable"])
        self.assertNotIn("20.205.243.166", json.dumps(evidence))

        blocked = probe.parse_output(
            "NET|github.com|0|0\nNET|opencode.ai|0|0\n"
        )["external_network_evidence"]
        self.assertEqual("blocked", blocked["status"])

    def test_parse_output_keeps_only_bounded_racknerd_route_result(self):
        payload = probe.parse_output(
            "\n".join(
                [
                    "META|remote-a|Linux|x86_64",
                    "ROUTE|racknerd|workload|direct|1",
                ]
            )
        )
        self.assertEqual(
            {
                "provider": "racknerd",
                "kind": "workload",
                "status": "direct",
                "verified": True,
                "source": "codex-racknerd-route verify",
            },
            payload["route_evidence"],
        )
        self.assertNotIn("egress", json.dumps(payload))

    def test_parse_output_keeps_psi_unknown_when_missing_or_invalid(self):
        missing = probe.parse_output("META|container|Linux|x86_64\n")
        self.assertNotIn("psi_some_avg10", missing)
        invalid = probe.parse_output("META|container|Linux|x86_64\nPSI|nan\n")
        self.assertNotIn("psi_some_avg10", invalid)

    def test_parse_output_accepts_vendor_mounts_as_data_capacity(self):
        payload = probe.parse_output(
            "\n".join(
                [
                    "META|container|Linux|x86_64",
                    "DISK|/root/EXAMPLE_001|1|590558003200|20000000000|1",
                    "DISK|/autodl-pub|1|6000000000000|5700000000000|0",
                ]
            )
        )
        self.assertEqual("/autodl-pub", payload["best_storage_path"])
        self.assertEqual("/root/EXAMPLE_001", payload["best_writable_storage_path"])
        self.assertEqual(2, len(payload["disks"]))

    def test_parse_output_without_disk_is_explicitly_unknown_not_root_capacity(self):
        payload = probe.parse_output("META|container|Linux|x86_64\n")
        self.assertFalse(payload["project_path_exists"])
        self.assertEqual(0.0, payload["disk_free_gib"])
        self.assertIsNone(payload["best_writable_storage_path"])
        self.assertTrue(payload["cgroup_required"])
        self.assertEqual("unknown", payload["cgroup_memory_evidence_status"])

    def test_capacity_receipt_is_derived_from_probe_and_contains_no_raw_commands(self):
        payload = probe.parse_output(
            "\n".join([
                "META|container|Linux|x86_64",
                "MEM|10000000000|8000000000",
                "DISK|/workspace|1|10000000000|9000000000|1|/workspace",
                "GPU|0,RTX 5090,32768,30000,0,595.0",
                "CMD|python3|/usr/bin/python3",
            ])
        )
        receipt = probe.capacity_receipt_from_probe(
            payload,
            host_identity_digest="sha256:" + "a" * 64,
            project_path_digest="sha256:" + "b" * 64,
            output_path_digest="sha256:" + "c" * 64,
            runtime_digest="sha256:" + "d" * 64,
            resource_request_digest="sha256:" + "e" * 64,
            required_disk_bytes=1,
            required_memory_bytes=1,
            observed_at="2026-08-15T00:00:00Z",
        )
        self.assertEqual("server_capacity_receipt", receipt["kind"])
        self.assertGreaterEqual(receipt["available_disk_bytes"], receipt["required_disk_bytes"])
        self.assertNotIn("/usr/bin/python3", json.dumps(receipt))
        self.assertNotIn("commands", json.dumps(receipt))

    def test_cgroup_v2_memory_overrides_proc_capacity_and_preserves_discrepancy(self):
        # The empty-value arm must not be written as ``''*``: in POSIX case
        # patterns that matches every string and silently drops valid cgroup
        # evidence from the real SSH probe.
        self.assertIn("''|*[!0-9:]*", probe.REMOTE_PROBE)
        payload = probe.parse_output(
            "\n".join(
                [
                    "META|container|Linux|x86_64",
                    "MEM|2061584302080|2147483648",
                    "CGMEM|96636764160|65600000000|5354168|0|0",
                ]
            )
        )
        self.assertEqual("cgroup_v2_current_max", payload["memory_source"])
        self.assertTrue(payload["cgroup_required"])
        self.assertEqual("complete", payload["cgroup_memory_evidence_status"])
        self.assertEqual(96636764160, payload["cgroup_memory_max_bytes"])
        self.assertEqual(65600000000, payload["cgroup_memory_current_bytes"])
        self.assertAlmostEqual(89.999, payload["memory_total_gib"], places=2)
        self.assertAlmostEqual(28.93, payload["memory_available_gib"], places=1)
        self.assertEqual(5354168, payload["cgroup_memory_events_high"])
        self.assertTrue(payload["memory_discrepancy"])

    def test_cgroup_memory_stat_separates_anon_file_cache_and_slab(self):
        self.assertIn("memory.stat", probe.REMOTE_PROBE)
        payload = probe.parse_output(
            "\n".join(
                [
                    "META|container|Linux|x86_64",
                    "CGMEM|1000|900|0|0|0",
                    "CGMEMSTAT|400|300|200|100|50",
                ]
            )
        )
        self.assertEqual(
            {"anon": 400, "file": 300, "active_file": 200, "inactive_file": 100, "slab": 50},
            payload["cgroup_memory_stat"],
        )
        self.assertEqual(400, payload["cgroup_memory_anon_bytes"])
        self.assertEqual(300, payload["cgroup_memory_file_bytes"])
        self.assertEqual("complete", payload["cgroup_memory_stat_evidence_status"])
        self.assertEqual(750, payload["cgroup_memory_stat_accounted_bytes"])

    def test_remote_process_probe_keeps_only_safe_pool_identity(self):
        payload = probe.parse_output(
            "\n".join(
                [
                    "META|bjb2|Linux|x86_64",
                    "PROC|410|1|/usr/local/bin/opencode run --model opencode-go/deepseek-v4-flash --prompt PRIVATE_PROMPT synthetic-token-value",
                    "PROC|411|1|/usr/local/bin/opencode run --model PRIVATE_PROMPT --prompt SECRET_TOKEN",
                    "PROC|412|1|/usr/local/bin/codex exec -m gpt-5.6-luna --prompt DO_NOT_PERSIST",
                    "PROCSCAN|1",
                ]
            )
        )
        consumers = payload["external_consumers"]
        self.assertEqual({"opencode.go": 1, "codex.luna": 1}, consumers["inflight_by_pool"])
        self.assertEqual(["codex.luna", "opencode.go"], sorted(row["pool_id"] for row in consumers["processes"]))
        serialized = json.dumps(payload, ensure_ascii=False)
        self.assertNotIn("PRIVATE_PROMPT", serialized)
        self.assertNotIn("SECRET_TOKEN", serialized)
        self.assertNotIn("synthetic-token-value", serialized)
        self.assertTrue(all(set(row) <= {"pid", "pool_id", "command_name", "arguments_collected", "model"} for row in consumers["processes"]))

    def test_remote_process_scan_without_ps_is_fail_closed(self):
        payload = probe.parse_output("META|bjb2|Linux|x86_64\nPROCSCAN|0\n")
        consumers = payload["external_consumers"]
        self.assertFalse(consumers["scan_ok"])
        self.assertTrue(consumers["unknown"])
        self.assertEqual({}, consumers["inflight_by_pool"])

    @patch.object(probe.subprocess, "run")
    def test_ssh_probe_uses_fake_read_only_stream_and_sanitizes_result(self, runner):
        runner.return_value = probe.subprocess.CompletedProcess(
            ["ssh"],
            0,
            stdout="\n".join(
                [
                    "META|bjb2|Linux|x86_64",
                    "PROC|901|1|opencode run --model opencode-go/deepseek-v4-flash --prompt PRIVATE",
                    "PROCSCAN|1",
                    "DISK|/root/EXAMPLE_001|1|1000000000|900000000|1",
                ]
            ),
            stderr="",
        )
        _, result = probe.probe_host(
            {
                "host_id": "bjb2",
                "transport": "ssh",
                "hostname": "example.invalid",
                "user": "root",
                "port": 54480,
                "project_path": "/root/EXAMPLE_001",
                "discover_storage": False,
            },
            timeout=5,
        )
        self.assertTrue(result["reachable"])
        self.assertEqual({"opencode.go": 1}, result["external_consumers"]["inflight_by_pool"])
        self.assertNotIn("PRIVATE", json.dumps(result))
        kwargs = runner.call_args.kwargs
        self.assertIn("PROCSCAN", kwargs["input"])
        self.assertNotIn("PRIVATE", kwargs["input"])

    @patch.object(probe.time, "time", side_effect=(1000.0, 1002.0))
    @patch.object(probe.subprocess, "run")
    def test_ssh_probe_projects_clock_skew_without_retaining_raw_output(self, runner, _wall_clock):
        runner.return_value = probe.subprocess.CompletedProcess(
            ["ssh"],
            0,
            stdout="META|compute-01|Linux|x86_64\nCLOCK|9000\nDISK|/srv/project|1|1000000000|900000000|1",
            stderr="",
        )
        _, result = probe.probe_host(
            {
                "host_id": "compute-01",
                "transport": "ssh",
                "hostname": "example.invalid",
                "user": "root",
                "port": 22,
                "project_path": "/srv/project",
                "discover_storage": False,
            },
            timeout=5,
        )
        evidence = result["clock_evidence"]
        self.assertEqual("blocked", evidence["status"])
        self.assertGreater(evidence["offset_seconds"], 60)
        self.assertNotIn("CLOCK|9000", json.dumps(result))

    @patch.object(probe.subprocess, "run")
    def test_explicit_route_verify_projects_target_host_without_helper_output(self, runner):
        runner.return_value = probe.subprocess.CompletedProcess(
            ["ssh"],
            0,
            stdout="\n".join(
                [
                    "META|remote-a|Linux|x86_64",
                    "ROUTE|racknerd|workload|direct|1",
                    "DISK|/srv/project|1|1000000000|900000000|1|/srv/project",
                ]
            ),
            stderr="",
        )
        _, result = probe.probe_host(
            {
                "host_id": "remote-a",
                "transport": "ssh",
                "hostname": "example.invalid",
                "user": "root",
                "port": 40622,
                "project_path": "/srv/project",
                "discover_storage": False,
            },
            timeout=5,
            verify_racknerd_route=True,
        )
        self.assertEqual("remote-a", result["route_evidence"]["target_host_id"])
        self.assertTrue(result["route_evidence"]["verified"])
        self.assertEqual(probe.RACKNERD_ROUTE_TTL_SECONDS, result["route_evidence"]["ttl_seconds"])
        self.assertEqual(result["last_probed_at_utc"], result["route_evidence"]["observed_at_utc"])
        self.assertIn("__LAD_VERIFY_RACKNERD_ROUTE__", runner.call_args.kwargs["input"])

    @patch.object(probe.subprocess, "run")
    def test_explicit_external_network_verify_projects_bounded_evidence(self, runner):
        runner.return_value = probe.subprocess.CompletedProcess(
            ["ssh"],
            0,
            stdout="\n".join(
                [
                    "META|remote-a|Linux|x86_64",
                    "NET|github.com|0|0",
                    "NET|opencode.ai|0|0",
                    "DISK|/srv/project|1|1000000000|900000000|1|/srv/project",
                ]
            ),
            stderr="",
        )
        _, result = probe.probe_host(
            {
                "host_id": "remote-a",
                "transport": "ssh",
                "hostname": "example.invalid",
                "user": "root",
                "port": 22,
                "project_path": "/srv/project",
                "discover_storage": False,
            },
            timeout=5,
            verify_external_network=True,
        )
        evidence = result["external_network_evidence"]
        self.assertEqual("blocked", evidence["status"])
        self.assertEqual("remote-a", evidence["target_host_id"])
        self.assertEqual(
            probe.EXTERNAL_NETWORK_EVIDENCE_TTL_SECONDS,
            evidence["ttl_seconds"],
        )
        self.assertIn("__LAD_VERIFY_EXTERNAL_NETWORK__", runner.call_args.kwargs["input"])


if __name__ == "__main__":
    unittest.main()
