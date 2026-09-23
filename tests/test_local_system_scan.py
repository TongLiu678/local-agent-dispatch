#!/usr/bin/env python3
"""Unit tests for the privacy-preserving local system scanner."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import tempfile
import unittest
from unittest import mock


SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "local_system_scan.py"
SPEC = importlib.util.spec_from_file_location("local_system_scan", SCRIPT)
assert SPEC and SPEC.loader
SCAN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SCAN)


class ParserTests(unittest.TestCase):
    def test_proc_cpuinfo_counts_socket_core_pairs(self) -> None:
        payload = """
processor : 0
physical id : 0
core id : 0
model name : Example CPU

processor : 1
physical id : 0
core id : 0
model name : Example CPU

processor : 2
physical id : 0
core id : 1
model name : Example CPU
"""
        physical, model = SCAN.parse_proc_cpuinfo(payload)
        self.assertEqual(physical, 2)
        self.assertEqual(model, "Example CPU")

    def test_meminfo_uses_memavailable(self) -> None:
        total, available = SCAN.parse_meminfo(
            "MemTotal:       1000 kB\nMemFree:         100 kB\nMemAvailable:    700 kB\n"
        )
        self.assertEqual(total, 1000 * 1024)
        self.assertEqual(available, 700 * 1024)

    def test_meminfo_legacy_kernel_estimates_reclaimable_memory(self) -> None:
        total, available = SCAN.parse_meminfo(
            "MemTotal:       1000 kB\n"
            "MemFree:         100 kB\n"
            "Buffers:         200 kB\n"
            "Cached:          300 kB\n"
        )
        self.assertEqual(total, 1000 * 1024)
        self.assertEqual(available, 600 * 1024)
        self.assertEqual(
            "procfs_legacy_estimate",
            SCAN.parse_meminfo_details(
                "MemTotal: 1000 kB\nMemFree: 100 kB\nBuffers: 200 kB\nCached: 300 kB\n"
            )[2],
        )

    def test_psi_memory_parser_keeps_avg10_and_rejects_invalid(self) -> None:
        self.assertEqual(
            12.5,
            SCAN.parse_psi_memory("some avg10=12.50 avg60=1.0 avg300=0.0 total=12\n"),
        )
        self.assertIsNone(SCAN.parse_psi_memory("some avg10=101.0 avg60=1.0"))

    def test_cgroup_v2_memory_parser_requires_finite_consistent_limit(self) -> None:
        evidence = SCAN.parse_cgroup_v2_memory(
            "memory.max 10737418240\n"
            "memory.current 6442450944\n"
            "high 7\noom 2\noom_kill 1\n"
        )
        self.assertEqual("complete", evidence["cgroup_memory_evidence_status"])
        self.assertEqual(4 * 1024**3, evidence["cgroup_memory_available_bytes"])
        self.assertEqual(7, evidence["cgroup_memory_events_high"])
        self.assertEqual(2, evidence["cgroup_memory_events_oom"])
        self.assertEqual(1, evidence["cgroup_memory_events_oom_kill"])
        self.assertEqual(
            "unknown",
            SCAN.parse_cgroup_v2_memory("memory.max max\nmemory.current 1\n")['cgroup_memory_evidence_status'],
        )

    def test_cgroup_v1_memory_parser_recognizes_unlimited_legacy_controller(self) -> None:
        evidence = SCAN.parse_cgroup_v1_memory(
            "memory.limit_in_bytes 9223372036854775807\n"
            "memory.usage_in_bytes 4294967296\n"
        )
        self.assertEqual("cgroup_v1", evidence["cgroup_memory_source"])
        self.assertEqual("unbounded", evidence["cgroup_memory_evidence_status"])
        self.assertTrue(evidence["cgroup_memory_unbounded"])
        self.assertEqual(4 * 1024**3, evidence["cgroup_memory_current_bytes"])

    def test_cgroup_v1_memory_parser_keeps_finite_boundary(self) -> None:
        evidence = SCAN.parse_cgroup_v1_memory(
            "memory.limit_in_bytes 10737418240\n"
            "memory.usage_in_bytes 6442450944\n"
        )
        self.assertEqual("complete", evidence["cgroup_memory_evidence_status"])
        self.assertEqual(4 * 1024**3, evidence["cgroup_memory_available_bytes"])
        self.assertFalse(evidence["cgroup_memory_unbounded"])

    def test_vm_stat_estimates_reclaimable_memory(self) -> None:
        payload = """
Mach Virtual Memory Statistics: (page size of 16384 bytes)
Pages free:                               100.
Pages inactive:                           50.
Pages speculative:                        20.
Pages purgeable:                          30.
Pages wired down:                       9999.
"""
        self.assertEqual(SCAN.parse_vm_stat(payload, 16384), 200 * 16384)

    def test_swapusage_parser_preserves_exhausted_swap(self) -> None:
        payload = "vm.swapusage: total = 1536.00M  used = 1536.00M  free = 0.00M"
        self.assertEqual(
            SCAN.parse_swapusage(payload),
            {
                "swap_total_bytes": 1536 * 1024**2,
                "swap_used_bytes": 1536 * 1024**2,
                "swap_free_bytes": 0,
            },
        )

    def test_memory_pressure_gate_blocks_exhausted_swap_with_low_headroom(self) -> None:
        self.assertEqual(
            SCAN._memory_pressure_state(
                total_bytes=32 * 1024**3,
                available_bytes=7 * 1024**3,
                swap_total_bytes=1536 * 1024**2,
                swap_free_bytes=0,
                pressure_free_percent=48,
            ),
            "critical",
        )

    def test_memory_pressure_gate_conserves_when_swap_is_already_high(self) -> None:
        # A healthy-looking instantaneous pressure percentage must not admit
        # another large context after the compressor has filled most swap.
        self.assertEqual(
            SCAN._memory_pressure_state(
                total_bytes=32 * 1024**3,
                available_bytes=8 * 1024**3,
                swap_total_bytes=2304 * 1024**2,
                swap_free_bytes=294 * 1024**2,
                pressure_free_percent=50,
            ),
            "conserve",
        )

    def test_memory_pressure_parser_is_bounded(self) -> None:
        self.assertEqual(
            SCAN.parse_memory_pressure("System-wide memory free percentage: 41%"),
            41,
        )
        self.assertIsNone(SCAN.parse_memory_pressure("memory free percentage: 101%"))

    def test_nvidia_parser_keeps_resource_fields(self) -> None:
        rows = SCAN.parse_nvidia_smi("0, RTX Test, 8192, 4096, 25, 555.1\n")
        self.assertEqual(rows[0]["vendor"], "NVIDIA")
        self.assertEqual(rows[0]["memory_total_bytes"], 8192 * 1024**2)
        self.assertEqual(rows[0]["utilization_percent"], 25.0)

    def test_lspci_recognizes_amd_and_intel(self) -> None:
        rows = SCAN.parse_lspci(
            '03:00.0 "VGA compatible controller" "Advanced Micro Devices, Inc." "Navi 31"\n'
            '00:02.0 "VGA compatible controller" "Intel Corporation" "Arc Graphics"\n'
        )
        self.assertEqual([row["vendor"] for row in rows], ["AMD", "Intel"])


class PrivacyTests(unittest.TestCase):
    def test_process_output_never_contains_arguments_or_prompt(self) -> None:
        text = (
            "100 /usr/local/bin/codex --prompt TOP_SECRET\n"
            "101 /opt/bin/opencode --task PRIVATE_REQUEST\n"
            "102 /usr/bin/python secret.py\n"
        )
        rows = SCAN.parse_unix_processes(text, current_pid=999)
        serialized = json.dumps(rows)
        self.assertEqual(
            rows,
            [
                {"pid": 100, "command_name": "codex", "kind": "agent"},
                {"pid": 101, "command_name": "opencode", "kind": "agent"},
            ],
        )
        self.assertNotIn("TOP_SECRET", serialized)
        self.assertNotIn("PRIVATE_REQUEST", serialized)
        self.assertNotIn("--prompt", serialized)

    def test_process_scan_can_record_rss_without_collecting_arguments(self) -> None:
        rows = SCAN.parse_unix_processes("100 4096 /usr/local/bin/opencode\n", current_pid=999)
        self.assertEqual(
            rows,
            [{"pid": 100, "command_name": "opencode", "kind": "agent", "rss_kib": 4096}],
        )

    def test_cli_probes_are_version_only(self) -> None:
        for args in SCAN.CLI_VERSION_ARGS.values():
            self.assertIn(args, (("--version",), ("-V",)))

    def test_safe_environment_keeps_home_but_excludes_credentials(self) -> None:
        with mock.patch.dict(
            SCAN.os.environ,
            {"PATH": "/bin", "OPENAI_API_KEY": "secret", "HOME": "/private/home"},
            clear=True,
        ):
            environment = SCAN._safe_environment()
        self.assertEqual(environment["PATH"], "/bin")
        self.assertEqual(environment["HOME"], "/private/home")
        self.assertNotIn("OPENAI_API_KEY", environment)
        self.assertEqual(environment["NODE_DISABLE_COMPILE_CACHE"], "1")


class ScanTests(unittest.TestCase):
    def test_python_runtime_evidence_enforces_package_minimum(self) -> None:
        old = SCAN.python_runtime_evidence((3, 9, 6), "/usr/bin/python3")
        current = SCAN.python_runtime_evidence((3, 10, 0), "/opt/python")
        self.assertFalse(old["supported"])
        self.assertEqual("3.10", old["minimum_version"])
        self.assertTrue(current["supported"])

    def test_opencode_is_part_of_the_cli_inventory(self) -> None:
        def fake_which(name: str) -> str | None:
            return f"/usr/bin/{name}" if name == "opencode" else None

        def fake_run(argv: list[str], timeout: float) -> dict[str, object]:
            self.assertEqual(argv, ["/usr/bin/opencode", "--version"])
            return {
                "ok": True,
                "returncode": 0,
                "stdout": "opencode 1.2.3\n",
                "stderr": "",
                "timed_out": False,
            }

        with mock.patch.object(SCAN, "_local_command", side_effect=fake_which), mock.patch.object(
            SCAN, "_run_command", side_effect=fake_run
        ):
            clis = SCAN.scan_clis(1.0)
        self.assertTrue(clis["opencode"]["present"])
        self.assertEqual(clis["opencode"]["version"], "opencode 1.2.3")
        self.assertFalse(clis["codex"]["present"])

    def test_cursor_desktop_does_not_substitute_for_cursor_agent(self) -> None:
        def fake_which(name: str) -> str | None:
            return "/usr/local/bin/cursor" if name == "cursor" else None

        def fake_run(argv: list[str], timeout: float) -> dict[str, object]:
            self.assertEqual(argv, ["/usr/local/bin/cursor", "--version"])
            return {
                "ok": True,
                "returncode": 0,
                "stdout": "3.5.33\n",
                "stderr": "",
                "timed_out": False,
            }

        with mock.patch.object(SCAN, "_local_command", side_effect=fake_which), mock.patch.object(
            SCAN, "_run_command", side_effect=fake_run
        ):
            clis = SCAN.scan_clis(1.0)
        self.assertTrue(clis["cursor"]["present"])
        self.assertFalse(clis["cursor-agent"]["present"])

    def test_ollama_version_is_static_and_never_invokes_cli(self) -> None:
        def fake_which(name: str) -> str | None:
            return "/opt/homebrew/bin/ollama" if name == "ollama" else None

        with mock.patch.object(SCAN, "_local_command", side_effect=fake_which), mock.patch.object(
            SCAN, "static_version_from_executable", return_value="0.22.0"
        ), mock.patch.object(SCAN, "_run_command") as run:
            clis = SCAN.scan_clis(1.0)
        run.assert_not_called()
        self.assertEqual(clis["ollama"]["version"], "0.22.0")
        self.assertEqual(clis["ollama"]["version_source"], "installation_path")

    def test_disk_scan_does_not_create_missing_cache_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cache = pathlib.Path(directory) / "not-created" / "cache"
            row = SCAN.scan_disk(cache)
            self.assertFalse(row["exists"])
            self.assertFalse(cache.exists())
            self.assertIsNotNone(row["free_bytes"])

    def test_disk_pressure_blocks_bulk_local_work(self) -> None:
        gate = SCAN.disk_capacity_gate(
            {
                "workspace": {"free_bytes": 5 * 1024**3, "free_percent": 20.0},
                "cache": {"free_bytes": 50 * 1024**3, "free_percent": 5.0},
            }
        )
        self.assertTrue(gate["disk_pressure"])
        self.assertFalse(gate["local_bulk_allowed"])
        self.assertEqual(gate["pressured_disks"], ["workspace", "cache"])

    def test_snapshot_blocks_new_agent_launch_when_disk_is_pressured(self) -> None:
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            SCAN, "scan_accelerators", return_value=([], [])
        ), mock.patch.object(SCAN, "scan_cpu", return_value={"logical_cores": 4}), mock.patch.object(
            SCAN,
            "scan_ram",
            return_value={"total_bytes": 16 * 1024**3, "available_bytes": 8 * 1024**3},
        ), mock.patch.object(SCAN, "scan_clis", return_value={}), mock.patch.object(
            SCAN,
            "scan_processes",
            return_value={"scan_ok": True, "arguments_collected": False, "processes": []},
        ), mock.patch.object(
            SCAN,
            "scan_disk",
            side_effect=[
                {"exists": True, "writable": True, "free_bytes": 128 * 1024**2, "free_percent": 1.0},
                {"exists": True, "writable": True, "free_bytes": 128 * 1024**2, "free_percent": 1.0},
            ],
        ):
            snapshot = SCAN.build_snapshot(pathlib.Path(directory), pathlib.Path(directory), 1.0)
        self.assertTrue(snapshot["capacity_gates"]["disk_pressure"])
        self.assertFalse(snapshot["capacity_gates"]["local_agent_launch_allowed"])
        self.assertIn("new agent launches are blocked", " ".join(snapshot["warnings"]))

    def test_snapshot_blocks_new_agent_launch_on_unsupported_python(self) -> None:
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            SCAN, "scan_accelerators", return_value=([], [])
        ), mock.patch.object(SCAN, "scan_cpu", return_value={"logical_cores": 4}), mock.patch.object(
            SCAN,
            "scan_ram",
            return_value={
                "total_bytes": 16 * 1024**3,
                "available_bytes": 8 * 1024**3,
                "pressure_state": "healthy",
            },
        ), mock.patch.object(SCAN, "scan_clis", return_value={}), mock.patch.object(
            SCAN,
            "scan_processes",
            return_value={"scan_ok": True, "arguments_collected": False, "processes": []},
        ), mock.patch.object(
            SCAN,
            "python_runtime_evidence",
            return_value={
                "version": "3.9.6",
                "implementation": "CPython",
                "executable": "/usr/bin/python3",
                "minimum_version": "3.10",
                "supported": False,
            },
        ):
            snapshot = SCAN.build_snapshot(
                pathlib.Path(directory), pathlib.Path(directory), 1.0
            )
        self.assertFalse(snapshot["capacity_gates"]["python_runtime_supported"])
        self.assertFalse(snapshot["capacity_gates"]["local_agent_launch_allowed"])
        self.assertIn("below the required 3.10", " ".join(snapshot["warnings"]))

    def test_scan_cpu_exposes_read_only_load_average_when_available(self) -> None:
        with mock.patch.object(
            SCAN.os, "getloadavg", return_value=(2.5, 2.0, 1.5), create=True
        ):
            cpu = SCAN.scan_cpu("Other", 1.0)
        self.assertEqual(2.5, cpu["load_1m"])
        self.assertEqual("os.getloadavg", cpu["load_source"])

    def test_scan_cpu_keeps_load_unknown_when_platform_has_no_load_average(self) -> None:
        with mock.patch.object(
            SCAN.os, "getloadavg", side_effect=OSError("unsupported"), create=True
        ):
            cpu = SCAN.scan_cpu("Other", 1.0)
        self.assertIsNone(cpu["load_1m"])
        self.assertIsNone(cpu["load_source"])

    def test_snapshot_has_stable_public_schema_and_read_only_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            SCAN, "scan_accelerators", return_value=([], [])
        ), mock.patch.object(SCAN, "scan_cpu", return_value={"logical_cores": 4}), mock.patch.object(
            SCAN, "scan_ram", return_value={"total_bytes": 1024}
        ), mock.patch.object(SCAN, "scan_clis", return_value={}), mock.patch.object(
            SCAN,
            "scan_processes",
            return_value={"scan_ok": True, "arguments_collected": False, "processes": []},
        ):
            snapshot = SCAN.build_snapshot(pathlib.Path(directory), pathlib.Path(directory), 1.0)
        for key in (
            "os",
            "arch",
            "kernel",
            "python",
            "cpu",
            "ram",
            "disks",
            "capacity_gates",
            "accelerators",
            "clis",
            "agent_model_processes",
        ):
            self.assertIn(key, snapshot)
        self.assertTrue(snapshot["scan_policy"]["read_only"])
        self.assertFalse(snapshot["scan_policy"]["network_probes"])
        self.assertFalse(snapshot["scan_policy"]["model_invocations"])
        self.assertFalse(snapshot["scan_policy"]["credential_queries"])
        self.assertFalse(snapshot["scan_policy"]["process_arguments_collected"])


if __name__ == "__main__":
    unittest.main()
