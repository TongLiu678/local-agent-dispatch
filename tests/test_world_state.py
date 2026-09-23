"""Provider-free tests for the world-state digital twin records."""

from __future__ import annotations

import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from local_agent_dispatch.domain.world_state import (  # noqa: E402
    SCHEMA_VERSION,
    CacheState,
    CpuTopology,
    DatasetLocation,
    GpuProcess,
    GpuState,
    Host,
    MountState,
    NumaNode,
    NumaTopology,
    Observation,
    QuotaState,
    RamState,
    ResourceValues,
    RouteRecord,
    RuntimeState,
    WorldStateSnapshot,
)

NOW = "2026-08-12T12:00:00+00:00"


class WorldStateRecordTests(unittest.TestCase):
    def test_schema_version_is_const_and_serialized(self):
        snapshot = WorldStateSnapshot(created_at=NOW)
        self.assertEqual(SCHEMA_VERSION, snapshot.schema_version)
        self.assertEqual(1, snapshot.to_dict()["schema_version"])
        self.assertEqual(snapshot, WorldStateSnapshot.from_dict(snapshot.to_dict()))

    def test_unknown_schema_version_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "unsupported world_state schema_version"):
            WorldStateSnapshot.from_dict({"schema_version": 2})

    def test_resource_values_keep_capacity_allocatable_available_reserved_apart(self):
        values = ResourceValues(
            units="MiB",
            capacity=24564.0,
            allocatable=23000.0,
            available_now=8000.0,
            reserved=2048.0,
        )
        restored = ResourceValues.from_dict(values.to_dict())
        self.assertEqual(24564.0, restored.capacity)
        self.assertEqual(23000.0, restored.allocatable)
        self.assertEqual(8000.0, restored.available_now)
        self.assertEqual(2048.0, restored.reserved)
        self.assertEqual(values, restored)

    def test_unknowns_are_preserved_not_fabricated(self):
        values = ResourceValues.from_dict(ResourceValues(units="MiB").to_dict())
        self.assertIsNone(values.capacity)
        self.assertIsNone(values.allocatable)
        self.assertIsNone(values.available_now)
        self.assertIsNone(values.reserved)
        self.assertEqual("MiB", values.units)
        payload = json.loads(json.dumps(values.to_dict()))
        self.assertEqual({"units": "MiB"}, payload)

    def test_observation_ttl_fresh_stale_and_unverifiable(self):
        fresh = Observation(
            kind="mount",
            source="statvfs",
            observed_at="2026-08-12T11:30:00+00:00",
            ttl_seconds=1800.0,
        )
        self.assertFalse(fresh.is_stale(NOW))
        self.assertTrue(fresh.is_stale("2026-08-12T12:01:00+00:00"))
        no_ttl = Observation(
            kind="mount",
            source="statvfs",
            observed_at="2026-08-12T11:30:00+00:00",
        )
        self.assertIsNone(no_ttl.is_stale(NOW))
        self.assertEqual(fresh, Observation.from_dict(fresh.to_dict()))

    def test_future_observation_is_unverifiable_not_fresh(self):
        future = Observation(
            kind="ram",
            source="provider-free-test",
            observed_at="2026-08-12T12:00:01+00:00",
            ttl_seconds=60.0,
        )

        self.assertIsNone(future.is_stale(NOW))

    def test_observation_preserves_evidence_and_confidence(self):
        observation = Observation(
            kind="vram",
            source="nvidia-smi",
            observed_at=NOW,
            evidence=("nvidia-smi --query-gpu", "nvidia-smi --query-compute-apps"),
            ttl_seconds=60.0,
            confidence=0.99,
        )
        restored = Observation.from_dict(observation.to_dict())
        self.assertEqual(
            ("nvidia-smi --query-gpu", "nvidia-smi --query-compute-apps"),
            restored.evidence,
        )
        self.assertEqual(0.99, restored.confidence)

    def test_host_roles_execution_and_workload_stay_separate(self):
        execution = Host(
            host_id="local", name="mac", os="darwin", arch="arm64",
            execution_host=True,
        )
        workload = Host(
            host_id="server", name="s1", os="linux", arch="x86_64",
            workload_host=True,
        )
        self.assertTrue(execution.execution_host)
        self.assertFalse(execution.workload_host)
        self.assertFalse(workload.execution_host)
        self.assertTrue(workload.workload_host)
        snapshot = WorldStateSnapshot(hosts=(execution, workload), created_at=NOW)
        restored = WorldStateSnapshot.from_dict(snapshot.to_dict())
        self.assertEqual(
            ("local",),
            tuple(h.host_id for h in restored.hosts_with_role(execution=True)),
        )
        self.assertEqual(
            ("server",),
            tuple(h.host_id for h in restored.hosts_with_role(workload=True)),
        )
        self.assertEqual(
            (),
            tuple(
                h.host_id
                for h in restored.hosts_with_role(execution=False, workload=False)
            ),
        )
        self.assertEqual(
            ("local",),
            tuple(
                h.host_id
                for h in restored.hosts_with_role(execution=True, workload=False)
            ),
        )
        self.assertEqual(
            ("server",),
            tuple(
                h.host_id
                for h in restored.hosts_with_role(execution=False, workload=True)
            ),
        )

    def test_cgroup_limits_and_gpu_process_fields_round_trip(self):
        ram = RamState(
            values=ResourceValues(units="bytes", capacity=68719476736),
            cgroup_limit_bytes=42949672960,
            cgroup_current_bytes=12884901888,
        )
        gpu = GpuState(
            index="0",
            model="NVIDIA GeForce RTX 4090",
            cuda_compatible=True,
            vram=ResourceValues(units="MiB", capacity=24564, available_now=8000),
            processes=(
                GpuProcess(pid=1111, name="python3", vram_mib=5000),
                GpuProcess(pid=2222, name="train.py", vram_mib=2000),
            ),
        )
        restored_ram = RamState.from_dict(ram.to_dict())
        self.assertEqual(42949672960, restored_ram.cgroup_limit_bytes)
        self.assertEqual(12884901888, restored_ram.cgroup_current_bytes)
        restored_gpu = GpuState.from_dict(gpu.to_dict())
        self.assertEqual(7000, restored_gpu.in_use_vram_mib())
        self.assertTrue(restored_gpu.cuda_compatible)
        self.assertEqual(("python3", "train.py"), tuple(p.name for p in restored_gpu.processes))
        gpu_no_processes = GpuState(index="1")
        self.assertEqual(0, gpu_no_processes.in_use_vram_mib())
        self.assertIsNone(gpu_no_processes.vram)

    def test_full_topology_records_round_trip(self):
        mount = MountState(
            path="/data",
            device="/dev/nvme0n1p3",
            fs_type="xfs",
            options=("rw", "noatime"),
            writable=True,
            probed_path="/data",
            values=ResourceValues(
                units="bytes",
                capacity=1073741824000,
                allocatable=1065151889408,
                available_now=858993459200,
                reserved=0,
            ),
            free_bytes=858993459200,
            free_inodes=2000000,
            quota=QuotaState(
                kind="project",
                unit="bytes",
                limit=268435456000,
                used=134217728000,
                free=134217728000,
                source="xfs_quota report",
            ),
            observation=Observation(
                kind="mount", source="statvfs", observed_at=NOW, ttl_seconds=1800
            ),
        )
        host = Host(
            host_id="h1",
            name="server-1",
            os="linux",
            arch="x86_64",
            execution_host=True,
            workload_host=True,
            cpu=CpuTopology(
                sockets=1,
                cores=16,
                threads=32,
                model="AMD EPYC 9454",
                numa=NumaTopology(
                    nodes=(
                        NumaNode(node_id="0", cpu_ids=("0", "1"), ram_bytes=53687091200),
                        NumaNode(node_id="1", cpu_ids=("16", "17"), ram_bytes=53687091200),
                    ),
                    distances=((10, 21), (21, 10)),
                ),
            ),
            ram=RamState(values=ResourceValues(units="bytes", capacity=107374182400)),
            gpus=(
                GpuState(
                    index="0",
                    model="RTX 4090",
                    vram=ResourceValues(units="MiB", capacity=24564, available_now=20000),
                ),
            ),
            mounts=(mount,),
            runtimes=(
                RuntimeState(
                    name="python3", version="3.11.9", compatible=True,
                    cuda_supported=False,
                ),
            ),
            caches=(CacheState(path="/data/EXAMPLE_001", mount_path="/data", declared_bytes=1073741824),),
            datasets=(
                DatasetLocation(
                    name="qwen2.5-awq",
                    path="/data/EXAMPLE_002/qwen2.5-7b-awq",
                    mount_path="/data",
                    bytes_total=5368709120,
                    classification="public",
                ),
            ),
            observations=(
                Observation(kind="cpu", source="lscpu", observed_at=NOW),
            ),
            labels=("ssh-host", "server-first"),
        )
        restored = Host.from_dict(host.to_dict())
        self.assertEqual(host, restored)
        self.assertIsNotNone(restored.mount("/data"))
        self.assertIsNone(restored.mount("/data/EXAMPLE_002"))

    def test_route_records_carry_kind_status_verification_and_evidence(self):
        control = RouteRecord(
            kind="control",
            status="direct",
            verified_at="2026-08-12T11:29:00+00:00",
            evidence=("ssh control channel verified",),
            peer="server-1:22",
            rtt_ms=3.1,
        )
        bulk = RouteRecord(
            kind="bulk_data",
            status="relay",
            verified_at="2026-08-12T11:29:10+00:00",
            evidence=("egress identity observed via relay",),
        )
        snapshot = WorldStateSnapshot(routes=(control, bulk), created_at=NOW)
        restored = WorldStateSnapshot.from_dict(snapshot.to_dict())
        self.assertEqual("direct", restored.route_status("control"))
        self.assertEqual("relay", restored.route_status("bulk_data"))
        self.assertEqual(
            ("ssh control channel verified",),
            restored.route("control").evidence,
        )
        self.assertEqual("2026-08-12T11:29:00+00:00", restored.route("control").verified_at)

    def test_missing_route_reports_unknown_not_inferred(self):
        snapshot = WorldStateSnapshot(routes=(), created_at=NOW)
        self.assertEqual("unknown", snapshot.route_status("bulk_data"))
        self.assertIsNone(snapshot.route("bulk_data"))
        self.assertEqual("unknown", snapshot.route_status("control"))

    def test_route_kinds_are_not_merged(self):
        routes = (
            RouteRecord(kind="control", status="direct"),
            RouteRecord(kind="artifact", status="relay"),
            RouteRecord(kind="bulk_data", status="unknown"),
            RouteRecord(kind="execution", status="direct"),
            RouteRecord(kind="workload", status="unknown"),
        )
        snapshot = WorldStateSnapshot(routes=routes, created_at=NOW)
        for kind in ("control", "artifact", "bulk_data", "execution", "workload"):
            self.assertEqual(1, len([r for r in snapshot.routes if r.kind == kind]))
        self.assertEqual("direct", snapshot.route_status("control"))
        self.assertEqual("relay", snapshot.route_status("artifact"))
        self.assertEqual("unknown", snapshot.route_status("bulk_data"))
        self.assertEqual("direct", snapshot.route_status("execution"))
        self.assertEqual("unknown", snapshot.route_status("workload"))


class WorldStateSchemaTests(unittest.TestCase):
    def test_schema_document_is_loadable_and_self_consistent(self):
        schema_path = ROOT / "schemas" / "world_state.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertEqual(
            "http://json-schema.org/draft-07/schema#", schema["$schema"]
        )
        self.assertEqual("World State Snapshot (Resource Digital Twin)", schema["title"])
        self.assertEqual({"type": "integer", "const": 1}, schema["properties"]["schema_version"])
        definitions = schema["definitions"]
        for name in (
            "observation",
            "resource_values",
            "numa_node",
            "numa_topology",
            "cpu",
            "ram",
            "gpu_process",
            "gpu",
            "quota",
            "mount",
            "runtime",
            "cache",
            "dataset",
            "route",
            "host",
        ):
            self.assertIn(name, definitions)

    def test_fixture_snapshots_satisfy_schema_shape(self):
        scenarios_path = ROOT / "research" / "scenarios" / "resource-topologies.json"
        scenarios = json.loads(scenarios_path.read_text(encoding="utf-8"))
        schema = json.loads(
            (ROOT / "schemas" / "world_state.schema.json").read_text(encoding="utf-8")
        )
        route_kinds = schema["definitions"]["route"]["properties"]["kind"]["enum"]
        route_statuses = schema["definitions"]["route"]["properties"]["status"]["enum"]
        for scenario in scenarios["scenarios"]:
            snapshot = scenario["snapshot"]
            self.assertEqual(1, snapshot["schema_version"])
            for host in snapshot.get("hosts", []):
                self.assertIn("host_id", host)
                self.assertIn("name", host)
            for route in snapshot.get("routes", []):
                self.assertIn(route["kind"], route_kinds)
                self.assertIn(route["status"], route_statuses)
                self.assertIn("kind", route)
                self.assertIn("status", route)

    def test_fixture_scenarios_load_through_domain_models(self):
        scenarios_path = ROOT / "research" / "scenarios" / "resource-topologies.json"
        scenarios = json.loads(scenarios_path.read_text(encoding="utf-8"))
        for scenario in scenarios["scenarios"]:
            snapshot = WorldStateSnapshot.from_dict(scenario["snapshot"])
            self.assertEqual(snapshot, WorldStateSnapshot.from_dict(snapshot.to_dict()))
            for host in snapshot.hosts:
                self.assertEqual(
                    host,
                    Host.from_dict(json.loads(json.dumps(host.to_dict()))),
                )


if __name__ == "__main__":
    unittest.main()
