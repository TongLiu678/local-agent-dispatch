"""Provider-free tests for mount/path topology gates and route evidence.

All fixtures come from ``research/scenarios/resource-topologies.json`` or are
parsed from captured probe text; no live probe runs in these tests.
"""

from __future__ import annotations

import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from local_agent_dispatch.domain.world_state import (  # noqa: E402
    Host,
    MountState,
    Observation,
    ResourceValues,
    WorldStateSnapshot,
)
from local_agent_dispatch.resources.probes import (  # noqa: E402
    apply_statvfs,
    parse_cgroup_v2_memory,
    parse_mountinfo,
    parse_nvidia_apps_csv,
    parse_nvidia_gpu_csv,
)
from local_agent_dispatch.resources.topology import (  # noqa: E402
    PathRequirements,
    evaluate_placement,
    evaluate_vram,
    rank_gpus,
    rank_paths,
    resolve_mount,
)

NOW = "2026-08-12T12:00:00+00:00"
GIB = 1024**3


def load_scenario(scenario_id: str) -> tuple[WorldStateSnapshot, str]:
    scenarios_path = ROOT / "research" / "scenarios" / "resource-topologies.json"
    scenarios = json.loads(scenarios_path.read_text(encoding="utf-8"))
    for scenario in scenarios["scenarios"]:
        if scenario["scenario_id"] == scenario_id:
            return (
                WorldStateSnapshot.from_dict(scenario["snapshot"]),
                scenario.get("now", NOW),
            )
    raise AssertionError(f"scenario {scenario_id!r} not found in fixtures")


def windows_mount(path: str = "C:\\data", *, probed_path: str = "C:/data") -> MountState:
    free = 20 * GIB
    return MountState(
        path=path,
        fs_type="ntfs",
        writable=True,
        probed_path=probed_path,
        free_bytes=free,
        free_inodes=100_000,
        values=ResourceValues(units="bytes", available_now=free),
        observation=Observation(
            kind="mount",
            source="windows-volume",
            observed_at="2026-08-12T11:30:00+00:00",
            ttl_seconds=1800,
        ),
    )


class CrossPlatformPathTests(unittest.TestCase):
    def test_windows_separator_variants_are_the_same_exact_mount(self):
        mount = windows_mount("C:\\data")
        resolution = resolve_mount("C:/data", (mount,))
        self.assertIs(mount, resolution.mount)
        self.assertTrue(resolution.probed)
        self.assertFalse(resolution.covering_prefix)

    def test_windows_mount_covers_workspace_without_prefix_collision(self):
        mount = windows_mount("C:/data")
        covered = resolve_mount("c:\\DATA\\workspace\\repo", (mount,))
        self.assertIs(mount, covered.mount)
        self.assertTrue(covered.covering_prefix)
        collision = resolve_mount("C:\\database\\repo", (mount,))
        self.assertIsNone(collision.mount)

        host = Host(host_id="windows", name="windows", mounts=(mount,))
        decision = evaluate_placement(
            host,
            "C:\\data\\workspace",
            PathRequirements(required_bytes=GIB),
            now=NOW,
        )
        self.assertEqual("safe", decision.verdict)
        self.assertIs(mount, decision.mount)

    def test_unc_path_is_explicitly_unknown_and_fails_closed(self):
        mount = windows_mount()
        path = r"\\server\share\workspace"
        resolution = resolve_mount(path, (mount,))
        self.assertIsNone(resolution.mount)
        self.assertTrue(resolution.evidence_unknown)
        self.assertIn("UNC", resolution.reason or "")

        host = Host(host_id="windows", name="windows", mounts=(mount,))
        decision = evaluate_placement(
            host, path, PathRequirements(required_bytes=1), now=NOW
        )
        self.assertEqual("unknown", decision.verdict)
        self.assertTrue(any("UNC" in reason for reason in decision.reasons))


class SmallRootProjectMountTests(unittest.TestCase):
    def test_large_project_mount_is_safe_while_small_root_is_rejected(self):
        snapshot, now = load_scenario("small-root-large-project-mount")
        host = snapshot.host("host-remote-a")
        requirements = PathRequirements(
            required_bytes=10 * GIB, required_inodes=5000
        )
        root = evaluate_placement(host, "/", requirements, now=now)
        self.assertEqual("reject", root.verdict)
        project = evaluate_placement(
            host, "/data/EXAMPLE_001/fem-mpb", requirements, now=now
        )
        self.assertEqual("safe", project.verdict)
        self.assertEqual(host.mount("/data"), project.mount)
        self.assertGreater(project.safe_to_place_bytes, 0)

    def test_root_capacity_never_substitutes_for_project_mount(self):
        snapshot, now = load_scenario("small-root-large-project-mount")
        host = snapshot.host("host-remote-a")
        requirements = PathRequirements(required_bytes=1 * GIB)
        # /data is writable and huge; the tiny root must not veto it.
        self.assertEqual(
            "safe", evaluate_placement(host, "/data/EXAMPLE_002", requirements, now=now).verdict
        )
        # A request that only fits the large mount must still reject on root.
        self.assertEqual(
            "reject", evaluate_placement(host, "/", requirements, now=now).verdict
        )


class RootOnlyProbeTests(unittest.TestCase):
    def test_root_only_probing_is_rejected_for_other_mounts(self):
        snapshot, now = load_scenario("root-only-probe")
        host = snapshot.host("host-root-only")
        requirements = PathRequirements(required_bytes=1 * GIB)
        decision = evaluate_placement(
            host, "/data/EXAMPLE_001/x", requirements, now=now
        )
        self.assertEqual("reject", decision.verdict)
        self.assertTrue(
            any("root-only" in reason or "never probed" in reason for reason in decision.reasons)
        )

    def test_unlisted_mount_disappearance_rejects_without_evidence(self):
        snapshot, now = load_scenario("mount-disappearance")
        host = snapshot.host("host-mount-gone")
        requirements = PathRequirements(required_bytes=1 * GIB)
        decision = evaluate_placement(
            host, "/data/EXAMPLE_001/x", requirements, now=now
        )
        self.assertEqual("reject", decision.verdict)
        self.assertTrue(
            any("no mount evidence" in reason for reason in decision.reasons)
        )


class StaleEvidenceTests(unittest.TestCase):
    def test_stale_root_capacity_is_never_accepted(self):
        snapshot, now = load_scenario("stale-root-evidence")
        host = snapshot.host("host-stale-root")
        requirements = PathRequirements(required_bytes=1 * GIB)
        root = evaluate_placement(host, "/", requirements, now=now)
        self.assertEqual("reject", root.verdict)
        self.assertTrue(
            any("stale" in reason for reason in root.reasons)
        )
        # The fresh mount remains usable.
        self.assertEqual(
            "safe", evaluate_placement(host, "/data/EXAMPLE_003", requirements, now=now).verdict
        )


class ReadOnlyMountTests(unittest.TestCase):
    def test_read_only_shared_mount_is_rejected_despite_free_space(self):
        snapshot, now = load_scenario("read-only-shared-mount")
        host = snapshot.host("host-ro-shared")
        requirements = PathRequirements(required_bytes=2 * GIB)
        shared = evaluate_placement(host, "/shared/artifacts", requirements, now=now)
        self.assertEqual("reject", shared.verdict)
        self.assertTrue(any("not writable" in reason for reason in shared.reasons))


class InodeAndQuotaTests(unittest.TestCase):
    def test_inode_exhaustion_is_rejected_with_healthy_free_bytes(self):
        snapshot, now = load_scenario("inode-exhaustion")
        host = snapshot.host("host-inodes")
        requirements = PathRequirements(
            required_bytes=1 * GIB, required_inodes=100
        )
        decision = evaluate_placement(host, "/data/project", requirements, now=now)
        self.assertEqual("reject", decision.verdict)
        self.assertTrue(any("inode exhaustion" in reason for reason in decision.reasons))

    def test_unknown_free_inodes_fail_closed(self):
        snapshot, now = load_scenario("inode-exhaustion")
        host = snapshot.host("host-inodes")
        requirements = PathRequirements(
            required_bytes=1 * GIB, required_inodes=100
        )
        decision = evaluate_placement(host, "/works/project", requirements, now=now)
        self.assertEqual("unknown", decision.verdict)
        self.assertTrue(any("inodes are unknown" in reason for reason in decision.reasons))

    def test_unknown_quota_free_fail_closed(self):
        snapshot, now = load_scenario("inode-exhaustion")
        host = snapshot.host("host-inodes")
        requirements = PathRequirements(required_bytes=1 * GIB)
        decision = evaluate_placement(host, "/quota/project", requirements, now=now)
        self.assertEqual("unknown", decision.verdict)
        self.assertTrue(any("quota exists but free quota is unknown" in reason for reason in decision.reasons))

    def test_known_quota_free_caps_effective_free_space(self):
        snapshot, now = load_scenario("inode-exhaustion")
        host = snapshot.host("host-inodes")
        data = host.to_dict()
        for mount in data["mounts"]:
            if mount["path"] == "/quota":
                mount["quota"]["free"] = 2 * GIB
        quota_host = WorldStateSnapshot.from_dict(
            {"schema_version": 1, "hosts": [data]}
        ).host("host-inodes")
        big_requirements = PathRequirements(required_bytes=2 * GIB)
        big = evaluate_placement(quota_host, "/quota/big", big_requirements, now=now)
        self.assertEqual("reject", big.verdict)
        self.assertTrue(any("P90 headroom" in reason for reason in big.reasons))
        small_requirements = PathRequirements(required_bytes=1 * GIB)
        small = evaluate_placement(quota_host, "/quota/small", small_requirements, now=now)
        self.assertEqual("safe", small.verdict)


class VramTests(unittest.TestCase):
    def test_vram_pressure_rejects_busy_gpu_and_safe_on_idle_gpu(self):
        snapshot, _ = load_scenario("vram-pressure")
        host = snapshot.host("host-vram")
        gpu_0 = host.gpus[0]
        gpu_1 = host.gpus[1]
        fit_0 = evaluate_vram(gpu_0, required_mib=2048)
        fit_1 = evaluate_vram(gpu_1, required_mib=2048)
        self.assertEqual("reject", fit_0.verdict)
        self.assertEqual("safe", fit_1.verdict)
        self.assertEqual(-500, fit_0.available_now_mib)
        self.assertEqual(8500, fit_0.in_use_mib)

    def test_rank_gpus_orders_safe_first(self):
        snapshot, _ = load_scenario("vram-pressure")
        host = snapshot.host("host-vram")
        ranked = rank_gpus(host.gpus, required_mib=2048)
        self.assertEqual(("safe", "reject"), tuple(fit.verdict for fit in ranked))
        self.assertEqual(("1", "0"), tuple(fit.gpu_index for fit in ranked))


class RankingTests(unittest.TestCase):
    def test_rank_paths_safe_first_then_by_headroom(self):
        snapshot, now = load_scenario("healthy-single-host")
        host = snapshot.host("host-healthy")
        requirements = PathRequirements(
            required_bytes=8 * GIB, required_inodes=1000
        )
        candidates = [
            "/",
            "/data/EXAMPLE_001/p1",
            "/data/EXAMPLE_002",
            "/data/tmp",
            "/data/EXAMPLE_004",
        ]
        ranked = rank_paths(host, requirements, candidates, now=now)
        self.assertEqual(("safe",) * 5, tuple(d.verdict for d in ranked))
        self.assertEqual("/data/EXAMPLE_001/p1", ranked[0].path)
        self.assertEqual("/", ranked[-1].path)
        self.assertEqual(2, len({d.safe_to_place_bytes for d in ranked}))

    def test_rank_paths_rejects_and_unknowns_sort_after_safe(self):
        snapshot, now = load_scenario("inode-exhaustion")
        host = snapshot.host("host-inodes")
        requirements = PathRequirements(
            required_bytes=1 * GIB, required_inodes=100
        )
        ranked = rank_paths(
            host, requirements, ["/data/project", "/works/project"], now=now
        )
        self.assertEqual(("unknown", "reject"), tuple(d.verdict for d in ranked))


class P90HeadroomTests(unittest.TestCase):
    def test_p90_headroom_is_enforced_on_boundary(self):
        from local_agent_dispatch.domain.world_state import (
            MountState,
            Observation,
            ResourceValues,
            Host,
        )

        free = 11000
        mount = MountState(
            path="/data",
            writable=True,
            probed_path="/data",
            free_bytes=free,
            free_inodes=10000,
            values=ResourceValues(units="bytes", available_now=free),
            observation=Observation(
                kind="mount",
                source="statvfs",
                observed_at="2026-08-12T11:30:00+00:00",
                ttl_seconds=1800,
            ),
        )
        host = Host(host_id="h", name="h", mounts=(mount,))
        just_fits = PathRequirements(required_bytes=10000, p90_headroom_ratio=0.1)
        self.assertEqual(
            "safe", evaluate_placement(host, "/data/EXAMPLE_003", just_fits, now=NOW).verdict
        )
        too_big = PathRequirements(required_bytes=10001, p90_headroom_ratio=0.1)
        decision = evaluate_placement(host, "/data/EXAMPLE_003", too_big, now=NOW)
        self.assertEqual("reject", decision.verdict)
        self.assertEqual(1000, decision.p90_headroom_bytes)

    def test_reserved_capacity_is_subtracted_from_safe_placement(self):
        from local_agent_dispatch.domain.world_state import (
            Host,
            MountState,
            Observation,
            ResourceValues,
        )

        mount = MountState(
            path="/data",
            writable=True,
            probed_path="/data",
            free_bytes=11000,
            free_inodes=10000,
            values=ResourceValues(
                units="bytes", available_now=11000, reserved=5000
            ),
            observation=Observation(
                kind="mount",
                source="statvfs",
                observed_at="2026-08-12T11:30:00+00:00",
                ttl_seconds=1800,
            ),
        )
        host = Host(host_id="h", name="h", mounts=(mount,))
        requirements = PathRequirements(required_bytes=10000, p90_headroom_ratio=0.0)
        decision = evaluate_placement(host, "/data/EXAMPLE_003", requirements, now=NOW)
        self.assertEqual("reject", decision.verdict)
        self.assertTrue(any("reserved" in reason for reason in decision.reasons))


class UnknownFreeSpaceTests(unittest.TestCase):
    def test_unknown_free_bytes_fail_closed(self):
        from local_agent_dispatch.domain.world_state import (
            Host,
            MountState,
            Observation,
            ResourceValues,
        )

        mount = MountState(
            path="/data",
            writable=True,
            probed_path="/data",
            free_bytes=None,
            free_inodes=None,
            values=ResourceValues(units="bytes"),
            observation=Observation(
                kind="mount",
                source="statvfs",
                observed_at="2026-08-12T11:30:00+00:00",
                ttl_seconds=1800,
            ),
        )
        host = Host(host_id="h", name="h", mounts=(mount,))
        decision = evaluate_placement(
            host, "/data/EXAMPLE_003", PathRequirements(required_bytes=1024), now=NOW
        )
        self.assertEqual("unknown", decision.verdict)
        self.assertTrue(any("free bytes are unknown" in reason for reason in decision.reasons))


class RouteSeparationTests(unittest.TestCase):
    def test_bulk_data_route_missing_reports_unknown(self):
        snapshot, _ = load_scenario("unknown-route")
        self.assertEqual("direct", snapshot.route_status("control"))
        self.assertEqual("relay", snapshot.route_status("artifact"))
        self.assertEqual("direct", snapshot.route_status("execution"))
        self.assertEqual("unknown", snapshot.route_status("bulk_data"))
        self.assertEqual("unknown", snapshot.route_status("workload"))
        self.assertIsNone(snapshot.route("bulk_data"))

    def test_execution_and_workload_hosts_stay_separate(self):
        snapshot, _ = load_scenario("unknown-route")
        local = snapshot.host("host-local")
        server = snapshot.host("host-server")
        self.assertTrue(local.execution_host)
        self.assertFalse(local.workload_host)
        self.assertFalse(server.execution_host)
        self.assertTrue(server.workload_host)

    def test_direct_route_requires_verification_evidence(self):
        from local_agent_dispatch.domain.world_state import RouteRecord

        with self.assertRaises(ValueError):
            RouteRecord.from_dict({"kind": "bulk_data", "status": "direct"})
        with self.assertRaises(ValueError):
            RouteRecord.from_dict(
                {
                    "kind": "bulk_data",
                    "status": "direct",
                    "verified_at": "2026-08-12T12:00:00+00:00",
                }
            )


class ProbeParserTests(unittest.TestCase):
    MOUNTINFO = """\
36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
37 36 0:25 / /data rw,noatime - xfs /dev/nvme0n1p3 rw
38 36 0:27 / /srv\\040data rw - nfs4 nfs-share ro
"""

    def test_parse_mountinfo_lists_mounts_without_fabricated_capacity(self):
        mounts = parse_mountinfo(self.MOUNTINFO)
        by_path = {m.path: m for m in mounts}
        self.assertEqual(("/mnt2", "/data", "/srv data"), tuple(m.path for m in mounts))
        self.assertEqual("ext3", by_path["/mnt2"].fs_type)
        self.assertEqual(("xfs", "nfs4"), (by_path["/data"].fs_type, by_path["/srv data"].fs_type))
        for mount in mounts:
            self.assertIsNone(mount.probed_path)
            self.assertIsNone(mount.free_bytes)
            self.assertIsNone(mount.observation)

    def test_statvfs_evidence_attaches_exact_path_probe(self):
        mounts = apply_statvfs(
            parse_mountinfo(self.MOUNTINFO),
            "/data",
            f_frsize=4096,
            f_blocks=262144000,
            f_bfree=210000000,
            f_bavail=200000000,
            f_files=10000000,
            f_ffree=9000000,
            f_favail=9000000,
            writable=True,
            observed_at="2026-08-12T11:30:00+00:00",
            source="statvfs(/data)",
            ttl_seconds=1800,
        )
        data = {m.path: m for m in mounts}["/data"]
        self.assertTrue(data.is_probed())
        self.assertEqual(200000000 * 4096, data.free_bytes)
        self.assertEqual(262144000 * 4096, data.values.capacity)
        self.assertEqual(9000000, data.free_inodes)
        self.assertIsNotNone(data.observation)
        self.assertFalse(data.observation.is_stale(NOW))

    def test_resolve_mount_rejects_root_evidence_for_unprobed_mount(self):
        snapshot, _ = load_scenario("root-only-probe")
        host = snapshot.host("host-root-only")
        resolution = resolve_mount("/data/EXAMPLE_001/x", host.mounts)
        self.assertFalse(resolution.probed)
        self.assertTrue(resolution.covering_prefix)
        self.assertIsNotNone(resolution.reason)
        exact = resolve_mount("/", host.mounts)
        self.assertTrue(exact.probed)
        self.assertFalse(exact.covering_prefix)
        missing = resolve_mount("/gone", host.mounts)
        self.assertIsNone(missing.mount)
        self.assertFalse(missing.probed)

    def test_nvidia_smi_csv_parsing_preserves_unknowns(self):
        gpus = parse_nvidia_gpu_csv(
            "0, NVIDIA GeForce RTX 4090, 24564 MiB, 8000 MiB, 16564 MiB\n"
            "1, NVIDIA A100, 81920 MiB, 70000 MiB, 11920 MiB\n",
            observed_at=NOW,
        )
        self.assertEqual(2, len(gpus))
        self.assertEqual(24564.0, gpus[0].vram.capacity)
        self.assertEqual(8000.0, gpus[0].vram.available_now)
        self.assertEqual(16564.0, gpus[0].vram.used)
        processes = parse_nvidia_apps_csv(
            "1111, 5000 MiB, python3\n2222, 2000 MiB, train.py\n"
        )
        self.assertEqual(((1111, 5000), (2222, 2000)), tuple((p.pid, p.vram_mib) for p in processes))
        missing = parse_nvidia_gpu_csv("2, GPU Model, 4096 MiB, - , - \n", observed_at=NOW)
        self.assertIsNone(missing[0].vram.available_now)
        self.assertIsNone(missing[0].vram.used)

    def test_cgroup_v2_memory_parsing(self):
        ram = parse_cgroup_v2_memory(
            "memory.max 42949672960\nmemory.current 12884901888\n"
        )
        self.assertEqual(42949672960, ram.cgroup_limit_bytes)
        self.assertEqual(12884901888, ram.cgroup_current_bytes)
        unlimited = parse_cgroup_v2_memory("memory.max max\nmemory.current 1\n")
        self.assertIsNone(unlimited.cgroup_limit_bytes)
        self.assertEqual(1, unlimited.cgroup_current_bytes)


if __name__ == "__main__":
    unittest.main()
