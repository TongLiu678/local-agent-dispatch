from __future__ import annotations

import importlib.util
import pathlib
import tempfile
import time
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "sqlite_store_resource_admission",
    ROOT / "scripts" / "sqlite_store.py",
)
assert SPEC and SPEC.loader
STORE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STORE)
ADMISSION_SPEC = importlib.util.spec_from_file_location(
    "resource_admission_under_test",
    ROOT / "scripts" / "resource_admission.py",
)
assert ADMISSION_SPEC and ADMISSION_SPEC.loader
ADMISSION = importlib.util.module_from_spec(ADMISSION_SPEC)
ADMISSION_SPEC.loader.exec_module(ADMISSION)


class ResourceAdmissionTests(unittest.TestCase):
    def test_sqlite_storage_admission_blocks_known_shared_mount(self) -> None:
        mountinfo = (
            "36 25 0:42 / /data rw,relatime - nfs4 server:/export "
            "rw,vers=4\n"
        )
        report = ADMISSION.check_sqlite_storage(
            "/data/EXAMPLE_001/dispatch.sqlite3", mountinfo_text=mountinfo
        )
        self.assertFalse(report["allowed"])
        self.assertEqual("shared", report["locality"])
        self.assertIn("sqlite:shared_filesystem:nfs4", report["reasons"])

    def test_sqlite_storage_admission_accepts_known_local_mount(self) -> None:
        mountinfo = "36 25 0:42 / /data rw,relatime - xfs /dev/nvme0n1 rw\n"
        # Injected Linux evidence owns path semantics even on a Windows host.
        with mock.patch.object(ADMISSION.sys, "platform", "win32"):
            report = ADMISSION.check_sqlite_storage(
                "/data/EXAMPLE_001/dispatch.sqlite3", mountinfo_text=mountinfo
            )
        self.assertTrue(report["allowed"])
        self.assertEqual("local_candidate", report["locality"])
        self.assertEqual("linux", report["mount"]["platform"])

    def test_sqlite_storage_admission_matches_root_mount(self) -> None:
        mountinfo = "21 1 8:2 / / rw,relatime - ext4 /dev/sda2 rw\n"
        report = ADMISSION.check_sqlite_storage(
            "/tmp/dispatch.sqlite3", mountinfo_text=mountinfo
        )
        self.assertTrue(report["allowed"])
        self.assertEqual("/", report["mount"]["mount_path"])
        self.assertEqual("local_candidate", report["locality"])

    def test_sqlite_storage_unknown_fuse_type_fails_closed(self) -> None:
        mountinfo = (
            "36 25 0:42 / /data rw,relatime - fuse.rclone remote: rw\n"
        )
        report = ADMISSION.check_sqlite_storage(
            "/data/EXAMPLE_002", mountinfo_text=mountinfo
        )
        self.assertFalse(report["allowed"])
        self.assertEqual("unknown", report["locality"])
        self.assertIn("sqlite:filesystem_locality_unknown", report["reasons"])

    def test_sqlite_storage_blocks_ephemeral_tmpfs(self) -> None:
        mountinfo = "36 25 0:42 / /volatile rw,relatime - tmpfs tmpfs rw\n"
        report = ADMISSION.check_sqlite_storage(
            "/volatile/dispatch.sqlite3", mountinfo_text=mountinfo
        )
        self.assertFalse(report["allowed"])
        self.assertEqual("ephemeral_local", report["locality"])
        self.assertIn("sqlite:ephemeral_filesystem:tmpfs", report["reasons"])

    def test_sqlite_storage_temp_path_is_not_claimed_persistent(self) -> None:
        mountinfo = "21 1 8:2 / / rw,relatime - ext4 /dev/sda2 rw\n"
        report = ADMISSION.check_sqlite_storage(
            "/tmp/dispatch.sqlite3",
            mountinfo_text=mountinfo,
        )
        self.assertTrue(report["allowed"])
        self.assertTrue(report["known_local"])
        self.assertFalse(report["persistent"])

    def test_sqlite_storage_admission_accepts_darwin_apfs_local_mount(self) -> None:
        mounts = (
            "/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)\n"
            "/dev/disk3s5 on /System/Volumes/Data (apfs, local, journaled)\n"
        )
        with mock.patch.object(ADMISSION.sys, "platform", "win32"):
            report = ADMISSION.check_sqlite_storage(
                "/project/dispatch.sqlite3", darwin_mount_text=mounts
            )
        self.assertTrue(report["allowed"])
        self.assertEqual("local_candidate", report["locality"])
        self.assertEqual("apfs", report["mount"]["fs_type"])
        self.assertTrue(report["mount"]["local_hint"])
        self.assertEqual("darwin", report["mount"]["platform"])

    def test_sqlite_storage_admission_blocks_darwin_smb_mount(self) -> None:
        mounts = (
            "/dev/disk3s1s1 on / (apfs, local, journaled)\n"
            "//user@example/share on /Volumes/team (smbfs, nodev, nosuid)\n"
        )
        with mock.patch.object(ADMISSION.sys, "platform", "darwin"):
            report = ADMISSION.check_sqlite_storage(
                "/Volumes/team/dispatch.sqlite3", darwin_mount_text=mounts
            )
        self.assertFalse(report["allowed"])
        self.assertEqual("shared", report["locality"])
        self.assertIn("sqlite:shared_filesystem:smbfs", report["reasons"])

    def test_sqlite_storage_darwin_apfs_without_local_evidence_fails_closed(self) -> None:
        mounts = (
            "/dev/disk3s1s1 on / (apfs, local, journaled)\n"
            "remote on /Volumes/unknown (apfs, nodev)\n"
        )
        with mock.patch.object(ADMISSION.sys, "platform", "darwin"):
            report = ADMISSION.check_sqlite_storage(
                "/Volumes/unknown/dispatch.sqlite3", darwin_mount_text=mounts
            )
        self.assertFalse(report["allowed"])
        self.assertEqual("unknown", report["locality"])
        self.assertIn("sqlite:filesystem_locality_unknown", report["reasons"])

    def test_sqlite_storage_unknown_is_strict_on_non_linux_platforms(self) -> None:
        with mock.patch.object(ADMISSION.sys, "platform", "darwin"), mock.patch.object(
            ADMISSION.subprocess, "run", side_effect=OSError("mount unavailable")
        ):
            report = ADMISSION.check_sqlite_storage("/tmp/dispatch.sqlite3")
        self.assertFalse(report["allowed"])
        self.assertIn("sqlite:filesystem_locality_unknown", report["reasons"])

    def test_sqlite_storage_accepts_windows_fixed_volume(self) -> None:
        evidence = {
            "mount_path": "C:\\\\",
            "fs_type": "ntfs",
            "source": "C:\\\\",
            "drive_type": 3,
            "local_hint": True,
            "shared_hint": False,
            "format": "windows_volume",
        }
        report = ADMISSION.check_sqlite_storage(
            "C:\\work\\dispatch.sqlite3", windows_volume_info=evidence
        )
        self.assertTrue(report["allowed"])
        self.assertEqual("local_candidate", report["locality"])
        self.assertEqual(3, report["mount"]["drive_type"])
        self.assertEqual("win32", report["mount"]["platform"])

    def test_explicit_platform_conflicting_with_evidence_fails_closed(self) -> None:
        evidence = {
            "mount_path": "C:\\\\",
            "fs_type": "ntfs",
            "source": "C:\\\\",
            "drive_type": 3,
            "local_hint": True,
            "shared_hint": False,
            "format": "windows_volume",
        }
        report = ADMISSION.check_sqlite_storage(
            "C:\\work\\dispatch.sqlite3",
            platform="linux",
            windows_volume_info=evidence,
        )
        self.assertFalse(report["allowed"])
        self.assertEqual("unknown", report["locality"])
        self.assertIn("sqlite:platform_evidence_conflict", report["reasons"])

    def test_sqlite_storage_blocks_windows_remote_volume(self) -> None:
        evidence = {
            "mount_path": "Z:\\\\",
            "fs_type": "ntfs",
            "source": "Z:\\\\",
            "drive_type": 4,
            "local_hint": False,
            "shared_hint": True,
            "format": "windows_volume",
        }
        with mock.patch.object(ADMISSION.sys, "platform", "win32"):
            report = ADMISSION.check_sqlite_storage(
                "Z:\\team\\dispatch.sqlite3", windows_volume_info=evidence
            )
        self.assertFalse(report["allowed"])
        self.assertEqual("shared", report["locality"])
        self.assertIn("sqlite:shared_filesystem:ntfs", report["reasons"])

    def test_sqlite_storage_windows_unknown_drive_fails_closed(self) -> None:
        evidence = {
            "mount_path": "Q:\\\\",
            "fs_type": "ntfs",
            "source": "Q:\\\\",
            "drive_type": 0,
            "local_hint": False,
            "shared_hint": False,
            "ephemeral_hint": False,
            "format": "windows_volume",
        }
        with mock.patch.object(ADMISSION.sys, "platform", "win32"):
            report = ADMISSION.check_sqlite_storage(
                "Q:\\unknown\\dispatch.sqlite3", windows_volume_info=evidence
            )
        self.assertFalse(report["allowed"])
        self.assertEqual("unknown", report["locality"])
        self.assertIn("sqlite:filesystem_locality_unknown", report["reasons"])

    def test_sqlite_storage_blocks_windows_ramdisk(self) -> None:
        evidence = {
            "mount_path": "R:\\\\",
            "fs_type": "refs",
            "source": "R:\\\\",
            "drive_type": 6,
            "local_hint": True,
            "shared_hint": False,
            "ephemeral_hint": True,
            "format": "windows_volume",
        }
        with mock.patch.object(ADMISSION.sys, "platform", "win32"):
            report = ADMISSION.check_sqlite_storage(
                "R:\\volatile\\dispatch.sqlite3", windows_volume_info=evidence
            )
        self.assertFalse(report["allowed"])
        self.assertEqual("ephemeral_local", report["locality"])
        self.assertIn("sqlite:ephemeral_filesystem:windows_ramdisk", report["reasons"])

    def test_windows_separator_variants_match_covering_volume(self) -> None:
        evidence = {
            "mount_path": "C:\\data",
            "fs_type": "ntfs",
            "source": "C:\\data",
            "drive_type": 3,
            "local_hint": True,
            "shared_hint": False,
            "format": "windows_volume",
        }
        with mock.patch.object(ADMISSION.sys, "platform", "win32"):
            report = ADMISSION.check_sqlite_storage(
                "c:/DATA/workspace/dispatch.sqlite3",
                windows_volume_info=evidence,
            )
        self.assertTrue(report["allowed"])
        self.assertEqual("local_candidate", report["locality"])
        self.assertEqual(r"c:\DATA\workspace\dispatch.sqlite3", report["path"])

    def test_windows_volume_evidence_for_other_drive_fails_closed(self) -> None:
        evidence = {
            "mount_path": "D:\\",
            "fs_type": "ntfs",
            "source": "D:\\",
            "drive_type": 3,
            "local_hint": True,
            "shared_hint": False,
            "format": "windows_volume",
        }
        with mock.patch.object(ADMISSION.sys, "platform", "win32"):
            report = ADMISSION.check_sqlite_storage(
                "C:\\work\\dispatch.sqlite3", windows_volume_info=evidence
            )
        self.assertFalse(report["allowed"])
        self.assertEqual("unknown", report["locality"])
        self.assertIn(
            "sqlite:windows_volume_does_not_cover_target", report["reasons"]
        )

    def test_windows_unc_path_is_explicitly_unknown(self) -> None:
        evidence = {
            "mount_path": r"\\server\share",
            "fs_type": "ntfs",
            "source": r"\\server\share",
            "drive_type": 4,
            "local_hint": False,
            "shared_hint": True,
            "format": "windows_volume",
        }
        with mock.patch.object(ADMISSION.sys, "platform", "win32"):
            report = ADMISSION.check_sqlite_storage(
                r"\\server\share\dispatch.sqlite3",
                windows_volume_info=evidence,
            )
        self.assertFalse(report["allowed"])
        self.assertEqual("unknown", report["locality"])
        self.assertIn("sqlite:unc_path_unsupported", report["reasons"])

    def test_filesystem_uses_disk_usage_when_statvfs_is_unavailable(self) -> None:
        usage = mock.Mock(total=10_000, free=6_000)
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(
            ADMISSION.os, "statvfs", None, create=True
        ), mock.patch.object(ADMISSION.shutil, "disk_usage", return_value=usage):
            row = ADMISSION._filesystem(pathlib.Path(tmp))
        self.assertEqual("complete", row["evidence"])
        self.assertEqual("disk_usage", row["source"])
        self.assertEqual(6_000, row["free_bytes"])
        self.assertEqual(10_000, row["total_bytes"])

    def test_missing_windows_disk_evidence_blocks_without_attribute_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(
            ADMISSION.os, "statvfs", None, create=True
        ), mock.patch.object(
            ADMISSION.shutil, "disk_usage", side_effect=OSError("unavailable")
        ):
            report = ADMISSION.check_local_launch(
                tmp,
                temporary_directory=tmp,
                minimum_free_bytes=1,
                label="windows_worker",
            )
        self.assertFalse(report["allowed"])
        self.assertEqual("block", report["decision"])
        self.assertTrue(
            any("filesystem_evidence_unknown" in reason for reason in report["reasons"])
        )

    def open_store(self, root: pathlib.Path):
        return STORE.SQLiteStore(root / "dispatch.sqlite3", timeout_seconds=5)

    def test_host_vector_admission_is_atomic_and_pool_slots_are_shared(self) -> None:
        """A second lane sees the first reservation before the capacity check."""
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            with self.open_store(root) as store:
                lease = store.acquire_controller_lease("controller", ttl_seconds=30)
                store.create_job("lane-1", {})
                store.create_job("lane-2", {})
                capacity = {
                    "host": {
                        "cpu_cores": 8,
                        "ram_gib": 8,
                        "gpu_count": 1,
                        "vram_gib": 16,
                        "new_disk_gib": 20,
                    },
                    "pool": {"slots": 1},
                    "host_id": "bjb2",
                    "pool_id": "opencode-go/deepseek-v4-flash",
                }
                request = {
                    "host_id": "bjb2",
                    "pool_id": "opencode-go/deepseek-v4-flash",
                    "cpu_cores": 4,
                    "ram_gib": 4,
                    "gpu_count": 1,
                    "vram_gib": 8,
                    "new_disk_gib": 10,
                }
                first = store.reserve_resources(
                    "lane-1", "controller", lease["fence_token"], request,
                    admission={"allowed": True, "capacity": capacity},
                )
                self.assertEqual("active", first["status"])
                self.assertTrue(first["admission"]["capacity_evidence_supplied"])
                self.assertNotIn("capacity", first["admission"])
                checks = first["admission"]["checks"]
                self.assertTrue(all(item["decision"] == "admit" for item in checks))
                with self.assertRaisesRegex(STORE.ReservationAdmissionError, "capacity_exceeded"):
                    store.reserve_resources(
                        "lane-2", "controller", lease["fence_token"], request,
                        capacity=capacity,
                    )
                self.assertEqual(1, len(store.list_reservations(statuses=("active",))))

    def test_release_frees_host_and_pool_capacity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            with self.open_store(root) as store:
                lease = store.acquire_controller_lease("controller", ttl_seconds=30)
                store.create_job("lane-1", {})
                store.create_job("lane-2", {})
                common = {"host_id": "westd", "pool_id": "fake.pool", "ram_gib": 2}
                cap = {"host": {"ram_gib": 2}, "pool": {"slots": 1}}
                store.reserve_resources(
                    "lane-1", "controller", lease["fence_token"], common, capacity=cap,
                )
                self.assertEqual(1, store.release_reservation("lane-1", "controller", lease["fence_token"]))
                second = store.reserve_resources(
                    "lane-2", "controller", lease["fence_token"], common, capacity=cap,
                )
                self.assertEqual("active", second["status"])
                self.assertEqual("lane-1", store.list_reservations()[0]["job_id"])
                self.assertEqual("released", store.list_reservations()[0]["status"])

    def test_expired_reservation_is_reaped_before_new_admission(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            with self.open_store(root) as store:
                lease = store.acquire_controller_lease("controller", ttl_seconds=30)
                store.create_job("lane-old", {})
                store.create_job("lane-new", {})
                request = {"host_id": "h", "pool_id": "p", "ram_gib": 2}
                cap = {"host": {"ram_gib": 2}, "pool": {"slots": 1}}
                store.reserve_resources(
                    "lane-old", "controller", lease["fence_token"], request,
                    capacity=cap, ttl_seconds=1,
                )
                time.sleep(1.15)
                replacement = store.reserve_resources(
                    "lane-new", "controller", lease["fence_token"], request,
                    capacity=cap, ttl_seconds=30,
                )
                self.assertEqual("active", replacement["status"])
                states = {row["job_id"]: row["status"] for row in store.list_reservations()}
                self.assertEqual("expired", states["lane-old"])
                self.assertEqual("active", states["lane-new"])

    def test_stale_fence_cannot_heartbeat_or_release_reservation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            with self.open_store(root) as store:
                old = store.acquire_controller_lease("old", ttl_seconds=1)
                store.create_job("lane", {})
                store.reserve_resources(
                    "lane", "old", old["fence_token"], {"host_id": "h", "ram_gib": 1},
                    capacity={"host": {"ram_gib": 2}}, ttl_seconds=30,
                )
                time.sleep(1.15)
                new = store.acquire_controller_lease("new", ttl_seconds=30)
                with self.assertRaises(STORE.FencingError):
                    store.heartbeat_reservation("lane", "old", old["fence_token"])
                with self.assertRaises(STORE.FencingError):
                    store.release_reservation("lane", "old", old["fence_token"])
                # A new controller fence cannot release another owner's
                # reservation by accident; the durable row remains for
                # explicit recovery/reconciliation.
                self.assertEqual(
                    0,
                    store.release_reservation("lane", "new", new["fence_token"]),
                )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
