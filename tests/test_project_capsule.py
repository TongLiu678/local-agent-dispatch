"""Provider-free tests for project-scoped capsule admission."""

from __future__ import annotations

import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.project_capsule import (  # noqa: E402
    CapsuleError,
    build_capsule,
    select_controller_db_path,
    validate_capsule,
    validate_noninterference,
    write_scope_conflicts,
)


def _digest(letter: str) -> str:
    return "sha256:" + letter * 64


def _capsule(project: str = "lad", workspace: str = "lad-ws-1", **overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": 1,
        "project_id": project,
        "workspace_id": workspace,
        "capsule_generation": 1,
        "capsule_spec_digest": _digest("a"),
        "source_tree_digest": _digest("b"),
        "controller_db_path": "/var/tmp/lad-controller/dispatch.sqlite3",
        "controller_db_mount_digest": _digest("c"),
        "data_root": "/data/lad/data",
        "artifact_root": "/data/lad/artifacts",
        "tmp_root": "/tmp/lad-run",
        "log_root": "/srv/lad/logs",
        "scheduler_backend": "torque-pbs",
        "write_scopes": ["src/lane-a"],
        "resource_limits": {"ram_gib": 8, "cpu_cores": 2},
        "status": "bound",
    }
    value.update(overrides)
    return value


def _mounts(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "controller_db_path": {"allowed": True, "locality": "known-local", "persistent": True},
        "tmp_root": {"allowed": True, "locality": "known-local"},
        "data_root": {"allowed": True, "shared": False},
        "artifact_root": {"allowed": True, "shared": False},
        "log_root": {"allowed": True, "shared": False},
    }
    value.update(overrides)
    return value


class ProjectCapsuleTests(unittest.TestCase):
    def test_identity_builder_is_unbound_and_does_not_fabricate_paths(self) -> None:
        capsule = build_capsule(project_id="lad", workspace_id="lad-ws-1", generation=1)
        self.assertEqual("unbound", capsule["status"])
        self.assertNotIn("controller_db_path", capsule)
        self.assertTrue(str(capsule["capsule_spec_digest"]).startswith("sha256:"))

    def test_capsule_rejects_shared_sqlite_and_overlapping_write_scopes(self) -> None:
        capsule = _capsule(write_scopes=["src", "src/scripts"])
        with self.assertRaises(CapsuleError):
            validate_capsule(capsule, mount_report={"controller_db_path": {"shared": True}})

    def test_known_local_controller_and_node_tmp_are_admitted(self) -> None:
        report = validate_capsule(_capsule(), mount_report=_mounts())
        self.assertTrue(report["valid"], report)
        self.assertEqual("lad", report["capsule"]["project_id"])

    def test_project_scoped_shared_data_mounts_are_admitted(self) -> None:
        mounts = _mounts(
            data_root={
                "allowed": True,
                "shared": True,
                "project_scoped": True,
                "project_id": "lad",
            },
            artifact_root={
                "allowed": True,
                "shared": True,
                "project_scoped": True,
                "project_id": "lad",
            },
            log_root={
                "allowed": True,
                "shared": True,
                "project_scoped": True,
                "project_id": "lad",
            },
        )
        report = validate_capsule(_capsule(), mount_report=mounts)
        self.assertTrue(report["valid"], report)

    def test_shared_data_mount_requires_matching_project_scope(self) -> None:
        for row in (
            {"allowed": True, "shared": True},
            {"allowed": True, "shared": True, "project_scoped": True, "project_id": "other"},
        ):
            with self.assertRaisesRegex(CapsuleError, "data_root shared mount lacks project scope"):
                validate_capsule(
                    _capsule(),
                    mount_report=_mounts(data_root=row),
                )

    def test_missing_data_mount_evidence_fails_closed(self) -> None:
        mounts = _mounts()
        del mounts["artifact_root"]
        with self.assertRaisesRegex(CapsuleError, "artifact_root mount evidence unknown"):
            validate_capsule(_capsule(), mount_report=mounts)

    def test_scope_conflicts_are_path_segment_aware(self) -> None:
        self.assertEqual([("src", "src/scripts")], write_scope_conflicts(["src/scripts", "src"]))
        self.assertEqual([], write_scope_conflicts(["src-a", "src-b"]))

    def test_noninterference_reports_shared_paths_or_write_scopes(self) -> None:
        left = _capsule()
        right = _capsule(project="other", workspace="other-ws", write_scopes=["src/lane-a/review"])
        report = validate_noninterference(left, right)
        self.assertFalse(report["valid"])
        self.assertTrue(report["conflicts"])
        right["artifact_root"] = "/data/other/artifacts"
        right["data_root"] = "/data/other/data"
        right["log_root"] = "/srv/other/logs"
        self.assertFalse(validate_noninterference(left, right)["valid"])

    def test_controller_selection_fails_closed_without_persistent_local_path(self) -> None:
        blocked = select_controller_db_path([
            {"path": "/data/lad/dispatch.sqlite3", "locality": "shared", "persistent": True},
            {"path": "/tmp/lad/dispatch.sqlite3", "locality": "known-local", "persistent": False},
        ])
        self.assertFalse(blocked["valid"])
        self.assertEqual("controller_storage_unavailable", blocked["error"])
        selected = select_controller_db_path([
            {"path": "/var/tmp/lad/dispatch.sqlite3", "locality": "known-local", "persistent": True, "priority": 2},
            {"path": "/tmp/lad/dispatch.sqlite3", "locality": "known-local", "persistent": True, "priority": 1},
        ])
        self.assertTrue(selected["valid"])
        self.assertEqual(str(pathlib.Path("/tmp/lad/dispatch.sqlite3").resolve()), selected["path"])

    def test_capsule_rejects_sensitive_runtime_and_default_cwd(self) -> None:
        with self.assertRaises(CapsuleError):
            validate_capsule(_capsule(runtime={"image_tag": "latest"}), mount_report=_mounts())
        with self.assertRaises(CapsuleError):
            validate_capsule(_capsule(metadata={"cwd": "."}), mount_report=_mounts())


if __name__ == "__main__":
    unittest.main()
