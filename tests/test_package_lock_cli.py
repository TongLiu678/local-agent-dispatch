"""Provider-free CLI coverage for canonical package lock workflows."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import sys
import tempfile
from pathlib import Path
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from local_agent_dispatch import cli  # noqa: E402
from local_agent_dispatch.packages import (  # noqa: E402
    ArtifactRecord,
    Dependency,
    ExtensionManifest,
    PackageStore,
    current_platform,
    load_lock_json,
)


class PackageLockCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.catalog = self.root / "catalog"
        self.catalog.mkdir()
        self.os_name, self.arch = current_platform()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _artifact(path: str, data: bytes) -> ArtifactRecord:
        return ArtifactRecord(
            path=path,
            sha256="sha256:" + hashlib.sha256(data).hexdigest(),
            size=len(data),
        )

    def _manifest(
        self,
        name: str,
        version: str,
        *,
        dependencies: tuple[Dependency, ...] = (),
        data: bytes | None = None,
    ) -> tuple[ExtensionManifest, bytes]:
        contents = data if data is not None else f"{name}-{version}\n".encode()
        return (
            ExtensionManifest(
                name=name,
                version=version,
                kind="agent_harness",
                entrypoint_type="none",
                entrypoint=None,
                dependencies=dependencies,
                artifacts=(self._artifact("payload.txt", contents),),
            ),
            contents,
        )

    def _catalog_entry(
        self, manifest: ExtensionManifest, *, directory: str | None = None
    ) -> Path:
        entry = self.catalog / (directory or manifest.coordinate.replace("@", "-"))
        entry.mkdir()
        (entry / "lad-package.json").write_text(
            json.dumps(manifest.to_dict(), sort_keys=True), encoding="utf-8"
        )
        return entry

    def _requirements(
        self,
        requirements: list[dict[str, object]],
        **overrides: object,
    ) -> Path:
        payload: dict[str, object] = {
            "schema_version": 1,
            "platform": {"os": self.os_name, "arch": self.arch},
            "include_optional": False,
            "requirements": requirements,
        }
        payload.update(overrides)
        path = self.root / "requirements.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def _run(self, *arguments: str) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli.main(list(arguments))
        return code, stdout.getvalue(), stderr.getvalue()

    def test_resolve_stdout_is_one_canonical_reusable_lock(self) -> None:
        leaf, _ = self._manifest("leaf", "1.0.0")
        app, _ = self._manifest(
            "application",
            "2.0.0",
            dependencies=(Dependency("leaf", ">=1.0.0,<2.0.0"),),
        )
        self._catalog_entry(app)
        self._catalog_entry(leaf)
        requirements = self._requirements(
            [{"name": "application", "constraint": "==2.0.0", "optional": False}]
        )

        with mock.patch.object(
            cli.subprocess, "run", side_effect=AssertionError("must stay provider-free")
        ):
            code, stdout, stderr = self._run(
                "package",
                "resolve",
                "--catalog",
                str(self.catalog),
                "--requirements",
                str(requirements),
                "--output",
                "-",
            )

        self.assertEqual(0, code)
        lock = load_lock_json(stdout)
        self.assertEqual(lock.to_json() + "\n", stdout)
        self.assertEqual(["application", "leaf"], [row.name for row in lock.packages])
        self.assertEqual("", stderr)

    def test_file_output_is_atomic_and_emits_write_evidence(self) -> None:
        manifest, _ = self._manifest("portable", "1.0.0")
        self._catalog_entry(manifest)
        requirements = self._requirements(
            [{"name": "portable", "constraint": "*", "optional": False}]
        )
        output = self.root / "lad.lock.json"
        output.write_text("old", encoding="utf-8")

        code, stdout, stderr = self._run(
            "package",
            "resolve",
            "--catalog",
            str(self.catalog),
            "--requirements",
            str(requirements),
            "--output",
            str(output),
        )

        receipt = json.loads(stdout)
        lock = load_lock_json(output.read_text(encoding="utf-8"))
        self.assertEqual(0, code)
        self.assertTrue(receipt["filesystem_written"])
        self.assertEqual(lock.digest, receipt["lock_digest"])
        self.assertEqual(lock.to_json(), output.read_text(encoding="utf-8"))
        self.assertEqual([], list(self.root.glob(".lad-package-lock-*.tmp")))
        self.assertEqual("", stderr)

    def test_atomic_replace_failure_preserves_existing_output(self) -> None:
        manifest, _ = self._manifest("portable", "1.0.0")
        self._catalog_entry(manifest)
        requirements = self._requirements(
            [{"name": "portable", "constraint": "*", "optional": False}]
        )
        output = self.root / "lad.lock.json"
        output.write_text("keep-me", encoding="utf-8")

        with mock.patch.object(cli.os, "replace", side_effect=OSError("synthetic")):
            code, stdout, _ = self._run(
                "package", "resolve",
                "--catalog", str(self.catalog),
                "--requirements", str(requirements),
                "--output", str(output),
            )

        self.assertEqual(2, code)
        self.assertFalse(json.loads(stdout)["ok"])
        self.assertEqual("keep-me", output.read_text(encoding="utf-8"))
        self.assertEqual([], list(self.root.glob(".lad-package-lock-*.tmp")))

    def test_verify_lock_reproduces_catalog_without_writing(self) -> None:
        manifest, _ = self._manifest("verified", "1.0.0")
        self._catalog_entry(manifest)
        requirements = self._requirements(
            [{"name": "verified", "constraint": "==1.0.0", "optional": False}]
        )
        lock_path = self.root / "lad.lock.json"
        self._run(
            "package", "resolve",
            "--catalog", str(self.catalog),
            "--requirements", str(requirements),
            "--output", str(lock_path),
        )

        code, stdout, stderr = self._run(
            "package", "verify-lock",
            "--catalog", str(self.catalog),
            "--lock", str(lock_path),
        )

        payload = json.loads(stdout)
        self.assertEqual(0, code)
        self.assertEqual("package.verify-lock", payload["command"])
        self.assertFalse(payload["filesystem_written"])
        self.assertTrue(payload["verification"]["catalog_verified"])
        self.assertFalse(payload["verification"]["store_verified"])
        self.assertFalse(payload["entrypoint_executed"])
        self.assertFalse(payload["network_accessed"])
        self.assertEqual("", stderr)

    def test_verify_lock_can_hash_existing_store_artifacts(self) -> None:
        manifest, contents = self._manifest("installed", "1.0.0")
        entry = self._catalog_entry(manifest)
        (entry / "payload.txt").write_bytes(contents)
        store_path = self.root / "store"
        PackageStore(store_path).install(entry)
        requirements = self._requirements(
            [{"name": "installed", "constraint": "*", "optional": False}]
        )
        lock_path = self.root / "lad.lock.json"
        self._run(
            "package", "resolve",
            "--catalog", str(self.catalog),
            "--requirements", str(requirements),
            "--output", str(lock_path),
        )

        code, stdout, _ = self._run(
            "package", "verify-lock",
            "--catalog", str(self.catalog),
            "--lock", str(lock_path),
            "--store", str(store_path),
        )

        payload = json.loads(stdout)
        self.assertEqual(0, code)
        self.assertTrue(payload["verification"]["store_verified"])
        self.assertTrue(payload["verification"]["artifacts_verified"])
        self.assertFalse(payload["verification"]["entrypoint_executed"])

    def test_requirements_duplicate_unknown_and_body_are_not_reflected(self) -> None:
        manifest, _ = self._manifest("safe", "1.0.0")
        self._catalog_entry(manifest)
        sensitive_marker = "DO_NOT_ECHO_SENSITIVE_BODY"
        requirements = self.root / "bad-requirements.json"
        requirements.write_text(
            '{"schema_version":1,"schema_version":1,"platform":'
            f'{{"os":"{self.os_name}","arch":"{self.arch}"}},'
            f'"include_optional":false,"requirements":[],"body":"{sensitive_marker}"}}',
            encoding="utf-8",
        )

        code, stdout, stderr = self._run(
            "package", "resolve",
            "--catalog", str(self.catalog),
            "--requirements", str(requirements),
            "--output", "-",
        )

        payload = json.loads(stdout)
        self.assertEqual(2, code)
        self.assertFalse(payload["ok"])
        self.assertIn("duplicate", payload["error"]["message"])
        self.assertNotIn(sensitive_marker, stdout)
        self.assertEqual("", stderr)

    def test_catalog_rejects_duplicate_coordinates(self) -> None:
        manifest, _ = self._manifest("duplicate", "1.0.0")
        self._catalog_entry(manifest, directory="first")
        self._catalog_entry(manifest, directory="second")
        requirements = self._requirements(
            [{"name": "duplicate", "constraint": "*", "optional": False}]
        )

        code, stdout, _ = self._run(
            "package", "resolve",
            "--catalog", str(self.catalog),
            "--requirements", str(requirements),
            "--output", "-",
        )

        self.assertEqual(2, code)
        self.assertIn("duplicate package coordinate", json.loads(stdout)["error"]["message"])

    def test_catalog_rejects_symlink_entry(self) -> None:
        target = self.root / "outside"
        target.mkdir()
        manifest, _ = self._manifest("linked", "1.0.0")
        (target / "lad-package.json").write_text(
            json.dumps(manifest.to_dict()), encoding="utf-8"
        )
        try:
            os.symlink(target, self.catalog / "linked")
        except (OSError, NotImplementedError):
            self.skipTest("symlinks are unavailable")
        requirements = self._requirements(
            [{"name": "linked", "constraint": "*", "optional": False}]
        )

        code, stdout, _ = self._run(
            "package", "resolve",
            "--catalog", str(self.catalog),
            "--requirements", str(requirements),
            "--output", "-",
        )

        self.assertEqual(2, code)
        self.assertIn("non-symlink directories", json.loads(stdout)["error"]["message"])


if __name__ == "__main__":
    unittest.main()
