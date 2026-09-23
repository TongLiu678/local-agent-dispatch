"""Provider-free CLI coverage for the local LAD package store."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import sys
import tempfile
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from local_agent_dispatch import cli  # noqa: E402
from local_agent_dispatch.packages import ArtifactRecord, ExtensionManifest  # noqa: E402


def _artifact(path: str, data: bytes) -> ArtifactRecord:
    return ArtifactRecord(
        path=path,
        sha256="sha256:" + hashlib.sha256(data).hexdigest(),
        size=len(data),
    )


class PackageCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.sources = self.root / "sources"
        self.sources.mkdir()
        self.store = self.root / "store"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _source(
        self,
        name: str,
        version: str,
        *,
        data: bytes | None = None,
        entrypoint: bool = False,
        manifest_name: str = "lad-package.json",
    ) -> tuple[Path, ExtensionManifest]:
        payload = data if data is not None else f"{name}-{version}\n".encode()
        artifact_path = "adapter.py" if entrypoint else "payload.txt"
        manifest = ExtensionManifest(
            name=name,
            version=version,
            kind="agent_harness",
            entrypoint_type="python" if entrypoint else "none",
            entrypoint="adapter:run" if entrypoint else None,
            artifacts=(_artifact(artifact_path, payload),),
        )
        source = self.sources / f"{name}-{version}"
        source.mkdir()
        (source / artifact_path).write_bytes(payload)
        (source / manifest_name).write_text(
            json.dumps(manifest.to_dict(), sort_keys=True), encoding="utf-8"
        )
        return source, manifest

    def _run(self, *args: str) -> tuple[int, dict[str, object], str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli.main(list(args))
        return code, json.loads(stdout.getvalue()), stderr.getvalue()

    def test_inspect_validates_manifest_without_running_entrypoint(self) -> None:
        marker = self.root / "must-not-run"
        code = (
            "from pathlib import Path\n"
            f"Path({str(marker)!r}).write_text('ran')\n"
        ).encode()
        source, manifest = self._source(
            "inspectable", "1.0.0", data=code, entrypoint=True
        )

        returncode, payload, stderr = self._run("package", "inspect", str(source))

        self.assertEqual(0, returncode)
        self.assertEqual("package.inspect", payload["command"])
        self.assertEqual("inspectable@1.0.0", payload["coordinate"])
        self.assertEqual(manifest.digest, payload["manifest_digest"])
        self.assertFalse(payload["entrypoint_executed"])
        self.assertFalse(payload["network_accessed"])
        self.assertFalse(payload["verification"]["artifacts_verified"])
        self.assertFalse(marker.exists())
        self.assertEqual("", stderr)

    def test_install_list_and_activate_exact_version(self) -> None:
        source_v1, _ = self._source("switchable", "1.0.0")
        source_v2, _ = self._source("switchable", "2.0.0")

        first_code, first, _ = self._run(
            "package", "install", str(source_v1), "--store", str(self.store)
        )
        second_code, second, _ = self._run(
            "package",
            "install",
            str(source_v2),
            "--store",
            str(self.store),
            "--no-activate",
        )
        list_code, listed, _ = self._run(
            "package", "list", "--store", str(self.store)
        )
        activate_code, activated, _ = self._run(
            "package",
            "activate",
            "switchable",
            "2.0.0",
            "--store",
            str(self.store),
        )

        self.assertEqual((0, 0, 0, 0), (first_code, second_code, list_code, activate_code))
        self.assertTrue(first["receipt"]["activated"])
        self.assertFalse(second["receipt"]["activated"])
        self.assertEqual(
            [{"name": "switchable", "versions": ["2.0.0", "1.0.0"], "active_version": "1.0.0"}],
            listed["packages"],
        )
        self.assertEqual({"switchable": "2.0.0"}, activated["active"])
        self.assertEqual(2, activated["active_generation"])

    def test_rollback_creates_new_generation_from_exact_target(self) -> None:
        source_v1, _ = self._source("rollbackable", "1.0.0")
        source_v2, _ = self._source("rollbackable", "2.0.0")
        self._run("package", "install", str(source_v1), "--store", str(self.store))
        self._run("package", "install", str(source_v2), "--store", str(self.store))

        returncode, payload, _ = self._run(
            "package",
            "rollback",
            "--store",
            str(self.store),
            "--generation",
            "1",
        )

        self.assertEqual(0, returncode)
        self.assertEqual({"rollbackable": "1.0.0"}, payload["active"])
        self.assertEqual(3, payload["active_generation"])
        self.assertEqual(1, payload["requested_generation"])

    def test_uninstall_removes_only_inactive_unreferenced_version(self) -> None:
        active_source, _ = self._source("removable", "1.0.0")
        inactive_source, _ = self._source("removable", "2.0.0")
        self._run(
            "package", "install", str(active_source), "--store", str(self.store)
        )
        self._run(
            "package",
            "install",
            str(inactive_source),
            "--store",
            str(self.store),
            "--no-activate",
        )

        rejected_code, rejected, _ = self._run(
            "package",
            "uninstall",
            "removable",
            "1.0.0",
            "--store",
            str(self.store),
        )
        removed_code, removed, _ = self._run(
            "package",
            "uninstall",
            "removable",
            "2.0.0",
            "--store",
            str(self.store),
        )

        self.assertEqual(2, rejected_code)
        self.assertFalse(rejected["ok"])
        self.assertIn("active package", rejected["error"]["message"])
        self.assertEqual(0, removed_code)
        self.assertTrue(removed["removed"])
        self.assertEqual(["1.0.0"], removed["remaining_versions"])

    def test_install_verifies_artifacts_and_never_runs_python_entrypoint(self) -> None:
        marker = self.root / "entrypoint-ran"
        code = (
            "from pathlib import Path\n"
            f"Path({str(marker)!r}).write_text('ran')\n"
        ).encode()
        source, _ = self._source(
            "safe-install", "1.0.0", data=code, entrypoint=True
        )

        returncode, payload, _ = self._run(
            "package", "install", str(source), "--store", str(self.store)
        )

        self.assertEqual(0, returncode)
        self.assertTrue(payload["ok"])
        self.assertFalse(payload["entrypoint_executed"])
        self.assertFalse(marker.exists())

    def test_bad_artifact_hash_fails_closed_with_json_error(self) -> None:
        source, _ = self._source("tampered", "1.0.0")
        (source / "payload.txt").write_bytes(b"changed")

        returncode, payload, stderr = self._run(
            "package", "install", str(source), "--store", str(self.store)
        )

        self.assertEqual(2, returncode)
        self.assertFalse(payload["ok"])
        self.assertEqual("package.install", payload["command"])
        self.assertEqual("InstallError", payload["error"]["type"])
        self.assertIn("mismatch", payload["error"]["message"])
        self.assertFalse(payload["network_accessed"])
        self.assertEqual("", stderr)
        self.assertFalse((self.store / "packages" / "tampered" / "1.0.0").exists())

    def test_remote_source_is_rejected_before_store_creation(self) -> None:
        returncode, payload, _ = self._run(
            "package",
            "install",
            "https://example.invalid/package",
            "--store",
            str(self.store),
        )

        self.assertEqual(2, returncode)
        self.assertFalse(payload["ok"])
        self.assertIn("local filesystem path", payload["error"]["message"])
        self.assertFalse(self.store.exists())

    def test_list_of_missing_store_fails_without_creating_it(self) -> None:
        returncode, payload, _ = self._run(
            "package", "list", "--store", str(self.store)
        )

        self.assertEqual(2, returncode)
        self.assertFalse(payload["ok"])
        self.assertIn("does not exist", payload["error"]["message"])
        self.assertFalse(self.store.exists())

    def test_list_does_not_initialize_an_existing_empty_directory(self) -> None:
        self.store.mkdir()

        returncode, payload, _ = self._run(
            "package", "list", "--store", str(self.store)
        )

        self.assertEqual(2, returncode)
        self.assertFalse(payload["ok"])
        self.assertIn("not initialized", payload["error"]["message"])
        self.assertEqual([], list(self.store.iterdir()))

    def test_manifest_filename_traversal_is_rejected(self) -> None:
        source, _ = self._source("bounded", "1.0.0")

        returncode, payload, _ = self._run(
            "package",
            "inspect",
            str(source),
            "--manifest-name",
            "../lad-package.json",
        )

        self.assertEqual(2, returncode)
        self.assertFalse(payload["ok"])
        self.assertIn("portable local filename", payload["error"]["message"])

    def test_inspect_rejects_duplicate_json_keys(self) -> None:
        source, _ = self._source("duplicate", "1.0.0")
        manifest_path = source / "lad-package.json"
        original = manifest_path.read_text(encoding="utf-8")
        manifest_path.write_text(
            original[:-1] + ', "name": "shadowed"}', encoding="utf-8"
        )

        returncode, payload, _ = self._run("package", "inspect", str(source))

        self.assertEqual(2, returncode)
        self.assertFalse(payload["ok"])
        self.assertIn("duplicate JSON key: name", payload["error"]["message"])


if __name__ == "__main__":
    unittest.main()
