"""Provider-free coverage for canonical package resolution lockfiles."""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from local_agent_dispatch.packages import (  # noqa: E402
    ArtifactRecord,
    Dependency,
    ExtensionManifest,
    LockError,
    PackageCatalog,
    PackageStore,
    PlatformConstraint,
    catalog_snapshot_digest,
    load_lock_json,
    resolve_to_lock,
    verify_lock,
)


def artifact(path: str, data: bytes) -> ArtifactRecord:
    return ArtifactRecord(
        path=path,
        sha256="sha256:" + hashlib.sha256(data).hexdigest(),
        size=len(data),
    )


def package(
    name: str,
    version: str,
    *,
    data: bytes | None = None,
    dependencies: tuple[Dependency, ...] = (),
    platforms: tuple[PlatformConstraint, ...] = (),
    entrypoint: bool = False,
) -> ExtensionManifest:
    contents = data if data is not None else f"{name}-{version}\n".encode()
    path = "adapter.py" if entrypoint else "payload.txt"
    return ExtensionManifest(
        name=name,
        version=version,
        kind="agent_harness",
        entrypoint_type="python" if entrypoint else "none",
        entrypoint="adapter:run" if entrypoint else None,
        artifacts=(artifact(path, contents),),
        dependencies=dependencies,
        platforms=platforms,
    )


def write_source(root: Path, manifest: ExtensionManifest, data: bytes) -> Path:
    source = root / f"{manifest.name}-{manifest.version}"
    source.mkdir(parents=True)
    record = manifest.artifacts[0]
    (source / record.path).write_bytes(data)
    (source / "lad-package.json").write_text(
        json.dumps(manifest.to_dict(), sort_keys=True),
        encoding="utf-8",
    )
    return source


class PackageLockTests(unittest.TestCase):
    def setUp(self) -> None:
        self.platforms = (
            PlatformConstraint("linux", "x86_64"),
            PlatformConstraint("darwin", "arm64"),
        )
        self.leaf = package("leaf", "1.2.0", platforms=self.platforms)
        self.application = package(
            "application",
            "2.0.0",
            dependencies=(Dependency("leaf", ">=1.0.0,<2.0.0"),),
            platforms=self.platforms,
        )

    def test_resolve_to_lock_is_canonical_and_insertion_order_independent(self) -> None:
        forward = PackageCatalog([self.leaf, self.application])
        reverse = PackageCatalog([self.application, self.leaf])

        first = resolve_to_lock(
            forward,
            {"application": "==2.0.0"},
            os_name="linux",
            arch="x86_64",
        )
        second = resolve_to_lock(
            reverse,
            {"application": "==2.0.0"},
            os_name="linux",
            arch="x86_64",
        )

        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertEqual(first.digest, second.digest)
        self.assertEqual(catalog_snapshot_digest(forward), first.catalog_snapshot_digest)
        self.assertEqual(1, first.schema_version)
        self.assertEqual("1", first.lock_version)
        self.assertEqual(
            ["application", "leaf"],
            [row["name"] for row in first.to_dict()["packages"]],
        )
        locked_application = first.to_dict()["packages"][0]
        self.assertEqual("agent_harness", locked_application["kind"])
        self.assertEqual(self.application.digest, locked_application["manifest_digest"])
        self.assertEqual(
            [
                {"os": "darwin", "arch": "arm64"},
                {"os": "linux", "arch": "x86_64"},
            ],
            locked_application["platforms"],
        )

        round_trip = load_lock_json(first.to_json())
        self.assertEqual(first, round_trip)
        self.assertEqual(first.digest, round_trip.digest)
        self.assertEqual(
            json.dumps(first.to_dict(), sort_keys=True, separators=(",", ":")),
            first.to_json(),
        )

    def test_lock_parser_rejects_duplicate_keys_and_unknown_fields(self) -> None:
        lock = resolve_to_lock(
            PackageCatalog([self.leaf, self.application]),
            {"application": "*"},
            os_name="linux",
            arch="x86_64",
        )
        canonical = lock.to_json()
        duplicate_top_level = canonical[:-1] + ',"schema_version":1}'
        with self.assertRaisesRegex(LockError, "duplicate JSON key: schema_version"):
            load_lock_json(duplicate_top_level)

        duplicate_nested = canonical.replace(
            '"kind":"agent_harness","manifest_digest"',
            '"kind":"agent_harness","kind":"bundle","manifest_digest"',
            1,
        )
        with self.assertRaisesRegex(LockError, "duplicate JSON key: kind"):
            load_lock_json(duplicate_nested)

        payload = lock.to_dict()
        payload["unexpected"] = True
        with self.assertRaisesRegex(LockError, "package lock contains unknown fields"):
            load_lock_json(json.dumps(payload))

        payload = lock.to_dict()
        payload["packages"][0]["unexpected"] = True
        with self.assertRaisesRegex(LockError, "locked package contains unknown fields"):
            load_lock_json(json.dumps(payload))

    def test_lock_parser_does_not_coerce_scalars(self) -> None:
        lock = resolve_to_lock(
            PackageCatalog([self.leaf, self.application]),
            {"application": "*"},
            os_name="linux",
            arch="x86_64",
        )
        for field, value in (("schema_version", True), ("include_optional", 0)):
            payload = lock.to_dict()
            payload[field] = value
            with self.subTest(field=field), self.assertRaises(LockError):
                load_lock_json(json.dumps(payload))

    def test_verify_reproduces_resolution_and_rejects_catalog_drift(self) -> None:
        catalog = PackageCatalog([self.leaf, self.application])
        lock = resolve_to_lock(
            catalog,
            {"application": "==2.0.0"},
            os_name="linux",
            arch="x86_64",
        )
        verified = verify_lock(lock, catalog)
        self.assertTrue(verified.catalog_verified)
        self.assertFalse(verified.store_verified)
        self.assertFalse(verified.artifacts_verified)
        self.assertEqual(2, verified.packages_verified)
        self.assertEqual(lock.digest, verified.lock_digest)

        drifted = PackageCatalog([self.leaf, self.application, package("unselected", "1.0.0")])
        with self.assertRaisesRegex(LockError, "catalog snapshot digest mismatch"):
            verify_lock(lock, drifted)

        tampered_payload = lock.to_dict()
        tampered_payload["packages"][0]["manifest_digest"] = "sha256:" + "0" * 64
        tampered = load_lock_json(json.dumps(tampered_payload))
        with self.assertRaisesRegex(LockError, "locked resolution"):
            verify_lock(tampered, catalog)

    def test_store_verification_hashes_artifacts_without_importing_entrypoint(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "entrypoint-imported"
            leaf_data = b"leaf\n"
            application_data = (
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('imported')\n"
            ).encode()
            leaf = package("leaf", "1.0.0", data=leaf_data)
            application = package(
                "application",
                "1.0.0",
                data=application_data,
                dependencies=(Dependency("leaf", "==1.0.0"),),
                entrypoint=True,
            )
            catalog = PackageCatalog([leaf, application])
            lock = resolve_to_lock(
                catalog,
                {"application": "==1.0.0"},
                os_name="linux",
                arch="x86_64",
            )
            sources = root / "sources"
            sources.mkdir()
            leaf_source = write_source(sources, leaf, leaf_data)
            application_source = write_source(sources, application, application_data)
            store = PackageStore(root / "store", os_name="linux", arch="x86_64")
            store.install(leaf_source)
            store.install(application_source)

            verified = verify_lock(lock, catalog, store=store)

            self.assertTrue(verified.store_verified)
            self.assertTrue(verified.artifacts_verified)
            self.assertFalse(verified.entrypoint_executed)
            self.assertFalse(verified.network_accessed)
            self.assertFalse(marker.exists())

            installed_artifact = (
                root / "store" / "packages" / "application" / "1.0.0" / "adapter.py"
            )
            installed_artifact.write_bytes(b"tampered\n")
            with self.assertRaisesRegex(LockError, "installed package verification failed"):
                verify_lock(lock, catalog, store=store)
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
