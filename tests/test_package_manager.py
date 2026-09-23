"""Provider-free tests for deterministic resolution and local package storage."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from local_agent_dispatch.packages import (  # noqa: E402
    ArtifactRecord,
    Dependency,
    ExtensionManifest,
    InstallError,
    ManifestError,
    PackageCatalog,
    PackageStore,
    PlatformConstraint,
    ResolutionError,
    version_satisfies,
)


MANIFEST_FILENAME = "lad-package.json"


def artifact_record(path: str, data: bytes, *, executable: bool = False) -> ArtifactRecord:
    return ArtifactRecord(
        path=path,
        sha256="sha256:" + hashlib.sha256(data).hexdigest(),
        size=len(data),
        executable=executable,
    )


def manifest(
    name: str,
    version: str,
    *,
    kind: str = "agent_harness",
    dependencies: tuple[Dependency, ...] = (),
    platforms: tuple[PlatformConstraint, ...] = (),
    artifacts: tuple[ArtifactRecord, ...] | None = None,
    description: str = "",
    entrypoint_type: str = "none",
    entrypoint: str | None = None,
) -> ExtensionManifest:
    default_data = f"{name}-{version}\n".encode()
    return ExtensionManifest(
        name=name,
        version=version,
        kind=kind,
        description=description,
        entrypoint_type=entrypoint_type,
        entrypoint=entrypoint,
        artifacts=artifacts
        if artifacts is not None
        else (artifact_record("payload.txt", default_data),),
        dependencies=dependencies,
        platforms=platforms,
    )


def write_source(
    base: Path,
    package_manifest: ExtensionManifest,
    files: dict[str, bytes] | None = None,
) -> Path:
    source = base / f"{package_manifest.name}-{package_manifest.version}"
    source.mkdir(parents=True)
    payloads = files or {
        record.path: f"{package_manifest.name}-{package_manifest.version}\n".encode()
        for record in package_manifest.artifacts
    }
    for relative, data in payloads.items():
        path = source / Path(relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    (source / MANIFEST_FILENAME).write_text(
        json.dumps(package_manifest.to_dict(), sort_keys=True),
        encoding="utf-8",
    )
    return source


class PackageManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.data = b"adapter\n"
        self.base = manifest(
            "strict-adapter",
            "1.0.0",
            artifacts=(artifact_record("adapter.py", self.data),),
            entrypoint_type="python",
            entrypoint="adapter:run",
        ).to_dict()

    def clone(self) -> dict[str, object]:
        return json.loads(json.dumps(self.base))

    def test_runtime_rejects_unknown_fields_at_every_protocol_object_boundary(self) -> None:
        cases: list[tuple[str, dict[str, object]]] = []

        top_level = self.clone()
        top_level["surprise"] = True
        cases.append(("manifest", top_level))

        entrypoint = self.clone()
        entrypoint["entrypoint"]["surprise"] = True  # type: ignore[index]
        cases.append(("entrypoint", entrypoint))

        platform = self.clone()
        platform["platforms"] = [{"os": "linux", "arch": "x86_64", "surprise": True}]
        cases.append(("platform", platform))

        dependency = self.clone()
        dependency["dependencies"] = [
            {"name": "helper", "constraint": "*", "optional": False, "surprise": True}
        ]
        cases.append(("dependency", dependency))

        artifact = self.clone()
        artifact["artifacts"][0]["surprise"] = True  # type: ignore[index]
        cases.append(("artifact", artifact))

        for label, payload in cases:
            with self.subTest(object=label), self.assertRaisesRegex(
                ManifestError, "unknown fields"
            ):
                ExtensionManifest.from_dict(payload)

    def test_integer_and_boolean_fields_do_not_coerce_json_scalars(self) -> None:
        for value in (True, 1.0):
            payload = self.clone()
            payload["schema_version"] = value
            with self.subTest(field="schema_version", value=value), self.assertRaises(
                ManifestError
            ):
                ExtensionManifest.from_dict(payload)

        for value in (True, 1.0):
            payload = self.clone()
            payload["artifacts"][0]["size"] = value  # type: ignore[index]
            with self.subTest(field="size", value=value), self.assertRaises(ManifestError):
                ExtensionManifest.from_dict(payload)

        for value in ("false", 0):
            payload = self.clone()
            payload["artifacts"][0]["executable"] = value  # type: ignore[index]
            with self.subTest(field="executable", value=value), self.assertRaises(
                ManifestError
            ):
                ExtensionManifest.from_dict(payload)

            payload = self.clone()
            payload["dependencies"] = [
                {"name": "helper", "constraint": "*", "optional": value}
            ]
            with self.subTest(field="optional", value=value), self.assertRaises(ManifestError):
                ExtensionManifest.from_dict(payload)

    def test_kinds_and_container_digest_are_closed_vocabulary(self) -> None:
        payload = self.clone()
        payload["kind"] = "mystery_adapter"
        with self.assertRaisesRegex(ManifestError, "kind must be one of"):
            ExtensionManifest.from_dict(payload)

        record = artifact_record("container.txt", b"container")
        for image in (
            "registry.example/adapter:latest",
            "registry.example/adapter@sha256:abc",
            "registry.example/adapter@sha256:" + "a" * 63,
            "registry.example/adapter@sha256:" + "a" * 64 + ":suffix",
        ):
            with self.subTest(image=image), self.assertRaisesRegex(
                ManifestError, "64 lowercase hex"
            ):
                manifest(
                    "container-adapter",
                    "1.0.0",
                    artifacts=(record,),
                    entrypoint_type="container",
                    entrypoint=image,
                )

        valid = manifest(
            "container-adapter",
            "1.0.0",
            artifacts=(record,),
            entrypoint_type="container",
            entrypoint="registry.example/adapter:latest@sha256:" + "a" * 64,
        )
        self.assertEqual("agent_harness", valid.kind)

    def test_skill_package_is_data_only_and_declares_root_skill_document(self) -> None:
        skill_bytes = b"---\nname: research-helper\n---\n"
        skill = manifest(
            "research-helper",
            "1.0.0",
            kind="skill",
            artifacts=(artifact_record("SKILL.md", skill_bytes),),
        )
        self.assertEqual("skill", skill.kind)
        self.assertEqual("none", skill.entrypoint_type)

        with self.assertRaisesRegex(ManifestError, "root SKILL.md"):
            manifest("missing-skill-doc", "1.0.0", kind="skill")
        with self.assertRaisesRegex(ManifestError, "entrypoint type=none"):
            manifest(
                "executable-skill",
                "1.0.0",
                kind="skill",
                artifacts=(
                    artifact_record("SKILL.md", skill_bytes),
                    artifact_record("runner.py", b"def run(): pass\n"),
                ),
                entrypoint_type="python",
                entrypoint="runner:run",
            )

    def test_python_entrypoint_must_resolve_to_declared_non_stdlib_source(self) -> None:
        with self.assertRaisesRegex(ManifestError, "declared Python artifact"):
            manifest(
                "unbound-python",
                "1.0.0",
                artifacts=(artifact_record("payload.txt", b"payload"),),
                entrypoint_type="python",
                entrypoint="unbound:run",
            )

        with self.assertRaisesRegex(ManifestError, "standard-library module"):
            manifest(
                "stdlib-python",
                "1.0.0",
                artifacts=(artifact_record("os/path.py", b"def join(): pass\n"),),
                entrypoint_type="python",
                entrypoint="os.path:join",
            )

        declared = manifest(
            "nested-python",
            "1.0.0",
            artifacts=(artifact_record("src/nested/adapter.py", b"def run(): pass\n"),),
            entrypoint_type="python",
            entrypoint="nested.adapter:run",
        )
        self.assertEqual("nested.adapter:run", declared.entrypoint)

    def test_semver_prerelease_identifiers_are_canonical_and_totally_ordered(self) -> None:
        for version in (
            "1.0.0-01",
            "1.0.0-alpha..1",
            "1.0.0-alpha.",
            "1.0.0+build..1",
        ):
            with self.subTest(version=version), self.assertRaises(ManifestError):
                manifest("invalid-version", version)

        self.assertTrue(version_satisfies("1.0.0-1", "<1.0.0-alpha"))
        self.assertFalse(version_satisfies("1.0.0-alpha", "<1.0.0-1"))
        self.assertTrue(version_satisfies("1.0.0+build.1", "==1.0.0+build.1"))
        self.assertFalse(version_satisfies("1.0.0+build.2", "==1.0.0+build.1"))
        self.assertTrue(version_satisfies("1.0.0+build.2", ">=1.0.0+build.1"))

    def test_metadata_rejects_nonfinite_json_numbers(self) -> None:
        payload = self.clone()
        payload["metadata"] = {"score": float("nan")}
        with self.assertRaisesRegex(ManifestError, "strict JSON"):
            ExtensionManifest.from_dict(payload)

        rendered = json.dumps(self.clone()).replace(
            '"metadata": {}', '"metadata": {"score": NaN}'
        )
        from local_agent_dispatch.packages import load_manifest_json

        with self.assertRaisesRegex(ManifestError, "non-finite JSON number"):
            load_manifest_json(rendered)


class PackageCatalogTests(unittest.TestCase):
    def test_transitive_resolution_backtracks_to_one_exact_deterministic_lock(self) -> None:
        shared_v1 = manifest("shared", "1.5.0")
        shared_v2 = manifest("shared", "2.5.0")
        engine_v1 = manifest(
            "engine",
            "1.0.0",
            dependencies=(Dependency("shared", ">=1.0.0"),),
        )
        engine_v2 = manifest(
            "engine",
            "2.0.0",
            dependencies=(Dependency("shared", ">=2.0.0"),),
        )
        application = manifest(
            "application",
            "1.0.0",
            dependencies=(
                Dependency("engine", "*"),
                Dependency("shared", "<2.0.0"),
            ),
        )
        entries = [shared_v2, engine_v2, application, engine_v1, shared_v1]
        forward = PackageCatalog(entries).resolve(
            {"application": "==1.0.0"}, os_name="linux", arch="x86_64"
        )
        reverse = PackageCatalog(list(reversed(entries))).resolve(
            {"application": "==1.0.0"}, os_name="linux", arch="x86_64"
        )

        self.assertEqual(
            {"shared": "1.5.0", "engine": "1.0.0", "application": "1.0.0"},
            forward.pins,
        )
        self.assertEqual(
            ("shared", "engine", "application"),
            tuple(row.name for row in forward.packages),
        )
        self.assertEqual(forward.to_lock_dict(), reverse.to_lock_dict())
        self.assertTrue(
            all(row["manifest_digest"].startswith("sha256:") for row in forward.to_lock_dict()["packages"])
        )

    def test_conflicts_cycles_and_platform_mismatch_fail_closed(self) -> None:
        leaf_v1 = manifest("leaf", "1.0.0")
        left = manifest(
            "left",
            "1.0.0",
            dependencies=(Dependency("leaf", "<2.0.0"),),
        )
        right = manifest(
            "right",
            "1.0.0",
            dependencies=(Dependency("leaf", ">=2.0.0"),),
        )
        with self.assertRaisesRegex(ResolutionError, "conflict"):
            PackageCatalog([leaf_v1, left, right]).resolve(
                {"left": "*", "right": "*"}, os_name="linux", arch="x86_64"
            )

        cycle_a = manifest(
            "cycle-a",
            "1.0.0",
            dependencies=(Dependency("cycle-b", "==1.0.0"),),
        )
        cycle_b = manifest(
            "cycle-b",
            "1.0.0",
            dependencies=(Dependency("cycle-a", "==1.0.0"),),
        )
        with self.assertRaisesRegex(ResolutionError, "dependency cycle"):
            PackageCatalog([cycle_a, cycle_b]).resolve(
                {"cycle-a": "==1.0.0"}, os_name="linux", arch="x86_64"
            )

        mac_only = manifest(
            "mac-only",
            "1.0.0",
            platforms=(PlatformConstraint("darwin", "arm64"),),
        )
        with self.assertRaisesRegex(ResolutionError, "platform mismatch"):
            PackageCatalog([mac_only]).resolve(
                {"mac-only": "*"}, os_name="linux", arch="x86_64"
            )

    def test_missing_dependency_and_conflicting_coordinate_fail_closed(self) -> None:
        root = manifest(
            "root",
            "1.0.0",
            dependencies=(Dependency("missing", "==1.0.0"),),
        )
        with self.assertRaisesRegex(ResolutionError, "missing package"):
            PackageCatalog([root]).resolve(
                {"root": "*"}, os_name="linux", arch="x86_64"
            )

        catalog = PackageCatalog([manifest("duplicate", "1.0.0", description="one")])
        with self.assertRaisesRegex(ResolutionError, "conflicting manifests"):
            catalog.add(manifest("duplicate", "1.0.0", description="two"))

    def test_optional_dependencies_are_opt_in(self) -> None:
        root = manifest(
            "root",
            "1.0.0",
            dependencies=(Dependency("optional-addon", "*", optional=True),),
        )
        without_optional = PackageCatalog([root]).resolve(
            {"root": "*"}, os_name="linux", arch="x86_64"
        )
        self.assertEqual({"root": "1.0.0"}, without_optional.pins)
        with self.assertRaisesRegex(ResolutionError, "missing package optional-addon"):
            PackageCatalog([root]).resolve(
                {"root": "*"},
                os_name="linux",
                arch="x86_64",
                include_optional=True,
            )


class PackageStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.sources = self.root / "sources"
        self.sources.mkdir()
        self.store = PackageStore(
            self.root / "store", os_name="linux", arch="x86_64"
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_install_verifies_and_activates_without_importing_entrypoint(self) -> None:
        marker = self.root / "entrypoint-ran"
        code = f"from pathlib import Path\nPath({str(marker)!r}).write_text('ran')\n".encode()
        record = artifact_record("adapter.py", code)
        package_manifest = manifest(
            "safe-adapter",
            "1.0.0",
            artifacts=(record,),
            entrypoint_type="python",
            entrypoint="adapter:run",
        )
        source = write_source(self.sources, package_manifest, {"adapter.py": code})

        receipt = self.store.install(source)
        self.assertFalse(marker.exists())
        self.assertTrue(receipt.activated)
        self.assertFalse(receipt.already_installed)
        self.assertEqual({"safe-adapter": "1.0.0"}, self.store.active_pins())
        self.assertEqual(("1.0.0",), self.store.installed_versions("safe-adapter"))
        installed = Path(receipt.package_path)
        self.assertEqual(code, (installed / "adapter.py").read_bytes())
        self.assertTrue((installed / "manifest.json").is_file())

        repeated = self.store.install(source)
        self.assertTrue(repeated.already_installed)
        self.assertEqual(receipt.active_generation, repeated.active_generation)

    def test_install_rejects_duplicate_json_keys_before_publication(self) -> None:
        data = b"duplicate-key\n"
        package_manifest = manifest(
            "duplicate-json",
            "1.0.0",
            artifacts=(artifact_record("payload.txt", data),),
        )
        source = self.sources / "duplicate-json"
        source.mkdir()
        (source / "payload.txt").write_bytes(data)
        canonical = json.dumps(package_manifest.to_dict(), sort_keys=True)
        (source / MANIFEST_FILENAME).write_text(
            canonical[:-1] + ', "name": "shadow-name"}',
            encoding="utf-8",
        )

        with self.assertRaisesRegex(InstallError, "duplicate JSON key: name"):
            self.store.install(source, activate=False)
        self.assertEqual((), self.store.installed_versions("duplicate-json"))
        self.assertEqual([], list((self.root / "store" / ".staging").iterdir()))

    def test_bad_hash_size_and_undeclared_files_leave_no_published_package(self) -> None:
        good = b"expected"
        record = artifact_record("payload.bin", good)
        package_manifest = manifest("tampered", "1.0.0", artifacts=(record,))

        for suffix, data, extra in (
            ("hash", b"XXXXXXXX", None),
            ("size", b"too-long-for-record", None),
            ("extra", good, ("undeclared.txt", b"no")),
        ):
            with self.subTest(case=suffix):
                case_root = self.sources / suffix
                case_root.mkdir()
                source = write_source(case_root, package_manifest, {"payload.bin": data})
                if extra is not None:
                    (source / extra[0]).write_bytes(extra[1])
                with self.assertRaises(InstallError):
                    self.store.install(source, activate=False)
                self.assertNotIn("1.0.0", self.store.installed_versions("tampered"))
                self.assertEqual([], list((self.root / "store" / ".staging").iterdir()))

    def test_symlinks_urls_and_platform_mismatch_are_rejected(self) -> None:
        data = b"payload"
        record = artifact_record("payload.bin", data)
        package_manifest = manifest("linked", "1.0.0", artifacts=(record,))
        source = write_source(self.sources, package_manifest, {"payload.bin": data})
        outside = self.root / "outside.bin"
        outside.write_bytes(data)
        (source / "payload.bin").unlink()
        try:
            os.symlink(outside, source / "payload.bin")
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation is not available")
        with self.assertRaisesRegex(InstallError, "unsafe file entry"):
            self.store.install(source, activate=False)
        with self.assertRaisesRegex(InstallError, "URLs are not accepted"):
            self.store.install("https://example.invalid/package")

        mac_manifest = manifest(
            "mac-package",
            "1.0.0",
            platforms=(PlatformConstraint("darwin", "arm64"),),
        )
        mac_source = write_source(self.sources, mac_manifest)
        with self.assertRaisesRegex(InstallError, "does not support"):
            self.store.install(mac_source, activate=False)

    def test_windows_invalid_and_device_artifact_paths_fail_on_every_platform(self) -> None:
        invalid_paths = (
            "C:escape.txt",
            'bad<name.txt',
            'bad>name.txt',
            'bad"name.txt',
            "bad\\name.txt",
            "bad|name.txt",
            "bad?name.txt",
            "bad*name.txt",
            "bad\x1fname.txt",
            "con.txt",
            "CONIN$",
            "conout$.log",
            "CLOCK$.log",
            "COM¹.txt",
            "lpt².data",
            "COM³",
        )
        for index, artifact_path in enumerate(invalid_paths):
            with self.subTest(path=artifact_path):
                data = b"unsafe-name"
                with self.assertRaises(ManifestError):
                    artifact_record(artifact_path, data)
                package_manifest = manifest(
                    f"portable-{index}",
                    "1.0.0",
                    artifacts=(artifact_record("payload.txt", data),),
                )
                source = self.sources / f"portable-{index}"
                source.mkdir()
                serialized = package_manifest.to_dict()
                serialized["artifacts"][0]["path"] = artifact_path
                (source / MANIFEST_FILENAME).write_text(
                    json.dumps(serialized, sort_keys=True),
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(
                    InstallError, "portable|separator"
                ):
                    self.store.install(source, activate=False)

        with self.assertRaisesRegex(ManifestError, "portable filesystem"):
            manifest("con", "1.0.0")

        collision = manifest(
            "case-collision",
            "1.0.0",
            artifacts=(
                artifact_record("Data/result.txt", b"one"),
                artifact_record("data/RESULT.txt", b"two"),
            ),
        )
        source = self.sources / "case-collision"
        source.mkdir()
        (source / MANIFEST_FILENAME).write_text(
            json.dumps(collision.to_dict(), sort_keys=True), encoding="utf-8"
        )
        with self.assertRaisesRegex(InstallError, "paths collide"):
            self.store.install(source, activate=False)

    def test_dependency_pins_are_validated_before_atomic_activation(self) -> None:
        dep_data = b"dep\n"
        dep = manifest(
            "dependency",
            "1.0.0",
            artifacts=(artifact_record("payload.txt", dep_data),),
        )
        app_data = b"app\n"
        app = manifest(
            "dependent",
            "1.0.0",
            artifacts=(artifact_record("payload.txt", app_data),),
            dependencies=(Dependency("dependency", "==1.0.0"),),
        )
        dep_source = write_source(self.sources, dep, {"payload.txt": dep_data})
        app_source = write_source(self.sources, app, {"payload.txt": app_data})
        self.store.install(dep_source, activate=False)
        self.store.install(app_source, activate=False)

        with self.assertRaisesRegex(InstallError, "requires unpinned dependency"):
            self.store.activate("dependent", "1.0.0")
        generation = self.store.activate_pins(
            {"dependency": "1.0.0", "dependent": "1.0.0"}, replace=True
        )
        self.assertEqual(1, generation)
        self.assertEqual(
            {"dependency": "1.0.0", "dependent": "1.0.0"},
            self.store.active_pins(),
        )

    def test_versioned_locks_rollback_and_uninstall_safety(self) -> None:
        first_data = b"v1\n"
        second_data = b"v2\n"
        third_data = b"v3\n"
        first = manifest(
            "versioned",
            "1.0.0",
            artifacts=(artifact_record("payload.txt", first_data),),
        )
        second = manifest(
            "versioned",
            "2.0.0",
            artifacts=(artifact_record("payload.txt", second_data),),
        )
        third = manifest(
            "versioned",
            "3.0.0",
            artifacts=(artifact_record("payload.txt", third_data),),
        )
        self.store.install(
            write_source(self.sources, first, {"payload.txt": first_data})
        )
        self.store.install(
            write_source(self.sources, second, {"payload.txt": second_data})
        )
        self.store.install(
            write_source(self.sources, third, {"payload.txt": third_data}),
            activate=False,
        )
        self.assertEqual({"versioned": "2.0.0"}, self.store.active_pins())
        self.assertEqual({"versioned": "1.0.0"}, self.store.rollback())
        self.assertEqual(3, self.store.active_generation())

        with self.assertRaisesRegex(InstallError, "active package"):
            self.store.uninstall("versioned", "1.0.0")
        with self.assertRaisesRegex(InstallError, "rollback generation"):
            self.store.uninstall("versioned", "2.0.0")
        self.store.uninstall("versioned", "3.0.0")
        self.assertEqual(("2.0.0", "1.0.0"), self.store.installed_versions("versioned"))

        lock_files = sorted((self.root / "store" / "state" / "locks").glob("*.json"))
        self.assertEqual(3, len(lock_files))
        latest = json.loads(lock_files[-1].read_text(encoding="utf-8"))
        self.assertEqual(1, latest["schema_version"])
        self.assertEqual(1, latest["rollback_target"])
        self.assertTrue(
            latest["pins"]["versioned"]["manifest_digest"].startswith("sha256:")
        )

    def test_rollback_ignores_lock_written_but_never_made_active(self) -> None:
        payloads = {version: f"{version}\n".encode() for version in ("1.0.0", "2.0.0", "3.0.0")}
        manifests = {
            version: manifest(
                "crash-safe",
                version,
                artifacts=(artifact_record("payload.txt", data),),
            )
            for version, data in payloads.items()
        }
        for version in ("1.0.0", "2.0.0"):
            self.store.install(
                write_source(
                    self.sources,
                    manifests[version],
                    {"payload.txt": payloads[version]},
                ),
                activate=version == "1.0.0",
            )

        lock_directory = self.root / "store" / "state" / "locks"
        first_payload = json.loads(
            (lock_directory / "00000000000000000001.json").read_text(encoding="utf-8")
        )
        orphan = dict(first_payload)
        orphan["generation"] = 2
        orphan["previous_generation"] = 1
        orphan["pins"] = {
            "crash-safe": {
                "version": "2.0.0",
                "manifest_digest": manifests["2.0.0"].digest,
            }
        }
        (lock_directory / "00000000000000000002.json").write_text(
            json.dumps(orphan, sort_keys=True), encoding="utf-8"
        )

        self.store.install(
            write_source(
                self.sources,
                manifests["3.0.0"],
                {"payload.txt": payloads["3.0.0"]},
            )
        )
        self.assertEqual(3, self.store.active_generation())
        self.assertEqual({"crash-safe": "1.0.0"}, self.store.rollback())
        self.store.uninstall("crash-safe", "2.0.0")
        self.assertNotIn("2.0.0", self.store.installed_versions("crash-safe"))

    def test_declared_executable_is_installed_but_never_run(self) -> None:
        marker = self.root / "executable-ran"
        data = f"#!/bin/sh\ntouch {marker}\n".encode()
        package_manifest = manifest(
            "executable-adapter",
            "1.0.0",
            artifacts=(artifact_record("bin/actual", data, executable=True),),
            entrypoint_type="executable",
            entrypoint="bin/actual",
        )
        source = write_source(
            self.sources, package_manifest, {"bin/actual": data}
        )
        receipt = self.store.install(source, activate=False)
        self.assertFalse(marker.exists())
        self.assertTrue((Path(receipt.package_path) / "bin" / "actual").is_file())


if __name__ == "__main__":
    unittest.main()
