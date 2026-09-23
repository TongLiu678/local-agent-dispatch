"""Atomic, non-executing local package store for LAD extensions."""

from __future__ import annotations

import contextlib
import datetime as _dt
import hashlib
import json
import os
import shutil
import stat
import tempfile
import threading
import unicodedata
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from functools import cmp_to_key
from pathlib import Path, PurePosixPath
from typing import Any

from .manifest import (
    ArtifactRecord,
    ExtensionManifest,
    ManifestError,
    _compare_versions,
    _name,
    _version_tuple,
    current_platform,
    is_portable_filesystem_component,
    load_manifest_json,
    normalize_sha256,
    safe_artifact_path,
    version_satisfies,
)


STORE_STATE_SCHEMA_VERSION = 1
INSTALL_RECEIPT_SCHEMA_VERSION = 1
DEFAULT_MANIFEST_FILENAME = "lad-package.json"
_INSTALLED_MANIFEST_FILENAME = "manifest.json"
_MAX_MANIFEST_BYTES = 1024 * 1024
_COPY_CHUNK_BYTES = 1024 * 1024
class InstallError(RuntimeError):
    """Raised when installation or active-state mutation cannot be proven safe."""


@dataclass(frozen=True)
class InstallReceipt:
    """Provider-free receipt for one verified local installation."""

    name: str
    version: str
    manifest_digest: str
    package_path: str
    activated: bool
    active_generation: int
    already_installed: bool = False
    previous_version: str | None = None
    schema_version: int = INSTALL_RECEIPT_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "name": self.name,
            "version": self.version,
            "manifest_digest": self.manifest_digest,
            "package_path": self.package_path,
            "activated": self.activated,
            "active_generation": self.active_generation,
            "already_installed": self.already_installed,
            "previous_version": self.previous_version,
        }


class PackageStore:
    """Versioned package store that never imports or executes an entrypoint."""

    def __init__(
        self,
        root: str | os.PathLike[str],
        *,
        os_name: str | None = None,
        arch: str | None = None,
    ) -> None:
        raw_root = Path(root).expanduser().absolute()
        if raw_root.exists() and raw_root.is_symlink():
            raise InstallError("package store root must not be a symlink")
        if raw_root.exists() and not raw_root.is_dir():
            raise InstallError("package store root must be a directory")
        raw_root.mkdir(parents=True, exist_ok=True)
        self.root = raw_root.resolve()
        detected_os, detected_arch = current_platform()
        self.os_name = (os_name or detected_os).strip().lower()
        self.arch = (arch or detected_arch).strip().lower()
        if not self.os_name or not self.arch:
            raise InstallError("store platform os and arch must be non-empty")

        self._packages = self._ensure_directory(self.root / "packages")
        self._staging = self._ensure_directory(self.root / ".staging")
        self._state = self._ensure_directory(self.root / "state")
        self._locks = self._ensure_directory(self._state / "locks")
        self._active_path = self._state / "active-v1.json"
        self._mutation_path = self._state / ".mutation.lock"
        self._thread_lock = threading.RLock()

    @staticmethod
    def _ensure_directory(path: Path) -> Path:
        if path.exists() and path.is_symlink():
            raise InstallError(f"store directory must not be a symlink: {path}")
        if path.exists() and not path.is_dir():
            raise InstallError(f"store path must be a directory: {path}")
        path.mkdir(parents=True, exist_ok=True)
        return path

    @contextlib.contextmanager
    def _mutation_guard(self) -> Iterator[None]:
        """Serialize state changes across threads and cooperating processes."""

        with self._thread_lock:
            try:
                self._mutation_path.mkdir()
            except FileExistsError as exc:
                raise InstallError(
                    "another package-store mutation is active or left a stale lock"
                ) from exc
            try:
                yield
            finally:
                try:
                    self._mutation_path.rmdir()
                except FileNotFoundError:
                    pass

    def install(
        self,
        source_directory: str | os.PathLike[str],
        *,
        manifest_filename: str = DEFAULT_MANIFEST_FILENAME,
        activate: bool = True,
    ) -> InstallReceipt:
        """Verify and atomically install one package from a local directory.

        The source manifest is data only. This method never imports its Python
        entrypoint and never invokes an executable, container, endpoint, or
        provider operation.
        """

        with self._mutation_guard():
            source, manifest = self._load_source(source_directory, manifest_filename)
            portable_keys: dict[str, str] = {}
            for record in manifest.artifacts:
                key = self._portable_path_key(record.path, "artifact path")
                previous = portable_keys.get(key)
                if previous is not None:
                    raise InstallError(
                        "artifact paths collide on a portable filesystem: "
                        f"{previous!r} and {record.path!r}"
                    )
                portable_keys[key] = record.path
            source_manifest_key = self._portable_path_key(
                manifest_filename, "manifest_filename"
            )
            installed_manifest_key = self._portable_path_key(
                _INSTALLED_MANIFEST_FILENAME, "installed manifest filename"
            )
            if source_manifest_key in portable_keys or installed_manifest_key in portable_keys:
                raise InstallError("an artifact path collides with a manifest filename")
            actual_files = self._inventory_source(source)
            declared = {record.path for record in manifest.artifacts}
            if manifest_filename in declared:
                raise InstallError("the source manifest must not also be a declared artifact")
            if _INSTALLED_MANIFEST_FILENAME in declared:
                raise InstallError(
                    f"artifact path {_INSTALLED_MANIFEST_FILENAME!r} is reserved by the store"
                )
            allowed = declared | {manifest_filename}
            missing = sorted(declared - actual_files)
            undeclared = sorted(actual_files - allowed)
            if missing:
                raise InstallError("declared artifacts are missing: " + ", ".join(missing))
            if undeclared:
                raise InstallError("undeclared source files: " + ", ".join(undeclared))
            if manifest.entrypoint_type == "executable":
                try:
                    executable_path = safe_artifact_path(manifest.entrypoint)
                except ManifestError as exc:
                    raise InstallError(f"unsafe executable entrypoint: {exc}") from exc
                if executable_path not in declared:
                    raise InstallError("executable entrypoint must name a declared artifact")
            if not manifest.supports(self.os_name, self.arch):
                raise InstallError(
                    f"package {manifest.coordinate} does not support "
                    f"{self.os_name}/{self.arch}"
                )

            generation, current_records = self._read_active_records()
            current_pins = {
                name: record["version"] for name, record in current_records.items()
            }
            previous_version = current_pins.get(manifest.name)
            current_record = current_records.get(manifest.name)
            if (
                current_record is not None
                and current_record["version"] == manifest.version
                and current_record["manifest_digest"] != manifest.digest
            ):
                raise InstallError(
                    f"active pin digest disagrees with source manifest for {manifest.coordinate}"
                )
            proposed_pins = dict(current_pins)
            if activate:
                proposed_pins[manifest.name] = manifest.version
                self._validate_active_graph(
                    proposed_pins,
                    overrides={(manifest.name, manifest.version): manifest},
                )

            target = self._package_path(manifest.name, manifest.version)
            already_installed = target.exists() or target.is_symlink()
            if already_installed:
                installed = self._verify_installed_package(target)
                if installed.digest != manifest.digest:
                    raise InstallError(
                        f"installed coordinate {manifest.coordinate} has a different manifest"
                    )
            else:
                self._stage_and_publish(source, manifest, target)

            if activate and previous_version != manifest.version:
                generation = self._commit_active(
                    proposed_pins,
                    reason=f"activate:{manifest.coordinate}",
                )
            return InstallReceipt(
                name=manifest.name,
                version=manifest.version,
                manifest_digest=manifest.digest,
                package_path=str(target),
                activated=activate,
                active_generation=generation,
                already_installed=already_installed,
                previous_version=previous_version,
            )

    def active_pins(self) -> dict[str, str]:
        """Return a copy of the current exact active pins."""

        _, records = self._read_active_records()
        pins = {name: record["version"] for name, record in records.items()}
        manifests = self._validate_active_graph(pins)
        for name, record in records.items():
            if manifests[name].digest != record["manifest_digest"]:
                raise InstallError(f"active manifest digest mismatch for {name}")
        return pins

    def active_generation(self) -> int:
        generation, _ = self._read_active_records()
        return generation

    def activate(self, name: str, version: str) -> int:
        """Activate one installed version and return the new lock generation."""

        return self.activate_pins({name: version}, replace=False)

    def activate_pins(
        self, pins: Mapping[str, str], *, replace: bool = False
    ) -> int:
        """Atomically activate a validated exact pin set."""

        requested = self._normalize_pins(pins)
        with self._mutation_guard():
            _, current_records = self._read_active_records()
            next_pins = {} if replace else {
                name: record["version"] for name, record in current_records.items()
            }
            next_pins.update(requested)
            return self._commit_active(next_pins, reason="activate-pins")

    def rollback(self, generation: int | None = None) -> dict[str, str]:
        """Restore an earlier exact pin set as a new auditable generation."""

        with self._mutation_guard():
            current_generation, _ = self._read_active_records()
            available = [
                value
                for value in self._committed_generations()
                if value != current_generation
            ]
            if generation is None:
                if not available:
                    raise InstallError("no earlier active generation is available")
                target_generation = max(available)
            else:
                if isinstance(generation, bool) or not isinstance(generation, int):
                    raise InstallError("rollback generation must be an integer")
                target_generation = generation
                if target_generation not in available:
                    raise InstallError(
                        f"rollback generation {target_generation} is unavailable or not earlier"
                    )
            _, records = self._read_lock_records(target_generation)
            pins = {name: record["version"] for name, record in records.items()}
            manifests = self._validate_active_graph(pins)
            for name, record in records.items():
                if manifests[name].digest != record["manifest_digest"]:
                    raise InstallError(
                        f"rollback manifest digest mismatch for {name}@{record['version']}"
                    )
            self._commit_active(
                pins,
                reason=f"rollback:{target_generation}",
                rollback_target=target_generation,
            )
            return dict(sorted(pins.items()))

    def uninstall(self, name: str, version: str) -> None:
        """Remove an inactive version only when no rollback lock references it."""

        normalized_name, normalized_version = self._coordinate(name, version)
        with self._mutation_guard():
            _, active_records = self._read_active_records()
            active = active_records.get(normalized_name)
            if active is not None and active["version"] == normalized_version:
                raise InstallError(
                    f"cannot uninstall active package {normalized_name}@{normalized_version}"
                )
            for generation in self._committed_generations():
                _, records = self._read_lock_records(generation)
                record = records.get(normalized_name)
                if record is not None and record["version"] == normalized_version:
                    raise InstallError(
                        f"cannot uninstall {normalized_name}@{normalized_version}; "
                        f"rollback generation {generation} still references it"
                    )

            target = self._package_path(normalized_name, normalized_version)
            if not target.exists() and not target.is_symlink():
                raise InstallError(
                    f"package is not installed: {normalized_name}@{normalized_version}"
                )
            self._verify_installed_package(target)
            if target.is_symlink() or target.parent != self._packages / normalized_name:
                raise InstallError("refusing to remove an unsafe package path")
            shutil.rmtree(target)
            try:
                target.parent.rmdir()
            except OSError:
                pass

    def installed_versions(self, name: str) -> tuple[str, ...]:
        normalized = _name(name, "package name")
        package_root = self._packages / normalized
        if not package_root.exists():
            return ()
        if package_root.is_symlink() or not package_root.is_dir():
            raise InstallError(f"unsafe package directory: {package_root}")
        versions: list[str] = []
        for child in package_root.iterdir():
            if child.is_symlink() or not child.is_dir():
                raise InstallError(f"unsafe entry in package directory: {child}")
            try:
                _version_tuple(child.name)
            except ManifestError as exc:
                raise InstallError(f"invalid installed version directory: {child.name}") from exc
            versions.append(child.name)
        return tuple(
            sorted(
                versions,
                key=cmp_to_key(self._compare_version_strings),
                reverse=True,
            )
        )

    def verify_installed(self, name: str, version: str) -> ExtensionManifest:
        """Verify one installed package and return its inert manifest.

        Verification inventories the installed directory and streams every
        declared artifact through its size and SHA-256 checks.  It never imports
        or executes the manifest entrypoint.
        """

        normalized_name, normalized_version = self._coordinate(name, version)
        return self._installed_manifest(normalized_name, normalized_version)

    @staticmethod
    def _compare_version_strings(left: str, right: str) -> int:
        comparison = _compare_versions(left, right)
        if comparison:
            return comparison
        return (left > right) - (left < right)

    def _load_source(
        self,
        source_directory: str | os.PathLike[str],
        manifest_filename: str,
    ) -> tuple[Path, ExtensionManifest]:
        try:
            raw_source = os.fspath(source_directory)
        except TypeError as exc:
            raise InstallError("source_directory must be a local filesystem path") from exc
        if isinstance(raw_source, bytes):
            raw_source = os.fsdecode(raw_source)
        if "://" in raw_source:
            raise InstallError("source_directory must be local; URLs are not accepted")
        parts = self._portable_path_parts(manifest_filename, "manifest_filename")
        if len(parts) != 1:
            raise InstallError("manifest_filename must be one normalized filename")
        source = Path(raw_source).expanduser().absolute()
        if source.is_symlink():
            raise InstallError("source directory must not be a symlink")
        if not source.is_dir():
            raise InstallError("source_directory must be an existing local directory")
        source = source.resolve()
        manifest_path = source / manifest_filename
        manifest = self._read_manifest(manifest_path)
        return source, manifest

    def _inventory_source(self, source: Path) -> set[str]:
        files: set[str] = set()
        for directory, directory_names, file_names in os.walk(source, followlinks=False):
            directory_path = Path(directory)
            for name in sorted(directory_names):
                path = directory_path / name
                mode = path.lstat().st_mode
                if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
                    raise InstallError(f"source contains unsafe directory entry: {path}")
            for name in sorted(file_names):
                path = directory_path / name
                mode = path.lstat().st_mode
                if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
                    raise InstallError(f"source contains unsafe file entry: {path}")
                try:
                    resolved = path.resolve(strict=True)
                    resolved.relative_to(source)
                except (OSError, ValueError) as exc:
                    raise InstallError(f"source file escapes package directory: {path}") from exc
                files.add(path.relative_to(source).as_posix())
        return files

    def _stage_and_publish(
        self, source: Path, manifest: ExtensionManifest, target: Path
    ) -> None:
        stage_root = Path(
            tempfile.mkdtemp(prefix=f"{manifest.name}-{manifest.version}-", dir=self._staging)
        )
        payload = stage_root / "payload"
        payload.mkdir()
        try:
            for record in sorted(manifest.artifacts, key=lambda item: item.path):
                source_path = self._confined_path(source, record.path)
                destination = self._confined_path(payload, record.path)
                destination.parent.mkdir(parents=True, exist_ok=True)
                self._copy_verified(source_path, destination, record)
            self._write_json_file(payload / _INSTALLED_MANIFEST_FILENAME, manifest.to_dict())
            self._ensure_directory(target.parent)
            if target.exists():
                raise InstallError(f"package target appeared during install: {target}")
            os.replace(payload, target)
            self._fsync_directory(target.parent)
        finally:
            shutil.rmtree(stage_root, ignore_errors=True)

    @staticmethod
    def _copy_verified(source: Path, destination: Path, record: ArtifactRecord) -> None:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            source_fd = os.open(source, flags)
        except OSError as exc:
            raise InstallError(f"cannot open declared artifact safely: {record.path}") from exc
        digest = hashlib.sha256()
        size = 0
        try:
            source_stat = os.fstat(source_fd)
            if not stat.S_ISREG(source_stat.st_mode):
                raise InstallError(f"declared artifact is not a regular file: {record.path}")
            with os.fdopen(source_fd, "rb", closefd=False) as source_handle, destination.open("xb") as output:
                while True:
                    chunk = source_handle.read(_COPY_CHUNK_BYTES)
                    if not chunk:
                        break
                    digest.update(chunk)
                    size += len(chunk)
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
        finally:
            os.close(source_fd)
        actual_digest = "sha256:" + digest.hexdigest()
        if size != record.size:
            raise InstallError(
                f"artifact size mismatch for {record.path}: expected {record.size}, got {size}"
            )
        if actual_digest != record.sha256:
            raise InstallError(f"artifact sha256 mismatch for {record.path}")
        destination.chmod(0o755 if record.executable else 0o644)

    def _verify_installed_package(self, target: Path) -> ExtensionManifest:
        if target.is_symlink() or not target.is_dir():
            raise InstallError(f"installed package path is unsafe: {target}")
        manifest = self._read_manifest(target / _INSTALLED_MANIFEST_FILENAME)
        actual = self._inventory_source(target)
        declared = {record.path for record in manifest.artifacts}
        expected = declared | {_INSTALLED_MANIFEST_FILENAME}
        if actual != expected:
            extra = sorted(actual - expected)
            missing = sorted(expected - actual)
            details = []
            if extra:
                details.append("undeclared=" + ",".join(extra))
            if missing:
                details.append("missing=" + ",".join(missing))
            raise InstallError("installed package inventory mismatch: " + "; ".join(details))
        for record in manifest.artifacts:
            self._verify_file(self._confined_path(target, record.path), record)
        return manifest

    @staticmethod
    def _verify_file(path: Path, record: ArtifactRecord) -> None:
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
            raise InstallError(f"installed artifact is unsafe: {record.path}")
        digest = hashlib.sha256()
        size = 0
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(_COPY_CHUNK_BYTES)
                if not chunk:
                    break
                digest.update(chunk)
                size += len(chunk)
        if size != record.size or "sha256:" + digest.hexdigest() != record.sha256:
            raise InstallError(f"installed artifact verification failed: {record.path}")

    def _read_manifest(self, path: Path) -> ExtensionManifest:
        if path.is_symlink() or not path.is_file():
            raise InstallError(f"package manifest is missing or unsafe: {path}")
        if path.stat().st_size > _MAX_MANIFEST_BYTES:
            raise InstallError("package manifest exceeds the 1 MiB limit")
        try:
            manifest_text = path.read_text(encoding="utf-8")
            manifest = load_manifest_json(manifest_text)
            # Recheck the original JSON spelling as a defense in depth.  The
            # manifest model already rejects non-portable components and
            # backslashes; this keeps the store boundary closed if that model
            # is ever relaxed independently.
            raw_payload = json.loads(manifest_text)
            for record in raw_payload["artifacts"]:
                raw_path = record["path"]
                if any(
                    not is_portable_filesystem_component(part)
                    for part in raw_path.split("/")
                ):
                    raise InstallError(
                        "artifact path is not a portable filesystem path: "
                        f"{raw_path!r}"
                    )
            return manifest
        except (OSError, UnicodeError, json.JSONDecodeError, ManifestError) as exc:
            raise InstallError(f"invalid package manifest {path.name}: {exc}") from exc

    def _package_path(self, name: str, version: str) -> Path:
        normalized_name, normalized_version = self._coordinate(name, version)
        path = self._packages / normalized_name / normalized_version
        try:
            path.relative_to(self._packages)
        except ValueError as exc:
            raise InstallError("package coordinate escapes the store") from exc
        return path

    @staticmethod
    def _coordinate(name: str, version: str) -> tuple[str, str]:
        try:
            normalized_name = _name(name, "package name")
            _version_tuple(version)
        except ManifestError as exc:
            raise InstallError(str(exc)) from exc
        PackageStore._portable_component(normalized_name, "package name")
        PackageStore._portable_component(version, "package version")
        return normalized_name, version

    @staticmethod
    def _portable_component(value: str, label: str) -> None:
        if not is_portable_filesystem_component(value):
            raise InstallError(f"{label} is not a portable filesystem component: {value!r}")

    @staticmethod
    def _portable_path_parts(value: str, label: str) -> tuple[str, ...]:
        try:
            normalized = safe_artifact_path(value)
        except ManifestError as exc:
            raise InstallError(f"{label} is unsafe: {exc}") from exc
        parts = PurePosixPath(normalized).parts
        for part in parts:
            PackageStore._portable_component(part, label)
        return parts

    @staticmethod
    def _portable_path_key(value: str, label: str) -> str:
        parts = PackageStore._portable_path_parts(value, label)
        return "/".join(unicodedata.normalize("NFC", part).casefold() for part in parts)

    @staticmethod
    def _confined_path(root: Path, relative: str) -> Path:
        parts = PackageStore._portable_path_parts(relative, "artifact path")
        candidate = root.joinpath(*parts)
        try:
            candidate.relative_to(root)
        except ValueError as exc:
            raise InstallError(f"artifact path escapes package root: {relative!r}") from exc
        return candidate

    def _installed_manifest(self, name: str, version: str) -> ExtensionManifest:
        target = self._package_path(name, version)
        if not target.exists():
            raise InstallError(f"active pin is not installed: {name}@{version}")
        manifest = self._verify_installed_package(target)
        if manifest.name != name or manifest.version != version:
            raise InstallError(f"installed manifest coordinate mismatch at {target}")
        return manifest

    def _validate_active_graph(
        self,
        pins: Mapping[str, str],
        *,
        overrides: Mapping[tuple[str, str], ExtensionManifest] | None = None,
    ) -> dict[str, ExtensionManifest]:
        normalized = self._normalize_pins(pins)
        override_map = dict(overrides or {})
        manifests: dict[str, ExtensionManifest] = {}
        for name, version in sorted(normalized.items()):
            manifest = override_map.get((name, version))
            if manifest is None:
                manifest = self._installed_manifest(name, version)
            if manifest.name != name or manifest.version != version:
                raise InstallError(f"pin manifest mismatch for {name}@{version}")
            if not manifest.supports(self.os_name, self.arch):
                raise InstallError(
                    f"active package {manifest.coordinate} does not support "
                    f"{self.os_name}/{self.arch}"
                )
            manifests[name] = manifest

        graph: dict[str, tuple[str, ...]] = {}
        for name, manifest in sorted(manifests.items()):
            required_names: list[str] = []
            for dependency in manifest.dependencies:
                if dependency.optional:
                    continue
                pinned = normalized.get(dependency.name)
                if pinned is None:
                    raise InstallError(
                        f"active package {manifest.coordinate} requires unpinned "
                        f"dependency {dependency.name} {dependency.constraint}"
                    )
                if not version_satisfies(pinned, dependency.constraint):
                    raise InstallError(
                        f"active dependency conflict: {manifest.coordinate} requires "
                        f"{dependency.name} {dependency.constraint}, got {pinned}"
                    )
                required_names.append(dependency.name)
            graph[name] = tuple(sorted(required_names))

        visiting: list[str] = []
        visited: set[str] = set()

        def visit(name: str) -> None:
            if name in visited:
                return
            if name in visiting:
                start = visiting.index(name)
                raise InstallError(
                    "active dependency cycle: "
                    + " -> ".join(visiting[start:] + [name])
                )
            visiting.append(name)
            for dependency_name in graph[name]:
                visit(dependency_name)
            visiting.pop()
            visited.add(name)

        for package_name in sorted(graph):
            visit(package_name)
        return manifests

    @staticmethod
    def _normalize_pins(pins: Mapping[str, str]) -> dict[str, str]:
        if not isinstance(pins, Mapping):
            raise InstallError("pins must be a mapping")
        normalized: dict[str, str] = {}
        for name, version in pins.items():
            normalized_name, normalized_version = PackageStore._coordinate(
                str(name), str(version)
            )
            if normalized_name in normalized:
                raise InstallError(f"duplicate normalized pin: {normalized_name}")
            normalized[normalized_name] = normalized_version
        return dict(sorted(normalized.items()))

    def _commit_active(
        self,
        pins: Mapping[str, str],
        *,
        reason: str,
        rollback_target: int | None = None,
    ) -> int:
        normalized = self._normalize_pins(pins)
        manifests = self._validate_active_graph(normalized)
        current_generation, _ = self._read_active_records()
        generation = max([current_generation, *self._history_generations()], default=0) + 1
        records = {
            name: {
                "version": version,
                "manifest_digest": manifests[name].digest,
            }
            for name, version in normalized.items()
        }
        payload: dict[str, Any] = {
            "schema_version": STORE_STATE_SCHEMA_VERSION,
            "generation": generation,
            "previous_generation": current_generation,
            "created_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            "reason": reason,
            "platform": {"os": self.os_name, "arch": self.arch},
            "pins": records,
        }
        if rollback_target is not None:
            payload["rollback_target"] = rollback_target
        self._atomic_write_json(self._lock_path(generation), payload, require_absent=True)
        self._atomic_write_json(self._active_path, payload)
        return generation

    def _read_active_records(self) -> tuple[int, dict[str, dict[str, str]]]:
        if self._active_path.is_symlink():
            raise InstallError("active package state must not be a symlink")
        if not self._active_path.exists():
            return 0, {}
        payload = self._read_json(self._active_path)
        generation, records = self._decode_state(payload)
        lock_payload = self._read_json(self._lock_path(generation))
        lock_generation, lock_records = self._decode_state(lock_payload)
        if lock_generation != generation or lock_records != records or lock_payload != payload:
            raise InstallError("active package state does not match its lock generation")
        return generation, records

    def _read_lock_records(
        self, generation: int
    ) -> tuple[int, dict[str, dict[str, str]]]:
        payload = self._read_json(self._lock_path(generation))
        decoded_generation, records = self._decode_state(payload)
        if decoded_generation != generation:
            raise InstallError(
                f"lock filename generation {generation} does not match its payload"
            )
        return decoded_generation, records

    def _decode_state(
        self, payload: Mapping[str, Any]
    ) -> tuple[int, dict[str, dict[str, str]]]:
        if payload.get("schema_version") != STORE_STATE_SCHEMA_VERSION:
            raise InstallError("unsupported or missing package-store state schema")
        generation = payload.get("generation")
        if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
            raise InstallError("package-store generation must be a positive integer")
        raw_pins = payload.get("pins")
        if not isinstance(raw_pins, Mapping):
            raise InstallError("package-store pins must be an object")
        records: dict[str, dict[str, str]] = {}
        for raw_name, raw_record in raw_pins.items():
            if not isinstance(raw_record, Mapping):
                raise InstallError("package-store pin records must be objects")
            name, version = self._coordinate(
                str(raw_name), str(raw_record.get("version", ""))
            )
            if name in records:
                raise InstallError(f"duplicate normalized active pin: {name}")
            digest = raw_record.get("manifest_digest")
            try:
                digest = normalize_sha256(digest)
            except ManifestError as exc:
                raise InstallError(f"invalid manifest digest in active pin: {name}") from exc
            records[name] = {"version": version, "manifest_digest": digest}
        return generation, dict(sorted(records.items()))

    def _history_generations(self) -> list[int]:
        generations: list[int] = []
        for path in sorted(self._locks.iterdir()):
            if path.is_symlink() or not path.is_file():
                raise InstallError(f"unsafe package lock history entry: {path.name}")
            if path.suffix != ".json" or not path.stem.isdigit():
                raise InstallError(f"unexpected package lock history entry: {path.name}")
            generations.append(int(path.stem))
        if len(generations) != len(set(generations)):
            raise InstallError("duplicate package lock generations")
        return sorted(generations)

    def _committed_generations(self) -> list[int]:
        """Return the active generation lineage, excluding orphan lock writes."""

        current, _ = self._read_active_records()
        if current == 0:
            return []
        generations: list[int] = []
        seen: set[int] = set()
        generation = current
        while generation:
            if generation in seen:
                raise InstallError("package lock history contains a generation cycle")
            seen.add(generation)
            payload = self._read_json(self._lock_path(generation))
            decoded_generation, _ = self._decode_state(payload)
            if decoded_generation != generation:
                raise InstallError(
                    f"lock filename generation {generation} does not match its payload"
                )
            generations.append(generation)
            previous = payload.get("previous_generation")
            if (
                isinstance(previous, bool)
                or not isinstance(previous, int)
                or previous < 0
                or previous >= generation
            ):
                raise InstallError(
                    f"invalid previous_generation in lock {generation}: {previous!r}"
                )
            generation = previous
        return generations

    def _lock_path(self, generation: int) -> Path:
        return self._locks / f"{generation:020d}.json"

    @staticmethod
    def _read_json(path: Path) -> dict[str, Any]:
        if path.is_symlink() or not path.is_file():
            raise InstallError(f"state file is missing or unsafe: {path}")
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise InstallError(f"invalid state file {path.name}: {exc}") from exc
        if not isinstance(value, dict):
            raise InstallError(f"state file must contain an object: {path.name}")
        return value

    @staticmethod
    def _write_json_file(path: Path, payload: Mapping[str, Any]) -> None:
        encoded = (
            json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            + "\n"
        ).encode("utf-8")
        with path.open("xb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())

    def _atomic_write_json(
        self,
        path: Path,
        payload: Mapping[str, Any],
        *,
        require_absent: bool = False,
    ) -> None:
        if path.exists() and path.is_symlink():
            raise InstallError(f"refusing to replace symlink state path: {path}")
        if require_absent and path.exists():
            raise InstallError(f"lock generation already exists: {path.name}")
        encoded = (
            json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            + "\n"
        ).encode("utf-8")
        file_descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", dir=path.parent
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(file_descriptor, "wb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            if require_absent and path.exists():
                raise InstallError(f"lock generation appeared concurrently: {path.name}")
            os.replace(temporary, path)
            self._fsync_directory(path.parent)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError:
            return
        try:
            os.fsync(descriptor)
        except OSError:
            pass
        finally:
            os.close(descriptor)


__all__ = [
    "DEFAULT_MANIFEST_FILENAME",
    "INSTALL_RECEIPT_SCHEMA_VERSION",
    "is_portable_filesystem_component",
    "STORE_STATE_SCHEMA_VERSION",
    "InstallError",
    "InstallReceipt",
    "PackageStore",
]
