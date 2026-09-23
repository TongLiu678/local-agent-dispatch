"""Canonical, provider-free lockfiles for local LAD package catalogs.

A package lock is data, not an execution plan.  Resolving, parsing, hashing,
and verifying one never imports or invokes a package entrypoint and never
contacts a provider or network registry.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .catalog import PackageCatalog, ResolutionError
from .manifest import (
    PACKAGE_KINDS,
    Dependency,
    ExtensionManifest,
    ManifestError,
    PlatformConstraint,
    _name,
    _version_tuple,
    normalize_sha256,
)
from .store import InstallError, PackageStore


PACKAGE_LOCK_SCHEMA_VERSION = 1
PACKAGE_LOCK_FORMAT_VERSION = "1"

_LOCK_FIELDS = frozenset(
    {
        "schema_version",
        "lock_version",
        "catalog_snapshot_digest",
        "platform",
        "include_optional",
        "roots",
        "packages",
    }
)
_LOCKED_PACKAGE_FIELDS = frozenset(
    {"name", "version", "manifest_digest", "kind", "platforms"}
)


class LockError(ValueError):
    """Raised when a package lock cannot be trusted or reproduced."""


def _strict_mapping(
    value: Any,
    label: str,
    *,
    allowed: frozenset[str],
    required: frozenset[str] | None = None,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise LockError(f"{label} must be an object")
    payload = dict(value)
    unknown = sorted(str(key) for key in payload if key not in allowed)
    if unknown:
        raise LockError(f"{label} contains unknown fields: {', '.join(unknown)}")
    missing = sorted((required or allowed) - payload.keys())
    if missing:
        raise LockError(f"{label} is missing required fields: {', '.join(missing)}")
    return payload


def _array(value: Any, label: str) -> tuple[Any, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise LockError(f"{label} must be an array")
    return tuple(value)


def _digest(value: Any, label: str) -> str:
    try:
        return normalize_sha256(value)
    except ManifestError as exc:
        raise LockError(f"invalid {label}: {exc}") from exc


def _canonical_bytes(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


@dataclass(frozen=True)
class LockedPackage:
    """The immutable manifest identity recorded for one resolved package."""

    name: str
    version: str
    manifest_digest: str
    kind: str
    platforms: tuple[PlatformConstraint, ...] = ()

    def __post_init__(self) -> None:
        try:
            name = _name(self.name, "locked package name")
            _version_tuple(self.version)
            kind = _name(self.kind, "locked package kind")
        except (ManifestError, TypeError) as exc:
            raise LockError(str(exc)) from exc
        if kind not in PACKAGE_KINDS:
            raise LockError(f"locked package kind must be one of {list(PACKAGE_KINDS)}")
        platforms = tuple(self.platforms)
        if any(not isinstance(item, PlatformConstraint) for item in platforms):
            raise LockError("locked package platforms must contain platform objects")
        platform_keys = [(item.os, item.arch) for item in platforms]
        if len(platform_keys) != len(set(platform_keys)):
            raise LockError("locked package platforms must not contain duplicates")
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "kind", kind)
        object.__setattr__(
            self,
            "manifest_digest",
            _digest(self.manifest_digest, "manifest digest"),
        )
        object.__setattr__(
            self,
            "platforms",
            tuple(sorted(platforms, key=lambda item: (item.os, item.arch))),
        )

    @classmethod
    def from_manifest(cls, manifest: ExtensionManifest) -> "LockedPackage":
        if not isinstance(manifest, ExtensionManifest):
            raise TypeError("locked packages can be created only from ExtensionManifest values")
        return cls(
            name=manifest.name,
            version=manifest.version,
            manifest_digest=manifest.digest,
            kind=manifest.kind,
            platforms=manifest.platforms,
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "LockedPackage":
        payload = _strict_mapping(
            value,
            "locked package",
            allowed=_LOCKED_PACKAGE_FIELDS,
        )
        raw_platforms = _array(payload["platforms"], "locked package platforms")
        try:
            platforms = tuple(PlatformConstraint.from_dict(item) for item in raw_platforms)
        except (ManifestError, TypeError) as exc:
            raise LockError(f"invalid locked package platform: {exc}") from exc
        return cls(
            name=payload["name"],
            version=payload["version"],
            manifest_digest=payload["manifest_digest"],
            kind=payload["kind"],
            platforms=platforms,
        )

    def supports(self, os_name: str, arch: str) -> bool:
        return not self.platforms or any(
            platform.matches(os_name, arch) for platform in self.platforms
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "manifest_digest": self.manifest_digest,
            "kind": self.kind,
            "platforms": [item.to_dict() for item in self.platforms],
        }


@dataclass(frozen=True)
class PackageLock:
    """One canonical exact resolution bound to a complete catalog snapshot."""

    roots: tuple[Dependency, ...]
    packages: tuple[LockedPackage, ...]
    os_name: str
    arch: str
    include_optional: bool
    catalog_snapshot_digest: str
    schema_version: int = PACKAGE_LOCK_SCHEMA_VERSION
    lock_version: str = PACKAGE_LOCK_FORMAT_VERSION

    def __post_init__(self) -> None:
        if (
            isinstance(self.schema_version, bool)
            or not isinstance(self.schema_version, int)
            or self.schema_version != PACKAGE_LOCK_SCHEMA_VERSION
        ):
            raise LockError(
                f"unsupported package lock schema_version {self.schema_version!r}; "
                f"expected {PACKAGE_LOCK_SCHEMA_VERSION}"
            )
        if self.lock_version != PACKAGE_LOCK_FORMAT_VERSION:
            raise LockError(
                f"unsupported package lock version {self.lock_version!r}; "
                f"expected {PACKAGE_LOCK_FORMAT_VERSION!r}"
            )
        if type(self.include_optional) is not bool:
            raise LockError("include_optional must be a boolean")
        try:
            os_name = _name(self.os_name, "lock platform os")
            arch = _name(self.arch, "lock platform arch")
        except ManifestError as exc:
            raise LockError(str(exc)) from exc
        if os_name == "any" or arch == "any":
            raise LockError("lock target platform must be concrete, not 'any'")

        roots = tuple(self.roots)
        if not roots or any(not isinstance(item, Dependency) for item in roots):
            raise LockError("roots must contain at least one Dependency")
        root_names = [item.name for item in roots]
        if len(root_names) != len(set(root_names)):
            raise LockError("root requirement names must be unique")

        packages = tuple(self.packages)
        if not packages or any(not isinstance(item, LockedPackage) for item in packages):
            raise LockError("packages must contain at least one LockedPackage")
        package_names = [item.name for item in packages]
        if len(package_names) != len(set(package_names)):
            raise LockError("a package lock cannot contain two versions of one package")
        missing_roots = sorted(set(root_names) - set(package_names))
        if missing_roots:
            raise LockError("root requirements are not resolved: " + ", ".join(missing_roots))
        unsupported = sorted(
            item.name for item in packages if not item.supports(os_name, arch)
        )
        if unsupported:
            raise LockError(
                f"locked packages do not support {os_name}/{arch}: "
                + ", ".join(unsupported)
            )

        object.__setattr__(self, "os_name", os_name)
        object.__setattr__(self, "arch", arch)
        object.__setattr__(
            self,
            "roots",
            tuple(sorted(roots, key=lambda item: (item.name, item.constraint, item.optional))),
        )
        object.__setattr__(self, "packages", tuple(sorted(packages, key=lambda item: item.name)))
        object.__setattr__(
            self,
            "catalog_snapshot_digest",
            _digest(self.catalog_snapshot_digest, "catalog snapshot digest"),
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "PackageLock":
        payload = _strict_mapping(value, "package lock", allowed=_LOCK_FIELDS)
        platform = _strict_mapping(
            payload["platform"],
            "package lock platform",
            allowed=frozenset({"os", "arch"}),
        )
        raw_roots = _array(payload["roots"], "package lock roots")
        raw_packages = _array(payload["packages"], "package lock packages")
        try:
            roots = tuple(Dependency.from_dict(item) for item in raw_roots)
        except (ManifestError, TypeError) as exc:
            raise LockError(f"invalid root requirement: {exc}") from exc
        return cls(
            schema_version=payload["schema_version"],
            lock_version=payload["lock_version"],
            catalog_snapshot_digest=payload["catalog_snapshot_digest"],
            os_name=platform["os"],
            arch=platform["arch"],
            include_optional=payload["include_optional"],
            roots=roots,
            packages=tuple(LockedPackage.from_dict(item) for item in raw_packages),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "lock_version": self.lock_version,
            "catalog_snapshot_digest": self.catalog_snapshot_digest,
            "platform": {"os": self.os_name, "arch": self.arch},
            "include_optional": self.include_optional,
            "roots": [item.to_dict() for item in self.roots],
            "packages": [item.to_dict() for item in self.packages],
        }

    def canonical_bytes(self) -> bytes:
        """Return the one canonical UTF-8 representation used for hashing."""

        return _canonical_bytes(self.to_dict())

    def to_json(self) -> str:
        return self.canonical_bytes().decode("utf-8")

    @property
    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(self.canonical_bytes()).hexdigest()


@dataclass(frozen=True)
class LockVerification:
    """Positive evidence returned only after every requested check succeeds."""

    lock_digest: str
    catalog_snapshot_digest: str
    packages_verified: int
    catalog_verified: bool = True
    store_verified: bool = False
    artifacts_verified: bool = False
    entrypoint_executed: bool = False
    network_accessed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "lock_digest": self.lock_digest,
            "catalog_snapshot_digest": self.catalog_snapshot_digest,
            "packages_verified": self.packages_verified,
            "catalog_verified": self.catalog_verified,
            "store_verified": self.store_verified,
            "artifacts_verified": self.artifacts_verified,
            "entrypoint_executed": self.entrypoint_executed,
            "network_accessed": self.network_accessed,
        }


def _catalog_digest_from_manifests(manifests: Sequence[ExtensionManifest]) -> str:
    rows = sorted(
        (
            {
                "name": manifest.name,
                "version": manifest.version,
                "manifest_digest": manifest.digest,
            }
            for manifest in manifests
        ),
        key=lambda item: (item["name"], item["version"], item["manifest_digest"]),
    )
    payload = {"schema_version": 1, "manifests": rows}
    return "sha256:" + hashlib.sha256(_canonical_bytes(payload)).hexdigest()


def catalog_snapshot_digest(catalog: PackageCatalog) -> str:
    """Hash every exact manifest identity in a deterministic catalog snapshot."""

    if not isinstance(catalog, PackageCatalog):
        raise TypeError("catalog must be a PackageCatalog")
    return _catalog_digest_from_manifests(catalog.manifests())


def resolve_to_lock(
    catalog: PackageCatalog,
    requirements: Sequence[Dependency] | Mapping[str, str],
    *,
    os_name: str | None = None,
    arch: str | None = None,
    include_optional: bool = False,
) -> PackageLock:
    """Resolve one immutable catalog snapshot to a canonical exact lock."""

    if not isinstance(catalog, PackageCatalog):
        raise TypeError("catalog must be a PackageCatalog")
    if type(include_optional) is not bool:
        raise LockError("include_optional must be a boolean")
    snapshot = catalog.manifests()
    snapshot_catalog = PackageCatalog(snapshot)
    try:
        result = snapshot_catalog.resolve(
            requirements,
            os_name=os_name,
            arch=arch,
            include_optional=include_optional,
        )
    except (ManifestError, ResolutionError, TypeError) as exc:
        raise LockError(f"cannot resolve package lock: {exc}") from exc
    try:
        return PackageLock(
            roots=result.roots,
            packages=tuple(LockedPackage.from_manifest(item) for item in result.packages),
            os_name=result.os_name,
            arch=result.arch,
            include_optional=result.include_optional,
            catalog_snapshot_digest=_catalog_digest_from_manifests(snapshot),
        )
    except LockError as exc:
        raise LockError(f"cannot create package lock: {exc}") from exc


def load_lock_json(value: str | bytes | bytearray) -> PackageLock:
    """Decode a v1 package lock while rejecting duplicate keys at every depth."""

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, child in pairs:
            if key in result:
                raise LockError(f"duplicate JSON key: {key}")
            result[key] = child
        return result

    def reject_constant(value: str) -> None:
        raise LockError(f"non-finite JSON number is not allowed: {value}")

    try:
        payload = json.loads(
            value,
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (json.JSONDecodeError, UnicodeError, TypeError) as exc:
        raise LockError(f"invalid package lock JSON: {exc}") from exc
    return PackageLock.from_dict(payload)


def verify_lock(
    package_lock: PackageLock,
    catalog: PackageCatalog,
    *,
    store: PackageStore | None = None,
) -> LockVerification:
    """Reproduce a lock locally and optionally verify every installed artifact."""

    if not isinstance(package_lock, PackageLock):
        raise TypeError("package_lock must be a PackageLock")
    if not isinstance(catalog, PackageCatalog):
        raise TypeError("catalog must be a PackageCatalog")
    snapshot = catalog.manifests()
    actual_catalog_digest = _catalog_digest_from_manifests(snapshot)
    if actual_catalog_digest != package_lock.catalog_snapshot_digest:
        raise LockError(
            "catalog snapshot digest mismatch: lock was resolved against a different catalog"
        )
    expected = resolve_to_lock(
        PackageCatalog(snapshot),
        package_lock.roots,
        os_name=package_lock.os_name,
        arch=package_lock.arch,
        include_optional=package_lock.include_optional,
    )
    if expected.to_dict() != package_lock.to_dict():
        raise LockError("locked resolution does not match the local catalog")

    if store is not None:
        if not isinstance(store, PackageStore):
            raise TypeError("store must be a PackageStore")
        if store.os_name != package_lock.os_name or store.arch != package_lock.arch:
            raise LockError(
                "package store platform does not match the lock target platform"
            )
        for item in package_lock.packages:
            try:
                manifest = store.verify_installed(item.name, item.version)
            except InstallError as exc:
                raise LockError(
                    f"installed package verification failed for {item.name}@{item.version}: {exc}"
                ) from exc
            if manifest.digest != item.manifest_digest:
                raise LockError(
                    f"installed manifest digest mismatch for {item.name}@{item.version}"
                )
            if manifest.kind != item.kind:
                raise LockError(f"installed package kind mismatch for {item.name}@{item.version}")
            installed_platforms = tuple(
                sorted(manifest.platforms, key=lambda platform: (platform.os, platform.arch))
            )
            if installed_platforms != item.platforms:
                raise LockError(
                    f"installed platform constraints mismatch for {item.name}@{item.version}"
                )

    return LockVerification(
        lock_digest=package_lock.digest,
        catalog_snapshot_digest=actual_catalog_digest,
        packages_verified=len(package_lock.packages),
        store_verified=store is not None,
        artifacts_verified=store is not None,
    )


__all__ = [
    "PACKAGE_LOCK_FORMAT_VERSION",
    "PACKAGE_LOCK_SCHEMA_VERSION",
    "LockError",
    "LockedPackage",
    "LockVerification",
    "PackageLock",
    "catalog_snapshot_digest",
    "load_lock_json",
    "resolve_to_lock",
    "verify_lock",
]
