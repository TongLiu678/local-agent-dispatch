"""Portable package manifests, resolution, and non-executing installation."""

from .catalog import PackageCatalog, ResolutionError, ResolutionResult
from .manifest import (
    ArtifactRecord,
    Dependency,
    ExtensionManifest,
    ManifestError,
    PlatformConstraint,
    current_platform,
    load_manifest_json,
    version_satisfies,
)
from .store import InstallError, InstallReceipt, PackageStore
from .lockfile import (
    PACKAGE_LOCK_FORMAT_VERSION,
    PACKAGE_LOCK_SCHEMA_VERSION,
    LockError,
    LockedPackage,
    LockVerification,
    PackageLock,
    catalog_snapshot_digest,
    load_lock_json,
    resolve_to_lock,
    verify_lock,
)

__all__ = [
    "ArtifactRecord",
    "Dependency",
    "ExtensionManifest",
    "InstallError",
    "InstallReceipt",
    "LockError",
    "LockedPackage",
    "LockVerification",
    "ManifestError",
    "PACKAGE_LOCK_FORMAT_VERSION",
    "PACKAGE_LOCK_SCHEMA_VERSION",
    "PackageCatalog",
    "PackageLock",
    "PackageStore",
    "PlatformConstraint",
    "ResolutionError",
    "ResolutionResult",
    "current_platform",
    "catalog_snapshot_digest",
    "load_lock_json",
    "load_manifest_json",
    "resolve_to_lock",
    "verify_lock",
    "version_satisfies",
]
