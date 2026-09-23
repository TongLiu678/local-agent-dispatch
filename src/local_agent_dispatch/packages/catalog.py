"""Deterministic, provider-free dependency resolution for LAD packages."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from functools import cmp_to_key
from typing import Any

from .manifest import (
    Dependency,
    ExtensionManifest,
    _compare_versions,
    _name,
    current_platform,
    version_satisfies,
)


RESOLUTION_SCHEMA_VERSION = 1


class ResolutionError(ValueError):
    """Raised when no complete, acyclic, platform-compatible lock exists."""


@dataclass(frozen=True)
class ResolutionResult:
    """One exact, dependency-first package lock produced by the catalog."""

    roots: tuple[Dependency, ...]
    packages: tuple[ExtensionManifest, ...]
    os_name: str
    arch: str
    include_optional: bool = False
    schema_version: int = RESOLUTION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != RESOLUTION_SCHEMA_VERSION:
            raise ResolutionError(
                f"unsupported resolution schema_version: {self.schema_version!r}"
            )
        object.__setattr__(self, "roots", tuple(self.roots))
        object.__setattr__(self, "packages", tuple(self.packages))
        names = [manifest.name for manifest in self.packages]
        if len(names) != len(set(names)):
            raise ResolutionError("a resolution cannot contain two versions of one package")

    @property
    def pins(self) -> dict[str, str]:
        """Return exact name-to-version pins in deterministic package order."""

        return {manifest.name: manifest.version for manifest in self.packages}

    def to_lock_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable exact lock without executable objects."""

        selected = {manifest.name: manifest for manifest in self.packages}
        rows: list[dict[str, Any]] = []
        for manifest in self.packages:
            dependencies = []
            for dependency in sorted(manifest.dependencies, key=lambda item: item.name):
                resolved = selected.get(dependency.name)
                if resolved is None:
                    continue
                dependencies.append(
                    {
                        "name": dependency.name,
                        "version": resolved.version,
                        "manifest_digest": resolved.digest,
                    }
                )
            rows.append(
                {
                    "name": manifest.name,
                    "version": manifest.version,
                    "kind": manifest.kind,
                    "manifest_digest": manifest.digest,
                    "dependencies": dependencies,
                }
            )
        return {
            "schema_version": self.schema_version,
            "platform": {"os": self.os_name, "arch": self.arch},
            "include_optional": self.include_optional,
            "roots": [dependency.to_dict() for dependency in self.roots],
            "packages": rows,
        }


class PackageCatalog:
    """In-memory manifest catalog with deterministic backtracking resolution.

    Catalog construction and resolution are data-only operations. They never
    import entrypoints, inspect artifacts, contact a registry, or mutate an
    installation store.
    """

    def __init__(self, manifests: Sequence[ExtensionManifest] = ()) -> None:
        self._manifests: dict[str, dict[str, ExtensionManifest]] = {}
        for manifest in manifests:
            self.add(manifest)

    def add(self, manifest: ExtensionManifest) -> None:
        if not isinstance(manifest, ExtensionManifest):
            raise TypeError("catalog entries must be ExtensionManifest values")
        versions = self._manifests.setdefault(manifest.name, {})
        existing = versions.get(manifest.version)
        if existing is not None and existing.digest != manifest.digest:
            raise ResolutionError(
                f"catalog coordinate {manifest.coordinate} has conflicting manifests"
            )
        versions[manifest.version] = manifest

    def available(self, name: str) -> tuple[ExtensionManifest, ...]:
        """Return all versions for ``name`` in descending SemVer order."""

        normalized = _name(name, "package name")
        rows = tuple(self._manifests.get(normalized, {}).values())
        return tuple(
            sorted(
                rows,
                key=cmp_to_key(
                    lambda left, right: self._compare_manifests(left, right)
                ),
                reverse=True,
            )
        )

    def manifests(self) -> tuple[ExtensionManifest, ...]:
        """Return a deterministic immutable snapshot of every catalog entry.

        Exposing a tuple rather than the backing dictionaries lets the lockfile
        layer commit to the exact catalog used for resolution without allowing
        callers to mutate catalog state accidentally.
        """

        return tuple(
            manifest
            for name in sorted(self._manifests)
            for manifest in self.available(name)
        )

    @staticmethod
    def _compare_manifests(left: ExtensionManifest, right: ExtensionManifest) -> int:
        comparison = _compare_versions(left.version, right.version)
        if comparison:
            return comparison
        # SemVer build metadata has equal precedence. Use the full version as
        # a deterministic package-manager tie-break independent of insertion.
        return (left.version > right.version) - (left.version < right.version)

    def resolve(
        self,
        requirements: Sequence[Dependency] | Mapping[str, str],
        *,
        os_name: str | None = None,
        arch: str | None = None,
        include_optional: bool = False,
    ) -> ResolutionResult:
        """Resolve all transitive dependencies to one exact deterministic lock.

        Highest compatible versions are tried first, but the solver
        backtracks when a later constraint conflicts. Cycles are invalid even
        when every involved version constraint would otherwise be satisfied.
        """

        if isinstance(requirements, Mapping):
            roots = tuple(
                Dependency(name=str(name), constraint=str(constraint))
                for name, constraint in sorted(requirements.items())
            )
        else:
            roots = tuple(requirements)
            if any(not isinstance(item, Dependency) for item in roots):
                raise TypeError("requirements must contain only Dependency values")
            roots = tuple(sorted(roots, key=lambda item: (item.name, item.constraint)))

        detected_os, detected_arch = current_platform()
        target_os = (os_name or detected_os).strip().lower()
        target_arch = (arch or detected_arch).strip().lower()
        if not target_os or not target_arch:
            raise ResolutionError("target platform os and arch must be non-empty")

        constraints: dict[str, tuple[tuple[str, str], ...]] = {}
        for root in roots:
            constraints[root.name] = constraints.get(root.name, ()) + (
                (root.constraint, "root"),
            )

        failures: set[str] = set()
        resolved = self._search(
            selected={},
            constraints=constraints,
            os_name=target_os,
            arch=target_arch,
            include_optional=include_optional,
            failures=failures,
        )
        if resolved is None:
            details = "; ".join(sorted(failures)[:8]) or "no complete solution"
            raise ResolutionError(f"package resolution failed: {details}")
        selected, order = resolved
        return ResolutionResult(
            roots=roots,
            packages=tuple(selected[name] for name in order),
            os_name=target_os,
            arch=target_arch,
            include_optional=include_optional,
        )

    def _search(
        self,
        *,
        selected: dict[str, ExtensionManifest],
        constraints: dict[str, tuple[tuple[str, str], ...]],
        os_name: str,
        arch: str,
        include_optional: bool,
        failures: set[str],
    ) -> tuple[dict[str, ExtensionManifest], tuple[str, ...]] | None:
        for name in sorted(selected):
            manifest = selected[name]
            required = constraints.get(name, ())
            if not all(version_satisfies(manifest.version, value) for value, _ in required):
                rendered = ", ".join(
                    f"{value} from {source}" for value, source in required
                )
                failures.add(
                    f"conflict for {name}: selected {manifest.version}, required {rendered}"
                )
                return None

        unresolved = sorted(name for name in constraints if name not in selected)
        if not unresolved:
            try:
                order = self._dependency_order(selected, include_optional=include_optional)
            except ResolutionError as exc:
                failures.add(str(exc))
                return None
            return dict(selected), order

        name = unresolved[0]
        required = constraints[name]
        all_versions = self.available(name)
        if not all_versions:
            failures.add(f"missing package {name}")
            return None
        matching = tuple(
            manifest
            for manifest in all_versions
            if all(version_satisfies(manifest.version, value) for value, _ in required)
        )
        if not matching:
            rendered = ", ".join(
                f"{value} from {source}" for value, source in required
            )
            failures.add(f"conflict for {name}: no version satisfies {rendered}")
            return None
        candidates = tuple(
            manifest for manifest in matching if manifest.supports(os_name, arch)
        )
        if not candidates:
            versions = ", ".join(manifest.version for manifest in matching)
            failures.add(
                f"platform mismatch for {name} ({versions}) on {os_name}/{arch}"
            )
            return None

        for candidate in candidates:
            next_selected = dict(selected)
            next_selected[name] = candidate
            next_constraints = dict(constraints)
            for dependency in sorted(candidate.dependencies, key=lambda item: item.name):
                if dependency.optional and not include_optional:
                    continue
                source = candidate.coordinate
                next_constraints[dependency.name] = next_constraints.get(
                    dependency.name, ()
                ) + ((dependency.constraint, source),)
            result = self._search(
                selected=next_selected,
                constraints=next_constraints,
                os_name=os_name,
                arch=arch,
                include_optional=include_optional,
                failures=failures,
            )
            if result is not None:
                return result
        return None

    @staticmethod
    def _dependency_order(
        selected: Mapping[str, ExtensionManifest], *, include_optional: bool
    ) -> tuple[str, ...]:
        """Return dependency-first order and reject every dependency cycle."""

        visiting: list[str] = []
        visited: set[str] = set()
        order: list[str] = []

        def visit(name: str) -> None:
            if name in visited:
                return
            if name in visiting:
                start = visiting.index(name)
                cycle = visiting[start:] + [name]
                raise ResolutionError("dependency cycle: " + " -> ".join(cycle))
            visiting.append(name)
            manifest = selected[name]
            dependencies = sorted(manifest.dependencies, key=lambda item: item.name)
            for dependency in dependencies:
                if dependency.optional and not include_optional:
                    continue
                if dependency.name in selected:
                    visit(dependency.name)
            visiting.pop()
            visited.add(name)
            order.append(name)

        for package_name in sorted(selected):
            visit(package_name)
        return tuple(order)


__all__ = [
    "RESOLUTION_SCHEMA_VERSION",
    "PackageCatalog",
    "ResolutionError",
    "ResolutionResult",
]
