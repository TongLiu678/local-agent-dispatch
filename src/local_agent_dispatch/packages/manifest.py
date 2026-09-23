"""Strict, provider-free manifests for dispatch ecosystem packages.

The package layer is intentionally separate from Python packaging.  A package
may describe a Python adapter, a native harness executable, a container image,
an endpoint contract, or a bundle of other packages.  Parsing or installing a
manifest never imports its entrypoint and never starts its executable.
"""

from __future__ import annotations

import hashlib
import json
import platform
import re
import sys
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any, Mapping, Sequence

from ..plugins.protocols import PLUGIN_KINDS


PACKAGE_MANIFEST_SCHEMA_VERSION = 1
PACKAGE_API_VERSION = "1"
PACKAGE_KINDS = (*PLUGIN_KINDS, "bundle", "skill")

_NAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$")
_VERSION_RE = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
_SHA256_RE = re.compile(r"^(?:sha256:)?([0-9a-f]{64})$")
_ENTRYPOINT_TYPES = frozenset({"python", "executable", "container", "endpoint", "none"})
_CONTAINER_ENTRYPOINT_RE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
_PYTHON_ENTRYPOINT_RE = re.compile(
    r"(?P<module>[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)"
    r":(?P<attribute>[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)$"
)
_PERMISSIONS = frozenset(
    {
        "network",
        "provider_prompt",
        "subprocess",
        "workspace_read",
        "workspace_write",
        "host_probe",
        "remote_transport",
        "credential_reference",
    }
)
_WINDOWS_FORBIDDEN_CHARACTERS = frozenset('<>:"/\\|?*')
_WINDOWS_RESERVED_NAMES = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        "CLOCK$",
        "CONIN$",
        "CONOUT$",
        *(f"COM{index}" for index in range(1, 10)),
        *(f"LPT{index}" for index in range(1, 10)),
        *(f"COM{index}" for index in ("¹", "²", "³")),
        *(f"LPT{index}" for index in ("¹", "²", "³")),
    }
)
_MANIFEST_FIELDS = frozenset(
    {
        "schema_version",
        "api_version",
        "name",
        "version",
        "kind",
        "description",
        "entrypoint",
        "capabilities",
        "platforms",
        "dependencies",
        "permissions",
        "artifacts",
        "publisher",
        "metadata",
    }
)
_REQUIRED_MANIFEST_FIELDS = frozenset(
    {"schema_version", "api_version", "name", "version", "kind", "entrypoint", "artifacts"}
)


class ManifestError(ValueError):
    """Raised when untrusted manifest data violates the v1 contract."""


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ManifestError(f"{label} must be an object")
    return dict(value)


def _strict_mapping(
    value: Any,
    label: str,
    *,
    allowed: frozenset[str],
    required: frozenset[str],
) -> dict[str, Any]:
    result = _mapping(value, label)
    unknown = sorted(str(key) for key in result if key not in allowed)
    if unknown:
        raise ManifestError(f"{label} contains unknown fields: {', '.join(unknown)}")
    missing = sorted(required - result.keys())
    if missing:
        raise ManifestError(f"{label} is missing required fields: {', '.join(missing)}")
    return result


def _nonempty(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ManifestError(f"{label} must be a non-empty string")
    return value.strip()


def _name(value: Any, label: str = "name") -> str:
    text = _nonempty(value, label).lower()
    if not _NAME_RE.fullmatch(text):
        raise ManifestError(f"{label} must match {_NAME_RE.pattern}")
    return text


def is_portable_filesystem_component(value: str) -> bool:
    """Return whether *value* is one filename on every supported host."""

    if not value or value in {".", ".."} or value.rstrip(" .") != value:
        return False
    if any(
        character in _WINDOWS_FORBIDDEN_CHARACTERS or ord(character) < 32
        for character in value
    ):
        return False
    return value.split(".", 1)[0].upper() not in _WINDOWS_RESERVED_NAMES


def _package_name(value: Any, label: str = "name") -> str:
    text = _name(value, label)
    if not is_portable_filesystem_component(text):
        raise ManifestError(f"{label} must be a portable filesystem component")
    return text


def normalize_sha256(value: Any) -> str:
    text = _nonempty(value, "sha256").lower()
    match = _SHA256_RE.fullmatch(text)
    if not match:
        raise ManifestError("sha256 must contain exactly 64 lowercase hex characters")
    return "sha256:" + match.group(1)


def safe_artifact_path(value: Any) -> str:
    text = _nonempty(value, "artifact path")
    if "\\" in text:
        raise ManifestError("artifact path must use portable '/' separators")
    path = PurePosixPath(text)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ManifestError(f"artifact path must be normalized and relative: {text!r}")
    normalized = path.as_posix()
    if normalized != text:
        raise ManifestError(f"artifact path is not normalized: {text!r}")
    if any(not is_portable_filesystem_component(part) for part in path.parts):
        raise ManifestError(f"artifact path is not portable: {text!r}")
    return normalized


@dataclass(frozen=True)
class PlatformConstraint:
    os: str
    arch: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "os", _name(self.os, "platform os"))
        object.__setattr__(self, "arch", _name(self.arch, "platform arch"))

    def matches(self, os_name: str, arch: str) -> bool:
        return self.os in {"any", os_name.lower()} and self.arch in {"any", arch.lower()}

    def to_dict(self) -> dict[str, str]:
        return {"os": self.os, "arch": self.arch}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "PlatformConstraint":
        payload = _strict_mapping(
            value,
            "platform",
            allowed=frozenset({"os", "arch"}),
            required=frozenset({"os", "arch"}),
        )
        return cls(os=payload["os"], arch=payload["arch"])


@dataclass(frozen=True)
class Dependency:
    name: str
    constraint: str = "*"
    optional: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "name", _package_name(self.name, "dependency name")
        )
        text = _nonempty(self.constraint, "dependency constraint")
        if type(self.optional) is not bool:
            raise ManifestError("dependency optional must be a boolean")
        # Parse eagerly so a malformed constraint cannot enter a lock plan.
        version_satisfies("0.0.0", text)
        object.__setattr__(self, "constraint", text)

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "constraint": self.constraint, "optional": self.optional}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Dependency":
        payload = _strict_mapping(
            value,
            "dependency",
            allowed=frozenset({"name", "constraint", "optional"}),
            required=frozenset({"name", "constraint", "optional"}),
        )
        return cls(
            name=payload["name"],
            constraint=payload["constraint"],
            optional=payload["optional"],
        )


@dataclass(frozen=True)
class ArtifactRecord:
    path: str
    sha256: str
    size: int
    executable: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", safe_artifact_path(self.path))
        object.__setattr__(self, "sha256", normalize_sha256(self.sha256))
        if isinstance(self.size, bool) or not isinstance(self.size, int) or self.size < 0:
            raise ManifestError("artifact size must be a non-negative integer")
        if type(self.executable) is not bool:
            raise ManifestError("artifact executable must be a boolean")

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
            "executable": self.executable,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ArtifactRecord":
        payload = _strict_mapping(
            value,
            "artifact",
            allowed=frozenset({"path", "sha256", "size", "executable"}),
            required=frozenset({"path", "sha256", "size", "executable"}),
        )
        return cls(
            path=payload["path"],
            sha256=payload["sha256"],
            size=payload["size"],
            executable=payload["executable"],
        )


@dataclass(frozen=True)
class ExtensionManifest:
    name: str
    version: str
    kind: str
    entrypoint_type: str
    entrypoint: str | None
    artifacts: tuple[ArtifactRecord, ...]
    schema_version: int = PACKAGE_MANIFEST_SCHEMA_VERSION
    api_version: str = PACKAGE_API_VERSION
    description: str = ""
    capabilities: tuple[str, ...] = ()
    platforms: tuple[PlatformConstraint, ...] = ()
    dependencies: tuple[Dependency, ...] = ()
    permissions: tuple[str, ...] = ()
    publisher: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if (
            isinstance(self.schema_version, bool)
            or not isinstance(self.schema_version, int)
            or self.schema_version != PACKAGE_MANIFEST_SCHEMA_VERSION
        ):
            raise ManifestError(
                f"unsupported package schema_version {self.schema_version!r}; "
                f"expected {PACKAGE_MANIFEST_SCHEMA_VERSION}"
            )
        if self.api_version != PACKAGE_API_VERSION:
            raise ManifestError(
                f"unsupported package api_version {self.api_version!r}; "
                f"expected {PACKAGE_API_VERSION!r}"
            )
        object.__setattr__(self, "name", _package_name(self.name))
        version = _nonempty(self.version, "version")
        if not _VERSION_RE.fullmatch(version):
            raise ManifestError("version must be a SemVer x.y.z value")
        object.__setattr__(self, "version", version)
        kind = _name(self.kind, "kind")
        if kind not in PACKAGE_KINDS:
            raise ManifestError(f"kind must be one of {list(PACKAGE_KINDS)}")
        object.__setattr__(self, "kind", kind)
        entrypoint_type = _nonempty(self.entrypoint_type, "entrypoint type")
        if entrypoint_type not in _ENTRYPOINT_TYPES:
            raise ManifestError(f"entrypoint type must be one of {sorted(_ENTRYPOINT_TYPES)}")
        object.__setattr__(self, "entrypoint_type", entrypoint_type)
        if entrypoint_type == "none":
            if self.entrypoint is not None and self.entrypoint != "":
                raise ManifestError("entrypoint must be empty when type=none")
            object.__setattr__(self, "entrypoint", None)
        else:
            object.__setattr__(self, "entrypoint", _nonempty(self.entrypoint, "entrypoint value"))
        if not isinstance(self.description, str):
            raise ManifestError("description must be a string")
        artifacts = tuple(self.artifacts)
        platforms = tuple(self.platforms)
        dependencies = tuple(self.dependencies)
        if any(not isinstance(item, ArtifactRecord) for item in artifacts):
            raise ManifestError("artifacts entries must be ArtifactRecord values")
        if any(not isinstance(item, PlatformConstraint) for item in platforms):
            raise ManifestError("platforms entries must be PlatformConstraint values")
        if any(not isinstance(item, Dependency) for item in dependencies):
            raise ManifestError("dependencies entries must be Dependency values")
        object.__setattr__(self, "artifacts", artifacts)
        object.__setattr__(self, "platforms", platforms)
        object.__setattr__(self, "dependencies", dependencies)
        if not self.artifacts and self.entrypoint_type != "endpoint" and self.kind != "bundle":
            raise ManifestError("non-endpoint packages require at least one artifact")
        paths = [item.path for item in self.artifacts]
        if len(paths) != len(set(paths)):
            raise ManifestError("artifact paths must be unique")
        if self.kind == "skill":
            if self.entrypoint_type != "none":
                raise ManifestError("skill packages must use entrypoint type=none")
            if "SKILL.md" not in paths:
                raise ManifestError("skill packages must declare a root SKILL.md artifact")
        dep_names = [item.name for item in self.dependencies]
        if self.name in dep_names:
            raise ManifestError("a package cannot depend on itself")
        if len(dep_names) != len(set(dep_names)):
            raise ManifestError("dependency names must be unique within one manifest")
        platform_keys = [(item.os, item.arch) for item in self.platforms]
        if len(platform_keys) != len(set(platform_keys)):
            raise ManifestError("platform constraints must not contain duplicates")
        caps = tuple(_name(item, "capability") for item in self.capabilities)
        if len(caps) != len(set(caps)):
            raise ManifestError("capabilities must not contain duplicates")
        perms = tuple(_name(item, "permission") for item in self.permissions)
        unknown_permissions = sorted(set(perms) - _PERMISSIONS)
        if unknown_permissions:
            raise ManifestError("unknown permissions: " + ", ".join(unknown_permissions))
        if len(perms) != len(set(perms)):
            raise ManifestError("permissions must not contain duplicates")
        object.__setattr__(self, "capabilities", caps)
        object.__setattr__(self, "permissions", perms)
        object.__setattr__(self, "metadata", _mapping(self.metadata, "metadata"))
        if self.publisher is not None:
            object.__setattr__(self, "publisher", _name(self.publisher, "publisher"))
        try:
            json.dumps(
                self.metadata,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
        except (TypeError, ValueError) as exc:
            raise ManifestError("metadata must be strict JSON-serializable") from exc

        if self.entrypoint_type == "executable":
            entrypoint_path = safe_artifact_path(self.entrypoint)
            matching = [item for item in self.artifacts if item.path == entrypoint_path]
            if not matching or not matching[0].executable:
                raise ManifestError(
                    "an executable entrypoint must name a declared executable artifact"
                )
            object.__setattr__(self, "entrypoint", entrypoint_path)
        elif self.entrypoint_type == "python":
            match = _PYTHON_ENTRYPOINT_RE.fullmatch(self.entrypoint or "")
            if not match:
                raise ManifestError("python entrypoint must use module:attribute syntax")
            module = match.group("module")
            root_module = module.split(".", 1)[0]
            if root_module in getattr(sys, "stdlib_module_names", frozenset()):
                raise ManifestError("python entrypoint must not target a standard-library module")
            module_path = module.replace(".", "/")
            module_artifacts = {
                f"{module_path}.py",
                f"{module_path}/__init__.py",
                f"src/{module_path}.py",
                f"src/{module_path}/__init__.py",
            }
            if not any(item.path in module_artifacts for item in self.artifacts):
                raise ManifestError(
                    "python entrypoint module must be backed by a declared Python artifact"
                )
        elif self.entrypoint_type == "container":
            if not _CONTAINER_ENTRYPOINT_RE.fullmatch(self.entrypoint or ""):
                raise ManifestError(
                    "container entrypoints must end with @sha256: followed by "
                    "64 lowercase hex characters"
                )

    @property
    def coordinate(self) -> str:
        return f"{self.name}@{self.version}"

    @property
    def digest(self) -> str:
        encoded = json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
        return "sha256:" + hashlib.sha256(encoded).hexdigest()

    def supports(self, os_name: str, arch: str) -> bool:
        return not self.platforms or any(row.matches(os_name, arch) for row in self.platforms)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "api_version": self.api_version,
            "name": self.name,
            "version": self.version,
            "kind": self.kind,
            "description": self.description,
            "entrypoint": {"type": self.entrypoint_type, "value": self.entrypoint},
            "capabilities": list(self.capabilities),
            "platforms": [row.to_dict() for row in self.platforms],
            "dependencies": [row.to_dict() for row in self.dependencies],
            "permissions": list(self.permissions),
            "artifacts": [row.to_dict() for row in self.artifacts],
            "publisher": self.publisher,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ExtensionManifest":
        payload = _strict_mapping(
            value,
            "manifest",
            allowed=_MANIFEST_FIELDS,
            required=_REQUIRED_MANIFEST_FIELDS,
        )
        entrypoint = _strict_mapping(
            payload["entrypoint"],
            "entrypoint",
            allowed=frozenset({"type", "value"}),
            required=frozenset({"type", "value"}),
        )
        raw_artifacts = payload["artifacts"]
        raw_platforms = payload.get("platforms", ())
        raw_dependencies = payload.get("dependencies", ())
        raw_capabilities = payload.get("capabilities", ())
        raw_permissions = payload.get("permissions", ())
        for raw, label in (
            (raw_artifacts, "artifacts"),
            (raw_platforms, "platforms"),
            (raw_dependencies, "dependencies"),
            (raw_capabilities, "capabilities"),
            (raw_permissions, "permissions"),
        ):
            if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
                raise ManifestError(f"{label} must be an array")
        for raw, label in (
            (raw_artifacts, "artifacts"),
            (raw_platforms, "platforms"),
            (raw_dependencies, "dependencies"),
        ):
            if any(not isinstance(item, Mapping) for item in raw):
                raise ManifestError(f"{label} entries must be objects")
        return cls(
            schema_version=payload["schema_version"],
            api_version=payload["api_version"],
            name=payload["name"],
            version=payload["version"],
            kind=payload["kind"],
            description=payload.get("description", ""),
            entrypoint_type=entrypoint["type"],
            entrypoint=entrypoint["value"],
            capabilities=tuple(raw_capabilities),
            platforms=tuple(PlatformConstraint.from_dict(item) for item in raw_platforms),
            dependencies=tuple(Dependency.from_dict(item) for item in raw_dependencies),
            permissions=tuple(raw_permissions),
            artifacts=tuple(ArtifactRecord.from_dict(item) for item in raw_artifacts),
            publisher=payload.get("publisher"),
            metadata=_mapping(payload.get("metadata", {}), "metadata"),
        )


def _version_tuple(value: str) -> tuple[int, int, int, tuple[str, ...] | None]:
    match = _VERSION_RE.fullmatch(value)
    if not match:
        raise ManifestError(f"invalid SemVer value: {value!r}")
    prerelease = tuple(match.group(4).split(".")) if match.group(4) else None
    return int(match.group(1)), int(match.group(2)), int(match.group(3)), prerelease


def _compare_prerelease(left: tuple[str, ...], right: tuple[str, ...]) -> int:
    for left_item, right_item in zip(left, right):
        if left_item == right_item:
            continue
        left_numeric = left_item.isdigit()
        right_numeric = right_item.isdigit()
        if left_numeric and right_numeric:
            left_number = int(left_item)
            right_number = int(right_item)
            if left_number == right_number:
                continue
            return -1 if left_number < right_number else 1
        if left_numeric != right_numeric:
            # SemVer orders numeric identifiers below non-numeric identifiers.
            return -1 if left_numeric else 1
        return -1 if left_item < right_item else 1
    if len(left) == len(right):
        return 0
    return -1 if len(left) < len(right) else 1


def _compare_versions(left: str, right: str) -> int:
    l_major, l_minor, l_patch, l_pre = _version_tuple(left)
    r_major, r_minor, r_patch, r_pre = _version_tuple(right)
    numeric_left = (l_major, l_minor, l_patch)
    numeric_right = (r_major, r_minor, r_patch)
    if numeric_left != numeric_right:
        return -1 if numeric_left < numeric_right else 1
    if l_pre is None and r_pre is None:
        return 0
    if l_pre is None:
        return 1
    if r_pre is None:
        return -1
    return _compare_prerelease(l_pre, r_pre)


def version_satisfies(version: str, constraint: str) -> bool:
    """Evaluate a deliberately small, deterministic SemVer constraint set."""

    _version_tuple(version)
    text = constraint.strip()
    if text in {"", "*"}:
        return True
    for clause in text.split(","):
        clause = clause.strip()
        match = re.fullmatch(r"(==|>=|<=|>|<)\s*(.+)", clause)
        if not match:
            raise ManifestError(f"unsupported version constraint: {clause!r}")
        operand = match.group(2)
        comparison = _compare_versions(version, operand)
        operator = match.group(1)
        # SemVer deliberately excludes build metadata from precedence, but an
        # exact package coordinate must still identify one exact artifact.
        # Otherwise ``==1.0.0+trusted`` would also admit
        # ``1.0.0+untrusted`` even though the catalog stores both versions.
        if operator == "==" and version != operand:
            return False
        if operator == ">=" and comparison < 0:
            return False
        if operator == "<=" and comparison > 0:
            return False
        if operator == ">" and comparison <= 0:
            return False
        if operator == "<" and comparison >= 0:
            return False
    return True


def current_platform() -> tuple[str, str]:
    os_name = {
        "darwin": "darwin",
        "linux": "linux",
        "win32": "windows",
        "cygwin": "windows",
    }.get(sys.platform, sys.platform.lower())
    arch = platform.machine().lower() or "unknown"
    aliases = {"amd64": "x86_64", "x64": "x86_64", "aarch64": "arm64"}
    return os_name, aliases.get(arch, arch)


def load_manifest_json(value: str | bytes | bytearray) -> ExtensionManifest:
    """Decode one manifest while rejecting duplicate keys at every depth."""

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, child in pairs:
            if key in result:
                raise ManifestError(f"duplicate JSON key: {key}")
            result[key] = child
        return result

    def reject_nonfinite(value: str) -> Any:
        raise ManifestError(f"non-finite JSON number is not allowed: {value}")

    payload = json.loads(
        value,
        object_pairs_hook=reject_duplicates,
        parse_constant=reject_nonfinite,
    )
    return ExtensionManifest.from_dict(payload)


__all__ = [
    "PACKAGE_API_VERSION",
    "PACKAGE_KINDS",
    "PACKAGE_MANIFEST_SCHEMA_VERSION",
    "ArtifactRecord",
    "Dependency",
    "ExtensionManifest",
    "ManifestError",
    "PlatformConstraint",
    "current_platform",
    "load_manifest_json",
    "normalize_sha256",
    "is_portable_filesystem_component",
    "safe_artifact_path",
    "version_satisfies",
]
