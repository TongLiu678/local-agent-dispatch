"""Strict, provider-free creation of inert skill package sources.

The scaffold boundary turns reviewed text into a two-file local package source.
It deliberately does not install, activate, index, import, execute, or send the
skill to a provider. Instruction text is handled only as UTF-8 data.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..packages.manifest import (
    ArtifactRecord,
    ExtensionManifest,
    ManifestError,
    is_portable_filesystem_component,
)
from ..packages.store import (
    DEFAULT_MANIFEST_FILENAME,
)


SCAFFOLD_SCHEMA_VERSION = 1
SCAFFOLD_RECEIPT_SCHEMA_VERSION = 1
MAX_SCAFFOLD_JSON_BYTES = 128 * 1024
MAX_INSTRUCTION_BYTES = 64 * 1024

_NAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_SEMVER_RE = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
_SPEC_FIELDS = frozenset(
    {"schema_version", "name", "version", "description", "instructions"}
)


class ScaffoldError(ValueError):
    """An untrusted scaffold or destination failed a closed safety check."""


def _strict_text(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ScaffoldError(f"{label} must be a string")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ScaffoldError(f"{label} must be valid UTF-8 text") from exc
    return value


def _skill_name(value: Any) -> str:
    text = _strict_text(value, "name")
    if not _NAME_RE.fullmatch(text):
        raise ScaffoldError(
            "name must contain only lowercase letters, digits, and internal hyphens "
            "and be shorter than 64 characters"
        )
    if not is_portable_filesystem_component(text):
        raise ScaffoldError("name must be a portable filesystem component")
    return text


def _version(value: Any) -> str:
    text = _strict_text(value, "version")
    if not _SEMVER_RE.fullmatch(text):
        raise ScaffoldError("version must be a SemVer x.y.z value")
    return text


def _description(value: Any, name: str) -> str:
    text = _strict_text(value, "description").strip()
    if not 12 <= len(text) <= 280:
        raise ScaffoldError("description must contain 12 to 280 characters")
    if any(ord(character) < 32 or ord(character) == 127 for character in text):
        raise ScaffoldError("description must be one printable line")
    normalized = re.sub(r"[^a-z0-9]+", " ", text.casefold()).strip()
    normalized_name = name.replace("-", " ")
    if normalized in {"skill", normalized_name, f"{normalized_name} skill"}:
        raise ScaffoldError(
            "description must distinguish what the skill does and when it applies"
        )
    return text


def _instructions(value: Any) -> str:
    text = _strict_text(value, "instructions")
    text = text.replace("\r\n", "\n").replace("\r", "\n").strip()
    if not text:
        raise ScaffoldError("instructions must not be empty")
    if any(
        (ord(character) < 32 and character not in {"\n", "\t"})
        or ord(character) == 127
        for character in text
    ):
        raise ScaffoldError("instructions contain unsupported control characters")
    if len(text.encode("utf-8")) > MAX_INSTRUCTION_BYTES:
        raise ScaffoldError(
            f"instructions must be at most {MAX_INSTRUCTION_BYTES} UTF-8 bytes"
        )
    return text


@dataclass(frozen=True, kw_only=True)
class ScaffoldSpec:
    """Closed input contract for one minimal skill package source."""

    name: str
    version: str
    description: str
    instructions: str
    schema_version: int = SCAFFOLD_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            isinstance(self.schema_version, bool)
            or not isinstance(self.schema_version, int)
            or self.schema_version != SCAFFOLD_SCHEMA_VERSION
        ):
            raise ScaffoldError("schema_version must equal 1")
        name = _skill_name(self.name)
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "version", _version(self.version))
        object.__setattr__(self, "description", _description(self.description, name))
        object.__setattr__(self, "instructions", _instructions(self.instructions))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "instructions": self.instructions,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ScaffoldSpec":
        if not isinstance(value, Mapping):
            raise ScaffoldError("scaffold spec must be an object")
        if any(not isinstance(key, str) for key in value):
            raise ScaffoldError("scaffold spec field names must be strings")
        missing = sorted(_SPEC_FIELDS - set(value))
        unknown = sorted(set(value) - _SPEC_FIELDS)
        if missing:
            raise ScaffoldError(
                "scaffold spec is missing required fields: " + ", ".join(missing)
            )
        if unknown:
            raise ScaffoldError(
                "scaffold spec contains unknown fields: " + ", ".join(unknown)
            )
        return cls(
            schema_version=value["schema_version"],
            name=value["name"],
            version=value["version"],
            description=value["description"],
            instructions=value["instructions"],
        )


@dataclass(frozen=True, kw_only=True)
class SkillScaffoldReceipt:
    """Body-free evidence for one atomically published package source."""

    name: str
    version: str
    package_path: str
    manifest_digest: str
    skill_sha256: str
    skill_size: int
    files: tuple[str, ...] = ("SKILL.md", DEFAULT_MANIFEST_FILENAME)
    schema_version: int = SCAFFOLD_RECEIPT_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "name": self.name,
            "version": self.version,
            "package_path": self.package_path,
            "manifest_digest": self.manifest_digest,
            "skill_sha256": self.skill_sha256,
            "skill_size": self.skill_size,
            "files": list(self.files),
        }


def load_scaffold_json(value: str | bytes | bytearray) -> ScaffoldSpec:
    """Decode one bounded JSON spec, rejecting duplicate keys at every depth."""

    if not isinstance(value, (str, bytes, bytearray)):
        raise ScaffoldError("scaffold JSON must be text or bytes")
    try:
        encoded = value.encode("utf-8") if isinstance(value, str) else bytes(value)
    except UnicodeEncodeError as exc:
        raise ScaffoldError("scaffold JSON must be valid UTF-8") from exc
    if len(encoded) > MAX_SCAFFOLD_JSON_BYTES:
        raise ScaffoldError(
            f"scaffold JSON exceeds the {MAX_SCAFFOLD_JSON_BYTES}-byte limit"
        )
    try:
        text = encoded.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ScaffoldError("scaffold JSON must be valid UTF-8") from exc

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, child in pairs:
            if key in result:
                raise ScaffoldError(f"duplicate JSON key: {key}")
            result[key] = child
        return result

    def reject_constant(value_text: str) -> None:
        raise ScaffoldError(f"non-finite JSON number is not accepted: {value_text}")

    try:
        payload = json.loads(
            text,
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except json.JSONDecodeError as exc:
        raise ScaffoldError(f"invalid scaffold JSON: {exc.msg}") from exc
    return ScaffoldSpec.from_dict(payload)


def _render_skill(spec: ScaffoldSpec) -> bytes:
    # A JSON string is also a valid YAML double-quoted scalar and safely keeps
    # colons, hashes, quotes, and non-ASCII text inside the description value.
    yaml_description = json.dumps(spec.description, ensure_ascii=False)
    text = (
        "---\n"
        f"name: {spec.name}\n"
        f"description: {yaml_description}\n"
        "---\n\n"
        f"{spec.instructions}\n"
    )
    return text.encode("utf-8")


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("utf-8")


def _write_new_file(path: Path, content: bytes) -> None:
    with path.open("xb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    path.chmod(0o644)


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


def _local_destination(destination: str | os.PathLike[str]) -> Path:
    try:
        raw = os.fspath(destination)
    except TypeError as exc:
        raise ScaffoldError("destination must be a local filesystem path") from exc
    if isinstance(raw, bytes):
        raw = os.fsdecode(raw)
    if not raw or "://" in raw:
        raise ScaffoldError("destination must be a non-empty local filesystem path")
    if "\x00" in raw:
        raise ScaffoldError("destination name must be a portable filesystem component")
    requested = Path(raw).expanduser().absolute()
    if not is_portable_filesystem_component(requested.name):
        raise ScaffoldError("destination name must be a portable filesystem component")
    if requested.exists() or requested.is_symlink():
        raise ScaffoldError("destination already exists or is a symlink")
    parent = requested.parent
    if parent.is_symlink() or not parent.is_dir():
        raise ScaffoldError("destination parent must be an existing non-symlink directory")
    try:
        parent = parent.resolve(strict=True)
    except OSError as exc:
        raise ScaffoldError("destination parent cannot be resolved safely") from exc
    target = parent / requested.name
    if target.exists() or target.is_symlink():
        raise ScaffoldError("destination already exists or is a symlink")
    return target


def _atomic_publish(staging: Path, target: Path) -> None:
    if target.exists() or target.is_symlink():
        raise ScaffoldError("destination appeared while the package was being created")
    os.replace(staging, target)


def create_skill_package(
    spec: ScaffoldSpec,
    destination: str | os.PathLike[str],
) -> SkillScaffoldReceipt:
    """Create one inert two-file skill package source atomically."""

    if not isinstance(spec, ScaffoldSpec):
        raise ScaffoldError("spec must be a validated ScaffoldSpec")

    skill_bytes = _render_skill(spec)
    skill_digest = "sha256:" + hashlib.sha256(skill_bytes).hexdigest()
    try:
        manifest = ExtensionManifest(
            name=spec.name,
            version=spec.version,
            kind="skill",
            description=spec.description,
            entrypoint_type="none",
            entrypoint=None,
            artifacts=(
                ArtifactRecord(
                    path="SKILL.md",
                    sha256=skill_digest,
                    size=len(skill_bytes),
                    executable=False,
                ),
            ),
        )
    except ManifestError as exc:
        raise ScaffoldError(f"scaffold does not form a valid package manifest: {exc}") from exc
    manifest_bytes = _canonical_json(manifest.to_dict())
    target = _local_destination(destination)

    staging: Path | None = None
    try:
        staging = Path(
            tempfile.mkdtemp(
                prefix=f".lad-skill-scaffold-{spec.name}-",
                dir=target.parent,
            )
        )
        _write_new_file(staging / "SKILL.md", skill_bytes)
        _write_new_file(staging / DEFAULT_MANIFEST_FILENAME, manifest_bytes)
        _fsync_directory(staging)
        _atomic_publish(staging, target)
        staging = None
        _fsync_directory(target.parent)
    except ScaffoldError:
        raise
    except OSError as exc:
        raise ScaffoldError(f"could not create skill package: {exc}") from exc
    finally:
        if staging is not None and staging.parent == target.parent:
            if staging.exists() and not staging.is_symlink():
                shutil.rmtree(staging, ignore_errors=True)

    return SkillScaffoldReceipt(
        name=spec.name,
        version=spec.version,
        package_path=str(target),
        manifest_digest=manifest.digest,
        skill_sha256=skill_digest,
        skill_size=len(skill_bytes),
    )


__all__ = [
    "MAX_INSTRUCTION_BYTES",
    "MAX_SCAFFOLD_JSON_BYTES",
    "SCAFFOLD_RECEIPT_SCHEMA_VERSION",
    "SCAFFOLD_SCHEMA_VERSION",
    "ScaffoldError",
    "ScaffoldSpec",
    "SkillScaffoldReceipt",
    "create_skill_package",
    "load_scaffold_json",
]
