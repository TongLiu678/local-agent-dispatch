"""Provider-free v1 contracts shared by controllers and workers.

The module contains data only: it performs no discovery, networking, process
launch, persistence, or provider calls.  Every top-level message is explicitly
versioned, rejects unknown fields, carries idempotency and fencing data, and
round-trips through canonical JSON using only the Python standard library.

Unknown resource observations are represented by ``None`` and serialized as
JSON ``null``.  They are never coerced to zero.  Snapshot freshness is
three-valued (``fresh``, ``stale``, or ``unknown``); consumers must treat every
result other than ``fresh`` as fail-closed for admission.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, ClassVar

from ._validation import (
    ContractValidationError,
    JsonContract,
    boolean_or_none,
    freshness,
    integer,
    nonempty_string,
    number,
    optional_integer,
    optional_number,
    optional_string,
    strict_object,
    string_tuple,
    timestamp,
    validate_version,
)


SCHEMA_VERSION = 1
WORKER_API_VERSION = "local-agent-dispatch.worker.v1"

HOST_ROLES = ("execution", "workload")
CAPABILITY_KINDS = (
    "runtime",
    "transport",
    "validator",
    "scheduler",
    "accelerator",
    "filesystem",
    "worker",
    "other",
)
CAPABILITY_STATUSES = ("available", "unavailable", "blocked", "unknown")
WORKER_REPORTED_STATES = ("ready", "busy", "draining", "stopped", "unknown")
EXECUTION_STATES = (
    "accepted",
    "running",
    "exited",
    "failed",
    "cancelled",
    "lost",
    "unknown",
)

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$")
_WINDOWS_ABS_RE = re.compile(r"^[A-Za-z]:[\\/]")


def _identifier(value: Any, field_name: str) -> str:
    text = nonempty_string(value, field_name)
    if not _ID_RE.fullmatch(text):
        raise ContractValidationError(
            f"{field_name} must be a bounded path-free identifier"
        )
    return text


def _absolute_path(value: Any, field_name: str) -> str:
    text = nonempty_string(value, field_name)
    normalized = text.replace("\\", "/")
    if not (normalized.startswith("/") or _WINDOWS_ABS_RE.match(text)):
        raise ContractValidationError(f"{field_name} must be an absolute path")
    if ".." in normalized.split("/"):
        raise ContractValidationError(f"{field_name} must not contain '..'")
    if _WINDOWS_ABS_RE.match(text):
        suffix = "/" + normalized[2:].lstrip("/")
        return normalized[0].upper() + ":" + posixpath.normpath(suffix)
    return posixpath.normpath(normalized)


def _enum(value: Any, field_name: str, allowed: tuple[str, ...]) -> str:
    text = nonempty_string(value, field_name)
    if text not in allowed:
        raise ContractValidationError(
            f"{field_name} must be one of {allowed}; got {text!r}"
        )
    return text


def _validate_observation(
    *,
    observed_at: Any,
    ttl_seconds: Any,
    source: Any,
    confidence: Any,
    sequence: Any,
) -> None:
    timestamp(observed_at, "observed_at")
    optional_integer(ttl_seconds, "ttl_seconds", minimum=1)
    nonempty_string(source, "source")
    confidence_value = optional_number(confidence, "confidence", minimum=0.0)
    if confidence_value is not None and confidence_value > 1.0:
        raise ContractValidationError("confidence must be within [0, 1]")
    integer(sequence, "sequence", minimum=1)


def _observation_payload(value: Any) -> dict[str, Any]:
    return {
        "observed_at": value.observed_at,
        "ttl_seconds": value.ttl_seconds,
        "source": value.source,
        "confidence": value.confidence,
        "sequence": value.sequence,
    }


def _version_payload(value: Any) -> dict[str, Any]:
    return {
        "schema_version": value.schema_version,
        "api_version": value.api_version,
    }


@dataclass(frozen=True, kw_only=True)
class Capability(JsonContract):
    """One statically named worker capability; status may remain unknown."""

    capability_id: str
    kind: str
    status: str = "unknown"
    version: str | None = None
    constraints: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _identifier(self.capability_id, "capability_id")
        _enum(self.kind, "kind", CAPABILITY_KINDS)
        _enum(self.status, "status", CAPABILITY_STATUSES)
        optional_string(self.version, "version")
        object.__setattr__(
            self, "constraints", string_tuple(self.constraints, "constraints")
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "capability_id": self.capability_id,
            "kind": self.kind,
            "status": self.status,
            "version": self.version,
            "constraints": list(self.constraints),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Capability":
        strict_object(
            data,
            required={"capability_id", "kind", "status", "version", "constraints"},
            name="Capability",
        )
        return cls(
            capability_id=data["capability_id"],
            kind=data["kind"],
            status=data["status"],
            version=data["version"],
            constraints=string_tuple(data["constraints"], "constraints"),
        )


@dataclass(frozen=True, kw_only=True)
class CpuResources(JsonContract):
    capacity_cores: float | None = None
    allocatable_cores: float | None = None
    available_cores: float | None = None
    utilization_percent: float | None = None

    def __post_init__(self) -> None:
        for name in ("capacity_cores", "allocatable_cores", "available_cores"):
            optional_number(getattr(self, name), name, minimum=0.0)
        utilization = optional_number(
            self.utilization_percent, "utilization_percent", minimum=0.0
        )
        if utilization is not None and utilization > 100.0:
            raise ContractValidationError("utilization_percent must be <= 100")
        if (
            self.capacity_cores is not None
            and self.allocatable_cores is not None
            and self.allocatable_cores > self.capacity_cores
        ):
            raise ContractValidationError(
                "allocatable_cores must not exceed capacity_cores"
            )
        if (
            self.allocatable_cores is not None
            and self.available_cores is not None
            and self.available_cores > self.allocatable_cores
        ):
            raise ContractValidationError(
                "available_cores must not exceed allocatable_cores"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "capacity_cores": self.capacity_cores,
            "allocatable_cores": self.allocatable_cores,
            "available_cores": self.available_cores,
            "utilization_percent": self.utilization_percent,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CpuResources":
        fields = {
            "capacity_cores",
            "allocatable_cores",
            "available_cores",
            "utilization_percent",
        }
        strict_object(data, required=fields, name="CpuResources")
        return cls(**{name: data[name] for name in fields})


@dataclass(frozen=True, kw_only=True)
class MemoryResources(JsonContract):
    capacity_bytes: int | None = None
    allocatable_bytes: int | None = None
    available_bytes: int | None = None
    used_bytes: int | None = None

    def __post_init__(self) -> None:
        for name in (
            "capacity_bytes",
            "allocatable_bytes",
            "available_bytes",
            "used_bytes",
        ):
            optional_integer(getattr(self, name), name, minimum=0)
        if (
            self.capacity_bytes is not None
            and self.allocatable_bytes is not None
            and self.allocatable_bytes > self.capacity_bytes
        ):
            raise ContractValidationError(
                "allocatable_bytes must not exceed capacity_bytes"
            )
        if (
            self.allocatable_bytes is not None
            and self.available_bytes is not None
            and self.available_bytes > self.allocatable_bytes
        ):
            raise ContractValidationError(
                "available_bytes must not exceed allocatable_bytes"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "capacity_bytes": self.capacity_bytes,
            "allocatable_bytes": self.allocatable_bytes,
            "available_bytes": self.available_bytes,
            "used_bytes": self.used_bytes,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "MemoryResources":
        fields = {
            "capacity_bytes",
            "allocatable_bytes",
            "available_bytes",
            "used_bytes",
        }
        strict_object(data, required=fields, name="MemoryResources")
        return cls(**{name: data[name] for name in fields})


@dataclass(frozen=True, kw_only=True)
class CgroupResources(JsonContract):
    cpu_quota_cores: float | None = None
    memory_limit_bytes: int | None = None
    memory_current_bytes: int | None = None
    swap_limit_bytes: int | None = None
    swap_current_bytes: int | None = None

    def __post_init__(self) -> None:
        optional_number(self.cpu_quota_cores, "cpu_quota_cores", minimum=0.0)
        for name in (
            "memory_limit_bytes",
            "memory_current_bytes",
            "swap_limit_bytes",
            "swap_current_bytes",
        ):
            optional_integer(getattr(self, name), name, minimum=0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cpu_quota_cores": self.cpu_quota_cores,
            "memory_limit_bytes": self.memory_limit_bytes,
            "memory_current_bytes": self.memory_current_bytes,
            "swap_limit_bytes": self.swap_limit_bytes,
            "swap_current_bytes": self.swap_current_bytes,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CgroupResources":
        fields = {
            "cpu_quota_cores",
            "memory_limit_bytes",
            "memory_current_bytes",
            "swap_limit_bytes",
            "swap_current_bytes",
        }
        strict_object(data, required=fields, name="CgroupResources")
        return cls(**{name: data[name] for name in fields})


@dataclass(frozen=True, kw_only=True)
class MountResources(JsonContract):
    """Evidence for one exact mount; never evidence for a prefix substitute."""

    mount_path: str
    device: str | None = None
    fs_type: str | None = None
    writable: bool | None = None
    capacity_bytes: int | None = None
    available_bytes: int | None = None
    total_inodes: int | None = None
    free_inodes: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "mount_path", _absolute_path(self.mount_path, "mount_path")
        )
        optional_string(self.device, "device")
        optional_string(self.fs_type, "fs_type")
        boolean_or_none(self.writable, "writable")
        for name in (
            "capacity_bytes",
            "available_bytes",
            "total_inodes",
            "free_inodes",
        ):
            optional_integer(getattr(self, name), name, minimum=0)
        if (
            self.capacity_bytes is not None
            and self.available_bytes is not None
            and self.available_bytes > self.capacity_bytes
        ):
            raise ContractValidationError(
                "available_bytes must not exceed capacity_bytes"
            )
        if (
            self.total_inodes is not None
            and self.free_inodes is not None
            and self.free_inodes > self.total_inodes
        ):
            raise ContractValidationError("free_inodes must not exceed total_inodes")

    def to_dict(self) -> dict[str, Any]:
        return {
            "mount_path": self.mount_path,
            "device": self.device,
            "fs_type": self.fs_type,
            "writable": self.writable,
            "capacity_bytes": self.capacity_bytes,
            "available_bytes": self.available_bytes,
            "total_inodes": self.total_inodes,
            "free_inodes": self.free_inodes,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "MountResources":
        fields = {
            "mount_path",
            "device",
            "fs_type",
            "writable",
            "capacity_bytes",
            "available_bytes",
            "total_inodes",
            "free_inodes",
        }
        strict_object(data, required=fields, name="MountResources")
        return cls(**{name: data[name] for name in fields})


@dataclass(frozen=True, kw_only=True)
class GpuResources(JsonContract):
    gpu_id: str
    model: str | None = None
    memory_capacity_bytes: int | None = None
    memory_available_bytes: int | None = None
    utilization_percent: float | None = None

    def __post_init__(self) -> None:
        _identifier(self.gpu_id, "gpu_id")
        optional_string(self.model, "model")
        optional_integer(
            self.memory_capacity_bytes, "memory_capacity_bytes", minimum=0
        )
        optional_integer(
            self.memory_available_bytes, "memory_available_bytes", minimum=0
        )
        utilization = optional_number(
            self.utilization_percent, "utilization_percent", minimum=0.0
        )
        if utilization is not None and utilization > 100.0:
            raise ContractValidationError("utilization_percent must be <= 100")
        if (
            self.memory_capacity_bytes is not None
            and self.memory_available_bytes is not None
            and self.memory_available_bytes > self.memory_capacity_bytes
        ):
            raise ContractValidationError(
                "memory_available_bytes must not exceed memory_capacity_bytes"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "gpu_id": self.gpu_id,
            "model": self.model,
            "memory_capacity_bytes": self.memory_capacity_bytes,
            "memory_available_bytes": self.memory_available_bytes,
            "utilization_percent": self.utilization_percent,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "GpuResources":
        fields = {
            "gpu_id",
            "model",
            "memory_capacity_bytes",
            "memory_available_bytes",
            "utilization_percent",
        }
        strict_object(data, required=fields, name="GpuResources")
        return cls(**{name: data[name] for name in fields})


@dataclass(frozen=True, kw_only=True)
class OwnedProcessResources(JsonContract):
    """Bounded process evidence; deliberately excludes argv and command text."""

    process_id: str
    attempt_id: str
    pid: int
    started_at: str
    fence_token: int
    rss_bytes: int | None = None
    gpu_memory_bytes: int | None = None

    def __post_init__(self) -> None:
        _identifier(self.process_id, "process_id")
        _identifier(self.attempt_id, "attempt_id")
        integer(self.pid, "pid", minimum=1)
        timestamp(self.started_at, "started_at")
        integer(self.fence_token, "fence_token", minimum=1)
        optional_integer(self.rss_bytes, "rss_bytes", minimum=0)
        optional_integer(self.gpu_memory_bytes, "gpu_memory_bytes", minimum=0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "process_id": self.process_id,
            "attempt_id": self.attempt_id,
            "pid": self.pid,
            "started_at": self.started_at,
            "fence_token": self.fence_token,
            "rss_bytes": self.rss_bytes,
            "gpu_memory_bytes": self.gpu_memory_bytes,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "OwnedProcessResources":
        fields = {
            "process_id",
            "attempt_id",
            "pid",
            "started_at",
            "fence_token",
            "rss_bytes",
            "gpu_memory_bytes",
        }
        strict_object(data, required=fields, name="OwnedProcessResources")
        return cls(**{name: data[name] for name in fields})


@dataclass(frozen=True, kw_only=True)
class ResourceUsage(JsonContract):
    """Reserved or actual aggregate usage; null means unknown, never zero."""

    cpu_cores: float | None = None
    ram_bytes: int | None = None
    swap_bytes: int | None = None
    gpu_memory_bytes: int | None = None
    disk_bytes: int | None = None
    inodes: int | None = None
    owned_process_rss_bytes: int | None = None

    DIMENSIONS: ClassVar[tuple[str, ...]] = (
        "cpu_cores",
        "ram_bytes",
        "swap_bytes",
        "gpu_memory_bytes",
        "disk_bytes",
        "inodes",
        "owned_process_rss_bytes",
    )

    def __post_init__(self) -> None:
        optional_number(self.cpu_cores, "cpu_cores", minimum=0.0)
        for name in self.DIMENSIONS[1:]:
            optional_integer(getattr(self, name), name, minimum=0)

    def to_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.DIMENSIONS}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ResourceUsage":
        fields = set(cls.DIMENSIONS)
        strict_object(data, required=fields, name="ResourceUsage")
        return cls(**{name: data[name] for name in cls.DIMENSIONS})


@dataclass(frozen=True, kw_only=True)
class HostRegistration(JsonContract):
    schema_version: int = SCHEMA_VERSION
    api_version: str = WORKER_API_VERSION
    registration_id: str
    host_id: str
    worker_id: str
    roles: tuple[str, ...]
    registered_at: str
    idempotency_key: str
    fence_token: int
    labels: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        validate_version(self.schema_version, self.api_version, WORKER_API_VERSION)
        _identifier(self.registration_id, "registration_id")
        _identifier(self.host_id, "host_id")
        _identifier(self.worker_id, "worker_id")
        roles = string_tuple(self.roles, "roles")
        if not roles:
            raise ContractValidationError("roles must contain at least one role")
        for role in roles:
            _enum(role, "roles[]", HOST_ROLES)
        object.__setattr__(self, "roles", roles)
        timestamp(self.registered_at, "registered_at")
        _identifier(self.idempotency_key, "idempotency_key")
        integer(self.fence_token, "fence_token", minimum=1)
        object.__setattr__(self, "labels", string_tuple(self.labels, "labels"))

    def to_dict(self) -> dict[str, Any]:
        return {
            **_version_payload(self),
            "registration_id": self.registration_id,
            "host_id": self.host_id,
            "worker_id": self.worker_id,
            "roles": list(self.roles),
            "registered_at": self.registered_at,
            "idempotency_key": self.idempotency_key,
            "fence_token": self.fence_token,
            "labels": list(self.labels),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "HostRegistration":
        fields = {
            "schema_version",
            "api_version",
            "registration_id",
            "host_id",
            "worker_id",
            "roles",
            "registered_at",
            "idempotency_key",
            "fence_token",
            "labels",
        }
        strict_object(data, required=fields, name="HostRegistration")
        return cls(
            schema_version=data["schema_version"],
            api_version=data["api_version"],
            registration_id=data["registration_id"],
            host_id=data["host_id"],
            worker_id=data["worker_id"],
            roles=string_tuple(data["roles"], "roles"),
            registered_at=data["registered_at"],
            idempotency_key=data["idempotency_key"],
            fence_token=data["fence_token"],
            labels=string_tuple(data["labels"], "labels"),
        )


@dataclass(frozen=True, kw_only=True)
class CapabilitySnapshot(JsonContract):
    schema_version: int = SCHEMA_VERSION
    api_version: str = WORKER_API_VERSION
    snapshot_id: str
    host_id: str
    worker_id: str
    capabilities: tuple[Capability, ...]
    observed_at: str
    ttl_seconds: int | None
    source: str
    confidence: float | None
    sequence: int
    idempotency_key: str
    fence_token: int

    def __post_init__(self) -> None:
        validate_version(self.schema_version, self.api_version, WORKER_API_VERSION)
        _identifier(self.snapshot_id, "snapshot_id")
        _identifier(self.host_id, "host_id")
        _identifier(self.worker_id, "worker_id")
        capabilities = tuple(self.capabilities)
        if not all(isinstance(item, Capability) for item in capabilities):
            raise ContractValidationError("capabilities must contain Capability values")
        ids = tuple(item.capability_id for item in capabilities)
        if len(ids) != len(set(ids)):
            raise ContractValidationError("capability_id values must be unique")
        object.__setattr__(self, "capabilities", capabilities)
        _validate_observation(
            observed_at=self.observed_at,
            ttl_seconds=self.ttl_seconds,
            source=self.source,
            confidence=self.confidence,
            sequence=self.sequence,
        )
        _identifier(self.idempotency_key, "idempotency_key")
        integer(self.fence_token, "fence_token", minimum=1)

    def freshness(self, now: str | None = None) -> str:
        return freshness(
            observed_at=self.observed_at, ttl_seconds=self.ttl_seconds, now=now
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            **_version_payload(self),
            "snapshot_id": self.snapshot_id,
            "host_id": self.host_id,
            "worker_id": self.worker_id,
            "capabilities": [item.to_dict() for item in self.capabilities],
            **_observation_payload(self),
            "idempotency_key": self.idempotency_key,
            "fence_token": self.fence_token,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CapabilitySnapshot":
        fields = {
            "schema_version",
            "api_version",
            "snapshot_id",
            "host_id",
            "worker_id",
            "capabilities",
            "observed_at",
            "ttl_seconds",
            "source",
            "confidence",
            "sequence",
            "idempotency_key",
            "fence_token",
        }
        strict_object(data, required=fields, name="CapabilitySnapshot")
        raw_capabilities = data["capabilities"]
        if not isinstance(raw_capabilities, list):
            raise ContractValidationError("capabilities must be an array")
        return cls(
            schema_version=data["schema_version"],
            api_version=data["api_version"],
            snapshot_id=data["snapshot_id"],
            host_id=data["host_id"],
            worker_id=data["worker_id"],
            capabilities=tuple(Capability.from_dict(item) for item in raw_capabilities),
            observed_at=data["observed_at"],
            ttl_seconds=data["ttl_seconds"],
            source=data["source"],
            confidence=data["confidence"],
            sequence=data["sequence"],
            idempotency_key=data["idempotency_key"],
            fence_token=data["fence_token"],
        )


@dataclass(frozen=True, kw_only=True)
class ResourceSnapshot(JsonContract):
    schema_version: int = SCHEMA_VERSION
    api_version: str = WORKER_API_VERSION
    snapshot_id: str
    host_id: str
    worker_id: str
    cpu: CpuResources
    ram: MemoryResources
    swap: MemoryResources
    cgroup: CgroupResources
    mounts: tuple[MountResources, ...]
    gpus: tuple[GpuResources, ...]
    owned_processes: tuple[OwnedProcessResources, ...]
    observed_at: str
    ttl_seconds: int | None
    source: str
    confidence: float | None
    sequence: int
    idempotency_key: str
    fence_token: int

    def __post_init__(self) -> None:
        validate_version(self.schema_version, self.api_version, WORKER_API_VERSION)
        _identifier(self.snapshot_id, "snapshot_id")
        _identifier(self.host_id, "host_id")
        _identifier(self.worker_id, "worker_id")
        if not isinstance(self.cpu, CpuResources):
            raise ContractValidationError("cpu must be CpuResources")
        if not isinstance(self.ram, MemoryResources):
            raise ContractValidationError("ram must be MemoryResources")
        if not isinstance(self.swap, MemoryResources):
            raise ContractValidationError("swap must be MemoryResources")
        if not isinstance(self.cgroup, CgroupResources):
            raise ContractValidationError("cgroup must be CgroupResources")
        mounts = tuple(self.mounts)
        gpus = tuple(self.gpus)
        processes = tuple(self.owned_processes)
        if not all(isinstance(item, MountResources) for item in mounts):
            raise ContractValidationError("mounts must contain MountResources")
        if not all(isinstance(item, GpuResources) for item in gpus):
            raise ContractValidationError("gpus must contain GpuResources")
        if not all(isinstance(item, OwnedProcessResources) for item in processes):
            raise ContractValidationError(
                "owned_processes must contain OwnedProcessResources"
            )
        for values, label in (
            ((item.mount_path for item in mounts), "mount_path"),
            ((item.gpu_id for item in gpus), "gpu_id"),
            ((item.process_id for item in processes), "process_id"),
        ):
            ids = tuple(values)
            if len(ids) != len(set(ids)):
                raise ContractValidationError(f"{label} values must be unique")
        for process in processes:
            if process.fence_token != self.fence_token:
                raise ContractValidationError(
                    "owned process fence_token must match snapshot fence_token"
                )
        object.__setattr__(self, "mounts", mounts)
        object.__setattr__(self, "gpus", gpus)
        object.__setattr__(self, "owned_processes", processes)
        _validate_observation(
            observed_at=self.observed_at,
            ttl_seconds=self.ttl_seconds,
            source=self.source,
            confidence=self.confidence,
            sequence=self.sequence,
        )
        _identifier(self.idempotency_key, "idempotency_key")
        integer(self.fence_token, "fence_token", minimum=1)

    def freshness(self, now: str | None = None) -> str:
        return freshness(
            observed_at=self.observed_at, ttl_seconds=self.ttl_seconds, now=now
        )

    def owned_process_rss_bytes(self) -> int | None:
        total = 0
        for process in self.owned_processes:
            if process.rss_bytes is None:
                return None
            total += process.rss_bytes
        return total

    def to_dict(self) -> dict[str, Any]:
        return {
            **_version_payload(self),
            "snapshot_id": self.snapshot_id,
            "host_id": self.host_id,
            "worker_id": self.worker_id,
            "cpu": self.cpu.to_dict(),
            "ram": self.ram.to_dict(),
            "swap": self.swap.to_dict(),
            "cgroup": self.cgroup.to_dict(),
            "mounts": [item.to_dict() for item in self.mounts],
            "gpus": [item.to_dict() for item in self.gpus],
            "owned_processes": [item.to_dict() for item in self.owned_processes],
            **_observation_payload(self),
            "idempotency_key": self.idempotency_key,
            "fence_token": self.fence_token,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ResourceSnapshot":
        fields = {
            "schema_version",
            "api_version",
            "snapshot_id",
            "host_id",
            "worker_id",
            "cpu",
            "ram",
            "swap",
            "cgroup",
            "mounts",
            "gpus",
            "owned_processes",
            "observed_at",
            "ttl_seconds",
            "source",
            "confidence",
            "sequence",
            "idempotency_key",
            "fence_token",
        }
        strict_object(data, required=fields, name="ResourceSnapshot")
        for name in ("mounts", "gpus", "owned_processes"):
            if not isinstance(data[name], list):
                raise ContractValidationError(f"{name} must be an array")
        return cls(
            schema_version=data["schema_version"],
            api_version=data["api_version"],
            snapshot_id=data["snapshot_id"],
            host_id=data["host_id"],
            worker_id=data["worker_id"],
            cpu=CpuResources.from_dict(data["cpu"]),
            ram=MemoryResources.from_dict(data["ram"]),
            swap=MemoryResources.from_dict(data["swap"]),
            cgroup=CgroupResources.from_dict(data["cgroup"]),
            mounts=tuple(MountResources.from_dict(item) for item in data["mounts"]),
            gpus=tuple(GpuResources.from_dict(item) for item in data["gpus"]),
            owned_processes=tuple(
                OwnedProcessResources.from_dict(item)
                for item in data["owned_processes"]
            ),
            observed_at=data["observed_at"],
            ttl_seconds=data["ttl_seconds"],
            source=data["source"],
            confidence=data["confidence"],
            sequence=data["sequence"],
            idempotency_key=data["idempotency_key"],
            fence_token=data["fence_token"],
        )


@dataclass(frozen=True, kw_only=True)
class WorkerHeartbeat(JsonContract):
    schema_version: int = SCHEMA_VERSION
    api_version: str = WORKER_API_VERSION
    heartbeat_id: str
    host_id: str
    worker_id: str
    state: str
    observed_at: str
    ttl_seconds: int | None
    source: str
    confidence: float | None
    sequence: int
    idempotency_key: str
    fence_token: int
    capability_sequence: int | None
    resource_sequence: int | None
    reserved_usage: ResourceUsage
    actual_usage: ResourceUsage
    active_execution_handles: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        validate_version(self.schema_version, self.api_version, WORKER_API_VERSION)
        _identifier(self.heartbeat_id, "heartbeat_id")
        _identifier(self.host_id, "host_id")
        _identifier(self.worker_id, "worker_id")
        _enum(self.state, "state", WORKER_REPORTED_STATES)
        _validate_observation(
            observed_at=self.observed_at,
            ttl_seconds=self.ttl_seconds,
            source=self.source,
            confidence=self.confidence,
            sequence=self.sequence,
        )
        _identifier(self.idempotency_key, "idempotency_key")
        integer(self.fence_token, "fence_token", minimum=1)
        optional_integer(self.capability_sequence, "capability_sequence", minimum=1)
        optional_integer(self.resource_sequence, "resource_sequence", minimum=1)
        if not isinstance(self.reserved_usage, ResourceUsage):
            raise ContractValidationError("reserved_usage must be ResourceUsage")
        if not isinstance(self.actual_usage, ResourceUsage):
            raise ContractValidationError("actual_usage must be ResourceUsage")
        handles = string_tuple(
            self.active_execution_handles, "active_execution_handles"
        )
        for handle_id in handles:
            _identifier(handle_id, "active_execution_handles[]")
        object.__setattr__(self, "active_execution_handles", handles)

    def freshness(self, now: str | None = None) -> str:
        return freshness(
            observed_at=self.observed_at, ttl_seconds=self.ttl_seconds, now=now
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            **_version_payload(self),
            "heartbeat_id": self.heartbeat_id,
            "host_id": self.host_id,
            "worker_id": self.worker_id,
            "state": self.state,
            **_observation_payload(self),
            "idempotency_key": self.idempotency_key,
            "fence_token": self.fence_token,
            "capability_sequence": self.capability_sequence,
            "resource_sequence": self.resource_sequence,
            "reserved_usage": self.reserved_usage.to_dict(),
            "actual_usage": self.actual_usage.to_dict(),
            "active_execution_handles": list(self.active_execution_handles),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "WorkerHeartbeat":
        fields = {
            "schema_version",
            "api_version",
            "heartbeat_id",
            "host_id",
            "worker_id",
            "state",
            "observed_at",
            "ttl_seconds",
            "source",
            "confidence",
            "sequence",
            "idempotency_key",
            "fence_token",
            "capability_sequence",
            "resource_sequence",
            "reserved_usage",
            "actual_usage",
            "active_execution_handles",
        }
        strict_object(data, required=fields, name="WorkerHeartbeat")
        return cls(
            schema_version=data["schema_version"],
            api_version=data["api_version"],
            heartbeat_id=data["heartbeat_id"],
            host_id=data["host_id"],
            worker_id=data["worker_id"],
            state=data["state"],
            observed_at=data["observed_at"],
            ttl_seconds=data["ttl_seconds"],
            source=data["source"],
            confidence=data["confidence"],
            sequence=data["sequence"],
            idempotency_key=data["idempotency_key"],
            fence_token=data["fence_token"],
            capability_sequence=data["capability_sequence"],
            resource_sequence=data["resource_sequence"],
            reserved_usage=ResourceUsage.from_dict(data["reserved_usage"]),
            actual_usage=ResourceUsage.from_dict(data["actual_usage"]),
            active_execution_handles=string_tuple(
                data["active_execution_handles"], "active_execution_handles"
            ),
        )


@dataclass(frozen=True, kw_only=True)
class ExecutionHandle(JsonContract):
    """A fenced execution witness; ``exited`` is not task success evidence."""

    schema_version: int = SCHEMA_VERSION
    api_version: str = WORKER_API_VERSION
    handle_id: str
    job_id: str
    attempt_id: str
    host_id: str
    worker_id: str
    state: str
    observed_at: str
    ttl_seconds: int | None
    source: str
    confidence: float | None
    sequence: int
    idempotency_key: str
    fence_token: int
    reservation_id: str | None
    process_id: str | None
    reserved_usage: ResourceUsage
    actual_usage: ResourceUsage
    artifact_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        validate_version(self.schema_version, self.api_version, WORKER_API_VERSION)
        for name in ("handle_id", "job_id", "attempt_id", "host_id", "worker_id"):
            _identifier(getattr(self, name), name)
        _enum(self.state, "state", EXECUTION_STATES)
        _validate_observation(
            observed_at=self.observed_at,
            ttl_seconds=self.ttl_seconds,
            source=self.source,
            confidence=self.confidence,
            sequence=self.sequence,
        )
        _identifier(self.idempotency_key, "idempotency_key")
        integer(self.fence_token, "fence_token", minimum=1)
        if self.reservation_id is not None:
            _identifier(self.reservation_id, "reservation_id")
        if self.process_id is not None:
            _identifier(self.process_id, "process_id")
        if self.state == "running" and (
            self.reservation_id is None or self.process_id is None
        ):
            raise ContractValidationError(
                "running execution requires reservation_id and process_id"
            )
        if not isinstance(self.reserved_usage, ResourceUsage):
            raise ContractValidationError("reserved_usage must be ResourceUsage")
        if not isinstance(self.actual_usage, ResourceUsage):
            raise ContractValidationError("actual_usage must be ResourceUsage")
        refs = string_tuple(self.artifact_refs, "artifact_refs")
        object.__setattr__(self, "artifact_refs", refs)

    def freshness(self, now: str | None = None) -> str:
        return freshness(
            observed_at=self.observed_at, ttl_seconds=self.ttl_seconds, now=now
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            **_version_payload(self),
            "handle_id": self.handle_id,
            "job_id": self.job_id,
            "attempt_id": self.attempt_id,
            "host_id": self.host_id,
            "worker_id": self.worker_id,
            "state": self.state,
            **_observation_payload(self),
            "idempotency_key": self.idempotency_key,
            "fence_token": self.fence_token,
            "reservation_id": self.reservation_id,
            "process_id": self.process_id,
            "reserved_usage": self.reserved_usage.to_dict(),
            "actual_usage": self.actual_usage.to_dict(),
            "artifact_refs": list(self.artifact_refs),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ExecutionHandle":
        fields = {
            "schema_version",
            "api_version",
            "handle_id",
            "job_id",
            "attempt_id",
            "host_id",
            "worker_id",
            "state",
            "observed_at",
            "ttl_seconds",
            "source",
            "confidence",
            "sequence",
            "idempotency_key",
            "fence_token",
            "reservation_id",
            "process_id",
            "reserved_usage",
            "actual_usage",
            "artifact_refs",
        }
        strict_object(data, required=fields, name="ExecutionHandle")
        return cls(
            schema_version=data["schema_version"],
            api_version=data["api_version"],
            handle_id=data["handle_id"],
            job_id=data["job_id"],
            attempt_id=data["attempt_id"],
            host_id=data["host_id"],
            worker_id=data["worker_id"],
            state=data["state"],
            observed_at=data["observed_at"],
            ttl_seconds=data["ttl_seconds"],
            source=data["source"],
            confidence=data["confidence"],
            sequence=data["sequence"],
            idempotency_key=data["idempotency_key"],
            fence_token=data["fence_token"],
            reservation_id=data["reservation_id"],
            process_id=data["process_id"],
            reserved_usage=ResourceUsage.from_dict(data["reserved_usage"]),
            actual_usage=ResourceUsage.from_dict(data["actual_usage"]),
            artifact_refs=string_tuple(data["artifact_refs"], "artifact_refs"),
        )


__all__ = [
    "SCHEMA_VERSION",
    "WORKER_API_VERSION",
    "HOST_ROLES",
    "CAPABILITY_KINDS",
    "CAPABILITY_STATUSES",
    "WORKER_REPORTED_STATES",
    "EXECUTION_STATES",
    "ContractValidationError",
    "Capability",
    "CpuResources",
    "MemoryResources",
    "CgroupResources",
    "MountResources",
    "GpuResources",
    "OwnedProcessResources",
    "ResourceUsage",
    "HostRegistration",
    "CapabilitySnapshot",
    "ResourceSnapshot",
    "WorkerHeartbeat",
    "ExecutionHandle",
]
