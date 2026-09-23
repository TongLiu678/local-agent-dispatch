"""Schema-versioned resource digital twin for the world-state plane.

Every record is a frozen dataclass with explicit ``to_dict``/``from_dict``
serialization so snapshots can be persisted, compared, and replayed without
running any live probe.  Unknown values are preserved as ``None``; they are
never converted into fabricated numbers.

The five resource value kinds are kept distinct on every sized record:

- ``capacity``: physical/declared total;
- ``allocatable``: total after system-reserved overhead;
- ``available_now``: free at the last observation;
- ``reserved``: already committed to inflight or future work;
- safe-to-place: derived by the placement gate (``resources/topology.py``) as
  available capacity minus reservations minus P90 headroom.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping, Optional, Sequence, Tuple

SCHEMA_VERSION = 1

ROUTE_KINDS = ("control", "artifact", "bulk_data", "execution", "workload")
ROUTE_STATUSES = ("direct", "bastion", "proxy", "relay", "unknown")

PLACEMENT_VERDICTS = ("safe", "unknown", "reject")


def _parse_iso(value: str) -> datetime:
    """Parse an ISO-8601 timestamp, tolerating ``Z`` and naive timestamps."""
    text = value.strip()
    if text.endswith("Z") or text.endswith("z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _min_known(values: Sequence[Optional[float]]) -> Optional[float]:
    """Smallest non-None value, or None when every input is unknown."""
    known = [v for v in values if v is not None]
    return min(known) if known else None


@dataclass(frozen=True)
class Observation:
    """A timestamped, sourced measurement with a TTL and optional confidence.

    ``confidence`` is ``None`` when the probing source cannot quantify how
    trustworthy a reading is; it is never replaced with a default.
    """

    kind: str
    source: str
    observed_at: str
    evidence: Tuple[str, ...] = ()
    ttl_seconds: Optional[float] = None
    confidence: Optional[float] = None

    def is_stale(self, now: Optional[str] = None) -> Optional[bool]:
        """Return three-valued freshness for this observation.

        ``True`` means the TTL has expired and ``False`` means freshness was
        verified against a known TTL.  ``None`` means freshness cannot be
        established, either because the TTL is unknown or because the
        observation claims to come from the future relative to ``now``.
        Future-dated evidence must not be accepted as indefinitely fresh.
        """
        if self.ttl_seconds is None:
            return None
        anchor = now or datetime.now(timezone.utc).isoformat()
        age = (_parse_iso(anchor) - _parse_iso(self.observed_at)).total_seconds()
        if age < 0:
            return None
        return age > self.ttl_seconds

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "kind": self.kind,
            "source": self.source,
            "observed_at": self.observed_at,
        }
        if self.evidence:
            payload["evidence"] = list(self.evidence)
        if self.ttl_seconds is not None:
            payload["ttl_seconds"] = self.ttl_seconds
        if self.confidence is not None:
            payload["confidence"] = self.confidence
        return payload

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Observation":
        return cls(
            kind=str(data["kind"]),
            source=str(data["source"]),
            observed_at=str(data["observed_at"]),
            evidence=tuple(str(e) for e in data.get("evidence", ())),
            ttl_seconds=data.get("ttl_seconds"),
            confidence=data.get("confidence"),
        )


@dataclass(frozen=True)
class ResourceValues:
    """Sized values with capacity/allocatable/available/reserved kept apart."""

    units: str
    capacity: Optional[float] = None
    allocatable: Optional[float] = None
    available_now: Optional[float] = None
    reserved: Optional[float] = None
    used: Optional[float] = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"units": self.units}
        for key in ("capacity", "allocatable", "available_now", "reserved", "used"):
            value = getattr(self, key)
            if value is not None:
                payload[key] = value
        return payload

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ResourceValues":
        return cls(
            units=str(data["units"]),
            capacity=data.get("capacity"),
            allocatable=data.get("allocatable"),
            available_now=data.get("available_now"),
            reserved=data.get("reserved"),
            used=data.get("used"),
        )


@dataclass(frozen=True)
class NumaNode:
    node_id: str
    cpu_ids: Tuple[str, ...] = ()
    ram_bytes: Optional[int] = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"node_id": self.node_id, "cpu_ids": list(self.cpu_ids)}
        if self.ram_bytes is not None:
            payload["ram_bytes"] = self.ram_bytes
        return payload

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "NumaNode":
        return cls(
            node_id=str(data["node_id"]),
            cpu_ids=tuple(str(c) for c in data.get("cpu_ids", ())),
            ram_bytes=data.get("ram_bytes"),
        )


@dataclass(frozen=True)
class NumaTopology:
    nodes: Tuple[NumaNode, ...] = ()
    distances: Optional[Tuple[Tuple[int, ...], ...]] = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"nodes": [n.to_dict() for n in self.nodes]}
        if self.distances is not None:
            payload["distances"] = [list(row) for row in self.distances]
        return payload

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "NumaTopology":
        distances = data.get("distances")
        return cls(
            nodes=tuple(NumaNode.from_dict(n) for n in data.get("nodes", ())),
            distances=tuple(tuple(int(v) for v in row) for row in distances)
            if distances is not None
            else None,
        )


@dataclass(frozen=True)
class CpuTopology:
    sockets: Optional[int] = None
    cores: Optional[int] = None
    threads: Optional[int] = None
    model: Optional[str] = None
    numa: Optional[NumaTopology] = None
    observation: Optional[Observation] = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {}
        for key in ("sockets", "cores", "threads", "model"):
            value = getattr(self, key)
            if value is not None:
                payload[key] = value
        if self.numa is not None:
            payload["numa"] = self.numa.to_dict()
        if self.observation is not None:
            payload["observation"] = self.observation.to_dict()
        return payload

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CpuTopology":
        return cls(
            sockets=data.get("sockets"),
            cores=data.get("cores"),
            threads=data.get("threads"),
            model=data.get("model"),
            numa=NumaTopology.from_dict(data["numa"]) if data.get("numa") else None,
            observation=Observation.from_dict(data["observation"])
            if data.get("observation")
            else None,
        )


@dataclass(frozen=True)
class RamState:
    values: ResourceValues
    cgroup_limit_bytes: Optional[int] = None
    cgroup_current_bytes: Optional[int] = None
    observation: Optional[Observation] = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"values": self.values.to_dict()}
        if self.cgroup_limit_bytes is not None:
            payload["cgroup_limit_bytes"] = self.cgroup_limit_bytes
        if self.cgroup_current_bytes is not None:
            payload["cgroup_current_bytes"] = self.cgroup_current_bytes
        if self.observation is not None:
            payload["observation"] = self.observation.to_dict()
        return payload

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "RamState":
        return cls(
            values=ResourceValues.from_dict(data["values"]),
            cgroup_limit_bytes=data.get("cgroup_limit_bytes"),
            cgroup_current_bytes=data.get("cgroup_current_bytes"),
            observation=Observation.from_dict(data["observation"])
            if data.get("observation")
            else None,
        )


@dataclass(frozen=True)
class GpuProcess:
    pid: int
    name: str
    vram_mib: Optional[int] = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"pid": self.pid, "name": self.name}
        if self.vram_mib is not None:
            payload["vram_mib"] = self.vram_mib
        return payload

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "GpuProcess":
        return cls(
            pid=int(data["pid"]),
            name=str(data["name"]),
            vram_mib=data.get("vram_mib"),
        )


@dataclass(frozen=True)
class GpuState:
    index: str
    model: Optional[str] = None
    vram: Optional[ResourceValues] = None
    processes: Tuple[GpuProcess, ...] = ()
    cuda_compatible: Optional[bool] = None
    observation: Optional[Observation] = None

    def in_use_vram_mib(self) -> Optional[int]:
        """Sum of observed GPU process VRAM; None when any process lacks one."""
        total = 0
        for process in self.processes:
            if process.vram_mib is None:
                return None
            total += process.vram_mib
        return total

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"index": self.index}
        if self.model is not None:
            payload["model"] = self.model
        if self.vram is not None:
            payload["vram"] = self.vram.to_dict()
        if self.processes:
            payload["processes"] = [p.to_dict() for p in self.processes]
        if self.cuda_compatible is not None:
            payload["cuda_compatible"] = self.cuda_compatible
        if self.observation is not None:
            payload["observation"] = self.observation.to_dict()
        return payload

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "GpuState":
        return cls(
            index=str(data["index"]),
            model=data.get("model"),
            vram=ResourceValues.from_dict(data["vram"]) if data.get("vram") else None,
            processes=tuple(GpuProcess.from_dict(p) for p in data.get("processes", ())),
            cuda_compatible=data.get("cuda_compatible"),
            observation=Observation.from_dict(data["observation"])
            if data.get("observation")
            else None,
        )


@dataclass(frozen=True)
class QuotaState:
    kind: str
    unit: str
    limit: Optional[float] = None
    used: Optional[float] = None
    free: Optional[float] = None
    source: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"kind": self.kind, "unit": self.unit}
        for key in ("limit", "used", "free", "source"):
            value = getattr(self, key)
            if value is not None:
                payload[key] = value
        return payload

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "QuotaState":
        return cls(
            kind=str(data["kind"]),
            unit=str(data["unit"]),
            limit=data.get("limit"),
            used=data.get("used"),
            free=data.get("free"),
            source=data.get("source"),
        )


@dataclass(frozen=True)
class MountState:
    """One filesystem mount with exact-path probe evidence.

    ``probed_path`` records the directory that was actually measured; it is
    ``None`` when the mount was listed (e.g. by ``mountinfo``) but never
    probed.  Placement must never substitute evidence from a different mount
    (for example root-only probing) for this one.
    """

    path: str
    device: Optional[str] = None
    fs_type: Optional[str] = None
    options: Tuple[str, ...] = ()
    writable: Optional[bool] = None
    probed_path: Optional[str] = None
    values: ResourceValues = field(
        default_factory=lambda: ResourceValues(units="bytes")
    )
    free_bytes: Optional[int] = None
    free_inodes: Optional[int] = None
    quota: Optional[QuotaState] = None
    observation: Optional[Observation] = None

    def is_probed(self) -> bool:
        return self.probed_path is not None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"path": self.path}
        for key in ("device", "fs_type"):
            value = getattr(self, key)
            if value is not None:
                payload[key] = value
        if self.options:
            payload["options"] = list(self.options)
        if self.writable is not None:
            payload["writable"] = self.writable
        if self.probed_path is not None:
            payload["probed_path"] = self.probed_path
        payload["values"] = self.values.to_dict()
        if self.free_bytes is not None:
            payload["free_bytes"] = self.free_bytes
        if self.free_inodes is not None:
            payload["free_inodes"] = self.free_inodes
        if self.quota is not None:
            payload["quota"] = self.quota.to_dict()
        if self.observation is not None:
            payload["observation"] = self.observation.to_dict()
        return payload

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "MountState":
        return cls(
            path=str(data["path"]),
            device=data.get("device"),
            fs_type=data.get("fs_type"),
            options=tuple(str(o) for o in data.get("options", ())),
            writable=data.get("writable"),
            probed_path=data.get("probed_path"),
            values=ResourceValues.from_dict(data.get("values", {"units": "bytes"})),
            free_bytes=data.get("free_bytes"),
            free_inodes=data.get("free_inodes"),
            quota=QuotaState.from_dict(data["quota"]) if data.get("quota") else None,
            observation=Observation.from_dict(data["observation"])
            if data.get("observation")
            else None,
        )


@dataclass(frozen=True)
class RuntimeState:
    name: str
    version: Optional[str] = None
    compatible: Optional[bool] = None
    cuda_supported: Optional[bool] = None
    observation: Optional[Observation] = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"name": self.name}
        for key in ("version", "compatible", "cuda_supported"):
            value = getattr(self, key)
            if value is not None:
                payload[key] = value
        if self.observation is not None:
            payload["observation"] = self.observation.to_dict()
        return payload

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "RuntimeState":
        return cls(
            name=str(data["name"]),
            version=data.get("version"),
            compatible=data.get("compatible"),
            cuda_supported=data.get("cuda_supported"),
            observation=Observation.from_dict(data["observation"])
            if data.get("observation")
            else None,
        )


@dataclass(frozen=True)
class CacheState:
    path: str
    mount_path: Optional[str] = None
    declared_bytes: Optional[int] = None
    observation: Optional[Observation] = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"path": self.path}
        if self.mount_path is not None:
            payload["mount_path"] = self.mount_path
        if self.declared_bytes is not None:
            payload["declared_bytes"] = self.declared_bytes
        if self.observation is not None:
            payload["observation"] = self.observation.to_dict()
        return payload

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CacheState":
        return cls(
            path=str(data["path"]),
            mount_path=data.get("mount_path"),
            declared_bytes=data.get("declared_bytes"),
            observation=Observation.from_dict(data["observation"])
            if data.get("observation")
            else None,
        )


@dataclass(frozen=True)
class DatasetLocation:
    name: str
    path: str
    mount_path: Optional[str] = None
    bytes_total: Optional[int] = None
    classification: Optional[str] = None
    observation: Optional[Observation] = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"name": self.name, "path": self.path}
        for key in ("mount_path", "bytes_total", "classification"):
            value = getattr(self, key)
            if value is not None:
                payload[key] = value
        if self.observation is not None:
            payload["observation"] = self.observation.to_dict()
        return payload

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "DatasetLocation":
        return cls(
            name=str(data["name"]),
            path=str(data["path"]),
            mount_path=data.get("mount_path"),
            bytes_total=data.get("bytes_total"),
            classification=data.get("classification"),
            observation=Observation.from_dict(data["observation"])
            if data.get("observation")
            else None,
        )


@dataclass(frozen=True)
class RouteRecord:
    """One network route kind with verification time and direct/indirect status.

    ``status`` is one of ``direct``, ``bastion``, ``proxy``, ``relay``, or
    ``unknown``.  A missing or unverified route is reported as ``unknown`` and
    never upgraded to ``direct`` by inference.
    """

    kind: str
    status: str
    verified_at: Optional[str] = None
    evidence: Tuple[str, ...] = ()
    peer: Optional[str] = None
    rtt_ms: Optional[float] = None
    throughput_mbps: Optional[float] = None
    ssh_config: Optional[str] = None
    observation: Optional[Observation] = None

    def __post_init__(self) -> None:
        if self.kind not in ROUTE_KINDS:
            raise ValueError(f"unknown route kind: {self.kind!r}")
        if self.status not in ROUTE_STATUSES:
            raise ValueError(f"unknown route status: {self.status!r}")

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"kind": self.kind, "status": self.status}
        if self.verified_at is not None:
            payload["verified_at"] = self.verified_at
        if self.evidence:
            payload["evidence"] = list(self.evidence)
        for key in ("peer", "rtt_ms", "throughput_mbps", "ssh_config"):
            value = getattr(self, key)
            if value is not None:
                payload[key] = value
        if self.observation is not None:
            payload["observation"] = self.observation.to_dict()
        return payload

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "RouteRecord":
        record = cls(
            kind=str(data["kind"]),
            status=str(data["status"]),
            verified_at=data.get("verified_at"),
            evidence=tuple(str(e) for e in data.get("evidence", ())),
            peer=data.get("peer"),
            rtt_ms=data.get("rtt_ms"),
            throughput_mbps=data.get("throughput_mbps"),
            ssh_config=data.get("ssh_config"),
            observation=Observation.from_dict(data["observation"])
            if data.get("observation")
            else None,
        )
        # Untrusted serialized state must not upgrade a route to direct solely
        # from a status string.  Keep the constructor permissive for trusted
        # in-memory fixtures, but enforce the evidence contract at the
        # persistence/deserialization boundary used by live world snapshots.
        if record.status == "direct" and (
            not record.verified_at or not record.evidence
        ):
            raise ValueError(
                "direct route requires verified_at and non-empty evidence"
            )
        return record


@dataclass(frozen=True)
class Host:
    host_id: str
    name: str
    os: Optional[str] = None
    arch: Optional[str] = None
    execution_host: bool = False
    workload_host: bool = False
    cpu: Optional[CpuTopology] = None
    ram: Optional[RamState] = None
    gpus: Tuple[GpuState, ...] = ()
    mounts: Tuple[MountState, ...] = ()
    runtimes: Tuple[RuntimeState, ...] = ()
    caches: Tuple[CacheState, ...] = ()
    datasets: Tuple[DatasetLocation, ...] = ()
    observations: Tuple[Observation, ...] = ()
    labels: Tuple[str, ...] = ()

    def mount(self, path: str) -> Optional[MountState]:
        normalized = path.rstrip("/") or "/"
        for mount in self.mounts:
            if mount.path.rstrip("/") == normalized:
                return mount
        return None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "host_id": self.host_id,
            "name": self.name,
        }
        for key in ("os", "arch"):
            value = getattr(self, key)
            if value is not None:
                payload[key] = value
        if self.execution_host:
            payload["execution_host"] = True
        if self.workload_host:
            payload["workload_host"] = True
        if self.cpu is not None:
            payload["cpu"] = self.cpu.to_dict()
        if self.ram is not None:
            payload["ram"] = self.ram.to_dict()
        if self.gpus:
            payload["gpus"] = [g.to_dict() for g in self.gpus]
        if self.mounts:
            payload["mounts"] = [m.to_dict() for m in self.mounts]
        if self.runtimes:
            payload["runtimes"] = [r.to_dict() for r in self.runtimes]
        if self.caches:
            payload["caches"] = [c.to_dict() for c in self.caches]
        if self.datasets:
            payload["datasets"] = [d.to_dict() for d in self.datasets]
        if self.observations:
            payload["observations"] = [o.to_dict() for o in self.observations]
        if self.labels:
            payload["labels"] = list(self.labels)
        return payload

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Host":
        return cls(
            host_id=str(data["host_id"]),
            name=str(data["name"]),
            os=data.get("os"),
            arch=data.get("arch"),
            execution_host=bool(data.get("execution_host", False)),
            workload_host=bool(data.get("workload_host", False)),
            cpu=CpuTopology.from_dict(data["cpu"]) if data.get("cpu") else None,
            ram=RamState.from_dict(data["ram"]) if data.get("ram") else None,
            gpus=tuple(GpuState.from_dict(g) for g in data.get("gpus", ())),
            mounts=tuple(MountState.from_dict(m) for m in data.get("mounts", ())),
            runtimes=tuple(
                RuntimeState.from_dict(r) for r in data.get("runtimes", ())
            ),
            caches=tuple(CacheState.from_dict(c) for c in data.get("caches", ())),
            datasets=tuple(
                DatasetLocation.from_dict(d) for d in data.get("datasets", ())
            ),
            observations=tuple(
                Observation.from_dict(o) for o in data.get("observations", ())
            ),
            labels=tuple(str(label) for label in data.get("labels", ())),
        )


@dataclass(frozen=True)
class WorldStateSnapshot:
    """Versioned projection of hosts, routes, and observations.

    ``execution_host``/``workload_host`` are host roles and
    ``control``/``artifact``/``bulk_data`` routes are separate records; they
    must never be merged or inferred from each other.
    """

    schema_version: int = SCHEMA_VERSION
    created_at: str = ""
    hosts: Tuple[Host, ...] = ()
    routes: Tuple[RouteRecord, ...] = ()
    observations: Tuple[Observation, ...] = ()

    def host(self, host_id: str) -> Optional[Host]:
        for host in self.hosts:
            if host.host_id == host_id:
                return host
        return None

    def route(self, kind: str) -> Optional[RouteRecord]:
        for route in self.routes:
            if route.kind == kind:
                return route
        return None

    def route_status(self, kind: str) -> str:
        """Exact recorded status, or ``unknown`` when no evidence exists."""
        route = self.route(kind)
        if route is None:
            return "unknown"
        return route.status

    def hosts_with_role(self, execution: bool = False, workload: bool = False) -> Tuple[Host, ...]:
        return tuple(
            host
            for host in self.hosts
            if host.execution_host == execution and host.workload_host == workload
        )

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"schema_version": self.schema_version}
        if self.created_at:
            payload["created_at"] = self.created_at
        if self.hosts:
            payload["hosts"] = [h.to_dict() for h in self.hosts]
        if self.routes:
            payload["routes"] = [r.to_dict() for r in self.routes]
        if self.observations:
            payload["observations"] = [o.to_dict() for o in self.observations]
        return payload

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "WorldStateSnapshot":
        version = data.get("schema_version")
        if version != SCHEMA_VERSION:
            raise ValueError(
                f"unsupported world_state schema_version {version!r}; "
                f"expected {SCHEMA_VERSION}"
            )
        return cls(
            schema_version=version,
            created_at=str(data.get("created_at", "")),
            hosts=tuple(Host.from_dict(h) for h in data.get("hosts", ())),
            routes=tuple(RouteRecord.from_dict(r) for r in data.get("routes", ())),
            observations=tuple(
                Observation.from_dict(o) for o in data.get("observations", ())
            ),
        )


__all__ = [
    "SCHEMA_VERSION",
    "ROUTE_KINDS",
    "ROUTE_STATUSES",
    "PLACEMENT_VERDICTS",
    "Observation",
    "ResourceValues",
    "NumaNode",
    "NumaTopology",
    "CpuTopology",
    "RamState",
    "GpuProcess",
    "GpuState",
    "QuotaState",
    "MountState",
    "RuntimeState",
    "CacheState",
    "DatasetLocation",
    "RouteRecord",
    "Host",
    "WorldStateSnapshot",
]
