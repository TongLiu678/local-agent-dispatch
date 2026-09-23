"""Deterministic filter -> score -> reserve -> reconcile scheduling core.

This module deliberately contains no provider, subprocess, network, or live
probe code.  It consumes schema-versioned :class:`Host` snapshots and makes a
placement decision from their evidence.  Dynamic resource evidence is
fail-closed: an unknown or stale RAM, disk, route, or GPU reading cannot be
treated as capacity.

Planning is read-only.  ``ReservationBook.reserve_best`` repeats planning
while holding an in-process lock, then records a fenced reservation.  This
closes the common gap where two callers both observe enough capacity and then
oversubscribe the same target.  A durable controller can persist the returned
records and use the same fence/idempotency fields at its transaction boundary.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass, field, replace
from typing import Any, Literal, Mapping, Sequence

from ..domain.world_state import Host
from ..resources.topology import PathRequirements, evaluate_placement


SCHEDULER_SCHEMA_VERSION = 1
AssessmentVerdict = Literal["eligible", "unknown", "reject"]
ReservationState = Literal["active", "completed", "cancelled"]


def _positive_int(value: int | None, field_name: str) -> None:
    if value is not None and (isinstance(value, bool) or value < 0):
        raise ValueError(f"{field_name} must be a non-negative integer or None")


def _stable_digest(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class WorkloadRequirements:
    """P90 resource and compatibility requirements for one dispatch unit."""

    job_id: str
    memory_bytes: int
    disk_bytes: int
    disk_inodes: int | None = None
    cpu_threads: int | None = None
    gpu_vram_mib: int | None = None
    required_capabilities: tuple[str, ...] = ()
    preferred_host_ids: tuple[str, ...] = ()
    server_preferred: bool = True
    headroom_ratio: float = 0.10

    def __post_init__(self) -> None:
        if not self.job_id.strip():
            raise ValueError("job_id must be non-empty")
        _positive_int(self.memory_bytes, "memory_bytes")
        _positive_int(self.disk_bytes, "disk_bytes")
        _positive_int(self.disk_inodes, "disk_inodes")
        _positive_int(self.cpu_threads, "cpu_threads")
        _positive_int(self.gpu_vram_mib, "gpu_vram_mib")
        if not 0.0 <= self.headroom_ratio <= 10.0:
            raise ValueError("headroom_ratio must be between 0 and 10")
        if any(not item.strip() for item in self.required_capabilities):
            raise ValueError("required_capabilities must contain non-empty strings")
        object.__setattr__(self, "required_capabilities", tuple(self.required_capabilities))
        object.__setattr__(self, "preferred_host_ids", tuple(self.preferred_host_ids))

    @property
    def memory_with_headroom(self) -> int:
        return self.memory_bytes + int(round(self.memory_bytes * self.headroom_ratio))

    @property
    def gpu_with_headroom_mib(self) -> int | None:
        if self.gpu_vram_mib is None:
            return None
        return self.gpu_vram_mib + int(round(self.gpu_vram_mib * self.headroom_ratio))

    def to_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "memory_bytes": self.memory_bytes,
            "disk_bytes": self.disk_bytes,
            "disk_inodes": self.disk_inodes,
            "cpu_threads": self.cpu_threads,
            "gpu_vram_mib": self.gpu_vram_mib,
            "required_capabilities": list(self.required_capabilities),
            "preferred_host_ids": list(self.preferred_host_ids),
            "server_preferred": self.server_preferred,
            "headroom_ratio": self.headroom_ratio,
        }


@dataclass(frozen=True)
class CandidateTarget:
    """One concrete host + harness/provider/runtime execution target.

    ``workspace_path`` is intentionally target-specific.  Windows, macOS, and
    Linux workers may expose different paths; disk admission always evaluates
    the exact path and mount belonging to this target.
    """

    target_id: str
    host: Host
    workspace_path: str
    capabilities: tuple[str, ...]
    harness_id: str
    provider_id: str | None = None
    runtime_id: str | None = None
    remote: bool = False
    route_verified: bool | None = None
    execution_ready: bool | None = None
    max_lanes: int = 1
    active_lanes: int = 0
    reliability: float | None = None

    def __post_init__(self) -> None:
        if not self.target_id.strip() or not self.workspace_path.strip():
            raise ValueError("target_id and workspace_path must be non-empty")
        if not self.harness_id.strip():
            raise ValueError("harness_id must be non-empty")
        if self.max_lanes < 1 or self.active_lanes < 0:
            raise ValueError("max_lanes must be positive and active_lanes non-negative")
        if self.reliability is not None and not 0.0 <= self.reliability <= 1.0:
            raise ValueError("reliability must be between 0 and 1")
        object.__setattr__(self, "capabilities", tuple(self.capabilities))


@dataclass(frozen=True)
class ResourceUsage:
    """Capacity currently committed by this scheduler for one target."""

    memory_bytes: int = 0
    disk_bytes: int = 0
    disk_inodes: int = 0
    gpu_vram_mib: int = 0
    lanes: int = 0
    cpu_threads: int = 0

    def __post_init__(self) -> None:
        for name in (
            "memory_bytes",
            "disk_bytes",
            "disk_inodes",
            "gpu_vram_mib",
            "lanes",
            "cpu_threads",
        ):
            _positive_int(getattr(self, name), name)


@dataclass(frozen=True)
class CandidateAssessment:
    target_id: str
    host_id: str
    verdict: AssessmentVerdict
    score: float | None
    reasons: tuple[str, ...]
    available_memory_bytes: int | None = None
    safe_disk_bytes_after_request: int | None = None
    available_gpu_vram_mib: int | None = None
    lane_slots_after_request: int | None = None
    score_components: Mapping[str, float] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "reasons", tuple(self.reasons))
        object.__setattr__(self, "score_components", dict(self.score_components))


@dataclass(frozen=True)
class PlacementPlan:
    schema_version: int
    job_id: str
    decision: Literal["place", "blocked"]
    selected_target_id: str | None
    assessments: tuple[CandidateAssessment, ...]

    @property
    def selected(self) -> CandidateAssessment | None:
        if self.selected_target_id is None:
            return None
        return next(
            (row for row in self.assessments if row.target_id == self.selected_target_id),
            None,
        )


def _freshness(observation: Any, now: str | None, label: str) -> tuple[AssessmentVerdict, str | None]:
    if observation is None:
        return "unknown", f"{label} observation is missing"
    try:
        stale = observation.is_stale(now)
    except (TypeError, ValueError):
        return "unknown", f"{label} observation timestamp is invalid"
    if stale is True:
        return "reject", f"{label} observation is stale"
    if stale is None:
        if getattr(observation, "ttl_seconds", None) is None:
            return "unknown", f"{label} observation TTL is unknown"
        return "unknown", f"{label} observation freshness is unverifiable"
    return "eligible", None


def _merge_verdict(current: AssessmentVerdict, incoming: AssessmentVerdict) -> AssessmentVerdict:
    order = {"eligible": 0, "unknown": 1, "reject": 2}
    return incoming if order[incoming] > order[current] else current


def _memory_available(host: Host, usage: ResourceUsage, now: str | None) -> tuple[AssessmentVerdict, int | None, str | None]:
    if host.ram is None:
        return "unknown", None, "RAM evidence is missing"
    verdict, reason = _freshness(host.ram.observation, now, "RAM")
    if verdict != "eligible":
        return verdict, None, reason
    values = host.ram.values
    if values.available_now is None:
        return "unknown", None, "RAM available_now is unknown"
    candidates = [int(values.available_now)]
    if host.ram.cgroup_limit_bytes is not None or host.ram.cgroup_current_bytes is not None:
        if host.ram.cgroup_limit_bytes is None or host.ram.cgroup_current_bytes is None:
            return "unknown", None, "cgroup RAM evidence is incomplete"
        candidates.append(max(0, host.ram.cgroup_limit_bytes - host.ram.cgroup_current_bytes))
    snapshot_reserved = int(values.reserved or 0)
    available = max(0, min(candidates) - snapshot_reserved - usage.memory_bytes)
    return "eligible", available, None


def _gpu_available(host: Host, usage: ResourceUsage, now: str | None) -> tuple[AssessmentVerdict, int | None, str | None]:
    if not host.gpus:
        return "reject", None, "GPU is required but host reports no GPU"
    saw_unknown = False
    best: int | None = None
    for gpu in host.gpus:
        verdict, _reason = _freshness(gpu.observation, now, f"GPU {gpu.index}")
        if verdict == "unknown":
            saw_unknown = True
            continue
        if verdict == "reject" or gpu.vram is None or gpu.vram.available_now is None:
            if gpu.vram is None or gpu.vram.available_now is None:
                saw_unknown = True
            continue
        available = int(gpu.vram.available_now - (gpu.vram.reserved or 0))
        best = available if best is None else max(best, available)
    if best is None:
        if saw_unknown:
            return "unknown", None, "fresh per-device GPU VRAM evidence is unavailable"
        return "reject", None, "all GPU VRAM observations are stale"
    # Current reservations are conservatively charged against the best device.
    return "eligible", max(0, best - usage.gpu_vram_mib), None


def assess_candidate(
    candidate: CandidateTarget,
    requirements: WorkloadRequirements,
    *,
    usage: ResourceUsage = ResourceUsage(),
    now: str | None = None,
) -> CandidateAssessment:
    """Filter and score one candidate using only supplied evidence."""

    reasons: list[str] = []
    verdict: AssessmentVerdict = "eligible"

    if candidate.execution_ready is False:
        verdict = "reject"
        reasons.append("execution target is explicitly not ready")
    elif candidate.execution_ready is None:
        verdict = _merge_verdict(verdict, "unknown")
        reasons.append("execution readiness is unknown")

    if candidate.remote:
        if candidate.route_verified is False:
            verdict = "reject"
            reasons.append("remote execution route is not verified")
        elif candidate.route_verified is None:
            verdict = _merge_verdict(verdict, "unknown")
            reasons.append("remote execution route evidence is unknown")

    missing_caps = sorted(set(requirements.required_capabilities) - set(candidate.capabilities))
    if missing_caps:
        verdict = "reject"
        reasons.append("missing capabilities: " + ", ".join(missing_caps))

    lane_slots = candidate.max_lanes - candidate.active_lanes - usage.lanes - 1
    if lane_slots < 0:
        verdict = "reject"
        reasons.append("no scheduler lane is available")

    if requirements.cpu_threads is not None:
        threads = candidate.host.cpu.threads if candidate.host.cpu is not None else None
        if threads is None:
            verdict = _merge_verdict(verdict, "unknown")
            reasons.append("CPU thread capacity is unknown")
        elif threads - usage.cpu_threads < requirements.cpu_threads:
            verdict = "reject"
            reasons.append(
                f"CPU threads {max(0, threads - usage.cpu_threads)} available "
                f"< required {requirements.cpu_threads}"
            )

    memory_verdict, available_memory, memory_reason = _memory_available(
        candidate.host, usage, now
    )
    verdict = _merge_verdict(verdict, memory_verdict)
    if memory_reason:
        reasons.append(memory_reason)
    elif available_memory is not None and available_memory < requirements.memory_with_headroom:
        verdict = "reject"
        reasons.append(
            f"RAM {available_memory} < required P90+headroom {requirements.memory_with_headroom}"
        )

    disk_decision = evaluate_placement(
        candidate.host,
        candidate.workspace_path,
        PathRequirements(
            required_bytes=requirements.disk_bytes,
            required_inodes=requirements.disk_inodes,
            p90_headroom_ratio=requirements.headroom_ratio,
        ),
        now=now,
    )
    disk_verdict: AssessmentVerdict = {
        "safe": "eligible",
        "unknown": "unknown",
        "reject": "reject",
    }[disk_decision.verdict]
    verdict = _merge_verdict(verdict, disk_verdict)
    if disk_decision.verdict != "safe":
        reasons.extend(disk_decision.reasons)
    disk_after = disk_decision.safe_to_place_bytes
    if disk_after is not None:
        disk_after -= usage.disk_bytes
        if disk_after < 0:
            verdict = "reject"
            reasons.append("active reservations exhaust safe disk capacity")
    if requirements.disk_inodes is not None and usage.disk_inodes:
        if disk_decision.free_inodes is None:
            verdict = _merge_verdict(verdict, "unknown")
            reasons.append("free inode evidence is unknown")
        elif disk_decision.free_inodes - usage.disk_inodes < requirements.disk_inodes:
            verdict = "reject"
            reasons.append("active reservations exhaust safe inode capacity")

    available_gpu: int | None = None
    gpu_needed = requirements.gpu_with_headroom_mib
    if gpu_needed is not None:
        gpu_verdict, available_gpu, gpu_reason = _gpu_available(candidate.host, usage, now)
        verdict = _merge_verdict(verdict, gpu_verdict)
        if gpu_reason:
            reasons.append(gpu_reason)
        elif available_gpu is not None and available_gpu < gpu_needed:
            verdict = "reject"
            reasons.append(f"GPU VRAM {available_gpu} MiB < required {gpu_needed} MiB")

    if verdict != "eligible":
        return CandidateAssessment(
            target_id=candidate.target_id,
            host_id=candidate.host.host_id,
            verdict=verdict,
            score=None,
            reasons=tuple(dict.fromkeys(reasons)),
            available_memory_bytes=available_memory,
            safe_disk_bytes_after_request=disk_after,
            available_gpu_vram_mib=available_gpu,
            lane_slots_after_request=max(lane_slots, 0),
        )

    memory_margin = max(0, (available_memory or 0) - requirements.memory_with_headroom)
    memory_score = min(30.0, 30.0 * memory_margin / max(requirements.memory_with_headroom, 1))
    disk_score = min(20.0, 20.0 * max(disk_after or 0, 0) / max(requirements.disk_bytes, 1))
    lane_score = min(10.0, 10.0 * max(lane_slots, 0) / max(candidate.max_lanes, 1))
    preference_score = 20.0 if candidate.host.host_id in requirements.preferred_host_ids else 0.0
    topology_score = 10.0 if requirements.server_preferred and candidate.remote else 0.0
    if not requirements.server_preferred and not candidate.remote:
        topology_score = 10.0
    reliability_score = 5.0 * candidate.reliability if candidate.reliability is not None else 0.0
    route_score = 5.0 if (not candidate.remote or candidate.route_verified is True) else 0.0
    components = {
        "memory_headroom": round(memory_score, 6),
        "disk_headroom": round(disk_score, 6),
        "lane_headroom": round(lane_score, 6),
        "preferred_host": preference_score,
        "topology": topology_score,
        "reliability": round(reliability_score, 6),
        "verified_route": route_score,
    }
    score = round(sum(components.values()), 6)
    return CandidateAssessment(
        target_id=candidate.target_id,
        host_id=candidate.host.host_id,
        verdict="eligible",
        score=score,
        reasons=("all hard gates passed",),
        available_memory_bytes=available_memory,
        safe_disk_bytes_after_request=disk_after,
        available_gpu_vram_mib=available_gpu,
        lane_slots_after_request=lane_slots,
        score_components=components,
    )


def rank_candidates(
    candidates: Sequence[CandidateTarget],
    requirements: WorkloadRequirements,
    *,
    usage_by_target: Mapping[str, ResourceUsage] | None = None,
    now: str | None = None,
) -> PlacementPlan:
    """Return a deterministic, read-only placement plan."""

    usage = usage_by_target or {}
    rows = [
        assess_candidate(
            candidate,
            requirements,
            usage=usage.get(candidate.target_id, ResourceUsage()),
            now=now,
        )
        for candidate in candidates
    ]
    rows.sort(
        key=lambda row: (
            0 if row.verdict == "eligible" else 1 if row.verdict == "unknown" else 2,
            -(row.score or 0.0),
            row.target_id,
        )
    )
    selected = next((row for row in rows if row.verdict == "eligible"), None)
    return PlacementPlan(
        schema_version=SCHEDULER_SCHEMA_VERSION,
        job_id=requirements.job_id,
        decision="place" if selected else "blocked",
        selected_target_id=selected.target_id if selected else None,
        assessments=tuple(rows),
    )


@dataclass(frozen=True)
class Reservation:
    reservation_id: str
    idempotency_key: str
    request_digest: str
    job_id: str
    target_id: str
    fence_token: int
    state: ReservationState
    reserved: ResourceUsage
    actual: ResourceUsage = ResourceUsage()
    overage: bool = False


class ReservationConflict(RuntimeError):
    """Raised for stale fences or conflicting idempotent replays."""


class ReservationBook:
    """Thread-safe reference reservation ledger for one scheduler process."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._revision = 0
        self._reservations: dict[str, Reservation] = {}
        self._by_idempotency: dict[str, str] = {}
        self._plans_by_reservation: dict[str, PlacementPlan] = {}

    @property
    def revision(self) -> int:
        with self._lock:
            return self._revision

    def reservations(self) -> tuple[Reservation, ...]:
        with self._lock:
            return tuple(
                sorted(self._reservations.values(), key=lambda item: item.reservation_id)
            )

    def usage_by_target(self) -> dict[str, ResourceUsage]:
        with self._lock:
            totals: dict[str, ResourceUsage] = {}
            for row in self._reservations.values():
                if row.state != "active":
                    continue
                charge = ResourceUsage(
                    memory_bytes=max(row.reserved.memory_bytes, row.actual.memory_bytes),
                    disk_bytes=max(row.reserved.disk_bytes, row.actual.disk_bytes),
                    disk_inodes=max(row.reserved.disk_inodes, row.actual.disk_inodes),
                    gpu_vram_mib=max(row.reserved.gpu_vram_mib, row.actual.gpu_vram_mib),
                    lanes=max(row.reserved.lanes, row.actual.lanes),
                    cpu_threads=max(row.reserved.cpu_threads, row.actual.cpu_threads),
                )
                old = totals.get(row.target_id, ResourceUsage())
                totals[row.target_id] = ResourceUsage(
                    memory_bytes=old.memory_bytes + charge.memory_bytes,
                    disk_bytes=old.disk_bytes + charge.disk_bytes,
                    disk_inodes=old.disk_inodes + charge.disk_inodes,
                    gpu_vram_mib=old.gpu_vram_mib + charge.gpu_vram_mib,
                    lanes=old.lanes + charge.lanes,
                    cpu_threads=old.cpu_threads + charge.cpu_threads,
                )
            return totals

    def plan(
        self,
        candidates: Sequence[CandidateTarget],
        requirements: WorkloadRequirements,
        *,
        now: str | None = None,
    ) -> PlacementPlan:
        with self._lock:
            return rank_candidates(
                candidates,
                requirements,
                usage_by_target=self.usage_by_target(),
                now=now,
            )

    def reserve_best(
        self,
        candidates: Sequence[CandidateTarget],
        requirements: WorkloadRequirements,
        *,
        idempotency_key: str,
        expected_revision: int | None = None,
        now: str | None = None,
    ) -> tuple[PlacementPlan, Reservation | None]:
        """Atomically re-plan and reserve the best eligible target.

        A blocked plan returns ``(plan, None)``.  Replaying the same
        idempotency key and request returns the original reservation; changing
        the request under the same key raises ``ReservationConflict``.
        """

        if not idempotency_key.strip():
            raise ValueError("idempotency_key must be non-empty")
        digest = _stable_digest(requirements.to_dict())
        with self._lock:
            existing_id = self._by_idempotency.get(idempotency_key)
            if existing_id is not None:
                existing = self._reservations[existing_id]
                if existing.request_digest != digest:
                    raise ReservationConflict("idempotency key was reused for a different request")
                # Idempotent replay returns the original placement response.
                # Re-planning here would count the reservation against itself
                # and could report a blocked plan or select another target.
                plan = self._plans_by_reservation[existing_id]
                return plan, existing
            if expected_revision is not None and expected_revision != self._revision:
                raise ReservationConflict(
                    f"stale scheduler revision {expected_revision}; current is {self._revision}"
                )
            plan = self.plan(candidates, requirements, now=now)
            if plan.selected_target_id is None:
                return plan, None
            self._revision += 1
            reserved = ResourceUsage(
                memory_bytes=requirements.memory_with_headroom,
                disk_bytes=requirements.disk_bytes
                + int(round(requirements.disk_bytes * requirements.headroom_ratio)),
                disk_inodes=requirements.disk_inodes or 0,
                gpu_vram_mib=requirements.gpu_with_headroom_mib or 0,
                lanes=1,
                cpu_threads=requirements.cpu_threads or 0,
            )
            reservation_id = f"rsv-{self._revision:08d}"
            row = Reservation(
                reservation_id=reservation_id,
                idempotency_key=idempotency_key,
                request_digest=digest,
                job_id=requirements.job_id,
                target_id=plan.selected_target_id,
                fence_token=self._revision,
                state="active",
                reserved=reserved,
            )
            self._reservations[reservation_id] = row
            self._by_idempotency[idempotency_key] = reservation_id
            self._plans_by_reservation[reservation_id] = plan
            return plan, row

    def reconcile(
        self,
        reservation_id: str,
        *,
        fence_token: int,
        actual: ResourceUsage,
        terminal_state: Literal["completed", "cancelled"] | None = None,
    ) -> Reservation:
        """Record actual use and optionally release the reservation."""

        if terminal_state not in (None, "completed", "cancelled"):
            raise ValueError("terminal_state must be completed, cancelled, or None")
        with self._lock:
            try:
                row = self._reservations[reservation_id]
            except KeyError as exc:
                raise ReservationConflict(f"unknown reservation: {reservation_id}") from exc
            if row.fence_token != fence_token:
                raise ReservationConflict("stale reservation fence token")
            if row.state != "active":
                if terminal_state is None:
                    raise ReservationConflict("terminal reservation cannot return to active")
                if terminal_state != row.state:
                    raise ReservationConflict(
                        f"terminal reservation cannot transition from {row.state} "
                        f"to {terminal_state}"
                    )
                if actual != row.actual:
                    raise ReservationConflict("terminal reservation usage is immutable")
                return row
            overage = any(
                getattr(actual, name) > getattr(row.reserved, name)
                for name in (
                    "memory_bytes",
                    "disk_bytes",
                    "disk_inodes",
                    "gpu_vram_mib",
                    "lanes",
                    "cpu_threads",
                )
            )
            updated = replace(
                row,
                actual=actual,
                overage=overage,
                state=terminal_state or row.state,
            )
            if updated != row:
                self._revision += 1
                self._reservations[reservation_id] = updated
            return updated

    def cancel(self, reservation_id: str, *, fence_token: int) -> Reservation:
        return self.reconcile(
            reservation_id,
            fence_token=fence_token,
            actual=ResourceUsage(),
            terminal_state="cancelled",
        )


__all__ = [
    "SCHEDULER_SCHEMA_VERSION",
    "CandidateAssessment",
    "CandidateTarget",
    "PlacementPlan",
    "Reservation",
    "ReservationBook",
    "ReservationConflict",
    "ResourceUsage",
    "WorkloadRequirements",
    "assess_candidate",
    "rank_candidates",
]
