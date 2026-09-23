"""Layered scheduling policy and provider-free adaptive concurrency.

The module is intentionally pure: it reads no files, performs no probes, and
contacts no providers.  Callers may atomically replace an
``OrganizationPolicy`` value after validating a hot-reload payload, then pass
the resulting policy and already-observed facts to ``adapt_concurrency``.

Safety invariants always win.  Organization policy and per-task preferences
may tighten a safety floor or ceiling, but attempts to weaken one are ignored
and reported as deterministic diagnostics.
"""

from __future__ import annotations

import json
import math
import posixpath
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

from ..api.contracts import ResourceSnapshot, ResourceUsage, WorkerHeartbeat


POLICY_SCHEMA_VERSION = 1
POLICY_API_VERSION = "local-agent-dispatch.scheduling-policy.v1"
SCHEDULER_DECISION_INPUT_SCHEMA_VERSION = 1

DiagnosticSeverity = Literal["warning", "error"]
DecisionStatus = Literal["blocked", "increase", "decrease", "hold"]

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$")
_WINDOWS_ABS_RE = re.compile(r"^[A-Za-z]:[\\/]")


def _canonical_mount_path(value: str) -> str:
    normalized = value.replace("\\", "/")
    if _WINDOWS_ABS_RE.match(value):
        suffix = "/" + normalized[2:].lstrip("/")
        return normalized[0].upper() + ":" + posixpath.normpath(suffix)
    return posixpath.normpath(normalized)


def _mount_path_key(value: str) -> tuple[str, str]:
    canonical = _canonical_mount_path(value)
    if _WINDOWS_ABS_RE.match(canonical) or canonical.startswith("//"):
        return "windows", canonical.casefold()
    return "posix", canonical


class SchedulingPolicyError(ValueError):
    """A policy document is malformed or cannot be hot-reloaded safely."""


def _integer(value: Any, name: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise SchedulingPolicyError(f"{name} must be an integer >= {minimum}")
    return value


def _number(
    value: Any,
    name: str,
    *,
    minimum: float | None = None,
    maximum: float | None = None,
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SchedulingPolicyError(f"{name} must be a number")
    result = float(value)
    if not math.isfinite(result):
        raise SchedulingPolicyError(f"{name} must be finite")
    if minimum is not None and result < minimum:
        raise SchedulingPolicyError(f"{name} must be >= {minimum}")
    if maximum is not None and result > maximum:
        raise SchedulingPolicyError(f"{name} must be <= {maximum}")
    return result


def _identifier(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise SchedulingPolicyError(f"{name} must be a bounded path-free identifier")
    return value


def _strict_object(data: Any, fields: set[str], name: str) -> Mapping[str, Any]:
    if not isinstance(data, Mapping):
        raise SchedulingPolicyError(f"{name} must be an object")
    if any(not isinstance(key, str) for key in data):
        raise SchedulingPolicyError(f"{name} field names must be strings")
    missing = sorted(fields - set(data))
    unknown = sorted(set(data) - fields)
    if missing:
        raise SchedulingPolicyError(
            f"{name} is missing required field(s): {', '.join(missing)}"
        )
    if unknown:
        raise SchedulingPolicyError(
            f"{name} contains unknown field(s): {', '.join(unknown)}"
        )
    return data


def _optional_integer(value: Any, name: str) -> int | None:
    return None if value is None else _integer(value, name)


def _optional_ratio(value: Any, name: str) -> float | None:
    return None if value is None else _number(value, name, minimum=0, maximum=1)


def _optional_positive_number(value: Any, name: str) -> float | None:
    if value is None:
        return None
    result = _number(value, name, minimum=0)
    if result == 0:
        raise SchedulingPolicyError(f"{name} must be > 0")
    return result


def _parse_time(value: str, name: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise SchedulingPolicyError(f"{name} must be an RFC 3339 timestamp")
    normalized = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
    try:
        result = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise SchedulingPolicyError(f"{name} must be an RFC 3339 timestamp") from exc
    if result.tzinfo is None or result.utcoffset() is None:
        raise SchedulingPolicyError(f"{name} must include a timezone offset")
    return result.astimezone(timezone.utc)


def _now(value: str | datetime | None) -> tuple[datetime, str]:
    if value is None:
        parsed = datetime.now(timezone.utc)
    elif isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise SchedulingPolicyError("now must include timezone information")
        parsed = value.astimezone(timezone.utc)
    else:
        parsed = _parse_time(value, "now")
    return parsed, parsed.isoformat()


@dataclass(frozen=True, kw_only=True)
class SafetyInvariants:
    """Deployment-owned bounds that runtime policy cannot weaken."""

    hard_max_concurrency: int
    min_memory_reserve_bytes: int
    min_disk_reserve_bytes: int
    min_quota_reserve_ratio: float
    max_error_rate: float
    require_fresh_telemetry: bool = field(default=True, init=False)
    unknown_concurrency: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        _integer(self.hard_max_concurrency, "hard_max_concurrency")
        _integer(self.min_memory_reserve_bytes, "min_memory_reserve_bytes")
        _integer(self.min_disk_reserve_bytes, "min_disk_reserve_bytes")
        _number(
            self.min_quota_reserve_ratio,
            "min_quota_reserve_ratio",
            minimum=0,
            maximum=1,
        )
        _number(self.max_error_rate, "max_error_rate", minimum=0, maximum=1)

    def to_dict(self) -> dict[str, Any]:
        return {
            "hard_max_concurrency": self.hard_max_concurrency,
            "min_memory_reserve_bytes": self.min_memory_reserve_bytes,
            "min_disk_reserve_bytes": self.min_disk_reserve_bytes,
            "min_quota_reserve_ratio": self.min_quota_reserve_ratio,
            "max_error_rate": self.max_error_rate,
            "require_fresh_telemetry": self.require_fresh_telemetry,
            "unknown_concurrency": self.unknown_concurrency,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "SafetyInvariants":
        fields = {
            "hard_max_concurrency",
            "min_memory_reserve_bytes",
            "min_disk_reserve_bytes",
            "min_quota_reserve_ratio",
            "max_error_rate",
            "require_fresh_telemetry",
            "unknown_concurrency",
        }
        data = _strict_object(data, fields, "SafetyInvariants")
        if data["require_fresh_telemetry"] is not True:
            raise SchedulingPolicyError("require_fresh_telemetry must be true")
        if data["unknown_concurrency"] != 0 or isinstance(
            data["unknown_concurrency"], bool
        ):
            raise SchedulingPolicyError("unknown_concurrency must be 0")
        return cls(
            hard_max_concurrency=data["hard_max_concurrency"],
            min_memory_reserve_bytes=data["min_memory_reserve_bytes"],
            min_disk_reserve_bytes=data["min_disk_reserve_bytes"],
            min_quota_reserve_ratio=data["min_quota_reserve_ratio"],
            max_error_rate=data["max_error_rate"],
        )


@dataclass(frozen=True, kw_only=True)
class OrganizationPolicy:
    """Revisioned value that a caller may atomically hot-reload."""

    policy_id: str
    revision: int
    min_concurrency: int
    max_concurrency: int
    memory_reserve_bytes: int
    disk_reserve_bytes: int
    quota_reserve_ratio: float
    max_error_rate: float
    target_latency_seconds: float
    additive_increase: int = 1
    decrease_factor: float = 0.5
    scale_up_windows: int = 2
    cooldown_seconds: int = 30

    def __post_init__(self) -> None:
        _identifier(self.policy_id, "policy_id")
        _integer(self.revision, "revision", minimum=1)
        _integer(self.min_concurrency, "min_concurrency")
        _integer(self.max_concurrency, "max_concurrency")
        _integer(self.memory_reserve_bytes, "memory_reserve_bytes")
        _integer(self.disk_reserve_bytes, "disk_reserve_bytes")
        _number(self.quota_reserve_ratio, "quota_reserve_ratio", minimum=0, maximum=1)
        _number(self.max_error_rate, "max_error_rate", minimum=0, maximum=1)
        _optional_positive_number(
            self.target_latency_seconds, "target_latency_seconds"
        )
        _integer(self.additive_increase, "additive_increase", minimum=1)
        factor = _number(self.decrease_factor, "decrease_factor", minimum=0)
        if factor <= 0 or factor >= 1:
            raise SchedulingPolicyError("decrease_factor must be within (0, 1)")
        _integer(self.scale_up_windows, "scale_up_windows", minimum=1)
        _integer(self.cooldown_seconds, "cooldown_seconds")

    def to_dict(self) -> dict[str, Any]:
        return {
            name: getattr(self, name)
            for name in (
                "policy_id",
                "revision",
                "min_concurrency",
                "max_concurrency",
                "memory_reserve_bytes",
                "disk_reserve_bytes",
                "quota_reserve_ratio",
                "max_error_rate",
                "target_latency_seconds",
                "additive_increase",
                "decrease_factor",
                "scale_up_windows",
                "cooldown_seconds",
            )
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "OrganizationPolicy":
        fields = {
            "policy_id",
            "revision",
            "min_concurrency",
            "max_concurrency",
            "memory_reserve_bytes",
            "disk_reserve_bytes",
            "quota_reserve_ratio",
            "max_error_rate",
            "target_latency_seconds",
            "additive_increase",
            "decrease_factor",
            "scale_up_windows",
            "cooldown_seconds",
        }
        data = _strict_object(data, fields, "OrganizationPolicy")
        return cls(**{name: data[name] for name in fields})


@dataclass(frozen=True, kw_only=True)
class TaskPreferences:
    """Task-local soft requests; ``None`` inherits organization policy."""

    task_id: str
    preferred_min_concurrency: int | None = None
    preferred_max_concurrency: int | None = None
    memory_reserve_bytes: int | None = None
    disk_reserve_bytes: int | None = None
    quota_reserve_ratio: float | None = None
    max_error_rate: float | None = None
    target_latency_seconds: float | None = None

    def __post_init__(self) -> None:
        _identifier(self.task_id, "task_id")
        _optional_integer(self.preferred_min_concurrency, "preferred_min_concurrency")
        _optional_integer(self.preferred_max_concurrency, "preferred_max_concurrency")
        _optional_integer(self.memory_reserve_bytes, "memory_reserve_bytes")
        _optional_integer(self.disk_reserve_bytes, "disk_reserve_bytes")
        _optional_ratio(self.quota_reserve_ratio, "quota_reserve_ratio")
        _optional_ratio(self.max_error_rate, "max_error_rate")
        _optional_positive_number(
            self.target_latency_seconds, "target_latency_seconds"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            name: getattr(self, name)
            for name in (
                "task_id",
                "preferred_min_concurrency",
                "preferred_max_concurrency",
                "memory_reserve_bytes",
                "disk_reserve_bytes",
                "quota_reserve_ratio",
                "max_error_rate",
                "target_latency_seconds",
            )
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "TaskPreferences":
        fields = {
            "task_id",
            "preferred_min_concurrency",
            "preferred_max_concurrency",
            "memory_reserve_bytes",
            "disk_reserve_bytes",
            "quota_reserve_ratio",
            "max_error_rate",
            "target_latency_seconds",
        }
        data = _strict_object(data, fields, "TaskPreferences")
        return cls(**{name: data[name] for name in fields})


@dataclass(frozen=True, kw_only=True)
class SchedulingPolicyBundle:
    schema_version: int = POLICY_SCHEMA_VERSION
    api_version: str = POLICY_API_VERSION
    safety: SafetyInvariants
    organization: OrganizationPolicy
    task: TaskPreferences | None = None

    def __post_init__(self) -> None:
        if (
            isinstance(self.schema_version, bool)
            or self.schema_version != POLICY_SCHEMA_VERSION
        ):
            raise SchedulingPolicyError("unsupported scheduling policy schema_version")
        if self.api_version != POLICY_API_VERSION:
            raise SchedulingPolicyError("unsupported scheduling policy api_version")
        if not isinstance(self.safety, SafetyInvariants):
            raise SchedulingPolicyError("safety must be SafetyInvariants")
        if not isinstance(self.organization, OrganizationPolicy):
            raise SchedulingPolicyError("organization must be OrganizationPolicy")
        if self.task is not None and not isinstance(self.task, TaskPreferences):
            raise SchedulingPolicyError("task must be TaskPreferences or null")

    def with_organization(
        self, candidate: OrganizationPolicy
    ) -> "SchedulingPolicyBundle":
        """Return a revision-advanced bundle; the caller owns atomic swapping."""

        if candidate.policy_id != self.organization.policy_id:
            raise SchedulingPolicyError("hot reload cannot change policy_id")
        if candidate.revision <= self.organization.revision:
            raise SchedulingPolicyError("hot reload revision must increase")
        return SchedulingPolicyBundle(
            safety=self.safety,
            organization=candidate,
            task=self.task,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "api_version": self.api_version,
            "safety": self.safety.to_dict(),
            "organization": self.organization.to_dict(),
            "task": self.task.to_dict() if self.task is not None else None,
        }

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "SchedulingPolicyBundle":
        fields = {"schema_version", "api_version", "safety", "organization", "task"}
        data = _strict_object(data, fields, "SchedulingPolicyBundle")
        return cls(
            schema_version=data["schema_version"],
            api_version=data["api_version"],
            safety=SafetyInvariants.from_dict(data["safety"]),
            organization=OrganizationPolicy.from_dict(data["organization"]),
            task=(
                TaskPreferences.from_dict(data["task"])
                if data["task"] is not None
                else None
            ),
        )

    @classmethod
    def from_json(cls, text: str) -> "SchedulingPolicyBundle":
        if not isinstance(text, str):
            raise SchedulingPolicyError("policy JSON must be text")

        def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise SchedulingPolicyError(f"duplicate JSON key: {key!r}")
                result[key] = value
            return result

        try:
            data = json.loads(text, object_pairs_hook=reject_duplicates)
        except SchedulingPolicyError:
            raise
        except (json.JSONDecodeError, TypeError) as exc:
            raise SchedulingPolicyError("invalid policy JSON") from exc
        return cls.from_dict(data)


@dataclass(frozen=True)
class PolicyDiagnostic:
    code: str
    layer: str
    field: str
    severity: DiagnosticSeverity
    requested: int | float | None
    applied: int | float | None
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "layer": self.layer,
            "field": self.field,
            "severity": self.severity,
            "requested": self.requested,
            "applied": self.applied,
            "message": self.message,
        }


@dataclass(frozen=True, kw_only=True)
class EffectiveSchedulingPolicy:
    policy_id: str
    revision: int
    task_id: str | None
    min_concurrency: int
    max_concurrency: int
    memory_reserve_bytes: int
    disk_reserve_bytes: int
    quota_reserve_ratio: float
    max_error_rate: float
    target_latency_seconds: float
    additive_increase: int
    decrease_factor: float
    scale_up_windows: int
    cooldown_seconds: int

    def to_dict(self) -> dict[str, Any]:
        return {
            name: getattr(self, name)
            for name in (
                "policy_id",
                "revision",
                "task_id",
                "min_concurrency",
                "max_concurrency",
                "memory_reserve_bytes",
                "disk_reserve_bytes",
                "quota_reserve_ratio",
                "max_error_rate",
                "target_latency_seconds",
                "additive_increase",
                "decrease_factor",
                "scale_up_windows",
                "cooldown_seconds",
            )
        }


@dataclass(frozen=True)
class PolicyResolution:
    valid: bool
    effective: EffectiveSchedulingPolicy
    diagnostics: tuple[PolicyDiagnostic, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "effective": self.effective.to_dict(),
            "diagnostics": [item.to_dict() for item in self.diagnostics],
        }


def _diagnostic(
    *,
    code: str,
    layer: str,
    field_name: str,
    severity: DiagnosticSeverity,
    requested: int | float | None,
    applied: int | float | None,
    message: str,
) -> PolicyDiagnostic:
    return PolicyDiagnostic(
        code=code,
        layer=layer,
        field=field_name,
        severity=severity,
        requested=requested,
        applied=applied,
        message=message,
    )


def resolve_policy(bundle: SchedulingPolicyBundle) -> PolicyResolution:
    """Resolve safety -> organization -> task with stable diagnostics."""

    if not isinstance(bundle, SchedulingPolicyBundle):
        raise TypeError("bundle must be SchedulingPolicyBundle")
    safety = bundle.safety
    organization = bundle.organization
    task = bundle.task
    diagnostics: list[PolicyDiagnostic] = []

    maximum = min(safety.hard_max_concurrency, organization.max_concurrency)
    if organization.max_concurrency > safety.hard_max_concurrency:
        diagnostics.append(
            _diagnostic(
                code="safety_ceiling_applied",
                layer="organization",
                field_name="max_concurrency",
                severity="warning",
                requested=organization.max_concurrency,
                applied=maximum,
                message="organization max_concurrency cannot exceed the safety ceiling",
            )
        )

    memory_reserve = max(
        safety.min_memory_reserve_bytes, organization.memory_reserve_bytes
    )
    disk_reserve = max(safety.min_disk_reserve_bytes, organization.disk_reserve_bytes)
    quota_reserve = max(
        safety.min_quota_reserve_ratio, organization.quota_reserve_ratio
    )
    max_error = min(safety.max_error_rate, organization.max_error_rate)
    for field_name, requested, applied, relation in (
        (
            "memory_reserve_bytes",
            organization.memory_reserve_bytes,
            memory_reserve,
            "floor",
        ),
        (
            "disk_reserve_bytes",
            organization.disk_reserve_bytes,
            disk_reserve,
            "floor",
        ),
        (
            "quota_reserve_ratio",
            organization.quota_reserve_ratio,
            quota_reserve,
            "floor",
        ),
        ("max_error_rate", organization.max_error_rate, max_error, "ceiling"),
    ):
        if requested != applied:
            diagnostics.append(
                _diagnostic(
                    code=f"safety_{relation}_applied",
                    layer="organization",
                    field_name=field_name,
                    severity="warning",
                    requested=requested,
                    applied=applied,
                    message=f"organization {field_name} cannot weaken its safety {relation}",
                )
            )

    valid = True
    minimum = organization.min_concurrency
    if minimum > maximum:
        valid = False
        diagnostics.append(
            _diagnostic(
                code="impossible_concurrency_range",
                layer="organization",
                field_name="min_concurrency",
                severity="error",
                requested=minimum,
                applied=maximum,
                message="organization min_concurrency exceeds the effective maximum",
            )
        )
        minimum = maximum

    if task is not None:
        inherited_maximum = maximum
        if task.preferred_max_concurrency is not None:
            maximum = min(maximum, task.preferred_max_concurrency)
            if task.preferred_max_concurrency > inherited_maximum:
                diagnostics.append(
                    _diagnostic(
                        code="inherited_ceiling_applied",
                        layer="task",
                        field_name="preferred_max_concurrency",
                        severity="warning",
                        requested=task.preferred_max_concurrency,
                        applied=inherited_maximum,
                        message="task preference cannot raise the inherited maximum",
                    )
                )
        if task.preferred_min_concurrency is not None:
            inherited_minimum = minimum
            minimum = min(minimum, task.preferred_min_concurrency)
            if task.preferred_min_concurrency > inherited_minimum:
                diagnostics.append(
                    _diagnostic(
                        code="inherited_minimum_applied",
                        layer="task",
                        field_name="preferred_min_concurrency",
                        severity="warning",
                        requested=task.preferred_min_concurrency,
                        applied=inherited_minimum,
                        message=(
                            "task preference cannot raise the inherited "
                            "min_concurrency"
                        ),
                    )
                )
        if minimum > maximum:
            diagnostics.append(
                _diagnostic(
                    code="task_preference_clipped",
                    layer="task",
                    field_name="preferred_min_concurrency",
                    severity="warning",
                    requested=minimum,
                    applied=maximum,
                    message="task preferred minimum was clipped to its effective maximum",
                )
            )
            minimum = maximum

        for field_name, requested in (
            ("memory_reserve_bytes", task.memory_reserve_bytes),
            ("disk_reserve_bytes", task.disk_reserve_bytes),
            ("quota_reserve_ratio", task.quota_reserve_ratio),
        ):
            if requested is None:
                continue
            inherited = {
                "memory_reserve_bytes": memory_reserve,
                "disk_reserve_bytes": disk_reserve,
                "quota_reserve_ratio": quota_reserve,
            }[field_name]
            applied = max(inherited, requested)
            if requested < inherited:
                diagnostics.append(
                    _diagnostic(
                        code="inherited_floor_applied",
                        layer="task",
                        field_name=field_name,
                        severity="warning",
                        requested=requested,
                        applied=inherited,
                        message=f"task preference cannot lower inherited {field_name}",
                    )
                )
            if field_name == "memory_reserve_bytes":
                memory_reserve = int(applied)
            elif field_name == "disk_reserve_bytes":
                disk_reserve = int(applied)
            else:
                quota_reserve = float(applied)

        if task.max_error_rate is not None:
            inherited_error = max_error
            max_error = min(max_error, task.max_error_rate)
            if task.max_error_rate > inherited_error:
                diagnostics.append(
                    _diagnostic(
                        code="inherited_ceiling_applied",
                        layer="task",
                        field_name="max_error_rate",
                        severity="warning",
                        requested=task.max_error_rate,
                        applied=inherited_error,
                        message="task preference cannot raise inherited max_error_rate",
                    )
                )

    effective = EffectiveSchedulingPolicy(
        policy_id=organization.policy_id,
        revision=organization.revision,
        task_id=task.task_id if task is not None else None,
        min_concurrency=minimum,
        max_concurrency=maximum,
        memory_reserve_bytes=memory_reserve,
        disk_reserve_bytes=disk_reserve,
        quota_reserve_ratio=quota_reserve,
        max_error_rate=max_error,
        target_latency_seconds=(
            task.target_latency_seconds
            if task is not None and task.target_latency_seconds is not None
            else organization.target_latency_seconds
        ),
        additive_increase=organization.additive_increase,
        decrease_factor=organization.decrease_factor,
        scale_up_windows=organization.scale_up_windows,
        cooldown_seconds=organization.cooldown_seconds,
    )
    return PolicyResolution(valid, effective, tuple(diagnostics))


@dataclass(frozen=True, kw_only=True)
class ProviderSignals:
    provider_id: str
    max_concurrency: int | None
    quota_remaining_ratio: float | None
    error_rate: float | None
    latency_seconds: float | None
    timed_out: bool | None = None
    observed_at: str
    ttl_seconds: int | None
    confidence: float | None
    sequence: int

    def __post_init__(self) -> None:
        _identifier(self.provider_id, "provider_id")
        _optional_integer(self.max_concurrency, "max_concurrency")
        _optional_ratio(self.quota_remaining_ratio, "quota_remaining_ratio")
        _optional_ratio(self.error_rate, "error_rate")
        if self.latency_seconds is not None:
            _number(self.latency_seconds, "latency_seconds", minimum=0)
        if self.timed_out is not None and not isinstance(self.timed_out, bool):
            raise SchedulingPolicyError("timed_out must be a Boolean or null")
        _parse_time(self.observed_at, "observed_at")
        if self.ttl_seconds is not None:
            _integer(self.ttl_seconds, "ttl_seconds", minimum=1)
        if self.confidence is not None:
            _number(self.confidence, "confidence", minimum=0, maximum=1)
        _integer(self.sequence, "sequence", minimum=1)

    def freshness(self, now: str | datetime | None = None) -> str:
        if self.ttl_seconds is None:
            return "unknown"
        current, _ = _now(now)
        age = (current - _parse_time(self.observed_at, "observed_at")).total_seconds()
        if age < 0:
            return "unknown"
        return "fresh" if age <= self.ttl_seconds else "stale"

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider_id": self.provider_id,
            "max_concurrency": self.max_concurrency,
            "quota_remaining_ratio": self.quota_remaining_ratio,
            "error_rate": self.error_rate,
            "latency_seconds": self.latency_seconds,
            "timed_out": self.timed_out,
            "observed_at": self.observed_at,
            "ttl_seconds": self.ttl_seconds,
            "confidence": self.confidence,
            "sequence": self.sequence,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ProviderSignals":
        fields = {
            "provider_id",
            "max_concurrency",
            "quota_remaining_ratio",
            "error_rate",
            "latency_seconds",
            "timed_out",
            "observed_at",
            "ttl_seconds",
            "confidence",
            "sequence",
        }
        data = _strict_object(data, fields, "ProviderSignals")
        return cls(**{name: data[name] for name in fields})


@dataclass(frozen=True, kw_only=True)
class TaskResourceEstimate:
    """Per-added-slot estimates and the exact mount they will consume.

    New dimensions are nullable for wire/API compatibility, but ``None`` is
    unknown rather than zero.  Adaptive admission requires an explicit value
    for every dimension; callers use zero only for known non-consumption.
    """

    memory_bytes_per_slot: int
    disk_bytes_per_slot: int
    mount_path: str
    cpu_cores_per_slot: float | None = None
    swap_bytes_per_slot: int | None = None
    gpu_memory_bytes_per_slot: int | None = None
    inodes_per_slot: int | None = None
    owned_process_rss_bytes_per_slot: int | None = None

    def __post_init__(self) -> None:
        _integer(self.memory_bytes_per_slot, "memory_bytes_per_slot", minimum=1)
        _integer(self.disk_bytes_per_slot, "disk_bytes_per_slot", minimum=1)
        if self.cpu_cores_per_slot is not None:
            cpu = _number(
                self.cpu_cores_per_slot,
                "cpu_cores_per_slot",
                minimum=0,
            )
            if cpu == 0:
                raise SchedulingPolicyError("cpu_cores_per_slot must be > 0")
        for name in (
            "swap_bytes_per_slot",
            "gpu_memory_bytes_per_slot",
            "inodes_per_slot",
            "owned_process_rss_bytes_per_slot",
        ):
            _optional_integer(getattr(self, name), name)
        if not isinstance(self.mount_path, str) or not self.mount_path:
            raise SchedulingPolicyError("mount_path must be a non-empty absolute path")
        normalized = self.mount_path.replace("\\", "/")
        if not (normalized.startswith("/") or _WINDOWS_ABS_RE.match(self.mount_path)):
            raise SchedulingPolicyError("mount_path must be an absolute path")
        if ".." in normalized.split("/"):
            raise SchedulingPolicyError("mount_path must not contain '..'")
        object.__setattr__(
            self, "mount_path", _canonical_mount_path(self.mount_path)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "cpu_cores_per_slot": self.cpu_cores_per_slot,
            "memory_bytes_per_slot": self.memory_bytes_per_slot,
            "swap_bytes_per_slot": self.swap_bytes_per_slot,
            "gpu_memory_bytes_per_slot": self.gpu_memory_bytes_per_slot,
            "disk_bytes_per_slot": self.disk_bytes_per_slot,
            "inodes_per_slot": self.inodes_per_slot,
            "owned_process_rss_bytes_per_slot": (
                self.owned_process_rss_bytes_per_slot
            ),
            "mount_path": self.mount_path,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "TaskResourceEstimate":
        fields = {
            "cpu_cores_per_slot",
            "memory_bytes_per_slot",
            "swap_bytes_per_slot",
            "gpu_memory_bytes_per_slot",
            "disk_bytes_per_slot",
            "inodes_per_slot",
            "owned_process_rss_bytes_per_slot",
            "mount_path",
        }
        data = _strict_object(data, fields, "TaskResourceEstimate")
        return cls(**{name: data[name] for name in fields})


@dataclass(frozen=True, kw_only=True)
class AdaptiveConcurrencyState:
    current_limit: int
    healthy_windows: int = 0
    last_adjusted_at: str | None = None
    last_resource_sequence: int | None = None
    last_heartbeat_sequence: int | None = None
    last_provider_sequence: int | None = None

    def __post_init__(self) -> None:
        _integer(self.current_limit, "current_limit")
        _integer(self.healthy_windows, "healthy_windows")
        if self.last_adjusted_at is not None:
            _parse_time(self.last_adjusted_at, "last_adjusted_at")
        for name in (
            "last_resource_sequence",
            "last_heartbeat_sequence",
            "last_provider_sequence",
        ):
            value = getattr(self, name)
            if value is not None:
                _integer(value, name, minimum=1)

    def to_dict(self) -> dict[str, Any]:
        return {
            "current_limit": self.current_limit,
            "healthy_windows": self.healthy_windows,
            "last_adjusted_at": self.last_adjusted_at,
            "last_resource_sequence": self.last_resource_sequence,
            "last_heartbeat_sequence": self.last_heartbeat_sequence,
            "last_provider_sequence": self.last_provider_sequence,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "AdaptiveConcurrencyState":
        fields = {
            "current_limit",
            "healthy_windows",
            "last_adjusted_at",
            "last_resource_sequence",
            "last_heartbeat_sequence",
            "last_provider_sequence",
        }
        data = _strict_object(data, fields, "AdaptiveConcurrencyState")
        return cls(**{name: data[name] for name in fields})


@dataclass(frozen=True, kw_only=True)
class ConcurrencyDecision:
    target_concurrency: int
    status: DecisionStatus
    hard_cap: int
    resource_cap: int | None
    reasons: tuple[str, ...]
    next_state: AdaptiveConcurrencyState

    def __post_init__(self) -> None:
        _integer(self.target_concurrency, "target_concurrency")
        if self.status not in {"blocked", "increase", "decrease", "hold"}:
            raise SchedulingPolicyError("status is not a supported decision status")
        _integer(self.hard_cap, "hard_cap")
        _optional_integer(self.resource_cap, "resource_cap")
        if (
            not isinstance(self.reasons, tuple)
            or any(not isinstance(item, str) or not item for item in self.reasons)
        ):
            raise SchedulingPolicyError("reasons must contain non-empty strings")
        if not isinstance(self.next_state, AdaptiveConcurrencyState):
            raise SchedulingPolicyError(
                "next_state must be AdaptiveConcurrencyState"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_concurrency": self.target_concurrency,
            "status": self.status,
            "hard_cap": self.hard_cap,
            "resource_cap": self.resource_cap,
            "reasons": list(self.reasons),
            "next_state": self.next_state.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ConcurrencyDecision":
        fields = {
            "target_concurrency",
            "status",
            "hard_cap",
            "resource_cap",
            "reasons",
            "next_state",
        }
        data = _strict_object(data, fields, "ConcurrencyDecision")
        reasons = data["reasons"]
        if not isinstance(reasons, list):
            raise SchedulingPolicyError("ConcurrencyDecision.reasons must be an array")
        return cls(
            target_concurrency=data["target_concurrency"],
            status=data["status"],
            hard_cap=data["hard_cap"],
            resource_cap=data["resource_cap"],
            reasons=tuple(reasons),
            next_state=AdaptiveConcurrencyState.from_dict(data["next_state"]),
        )


@dataclass(frozen=True, kw_only=True)
class SchedulerDecisionInput:
    """Strict, replayable input envelope for one provider-free decision."""

    bundle: SchedulingPolicyBundle
    state: AdaptiveConcurrencyState
    resource_snapshot: ResourceSnapshot
    heartbeat: WorkerHeartbeat
    provider: ProviderSignals
    task_resources: TaskResourceEstimate
    now: str
    schema_version: int = SCHEDULER_DECISION_INPUT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            isinstance(self.schema_version, bool)
            or self.schema_version != SCHEDULER_DECISION_INPUT_SCHEMA_VERSION
        ):
            raise SchedulingPolicyError(
                "unsupported scheduler decision input schema_version"
            )
        for value, expected, name in (
            (self.bundle, SchedulingPolicyBundle, "bundle"),
            (self.state, AdaptiveConcurrencyState, "state"),
            (self.resource_snapshot, ResourceSnapshot, "resource_snapshot"),
            (self.heartbeat, WorkerHeartbeat, "heartbeat"),
            (self.provider, ProviderSignals, "provider"),
            (self.task_resources, TaskResourceEstimate, "task_resources"),
        ):
            if not isinstance(value, expected):
                raise SchedulingPolicyError(f"{name} must be {expected.__name__}")
        _parse_time(self.now, "now")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "bundle": self.bundle.to_dict(),
            "state": self.state.to_dict(),
            "resource_snapshot": self.resource_snapshot.to_dict(),
            "heartbeat": self.heartbeat.to_dict(),
            "provider": self.provider.to_dict(),
            "task_resources": self.task_resources.to_dict(),
            "now": self.now,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "SchedulerDecisionInput":
        fields = {
            "schema_version",
            "bundle",
            "state",
            "resource_snapshot",
            "heartbeat",
            "provider",
            "task_resources",
            "now",
        }
        data = _strict_object(data, fields, "SchedulerDecisionInput")
        return cls(
            schema_version=data["schema_version"],
            bundle=SchedulingPolicyBundle.from_dict(data["bundle"]),
            state=AdaptiveConcurrencyState.from_dict(data["state"]),
            resource_snapshot=ResourceSnapshot.from_dict(data["resource_snapshot"]),
            heartbeat=WorkerHeartbeat.from_dict(data["heartbeat"]),
            provider=ProviderSignals.from_dict(data["provider"]),
            task_resources=TaskResourceEstimate.from_dict(data["task_resources"]),
            now=data["now"],
        )


def _usage_status(reserved: ResourceUsage, actual: ResourceUsage) -> str:
    compared = False
    unknown = False
    exceeded = False
    for dimension in ResourceUsage.DIMENSIONS:
        expected = getattr(reserved, dimension)
        observed = getattr(actual, dimension)
        if expected is None and observed is None:
            continue
        if expected is None or observed is None:
            unknown = True
            continue
        compared = True
        exceeded = exceeded or observed > expected
    if exceeded:
        return "exceeded"
    if unknown or not compared:
        return "unknown"
    return "within"


def _resource_cap(
    snapshot: ResourceSnapshot,
    heartbeat: WorkerHeartbeat,
    policy: EffectiveSchedulingPolicy,
    estimate: TaskResourceEstimate,
) -> tuple[int | None, tuple[str, ...]]:
    reasons: list[str] = []
    per_slot = {
        "cpu_cores": estimate.cpu_cores_per_slot,
        "ram_bytes": estimate.memory_bytes_per_slot,
        "swap_bytes": estimate.swap_bytes_per_slot,
        "gpu_memory_bytes": estimate.gpu_memory_bytes_per_slot,
        "disk_bytes": estimate.disk_bytes_per_slot,
        "inodes": estimate.inodes_per_slot,
        "owned_process_rss_bytes": estimate.owned_process_rss_bytes_per_slot,
    }
    for dimension, amount in per_slot.items():
        if amount is None:
            reasons.append(f"task per-slot {dimension} estimate is unknown")
            continue
        if amount > 0 and (
            getattr(heartbeat.reserved_usage, dimension) is None
            or getattr(heartbeat.actual_usage, dimension) is None
        ):
            reasons.append(
                "reservation/actual usage reconciliation is unknown for "
                f"{dimension}"
            )

    cpu_available = snapshot.cpu.available_cores
    if cpu_available is None:
        reasons.append("CPU available_cores is unknown")
    elif snapshot.cgroup.cpu_quota_cores is not None:
        actual_cpu = heartbeat.actual_usage.cpu_cores
        if actual_cpu is None:
            reasons.append("cgroup CPU availability cannot be reconciled")
        else:
            cpu_available = min(
                cpu_available,
                max(0.0, snapshot.cgroup.cpu_quota_cores - actual_cpu),
            )

    memory_available = snapshot.ram.available_bytes
    if memory_available is None:
        reasons.append("RAM available_bytes is unknown")
    cgroup = snapshot.cgroup
    if cgroup.memory_limit_bytes is not None or cgroup.memory_current_bytes is not None:
        if cgroup.memory_limit_bytes is None or cgroup.memory_current_bytes is None:
            reasons.append("cgroup memory evidence is incomplete")
        else:
            cgroup_available = max(
                0, cgroup.memory_limit_bytes - cgroup.memory_current_bytes
            )
            memory_available = (
                cgroup_available
                if memory_available is None
                else min(memory_available, cgroup_available)
            )

    swap_available: int | None = None
    if estimate.swap_bytes_per_slot is not None and estimate.swap_bytes_per_slot > 0:
        swap_available = snapshot.swap.available_bytes
        if swap_available is None:
            reasons.append("swap available_bytes is unknown")
        if (
            snapshot.cgroup.swap_limit_bytes is not None
            or snapshot.cgroup.swap_current_bytes is not None
        ):
            if (
                snapshot.cgroup.swap_limit_bytes is None
                or snapshot.cgroup.swap_current_bytes is None
            ):
                reasons.append("cgroup swap evidence is incomplete")
            else:
                cgroup_swap_available = max(
                    0,
                    snapshot.cgroup.swap_limit_bytes
                    - snapshot.cgroup.swap_current_bytes,
                )
                swap_available = (
                    cgroup_swap_available
                    if swap_available is None
                    else min(swap_available, cgroup_swap_available)
                )

    expected_mount = _mount_path_key(estimate.mount_path)
    mounts = [
        item
        for item in snapshot.mounts
        if _mount_path_key(item.mount_path) == expected_mount
    ]
    if len(mounts) != 1:
        reasons.append("exact task mount evidence is missing")
        mount = None
    else:
        mount = mounts[0]
        if mount.writable is not True:
            reasons.append("exact task mount is not known writable")
        if mount.available_bytes is None:
            reasons.append("exact task mount available_bytes is unknown")
        if (
            estimate.inodes_per_slot is not None
            and estimate.inodes_per_slot > 0
            and mount.free_inodes is None
        ):
            reasons.append("exact task mount free_inodes is unknown")

    gpu_slots: int | None = None
    if (
        estimate.gpu_memory_bytes_per_slot is not None
        and estimate.gpu_memory_bytes_per_slot > 0
    ):
        if not snapshot.gpus:
            reasons.append("GPU memory is required but no GPU evidence is present")
        elif any(item.memory_available_bytes is None for item in snapshot.gpus):
            reasons.append("per-device GPU available memory is unknown")
        else:
            gpu_slots = sum(
                int(item.memory_available_bytes or 0)
                // estimate.gpu_memory_bytes_per_slot
                for item in snapshot.gpus
            )

    owned_rss = snapshot.owned_process_rss_bytes()
    if (
        estimate.owned_process_rss_bytes_per_slot is not None
        and estimate.owned_process_rss_bytes_per_slot > 0
    ):
        if owned_rss is None:
            reasons.append("owned-process RSS evidence is unknown")
        elif heartbeat.actual_usage.owned_process_rss_bytes != owned_rss:
            reasons.append(
                "owned-process RSS does not match heartbeat actual usage"
            )

    if (
        reasons
        or cpu_available is None
        or memory_available is None
        or mount is None
    ):
        return None, tuple(reasons)
    assert mount.available_bytes is not None
    if memory_available < policy.memory_reserve_bytes:
        return 0, ("RAM reserve gate is not satisfied",)
    if mount.available_bytes < policy.disk_reserve_bytes:
        return 0, ("disk reserve gate is not satisfied",)

    active = len(heartbeat.active_execution_handles)
    assert estimate.cpu_cores_per_slot is not None
    additional_slots: list[float] = [
        cpu_available / float(estimate.cpu_cores_per_slot),
        (memory_available - policy.memory_reserve_bytes)
        // estimate.memory_bytes_per_slot,
        (mount.available_bytes - policy.disk_reserve_bytes)
        // estimate.disk_bytes_per_slot,
    ]
    if estimate.swap_bytes_per_slot and swap_available is not None:
        additional_slots.append(
            swap_available // estimate.swap_bytes_per_slot
        )
    if estimate.gpu_memory_bytes_per_slot:
        assert gpu_slots is not None
        additional_slots.append(gpu_slots)
    if estimate.inodes_per_slot:
        assert mount.free_inodes is not None
        additional_slots.append(mount.free_inodes // estimate.inodes_per_slot)
    if estimate.owned_process_rss_bytes_per_slot:
        additional_slots.append(
            (memory_available - policy.memory_reserve_bytes)
            // estimate.owned_process_rss_bytes_per_slot
        )
    return active + int(math.floor(min(additional_slots))), ()


def _decision(
    *,
    state: AdaptiveConcurrencyState,
    target: int,
    status: DecisionStatus,
    hard_cap: int,
    resource_cap: int | None,
    reasons: list[str],
    healthy_windows: int,
    now_text: str,
    snapshot: ResourceSnapshot,
    heartbeat: WorkerHeartbeat,
    provider: ProviderSignals,
    accept_sequences: bool = True,
) -> ConcurrencyDecision:
    changed = target != state.current_limit
    next_state = AdaptiveConcurrencyState(
        current_limit=target,
        healthy_windows=healthy_windows,
        last_adjusted_at=now_text if changed else state.last_adjusted_at,
        last_resource_sequence=(
            snapshot.sequence if accept_sequences else state.last_resource_sequence
        ),
        last_heartbeat_sequence=(
            heartbeat.sequence if accept_sequences else state.last_heartbeat_sequence
        ),
        last_provider_sequence=(
            provider.sequence if accept_sequences else state.last_provider_sequence
        ),
    )
    return ConcurrencyDecision(
        target_concurrency=target,
        status=status,
        hard_cap=hard_cap,
        resource_cap=resource_cap,
        reasons=tuple(reasons),
        next_state=next_state,
    )


def adapt_concurrency(
    *,
    state: AdaptiveConcurrencyState,
    policy: PolicyResolution,
    resource_snapshot: ResourceSnapshot,
    heartbeat: WorkerHeartbeat,
    provider: ProviderSignals,
    task_resources: TaskResourceEstimate,
    now: str | datetime | None = None,
) -> ConcurrencyDecision:
    """Return one bounded AIMD decision and the next immutable state."""

    for value, expected, name in (
        (state, AdaptiveConcurrencyState, "state"),
        (policy, PolicyResolution, "policy"),
        (resource_snapshot, ResourceSnapshot, "resource_snapshot"),
        (heartbeat, WorkerHeartbeat, "heartbeat"),
        (provider, ProviderSignals, "provider"),
        (task_resources, TaskResourceEstimate, "task_resources"),
    ):
        if not isinstance(value, expected):
            raise TypeError(f"{name} must be {expected.__name__}")

    current_time, now_text = _now(now)
    effective = policy.effective
    reasons: list[str] = []
    if not policy.valid:
        reasons.append("effective policy is impossible")
        return _decision(
            state=state,
            target=0,
            status="blocked",
            hard_cap=0,
            resource_cap=None,
            reasons=reasons,
            healthy_windows=0,
            now_text=now_text,
            snapshot=resource_snapshot,
            heartbeat=heartbeat,
            provider=provider,
        )

    for incoming, previous, label in (
        (resource_snapshot.sequence, state.last_resource_sequence, "resource"),
        (heartbeat.sequence, state.last_heartbeat_sequence, "heartbeat"),
        (provider.sequence, state.last_provider_sequence, "provider"),
    ):
        if previous is not None and incoming < previous:
            reasons.append(f"{label} evidence sequence regressed")
    if reasons:
        return _decision(
            state=state,
            target=0,
            status="blocked",
            hard_cap=0,
            resource_cap=None,
            reasons=reasons,
            healthy_windows=0,
            now_text=now_text,
            snapshot=resource_snapshot,
            heartbeat=heartbeat,
            provider=provider,
            accept_sequences=False,
        )

    now_for_contract = current_time.isoformat()
    for label, freshness_value in (
        ("resource", resource_snapshot.freshness(now_for_contract)),
        ("heartbeat", heartbeat.freshness(now_for_contract)),
        ("provider", provider.freshness(current_time)),
    ):
        if freshness_value != "fresh":
            reasons.append(f"{label} telemetry is {freshness_value}")
    if resource_snapshot.confidence is None or resource_snapshot.confidence <= 0:
        reasons.append("resource confidence is unknown")
    if heartbeat.confidence is None or heartbeat.confidence <= 0:
        reasons.append("heartbeat confidence is unknown")
    if provider.confidence is None or provider.confidence <= 0:
        reasons.append("provider confidence is unknown")
    if (
        resource_snapshot.host_id != heartbeat.host_id
        or resource_snapshot.worker_id != heartbeat.worker_id
        or resource_snapshot.fence_token != heartbeat.fence_token
    ):
        reasons.append("worker resource and heartbeat identity/fence do not match")
    if heartbeat.resource_sequence != resource_snapshot.sequence:
        reasons.append("heartbeat does not reference the resource snapshot sequence")
    required_provider_values = (
        provider.max_concurrency,
        provider.quota_remaining_ratio,
        provider.error_rate,
        provider.latency_seconds,
        provider.timed_out,
    )
    if any(value is None for value in required_provider_values):
        reasons.append("provider capacity/quota/error/latency evidence is incomplete")
    if reasons:
        return _decision(
            state=state,
            target=0,
            status="blocked",
            hard_cap=0,
            resource_cap=None,
            reasons=reasons,
            healthy_windows=0,
            now_text=now_text,
            snapshot=resource_snapshot,
            heartbeat=heartbeat,
            provider=provider,
        )

    if heartbeat.state in {"draining", "stopped", "unknown"}:
        reasons.append(f"worker reports {heartbeat.state}")
        return _decision(
            state=state,
            target=0,
            status="blocked",
            hard_cap=0,
            resource_cap=0,
            reasons=reasons,
            healthy_windows=0,
            now_text=now_text,
            snapshot=resource_snapshot,
            heartbeat=heartbeat,
            provider=provider,
        )

    resource_cap, resource_reasons = _resource_cap(
        resource_snapshot, heartbeat, effective, task_resources
    )
    if resource_cap is None:
        reasons.extend(resource_reasons)
        return _decision(
            state=state,
            target=0,
            status="blocked",
            hard_cap=0,
            resource_cap=None,
            reasons=reasons,
            healthy_windows=0,
            now_text=now_text,
            snapshot=resource_snapshot,
            heartbeat=heartbeat,
            provider=provider,
        )

    assert provider.max_concurrency is not None
    assert provider.quota_remaining_ratio is not None
    assert provider.error_rate is not None
    assert provider.latency_seconds is not None
    assert provider.timed_out is not None

    severe_provider_reasons: list[str] = []
    if provider.error_rate >= 1.0:
        severe_provider_reasons.append("provider reports a total error window")
    if provider.timed_out:
        severe_provider_reasons.append("provider reports an explicit timeout")
    if severe_provider_reasons:
        reasons.extend(severe_provider_reasons)
        return _decision(
            state=state,
            target=0,
            status="blocked",
            hard_cap=0,
            resource_cap=resource_cap,
            reasons=reasons,
            healthy_windows=0,
            now_text=now_text,
            snapshot=resource_snapshot,
            heartbeat=heartbeat,
            provider=provider,
        )

    hard_cap = min(
        effective.max_concurrency,
        provider.max_concurrency,
        resource_cap,
    )
    reasons.extend(resource_reasons)
    if provider.quota_remaining_ratio <= effective.quota_reserve_ratio:
        hard_cap = 0
        reasons.append("provider quota reserve gate is not satisfied")

    if hard_cap < state.current_limit:
        reasons.append("a hard concurrency cap decreased")
        return _decision(
            state=state,
            target=hard_cap,
            status="decrease" if hard_cap > 0 else "blocked",
            hard_cap=hard_cap,
            resource_cap=resource_cap,
            reasons=reasons,
            healthy_windows=0,
            now_text=now_text,
            snapshot=resource_snapshot,
            heartbeat=heartbeat,
            provider=provider,
        )
    if hard_cap == 0:
        reasons.append("no concurrency is safely admissible")
        return _decision(
            state=state,
            target=0,
            status="blocked",
            hard_cap=0,
            resource_cap=resource_cap,
            reasons=reasons,
            healthy_windows=0,
            now_text=now_text,
            snapshot=resource_snapshot,
            heartbeat=heartbeat,
            provider=provider,
        )

    usage_status = _usage_status(heartbeat.reserved_usage, heartbeat.actual_usage)
    if usage_status == "unknown":
        reasons.append("reservation/actual usage reconciliation is unknown")
        return _decision(
            state=state,
            target=0,
            status="blocked",
            hard_cap=hard_cap,
            resource_cap=resource_cap,
            reasons=reasons,
            healthy_windows=0,
            now_text=now_text,
            snapshot=resource_snapshot,
            heartbeat=heartbeat,
            provider=provider,
        )

    pressure_reasons: list[str] = []
    if usage_status == "exceeded":
        pressure_reasons.append("actual usage exceeds its reservation")
    if provider.error_rate > effective.max_error_rate:
        pressure_reasons.append("provider error rate exceeds the policy ceiling")
    if provider.latency_seconds > effective.target_latency_seconds:
        pressure_reasons.append("provider latency exceeds the policy target")
    if pressure_reasons:
        target = max(
            effective.min_concurrency,
            int(math.floor(state.current_limit * effective.decrease_factor)),
        )
        target = min(target, hard_cap)
        reasons.extend(pressure_reasons)
        return _decision(
            state=state,
            target=target,
            status="decrease" if target < state.current_limit else "hold",
            hard_cap=hard_cap,
            resource_cap=resource_cap,
            reasons=reasons,
            healthy_windows=0,
            now_text=now_text,
            snapshot=resource_snapshot,
            heartbeat=heartbeat,
            provider=provider,
        )

    if heartbeat.state == "busy":
        reasons.append("busy workers do not trigger scale-up")
        return _decision(
            state=state,
            target=state.current_limit,
            status="hold",
            hard_cap=hard_cap,
            resource_cap=resource_cap,
            reasons=reasons,
            healthy_windows=0,
            now_text=now_text,
            snapshot=resource_snapshot,
            heartbeat=heartbeat,
            provider=provider,
        )

    if state.current_limit < effective.min_concurrency:
        target = min(effective.min_concurrency, hard_cap)
        reasons.append("healthy evidence admits the effective minimum")
        return _decision(
            state=state,
            target=target,
            status="increase" if target > state.current_limit else "hold",
            hard_cap=hard_cap,
            resource_cap=resource_cap,
            reasons=reasons,
            healthy_windows=0,
            now_text=now_text,
            snapshot=resource_snapshot,
            heartbeat=heartbeat,
            provider=provider,
        )

    same_window = (
        state.last_resource_sequence == resource_snapshot.sequence
        and state.last_heartbeat_sequence == heartbeat.sequence
        and state.last_provider_sequence == provider.sequence
    )
    healthy_windows = state.healthy_windows
    if not same_window:
        healthy_windows = min(
            effective.scale_up_windows, state.healthy_windows + 1
        )
    cooldown_elapsed = True
    if state.last_adjusted_at is not None:
        elapsed = (
            current_time - _parse_time(state.last_adjusted_at, "last_adjusted_at")
        ).total_seconds()
        cooldown_elapsed = elapsed >= effective.cooldown_seconds
    if (
        state.current_limit < hard_cap
        and healthy_windows >= effective.scale_up_windows
        and cooldown_elapsed
    ):
        target = min(
            hard_cap, state.current_limit + effective.additive_increase
        )
        reasons.append("healthy hysteresis window satisfied")
        return _decision(
            state=state,
            target=target,
            status="increase",
            hard_cap=hard_cap,
            resource_cap=resource_cap,
            reasons=reasons,
            healthy_windows=0,
            now_text=now_text,
            snapshot=resource_snapshot,
            heartbeat=heartbeat,
            provider=provider,
        )

    if same_window:
        reasons.append("duplicate evidence does not advance hysteresis")
    elif not cooldown_elapsed:
        reasons.append("scale-up cooldown has not elapsed")
    elif state.current_limit >= hard_cap:
        reasons.append("current concurrency is at its hard cap")
    else:
        reasons.append("scale-up hysteresis is not yet satisfied")
    return _decision(
        state=state,
        target=state.current_limit,
        status="hold",
        hard_cap=hard_cap,
        resource_cap=resource_cap,
        reasons=reasons,
        healthy_windows=healthy_windows,
        now_text=now_text,
        snapshot=resource_snapshot,
        heartbeat=heartbeat,
        provider=provider,
    )


@dataclass(frozen=True, kw_only=True)
class AdaptiveConcurrencyController:
    """Immutable convenience wrapper around ``adapt_concurrency``."""

    policy: PolicyResolution
    task_resources: TaskResourceEstimate

    def evaluate(
        self,
        *,
        state: AdaptiveConcurrencyState,
        resource_snapshot: ResourceSnapshot,
        heartbeat: WorkerHeartbeat,
        provider: ProviderSignals,
        now: str | datetime | None = None,
    ) -> ConcurrencyDecision:
        return adapt_concurrency(
            state=state,
            policy=self.policy,
            resource_snapshot=resource_snapshot,
            heartbeat=heartbeat,
            provider=provider,
            task_resources=self.task_resources,
            now=now,
        )


resolve_scheduling_policy = resolve_policy


__all__ = [
    "POLICY_SCHEMA_VERSION",
    "POLICY_API_VERSION",
    "SCHEDULER_DECISION_INPUT_SCHEMA_VERSION",
    "SchedulingPolicyError",
    "SafetyInvariants",
    "OrganizationPolicy",
    "TaskPreferences",
    "SchedulingPolicyBundle",
    "PolicyDiagnostic",
    "EffectiveSchedulingPolicy",
    "PolicyResolution",
    "resolve_policy",
    "resolve_scheduling_policy",
    "ProviderSignals",
    "TaskResourceEstimate",
    "AdaptiveConcurrencyState",
    "ConcurrencyDecision",
    "SchedulerDecisionInput",
    "adapt_concurrency",
    "AdaptiveConcurrencyController",
]
