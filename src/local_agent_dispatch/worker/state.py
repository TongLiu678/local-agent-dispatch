"""Pure in-memory projection for the provider-free worker v1 contracts.

``WorkerState`` has no filesystem, network, process, or provider dependency.
It consumes already-validated contract messages, fences prior worker
generations, refuses sequence rollback, derives lost/unknown states from TTL
evidence, and compares reservations with observed usage without treating
missing values as zero.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any

from ..api.contracts import (
    CapabilitySnapshot,
    ExecutionHandle,
    HostRegistration,
    ResourceSnapshot,
    ResourceUsage,
    WorkerHeartbeat,
)


class WorkerStateError(ValueError):
    """Base class for projection contract violations."""


class WorkerIdentityError(WorkerStateError):
    """A message belongs to another host or worker."""


class WorkerFenceError(WorkerStateError):
    """A message was emitted under a stale or unregistered fence."""


class WorkerSequenceError(WorkerStateError):
    """A stream attempted to move backwards or reuse a sequence."""


class WorkerIdempotencyError(WorkerStateError):
    """An idempotency key was reused for different content."""


_EXECUTION_TRANSITIONS: dict[str, set[str]] = {
    "unknown": {
        "unknown",
        "accepted",
        "running",
        "exited",
        "failed",
        "cancelled",
        "lost",
    },
    "accepted": {"accepted", "running", "failed", "cancelled", "lost", "unknown"},
    "running": {"running", "exited", "failed", "cancelled", "lost", "unknown"},
    "exited": {"exited"},
    "failed": {"failed"},
    "cancelled": {"cancelled"},
    "lost": {"lost"},
}


@dataclass(frozen=True)
class UsageReconciliation:
    """Conservative reservation/actual comparison.

    ``exceeded`` wins when at least one known dimension is over reservation.
    ``within`` requires every in-scope dimension to be known and within its
    reservation.  Missing one side remains ``unknown``.
    """

    status: str
    compared_dimensions: tuple[str, ...]
    unknown_dimensions: tuple[str, ...]
    overages: tuple[tuple[str, float], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "compared_dimensions": list(self.compared_dimensions),
            "unknown_dimensions": list(self.unknown_dimensions),
            "overages": {name: amount for name, amount in self.overages},
        }


def reconcile_usage(
    reserved: ResourceUsage, actual: ResourceUsage
) -> UsageReconciliation:
    if not isinstance(reserved, ResourceUsage) or not isinstance(actual, ResourceUsage):
        raise TypeError("reconcile_usage requires two ResourceUsage values")
    compared: list[str] = []
    unknown: list[str] = []
    overages: list[tuple[str, float]] = []
    for dimension in ResourceUsage.DIMENSIONS:
        expected = getattr(reserved, dimension)
        observed = getattr(actual, dimension)
        if expected is None and observed is None:
            # The dimension was outside the declared reservation and was not
            # observed.  It supplies no evidence either way.
            continue
        if expected is None or observed is None:
            unknown.append(dimension)
            continue
        compared.append(dimension)
        if observed > expected:
            overages.append((dimension, float(observed - expected)))
    if overages:
        status = "exceeded"
    elif unknown or not compared:
        status = "unknown"
    else:
        status = "within"
    return UsageReconciliation(
        status=status,
        compared_dimensions=tuple(compared),
        unknown_dimensions=tuple(unknown),
        overages=tuple(overages),
    )


class WorkerState:
    """Latest accepted v1 worker facts for one registered worker generation."""

    def __init__(self) -> None:
        # Projection methods intentionally call one another.  An RLock keeps
        # each public apply/projection boundary atomic without deadlocking on
        # those nested reads.
        self._lock = threading.RLock()
        self.registration: HostRegistration | None = None
        self.capability_snapshot: CapabilitySnapshot | None = None
        self.resource_snapshot: ResourceSnapshot | None = None
        self.heartbeat: WorkerHeartbeat | None = None
        self.execution_handles: dict[str, ExecutionHandle] = {}
        # A handle identifier is a durable execution identity, not a reusable
        # display label.  Keep this binding even when a higher worker fence
        # clears the live-handle projection so a later generation cannot
        # silently adopt the same identifier for another execution.
        self._execution_identities: dict[str, tuple[Any, ...]] = {}
        self._idempotency_payloads: dict[tuple[str, str], str] = {}

    @property
    def fence_token(self) -> int | None:
        with self._lock:
            return self.registration.fence_token if self.registration else None

    def _idempotency_result(self, stream: str, value: Any) -> bool | None:
        """Return False for an exact retry, None for a previously unseen key."""

        key = (stream, value.idempotency_key)
        payload = value.to_json()
        existing = self._idempotency_payloads.get(key)
        if existing is None:
            return None
        if existing != payload:
            raise WorkerIdempotencyError(
                f"{stream} idempotency_key {value.idempotency_key!r} "
                "was reused for different content"
            )
        return False

    def _remember(self, stream: str, value: Any) -> None:
        self._idempotency_payloads[(stream, value.idempotency_key)] = value.to_json()

    def _clear_generation_idempotency(self) -> None:
        """Forget prior-fence stream keys while retaining registration keys."""

        self._idempotency_payloads = {
            key: payload
            for key, payload in self._idempotency_payloads.items()
            if key[0] == "registration"
        }

    @staticmethod
    def _execution_identity(handle: ExecutionHandle) -> tuple[Any, ...]:
        return (
            handle.job_id,
            handle.attempt_id,
            handle.host_id,
            handle.worker_id,
            handle.fence_token,
            handle.reservation_id,
            handle.process_id,
        )

    def _require_current_identity(self, value: Any) -> None:
        registration = self.registration
        if registration is None:
            raise WorkerIdentityError("worker must be registered before snapshots")
        if (
            value.host_id != registration.host_id
            or value.worker_id != registration.worker_id
        ):
            raise WorkerIdentityError(
                "message host_id/worker_id does not match active registration"
            )
        if value.fence_token != registration.fence_token:
            raise WorkerFenceError(
                f"message fence {value.fence_token} does not match active "
                f"fence {registration.fence_token}"
            )

    @staticmethod
    def _require_forward_sequence(
        stream: str, incoming_sequence: int, current_sequence: int | None
    ) -> None:
        if current_sequence is None:
            return
        if incoming_sequence < current_sequence:
            raise WorkerSequenceError(
                f"{stream} sequence rollback: {incoming_sequence} < {current_sequence}"
            )
        if incoming_sequence == current_sequence:
            raise WorkerSequenceError(
                f"{stream} sequence {incoming_sequence} was reused with a new message"
            )

    def apply_registration(self, registration: HostRegistration) -> bool:
        if not isinstance(registration, HostRegistration):
            raise TypeError("registration must be HostRegistration")
        with self._lock:
            previous = self.registration
            if previous is not None:
                if (
                    registration.host_id != previous.host_id
                    or registration.worker_id != previous.worker_id
                ):
                    raise WorkerIdentityError(
                        "WorkerState cannot be rebound to another host or worker"
                    )
                if registration.fence_token < previous.fence_token:
                    raise WorkerFenceError(
                        f"registration fence rollback: {registration.fence_token} "
                        f"< {previous.fence_token}"
                    )
            duplicate = self._idempotency_result("registration", registration)
            if duplicate is False:
                return False
            if previous is not None:
                if registration.fence_token == previous.fence_token:
                    raise WorkerFenceError(
                        "a changed registration must advance fence_token"
                    )
                # A higher fence is a new ownership generation.  Old telemetry,
                # process handles, and their idempotency keys must not leak into
                # the new generation.  Registration keys remain globally stable.
                self.capability_snapshot = None
                self.resource_snapshot = None
                self.heartbeat = None
                self.execution_handles.clear()
                self._clear_generation_idempotency()
            self.registration = registration
            self._remember("registration", registration)
            return True

    def apply_capability_snapshot(self, snapshot: CapabilitySnapshot) -> bool:
        if not isinstance(snapshot, CapabilitySnapshot):
            raise TypeError("snapshot must be CapabilitySnapshot")
        with self._lock:
            self._require_current_identity(snapshot)
            duplicate = self._idempotency_result("capability", snapshot)
            if duplicate is False:
                return False
            current = self.capability_snapshot
            self._require_forward_sequence(
                "capability",
                snapshot.sequence,
                current.sequence if current is not None else None,
            )
            self.capability_snapshot = snapshot
            self._remember("capability", snapshot)
            return True

    def apply_resource_snapshot(self, snapshot: ResourceSnapshot) -> bool:
        if not isinstance(snapshot, ResourceSnapshot):
            raise TypeError("snapshot must be ResourceSnapshot")
        with self._lock:
            self._require_current_identity(snapshot)
            duplicate = self._idempotency_result("resource", snapshot)
            if duplicate is False:
                return False
            current = self.resource_snapshot
            self._require_forward_sequence(
                "resource",
                snapshot.sequence,
                current.sequence if current is not None else None,
            )
            self.resource_snapshot = snapshot
            self._remember("resource", snapshot)
            return True

    def apply_heartbeat(self, heartbeat: WorkerHeartbeat) -> bool:
        if not isinstance(heartbeat, WorkerHeartbeat):
            raise TypeError("heartbeat must be WorkerHeartbeat")
        with self._lock:
            self._require_current_identity(heartbeat)
            duplicate = self._idempotency_result("heartbeat", heartbeat)
            if duplicate is False:
                return False
            current = self.heartbeat
            self._require_forward_sequence(
                "heartbeat",
                heartbeat.sequence,
                current.sequence if current is not None else None,
            )
            self.heartbeat = heartbeat
            self._remember("heartbeat", heartbeat)
            return True

    def apply_execution_handle(self, handle: ExecutionHandle) -> bool:
        if not isinstance(handle, ExecutionHandle):
            raise TypeError("handle must be ExecutionHandle")
        with self._lock:
            self._require_current_identity(handle)
            stream = f"execution:{handle.handle_id}"
            duplicate = self._idempotency_result(stream, handle)
            if duplicate is False:
                return False
            identity = self._execution_identity(handle)
            established_identity = self._execution_identities.get(handle.handle_id)
            if established_identity is not None and identity != established_identity:
                raise WorkerIdentityError(
                    f"execution handle {handle.handle_id!r} cannot be rebound to "
                    "another job, attempt, worker fence, reservation, or process"
                )
            current = self.execution_handles.get(handle.handle_id)
            self._require_forward_sequence(
                stream, handle.sequence, current.sequence if current is not None else None
            )
            if (
                current is not None
                and handle.state not in _EXECUTION_TRANSITIONS[current.state]
            ):
                raise WorkerSequenceError(
                    f"illegal execution transition {current.state!r} -> {handle.state!r}"
                )
            self._execution_identities[handle.handle_id] = identity
            self.execution_handles[handle.handle_id] = handle
            self._remember(stream, handle)
            return True

    def worker_status(self, now: str | None = None) -> str:
        with self._lock:
            if self.registration is None or self.heartbeat is None:
                return "unknown"
            fresh = self.heartbeat.freshness(now)
            if fresh == "stale":
                return "lost"
            if fresh != "fresh":
                return "unknown"
            return self.heartbeat.state

    def execution_status(self, handle_id: str, now: str | None = None) -> str:
        with self._lock:
            handle = self.execution_handles.get(handle_id)
            if handle is None:
                return "unknown"
            fresh = handle.freshness(now)
            if handle.state in {"accepted", "running"}:
                if fresh == "stale":
                    return "lost"
                if fresh != "fresh":
                    return "unknown"
            return handle.state

    def usage_reconciliation(self) -> UsageReconciliation:
        with self._lock:
            if self.heartbeat is None:
                return UsageReconciliation("unknown", (), (), ())
            return reconcile_usage(
                self.heartbeat.reserved_usage, self.heartbeat.actual_usage
            )

    def admission_status(self, now: str | None = None) -> str:
        """Conservative dispatch readiness over correlated fresh evidence."""

        with self._lock:
            worker_status = self.worker_status(now)
            if worker_status != "ready":
                return worker_status
            if self.capability_snapshot is None or self.resource_snapshot is None:
                return "unknown"
            if self.capability_snapshot.freshness(now) != "fresh":
                return "unknown"
            if self.resource_snapshot.freshness(now) != "fresh":
                return "unknown"
            if (
                self.heartbeat is None
                or self.heartbeat.capability_sequence is None
                or self.heartbeat.resource_sequence is None
            ):
                return "unknown"
            if self.heartbeat.capability_sequence != self.capability_snapshot.sequence:
                return "unknown"
            if self.heartbeat.resource_sequence != self.resource_snapshot.sequence:
                return "unknown"
            # Confidence is evidence, not decoration.  Missing or zero/negative
            # confidence keeps a registration visible but cannot prove readiness.
            if any(
                item.confidence is None or item.confidence <= 0
                for item in (
                    self.capability_snapshot,
                    self.resource_snapshot,
                    self.heartbeat,
                )
            ):
                return "unknown"
            usage = self.usage_reconciliation().status
            if usage == "exceeded":
                return "blocked"
            if usage == "unknown":
                return "unknown"
            return "ready"

    def to_dict(self, now: str | None = None) -> dict[str, Any]:
        """Return a JSON-ready projection without writing it anywhere."""

        with self._lock:
            return {
                "registration": self.registration.to_dict() if self.registration else None,
                "capability_snapshot": (
                    self.capability_snapshot.to_dict() if self.capability_snapshot else None
                ),
                "resource_snapshot": (
                    self.resource_snapshot.to_dict() if self.resource_snapshot else None
                ),
                "heartbeat": self.heartbeat.to_dict() if self.heartbeat else None,
                "execution_handles": {
                    key: self.execution_handles[key].to_dict()
                    for key in sorted(self.execution_handles)
                },
                "worker_status": self.worker_status(now),
                "admission_status": self.admission_status(now),
                "usage_reconciliation": self.usage_reconciliation().to_dict(),
            }


__all__ = [
    "WorkerStateError",
    "WorkerIdentityError",
    "WorkerFenceError",
    "WorkerSequenceError",
    "WorkerIdempotencyError",
    "UsageReconciliation",
    "reconcile_usage",
    "WorkerState",
]
