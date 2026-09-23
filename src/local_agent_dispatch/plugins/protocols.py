"""Stable, provider-free plugin contracts for local-agent-dispatch.

The dispatch scripts intentionally remain usable as standalone files.  This
module is the small package-level seam that new integrations can implement
without importing a provider SDK or opening a network connection.  Protocols
describe the operations; the registry/conformance module checks metadata and
method presence before a plugin is admitted to a control-plane process.

The operation methods are deliberately split by evidence type.  A provider
whose quota probe fails must return an ``Evidence`` value with ``status`` set
to ``unknown``/``error``; it cannot manufacture a ready catalog or quota from
that failure.  None of the dataclasses below performs discovery or execution.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol, runtime_checkable


PLUGIN_API_VERSION = "1"
LIFECYCLE_SCHEMA_VERSION = "lad.plugin.lifecycle/1.0"

PLUGIN_KINDS = (
    "system_probe",
    "provider",
    "runtime",
    "transport",
    "validator",
    "agent_harness",
    "batch_scheduler",
    "artifact_store",
)

EVIDENCE_STATUSES = (
    "ready",
    "unknown",
    "blocked",
    "unavailable",
    "error",
)

EvidenceStatus = Literal[
    "ready", "unknown", "blocked", "unavailable", "error"
]

OPERATION_STATUSES = (
    "ready",
    "accepted",
    "pending",
    "running",
    "succeeded",
    "cancelled",
    "blocked",
    "unavailable",
    "unknown",
    "error",
)

OperationStatus = Literal[
    "ready",
    "accepted",
    "pending",
    "running",
    "succeeded",
    "cancelled",
    "blocked",
    "unavailable",
    "unknown",
    "error",
]

ERROR_CLASSES = (
    "none",
    "capability",
    "authentication",
    "authorization",
    "quota",
    "rate_limit",
    "resource",
    "transport",
    "timeout",
    "cancelled",
    "validation",
    "conflict",
    "fenced",
    "not_found",
    "plugin",
    "unknown",
)

ErrorClass = Literal[
    "none",
    "capability",
    "authentication",
    "authorization",
    "quota",
    "rate_limit",
    "resource",
    "transport",
    "timeout",
    "cancelled",
    "validation",
    "conflict",
    "fenced",
    "not_found",
    "plugin",
    "unknown",
]

FenceToken = int | str


def _copy_mapping(value: Mapping[str, Any] | None) -> dict[str, Any]:
    """Copy a mapping so frozen result objects do not alias caller state."""

    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise TypeError("plugin metadata must be a mapping")
    return dict(value)


def _require_nonempty(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")


def _validate_schema_version(value: str) -> None:
    if value != LIFECYCLE_SCHEMA_VERSION:
        raise ValueError(
            f"unsupported lifecycle schema_version: {value!r}; "
            f"expected {LIFECYCLE_SCHEMA_VERSION!r}"
        )


def _validate_fence_token(value: FenceToken) -> None:
    if isinstance(value, bool):
        raise TypeError("fence_token must be a non-negative integer or non-empty string")
    if isinstance(value, int):
        if value < 0:
            raise ValueError("fence_token must be non-negative")
        return
    if isinstance(value, str) and value.strip():
        return
    raise TypeError("fence_token must be a non-negative integer or non-empty string")


def _copy_artifact_references(
    values: tuple["ArtifactReference", ...] | list["ArtifactReference"],
) -> tuple["ArtifactReference", ...]:
    copied = tuple(values)
    if any(not isinstance(value, ArtifactReference) for value in copied):
        raise TypeError("artifact_references must contain only ArtifactReference values")
    return copied


def _validate_operation_result(status: str, error_class: str) -> None:
    if status not in OPERATION_STATUSES:
        raise ValueError(f"unsupported operation status: {status}")
    if error_class not in ERROR_CLASSES:
        raise ValueError(f"unsupported error_class: {error_class}")
    if status in {"ready", "accepted", "pending", "running", "succeeded"} and error_class != "none":
        raise ValueError(f"status={status!r} requires error_class='none'")
    if status in {"cancelled", "blocked", "unavailable", "error"} and error_class == "none":
        raise ValueError(f"status={status!r} requires a classified error")


@dataclass(frozen=True)
class PluginDescriptor:
    """Static identity and capability metadata for one plugin.

    ``plugin_id`` is scoped by ``kind`` in the registry, so ``local`` may be
    used once as a transport and once as a runtime.  Capabilities are labels,
    not permission grants; the planner still applies host, quota, and policy
    gates before any operation is invoked.
    """

    plugin_id: str
    kind: str
    version: str = "0.1.0"
    api_version: str = PLUGIN_API_VERSION
    capabilities: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "metadata", _copy_mapping(self.metadata))
        object.__setattr__(self, "capabilities", tuple(self.capabilities))


@dataclass(frozen=True)
class ProbeRequest:
    """Bounded context for local system discovery."""

    workspace: str | None = None
    host_id: str | None = None
    options: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "options", _copy_mapping(self.options))


@dataclass(frozen=True)
class DiscoveryRequest:
    """Provider/runtime discovery context with no prompt payload."""

    scope: str = "default"
    host_id: str | None = None
    options: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "options", _copy_mapping(self.options))


@dataclass(frozen=True)
class ExecutionRequest:
    """Opaque execution context supplied only after policy/lease gates."""

    job_id: str
    attempt_id: str
    workspace: str
    model: str | None = None
    variant: str | None = None
    prompt_file: str | None = None
    options: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "options", _copy_mapping(self.options))


@dataclass(frozen=True)
class TransportRequest:
    """Transport preparation/execution context.

    The request carries references rather than prompt text.  Concrete
    transports are responsible for their own confinement and authentication
    checks; this package never opens SSH or starts a subprocess.
    """

    job_id: str
    attempt_id: str
    source: str | None = None
    destination: str | None = None
    options: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "options", _copy_mapping(self.options))


@dataclass(frozen=True)
class ValidationRequest:
    """Artifact validation context supplied after an execution attempt."""

    job_id: str
    attempt_id: str
    workspace: str
    artifacts: tuple[str, ...] = ()
    options: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "artifacts", tuple(self.artifacts))
        object.__setattr__(self, "options", _copy_mapping(self.options))


@dataclass(frozen=True)
class Evidence:
    """Evidence returned by discovery/probe operations.

    ``status=unknown`` is intentional and distinct from ``ready``.  Consumers
    must not reinterpret absent or failed evidence as an available resource.
    """

    status: EvidenceStatus = "unknown"
    data: Mapping[str, Any] = field(default_factory=dict)
    source: str | None = None
    observed_at: str | None = None
    reason: str | None = None

    def __post_init__(self) -> None:
        if self.status not in EVIDENCE_STATUSES:
            raise ValueError(f"unsupported evidence status: {self.status}")
        object.__setattr__(self, "data", _copy_mapping(self.data))


@dataclass(frozen=True)
class ExecutionResult:
    """Provider/runtime execution result; completion still needs validation."""

    status: EvidenceStatus = "unknown"
    output: str | None = None
    data: Mapping[str, Any] = field(default_factory=dict)
    artifacts: Mapping[str, Any] = field(default_factory=dict)
    reason: str | None = None

    def __post_init__(self) -> None:
        if self.status not in EVIDENCE_STATUSES:
            raise ValueError(f"unsupported execution status: {self.status}")
        object.__setattr__(self, "data", _copy_mapping(self.data))
        object.__setattr__(self, "artifacts", _copy_mapping(self.artifacts))


@dataclass(frozen=True)
class ValidationResult:
    """Validator result; only ``ready`` with explicit artifact data can pass."""

    status: EvidenceStatus = "unknown"
    passed: bool = False
    data: Mapping[str, Any] = field(default_factory=dict)
    reason: str | None = None

    def __post_init__(self) -> None:
        if self.status not in EVIDENCE_STATUSES:
            raise ValueError(f"unsupported validation status: {self.status}")
        object.__setattr__(self, "data", _copy_mapping(self.data))


@dataclass(frozen=True)
class ArtifactReference:
    """Opaque, serializable reference to an input, output, or checkpoint.

    ``uri`` may be a confined local path or a store-specific URI.  Merely
    constructing a reference never opens it.  A digest is optional while an
    artifact is being prepared, but controllers may require one before claim
    promotion.
    """

    uri: str
    role: str = "output"
    digest: str | None = None
    media_type: str | None = None
    size_bytes: int | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)
    schema_version: str = LIFECYCLE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _validate_schema_version(self.schema_version)
        _require_nonempty(self.uri, "artifact uri")
        _require_nonempty(self.role, "artifact role")
        if self.digest is not None:
            _require_nonempty(self.digest, "artifact digest")
        if self.media_type is not None:
            _require_nonempty(self.media_type, "artifact media_type")
        if self.size_bytes is not None and (
            isinstance(self.size_bytes, bool) or self.size_bytes < 0
        ):
            raise ValueError("artifact size_bytes must be non-negative")
        object.__setattr__(self, "metadata", _copy_mapping(self.metadata))


@dataclass(frozen=True, kw_only=True)
class CapabilityRequest:
    """Read-only request for dynamic, host-scoped plugin capabilities."""

    scope: str = "default"
    host_id: str | None = None
    options: Mapping[str, Any] = field(default_factory=dict)
    schema_version: str = LIFECYCLE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _validate_schema_version(self.schema_version)
        _require_nonempty(self.scope, "capability scope")
        if self.host_id is not None:
            _require_nonempty(self.host_id, "host_id")
        object.__setattr__(self, "options", _copy_mapping(self.options))


@dataclass(frozen=True, kw_only=True)
class CapabilityResult:
    """Versioned dynamic capabilities; descriptor labels remain static hints."""

    status: EvidenceStatus = "unknown"
    capabilities: tuple[str, ...] = ()
    data: Mapping[str, Any] = field(default_factory=dict)
    source: str | None = None
    observed_at: str | None = None
    error_class: ErrorClass = "unknown"
    reason: str | None = None
    schema_version: str = LIFECYCLE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _validate_schema_version(self.schema_version)
        if self.status not in EVIDENCE_STATUSES:
            raise ValueError(f"unsupported capability status: {self.status}")
        if self.error_class not in ERROR_CLASSES:
            raise ValueError(f"unsupported error_class: {self.error_class}")
        if self.status == "ready" and self.error_class != "none":
            raise ValueError("status='ready' requires error_class='none'")
        if self.status in {"blocked", "unavailable", "error"} and self.error_class == "none":
            raise ValueError(f"status={self.status!r} requires a classified error")
        capabilities = tuple(self.capabilities)
        if any(not isinstance(value, str) or not value.strip() for value in capabilities):
            raise ValueError("capabilities must contain non-empty strings")
        if len(set(capabilities)) != len(capabilities):
            raise ValueError("capabilities must not contain duplicates")
        object.__setattr__(self, "capabilities", capabilities)
        object.__setattr__(self, "data", _copy_mapping(self.data))


@dataclass(frozen=True, kw_only=True)
class ExecutionHandle:
    """Durable identity returned by an asynchronous submit operation."""

    handle_id: str
    plugin_id: str
    job_id: str
    attempt_id: str
    idempotency_key: str
    fence_token: FenceToken
    submitted_at: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)
    schema_version: str = LIFECYCLE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _validate_schema_version(self.schema_version)
        for field_name in (
            "handle_id",
            "plugin_id",
            "job_id",
            "attempt_id",
            "idempotency_key",
        ):
            _require_nonempty(getattr(self, field_name), field_name)
        _validate_fence_token(self.fence_token)
        object.__setattr__(self, "metadata", _copy_mapping(self.metadata))


@dataclass(frozen=True, kw_only=True)
class LifecycleRequest:
    """Common fenced and idempotent identity for lifecycle operations."""

    job_id: str
    attempt_id: str
    idempotency_key: str
    fence_token: FenceToken
    artifact_references: tuple[ArtifactReference, ...] = ()
    options: Mapping[str, Any] = field(default_factory=dict)
    schema_version: str = LIFECYCLE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _validate_schema_version(self.schema_version)
        _require_nonempty(self.job_id, "job_id")
        _require_nonempty(self.attempt_id, "attempt_id")
        _require_nonempty(self.idempotency_key, "idempotency_key")
        _validate_fence_token(self.fence_token)
        object.__setattr__(
            self,
            "artifact_references",
            _copy_artifact_references(self.artifact_references),
        )
        object.__setattr__(self, "options", _copy_mapping(self.options))


@dataclass(frozen=True, kw_only=True)
class PrepareRequest(LifecycleRequest):
    """Prepare confined inputs, workspace, or scheduler submission state."""


@dataclass(frozen=True, kw_only=True)
class SubmitRequest(LifecycleRequest):
    """Submit one prepared attempt without waiting for completion."""

    preparation_id: str | None = None

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.preparation_id is not None:
            _require_nonempty(self.preparation_id, "preparation_id")


@dataclass(frozen=True, kw_only=True)
class HandleRequest(LifecycleRequest):
    """Lifecycle request bound to a previously persisted execution handle."""

    handle: ExecutionHandle

    def __post_init__(self) -> None:
        super().__post_init__()
        if not isinstance(self.handle, ExecutionHandle):
            raise TypeError("handle must be an ExecutionHandle")
        if self.handle.job_id != self.job_id or self.handle.attempt_id != self.attempt_id:
            raise ValueError("request job_id/attempt_id must match the execution handle")


@dataclass(frozen=True, kw_only=True)
class ObserveRequest(HandleRequest):
    """Read the current state of a durable execution handle."""


@dataclass(frozen=True, kw_only=True)
class HeartbeatRequest(HandleRequest):
    """Renew ownership for a handle under the supplied fence token."""


@dataclass(frozen=True, kw_only=True)
class CancelRequest(HandleRequest):
    """Request idempotent cancellation of a durable execution handle."""

    reason: str | None = None


@dataclass(frozen=True, kw_only=True)
class CollectRequest(HandleRequest):
    """Collect only declared artifact references from a completed handle."""

    destination: str | None = None

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.destination is not None:
            _require_nonempty(self.destination, "destination")


@dataclass(frozen=True, kw_only=True)
class ResumeRequest(HandleRequest):
    """Reattach to or resume a previously persisted execution handle."""

    checkpoint_reference: ArtifactReference | None = None

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.checkpoint_reference is not None and not isinstance(
            self.checkpoint_reference, ArtifactReference
        ):
            raise TypeError("checkpoint_reference must be an ArtifactReference")


# Public spelling aliases: resume is the operation; reattach describes the
# recovery use case.  They intentionally share one wire shape.
ReattachRequest = ResumeRequest


@dataclass(frozen=True, kw_only=True)
class LifecycleResult:
    """Common result envelope for scheduler/harness/store lifecycle calls."""

    status: OperationStatus = "unknown"
    handle: ExecutionHandle | None = None
    artifact_references: tuple[ArtifactReference, ...] = ()
    error_class: ErrorClass = "unknown"
    reason: str | None = None
    data: Mapping[str, Any] = field(default_factory=dict)
    schema_version: str = LIFECYCLE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _validate_schema_version(self.schema_version)
        _validate_operation_result(self.status, self.error_class)
        if self.handle is not None and not isinstance(self.handle, ExecutionHandle):
            raise TypeError("handle must be an ExecutionHandle")
        object.__setattr__(
            self,
            "artifact_references",
            _copy_artifact_references(self.artifact_references),
        )
        object.__setattr__(self, "data", _copy_mapping(self.data))


@dataclass(frozen=True, kw_only=True)
class PrepareResult(LifecycleResult):
    preparation_id: str | None = None

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.preparation_id is not None:
            _require_nonempty(self.preparation_id, "preparation_id")


@dataclass(frozen=True, kw_only=True)
class SubmitResult(LifecycleResult):
    def __post_init__(self) -> None:
        super().__post_init__()
        if self.status in {"accepted", "pending", "running", "succeeded"} and self.handle is None:
            raise ValueError(f"status={self.status!r} requires an execution handle")


@dataclass(frozen=True, kw_only=True)
class ObserveResult(LifecycleResult):
    pass


@dataclass(frozen=True, kw_only=True)
class HeartbeatResult(LifecycleResult):
    pass


@dataclass(frozen=True, kw_only=True)
class CancelResult(LifecycleResult):
    pass


@dataclass(frozen=True, kw_only=True)
class CollectResult(LifecycleResult):
    pass


@dataclass(frozen=True, kw_only=True)
class ResumeResult(LifecycleResult):
    def __post_init__(self) -> None:
        super().__post_init__()
        if self.status in {"accepted", "pending", "running", "succeeded"} and self.handle is None:
            raise ValueError(f"status={self.status!r} requires an execution handle")


ReattachResult = ResumeResult


@runtime_checkable
class Plugin(Protocol):
    """Common static surface shared by all plugin kinds."""

    @property
    def descriptor(self) -> PluginDescriptor:
        ...


@runtime_checkable
class SystemProbe(Plugin, Protocol):
    """Discover local OS/hardware/runtime facts without provider prompts."""

    def probe(self, request: ProbeRequest) -> Evidence:
        ...


@runtime_checkable
class ProviderAdapter(Plugin, Protocol):
    """Provider CLI/API boundary with separate evidence operations."""

    def discover_catalog(self, request: DiscoveryRequest) -> Evidence:
        ...

    def discover_auth_state(self, request: DiscoveryRequest) -> Evidence:
        ...

    def discover_quota(self, request: DiscoveryRequest) -> Evidence:
        ...

    def probe_runtime(self, request: DiscoveryRequest) -> Evidence:
        ...

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        ...


@runtime_checkable
class RuntimeAdapter(Plugin, Protocol):
    """Local/server model-runtime boundary (vLLM, Ollama, llama.cpp, etc.)."""

    def probe(self, request: DiscoveryRequest) -> Evidence:
        ...

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        ...


@runtime_checkable
class TransportAdapter(Plugin, Protocol):
    """Artifact/workspace transport boundary (local, OpenSSH, or future)."""

    def prepare(self, request: TransportRequest) -> Evidence:
        ...

    def execute(self, request: TransportRequest) -> Evidence:
        ...


@runtime_checkable
class Validator(Plugin, Protocol):
    """Independent artifact/quality validation boundary."""

    def validate(self, request: ValidationRequest) -> ValidationResult:
        ...


@runtime_checkable
class SchedulingLifecycle(Plugin, Protocol):
    """Durable asynchronous lifecycle shared by harnesses and schedulers."""

    def capabilities(self, request: CapabilityRequest) -> CapabilityResult:
        ...

    def prepare(self, request: PrepareRequest) -> PrepareResult:
        ...

    def submit(self, request: SubmitRequest) -> SubmitResult:
        ...

    def observe(self, request: ObserveRequest) -> ObserveResult:
        ...

    def heartbeat(self, request: HeartbeatRequest) -> HeartbeatResult:
        ...

    def cancel(self, request: CancelRequest) -> CancelResult:
        ...

    def collect(self, request: CollectRequest) -> CollectResult:
        ...

    def resume(self, request: ResumeRequest) -> ResumeResult:
        ...


@runtime_checkable
class AgentHarness(SchedulingLifecycle, Protocol):
    """Agent CLI/session boundary (Codex, Cursor, OpenCode, or equivalent)."""


@runtime_checkable
class BatchScheduler(SchedulingLifecycle, Protocol):
    """External scheduler boundary (local, PBS, Slurm, Kubernetes, etc.)."""


@runtime_checkable
class ArtifactStore(Plugin, Protocol):
    """Artifact reservation and collection boundary.

    Stores use ``prepare`` to validate/reserve declared references and
    ``collect`` to materialize only those references after an execution handle
    exists.  Long-running transfers may be represented by the handle supplied
    in ``CollectRequest``; the store does not receive prompt text.
    """

    def capabilities(self, request: CapabilityRequest) -> CapabilityResult:
        ...

    def prepare(self, request: PrepareRequest) -> PrepareResult:
        ...

    def collect(self, request: CollectRequest) -> CollectResult:
        ...


SCHEDULING_LIFECYCLE_METHODS = (
    "capabilities",
    "prepare",
    "submit",
    "observe",
    "heartbeat",
    "cancel",
    "collect",
    "resume",
)


PROTOCOL_METHODS: Mapping[str, tuple[str, ...]] = {
    "system_probe": ("probe",),
    "provider": (
        "discover_catalog",
        "discover_auth_state",
        "discover_quota",
        "probe_runtime",
        "execute",
    ),
    "runtime": ("probe", "execute"),
    "transport": ("prepare", "execute"),
    "validator": ("validate",),
    "agent_harness": SCHEDULING_LIFECYCLE_METHODS,
    "batch_scheduler": SCHEDULING_LIFECYCLE_METHODS,
    "artifact_store": ("capabilities", "prepare", "collect"),
}


__all__ = [
    "PLUGIN_API_VERSION",
    "LIFECYCLE_SCHEMA_VERSION",
    "PLUGIN_KINDS",
    "EVIDENCE_STATUSES",
    "OPERATION_STATUSES",
    "ERROR_CLASSES",
    "EvidenceStatus",
    "OperationStatus",
    "ErrorClass",
    "FenceToken",
    "PluginDescriptor",
    "ProbeRequest",
    "DiscoveryRequest",
    "ExecutionRequest",
    "TransportRequest",
    "ValidationRequest",
    "Evidence",
    "ExecutionResult",
    "ValidationResult",
    "ArtifactReference",
    "CapabilityRequest",
    "CapabilityResult",
    "ExecutionHandle",
    "LifecycleRequest",
    "PrepareRequest",
    "SubmitRequest",
    "HandleRequest",
    "ObserveRequest",
    "HeartbeatRequest",
    "CancelRequest",
    "CollectRequest",
    "ResumeRequest",
    "ReattachRequest",
    "LifecycleResult",
    "PrepareResult",
    "SubmitResult",
    "ObserveResult",
    "HeartbeatResult",
    "CancelResult",
    "CollectResult",
    "ResumeResult",
    "ReattachResult",
    "Plugin",
    "SystemProbe",
    "ProviderAdapter",
    "RuntimeAdapter",
    "TransportAdapter",
    "Validator",
    "SchedulingLifecycle",
    "AgentHarness",
    "BatchScheduler",
    "ArtifactStore",
    "SCHEDULING_LIFECYCLE_METHODS",
    "PROTOCOL_METHODS",
]
