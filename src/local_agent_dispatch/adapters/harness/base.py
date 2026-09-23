"""Generic, provider-free boundary between an AgentHarness and a runner.

The classes in this module do not import ``subprocess`` and do not discover a
provider.  A controller supplies an inert capability snapshot, a pure command
planner, and a callable runner.  Only lifecycle operations that explicitly
cross the execution boundary call the runner.
"""

from __future__ import annotations

import hashlib
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from typing import Any, Protocol

from ...plugins import (
    ERROR_CLASSES,
    OPERATION_STATUSES,
    ArtifactReference,
    CancelRequest,
    CancelResult,
    CapabilityRequest,
    CapabilityResult,
    CollectRequest,
    CollectResult,
    ErrorClass,
    ExecutionHandle,
    FenceToken,
    HeartbeatRequest,
    HeartbeatResult,
    LifecycleRequest,
    LifecycleResult,
    ObserveRequest,
    ObserveResult,
    OperationStatus,
    PluginDescriptor,
    PrepareRequest,
    PrepareResult,
    ResumeRequest,
    ResumeResult,
    SubmitRequest,
    SubmitResult,
)


RunnerOperation = str  # Kept open for forward-compatible runner-local operations.


class CommandPlanningError(ValueError):
    """Fail-closed planning rejection with a lifecycle error classification."""

    def __init__(
        self,
        reason: str,
        *,
        status: OperationStatus = "blocked",
        error_class: ErrorClass = "validation",
    ) -> None:
        if status not in OPERATION_STATUSES:
            raise ValueError(f"unsupported operation status: {status}")
        if error_class not in ERROR_CLASSES:
            raise ValueError(f"unsupported error_class: {error_class}")
        super().__init__(reason)
        self.status = status
        self.error_class = error_class
        self.reason = reason


@dataclass(frozen=True)
class CommandPlan:
    """An ephemeral command passed only to the injected runner.

    ``argv`` can contain sensitive prompt text and is therefore excluded from
    ``repr``.  Code that persists or logs a plan must use ``redacted_argv`` or
    ``summary``.  This boundary is intentionally an execution object, not a
    receipt or event payload.
    """

    argv: tuple[str, ...] = field(repr=False)
    cwd: str
    redacted_argv: tuple[str, ...]
    sensitive_argv_indices: tuple[int, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        argv = tuple(self.argv)
        redacted = tuple(self.redacted_argv)
        sensitive = tuple(self.sensitive_argv_indices)
        if not argv or any(not isinstance(item, str) or not item for item in argv):
            raise ValueError("argv must contain non-empty strings")
        if len(redacted) != len(argv) or any(
            not isinstance(item, str) or not item for item in redacted
        ):
            raise ValueError("redacted_argv must safely mirror argv")
        if not isinstance(self.cwd, str) or not self.cwd.strip():
            raise ValueError("cwd must be a non-empty string")
        if len(set(sensitive)) != len(sensitive) or any(
            isinstance(index, bool)
            or not isinstance(index, int)
            or index < 0
            or index >= len(argv)
            for index in sensitive
        ):
            raise ValueError("sensitive_argv_indices must be unique valid indices")
        if any(redacted[index] == argv[index] for index in sensitive):
            raise ValueError("every sensitive argv value must be redacted")
        if not isinstance(self.metadata, Mapping):
            raise TypeError("command metadata must be a mapping")
        if any(not isinstance(key, str) for key in self.metadata):
            raise TypeError("command metadata keys must be strings")
        reserved = {"command", "argv", "cwd"} & set(self.metadata)
        if reserved:
            raise ValueError(
                "command metadata cannot override receipt fields: "
                + ", ".join(sorted(reserved))
            )
        object.__setattr__(self, "argv", argv)
        object.__setattr__(self, "redacted_argv", redacted)
        object.__setattr__(self, "sensitive_argv_indices", sensitive)
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def fingerprint(self) -> str:
        """Return a stable digest without exposing raw argv values."""

        digest = hashlib.sha256()
        digest.update(self.cwd.encode("utf-8"))
        for value in self.argv:
            digest.update(b"\0")
            digest.update(value.encode("utf-8"))
        return digest.hexdigest()

    @property
    def summary(self) -> Mapping[str, Any]:
        """Return the explicitly non-secret subset suitable for a receipt."""

        return {
            "command": self.redacted_argv[0],
            "argv": self.redacted_argv,
            "cwd": self.cwd,
            **dict(self.metadata),
        }


class CommandPlanner(Protocol):
    """Pure request-to-command planning seam."""

    def __call__(self, request: LifecycleRequest) -> CommandPlan:
        ...


@dataclass(frozen=True)
class RunnerInvocation:
    """One explicit crossing of the injected execution boundary."""

    operation: RunnerOperation
    handle: ExecutionHandle
    request: LifecycleRequest = field(repr=False)
    command: CommandPlan | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.operation, str) or not self.operation.strip():
            raise ValueError("runner operation must be a non-empty string")
        if not isinstance(self.handle, ExecutionHandle):
            raise TypeError("runner handle must be an ExecutionHandle")
        if not isinstance(self.request, LifecycleRequest):
            raise TypeError("runner request must be a LifecycleRequest")
        if self.command is not None and not isinstance(self.command, CommandPlan):
            raise TypeError("runner command must be a CommandPlan")
        if self.operation == "submit" and self.command is None:
            raise ValueError("submit runner invocation requires a command")
        if self.operation != "submit" and self.command is not None:
            raise ValueError("only submit runner invocations may carry a command")


@dataclass(frozen=True)
class RunnerOutcome:
    """Sanitized outcome returned by an injected runner.

    ``external_handle_id`` is the only runner identifier copied into the
    durable execution handle.  It must not contain credentials or prompt text.
    """

    status: OperationStatus = "unknown"
    error_class: ErrorClass = "unknown"
    external_handle_id: str | None = None
    submitted_at: str | None = None
    artifact_references: tuple[ArtifactReference, ...] = ()
    data: Mapping[str, Any] = field(default_factory=dict)
    reason: str | None = None

    def __post_init__(self) -> None:
        # Reuse the public envelope's status/error and artifact validation.
        LifecycleResult(
            status=self.status,
            error_class=self.error_class,
            artifact_references=self.artifact_references,
            data=self.data,
            reason=self.reason,
        )
        if self.external_handle_id is not None and (
            not isinstance(self.external_handle_id, str)
            or not self.external_handle_id.strip()
        ):
            raise ValueError("external_handle_id must be a non-empty string")
        if self.submitted_at is not None and (
            not isinstance(self.submitted_at, str) or not self.submitted_at.strip()
        ):
            raise ValueError("submitted_at must be a non-empty string")
        object.__setattr__(self, "artifact_references", tuple(self.artifact_references))
        object.__setattr__(self, "data", dict(self.data))


class HarnessRunner(Protocol):
    """Callable provider/process boundary injected by the application."""

    def __call__(self, invocation: RunnerInvocation) -> RunnerOutcome:
        ...


@dataclass(frozen=True)
class _Receipt:
    request: LifecycleRequest
    result: LifecycleResult


class InjectedRunnerHarness:
    """Reference AgentHarness lifecycle backed by one injected callable.

    The class provides in-process idempotency and monotonic integer fencing.
    A production runner/store must additionally make its external submission
    and receipt persistence atomic.  Deterministic local handle IDs let a
    reconstructed adapter reattach through a durable runner without retaining
    prompt text or argv.
    """

    descriptor = PluginDescriptor(
        "injected-runner-reference",
        "agent_harness",
        version="0.1.0",
        capabilities=(
            "prepare",
            "submit",
            "observe",
            "heartbeat",
            "cancel",
            "collect",
            "resume",
        ),
    )

    def __init__(
        self,
        *,
        runner: HarnessRunner | Callable[[RunnerInvocation], RunnerOutcome],
        capability_snapshot: CapabilityResult,
        planner: CommandPlanner | Callable[[LifecycleRequest], CommandPlan],
    ) -> None:
        if not callable(runner):
            raise TypeError("runner must be callable")
        if not isinstance(capability_snapshot, CapabilityResult):
            raise TypeError("capability_snapshot must be a CapabilityResult")
        if not callable(planner):
            raise TypeError("planner must be callable")
        self._runner = runner
        self._capability_snapshot = capability_snapshot
        self._planner = planner
        self._lock = threading.RLock()
        self._fences: dict[tuple[str, str], FenceToken] = {}
        self._receipts: dict[tuple[str, str], _Receipt] = {}

    def capabilities(self, request: CapabilityRequest) -> CapabilityResult:
        """Return injected evidence without touching the runner."""

        if not isinstance(request, CapabilityRequest):
            raise TypeError("request must be a CapabilityRequest")
        return self._capability_snapshot

    def prepare(self, request: PrepareRequest) -> PrepareResult:
        if not isinstance(request, PrepareRequest):
            raise TypeError("request must be a PrepareRequest")
        with self._lock:
            rejected = self._preflight("prepare", request, PrepareResult)
            if rejected is not None:
                return rejected
            cached = self._cached("prepare", request, PrepareResult)
            if cached is not None:
                return cached
            blocked = self._capability_failure(PrepareResult)
            if blocked is not None:
                return self._remember("prepare", request, blocked)
            try:
                plan = self._planner(request)
            except CommandPlanningError as exc:
                result = PrepareResult(
                    status=exc.status,
                    error_class=exc.error_class,
                    reason=exc.reason,
                )
                return self._remember("prepare", request, result)
            except Exception as exc:
                result = PrepareResult(
                    status="error",
                    error_class="plugin",
                    reason=f"command planner failed ({exc.__class__.__name__})",
                )
                return self._remember("prepare", request, result)
            preparation_id = self._preparation_id(request, plan)
            result = PrepareResult(
                status="ready",
                error_class="none",
                preparation_id=preparation_id,
                data={"plan": plan.summary},
            )
            return self._remember("prepare", request, result)

    def submit(self, request: SubmitRequest) -> SubmitResult:
        if not isinstance(request, SubmitRequest):
            raise TypeError("request must be a SubmitRequest")
        with self._lock:
            rejected = self._preflight("submit", request, SubmitResult)
            if rejected is not None:
                return rejected
            cached = self._cached("submit", request, SubmitResult)
            if cached is not None:
                return cached
            blocked = self._capability_failure(SubmitResult)
            if blocked is not None:
                return self._remember("submit", request, blocked)
            try:
                plan = self._planner(request)
            except CommandPlanningError as exc:
                result = SubmitResult(
                    status=exc.status,
                    error_class=exc.error_class,
                    reason=exc.reason,
                )
                return self._remember("submit", request, result)
            except Exception as exc:
                result = SubmitResult(
                    status="error",
                    error_class="plugin",
                    reason=f"command planner failed ({exc.__class__.__name__})",
                )
                return self._remember("submit", request, result)
            expected_preparation = self._preparation_id(request, plan)
            if (
                request.preparation_id is not None
                and request.preparation_id != expected_preparation
            ):
                result = SubmitResult(
                    status="blocked",
                    error_class="conflict",
                    reason="preparation_id does not match this fenced command plan",
                )
                return self._remember("submit", request, result)
            handle = self._new_handle(request)
            result = self._invoke("submit", request, SubmitResult, handle, command=plan)
            return self._remember("submit", request, result)

    def observe(self, request: ObserveRequest) -> ObserveResult:
        return self._handle_operation("observe", request, ObserveRequest, ObserveResult)

    def heartbeat(self, request: HeartbeatRequest) -> HeartbeatResult:
        return self._handle_operation(
            "heartbeat", request, HeartbeatRequest, HeartbeatResult
        )

    def cancel(self, request: CancelRequest) -> CancelResult:
        return self._handle_operation("cancel", request, CancelRequest, CancelResult)

    def collect(self, request: CollectRequest) -> CollectResult:
        return self._handle_operation("collect", request, CollectRequest, CollectResult)

    def resume(self, request: ResumeRequest) -> ResumeResult:
        return self._handle_operation(
            "resume",
            request,
            ResumeRequest,
            ResumeResult,
            require_capability=True,
        )

    def _handle_operation(
        self,
        operation: str,
        request: LifecycleRequest,
        request_type: type[LifecycleRequest],
        result_type: type[LifecycleResult],
        *,
        require_capability: bool = False,
    ) -> Any:
        if not isinstance(request, request_type):
            raise TypeError(f"request must be a {request_type.__name__}")
        with self._lock:
            rejected = self._preflight(operation, request, result_type)
            if rejected is not None:
                return rejected
            cached = self._cached(operation, request, result_type)
            if cached is not None:
                return cached
            if require_capability:
                blocked = self._capability_failure(result_type)
                if blocked is not None:
                    return self._remember(operation, request, blocked)
            assert hasattr(request, "handle")
            handle = replace(request.handle, fence_token=request.fence_token)
            result = self._invoke(operation, request, result_type, handle)
            return self._remember(operation, request, result)

    def _preflight(
        self,
        operation: str,
        request: LifecycleRequest,
        result_type: type[LifecycleResult],
    ) -> LifecycleResult | None:
        handle = getattr(request, "handle", None)
        if handle is not None and handle.plugin_id != self.descriptor.plugin_id:
            return result_type(
                status="blocked",
                error_class="authorization",
                reason="execution handle belongs to another harness",
            )
        fence_reason = self._advance_fence(request, handle)
        if fence_reason is not None:
            return result_type(
                status="blocked",
                error_class="fenced",
                reason=fence_reason,
            )
        return None

    def _advance_fence(
        self,
        request: LifecycleRequest,
        handle: ExecutionHandle | None,
    ) -> str | None:
        identity = (request.job_id, request.attempt_id)
        current = self._fences.get(identity)
        if current is None and handle is not None:
            current = handle.fence_token
        candidate = request.fence_token
        if current is None:
            self._fences[identity] = candidate
            return None
        if isinstance(current, int) and isinstance(candidate, int):
            if candidate < current:
                return "request fence token is older than the accepted generation"
            self._fences[identity] = candidate
            return None
        if type(current) is type(candidate) and candidate == current:
            self._fences[identity] = candidate
            return None
        return "opaque or mixed fence token change cannot be proven newer"

    def _cached(
        self,
        operation: str,
        request: LifecycleRequest,
        result_type: type[LifecycleResult],
    ) -> LifecycleResult | None:
        receipt = self._receipts.get((operation, request.idempotency_key))
        if receipt is None:
            return None
        if receipt.request == request:
            return receipt.result
        return result_type(
            status="blocked",
            error_class="conflict",
            reason="idempotency key was already used for a different request",
        )

    def _remember(
        self,
        operation: str,
        request: LifecycleRequest,
        result: LifecycleResult,
    ) -> Any:
        self._receipts[(operation, request.idempotency_key)] = _Receipt(request, result)
        return result

    def _capability_failure(
        self, result_type: type[LifecycleResult]
    ) -> LifecycleResult | None:
        snapshot = self._capability_snapshot
        if snapshot.status == "ready":
            return None
        return result_type(
            status=snapshot.status,
            error_class=snapshot.error_class,
            reason=snapshot.reason or "required harness capability is not proven ready",
        )

    def _preparation_id(self, request: LifecycleRequest, plan: CommandPlan) -> str:
        digest = hashlib.sha256()
        for value in (
            self.descriptor.plugin_id,
            request.job_id,
            request.attempt_id,
            f"{type(request.fence_token).__name__}:{request.fence_token}",
            plan.fingerprint,
        ):
            digest.update(value.encode("utf-8"))
            digest.update(b"\0")
        return "prepared-" + digest.hexdigest()[:32]

    def _new_handle(self, request: SubmitRequest) -> ExecutionHandle:
        digest = hashlib.sha256()
        for value in (
            self.descriptor.plugin_id,
            request.job_id,
            request.attempt_id,
            request.idempotency_key,
        ):
            digest.update(value.encode("utf-8"))
            digest.update(b"\0")
        return ExecutionHandle(
            handle_id=f"{self.descriptor.plugin_id}:{digest.hexdigest()[:32]}",
            plugin_id=self.descriptor.plugin_id,
            job_id=request.job_id,
            attempt_id=request.attempt_id,
            idempotency_key=request.idempotency_key,
            fence_token=request.fence_token,
        )

    def _invoke(
        self,
        operation: str,
        request: LifecycleRequest,
        result_type: type[LifecycleResult],
        handle: ExecutionHandle,
        *,
        command: CommandPlan | None = None,
    ) -> LifecycleResult:
        invocation = RunnerInvocation(operation, handle, request, command)
        try:
            outcome = self._runner(invocation)
        except Exception as exc:
            # Runner exceptions can echo argv, headers, or credentials.  Keep
            # only the exception class at the control-plane boundary.
            return result_type(
                status="error",
                error_class="plugin",
                handle=handle,
                reason=f"runner {operation} failed ({exc.__class__.__name__})",
            )
        if not isinstance(outcome, RunnerOutcome):
            return result_type(
                status="error",
                error_class="plugin",
                handle=handle,
                reason="runner returned an invalid outcome type",
            )
        if outcome.external_handle_id is not None:
            metadata = dict(handle.metadata)
            metadata["runner_handle_id"] = outcome.external_handle_id
            handle = replace(handle, metadata=metadata)
        if outcome.submitted_at is not None and operation == "submit":
            handle = replace(handle, submitted_at=outcome.submitted_at)
        artifacts = outcome.artifact_references
        if operation == "collect" and any(
            artifact not in request.artifact_references for artifact in artifacts
        ):
            return result_type(
                status="error",
                error_class="validation",
                handle=handle,
                reason="runner returned an undeclared artifact reference",
            )
        include_handle = operation != "submit" or outcome.status in {
            "accepted",
            "pending",
            "running",
            "succeeded",
        }
        return result_type(
            status=outcome.status,
            error_class=outcome.error_class,
            handle=handle if include_handle else None,
            artifact_references=artifacts,
            data=outcome.data,
            reason=outcome.reason,
        )


__all__ = [
    "CommandPlan",
    "CommandPlanner",
    "CommandPlanningError",
    "HarnessRunner",
    "InjectedRunnerHarness",
    "RunnerInvocation",
    "RunnerOutcome",
]
