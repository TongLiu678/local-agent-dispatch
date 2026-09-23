"""Conservative Cursor Agent command planner and AgentHarness adapter."""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from ...plugins import (
    CapabilityResult,
    Evidence,
    LifecycleRequest,
    PluginDescriptor,
)
from .base import (
    CommandPlan,
    CommandPlanningError,
    HarnessRunner,
    InjectedRunnerHarness,
    RunnerInvocation,
    RunnerOutcome,
)


_FORBIDDEN_PRIVILEGE_OPTIONS = (
    "cursor_trust_workspace",
    "cursor_force_commands",
    "cursor_yolo",
    "cursor_approve_mcps",
)
_FORBIDDEN_ARGV = frozenset(("--trust", "--force", "-f", "--yolo"))


def _models_from_evidence(evidence: Evidence) -> tuple[str, ...] | None:
    raw = evidence.data.get("models")
    if isinstance(raw, (str, bytes)) or not isinstance(raw, Sequence):
        return None
    models = tuple(raw)
    if any(
        not isinstance(model, str) or not model or model != model.strip()
        for model in models
    ):
        return None
    # Preserve the provider's exact spellings and order while dropping exact
    # duplicate rows from a persisted probe.
    return tuple(dict.fromkeys(models))


def _authenticated(evidence: Evidence) -> bool:
    data = evidence.data
    return (
        data.get("authenticated") is True
        or data.get("isAuthenticated") is True
        or data.get("auth_state") == "authenticated"
    )


def _cursor_capability_snapshot(
    auth_evidence: Evidence,
    catalog_evidence: Evidence,
) -> tuple[CapabilityResult, tuple[str, ...]]:
    """Turn already-collected evidence into a fail-closed inert snapshot."""

    if auth_evidence.status != "ready":
        error_class = (
            "unknown" if auth_evidence.status == "unknown" else "authentication"
        )
        return (
            CapabilityResult(
                status=auth_evidence.status,
                error_class=error_class,
                reason="Cursor authentication evidence is not ready",
                source="injected-evidence",
            ),
            (),
        )
    if not _authenticated(auth_evidence):
        return (
            CapabilityResult(
                status="blocked",
                error_class="authentication",
                reason="Cursor authentication is not explicitly proven",
                source="injected-evidence",
            ),
            (),
        )
    if catalog_evidence.status != "ready":
        error_class = "unknown" if catalog_evidence.status == "unknown" else "capability"
        return (
            CapabilityResult(
                status=catalog_evidence.status,
                error_class=error_class,
                reason="Cursor model catalog evidence is not ready",
                source="injected-evidence",
            ),
            (),
        )
    models = _models_from_evidence(catalog_evidence)
    if models is None:
        return (
            CapabilityResult(
                status="unknown",
                error_class="unknown",
                reason="Cursor catalog evidence has no valid exact-model list",
                source="injected-evidence",
            ),
            (),
        )
    if not models:
        return (
            CapabilityResult(
                status="blocked",
                error_class="capability",
                reason="Cursor catalog has no selectable exact model",
                source="injected-evidence",
            ),
            (),
        )
    capabilities = CursorAgentHarness.descriptor.capabilities
    return (
        CapabilityResult(
            status="ready",
            error_class="none",
            capabilities=capabilities,
            data={
                "models": models,
                "sandbox": "required",
                "prompt_transport": "authorized-argv",
                "write_scope": "explicit",
            },
            source="injected-evidence",
        ),
        models,
    )


class CursorCommandPlanner:
    """Pure fail-closed planner for the standalone ``cursor-agent`` CLI.

    Cursor print mode takes the prompt as a positional argv value and exposes
    write and shell tools.  Planning therefore requires explicit disclosure
    authorization, an exact live-catalog model, sandbox mode, and a confined
    write root.  Privilege flags are unsupported rather than configurable.
    """

    def __init__(
        self,
        *,
        catalog_models: Sequence[str],
        executable: str = "cursor-agent",
    ) -> None:
        if not isinstance(executable, str) or not executable.strip():
            raise ValueError("Cursor executable must be a non-empty string")
        executable_path = Path(executable).expanduser()
        if executable_path.name != "cursor-agent":
            raise ValueError("Cursor executable must name the standalone cursor-agent CLI")
        if not executable_path.is_absolute() and executable != "cursor-agent":
            raise ValueError("Cursor executable must be cursor-agent or an absolute path")
        models = tuple(catalog_models)
        if any(
            not isinstance(model, str) or not model or model != model.strip()
            for model in models
        ):
            raise ValueError("catalog_models must contain exact non-empty model IDs")
        self._models = frozenset(models)
        self._executable = str(executable_path)

    def __call__(self, request: LifecycleRequest) -> CommandPlan:
        options = request.options
        model = options.get("model")
        if not isinstance(model, str) or not model:
            raise CommandPlanningError(
                "Cursor requires an exact model ID",
                error_class="capability",
            )
        if model not in self._models:
            raise CommandPlanningError(
                "Cursor model is absent from the injected exact catalog",
                error_class="capability",
            )
        prompt = options.get("prompt")
        if not isinstance(prompt, str) or not prompt.strip():
            raise CommandPlanningError("Cursor requires non-empty prompt text")
        if options.get("cursor_prompt_argv_authorized") is not True:
            raise CommandPlanningError(
                "Cursor prompt argv exposure requires explicit authorization",
                error_class="authorization",
            )
        if options.get("cursor_sandbox", "enabled") != "enabled":
            raise CommandPlanningError(
                "Cursor sandbox must remain enabled",
                error_class="authorization",
            )
        for key in _FORBIDDEN_PRIVILEGE_OPTIONS:
            if options.get(key) not in (None, False):
                raise CommandPlanningError(
                    f"Cursor reference adapter forbids privilege option {key}",
                    error_class="authorization",
                )
        mode = options.get("cursor_mode")
        if mode not in (None, "plan", "ask"):
            raise CommandPlanningError("Cursor mode must be plan, ask, or omitted")

        workspace, write_scope = self._confined_paths(options)
        # Cursor's sandbox is workspace-scoped.  Use the narrower declared
        # write root as both cwd and --workspace rather than granting the
        # entire containing repository by accident.
        argv = [
            self._executable,
            "--print",
            "--workspace",
            str(write_scope),
            "--model",
            model,
            "--sandbox",
            "enabled",
        ]
        if mode is not None:
            argv.extend(("--mode", mode))
        argv.extend(("--", prompt))
        option_argv = argv[: argv.index("--")]
        if any(value in _FORBIDDEN_ARGV for value in option_argv):
            raise AssertionError("Cursor planner constructed forbidden privilege argv")
        prompt_index = len(argv) - 1
        redacted = list(argv)
        redacted[prompt_index] = f"<redacted cursor prompt {len(prompt)} chars>"
        return CommandPlan(
            argv=tuple(argv),
            cwd=str(write_scope),
            redacted_argv=tuple(redacted),
            sensitive_argv_indices=(prompt_index,),
            metadata={
                "adapter": "cursor-agent",
                "model": model,
                "sandbox": "enabled",
                "outer_workspace": str(workspace),
                "write_scope": str(write_scope),
                "mode": mode,
                "prompt_in_argv": True,
            },
        )

    @staticmethod
    def _confined_paths(options: Mapping[str, Any]) -> tuple[Path, Path]:
        raw_workspace = options.get("workspace")
        if not isinstance(raw_workspace, str) or not raw_workspace.strip():
            raise CommandPlanningError("Cursor requires an explicit workspace")
        workspace_input = Path(raw_workspace).expanduser()
        if not workspace_input.is_absolute():
            raise CommandPlanningError("Cursor workspace must be absolute")
        workspace = workspace_input.resolve(strict=False)

        raw_scope = options.get("write_scope")
        if not isinstance(raw_scope, str) or not raw_scope.strip():
            raise CommandPlanningError("Cursor requires an explicit bounded write_scope")
        scope_input = Path(raw_scope).expanduser()
        if not scope_input.is_absolute():
            scope_input = workspace / scope_input
        write_scope = scope_input.resolve(strict=False)
        try:
            common = Path(os.path.commonpath((str(workspace), str(write_scope))))
        except ValueError as exc:
            raise CommandPlanningError(
                "Cursor write_scope must share the workspace filesystem"
            ) from exc
        if common != workspace:
            raise CommandPlanningError("Cursor write_scope escapes the workspace")
        if write_scope == Path(write_scope.anchor):
            raise CommandPlanningError("Cursor write_scope cannot be a filesystem root")
        return workspace, write_scope


class CursorAgentHarness(InjectedRunnerHarness):
    """Cursor Agent lifecycle using injected auth/catalog evidence and runner."""

    descriptor = PluginDescriptor(
        "cursor-agent-reference",
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
            "exact-model-catalog",
            "sandbox-required",
            "bounded-write-scope",
            "authorized-argv-prompt",
        ),
        metadata={"provider_calls_on_registration": False},
    )

    def __init__(
        self,
        *,
        runner: HarnessRunner,
        auth_evidence: Evidence,
        catalog_evidence: Evidence,
        executable: str = "cursor-agent",
    ) -> None:
        if not isinstance(auth_evidence, Evidence):
            raise TypeError("auth_evidence must be Evidence")
        if not isinstance(catalog_evidence, Evidence):
            raise TypeError("catalog_evidence must be Evidence")
        snapshot, models = _cursor_capability_snapshot(auth_evidence, catalog_evidence)
        planner = CursorCommandPlanner(catalog_models=models, executable=executable)
        super().__init__(
            runner=runner,
            capability_snapshot=snapshot,
            planner=planner,
        )


__all__ = ["CursorAgentHarness", "CursorCommandPlanner"]
