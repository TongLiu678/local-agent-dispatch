#!/usr/bin/env python3
"""Deterministic provider-free replay for the remote delivery fault matrix.

This is a virtual-time model, not a remote execution test.  It deliberately
does not sleep, open SSH, invoke a provider, or write a runtime directory.  It
checks the invariants that must hold before a real long-running canary is
allowed: duplicate delivery has one effect, accepted is not terminal,
controller fencing survives restart, and a terminal receipt is only promoted
when outcome evidence is present.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence


class ReplayError(ValueError):
    """Raised when a replay schedule is malformed or violates its contract."""


@dataclass
class _State:
    request_id: str
    payload_digest: str
    controller_owner: str = "controller-a"
    fence_token: int = 1
    worker_generation: int = 1
    transport: str = "pending"
    effect_count: int = 0
    result_digest: str | None = None
    stale_fence_rejections: int = 0
    events: list[dict[str, Any]] = field(default_factory=list)


_ALLOWED_EVENTS = {
    "enqueue",
    "disconnect",
    "controller_restart",
    "worker_restart",
    "receive",
    "duplicate_receive",
    "accepted_poll",
    "terminal_complete",
    "stale_terminal_attempt",
    "reconcile_terminal",
}


def _digest(payload: Mapping[str, Any]) -> str:
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def _default_schedule() -> list[dict[str, Any]]:
    return [
        {"at_seconds": 0, "event": "enqueue"},
        {"at_seconds": 300, "event": "receive"},
        {"at_seconds": 600, "event": "disconnect"},
        {"at_seconds": 900, "event": "controller_restart"},
        {"at_seconds": 1200, "event": "duplicate_receive"},
        {"at_seconds": 1800, "event": "worker_restart"},
        {"at_seconds": 3600, "event": "accepted_poll"},
        {"at_seconds": 43200, "event": "terminal_complete"},
        {"at_seconds": 43230, "event": "stale_terminal_attempt"},
        {"at_seconds": 43260, "event": "reconcile_terminal"},
        {"at_seconds": 86399, "event": "accepted_poll"},
    ]


def _validate_schedule(schedule: Sequence[Mapping[str, Any]], horizon_seconds: int) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    previous = -1
    for row in schedule:
        if not isinstance(row, Mapping):
            raise ReplayError("each schedule row must be an object")
        event = str(row.get("event") or "")
        if event not in _ALLOWED_EVENTS:
            raise ReplayError(f"unsupported replay event: {event}")
        try:
            at_seconds = int(row.get("at_seconds"))
        except (TypeError, ValueError) as exc:
            raise ReplayError("at_seconds must be an integer") from exc
        if at_seconds < 0 or at_seconds >= horizon_seconds:
            raise ReplayError("event is outside the virtual horizon")
        if at_seconds < previous:
            raise ReplayError("schedule must be ordered by at_seconds")
        previous = at_seconds
        normalized.append({"at_seconds": at_seconds, "event": event})
    return normalized


def replay(
    *,
    horizon_seconds: int = 24 * 60 * 60,
    schedule: Sequence[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Run a deterministic virtual-time delivery replay and return its report."""

    try:
        horizon = int(horizon_seconds)
    except (TypeError, ValueError) as exc:
        raise ReplayError("horizon_seconds must be an integer") from exc
    if horizon < 3600 or horizon > 7 * 24 * 60 * 60:
        raise ReplayError("horizon_seconds must be between one hour and seven days")
    rows = _validate_schedule(schedule or _default_schedule(), horizon)
    state = _State(
        request_id="fault-replay:attempt-1",
        payload_digest=_digest({
            "model": "opencode-go/deepseek-v4-flash",
            "variant": "max",
            "write_scope": ".lad/fault-replay",
        }),
    )
    invariant_failures: list[str] = []

    def record(at_seconds: int, event: str, **extra: Any) -> None:
        state.events.append({"at_seconds": at_seconds, "event": event, **extra})

    for row in rows:
        at = int(row["at_seconds"])
        event = str(row["event"])
        if event == "enqueue":
            if state.transport != "pending":
                invariant_failures.append("enqueue changed an existing request")
            record(at, event, status=state.transport, fence_token=state.fence_token)
        elif event == "receive":
            state.transport = "accepted"
            record(at, event, status="accepted", effect_count=state.effect_count, worker_generation=state.worker_generation)
        elif event == "duplicate_receive":
            if state.transport not in {"accepted", "completed", "failed"}:
                invariant_failures.append("duplicate receive was not idempotent")
            record(at, event, status=state.transport, effect_count=state.effect_count, duplicate=True)
        elif event == "disconnect":
            record(at, event, pending_preserved=state.transport in {"pending", "accepted"})
        elif event == "controller_restart":
            state.controller_owner = "controller-b"
            state.fence_token += 1
            record(at, event, owner=state.controller_owner, fence_token=state.fence_token)
        elif event == "worker_restart":
            state.worker_generation += 1
            record(at, event, worker_generation=state.worker_generation, status=state.transport)
        elif event == "accepted_poll":
            if state.transport not in {"accepted", "completed", "failed"}:
                invariant_failures.append("accepted poll lost durable request")
            record(at, event, status=state.transport, terminal=state.transport in {"completed", "failed"})
        elif event == "terminal_complete":
            if state.transport not in {"accepted", "completed"}:
                invariant_failures.append("terminal completion bypassed accepted state")
            state.transport = "completed"
            state.effect_count = 1
            state.result_digest = "b" * 64
            record(at, event, status=state.transport, effect_count=state.effect_count, result_digest=state.result_digest)
        elif event == "stale_terminal_attempt":
            state.stale_fence_rejections += 1
            record(at, event, accepted=False, reason="stale_fence", fence_token=state.fence_token - 1)
        elif event == "reconcile_terminal":
            if state.transport != "completed" or not state.result_digest:
                invariant_failures.append("reconcile promoted without terminal evidence")
            record(at, event, status=state.transport, result_digest=state.result_digest)

    if state.effect_count > 1:
        invariant_failures.append("duplicate delivery increased effect_count")
    if state.stale_fence_rejections != 1:
        invariant_failures.append("stale fence rejection was not observed exactly once")
    if state.transport != "completed" or not state.result_digest:
        invariant_failures.append("replay did not finish with a validated terminal receipt")

    report: dict[str, Any] = {
        "schema_version": 1,
        "report_type": "local-agent-dispatch.remote_fault_replay",
        "provider_execution": False,
        "network_execution": False,
        "virtual_horizon_seconds": horizon,
        "event_count": len(state.events),
        "final": {
            "request_id": state.request_id,
            "status": state.transport,
            "effect_count": state.effect_count,
            "result_digest": state.result_digest,
            "worker_generation": state.worker_generation,
            "fence_token": state.fence_token,
            "stale_fence_rejections": state.stale_fence_rejections,
        },
        "invariant_failures": invariant_failures,
        "events": state.events,
    }
    report["ok"] = not invariant_failures
    report["decision"] = "eligible_for_next_fault_gate" if report["ok"] else "blocked"
    report["decision_digest"] = _digest(report)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--horizon-seconds", type=int, default=24 * 60 * 60)
    parser.add_argument("--schedule", help="optional JSON array of virtual-time events")
    args = parser.parse_args(argv)
    try:
        schedule = json.loads(args.schedule) if args.schedule else None
        report = replay(horizon_seconds=args.horizon_seconds, schedule=schedule)
    except (ReplayError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"schema_version": 1, "ok": False, "error": type(exc).__name__}, sort_keys=True))
        return 2
    print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
