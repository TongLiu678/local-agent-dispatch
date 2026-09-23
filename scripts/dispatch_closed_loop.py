#!/usr/bin/env python3
"""Run a bounded, provider-free dispatch wave control loop.

This module closes the *control-plane* gap between an already reviewed packet
bundle and the monitor/replan boundary.  It deliberately does not capture a
new request, call the planner from free-form text, refresh a provider, open
SSH, or invoke a real adapter.

The default mode is ``dry-run``.  It validates an explicitly approved bridge
bundle and emits the wave that would be consumed, without creating a database
or touching the workspace.  ``fake-execute`` is a CI/demo-only mode: it
accepts only local ``command`` attempts whose provider is exactly ``fake`` and
whose executable is Python, runs them through the real SQLite controller, and
then feeds the durable snapshot through the real monitor and replan modules.
The next plan is always read-only; a replan never enqueues a new packet.

Approval is intentionally explicit.  A bundle may carry ``approved: true``
(or ``approval.approved: true``), or callers may pass ``--approved``/the
``approved=True`` API argument.  A bridge report in ``enqueue-ready`` mode
must also be ``ok``.  Raw packets are accepted only when the caller supplies
that explicit approval signal.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import shlex
import sys
from collections.abc import Mapping, Sequence
from typing import Any, Callable

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import continuity_controller as continuity  # noqa: E402
import controller_monitor_adapter  # noqa: E402
import dispatch_monitor  # noqa: E402
import replan_controller  # noqa: E402
from sqlite_controller import SQLiteController  # noqa: E402


SCHEMA_VERSION = 1
LOOP_TYPE = "local-agent-dispatch.closed_loop"
FAKE_EXECUTABLE_NAMES = {"python", "python3", "python3.10", "python3.11", "python3.12", "python3.13", "python3.14"}


class ClosedLoopError(ValueError):
    """Raised when a closed-loop input cannot be accepted safely."""


def now_utc() -> str:
    return dt.datetime.now(tz=dt.timezone.utc).isoformat()


def _canonical(payload: Any) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def digest(payload: Any) -> str:
    return hashlib.sha256(_canonical(payload)).hexdigest()


def load_json(path: pathlib.Path | str) -> Any:
    if str(path) == "-":
        return json.load(sys.stdin)
    return json.loads(pathlib.Path(path).expanduser().read_text(encoding="utf-8"))


def _approval_from_bundle(payload: Mapping[str, Any]) -> bool:
    approval = payload.get("approval")
    nested = approval.get("approved") if isinstance(approval, Mapping) else False
    return bool(payload.get("approved") is True or nested is True)


def _packet_rows(payload: Any, *, explicitly_approved: bool) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Extract packets and enforce the review/approval boundary.

    ``bridge_plan`` emits a report object, while tests and operators may keep
    a small approved envelope or a list of packets.  All forms are normalized
    here so the controller never has to guess whether a plan was reviewed.
    """

    metadata: dict[str, Any] = {}
    if isinstance(payload, Mapping):
        metadata = dict(payload)
        raw_packets = payload.get("packets")
        if raw_packets is None and isinstance(payload.get("packet"), Mapping):
            raw_packets = [payload["packet"]]
        if not isinstance(raw_packets, list):
            raise ClosedLoopError("approved bundle must contain a packets list")
        if payload.get("mode") is not None and str(payload.get("mode")) != "enqueue-ready":
            raise ClosedLoopError("closed loop accepts only enqueue-ready packet bundles")
        if payload.get("mode") == "enqueue-ready" and payload.get("ok") is not True:
            raise ClosedLoopError("enqueue-ready packet bundle is not marked ok")
        approval = explicitly_approved or _approval_from_bundle(payload)
    elif isinstance(payload, list):
        raw_packets = payload
        approval = bool(explicitly_approved)
    else:
        raise ClosedLoopError("approved input must be a packet list or bundle object")

    if not approval:
        raise ClosedLoopError(
            "explicit approval is required: set bundle.approved=true or pass --approved"
        )
    if not raw_packets:
        raise ClosedLoopError("approved packet bundle is empty")
    packets: list[dict[str, Any]] = []
    for index, raw in enumerate(raw_packets):
        if not isinstance(raw, Mapping):
            raise ClosedLoopError(f"packet {index} must be an object")
        packets.append(dict(raw))
    metadata["approval_verified"] = True
    return packets, metadata


def _validate_packets(packets: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Validate strict packets and reject ambiguous parallel write scopes."""

    result: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    seen_jobs: set[str] = set()
    seen_scopes: set[str] = set()
    for index, raw in enumerate(packets):
        packet = dict(raw)
        try:
            continuity.validate_task_packet(packet)
        except Exception as exc:
            raise ClosedLoopError(f"packet {index} validation failed: {exc}") from exc
        packet_id = str(packet.get("packet_id") or "")
        job_id = str(packet.get("job_id") or "")
        write_scope = str(packet.get("write_scope") or "")
        if packet_id in seen_ids:
            raise ClosedLoopError(f"duplicate packet_id: {packet_id}")
        if job_id in seen_jobs:
            raise ClosedLoopError(f"duplicate job_id: {job_id}")
        if write_scope in seen_scopes:
            raise ClosedLoopError(
                f"duplicate write_scope would make a parallel wave unsafe: {write_scope}"
            )
        seen_ids.add(packet_id)
        seen_jobs.add(job_id)
        seen_scopes.add(write_scope)
        top_model = str(packet.get("model") or "")
        top_variant = packet.get("variant")
        for attempt_index, raw_attempt in enumerate(packet.get("attempts") or []):
            attempt = dict(raw_attempt)
            if str(attempt.get("model") or "") != top_model:
                raise ClosedLoopError(
                    f"{job_id}: attempt {attempt_index} model does not match packet model"
                )
            if top_variant not in (None, "") and attempt.get("variant") not in (None, "", top_variant):
                raise ClosedLoopError(
                    f"{job_id}: attempt {attempt_index} variant does not match packet variant"
                )
        result.append(packet)
    return result


def _summary(packet: Mapping[str, Any]) -> dict[str, Any]:
    """Return a prompt/argv-free packet summary for audit output."""

    return {
        "packet_id": packet.get("packet_id"),
        "job_id": packet.get("job_id"),
        "pool_id": packet.get("pool_id"),
        "model": packet.get("model"),
        "variant": packet.get("variant"),
        "execution_host": packet.get("execution_host"),
        "workload_host": packet.get("workload_host"),
        "execution_transport": packet.get("execution_transport"),
        "write_scope": packet.get("write_scope"),
        "attempt_count": len(packet.get("attempts") or []),
        "packet_digest": digest(packet),
    }


_SENSITIVE_REPORT_KEYS = {"argv", "command", "prompt", "prompt_file", "validation_command"}


def _redact_report_value(value: Any) -> Any:
    """Drop prompt/command-bearing fields before a loop report is persisted."""

    if isinstance(value, Mapping):
        return {
            str(key): _redact_report_value(item)
            for key, item in value.items()
            if str(key) not in _SENSITIVE_REPORT_KEYS
        }
    if isinstance(value, list):
        return [_redact_report_value(item) for item in value]
    return value


def _enqueue_summary(row: Mapping[str, Any]) -> dict[str, Any]:
    """Keep SQLite enqueue evidence without copying packet payload/argv."""

    return {
        "job_id": row.get("job_id"),
        "status": row.get("status"),
        "attempt_count": row.get("attempt_count"),
        "state_revision": row.get("state_revision"),
        "packet_digest": digest(row.get("payload") or {}),
    }


def _snapshot_summary(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    """Project the durable snapshot into a prompt/argv-safe audit summary."""

    jobs = []
    for raw in snapshot.get("jobs") or []:
        if not isinstance(raw, Mapping):
            continue
        jobs.append(
            {
                "job_id": raw.get("job_id"),
                "status": raw.get("status"),
                "attempt_count": raw.get("attempt_count"),
                "claimed_by": raw.get("claimed_by"),
                "claim_fence": raw.get("claim_fence"),
                "error_class": raw.get("error_class"),
                "state_revision": raw.get("state_revision"),
                "updated_at_utc": raw.get("updated_at_utc"),
            }
        )
    attempts = []
    for raw in snapshot.get("attempts") or []:
        if not isinstance(raw, Mapping):
            continue
        attempts.append(
            {
                "attempt_id": raw.get("attempt_id"),
                "job_id": raw.get("job_id"),
                "attempt_no": raw.get("attempt_no"),
                "status": raw.get("status"),
                "error_class": raw.get("error_class"),
                "started_at_utc": raw.get("started_at_utc"),
                "finished_at_utc": raw.get("finished_at_utc"),
                "artifact_manifest": raw.get("artifact_manifest"),
                "validation": _redact_report_value(raw.get("validation")),
            }
        )
    events = []
    for raw in snapshot.get("events") or []:
        if not isinstance(raw, Mapping):
            continue
        events.append(
            {
                "event_seq": raw.get("event_seq"),
                "event_id": raw.get("event_id"),
                "event_type": raw.get("event_type"),
                "job_id": raw.get("job_id"),
                "attempt_id": raw.get("attempt_id"),
                "at_utc": raw.get("at_utc"),
            }
        )
    leases = []
    for raw in snapshot.get("leases") or []:
        if not isinstance(raw, Mapping):
            continue
        leases.append(
            {
                "scope": raw.get("scope"),
                "owner_id": raw.get("owner_id"),
                "fence_token": raw.get("fence_token"),
                "status": raw.get("status"),
                "heartbeat_at_utc": raw.get("heartbeat_at_utc"),
                "lease_expires_at_utc": raw.get("lease_expires_at_utc"),
            }
        )
    return {
        "schema_version": snapshot.get("schema_version"),
        "jobs": jobs,
        "attempts": attempts,
        "events": events,
        "leases": leases,
        "prompt_persisted": False,
        "argv_persisted": False,
    }


def _fake_attempt_allowed(packet: Mapping[str, Any]) -> tuple[bool, str | None]:
    """Allow only a local Python fake command in the provider-free executor."""

    for index, raw_attempt in enumerate(packet.get("attempts") or []):
        attempt = dict(raw_attempt)
        if str(attempt.get("provider") or "") != "fake":
            return False, f"attempt {index} provider must be exactly fake"
        if str(attempt.get("adapter") or "") != "command":
            return False, f"attempt {index} adapter must be command"
        if str(attempt.get("transport") or "") != "local":
            return False, f"attempt {index} transport must be local"
        argv = attempt.get("argv")
        if not isinstance(argv, list) or not argv:
            return False, f"attempt {index} has no argv"
        executable = pathlib.Path(str(argv[0])).name.lower()
        if executable not in FAKE_EXECUTABLE_NAMES:
            return False, f"attempt {index} executable is not an allow-listed Python fake"
        raw_attempt_validation = attempt.get("validation_argv") or attempt.get("validation_command")
        if raw_attempt_validation is not None:
            values = (
                list(raw_attempt_validation)
                if isinstance(raw_attempt_validation, list)
                else shlex.split(str(raw_attempt_validation))
            )
            if not values or pathlib.Path(str(values[0])).name.lower() not in FAKE_EXECUTABLE_NAMES:
                return False, f"attempt {index} validation executable is not an allow-listed Python fake"
    raw_validation = packet.get("validation_argv") or packet.get("validation_command")
    if raw_validation is not None:
        values = (
            list(raw_validation)
            if isinstance(raw_validation, list)
            else shlex.split(str(raw_validation))
        )
        if not values or pathlib.Path(str(values[0])).name.lower() not in FAKE_EXECUTABLE_NAMES:
            return False, "validation executable is not an allow-listed Python fake"
    return True, None


def _dry_run_report(
    packets: Sequence[Mapping[str, Any]],
    metadata: Mapping[str, Any],
    *,
    reason: str = "provider-free dry-run",
    quota_watch: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "report_type": LOOP_TYPE,
        "generated_at_utc": now_utc(),
        "ok": True,
        "mode": "dry-run",
        "read_only": True,
        "approved": True,
        "approval_verified": bool(metadata.get("approval_verified")),
        "intent_inferred": False,
        "provider_invocations": [],
        "model_prompts_sent": False,
        "enqueue_performed": False,
        "execution_performed": False,
        "side_effects": [],
        "source_digest": digest(packets),
        "approved_packets": [_summary(packet) for packet in packets],
        "quota_window_watch": quota_watch,
        "stages": [
            {"stage": "approval", "status": "accepted", "provider_contact": False},
            {"stage": "packet_validation", "status": "passed", "provider_contact": False},
            {"stage": "wave", "status": "preview", "reason": reason, "lane_count": len(packets)},
            {"stage": "monitor", "status": "not_run", "reason": "dry_run"},
            {"stage": "replan", "status": "not_run", "reason": "dry_run"},
        ],
        "next": "review the packet summaries, then invoke fake-execute or the explicit provider controller",
    }


def run_closed_loop(
    approved_packets: Any,
    *,
    workspace: pathlib.Path,
    db_path: pathlib.Path | None = None,
    approved: bool = False,
    mode: str = "dry-run",
    max_lanes: int = 1,
    monitor_duration_seconds: float = 0.0,
    monitor_interval_seconds: float = 0.1,
    monitor_stall_seconds: float = 120.0,
    planner_state: Mapping[str, Any] | None = None,
    jobs_payload: Any | None = None,
    plan: Mapping[str, Any] | None = None,
    quota_watch: Mapping[str, Any] | None = None,
    quota_snapshots: Sequence[Mapping[str, Any]] | None = None,
    quota_now_utc: str | None = None,
    quota_reserve_percent: float = 10.0,
    quota_poll_seconds: float = 30.0,
    unknown_quota_policy: str = "block",
    unknown_quota_pilot_percent: float = 5.0,
    owner_id: str | None = None,
    controller_factory: Callable[..., SQLiteController] = SQLiteController,
) -> dict[str, Any]:
    """Run one approved wave and a read-only monitor/replan cycle.

    ``mode=dry-run`` performs no filesystem mutation.  ``mode=fake-execute``
    is intentionally narrower than real execution and is suitable for CI or
    a local control-plane demo; every packet is checked for the fake command
    contract before SQLite is initialized.
    """

    if mode not in {"dry-run", "fake-execute"}:
        raise ClosedLoopError("mode must be dry-run or fake-execute")
    if isinstance(max_lanes, bool) or int(max_lanes) < 1:
        raise ClosedLoopError("max_lanes must be a positive integer")
    if monitor_duration_seconds < 0 or monitor_interval_seconds <= 0 or monitor_stall_seconds <= 0:
        raise ClosedLoopError("monitor durations must be non-negative and intervals/stall positive")
    if quota_watch is not None and quota_snapshots is not None:
        raise ClosedLoopError("provide quota_watch or quota_snapshots, not both")
    if quota_snapshots is not None:
        if not isinstance(quota_snapshots, Sequence) or isinstance(quota_snapshots, (str, bytes, bytearray)):
            raise ClosedLoopError("quota_snapshots must be a sequence of JSON objects")
        try:
            quota_watch = replan_controller.build_quota_window_watch(
                list(quota_snapshots),
                now_utc=quota_now_utc,
                reserve_percent=quota_reserve_percent,
                poll_seconds=quota_poll_seconds,
                unknown_quota_policy=unknown_quota_policy,
                unknown_pilot_percent=unknown_quota_pilot_percent,
            )
        except Exception as exc:  # noqa: BLE001 - surface a closed-loop input error
            raise ClosedLoopError(f"quota snapshot validation failed: {exc}") from exc
    packets, metadata = _packet_rows(approved_packets, explicitly_approved=approved)
    validated = _validate_packets(packets)
    if mode == "dry-run":
        return _dry_run_report(validated, metadata, quota_watch=quota_watch)
    if db_path is None:
        raise ClosedLoopError("fake-execute requires an explicit db_path")
    workspace = pathlib.Path(workspace).expanduser().resolve()
    if not workspace.is_dir():
        raise ClosedLoopError(f"workspace does not exist: {workspace}")
    for packet in validated:
        packet_workspace = pathlib.Path(str(packet.get("workspace") or "")).expanduser().resolve()
        try:
            packet_workspace.relative_to(workspace)
        except ValueError as exc:
            raise ClosedLoopError(
                f"{packet.get('job_id')}: fake-execute packet workspace escapes controller workspace"
            ) from exc
        allowed, reason = _fake_attempt_allowed(packet)
        if not allowed:
            raise ClosedLoopError(f"{packet.get('job_id')}: {reason}")

    controller = controller_factory(
        pathlib.Path(db_path).expanduser().resolve(),
        workspace=workspace,
        enforce_reservations=True,
    )
    enqueue_results: list[dict[str, Any]] = []
    with controller if hasattr(controller, "__enter__") else _null_context(controller) as active:
        for packet in validated:
            enqueue_results.append(_enqueue_summary(active.enqueue(packet)))
        execution = active.run(
            once=True,
            max_lanes=min(max(1, int(max_lanes)), len(validated)),
            owner_id=owner_id,
        )

    snapshot = execution.get("snapshot") if isinstance(execution, Mapping) else None
    if not isinstance(snapshot, Mapping):
        raise ClosedLoopError("SQLite execution did not return a durable snapshot")
    monitor_state = controller_monitor_adapter.build_monitor_state(snapshot)
    monitor_state["project_root"] = str(workspace)
    monitor_report = dispatch_monitor.monitor(
        monitor_state,
        duration_seconds=float(monitor_duration_seconds),
        interval_seconds=float(monitor_interval_seconds),
        stall_seconds=float(monitor_stall_seconds),
        refresh_codex=False,
        usage_timeout=2.0,
        refresh_compute=False,
        compute_timeout=2.0,
        stream=False,
    )
    # The monitor's durable adapter may retain validator diagnostics for local
    # debugging.  Keep that evidence in memory for replan classification but
    # remove argv/prompt-bearing fields from the persisted loop report.
    monitor_report = _redact_report_value(monitor_report)
    decision = replan_controller.build_replan_decision(
        monitor_report,
        jobs_payload=jobs_payload,
        plan=plan,
        # A replay caller may pin the quota observation clock.  Reuse it for
        # the schedule calculation so a reset is not turned into ``due_now``
        # merely because the test/worker process happens to run later.  Live
        # callers that omit this field continue to use the current UTC clock.
        generated_at_utc=quota_now_utc,
        quota_watch=quota_watch,
    )
    next_plan: dict[str, Any] | None = None
    if planner_state is not None and jobs_payload is not None:
        planned = replan_controller.plan_after_replan(
            decision,
            jobs_payload,
            planner_state,
            max_lanes=max(1, int(max_lanes)),
            horizon=8,
        )
        next_plan = planned.get("next_plan") if isinstance(planned, Mapping) else None

    statuses = [row.get("status") for row in execution.get("results", []) if isinstance(row, Mapping)]
    return {
        "schema_version": SCHEMA_VERSION,
        "report_type": LOOP_TYPE,
        "generated_at_utc": now_utc(),
        "ok": bool(execution.get("ok") and monitor_report.get("ok") and decision.get("ok")),
        "mode": "fake-execute",
        "read_only": False,
        "approved": True,
        "approval_verified": True,
        "intent_inferred": False,
        "provider_invocations": [],
        "model_prompts_sent": False,
        "enqueue_performed": True,
        "execution_performed": True,
        "side_effects": ["sqlite_enqueue", "provider_free_fake_execution"],
        "source_digest": digest(validated),
        "approved_packets": [_summary(packet) for packet in validated],
        "enqueue": {"count": len(enqueue_results), "jobs": enqueue_results},
        "execution": {
            "statuses": statuses,
            "results": _redact_report_value(execution.get("results") or []),
            "snapshot": _snapshot_summary(snapshot),
        },
        "monitor": monitor_report,
        "replan": decision,
        "next_plan": next_plan,
        "next_plan_read_only": True,
        "stages": [
            {"stage": "approval", "status": "accepted", "provider_contact": False},
            {"stage": "packet_validation", "status": "passed", "provider_contact": False},
            {"stage": "wave", "status": "executed", "lane_count": len(validated)},
            {"stage": "monitor", "status": "completed", "decision": monitor_report.get("decision")},
            {"stage": "replan", "status": "completed", "decision": decision.get("decision")},
            {
                "stage": "next_plan",
                "status": "generated_read_only" if next_plan is not None else "not_requested",
                "enqueue_performed": False,
            },
        ],
    }


class _null_context:
    """Context-manager shim for injected fake controllers in unit tests."""

    def __init__(self, value: Any) -> None:
        self.value = value

    def __enter__(self) -> Any:
        return self.value

    def __exit__(self, *_args: Any) -> None:
        close = getattr(self.value, "close", None)
        if callable(close):
            close()


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--approved-packets", required=True, help="approved bridge bundle JSON (or - for stdin)")
    parser.add_argument("--approved", action="store_true", help="explicitly attest that the packet bundle was reviewed")
    parser.add_argument("--mode", choices=("dry-run", "fake-execute"), default="dry-run")
    parser.add_argument("--db", help="SQLite database path required by fake-execute")
    parser.add_argument("--workspace", default=".")
    parser.add_argument("--max-lanes", type=int, default=1)
    parser.add_argument("--monitor-duration-seconds", type=float, default=0.0)
    parser.add_argument("--monitor-interval-seconds", type=float, default=0.1)
    parser.add_argument("--monitor-stall-seconds", type=float, default=120.0)
    parser.add_argument("--jobs", help="optional original planner jobs for a read-only next plan")
    parser.add_argument("--state", help="optional planner state for a read-only next plan")
    parser.add_argument("--plan", help="optional original dispatch plan for replan provenance")
    parser.add_argument(
        "--quota-snapshot",
        action="append",
        help="optional saved quota snapshot; repeatable and provider-free",
    )
    parser.add_argument("--quota-now-utc")
    parser.add_argument("--quota-reserve-percent", type=float, default=10.0)
    parser.add_argument("--quota-poll-seconds", type=float, default=30.0)
    parser.add_argument(
        "--unknown-quota-policy",
        choices=("block", "pilot"),
        default="block",
    )
    parser.add_argument("--unknown-quota-pilot-percent", type=float, default=5.0)
    parser.add_argument("--output")
    return parser.parse_args(argv)


def _write_output(payload: Mapping[str, Any], path: str | None) -> None:
    text = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if not path or path == "-":
        sys.stdout.write(text)
        return
    target = pathlib.Path(path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(target.suffix + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    temporary.replace(target)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        payload = load_json(args.approved_packets)
        jobs = load_json(args.jobs) if args.jobs else None
        state = load_json(args.state) if args.state else None
        plan = load_json(args.plan) if args.plan else None
        quota_snapshots = [load_json(path) for path in (args.quota_snapshot or [])]
        report = run_closed_loop(
            payload,
            workspace=pathlib.Path(args.workspace),
            db_path=pathlib.Path(args.db) if args.db else None,
            approved=bool(args.approved),
            mode=args.mode,
            max_lanes=args.max_lanes,
            monitor_duration_seconds=args.monitor_duration_seconds,
            monitor_interval_seconds=args.monitor_interval_seconds,
            monitor_stall_seconds=args.monitor_stall_seconds,
            planner_state=state if isinstance(state, Mapping) else None,
            jobs_payload=jobs,
            plan=plan if isinstance(plan, Mapping) else None,
            quota_snapshots=quota_snapshots or None,
            quota_now_utc=args.quota_now_utc,
            quota_reserve_percent=args.quota_reserve_percent,
            quota_poll_seconds=args.quota_poll_seconds,
            unknown_quota_policy=args.unknown_quota_policy,
            unknown_quota_pilot_percent=args.unknown_quota_pilot_percent,
        )
        _write_output(report, args.output)
        return 0 if report.get("ok") else 2
    except Exception as exc:
        report = {
            "schema_version": SCHEMA_VERSION,
            "report_type": LOOP_TYPE,
            "generated_at_utc": now_utc(),
            "ok": False,
            "mode": args.mode,
            "read_only": args.mode == "dry-run",
            "approved": False,
            "approval_verified": False,
            "intent_inferred": False,
            "provider_invocations": [],
            "model_prompts_sent": False,
            "error": f"{type(exc).__name__}: {exc}",
        }
        _write_output(report, args.output)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
