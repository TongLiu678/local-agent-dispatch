#!/usr/bin/env python3
"""Long-lived, fail-closed loop for a bounded durable supervisor.

This command is a control-plane runner, not a provider launcher.  It polls
already-approved segments, appends a small fsync'd JSONL record for every
state transition, and exits in a visibly blocked state after repeated
unrecoverable errors.  A scheduler (PBS/systemd) should supervise this
process; the SQLite lease and segment receipts make restart safe.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import signal
import sys
import threading
import time
from collections.abc import Callable, Mapping
from typing import Any

SCRIPT_ROOT = pathlib.Path(__file__).resolve().parent
if str(SCRIPT_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPT_ROOT))

from durable_controller import DurableControllerError, DurableControllerSupervisor  # noqa: E402
from pbs_controller_bridge import PBSBridgeError, PBSWorkerClient  # noqa: E402
from sqlite_segment_controller import SQLiteSegmentControllerAdapter  # noqa: E402
from sqlite_store import SQLiteStore, StoreError  # noqa: E402


class DurableRunLoopError(ValueError):
    """Raised when a loop configuration would be unsafe or ambiguous."""


class _NoopPBS:
    """Provider-free PBS seam used when the loop is not executing remotely.

    A dry-run controller must not require a private PBS inventory: the
    inventory is an execution-plane dependency and may be intentionally absent
    on a controller-only host.  The supervisor never calls these methods while
    ``execute`` is false, but keeping a bounded adapter makes that boundary
    explicit and protects future callers from accidentally opening SSH.
    """

    def submit(self, **_: Any) -> dict[str, Any]:
        return {
            "status": "pending",
            "pbs_job_id": "dry-run",
            "provider_execution": False,
            "network_execution": False,
        }

    def status(self, **_: Any) -> dict[str, Any]:
        return {
            "status": "pending",
            "pbs_job_id": "dry-run",
            "provider_execution": False,
            "network_execution": False,
        }


def _now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _compact_record(record: Mapping[str, Any], *, max_bytes: int) -> tuple[dict[str, Any], bool]:
    """Keep the monitor ledger bounded without discarding its identity.

    The SQLite event/receipt rows remain authoritative.  The JSONL file is a
    restart/debug breadcrumb, so a large reconciliation report must not make
    a 24-hour run consume unbounded disk.  When the serialized record exceeds
    the configured ceiling, retain stable top-level fields, a small report
    projection, and a digest of the omitted report.
    """

    encoded = json.dumps(dict(record), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(encoded) <= max_bytes:
        return dict(record), False
    compact: dict[str, Any] = {
        key: record.get(key)
        for key in ("schema_version", "record_type", "observed_at_utc", "run_id", "kind")
        if key in record
    }
    for key in (
        "loop_elapsed_seconds", "loop_remaining_seconds", "segment_remaining_seconds", "progress_clock",
    ):
        if key in record:
            compact[key] = record[key]
    report = record.get("report")
    if isinstance(report, Mapping):
        summary_keys = (
            "action", "status", "reason", "segment_id", "sequence", "remaining_seconds",
            "loop_elapsed_seconds", "loop_remaining_seconds", "segment_remaining_seconds",
            "progress_clock",
            "checkpoint_flushed", "provider_execution", "network_execution",
        )
        compact["report_summary"] = {
            key: report.get(key) for key in summary_keys if key in report
        }
    compact["report_digest"] = "sha256:" + hashlib.sha256(encoded).hexdigest()
    compact["record_truncated"] = True
    # A pathological set of stable fields should still not violate the cap.
    compact_encoded = json.dumps(compact, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(compact_encoded) > max_bytes:
        compact = {
            "schema_version": record.get("schema_version", 1),
            "record_type": record.get("record_type"),
            "observed_at_utc": record.get("observed_at_utc"),
            "run_id": record.get("run_id"),
            "kind": record.get("kind"),
            "report_digest": "sha256:" + hashlib.sha256(encoded).hexdigest(),
            "record_truncated": True,
        }
    return compact, True


def _append_record(
    path: pathlib.Path | None,
    record: Mapping[str, Any],
    *,
    max_bytes: int,
) -> bool:
    """Append one bounded record and fsync it before returning.

    Returns whether the record was compacted before writing.
    """

    if path is None:
        return False
    compact, truncated = _compact_record(record, max_bytes=max_bytes)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(compact, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
        handle.flush()
        import os

        os.fsync(handle.fileno())
    return truncated


def _validate_positive(value: Any, field: str, *, maximum: float) -> float:
    if isinstance(value, bool):
        raise DurableRunLoopError(f"{field} must be positive")
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise DurableRunLoopError(f"{field} must be positive") from exc
    if parsed <= 0 or parsed > maximum:
        raise DurableRunLoopError(f"{field} is outside the supported range")
    return parsed


def run_loop(
    supervisor: Any,
    *,
    poll_interval_seconds: float = 30.0,
    max_runtime_seconds: float | None = 24 * 60 * 60,
    max_consecutive_errors: int = 3,
    max_ticks: int | None = None,
    event_log: pathlib.Path | str | None = None,
    max_record_bytes: int = 131_072,
    sleep_fn: Callable[[float], Any] = time.sleep,
    monotonic_fn: Callable[[], float] = time.monotonic,
    stop_event: threading.Event | None = None,
) -> dict[str, Any]:
    """Drive a supervisor without retaining the full event stream in RAM."""

    interval = _validate_positive(poll_interval_seconds, "poll_interval_seconds", maximum=86_400)
    if max_runtime_seconds is not None:
        max_runtime = _validate_positive(max_runtime_seconds, "max_runtime_seconds", maximum=7 * 24 * 60 * 60)
    else:
        max_runtime = None
    if isinstance(max_consecutive_errors, bool) or not isinstance(max_consecutive_errors, int) or not 1 <= max_consecutive_errors <= 100:
        raise DurableRunLoopError("max_consecutive_errors must be between 1 and 100")
    if max_ticks is not None and (isinstance(max_ticks, bool) or not isinstance(max_ticks, int) or max_ticks < 1):
        raise DurableRunLoopError("max_ticks must be a positive integer")
    if isinstance(max_record_bytes, bool) or not isinstance(max_record_bytes, int) or not 4_096 <= max_record_bytes <= 8 * 1024 * 1024:
        raise DurableRunLoopError("max_record_bytes must be between 4096 and 8388608")
    log_path = pathlib.Path(event_log).expanduser() if event_log else None
    started_monotonic = monotonic_fn()
    ticks = 0
    errors = 0
    truncated_records = 0
    last_action: str | None = None
    terminal_reason: str | None = None

    def progress_payload() -> dict[str, Any]:
        """Expose whole-loop progress without confusing it with segment time.

        ``DurableControllerSupervisor`` reports ``remaining_seconds`` for the
        current wall-clock segment.  The outer runner has a separate monotonic
        budget (and survives node clock skew), so every monitor record carries
        both views under unambiguous names.  The original report field is
        retained for compatibility and mirrored as ``segment_remaining_seconds``.
        """

        elapsed = max(0.0, float(monotonic_fn() - started_monotonic))
        progress: dict[str, Any] = {
            "loop_elapsed_seconds": round(elapsed, 3),
            "loop_remaining_seconds": (
                round(max(0.0, max_runtime - elapsed), 3)
                if max_runtime is not None
                else None
            ),
            "progress_clock": "monotonic_runner",
        }
        return progress

    def record(kind: str, **payload: Any) -> None:
        nonlocal truncated_records
        progress = progress_payload()
        report = payload.get("report")
        if isinstance(report, Mapping) and "remaining_seconds" in report:
            progress["segment_remaining_seconds"] = report.get("remaining_seconds")
        progress.update({key: value for key, value in payload.items() if key in {
            "loop_elapsed_seconds", "loop_remaining_seconds", "segment_remaining_seconds", "progress_clock"
        }})
        truncated_records += int(_append_record(
            log_path,
            {
                "schema_version": 1,
                "record_type": "local-agent-dispatch.continuous-loop",
                "observed_at_utc": _now_utc(),
                "run_id": getattr(supervisor, "run_id", None),
                "kind": kind,
                **progress,
                **payload,
            },
            max_bytes=max_record_bytes,
        ))

    try:
        initial = supervisor.start()
        last_action = str(initial.get("action") or "start") if isinstance(initial, Mapping) else "start"
        record("start", report=initial)
    except Exception as exc:  # noqa: BLE001 - receipt the failure before exit
        record("start_error", error_class=type(exc).__name__)
        return {
            "schema_version": 1,
            "ok": False,
            "status": "blocked",
            "reason": "start_error",
            "error_class": type(exc).__name__,
            "ticks": 0,
            "errors": 1,
            "truncated_records": truncated_records,
            "max_record_bytes": max_record_bytes,
            "provider_execution": False,
            "network_execution": False,
        }

    while True:
        state = str(getattr(supervisor, "state", "running"))
        if state in {"finished", "stopped", "blocked"}:
            terminal_reason = state
            break
        if stop_event is not None and stop_event.is_set():
            terminal_reason = "stop_requested"
            try:
                report = supervisor.stop("stop_requested")
                record("stop", report=report)
            except Exception as exc:  # noqa: BLE001
                errors += 1
                record("stop_error", error_class=type(exc).__name__)
            break
        if max_ticks is not None and ticks >= max_ticks:
            terminal_reason = "max_ticks_reached"
            record("limit", reason=terminal_reason, ticks=ticks)
            break
        if max_runtime is not None and monotonic_fn() - started_monotonic >= max_runtime:
            terminal_reason = "max_runtime_reached"
            try:
                report = supervisor.stop(terminal_reason)
                record("stop", report=report)
            except Exception as exc:  # noqa: BLE001
                errors += 1
                record("stop_error", error_class=type(exc).__name__)
            break

        sleep_fn(interval)
        try:
            report = supervisor.tick()
            ticks += 1
            errors = 0
            last_action = str(report.get("action") or "tick") if isinstance(report, Mapping) else "tick"
            record("tick", tick=ticks, report=report)
            if isinstance(report, Mapping) and report.get("action") == "blocked_checkpoint":
                terminal_reason = "blocked_checkpoint"
                break
        except Exception as exc:  # noqa: BLE001 - retry is bounded and recorded
            errors += 1
            record("tick_error", tick=ticks, consecutive_errors=errors, error_class=type(exc).__name__)
            if errors >= max_consecutive_errors:
                terminal_reason = "consecutive_errors"
                break

    state = str(getattr(supervisor, "state", terminal_reason or "unknown"))
    if terminal_reason == "consecutive_errors" and state not in {"finished", "stopped"}:
        state = "blocked"
    elif terminal_reason == "max_ticks_reached" and state not in {"finished", "stopped", "blocked"}:
        state = "paused"
    ok = state == "finished" and not errors
    final_progress = progress_payload()
    return {
        "schema_version": 1,
        "ok": ok,
        "status": state,
        "reason": terminal_reason,
        "run_id": getattr(supervisor, "run_id", None),
        "ticks": ticks,
        "errors": errors,
        "truncated_records": truncated_records,
        "max_record_bytes": max_record_bytes,
        "last_action": last_action,
        "event_log": str(log_path) if log_path else None,
        "provider_execution": False,
        "network_execution": False,
        **final_progress,
    }


def _load_object(path: pathlib.Path | str) -> dict[str, Any]:
    try:
        value = json.loads(pathlib.Path(path).expanduser().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DurableRunLoopError(f"cannot read JSON object: {path}") from exc
    if not isinstance(value, Mapping):
        raise DurableRunLoopError(f"JSON object required: {path}")
    return dict(value)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--capsule", required=True)
    parser.add_argument("--inventory", required=True)
    parser.add_argument("--run-root", required=True)
    parser.add_argument("--owner-id")
    parser.add_argument("--poll-seconds", type=float, default=30.0)
    parser.add_argument("--max-runtime-seconds", type=float, default=24 * 60 * 60)
    parser.add_argument("--max-consecutive-errors", type=int, default=3)
    parser.add_argument("--max-ticks", type=int)
    parser.add_argument(
        "--max-record-bytes", type=int, default=131_072,
        help="maximum serialized bytes per fsync'd monitor JSONL record",
    )
    parser.add_argument("--execute", action="store_true", help="open the validated PBS SSH leg")
    args = parser.parse_args(argv)
    owner = args.owner_id or f"durable-loop-{pathlib.Path(args.db).stem}"
    stop_event = threading.Event()
    previous_handlers: dict[int, Any] = {}

    def request_stop(_signum: int, _frame: Any) -> None:
        stop_event.set()

    for signum in (signal.SIGINT, signal.SIGTERM):
        previous_handlers[signum] = signal.getsignal(signum)
        signal.signal(signum, request_stop)
    try:
        manifest = _load_object(args.manifest)
        capsule = _load_object(args.capsule)
        run_root = pathlib.Path(args.run_root).expanduser()
        event_log = run_root / "monitor" / "continuous-loop.jsonl"
        with SQLiteStore(pathlib.Path(args.db).expanduser()) as store:
            with store.controller_lease(
                owner,
                ttl_seconds=max(30, min(900, int(args.poll_seconds * 3))),
                metadata={"runner": "durable_run_loop", "run_id": manifest.get("run_id")},
            ) as lease:
                adapter = SQLiteSegmentControllerAdapter(
                    store,
                    owner_id=owner,
                    fence_token=int(lease["fence_token"]),
                )
                # The private PBS inventory belongs to the execution plane.
                # Provider-free/dry-run continuity must remain usable on a
                # controller-only host whose inventory intentionally has no
                # PBS stanza; only an explicit --execute may parse it.
                client = PBSWorkerClient(args.inventory) if args.execute else _NoopPBS()
                supervisor = DurableControllerSupervisor(
                    controller=adapter,
                    manifest=manifest,
                    capsule=capsule,
                    pbs_client=client,
                    clock=lambda: dt.datetime.now(dt.timezone.utc),
                    run_root=run_root,
                    owner_id=owner,
                    execute=bool(args.execute),
                )
                report = run_loop(
                    supervisor,
                    poll_interval_seconds=args.poll_seconds,
                    max_runtime_seconds=args.max_runtime_seconds,
                    max_consecutive_errors=args.max_consecutive_errors,
                    max_ticks=args.max_ticks,
                    max_record_bytes=args.max_record_bytes,
                    event_log=event_log,
                    stop_event=stop_event,
                )
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if report.get("ok") else 1
    except (DurableRunLoopError, DurableControllerError, PBSBridgeError, StoreError, OSError, ValueError, TypeError) as exc:
        print(json.dumps({"schema_version": 1, "ok": False, "status": "blocked", "error": type(exc).__name__}, sort_keys=True))
        return 2
    finally:
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)


__all__ = ["DurableRunLoopError", "run_loop"]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
