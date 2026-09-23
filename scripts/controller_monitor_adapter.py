#!/usr/bin/env python3
"""Project durable controller state into the monitor worker contract.

The SQLite controller deliberately keeps provider execution outside its short
transactions.  This adapter is the read-only seam that lets the periodic
monitor consume the same jobs/attempts/leases without requiring the
controller to persist prompt text or arbitrary argv.  Missing PID/log
telemetry is represented as ``unknown``; it is never inferred from a terminal
job row.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import sys
from typing import Any, Mapping


SCHEMA_VERSION = 1
_TERMINAL_RECEIPT_OBSERVATION_FIELDS = (
    "schema_version", "kind", "attempt_id", "state", "receipt_digest",
    "artifact_digest", "settlement_receipt_digest", "terminal_cause_kind",
    "terminal_cause_receipt_digest", "completed_at",
)


def iso_now() -> str:
    return dt.datetime.now(tz=dt.timezone.utc).isoformat()


def _parse_utc(value: Any) -> dt.datetime | None:
    if not value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def _lease_state(status: Any, expires_at: Any) -> str:
    """Classify persisted lease evidence without treating missing data as live."""
    status_text = str(status or "unknown").lower()
    expiry = _parse_utc(expires_at)
    if expiry is not None and expiry <= dt.datetime.now(tz=dt.timezone.utc):
        return "expired"
    if status_text == "active":
        return "active"
    if status_text in {"released", "terminal"}:
        return status_text
    return "unknown"


def _as_dict(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _attempt_spec(payload: Mapping[str, Any], row: Mapping[str, Any]) -> dict[str, Any]:
    attempts = payload.get("attempts")
    if not isinstance(attempts, list):
        return {}
    number = max(1, int(row.get("attempt_no") or 1))
    if number > len(attempts) or not isinstance(attempts[number - 1], Mapping):
        return {}
    return dict(attempts[number - 1])


def _latest_attempts(snapshot: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for raw in snapshot.get("attempts") or []:
        if not isinstance(raw, Mapping):
            continue
        job_id = str(raw.get("job_id") or "")
        if not job_id:
            continue
        previous = result.get(job_id)
        if previous is None or int(raw.get("attempt_no") or 0) >= int(previous.get("attempt_no") or 0):
            result[job_id] = dict(raw)
    return result


def _artifact_paths(payload: Mapping[str, Any], attempt: Mapping[str, Any]) -> list[str]:
    values = attempt.get("required_artifacts") or payload.get("required_artifacts") or []
    if isinstance(values, str):
        values = [values]
    return [str(value) for value in values if isinstance(value, (str, pathlib.PurePath))]


def _terminal_receipt_observation(attempt: Mapping[str, Any]) -> dict[str, Any] | None:
    """Project only safe terminal-receipt metadata into monitor state.

    The exporter may attach a receipt to an attempt result for a later
    snapshot.  Monitor state is an observation channel, not a verifier input:
    raw result/output, prompt, argv, and arbitrary receipt extensions are
    intentionally discarded here.
    """
    result = attempt.get("result")
    candidate = attempt.get("terminal_receipt")
    if not isinstance(candidate, Mapping) and isinstance(result, Mapping):
        candidate = result.get("terminal_receipt")
    if not isinstance(candidate, Mapping):
        return None
    safe = {
        key: candidate[key]
        for key in _TERMINAL_RECEIPT_OBSERVATION_FIELDS
        if key in candidate
    }
    if not isinstance(safe.get("receipt_digest"), str):
        return None
    return safe


def _worker(
    job_row: Mapping[str, Any],
    attempt_row: Mapping[str, Any] | None,
    *,
    controller_lease: Mapping[str, Any] | None = None,
    lane_index: int = 0,
    lane_count: int = 0,
) -> dict[str, Any]:
    payload = _as_dict(job_row.get("payload"))
    attempt_row = _as_dict(attempt_row)
    attempt = _attempt_spec(payload, attempt_row)
    merged = dict(payload)
    merged.update(attempt)
    job_id = str(job_row.get("job_id") or payload.get("job_id") or "")
    status = str(job_row.get("status") or "queued")
    row_status = str(attempt_row.get("status") or "")
    validation = attempt_row.get("validation")
    manifest = attempt_row.get("artifact_manifest")
    validation_ok = isinstance(validation, Mapping) and validation.get("ok") is True
    artifact_fresh = bool(
        isinstance(manifest, list)
        and manifest
        and all(item.get("exists") and item.get("sha256") for item in manifest if isinstance(item, Mapping))
    )
    if status == "running" or row_status == "running":
        observed_status = "unknown"
        observation_reason = "controller_state_has_no_pid_telemetry"
    elif status == "completed":
        observed_status = "completed"
        observation_reason = "durable_controller_terminal_state"
    elif status in {"failed", "retry"}:
        observed_status = "failed"
        observation_reason = "durable_controller_terminal_state"
    else:
        observed_status = status if status in {"queued", "deferred"} else "unknown"
        observation_reason = "controller_state_not_running"

    owner_id = attempt_row.get("owner_id") or job_row.get("claimed_by")
    fence_token = attempt_row.get("fence_token") or job_row.get("claim_fence")
    expires_at = attempt_row.get("lease_expires_at_utc") or job_row.get("lease_expires_at_utc")
    attempt_lease_state = _lease_state(
        "active" if row_status == "running" or status == "running" else "terminal",
        expires_at,
    )
    controller_lease = _as_dict(controller_lease)
    controller_lease_state = _lease_state(
        controller_lease.get("status"), controller_lease.get("lease_expires_at_utc")
    )
    heartbeat_at = controller_lease.get("heartbeat_at_utc")
    # ``jobs.updated_at_utc`` is updated by the transactional heartbeat.  It
    # is intentionally retained as a separate, weaker signal: it does not
    # prove a PID is alive and is never converted into ``healthy`` by itself.
    heartbeat_evidence = {
        "status": "observed" if heartbeat_at else "unknown",
        "controller_heartbeat_at_utc": heartbeat_at,
        "job_updated_at_utc": job_row.get("updated_at_utc"),
        "source": "sqlite.leases.heartbeat_at_utc"
        if heartbeat_at
        else "sqlite.jobs.updated_at_utc_only",
    }
    lease_evidence = {
        "status": attempt_lease_state,
        "owner_id": owner_id,
        "fence_token": fence_token,
        "expires_at_utc": expires_at,
        "source": "sqlite.attempts+jobs",
        "controller_scope": controller_lease.get("scope", "controller"),
        "controller_status": controller_lease.get("status"),
        "controller_lease_state": controller_lease_state,
        "controller_heartbeat_at_utc": heartbeat_at,
    }

    # Explicit allow-list: do not copy prompt, argv, command, or arbitrary
    # packet fields into the monitor state.
    worker: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "worker_id": job_id,
        "job_id": job_id,
        "attempt_id": attempt_row.get("attempt_id"),
        "attempt_no": attempt_row.get("attempt_no"),
        "lane_id": str(merged.get("lane_id") or job_id),
        "lane_index": int(lane_index),
        "lane_count": int(lane_count),
        "pool_id": merged.get("pool_id"),
        "provider": merged.get("provider"),
        "model": merged.get("model"),
        "variant": merged.get("variant"),
        "execution_host": merged.get("execution_host") or merged.get("host_id") or "local_system",
        "workload_host": merged.get("workload_host") or merged.get("execution_host") or merged.get("host_id") or "local_system",
        "status": observed_status,
        "controller_status": status,
        "attempt_status": row_status or None,
        "observation_reason": observation_reason,
        "error_class": job_row.get("error_class") or attempt_row.get("error_class"),
        "validation": validation,
        "validation_ok": validation_ok,
        "artifact_manifest": manifest,
        "artifact_freshness_verified": artifact_fresh,
        "required_paths": _artifact_paths(payload, attempt),
        "runtime_state_path": merged.get("runtime_state_path"),
        "log_path": merged.get("log_path") or merged.get("monitor_log_path"),
        "pid_path": merged.get("pid_path") or merged.get("monitor_pid_path"),
        "terminal_receipt": _terminal_receipt_observation(attempt_row),
        "lease": lease_evidence,
        "heartbeat": heartbeat_evidence,
    }
    return worker


def build_monitor_state(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    """Return a prompt-safe monitor state from a SQLite snapshot."""

    if not isinstance(snapshot, Mapping):
        raise ValueError("SQLite snapshot must be an object")
    attempts = _latest_attempts(snapshot)
    raw_leases = [dict(row) for row in snapshot.get("leases") or [] if isinstance(row, Mapping)]
    controller_lease = next(
        (row for row in raw_leases if str(row.get("scope") or "") == "controller"),
        raw_leases[0] if raw_leases else None,
    )
    job_rows = [row for row in snapshot.get("jobs") or [] if isinstance(row, Mapping)]
    workers = [
        _worker(
            row,
            attempts.get(str(row.get("job_id") or "")),
            controller_lease=controller_lease,
            lane_index=index,
            lane_count=len(job_rows),
        )
        for index, row in enumerate(job_rows)
    ]
    active_lanes = [
        {
            "lane_id": worker.get("lane_id"),
            "lane_index": worker.get("lane_index"),
            "job_id": worker.get("job_id"),
            "attempt_id": worker.get("attempt_id"),
            "status": worker.get("status"),
            "lease": worker.get("lease"),
            "heartbeat": worker.get("heartbeat"),
        }
        for worker in workers
        if worker.get("controller_status") == "running"
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "state_type": "local-agent-dispatch.monitor_state",
        "backend": "sqlite",
        "generated_at_utc": iso_now(),
        "workers": workers,
        "lane_count": len(workers),
        "active_lane_count": len(active_lanes),
        "lanes": active_lanes,
        "controller_leases": raw_leases,
        "source": {
            "schema_version": snapshot.get("schema_version"),
            "prompt_persisted": False,
            "argv_persisted": False,
            "telemetry_boundary": "pid_and_log_paths_only_when_explicitly_recorded",
        },
    }


def load_snapshot(db_path: str) -> dict[str, Any]:
    script_dir = pathlib.Path(__file__).resolve().parent
    if str(script_dir) not in sys.path:
        sys.path.insert(0, str(script_dir))
    from sqlite_store import SQLiteStore

    with SQLiteStore(pathlib.Path(db_path).expanduser()) as store:
        return store.snapshot()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--db")
    source.add_argument("--snapshot")
    parser.add_argument("--output", default="-")
    args = parser.parse_args(argv)
    snapshot = load_snapshot(args.db) if args.db else json.loads(pathlib.Path(args.snapshot).read_text(encoding="utf-8"))
    payload = build_monitor_state(snapshot)
    text = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    if args.output == "-":
        sys.stdout.write(text)
    else:
        target = pathlib.Path(args.output).expanduser()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
