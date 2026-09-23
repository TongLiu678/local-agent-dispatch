#!/usr/bin/env python3
"""Bounded, privacy-preserving importer for legacy JSON dispatch runs.

The historical runtime predates the transactional SQLite controller and has
many incompatible ``state.json`` shapes.  This module deliberately imports
only metadata needed for reconciliation and provenance.  It never copies
prompt text, argv, logs, credentials, or artifacts, and it never mutates the
legacy directory.  Without ``--output-db`` the command is a read-only audit.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import sys
from typing import Any, Callable, Iterable, Mapping

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
SOURCE_DIR = SCRIPT_DIR.parent / "src"
if str(SOURCE_DIR) not in sys.path:
    sys.path.insert(0, str(SOURCE_DIR))

from local_agent_dispatch.domain import events as ev  # noqa: E402

SCHEMA_VERSION = 1
MAX_STATE_BYTES = 4 * 1024 * 1024
MAX_EVENT_LINES = 2000
TERMINAL = {"completed", "failed", "blocked", "review", "artifact_ready_needs_review"}
IMPORTABLE_TERMINAL = {"completed", "failed", "blocked", "review"}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _load_object(path: pathlib.Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        if path.stat().st_size > MAX_STATE_BYTES:
            return None, "file_too_large"
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return None, type(exc).__name__
    return (value, None) if isinstance(value, dict) else (None, "not_object")


def _safe_status(value: Any) -> str:
    text = str(value or "unknown").strip().lower()
    return text if len(text) <= 64 else "unknown"


def _safe_string(value: Any, *, limit: int = 160) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text or len(text) > limit:
        return None
    return text


def _legacy_event_timestamp(
    report: Mapping[str, Any],
    job_id: str,
) -> tuple[str, bool]:
    """Choose a persisted observation time without pretending it is run time.

    ``summarize_run`` only has a trustworthy legacy timestamp when the old
    state file supplied ``updated_at_utc``.  If it did not, derive a stable
    timestamp from the run/job identity so repeated imports do not conflict;
    the returned boolean marks that value as synthetic observation metadata.
    """

    # ``summarize_run`` stamps each audit envelope with a fresh observation
    # time.  That timestamp describes this import, not the historical job, so
    # treating it as EventV2 evidence would make an idempotent re-import
    # conflict with the first one.  Only a timestamp explicitly carried by
    # the legacy state is trustworthy here; otherwise use the stable fallback.
    for candidate in (report.get("updated_at_utc"),):
        value = _safe_string(candidate, limit=80)
        if value:
            try:
                parsed = ev.parse_iso(value)
            except (TypeError, ValueError):
                continue
            # EventV2 requires seconds and an explicit timezone.  Normalize
            # only an otherwise valid ISO value; do not infer a local zone.
            normalized = parsed.isoformat()
            if parsed.tzinfo is not None and parsed.microsecond:
                normalized = normalized.replace("+00:00", "Z")
            elif parsed.tzinfo is not None:
                normalized = normalized.replace("+00:00", "Z")
            if "T" in normalized and (normalized.endswith("Z") or "+" in normalized or "-" in normalized[10:]):
                return normalized, False

    seed = f"legacy-observation:{report.get('run_id') or 'legacy-run'}:{job_id}"
    offset = int(hashlib.sha256(seed.encode("utf-8")).hexdigest()[:8], 16)
    base = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    timestamp = base + dt.timedelta(seconds=offset % (365 * 24 * 3600))
    return timestamp.isoformat().replace("+00:00", "Z"), True


def _job_rows(state: Mapping[str, Any]) -> list[dict[str, Any]]:
    raw = state.get("jobs")
    if isinstance(raw, dict):
        raw = list(raw.values())
    if not isinstance(raw, list):
        # Some early runs represented one job directly at the state root.
        raw = [state] if state.get("job_id") or state.get("task_id") else []
    rows: list[dict[str, Any]] = []
    for index, item in enumerate(raw):
        if not isinstance(item, Mapping):
            continue
        job_id = _safe_string(item.get("job_id") or item.get("task_id") or f"legacy-job-{index}")
        if not job_id:
            continue
        attempts = item.get("attempts")
        if not isinstance(attempts, list):
            attempts = []
        exact_model = _safe_string(item.get("model"))
        pool_id = _safe_string(item.get("pool_id"))
        adapter = _safe_string(item.get("adapter"))
        if not exact_model and attempts:
            first = attempts[0] if isinstance(attempts[0], Mapping) else {}
            exact_model = _safe_string(first.get("model"))
            pool_id = pool_id or _safe_string(first.get("pool_id"))
            adapter = adapter or _safe_string(first.get("adapter"))
        rows.append(
            {
                "job_id": job_id,
                "task_id": _safe_string(item.get("task_id")),
                "status": _safe_status(item.get("status") or state.get("status")),
                "model": exact_model,
                "pool_id": pool_id,
                "adapter": adapter,
                "attempt_count": len(attempts),
                "difficulty": item.get("difficulty") if isinstance(item.get("difficulty"), int) else None,
                "legacy_evidence_quality": "legacy_incomplete",
            }
        )
    return rows


def _event_summary(path: pathlib.Path) -> dict[str, Any]:
    if not path.is_file():
        return {"present": False, "lines": 0, "malformed_lines": 0, "event_types": {}}
    event_types: dict[str, int] = {}
    malformed = 0
    lines = 0
    try:
        with path.open(encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if lines >= MAX_EVENT_LINES:
                    break
                lines += 1
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    malformed += 1
                    continue
                if isinstance(row, Mapping):
                    event = _safe_string(row.get("event") or row.get("event_type"), limit=80)
                    if event:
                        event_types[event] = event_types.get(event, 0) + 1
    except OSError:
        malformed += 1
    return {
        "present": True,
        "lines": lines,
        "truncated": lines >= MAX_EVENT_LINES,
        "malformed_lines": malformed,
        "event_types": dict(sorted(event_types.items())),
    }


def _pid_liveness(pid: Any) -> str:
    try:
        value = int(pid)
    except (TypeError, ValueError):
        return "unknown"
    if value <= 1:
        return "unknown"
    try:
        os.kill(value, 0)
    except ProcessLookupError:
        return "dead"
    except (PermissionError, OSError):
        return "unknown"
    return "alive"


def _safe_pid_path(
    pid_path: Any,
    run_root: pathlib.Path | None,
) -> pathlib.Path | None:
    """Resolve a legacy PID breadcrumb without leaving its selected run.

    Legacy JSON is untrusted metadata.  A ``pid_path`` may be absolute,
    relative, or a symlink, so checking the textual path is insufficient:
    canonicalize it and require the resolved file to remain below the run
    root.  Without a run root, a path-based breadcrumb is not evidence.
    """

    if run_root is None or not isinstance(pid_path, (str, os.PathLike)):
        return None
    raw = str(pid_path).strip()
    if not raw or len(raw) > 4096:
        return None
    try:
        root = pathlib.Path(run_root).expanduser().resolve(strict=False)
        candidate = pathlib.Path(raw).expanduser()
        if not candidate.is_absolute():
            candidate = root / candidate
        resolved = candidate.resolve(strict=False)
        resolved.relative_to(root)
    except (OSError, RuntimeError, ValueError):
        return None
    return resolved


def _pid_from_record(
    record: Mapping[str, Any] | None,
    *,
    run_root: pathlib.Path | None = None,
) -> Any:
    """Read a bounded PID breadcrumb from one legacy metadata record.

    Legacy runs used both an inline ``pid`` and a tiny ``pid_path`` file.  A
    PID breadcrumb is evidence only; this helper never follows a command,
    starts a provider, or treats a missing/unreadable/escaped file as dead.
    """

    if not isinstance(record, Mapping):
        return None
    value = record.get("pid")
    if value in (None, ""):
        value = record.get("controller_pid")
    if value not in (None, ""):
        return value
    pid_path = record.get("pid_path")
    if pid_path in (None, ""):
        return None
    path = _safe_pid_path(pid_path, run_root)
    if path is None:
        return None
    try:
        if path.stat().st_size > 64:
            return None
        text = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError):
        return None
    return text or None


def _job_pid(
    state: Mapping[str, Any],
    job: Mapping[str, Any],
    *,
    run_root: pathlib.Path,
) -> Any:
    """Find the narrowest matching legacy PID breadcrumb.

    Prefer the job/attempt/worker record.  A run-level PID is used only when
    there is exactly one in-flight job; otherwise it is usually a controller
    PID and cannot establish the liveness of every child job.
    """

    job_id = str(job.get("job_id") or job.get("task_id") or "")
    raw_jobs = state.get("jobs")
    if isinstance(raw_jobs, Mapping):
        raw_jobs = list(raw_jobs.values())
    if isinstance(raw_jobs, list):
        for index, raw_job in enumerate(raw_jobs):
            if not isinstance(raw_job, Mapping):
                continue
            raw_job_id = str(
                raw_job.get("job_id")
                or raw_job.get("task_id")
                or f"legacy-job-{index}"
            )
            if raw_job_id != job_id:
                continue
            direct = _pid_from_record(raw_job, run_root=run_root)
            if direct is not None:
                return direct
            raw_attempts = raw_job.get("attempts")
            if isinstance(raw_attempts, list):
                for attempt in raw_attempts:
                    direct = _pid_from_record(
                        attempt if isinstance(attempt, Mapping) else None,
                        run_root=run_root,
                    )
                    if direct is not None:
                        return direct

    direct = _pid_from_record(job, run_root=run_root)
    if direct is not None:
        return direct
    attempts = job.get("attempts")
    if isinstance(attempts, list):
        for attempt in attempts:
            direct = _pid_from_record(
                attempt if isinstance(attempt, Mapping) else None,
                run_root=run_root,
            )
            if direct is not None:
                return direct
    workers = state.get("workers")
    if isinstance(workers, list):
        for worker in workers:
            if not isinstance(worker, Mapping):
                continue
            worker_job_id = str(worker.get("job_id") or worker.get("task_id") or "")
            if worker_job_id and worker_job_id == job_id:
                direct = _pid_from_record(worker, run_root=run_root)
                if direct is not None:
                    return direct
    active_jobs = [
        item for item in _job_rows(state)
        if item["status"] in {"running", "queued", "retry"}
    ]
    if len(active_jobs) == 1:
        return _pid_from_record(state, run_root=run_root)
    return None


def summarize_run(
    run_dir: str | os.PathLike[str],
    *,
    reconcile: bool = False,
    liveness_probe: Callable[[Any], str] = _pid_liveness,
) -> dict[str, Any]:
    """Summarize one legacy run without persisting sensitive payloads."""
    root = pathlib.Path(run_dir).expanduser().resolve()
    state_path = root / "state.json"
    state, error = _load_object(state_path)
    result: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "run_dir": str(root),
        "run_id": root.name,
        "observed_at_utc": utc_now(),
        "evidence_quality": "legacy_incomplete",
        "state_present": state is not None,
        "state_error": error,
        "jobs": [],
        "events": _event_summary(root / "events.jsonl"),
        "liveness": {},
    }
    if state is None:
        return result
    result["run_id"] = _safe_string(state.get("run_id")) or root.name
    result["state_status"] = _safe_status(state.get("status"))
    result["updated_at_utc"] = _safe_string(state.get("updated_at_utc") or state.get("updated_at"))
    jobs = _job_rows(state)
    result["jobs"] = jobs
    if reconcile:
        for job in jobs:
            if job["status"] in {"running", "queued", "retry"}:
                pid = _job_pid(state, job, run_root=root)
                result["liveness"][job["job_id"]] = liveness_probe(pid)
    result["counts"] = {
        "jobs": len(jobs),
        "running_or_queued": sum(job["status"] in {"running", "queued", "retry"} for job in jobs),
        "terminal": sum(job["status"] in TERMINAL for job in jobs),
    }
    return result


def discover_runs(root: str | os.PathLike[str], *, max_runs: int = 512) -> list[pathlib.Path]:
    base = pathlib.Path(root).expanduser().resolve()
    if not base.is_dir():
        raise NotADirectoryError(str(base))
    paths: list[pathlib.Path] = []
    for candidate in base.rglob("state.json"):
        if candidate.is_symlink() or not candidate.is_file():
            continue
        # A state file below a symlinked run directory is not a stable
        # provenance root.  Do not let a legacy tree escape its selected
        # root through a directory link.
        if candidate.parent.is_symlink():
            continue
        paths.append(candidate.parent)
    # Sort before applying the bound.  Filesystem traversal order is not a
    # deterministic batch boundary, and selecting the first N entries before
    # sorting could make two imports observe different runs.
    limit = max(1, int(max_runs))
    return sorted(set(paths), key=lambda path: str(path))[:limit]


def import_to_sqlite(reports: Iterable[Mapping[str, Any]], db_path: str | os.PathLike[str]) -> dict[str, Any]:
    """Write metadata-only legacy rows to a new SQLite database.

    Historical ``queued``/``running``/``retry`` rows are deliberately imported
    as ``review``.  A legacy state file cannot prove that its work was never
    claimed, and putting those rows back in the runnable queue could repeat a
    side effect after migration.  The observed status and liveness evidence
    remain in the payload for an explicit human or controller decision.
    """
    from sqlite_store import SQLiteStore

    imported = 0
    imported_attempts = 0
    imported_provenance_events = 0
    skipped = 0
    reviewed = 0
    terminal = 0
    status_by_import: dict[str, int] = {}
    path = pathlib.Path(db_path).expanduser().resolve()
    with SQLiteStore(path) as store:
        owner = "legacy-importer"
        with store.controller_lease(owner, ttl_seconds=120) as lease:
            fence = int(lease["fence_token"])
            for report in reports:
                run_id = _safe_string(report.get("run_id")) or "legacy-run"
                jobs = report.get("jobs")
                if not isinstance(jobs, list):
                    skipped += 1
                    continue
                for job in jobs:
                    if not isinstance(job, Mapping):
                        continue
                    job_id = f"legacy:{run_id}:{_safe_string(job.get('job_id')) or 'unknown'}"
                    payload = {
                        "job_id": job_id,
                        "run_id": run_id,
                        "legacy_source": report.get("run_dir"),
                        "legacy_evidence_quality": "legacy_incomplete",
                        "legacy_status": _safe_status(job.get("status")),
                        "model": _safe_string(job.get("model")),
                        "pool_id": _safe_string(job.get("pool_id")),
                        "adapter": _safe_string(job.get("adapter")),
                        "attempt_count_observed": job.get("attempt_count"),
                    }
                    observed_status = _safe_status(job.get("status"))
                    liveness = report.get("liveness")
                    if isinstance(liveness, Mapping):
                        live_state = _safe_status(liveness.get(str(job.get("job_id") or "")))
                    else:
                        live_state = "unknown"
                    payload["legacy_liveness"] = live_state
                    if observed_status in {"running", "retry"}:
                        if live_state == "dead":
                            liveness_class = "confirmed_dead"
                        elif live_state == "alive":
                            liveness_class = "confirmed_alive"
                        else:
                            liveness_class = "unknown"
                    else:
                        # A queued row has no evidence that a provider process
                        # was ever claimed.  Preserve any raw breadcrumb, but
                        # never turn it into an abandoned execution attempt.
                        liveness_class = "not_applicable_queued"
                    payload["legacy_liveness_classification"] = liveness_class
                    if observed_status in IMPORTABLE_TERMINAL:
                        status = observed_status
                        payload["import_policy"] = "preserve_terminal_only"
                        terminal += 1
                    elif observed_status in {"queued", "running", "retry"}:
                        status = "review"
                        payload["import_policy"] = "fail_closed_review"
                        reviewed += 1
                    else:
                        status = "review"
                        payload["import_policy"] = "unknown_status_review"
                        reviewed += 1
                    status_by_import[status] = status_by_import.get(status, 0) + 1
                    raw_job_id = _safe_string(job.get("job_id")) or "unknown"
                    attempt_id = ev.stable_id("attempt", "legacy", run_id, raw_job_id)
                    event_timestamp, timestamp_missing = _legacy_event_timestamp(
                        report, raw_job_id
                    )
                    if timestamp_missing:
                        payload["legacy_timestamp_missing"] = True
                    live_state = str(payload["legacy_liveness"])
                    provenance = ev.new_event(
                        event_type="attempt.queued",
                        source=f"legacy_import:{run_id}",
                        idempotency_key=ev.stable_id(
                            "legacy", "attempt", run_id, raw_job_id
                        ),
                        causal_parent=None,
                        confidence=0.5,
                        timestamp=event_timestamp,
                        privacy_class="internal",
                        attempt_id=attempt_id,
                        job_id=job_id,
                        evidence_quality="legacy_incomplete",
                        legacy_run_id=run_id,
                        legacy_status=observed_status,
                        legacy_liveness=live_state,
                        import_policy=payload["import_policy"],
                        legacy_timestamp_missing=timestamp_missing,
                    )
                    attempt_payload = {
                        "evidence_quality": "legacy_incomplete",
                        "legacy_run_id": run_id,
                        "legacy_status": observed_status,
                        "legacy_liveness": live_state,
                        "legacy_liveness_classification": liveness_class,
                        "import_policy": payload["import_policy"],
                        "legacy_timestamp_missing": timestamp_missing,
                    }
                    reconciliation_event: Mapping[str, Any] | None = None
                    # A liveness event is emitted only when the caller really
                    # supplied a probe result.  Missing probe evidence remains
                    # unknown and is not upgraded into a synthetic observation.
                    if (
                        observed_status in {"running", "retry"}
                        and isinstance(liveness, Mapping)
                        and str(job.get("job_id") or "") in liveness
                    ):
                        if live_state == "dead":
                            reconciliation_event = ev.new_event(
                                event_type="attempt.abandoned",
                                source=f"legacy_import:{run_id}:liveness",
                                idempotency_key=ev.stable_id(
                                    "legacy", "reconcile", run_id, raw_job_id, "dead"
                                ),
                                causal_parent=provenance["event_id"],
                                confidence=0.9,
                                timestamp=event_timestamp,
                                privacy_class="internal",
                                attempt_id=attempt_id,
                                evidence_quality="legacy_incomplete",
                                reason="legacy_stale_dead_pid",
                                preserves_evidence=True,
                                legacy_status=observed_status,
                                legacy_liveness="dead",
                            )
                        else:
                            reconciliation_event = ev.new_event(
                                event_type="attempt.review",
                                source=f"legacy_import:{run_id}:liveness",
                                idempotency_key=ev.stable_id(
                                    "legacy", "reconcile", run_id, raw_job_id, live_state
                                ),
                                causal_parent=provenance["event_id"],
                                confidence=0.7 if live_state == "alive" else 0.5,
                                timestamp=event_timestamp,
                                privacy_class="internal",
                                attempt_id=attempt_id,
                                evidence_quality="legacy_incomplete",
                                reason=(
                                    "legacy_process_alive"
                                    if live_state == "alive"
                                    else "legacy_liveness_unknown"
                                ),
                                decision="escalate",
                                preserves_evidence=True,
                                legacy_status=observed_status,
                                legacy_liveness=live_state,
                            )
                    existing = store.get_job(job_id)
                    existing_attempt = store.get_attempt(attempt_id)
                    result = store.import_legacy_job(
                        job_id,
                        attempt_id,
                        payload,
                        run_id=run_id,
                        task_id=_safe_string(job.get("task_id")),
                        status=status,
                        attempt_payload=attempt_payload,
                        attempt_status=(
                            "abandoned"
                            if reconciliation_event is not None
                            and reconciliation_event.get("event_type") == "attempt.abandoned"
                            else "review"
                        ),
                        attempt_no=1,
                        observed_at_utc=event_timestamp,
                        provenance_event=provenance,
                        reconciliation_event=reconciliation_event,
                        owner_id=owner,
                        fence_token=fence,
                    )
                    if existing is not None and existing_attempt is not None:
                        # Same stable ids and payloads are a no-op.  Do not
                        # count a re-import as new work or new evidence.
                        skipped += 1
                    else:
                        imported += 1
                        imported_attempts += 1
                        imported_provenance_events += 1
            store.append_event(
                "legacy_import_completed",
                owner_id=owner,
                fence_token=fence,
                payload={
                    "imported_jobs": imported,
                    "skipped": skipped,
                    "reviewed_jobs": reviewed,
                    "terminal_jobs": terminal,
                    "imported_attempts": imported_attempts,
                    "imported_provenance_events": imported_provenance_events,
                    "status_by_import": dict(sorted(status_by_import.items())),
                },
            )
    return {
        "db_path": str(path),
        "imported_jobs": imported,
        "imported_attempts": imported_attempts,
        "imported_provenance_events": imported_provenance_events,
        "skipped": skipped,
        "reviewed_jobs": reviewed,
        "terminal_jobs": terminal,
        "status_by_import": dict(sorted(status_by_import.items())),
    }


def _report_from_runs(
    root: str | os.PathLike[str],
    runs: Iterable[Mapping[str, Any]],
    *,
    read_only: bool,
) -> dict[str, Any]:
    """Build the bounded report envelope shared by audit and import paths."""

    materialized = [dict(run) for run in runs]
    counts: dict[str, int] = {}
    for report in materialized:
        for job in report.get("jobs") or []:
            status = str(job.get("status") or "unknown")
            counts[status] = counts.get(status, 0) + 1
    return {
        "schema_version": SCHEMA_VERSION,
        "report_type": "local-agent-dispatch.legacy-history",
        "read_only": bool(read_only),
        "provider_execution": False,
        "root": str(pathlib.Path(root).expanduser().resolve()),
        "observed_at_utc": utc_now(),
        "runs": materialized,
        "counts": {"runs": len(materialized), "jobs_by_status": dict(sorted(counts.items()))},
    }


def build_report(root: str | os.PathLike[str], *, reconcile: bool = False, max_runs: int = 512) -> dict[str, Any]:
    runs = [summarize_run(path, reconcile=reconcile) for path in discover_runs(root, max_runs=max_runs)]
    return _report_from_runs(root, runs, read_only=True)


def import_discovered_runs(
    root: str | os.PathLike[str],
    db_path: str | os.PathLike[str],
    *,
    reconcile: bool = False,
    max_runs: int = 512,
    liveness_probe: Callable[[Any], str] = _pid_liveness,
) -> dict[str, Any]:
    """Discover and import a bounded legacy batch without executing work.

    This is the explicit batch seam for M0 migration.  It only reads
    ``state.json``/``events.jsonl`` metadata, optionally records bounded PID
    liveness observations, and delegates writes to the transactional,
    review-only :func:`import_to_sqlite` path.  It never invokes a provider,
    starts a process, copies prompt/argv/artifact/credential bodies, or turns
    historical ``queued``/``running``/``retry`` rows into runnable jobs.

    The returned report is an audit envelope (``read_only`` is false only to
    indicate that the caller requested a SQLite write).  Re-running the same
    batch against the same database is safe: stable job, attempt, EventV2,
    and legacy event identifiers make the migration idempotent while the
    migration counters expose newly imported versus skipped rows.
    """

    paths = discover_runs(root, max_runs=max_runs)
    runs = [
        summarize_run(
            path,
            reconcile=reconcile,
            liveness_probe=liveness_probe,
        )
        for path in paths
    ]
    result = _report_from_runs(root, runs, read_only=False)
    result["migration"] = import_to_sqlite(runs, db_path)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True)
    parser.add_argument("--output-db")
    parser.add_argument("--reconcile", action="store_true")
    parser.add_argument("--max-runs", type=int, default=512)
    parser.add_argument("--output", default="-")
    args = parser.parse_args(argv)
    try:
        if args.output_db:
            # Keep the CLI on the same bounded discovery/import path as the
            # programmatic batch API.  This matters for migration safety:
            # discovery ordering, liveness reconciliation, stable IDs, and
            # the metadata-only review policy must not drift between callers.
            report = import_discovered_runs(
                args.root,
                args.output_db,
                reconcile=args.reconcile,
                max_runs=args.max_runs,
            )
        else:
            report = build_report(
                args.root,
                reconcile=args.reconcile,
                max_runs=args.max_runs,
            )
        text = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        if args.output == "-":
            print(text, end="")
        else:
            target = pathlib.Path(args.output).expanduser().resolve()
            target.parent.mkdir(parents=True, exist_ok=True)
            temporary = target.with_name(f".{target.name}.tmp")
            temporary.write_text(text, encoding="utf-8")
            temporary.replace(target)
        return 0
    except Exception as exc:
        print(json.dumps({"schema_version": SCHEMA_VERSION, "ok": False, "error": f"{type(exc).__name__}: {exc}"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
