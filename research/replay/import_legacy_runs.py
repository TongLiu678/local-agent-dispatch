"""Legacy JSON run importer for the provenance ledger.

Imported runs are labelled ``evidence_quality=legacy_incomplete``. The importer
copies only values that actually exist in the legacy record; it never invents
model, quota, resource, or terminal-state values. A legacy ``status`` field is
preserved verbatim as ``legacy_status`` inside ``legacy_evidence`` and is never
translated into a real terminal ledger event.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from local_agent_dispatch.domain import events as ev
from local_agent_dispatch.ledger.store import EventStore

_LEGACY_EPOCH = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _stable_fallback_timestamp(record_id: str) -> str:
    """Deterministic placeholder timestamp for records without one.

    Derived from the record id so re-imports are byte-identical; the record is
    flagged ``legacy_timestamp_missing`` so the placeholder is never mistaken
    for real evidence of when the run happened.
    """
    offset = int(hashlib.sha256(record_id.encode("utf-8")).hexdigest()[:8], 16)
    return (_LEGACY_EPOCH + timedelta(seconds=offset % (365 * 24 * 3600))).isoformat()

_KNOWN_EXACT_FIELDS = (
    "mission_id",
    "task_id",
    "plan_revision_id",
    "assignment_id",
    "reservation_id",
    "policy_version_id",
    "provider",
    "pool_id",
    "model_id",
    "model_variant",
    "execution_host",
    "workload_host",
    "mount",
    "route",
    "validator",
)

_GAP_REPORT_KEYS = {
    "model_id": "missing_model_id",
    "quota": "missing_quota",
    "resources": "missing_resources",
    "status": "missing_terminal_state",
}


def _record_id(record: Mapping[str, Any], index: int) -> str:
    for key in ("run_id", "id", "attempt_id", "record_id"):
        value = record.get(key)
        if isinstance(value, str) and value:
            return value
    return f"row:{index}"


def _extract_exact(record: Mapping[str, Any]) -> dict[str, Any]:
    """Verbatim copy of fields that are already exact references. Missing
    values stay missing; nothing is inferred."""
    return {
        key: record[key]
        for key in _KNOWN_EXACT_FIELDS
        if key in record and isinstance(record[key], str) and record[key]
    }


def import_legacy_json(
    store: EventStore,
    records: list[Mapping[str, Any]],
    *,
    source: str = "legacy_import",
    default_timestamp: str | None = None,
) -> dict[str, Any]:
    """Import legacy run records as ``attempt.queued`` events.

    Each record maps to exactly one root event labelled
    ``evidence_quality=legacy_incomplete``. Re-importing the same file is
    idempotent (same stable event ids).
    """
    if not isinstance(records, list):
        raise TypeError("records must be a list of legacy run mappings")

    report: dict[str, Any] = {
        "source": source,
        "imported": 0,
        "duplicates": 0,
        "skipped": 0,
        "attempt_ids": [],
        "gaps": {"missing_model_id": 0, "missing_quota": 0, "missing_resources": 0, "missing_terminal_state": 0},
    }
    seen: set[str] = set()
    for index, record in enumerate(records):
        if not isinstance(record, Mapping):
            report["skipped"] += 1
            continue

        record_id = _record_id(record, index)
        idempotency_key = ev.stable_id("legacy", source, record_id)
        event_id = ev.stable_id("event", idempotency_key)
        if event_id in seen:
            report["skipped"] += 1
            continue
        seen.add(event_id)

        legacy_evidence: dict[str, Any] = {}
        for key, value in record.items():
            if key not in _KNOWN_EXACT_FIELDS and key not in {
                "run_id",
                "id",
                "record_id",
                "attempt_id",
                "timestamp",
            }:
                legacy_evidence[key] = value

        payload: dict[str, Any] = dict(_extract_exact(record))
        attempt_id = record.get("attempt_id")
        if not isinstance(attempt_id, str) or not attempt_id:
            attempt_id = ev.stable_id("attempt", source, record_id)
        payload["attempt_id"] = attempt_id

        for gap_key, report_key in _GAP_REPORT_KEYS.items():
            if gap_key not in record:
                report["gaps"][report_key] += 1

        timestamp = record.get("timestamp")
        if not isinstance(timestamp, str) or not timestamp:
            legacy_evidence["legacy_timestamp_missing"] = True
            timestamp = default_timestamp or _stable_fallback_timestamp(record_id)
        else:
            legacy_evidence["legacy_timestamp"] = timestamp

        if legacy_evidence:
            payload["legacy_evidence"] = legacy_evidence

        event = ev.new_event(
            event_type="attempt.queued",
            source=source,
            idempotency_key=idempotency_key,
            causal_parent=None,
            confidence=0.5,
            timestamp=timestamp,
            privacy_class="internal",
            event_id=event_id,
            evidence_quality="legacy_incomplete",
            legacy_run_id=record_id,
            **payload,
        )
        outcome = store.append(event)
        if outcome == "duplicate":
            report["duplicates"] += 1
        else:
            report["imported"] += 1
            report["attempt_ids"].append(attempt_id)
    return report


def import_legacy_file(
    store: EventStore,
    path: str | pathlib.Path,
    *,
    source: str | None = None,
    default_timestamp: str | None = None,
) -> dict[str, Any]:
    """Import a JSON file containing either a list or a mapping with a
    ``runs``/``records`` list."""
    target = pathlib.Path(path)
    with target.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if isinstance(payload, list):
        records = payload
    elif isinstance(payload, Mapping):
        for key in ("runs", "records", "legacy_runs"):
            if isinstance(payload.get(key), list):
                records = payload[key]
                break
        else:
            raise ValueError(
                f"{target}: expected a list or a mapping with a runs/records list"
            )
    else:
        raise ValueError(f"{target}: legacy payload must be a list or mapping")
    effective_source = source or f"legacy_import:{target.name}"
    return import_legacy_json(
        store, records, source=effective_source, default_timestamp=default_timestamp
    )
