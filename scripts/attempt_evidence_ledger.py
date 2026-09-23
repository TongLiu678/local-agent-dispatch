#!/usr/bin/env python3
"""Provider-free per-attempt quota and resource evidence ledger.

The ledger deliberately stores only bounded metadata.  Quota snapshots are
reduced to an allow-list and a digest; resource observations are reduced to
peaks, pressure, and disk summaries.  The command never contacts a provider
or the network.  It is read-only unless ``--append`` is supplied explicitly.
"""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import json
import math
import os
import pathlib
import re
import sys
from typing import Any, Iterable, Mapping, Sequence


SCHEMA_VERSION = "lad_attempt_evidence/1.0.0"
SUMMARY_VERSION = "lad_attempt_evidence_summary/1.0.0"
_DIGEST_RE = re.compile(r"(?:sha256:)?[0-9a-f]{64}\Z")
_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")
_SECRET_KEY_RE = re.compile(
    r"(?:api[_-]?key|access[_-]?token|auth[_-]?token|authorization|bearer|"
    r"credential|password|private[_-]?key|client[_-]?secret)\Z",
    re.IGNORECASE,
)


class EvidenceLedgerError(ValueError):
    """Base error for invalid or unsafe ledger evidence."""


class EvidenceConflictError(EvidenceLedgerError):
    """A stable attempt id was reused with different evidence."""


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def stable_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _safe_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise EvidenceLedgerError(f"{field} is invalid")
    return value


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise EvidenceLedgerError(f"{field} must be a SHA-256 digest")
    return value if value.startswith("sha256:") else f"sha256:{value}"


def _reject_secrets(value: Any, path: str = "input") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if _SECRET_KEY_RE.search(str(key)):
                raise EvidenceLedgerError(f"{path}.{key}: secret-like field is refused")
            _reject_secrets(child, f"{path}.{key}")
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, child in enumerate(value):
            _reject_secrets(child, f"{path}[{index}]")


def _number(value: Any, field: str, *, maximum: float | None = None) -> int | float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise EvidenceLedgerError(f"{field} must be a non-negative finite number or null")
    number = float(value)
    if not math.isfinite(number) or number < 0 or (maximum is not None and number > maximum):
        raise EvidenceLedgerError(f"{field} is outside its valid range")
    return int(number) if number.is_integer() else number


def _integer(value: Any, field: str) -> int | None:
    number = _number(value, field)
    if number is None:
        return None
    if not isinstance(number, int):
        raise EvidenceLedgerError(f"{field} must be an integer")
    return number


def _timestamp(value: Any, field: str, *, required: bool = False) -> str | None:
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value:
        raise EvidenceLedgerError(f"{field} must be an RFC 3339 timestamp")
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError as exc:
        raise EvidenceLedgerError(f"{field} must be an RFC 3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise EvidenceLedgerError(f"{field} must include a timezone")
    return parsed.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def _first(mapping: Mapping[str, Any], *names: str) -> Any:
    for name in names:
        if name in mapping:
            return mapping[name]
    return None


def sanitize_quota_snapshot(snapshot: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """Return the stable quota allow-list plus its content digest."""
    if snapshot is None:
        return None
    if not isinstance(snapshot, Mapping):
        raise EvidenceLedgerError("quota snapshot must be an object or null")
    _reject_secrets(snapshot, "quota_snapshot")
    pool_id = _first(snapshot, "pool_id", "pool")
    window = _first(snapshot, "window", "quota_kind", "window_id")
    source = _first(snapshot, "source", "source_kind")
    result: dict[str, Any] = {
        "pool_id": _safe_id(pool_id, "quota_snapshot.pool_id") if pool_id is not None else None,
        "window": _safe_id(window, "quota_snapshot.window") if window is not None else None,
        "remaining_percent": _number(
            _first(snapshot, "remaining_percent", "effective_remaining_percent"),
            "quota_snapshot.remaining_percent",
            maximum=100.0,
        ),
        "remaining_units": _number(
            snapshot.get("remaining_units"), "quota_snapshot.remaining_units"
        ),
        "reserved_units": _number(
            snapshot.get("reserved_units"), "quota_snapshot.reserved_units"
        ),
        "reset_at_utc": _timestamp(
            _first(snapshot, "reset_at_utc", "resets_at_utc", "reset_at"),
            "quota_snapshot.reset_at_utc",
        ),
        "observed_at_utc": _timestamp(
            _first(snapshot, "observed_at_utc", "observed_at", "fetched_at_utc"),
            "quota_snapshot.observed_at_utc",
        ),
        "maximum_age_seconds": _integer(
            snapshot.get("maximum_age_seconds"), "quota_snapshot.maximum_age_seconds"
        ),
        "source": _safe_id(source, "quota_snapshot.source") if source is not None else None,
    }
    if result["maximum_age_seconds"] == 0:
        raise EvidenceLedgerError("quota_snapshot.maximum_age_seconds must be positive")
    result["snapshot_digest"] = stable_digest(result)
    return result


def quota_delta(
    before: Mapping[str, Any] | None,
    after: Mapping[str, Any] | None,
    *,
    as_of_utc: str | None = None,
) -> dict[str, Any]:
    """Compute an observed delta only inside one fresh pool/window."""
    unknown = {"state": "unknown", "reason": "missing_snapshot", "attribution": "unknown"}
    if before is None or after is None:
        return unknown
    if not before.get("pool_id") or before.get("pool_id") != after.get("pool_id"):
        return {**unknown, "reason": "pool_mismatch"}
    if not before.get("window") or before.get("window") != after.get("window"):
        return {**unknown, "reason": "window_mismatch"}
    before_at = before.get("observed_at_utc")
    after_at = after.get("observed_at_utc")
    if not isinstance(before_at, str) or not isinstance(after_at, str):
        return {**unknown, "reason": "observation_time_unknown"}
    start = _parse_timestamp(before_at)
    end = _parse_timestamp(after_at)
    if end < start:
        return {**unknown, "reason": "observation_time_reversed"}
    as_of = _parse_timestamp(as_of_utc) if as_of_utc else end
    if as_of < end:
        return {**unknown, "reason": "as_of_precedes_after_snapshot"}
    for label, row, observed in (("before", before, start), ("after", after, end)):
        ttl = row.get("maximum_age_seconds")
        if isinstance(ttl, int) and (as_of - observed).total_seconds() > ttl:
            return {**unknown, "reason": f"{label}_snapshot_stale"}
    before_reset = before.get("reset_at_utc")
    after_reset = after.get("reset_at_utc")
    if before_reset and after_reset and before_reset != after_reset:
        return {**unknown, "reason": "reset_boundary_changed"}
    reset = after_reset or before_reset
    if isinstance(reset, str) and end >= _parse_timestamp(reset):
        return {**unknown, "reason": "reset_boundary_crossed"}
    percent_before = before.get("remaining_percent")
    percent_after = after.get("remaining_percent")
    units_before = before.get("remaining_units")
    units_after = after.get("remaining_units")
    if percent_before is None and (units_before is None or units_after is None):
        return {**unknown, "reason": "comparable_balance_unknown"}
    result: dict[str, Any] = {
        "state": "known",
        "reason": None,
        "attribution": "non_exclusive_observed_delta",
        "pool_id": before["pool_id"],
        "window": before["window"],
        "elapsed_seconds": int((end - start).total_seconds()),
        "remaining_percent_change": None,
        "consumed_percent": None,
        "remaining_units_change": None,
        "consumed_units": None,
    }
    if percent_before is not None and percent_after is not None:
        result["remaining_percent_change"] = percent_after - percent_before
        result["consumed_percent"] = percent_before - percent_after
    if units_before is not None and units_after is not None:
        result["remaining_units_change"] = units_after - units_before
        result["consumed_units"] = units_before - units_after
    if result["remaining_percent_change"] is None and result["remaining_units_change"] is None:
        return {**unknown, "reason": "comparable_balance_unknown"}
    return result


_PEAK_FIELDS = (
    "ram_bytes",
    "rss_bytes",
    "swap_bytes",
    "cpu_percent",
    "gpu_percent",
    "vram_bytes",
    "disk_write_bytes",
    "network_bytes",
)
_PRESSURE_FIELDS = (
    "memory_score",
    "cpu_score",
    "io_score",
    "psi_memory_some_avg10",
    "psi_memory_full_avg10",
    "psi_cpu_some_avg10",
    "psi_io_some_avg10",
)
_PRESSURE_LEVELS = {"unknown": 0, "normal": 1, "warning": 2, "critical": 3}


def summarize_resources(evidence: Any) -> dict[str, Any]:
    """Reduce allow-listed resource samples to bounded per-attempt summaries."""
    if evidence is None:
        samples: list[Mapping[str, Any]] = []
    elif isinstance(evidence, Mapping):
        raw_samples = evidence.get("samples", [evidence])
        if not isinstance(raw_samples, Sequence) or isinstance(raw_samples, (str, bytes)):
            raise EvidenceLedgerError("resource samples must be an array")
        samples = list(raw_samples)
    elif isinstance(evidence, Sequence) and not isinstance(evidence, (str, bytes)):
        samples = list(evidence)
    else:
        raise EvidenceLedgerError("resource evidence must be an object or array")
    sanitized: list[dict[str, Any]] = []
    for index, raw in enumerate(samples):
        if not isinstance(raw, Mapping):
            raise EvidenceLedgerError(f"resource sample {index} must be an object")
        _reject_secrets(raw, f"resource_samples[{index}]")
        row: dict[str, Any] = {
            "observed_at_utc": _timestamp(
                _first(raw, "observed_at_utc", "observed_at"),
                f"resource_samples[{index}].observed_at_utc",
            )
        }
        peaks = raw.get("peaks") if isinstance(raw.get("peaks"), Mapping) else raw
        pressure = raw.get("pressure") if isinstance(raw.get("pressure"), Mapping) else raw
        disk = raw.get("disk") if isinstance(raw.get("disk"), Mapping) else raw
        for field in _PEAK_FIELDS:
            row[field] = _number(peaks.get(field), f"resource_samples[{index}].{field}")
        for field in _PRESSURE_FIELDS:
            row[field] = _number(pressure.get(field), f"resource_samples[{index}].{field}")
        level = _first(pressure, "memory_level", "memory_pressure_level")
        if level is not None and level not in _PRESSURE_LEVELS:
            raise EvidenceLedgerError(f"resource_samples[{index}].memory_level is invalid")
        row["memory_level"] = level
        row["disk_free_bytes"] = _number(
            _first(disk, "free_bytes", "disk_free_bytes"),
            f"resource_samples[{index}].disk_free_bytes",
        )
        row["disk_used_percent"] = _number(
            _first(disk, "used_percent", "disk_used_percent"),
            f"resource_samples[{index}].disk_used_percent",
            maximum=100.0,
        )
        writable = _first(disk, "writable", "disk_writable")
        if writable is not None and not isinstance(writable, bool):
            raise EvidenceLedgerError(f"resource_samples[{index}].disk_writable must be boolean")
        row["disk_writable"] = writable
        mount = _first(disk, "mount", "path", "disk_path")
        row["mount_digest"] = stable_digest(str(mount)) if mount is not None else None
        sanitized.append(row)

    def values(field: str) -> list[int | float]:
        return [row[field] for row in sanitized if row.get(field) is not None]

    times = sorted(row["observed_at_utc"] for row in sanitized if row.get("observed_at_utc"))
    levels = [row["memory_level"] for row in sanitized if row.get("memory_level")]
    writables = [row["disk_writable"] for row in sanitized if row.get("disk_writable") is not None]
    mounts = sorted({row["mount_digest"] for row in sanitized if row.get("mount_digest")})
    return {
        "sample_count": len(sanitized),
        "observed_from_utc": times[0] if times else None,
        "observed_to_utc": times[-1] if times else None,
        "peaks": {field: (max(values(field)) if values(field) else None) for field in _PEAK_FIELDS},
        "pressure": {
            "memory_level": max(levels, key=_PRESSURE_LEVELS.get) if levels else "unknown",
            **{
                f"{field}_max": max(values(field)) if values(field) else None
                for field in _PRESSURE_FIELDS
            },
        },
        "disk": {
            "free_bytes_min": min(values("disk_free_bytes")) if values("disk_free_bytes") else None,
            "used_percent_max": max(values("disk_used_percent")) if values("disk_used_percent") else None,
            "writable_all": all(writables) if writables else None,
            "mount_digests": mounts,
        },
        "source_digest": stable_digest(sanitized),
    }


def build_record(data: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(data, Mapping):
        raise EvidenceLedgerError("attempt input must be an object")
    _reject_secrets(data)
    model = _first(data, "model_id", "exact_model", "model")
    host = _first(data, "host_id", "execution_host", "host")
    cps = _first(data, "cps_digest", "cps_recipe_digest")
    before = sanitize_quota_snapshot(_first(data, "quota_before", "before_quota"))
    after = sanitize_quota_snapshot(_first(data, "quota_after", "after_quota"))
    observed = _timestamp(
        _first(data, "observed_at_utc", "finished_at_utc", "attempt_finished_at_utc"),
        "observed_at_utc",
    )
    observed = observed or (after or {}).get("observed_at_utc") or (before or {}).get("observed_at_utc")
    if observed is None:
        raise EvidenceLedgerError("observed_at_utc is required when quota snapshots have no timestamp")
    resource_input = _first(data, "resource_samples", "resource_evidence", "resource_summary")
    body: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "kind": "attempt_evidence",
        "attempt_id": _safe_id(data.get("attempt_id"), "attempt_id"),
        "job_id": _safe_id(data.get("job_id"), "job_id"),
        "model_id": _safe_id(model, "model_id"),
        "pool_id": _safe_id(data.get("pool_id"), "pool_id"),
        "host_id": _safe_id(host, "host_id"),
        "cps_digest": _digest(cps, "cps_digest"),
        "observed_at_utc": observed,
        "quota": {
            "before": before,
            "after": after,
            "delta": quota_delta(before, after, as_of_utc=observed),
        },
        "resources": summarize_resources(resource_input),
        "privacy": {
            "allowlist_only": True,
            "credential_values_read": False,
            "prompt_bodies_stored": False,
        },
        "execution": {
            "provider_execution": False,
            "network_execution": False,
        },
    }
    for label, snapshot in (("before", before), ("after", after)):
        if snapshot is not None and snapshot.get("pool_id") not in (None, body["pool_id"]):
            body["quota"]["delta"] = {
                "state": "unknown",
                "reason": f"{label}_pool_differs_from_attempt_pool",
                "attribution": "unknown",
            }
    body["record_digest"] = stable_digest(body)
    return body


def validate_record(record: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(record, Mapping):
        raise EvidenceLedgerError("ledger record must be an object")
    allowed = {
        "schema_version", "kind", "attempt_id", "job_id", "model_id", "pool_id",
        "host_id", "cps_digest", "observed_at_utc", "quota", "resources", "privacy",
        "execution", "record_digest",
    }
    if set(record) != allowed or record.get("schema_version") != SCHEMA_VERSION:
        raise EvidenceLedgerError("ledger record schema or fields are invalid")
    digest = record.get("record_digest")
    body = dict(record)
    body.pop("record_digest", None)
    if not isinstance(digest, str) or stable_digest(body) != digest:
        raise EvidenceLedgerError("ledger record digest mismatch")
    if record.get("privacy", {}).get("credential_values_read") is not False:
        raise EvidenceLedgerError("ledger privacy boundary is invalid")
    if record.get("execution") != {"provider_execution": False, "network_execution": False}:
        raise EvidenceLedgerError("ledger execution boundary is invalid")
    return dict(record)


def _read_locked(handle: Any, path: pathlib.Path) -> list[dict[str, Any]]:
    handle.seek(0)
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(handle, start=1):
        if not line.strip():
            continue
        try:
            records.append(validate_record(json.loads(line)))
        except (json.JSONDecodeError, EvidenceLedgerError) as exc:
            raise EvidenceLedgerError(f"corrupt ledger at {path}:{line_number}: {exc}") from exc
    return records


def load_ledger(path: pathlib.Path | str) -> list[dict[str, Any]]:
    target = pathlib.Path(path)
    if not target.exists():
        return []
    with target.open("r", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_SH)
        try:
            return _read_locked(handle, target)
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def append_record(path: pathlib.Path | str, record: Mapping[str, Any]) -> str:
    """Append once; identical retry is a no-op and conflicts fail closed."""
    canonical = validate_record(record)
    target = pathlib.Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            records = _read_locked(handle, target)
            for existing in records:
                if existing["attempt_id"] == canonical["attempt_id"]:
                    if existing == canonical:
                        return "duplicate"
                    raise EvidenceConflictError(
                        f"attempt_id {canonical['attempt_id']!r} already has conflicting evidence"
                    )
            handle.seek(0, os.SEEK_END)
            handle.write(canonical_json(canonical) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
            return "appended"
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def ledger_summary(records: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    rows = [validate_record(row) for row in records]
    known = sum(row["quota"]["delta"].get("state") == "known" for row in rows)
    return {
        "schema_version": SUMMARY_VERSION,
        "kind": "attempt_evidence_ledger_summary",
        "read_only": True,
        "provider_execution": False,
        "network_execution": False,
        "record_count": len(rows),
        "known_quota_delta_count": known,
        "unknown_quota_delta_count": len(rows) - known,
        "attempt_ids": [row["attempt_id"] for row in rows],
        "ledger_digest": stable_digest(rows),
    }


def _write_json(path: pathlib.Path | None, value: Mapping[str, Any]) -> None:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if path is None:
        sys.stdout.write(payload)
    else:
        path.write_text(payload, encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", type=pathlib.Path, help="JSONL ledger path")
    parser.add_argument("--input", type=pathlib.Path, help="one attempt evidence JSON object")
    parser.add_argument("--append", action="store_true", help="explicitly append --input to --ledger")
    parser.add_argument("--output", type=pathlib.Path, help="optional summary JSON path")
    args = parser.parse_args(argv)
    if args.append and (args.input is None or args.ledger is None):
        parser.error("--append requires both --input and --ledger")
    if args.ledger is None and args.input is None:
        parser.error("provide --ledger and/or --input")
    try:
        record = None
        append_status = None
        if args.input is not None:
            record = build_record(json.loads(args.input.read_text(encoding="utf-8")))
        if args.append:
            append_status = append_record(args.ledger, record)
        rows = load_ledger(args.ledger) if args.ledger is not None else []
        summary = ledger_summary(rows)
        summary["mode"] = "append" if args.append else "read_only"
        summary["append_status"] = append_status
        if record is not None:
            summary["candidate"] = {
                "attempt_id": record["attempt_id"],
                "record_digest": record["record_digest"],
                "quota_delta_state": record["quota"]["delta"]["state"],
                "quota_delta_reason": record["quota"]["delta"].get("reason"),
            }
        _write_json(args.output, summary)
        return 0
    except (OSError, json.JSONDecodeError, EvidenceLedgerError) as exc:
        print(f"attempt evidence ledger failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
