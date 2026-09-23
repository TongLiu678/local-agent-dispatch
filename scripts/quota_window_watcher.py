#!/usr/bin/env python3
"""Observe quota snapshots and emit a conservative, provider-free wake plan.

This module deliberately does not call a provider, refresh a credential, or
sleep.  It normalizes snapshots from Codex, Antigravity, and OpenCode-style
sources into shared-pool decisions.  An execution-ready claim is never
inferred from a catalog or a historical usage chart: the output separates
``quota_state`` from ``execution_state`` and returns a bounded wake hint for a
later re-probe/replan.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import pathlib
import re
import sys
from collections.abc import Mapping, Sequence
from typing import Any


SCHEMA_VERSION = 1
DEFAULT_POLL_SECONDS = 30.0
DEFAULT_TTL_SECONDS = 900.0
MAX_POLL_SECONDS = 3600.0
BLOCKED_HEALTH = {"blocked", "cooldown", "quota_exhausted", "unavailable"}
QUOTA_REASON_RE = re.compile(r"quota|rate.?limit|credit|spend|usage.?limit|reset", re.I)
AUTH_CONFLICT_RE = re.compile(
    r"not\s+signed\s+in|signing\s+in|login\s+required|unauthori[sz]ed|"
    r"invalid[_ -]?grant|authentication\s+failed",
    re.I,
)
SENSITIVE_KEY_RE = re.compile(
    r"(?:^|[_ -])(secret|password|private[_ -]?key|api[_ -]?key|"
    r"authorization|cookie|access[_ -]?token|refresh[_ -]?token|"
    r"id[_ -]?token|bearer[_ -]?token)(?:$|[_ -])",
    re.I,
)


class QuotaWatchError(ValueError):
    """Raised when a quota observation cannot be safely interpreted."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _parse_utc(value: Any) -> dt.datetime | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        if not math.isfinite(float(value)) or float(value) <= 0:
            return None
        try:
            return dt.datetime.fromtimestamp(float(value), tz=dt.timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(dt.timezone.utc)


def _now(value: str | dt.datetime | None) -> dt.datetime:
    if value is None:
        return dt.datetime.now(tz=dt.timezone.utc)
    if isinstance(value, dt.datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise QuotaWatchError("now_utc must include a timezone")
        return value.astimezone(dt.timezone.utc)
    parsed = _parse_utc(value)
    if parsed is None:
        raise QuotaWatchError("now_utc must be a timezone-aware ISO-8601 timestamp")
    return parsed


def _sensitive_keys(value: Any, path: str = "") -> list[str]:
    found: list[str] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            name = f"{path}.{key}" if path else str(key)
            key_text = str(key)
            normalized_key = re.sub(r"[- ]+", "_", key_text).lower()
            # ``auth_state``/``auth_message`` are diagnostic metadata and are
            # allowed; credential-bearing auth keys are not.
            auth_credential_key = normalized_key in {
                "auth",
                "auth_json",
                "auth_file",
                "auth_token",
                "authentication",
                "authentication_json",
                "authentication_file",
                "authorization",
            }
            token_credential_key = normalized_key in {
                "token",
                "access_token",
                "refresh_token",
                "id_token",
                "bearer_token",
                "api_token",
                "auth_token",
            }
            if SENSITIVE_KEY_RE.search(key_text) or auth_credential_key or token_credential_key:
                found.append(name)
            found.extend(_sensitive_keys(item, name))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, item in enumerate(value):
            found.extend(_sensitive_keys(item, f"{path}[{index}]"))
    return found


def _observed_at(snapshot: Mapping[str, Any]) -> dt.datetime | None:
    for key in ("observed_at_utc", "fetched_at_utc", "scanned_at_utc", "checked_at_utc"):
        parsed = _parse_utc(snapshot.get(key))
        if parsed is not None:
            return parsed
    return None


def _ttl(snapshot: Mapping[str, Any], row: Mapping[str, Any]) -> float:
    raw = row.get("ttl_seconds", snapshot.get("ttl_seconds", DEFAULT_TTL_SECONDS))
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return DEFAULT_TTL_SECONDS
    if not math.isfinite(value) or value <= 0:
        return DEFAULT_TTL_SECONDS
    return value


def _pool_rows(snapshot: Mapping[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    raw = snapshot.get("pools")
    rows: list[tuple[str, dict[str, Any]]] = []
    if isinstance(raw, Mapping):
        for pool_id, row in raw.items():
            if isinstance(row, Mapping):
                rows.append((str(pool_id), dict(row)))
    elif isinstance(snapshot.get("pool"), Mapping):
        row = dict(snapshot["pool"])
        rows.append((str(row.get("pool_id") or snapshot.get("pool_id") or "unknown"), row))
    elif snapshot.get("pool_id"):
        rows.append((str(snapshot["pool_id"]), dict(snapshot)))
    return rows


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or value in (None, ""):
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(parsed) or parsed < 0 or parsed > 100:
        return None
    return parsed


def _remaining_percent(snapshot: Mapping[str, Any], row: Mapping[str, Any]) -> float | None:
    direct_keys = (
        "effective_remaining_percent",
        "effective_percent_displayed",
        "remaining_percent",
    )
    for key in direct_keys:
        parsed = _number(row.get(key))
        if parsed is not None:
            return parsed
    quota = row.get("quota")
    if isinstance(quota, Mapping):
        parsed = _remaining_percent(snapshot, quota)
        if parsed is not None:
            return parsed
    candidates: list[float] = []
    for key in ("primary", "secondary", "five_hour", "weekly", "monthly"):
        bucket = row.get(key)
        if isinstance(bucket, Mapping):
            for name in ("remaining_percent", "effective_remaining_percent", "percent"):
                parsed = _number(bucket.get(name))
                if parsed is not None:
                    candidates.append(parsed)
                    break
    windows = row.get("windows")
    if isinstance(windows, Mapping):
        for bucket in windows.values():
            if isinstance(bucket, Mapping):
                parsed = _remaining_percent(snapshot, bucket)
                if parsed is not None:
                    candidates.append(parsed)
    return min(candidates) if candidates else None


def _reset_candidates(snapshot: Mapping[str, Any], row: Mapping[str, Any], observed: dt.datetime) -> list[dt.datetime]:
    candidates: list[dt.datetime] = []
    keys = ("reset_at_utc", "resets_at_utc", "reset_at", "resets_at")
    for key in keys:
        parsed = _parse_utc(row.get(key))
        if parsed is not None:
            candidates.append(parsed)
    for key in ("primary", "secondary", "five_hour", "weekly", "monthly"):
        bucket = row.get(key)
        if isinstance(bucket, Mapping):
            candidates.extend(_reset_candidates(snapshot, bucket, observed))
    windows = row.get("windows")
    if isinstance(windows, Mapping):
        for bucket in windows.values():
            if isinstance(bucket, Mapping):
                candidates.extend(_reset_candidates(snapshot, bucket, observed))
    # Antigravity exposes a relative refresh in minutes.  It is useful only
    # when the snapshot also carries an observation timestamp.
    for key in ("five_hour_refresh_minutes", "weekly_refresh_minutes"):
        raw = row.get(key)
        if isinstance(raw, (int, float)) and not isinstance(raw, bool):
            minutes = float(raw)
            if math.isfinite(minutes) and minutes > 0:
                candidates.append(observed + dt.timedelta(minutes=minutes))
    return candidates


def _auth_conflict(snapshot: Mapping[str, Any], row: Mapping[str, Any]) -> bool:
    for source in (snapshot, row):
        for key in ("raw_excerpt", "diagnostic", "diagnostics", "auth_message", "runtime_reason"):
            value = source.get(key)
            if isinstance(value, str) and AUTH_CONFLICT_RE.search(value):
                return True
            if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
                if any(isinstance(item, str) and AUTH_CONFLICT_RE.search(item) for item in value):
                    return True
    return False


def _catalog_visible(snapshot: Mapping[str, Any], row: Mapping[str, Any]) -> bool:
    value = row.get("catalog_visible", snapshot.get("catalog_visible"))
    if value is not None:
        return bool(value)
    models = row.get("schedulable_models") or row.get("models") or snapshot.get("models")
    return isinstance(models, Sequence) and not isinstance(models, (str, bytes, bytearray)) and bool(models)


def _auth_configured(snapshot: Mapping[str, Any], row: Mapping[str, Any]) -> bool:
    value = row.get("auth_state", snapshot.get("auth_state"))
    return str(value or "").lower() in {"configured", "authenticated", "ready"}


def _reason_is_quota(row: Mapping[str, Any], remaining: float | None) -> bool:
    health = str(row.get("health", "unknown")).lower()
    if remaining is not None and remaining <= 0:
        return True
    if health in {"cooldown", "quota_exhausted"}:
        return True
    reason = str(row.get("blocked_reason") or row.get("runtime_reason") or "")
    return bool(QUOTA_REASON_RE.search(reason)) and health in BLOCKED_HEALTH


def _policy_value(snapshot: Mapping[str, Any], key: str) -> Any:
    policy = snapshot.get("policy")
    if isinstance(policy, Mapping) and key in policy:
        return policy[key]
    return snapshot.get(key)


def _watch_row(
    snapshot: Mapping[str, Any],
    pool_id: str,
    row: Mapping[str, Any],
    *,
    now: dt.datetime,
    reserve_percent: float,
    unknown_quota_policy: str,
    unknown_pilot_percent: float,
) -> dict[str, Any]:
    observed = _observed_at(snapshot)
    stale = observed is None or observed + dt.timedelta(seconds=_ttl(snapshot, row)) < now
    remaining = _remaining_percent(snapshot, row)
    auth_conflict = _auth_conflict(snapshot, row)
    reset_candidates = _reset_candidates(snapshot, row, observed or now)
    future_resets = sorted(item for item in reset_candidates if item > now)
    reset_at = future_resets[0] if future_resets else None
    health = str(row.get("health", snapshot.get("health", "unknown"))).lower()
    quota_blocked = _reason_is_quota(row, remaining)
    provider = str(row.get("provider") or snapshot.get("provider") or "unknown")
    models = row.get("schedulable_models") or row.get("models") or []
    if isinstance(models, str):
        models = [models]

    if auth_conflict:
        quota_state = "known" if remaining is not None else "unknown"
        decision = "needs_reauth"
        reason = "snapshot contains an authentication conflict; model quota is not execution evidence"
        execution_state = "blocked"
    elif stale:
        quota_state = "stale"
        decision = "blocked_stale"
        reason = "quota snapshot is missing or outside its TTL"
        execution_state = "blocked"
    elif remaining is None:
        quota_state = "unknown"
        pilot = (
            unknown_quota_policy in {"pilot", "bounded_pilot", "pilot_cap"}
            and _catalog_visible(snapshot, row)
            and _auth_configured(snapshot, row)
        )
        if pilot:
            decision = "bounded_pilot"
            reason = "unknown balance allowed only by explicit pilot policy"
            execution_state = "pilot_only"
        else:
            decision = "blocked_unknown"
            reason = "remaining balance is unknown; no pilot policy was proven"
            execution_state = "blocked"
    elif remaining <= 0 or (health in BLOCKED_HEALTH and quota_blocked):
        quota_state = "blocked"
        decision = "cooldown_until_reset" if reset_at else "blocked_quota"
        reason = "shared pool reports no schedulable quota"
        execution_state = "blocked"
    elif remaining <= reserve_percent:
        quota_state = "known"
        decision = "drain"
        reason = "remaining quota is at or below the reserve"
        execution_state = "drain"
    else:
        quota_state = "known"
        decision = "ready"
        reason = "fresh quota is above the reserve"
        execution_state = "candidate"

    return {
        "schema_version": SCHEMA_VERSION,
        "pool_id": pool_id,
        "provider": provider,
        "models": [str(item) for item in models if item not in (None, "")],
        "remaining_percent": remaining,
        "reserve_percent": reserve_percent,
        "quota_state": quota_state,
        "execution_state": execution_state,
        "decision": decision,
        "reason": reason,
        "health_observed": health,
        "stale": stale,
        "auth_conflict": auth_conflict,
        "reset_at_utc": reset_at.isoformat() if reset_at else None,
        "pilot_percent": unknown_pilot_percent if decision == "bounded_pilot" else None,
        "observed_at_utc": observed.isoformat() if observed else None,
        "ttl_seconds": _ttl(snapshot, row),
        "source": str(row.get("source") or snapshot.get("source") or "unknown"),
    }


def watch(
    snapshots: Sequence[Mapping[str, Any]],
    *,
    now_utc: str | dt.datetime | None = None,
    reserve_percent: float = 10.0,
    poll_seconds: float = DEFAULT_POLL_SECONDS,
    unknown_quota_policy: str | None = None,
    unknown_pilot_percent: float = 5.0,
) -> dict[str, Any]:
    """Return normalized pool decisions and a bounded replan wake hint."""
    now = _now(now_utc)
    if isinstance(reserve_percent, bool) or not math.isfinite(float(reserve_percent)):
        raise QuotaWatchError("reserve_percent must be finite")
    reserve = float(reserve_percent)
    if reserve < 0 or reserve > 100:
        raise QuotaWatchError("reserve_percent must be between 0 and 100")
    if isinstance(poll_seconds, bool) or not math.isfinite(float(poll_seconds)):
        raise QuotaWatchError("poll_seconds must be finite")
    poll = float(poll_seconds)
    if poll <= 0 or poll > MAX_POLL_SECONDS:
        raise QuotaWatchError("poll_seconds is outside the supported range")
    pilot = float(unknown_pilot_percent)
    if not math.isfinite(pilot) or pilot <= 0 or pilot > 100:
        raise QuotaWatchError("unknown_pilot_percent must be between 0 and 100")
    policy = str(unknown_quota_policy or "block").lower()
    if policy not in {"block", "defer", "fail_closed", "pilot", "bounded_pilot", "pilot_cap"}:
        raise QuotaWatchError("unknown_quota_policy is not recognized")

    rows: list[dict[str, Any]] = []
    snapshot_digests: list[str] = []
    invalid_snapshots: list[dict[str, Any]] = []
    for index, raw in enumerate(snapshots):
        if not isinstance(raw, Mapping):
            invalid_snapshots.append({"index": index, "reason": "snapshot_not_mapping"})
            continue
        sensitive = _sensitive_keys(raw)
        if sensitive:
            invalid_snapshots.append({"index": index, "reason": "sensitive_key", "fields": sensitive})
            continue
        snapshot_digests.append(digest(raw))
        for pool_id, row in _pool_rows(raw):
            rows.append(
                _watch_row(
                    raw,
                    pool_id,
                    row,
                    now=now,
                    reserve_percent=reserve,
                    unknown_quota_policy=policy,
                    unknown_pilot_percent=pilot,
                )
            )
    # A duplicate pool observation is retained for provenance but the newest
    # row wins for the scheduler projection.  This prevents two isolated
    # runtime directories from silently adding quota together.
    latest: dict[str, dict[str, Any]] = {}
    for row in rows:
        previous = latest.get(row["pool_id"])
        if previous is None or str(row.get("observed_at_utc") or "") >= str(previous.get("observed_at_utc") or ""):
            latest[row["pool_id"]] = row
    pools = [latest[key] for key in sorted(latest)]
    ready = [row["pool_id"] for row in pools if row["decision"] in {"ready", "bounded_pilot"}]
    quota_blocked = [row for row in pools if row["decision"] == "cooldown_until_reset" and row.get("reset_at_utc")]
    future_reset = min((row["reset_at_utc"] for row in quota_blocked), default=None)
    if not pools or invalid_snapshots:
        next_wake = now + dt.timedelta(seconds=poll)
        replan_reason = "quota_observation_invalid_or_missing"
        wake_source = "bounded_poll"
    elif not ready and future_reset:
        next_wake = _parse_utc(future_reset) or now + dt.timedelta(seconds=poll)
        replan_reason = "blocked_pool_quota_reset"
        wake_source = "quota_reset"
    else:
        next_wake = now + dt.timedelta(seconds=poll)
        replan_reason = "quota_health_recheck"
        wake_source = "bounded_poll"
    return {
        "schema_version": SCHEMA_VERSION,
        "type": "local-agent-dispatch.quota-window-watch",
        "observed_at_utc": now.isoformat(),
        "pools": pools,
        "ready_pools": ready,
        "blocked_pools": [row["pool_id"] for row in pools if row["decision"] not in {"ready", "bounded_pilot"}],
        "invalid_snapshots": invalid_snapshots,
        "snapshot_digests": snapshot_digests,
        "next_wake_at_utc": next_wake.isoformat(),
        "wake_source": wake_source,
        "replan_feedback": {
            "replan_at_utc": next_wake.isoformat(),
            "replan_reason": replan_reason,
            "quota_reset_at_utc": future_reset,
            "quota_reset_pool_id": next(
                (row["pool_id"] for row in quota_blocked if row.get("reset_at_utc") == future_reset),
                None,
            ),
        },
        "provider_invocations": [],
        "note": "Observation only; caller must keep heartbeats and resource checks active while waiting.",
    }


def load_json(path: str) -> Any:
    if path == "-":
        return json.load(sys.stdin)
    return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))


def _write_json(path: str | None, payload: Mapping[str, Any]) -> None:
    text = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    if path:
        target = pathlib.Path(path).expanduser()
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_suffix(target.suffix + ".tmp")
        temporary.write_text(text, encoding="utf-8")
        temporary.replace(target)
    else:
        print(text, end="")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", action="append", required=True, help="JSON snapshot path; repeatable")
    parser.add_argument("--now-utc")
    parser.add_argument("--reserve-percent", type=float, default=10.0)
    parser.add_argument("--poll-seconds", type=float, default=DEFAULT_POLL_SECONDS)
    parser.add_argument("--unknown-quota-policy", choices=("block", "pilot"), default="block")
    parser.add_argument("--unknown-pilot-percent", type=float, default=5.0)
    parser.add_argument("--output")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(list(argv or sys.argv[1:]))
    try:
        snapshots = [load_json(path) for path in args.snapshot]
        result = watch(
            snapshots,
            now_utc=args.now_utc,
            reserve_percent=args.reserve_percent,
            poll_seconds=args.poll_seconds,
            unknown_quota_policy=args.unknown_quota_policy,
            unknown_pilot_percent=args.unknown_pilot_percent,
        )
    except (OSError, ValueError, json.JSONDecodeError, QuotaWatchError) as exc:
        print(f"quota-window-watcher: {exc}", file=sys.stderr)
        return 2
    _write_json(args.output, result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
