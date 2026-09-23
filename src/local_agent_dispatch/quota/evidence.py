"""Versioned quota-evidence records and conservative shared-pool accounting.

Provider-neutral: this module never sends a prompt, reads credential values,
or calls an undocumented balance endpoint.  Unknown remaining balances stay
``None``; they are never mapped to zero or full.

All evidence is scoped to the single shared ``opencode.go`` pool.  Exact model
and variant stay inside the event/record while quota and rate-limit failures
act on the shared pool, matching the local-agent-dispatch evidence model.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
from typing import Any, Iterable

SCHEMA_VERSION = 1
POOL_ID = "opencode.go"
PROVIDER_ID = "opencode-go"

SOURCES = ("console", "api", "receipt", "history", "runtime_error", "manual")
WINDOWS = ("five_hour", "weekly", "monthly")
WINDOW_ORDER = ("five_hour", "weekly", "monthly")
ATTRIBUTIONS = ("exclusive", "confounded", "unknown")
OVERAGE_STATES = ("unknown", "enabled", "disabled")
DEFAULT_TTL_SECONDS = 3600
CONSOLE_TTL_SECONDS = 6 * 3600
RECEIPT_TTL_SECONDS = 4 * 3600
RUNTIME_EVENT_TTL_SECONDS = 2 * 3600
USAGE_API_TTL_SECONDS = 5 * 60

SENSITIVE_KEYS = {
    "authorization",
    "proxyauthorization",
    "cookie",
    "setcookie",
    "credential",
    "credentials",
    "password",
    "passwd",
    "secret",
    "token",
    "accesstoken",
    "apitoken",
    "refreshtoken",
    "idtoken",
    "sessiontoken",
    "apikey",
    "privatekey",
}

_ANSI_RE = re.compile(r"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")
_STATUS_RE = re.compile(r"\b(429|401|403)\b")
_RATE_RE = re.compile(r"rate\s*[-_]?limit|too\s+many\s+requests", re.I)
_QUOTA_RE = re.compile(
    r"\bquota\b|usage\s*[-_]?limit|limit\s+exceeded|insufficient\s+balance|"
    r"payment\s+required|allowance\s+exhausted|exhausted|overage",
    re.I,
)
_AUTH_RE = re.compile(r"unauthorized|authentication\s+failed|not\s+authenticated|invalid\s+credentials", re.I)
_CAPABILITY_RE = re.compile(
    r"cannot\s+use\s+this\s+model|unsupported\s+model|not\s+entitled|"
    r"model\s+not\s+found|invalid\s+model|model_not_found|unavailable\s+model|"
    r"unknown\s+model\b",
    re.I,
)
_LOCATION_RE = re.compile(
    r"user\s+location\s+is\s+not\s+supported|"
    r"location\s+is\s+not\s+supported|"
    r"(?:unsupported|unavailable)\s+(?:country|region|location)|"
    r"(?:country|region|location)\s+(?:is\s+)?not\s+supported|"
    r"not\s+available\s+in\s+(?:your\s+)?location|"
    r"geographic(?:al)?\s+(?:restriction|block)",
    re.I,
)
_WINDOW_HINT_RE = re.compile(r"five[- ]?hour|5[- ]?hour|\bweekly\b|\bmonthly\b", re.I)
_RETRY_AFTER_RE = re.compile(r"retry[- ]after(?:\s*[:=])?\s*(\d+)", re.I)
_RESET_IN_RE = re.compile(
    r"reset(?:s|ting)?\s+(?:in|within)\s+(\d+(?:\.\d+)?)\s*"
    r"(second|sec|s|minute|min|m|hour|hr|h)",
    re.I,
)
_RESET_AT_RE = re.compile(r"reset(?:s|ting)?\s+at\s+(\d{4}-\d{2}-\d{2}T[^\s,)\]]+)", re.I)


def _parse_utc(value: Any) -> dt.datetime:
    if isinstance(value, dt.datetime):
        parsed = value
    else:
        parsed = dt.datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def _now_utc() -> str:
    return dt.datetime.now(tz=dt.timezone.utc).isoformat()


def now_utc() -> str:
    """Current UTC timestamp in ISO-8601 format."""
    return _now_utc()


def _redact_text(text: str, limit: int = 800) -> str:
    clean = _ANSI_RE.sub("", text).replace("\r", "\n")
    clean = re.sub(r"(?i)\bBearer\s+\S+", "Bearer <redacted>", clean)
    clean = re.sub(
        r"(?i)(api[-_]?key|token|secret|password|authorization)\s*[:=]\s*[^\s,;]+",
        r"\1=<redacted>",
        clean,
    )
    clean = re.sub(
        r'(?i)("(?:api[-_]?key|token|secret|password|authorization)"\s*:\s*)"[^"]*"',
        r'\1"<redacted>"',
        clean,
    )
    return clean.strip()[-limit:]


def _is_sensitive_key(key: Any) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
    return normalized in SENSITIVE_KEYS


def scope_hash(
    pool_id: str = POOL_ID,
    provider_id: str = PROVIDER_ID,
    scope_hint: str = "",
) -> str:
    """Stable SHA-256 of the canonical pool scope, never of credentials."""
    payload = json.dumps(
        {"pool_id": pool_id, "provider_id": provider_id, "scope_hint": scope_hint},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def make_record(
    *,
    source: str,
    window: str | None,
    observed_at_utc: str | None = None,
    scope_hint: str = "",
    remaining_percent: float | None = None,
    remaining_amount: float | None = None,
    cap_amount: float | None = None,
    reset_at_utc: str | None = None,
    confidence: float = 0.5,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    discrepancy: bool = False,
    attribution: str = "unknown",
    exact_balance: bool = False,
    overage_fallback_state: str = "unknown",
    note: str | None = None,
    event: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a versioned quota-evidence record.

    Unknown remaining values are never converted to zero or full: both
    ``remaining_percent`` and ``remaining_amount`` stay ``None``.
    """
    if source not in SOURCES:
        raise ValueError(f"unknown evidence source: {source!r}")
    if window is not None and window not in WINDOWS:
        raise ValueError(f"unknown window: {window!r}")
    if attribution not in ATTRIBUTIONS:
        raise ValueError(f"unknown attribution: {attribution!r}")
    if overage_fallback_state not in OVERAGE_STATES:
        raise ValueError(f"unknown overage fallback state: {overage_fallback_state!r}")
    if remaining_percent is not None and not 0.0 <= float(remaining_percent) <= 100.0:
        raise ValueError(f"remaining_percent out of range: {remaining_percent!r}")
    if remaining_amount is not None and float(remaining_amount) < 0.0:
        raise ValueError(f"remaining_amount must not be negative: {remaining_amount!r}")
    if cap_amount is not None and float(cap_amount) <= 0.0:
        raise ValueError(f"cap_amount must be positive: {cap_amount!r}")
    if ttl_seconds <= 0:
        raise ValueError(f"ttl_seconds must be positive: {ttl_seconds!r}")
    if not 0.0 <= confidence <= 1.0:
        raise ValueError(f"confidence out of range: {confidence!r}")
    if reset_at_utc is not None:
        _parse_utc(reset_at_utc)

    return {
        "schema_version": SCHEMA_VERSION,
        "source": source,
        "observed_at_utc": observed_at_utc or _now_utc(),
        "pool_id": POOL_ID,
        "scope_hash": scope_hash(scope_hint=scope_hint),
        "window": window,
        "remaining_percent": None if remaining_percent is None else float(remaining_percent),
        "remaining_amount": None if remaining_amount is None else float(remaining_amount),
        "cap_amount": None if cap_amount is None else float(cap_amount),
        "reset_at_utc": reset_at_utc,
        "confidence": float(confidence),
        "ttl_seconds": int(ttl_seconds),
        "discrepancy": bool(discrepancy),
        "attribution": attribution,
        "exact_balance": bool(exact_balance),
        "overage_fallback_state": overage_fallback_state,
        "note": note,
        "event": event,
    }


def is_stale(record: dict[str, Any], now_utc: str | dt.datetime | None = None) -> bool:
    """True when the record's TTL has expired relative to ``now_utc``."""
    now = _parse_utc(now_utc) if now_utc is not None else dt.datetime.now(tz=dt.timezone.utc)
    observed = _parse_utc(record["observed_at_utc"])
    ttl = int(record.get("ttl_seconds") or 0)
    return observed + dt.timedelta(seconds=ttl) < now


def _find_sensitive_keys(value: Any, path: str = "") -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            name = f"{path}.{key}" if path else str(key)
            if _is_sensitive_key(key):
                found.append(name)
            found.extend(_find_sensitive_keys(item, name))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(_find_sensitive_keys(item, f"{path}[{index}]"))
    return found


def parse_console_snapshot(data: dict[str, Any]) -> dict[str, Any]:
    """Import an explicit, user-supplied read-only console snapshot.

    Refuses (fails closed) when any credential-like key is present anywhere in
    the snapshot; only key names are reported, never their values.  A Zen
    balance is preserved separately and is never treated as free OpenCode Go
    quota.
    """
    if not isinstance(data, dict):
        raise ValueError("console snapshot must be a JSON object")
    sensitive = _find_sensitive_keys(data)
    if sensitive:
        raise ValueError(
            "refused console import: credential-like keys present: " + ", ".join(sorted(sensitive))
        )

    pool_id = str(data.get("pool_id") or POOL_ID)
    if pool_id != POOL_ID:
        raise ValueError(f"console snapshot is for pool {pool_id!r}, expected {POOL_ID!r}")
    provider_id = str(data.get("provider_id") or PROVIDER_ID)
    observed_at_utc = str(data.get("observed_at_utc") or _now_utc())
    _parse_utc(observed_at_utc)
    overage = str(data.get("overage_fallback_state") or "unknown")
    if overage not in OVERAGE_STATES:
        raise ValueError(f"invalid overage_fallback_state: {overage!r}")
    windows_raw = data.get("windows")
    if not isinstance(windows_raw, dict):
        raise ValueError("console snapshot requires a 'windows' object")

    records: list[dict[str, Any]] = []
    discrepancy_windows: list[str] = []
    invalid_windows: list[str] = []
    unknown_windows: list[str] = []

    for window in WINDOWS:
        entry = windows_raw.get(window)
        if not isinstance(entry, dict):
            unknown_windows.append(window)
            records.append(
                make_record(
                    source="console",
                    window=window,
                    observed_at_utc=observed_at_utc,
                    remaining_percent=None,
                    remaining_amount=None,
                    reset_at_utc=None,
                    confidence=0.5,
                    ttl_seconds=CONSOLE_TTL_SECONDS,
                    discrepancy=False,
                    attribution="unknown",
                    exact_balance=False,
                    overage_fallback_state=overage,
                    note="Window not present in the console snapshot; remaining balance remains unknown.",
                )
            )
            continue
        percent = entry.get("remaining_percent")
        amount = entry.get("remaining_amount")
        cap = entry.get("cap_amount")
        reset_at = entry.get("reset_at_utc")
        notes: list[str] = []
        discrepancy = False
        valid = True

        if percent is not None:
            try:
                percent = float(percent)
                if not 0.0 <= percent <= 100.0:
                    notes.append(f"remaining_percent {percent!r} out of range")
                    percent = None
                    discrepancy = True
                    valid = False
            except (TypeError, ValueError):
                notes.append("remaining_percent is not numeric")
                percent = None
                discrepancy = True
                valid = False
        if amount is not None:
            try:
                amount = float(amount)
                if amount < 0.0:
                    notes.append(f"remaining_amount {amount!r} negative")
                    amount = None
                    discrepancy = True
                    valid = False
            except (TypeError, ValueError):
                notes.append("remaining_amount is not numeric")
                amount = None
                discrepancy = True
                valid = False
        if cap is not None:
            try:
                cap = float(cap)
                if cap <= 0.0:
                    notes.append(f"cap_amount {cap!r} not positive")
                    cap = None
                    discrepancy = True
            except (TypeError, ValueError):
                notes.append("cap_amount is not numeric")
                cap = None
                discrepancy = True
        if reset_at is not None:
            try:
                reset_dt = _parse_utc(reset_at)
                if reset_dt < _parse_utc(observed_at_utc):
                    notes.append("reset_at_utc precedes observed_at_utc")
                    discrepancy = True
                reset_at = reset_dt.isoformat()
            except (TypeError, ValueError):
                notes.append("reset_at_utc is not ISO-8601")
                reset_at = None
                discrepancy = True
        if (
            percent is not None
            and amount is not None
            and cap is not None
            and abs(percent - 100.0 * amount / cap) > 1.0
        ):
            notes.append("remaining_percent disagrees with remaining_amount/cap_amount")
            discrepancy = True
            valid = False

        if not valid:
            invalid_windows.append(window)
        if discrepancy:
            discrepancy_windows.append(window)
        records.append(
            make_record(
                source="console",
                window=window,
                observed_at_utc=observed_at_utc,
                remaining_percent=percent,
                remaining_amount=amount,
                cap_amount=cap,
                reset_at_utc=reset_at,
                confidence=1.0 if valid and percent is not None else 0.5,
                ttl_seconds=CONSOLE_TTL_SECONDS,
                discrepancy=discrepancy,
                attribution="unknown",
                exact_balance=percent is not None or amount is not None,
                overage_fallback_state=overage,
                note="; ".join(notes) or (
                    "Console balance is account-level; concurrent-pool attribution "
                    "is not derivable from this snapshot."
                ),
            )
        )

    contradictory: list[tuple[str, str]] = []
    resets: dict[str, dt.datetime | None] = {}
    for window in WINDOWS:
        entry = windows_raw.get(window)
        if isinstance(entry, dict) and entry.get("reset_at_utc"):
            try:
                resets[window] = _parse_utc(entry["reset_at_utc"])
            except (TypeError, ValueError):
                resets[window] = None
        else:
            resets[window] = None
    for earlier, later in zip(WINDOW_ORDER, WINDOW_ORDER[1:]):
        if resets[earlier] is not None and resets[later] is not None:
            if resets[earlier] > resets[later]:
                contradictory.append((earlier, later))
                discrepancy_windows.extend((earlier, later))
                for record in records:
                    if record["window"] in (earlier, later) and not record["discrepancy"]:
                        record["discrepancy"] = True
                        record["note"] = (
                            f"reset ordering contradiction: {earlier} resets after {later}"
                        )

    for window in WINDOWS:
        usable = [
            r for r in records
            if r["window"] == window
            and not is_stale(r, observed_at_utc)
            and (r["remaining_percent"] is not None or r["remaining_amount"] is not None)
        ]
        if not usable and window not in invalid_windows:
            unknown_windows.append(window)

    zen = data.get("zen_balance")
    zen_balance = None
    if isinstance(zen, dict):
        zen_balance = {
            "state": str(zen.get("state") or "observed"),
            "amount_usd": zen.get("amount_usd"),
            "currency": str(zen.get("currency") or "USD"),
            "note": str(
                zen.get("note")
                or "A Zen balance fallback is not free OpenCode Go quota; it is kept separate."
            ),
            "is_free_quota": False,
        }
    elif zen is not None:
        zen_balance = {
            "state": "observed",
            "amount_usd": None,
            "note": "Zen balance present but not in the expected shape; kept separate.",
            "is_free_quota": False,
        }

    return {
        "schema_version": SCHEMA_VERSION,
        "source": "console",
        "pool_id": pool_id,
        "provider_id": provider_id,
        "scope_hash": scope_hash(scope_hint="console"),
        "observed_at_utc": observed_at_utc,
        "records": records,
        "overage_fallback_state": overage,
        "zen_balance": zen_balance,
        "validation": {
            "unknown_windows": sorted(set(unknown_windows)),
            "invalid_windows": sorted(set(invalid_windows)),
            "discrepancy_windows": sorted(set(discrepancy_windows)),
            "contradictory_window_pairs": [list(pair) for pair in sorted(contradictory)],
        },
        "security": {
            "credential_values_read": False,
            "sensitive_keys_refused": sorted(sensitive),
            "redaction": "Console import refuses credential-like keys; values are never read.",
        },
    }


def parse_usage_api_response(
    data: dict[str, Any],
    *,
    observed_at_utc: str | None = None,
    overage_fallback_state: str | None = None,
    endpoint: str = "https://opencode.ai/zen/go/v1/usage",
) -> dict[str, Any]:
    """Parse the documented OpenCode Go usage response.

    The service reports *used* percentages under ``rolling``, ``weekly`` and
    ``monthly``.  The scheduler stores the complementary remaining percentage
    while retaining the original values in ``api_metadata``.  ``rolling`` is
    normalized to the local ``five_hour`` window name.  Missing or malformed
    windows remain unknown and never become zero/full.
    """
    if not isinstance(data, dict):
        raise ValueError("usage API response must be a JSON object")
    usage = data.get("usage")
    if not isinstance(usage, dict):
        raise ValueError("usage API response requires a 'usage' object")
    observed = observed_at_utc or _now_utc()
    _parse_utc(observed)
    overage = overage_fallback_state
    if overage is None and isinstance(data.get("useBalance"), bool):
        overage = "enabled" if data["useBalance"] else "disabled"
    overage = overage or "unknown"
    if overage not in OVERAGE_STATES:
        raise ValueError(f"invalid overage_fallback_state: {overage!r}")

    mapping = {"rolling": "five_hour", "weekly": "weekly", "monthly": "monthly"}
    records: list[dict[str, Any]] = []
    metadata: dict[str, Any] = {"endpoint": endpoint, "windows": {}}
    missing: list[str] = []
    invalid: list[str] = []
    discrepancy_windows: list[str] = []
    for api_window, local_window in mapping.items():
        item = usage.get(api_window)
        if not isinstance(item, dict):
            missing.append(local_window)
            records.append(
                make_record(
                    source="api",
                    window=local_window,
                    observed_at_utc=observed,
                    ttl_seconds=USAGE_API_TTL_SECONDS,
                    confidence=0.45,
                    attribution="unknown",
                    exact_balance=False,
                    overage_fallback_state=overage,
                    note=f"Official usage response omitted {api_window}; remaining is unknown.",
                )
            )
            continue
        raw_percent = item.get("percent")
        reset_at = item.get("resetsAt")
        status = str(item.get("status") or "unknown")
        metadata["windows"][local_window] = {
            "provider_window": api_window,
            "used_percent": raw_percent,
            "status": status,
            "resets_at": reset_at,
        }
        discrepancy = False
        notes: list[str] = []
        used: float | None
        try:
            used = float(raw_percent)
            if not 0.0 <= used <= 100.0:
                raise ValueError
        except (TypeError, ValueError):
            used = None
            invalid.append(local_window)
            discrepancy = True
            notes.append("provider percent is missing or outside 0..100")
        normalized_reset: str | None = None
        if reset_at is not None:
            try:
                normalized_reset = _parse_utc(reset_at).isoformat()
                if _parse_utc(normalized_reset) < _parse_utc(observed):
                    discrepancy = True
                    notes.append("reset timestamp precedes observation")
            except (TypeError, ValueError):
                discrepancy = True
                notes.append("provider reset timestamp is not ISO-8601")
        # The official Go endpoint uses ``rate-limited`` as a valid terminal
        # status when a window is exhausted. It is not malformed evidence:
        # percent=100 plus a reset timestamp is an exact zero-remaining gate.
        if status not in {"ok", "rate-limited", "unknown"}:
            discrepancy = True
            notes.append(f"provider status={status}")
        if discrepancy:
            discrepancy_windows.append(local_window)
        records.append(
            make_record(
                source="api",
                window=local_window,
                observed_at_utc=observed,
                remaining_percent=None if used is None else 100.0 - used,
                reset_at_utc=normalized_reset,
                confidence=0.99 if used is not None and not discrepancy else 0.5,
                ttl_seconds=USAGE_API_TTL_SECONDS,
                discrepancy=discrepancy,
                attribution="unknown",
                exact_balance=used is not None and not discrepancy,
                overage_fallback_state=overage,
                note="; ".join(notes) or "Official OpenCode Go usage API evidence.",
            )
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "source": "api",
        "pool_id": POOL_ID,
        "provider_id": PROVIDER_ID,
        "scope_hash": scope_hash(scope_hint="official-usage-api"),
        "observed_at_utc": observed,
        "records": records,
        "overage_fallback_state": overage,
        "api_metadata": metadata,
        "validation": {
            "missing_windows": sorted(set(missing)),
            "invalid_windows": sorted(set(invalid)),
            "discrepancy_windows": sorted(set(discrepancy_windows)),
        },
    }


def _receipt_window(receipt: dict[str, Any]) -> list[str]:
    window = receipt.get("window")
    if isinstance(window, str) and window in WINDOWS:
        return [window]
    if isinstance(window, list):
        return [w for w in window if w in WINDOWS] or list(WINDOWS)
    return list(WINDOWS)


def _receipt_spend(receipt: dict[str, Any]) -> tuple[float | None, float | None]:
    if "cost_usd" in receipt and receipt["cost_usd"] is not None:
        try:
            cost = float(receipt["cost_usd"])
            return cost, cost
        except (TypeError, ValueError):
            return None, None
    spend_min = receipt.get("cost_min_usd")
    spend_max = receipt.get("cost_max_usd")
    try:
        minimum = None if spend_min is None else float(spend_min)
        maximum = None if spend_max is None else float(spend_max)
    except (TypeError, ValueError):
        return None, None
    if minimum is not None and maximum is None:
        maximum = minimum
    if maximum is not None and minimum is None:
        minimum = maximum
    return minimum, maximum


def spend_bounds(
    receipts: Iterable[dict[str, Any]],
    caps: dict[str, float] | None = None,
    observed_at_utc: str | None = None,
    scope_hint: str = "receipts",
) -> dict[str, Any]:
    """Conservative spend bounds from before/after usage receipts.

    Receipts are historical spend evidence only: they never become a remaining
    balance.  When any receipt in a window has unknown spend or the window cap
    is unknown, the remaining-percent bounds stay ``None`` rather than claiming
    zero or full remaining quota.
    """
    caps = caps or {}
    totals: dict[str, dict[str, Any]] = {}
    for window in WINDOWS:
        totals[window] = {
            "spend_min_usd": 0.0,
            "spend_max_usd": 0.0,
            "spend_known": True,
            "attribution": "exclusive",
            "count": 0,
            "overlapping": False,
        }
    spans: dict[str, list[tuple[dt.datetime, dt.datetime]]] = {w: [] for w in WINDOWS}

    for raw in receipts:
        if not isinstance(raw, dict):
            continue
        minimum, maximum = _receipt_spend(raw)
        windows = _receipt_window(raw)
        attribution = str(raw.get("attribution") or "unknown")
        if attribution not in ATTRIBUTIONS:
            attribution = "unknown"
        start = raw.get("started_at_utc") or raw.get("started_at")
        end = raw.get("ended_at_utc") or raw.get("ended_at")
        for window in windows:
            row = totals[window]
            row["count"] += 1
            if minimum is None or maximum is None:
                row["spend_known"] = False
            else:
                row["spend_min_usd"] += minimum
                row["spend_max_usd"] += maximum
            if attribution == "confounded":
                row["attribution"] = "confounded"
            elif attribution == "unknown" and row["attribution"] == "exclusive":
                row["attribution"] = "unknown"
            try:
                if start and end:
                    spans[window].append((_parse_utc(start), _parse_utc(end)))
            except (TypeError, ValueError):
                row["attribution"] = "unknown"

    windows_out: dict[str, Any] = {}
    for window in WINDOWS:
        row = totals[window]
        spend_min = row["spend_min_usd"] if row["spend_known"] else None
        spend_max = row["spend_max_usd"] if row["spend_known"] else None
        if row["count"] == 0:
            spend_min = None
            spend_max = None
            lower = None
            upper = None
            attribution = "unknown"
            note = "No receipts supplied; absence is not evidence of zero spend."
        else:
            attribution = row["attribution"]
            if attribution == "exclusive":
                intervals = spans[window]
                for index, (a_start, a_end) in enumerate(intervals):
                    for b_start, b_end in intervals[index + 1 :]:
                        if a_start < b_end and b_start < a_end:
                            attribution = "confounded"
                            row["overlapping"] = True
                            break
                    if row["overlapping"]:
                        break
                if not row["overlapping"] and len(intervals) != len({(s, e) for s, e in intervals}):
                    attribution = "unknown"
            cap = caps.get(window)
            if cap is None or cap <= 0:
                lower = None
                upper = None
                note = (
                    "Window cap unknown; remaining-percent bounds cannot be derived "
                    "from spend alone."
                )
            elif spend_min is None or spend_max is None:
                lower = None
                upper = None
                note = "Spend partially unknown; remaining-percent bounds withheld."
            else:
                upper = max(0.0, 100.0 * (1.0 - spend_min / cap))
                lower = max(0.0, 100.0 * (1.0 - spend_max / cap))
                note = (
                    f"Bounds derived from {spend_min:.6g}..{spend_max:.6g} USD spend "
                    f"against a {cap:.6g} USD cap; not an exact balance."
                )
        windows_out[window] = {
            "count": row["count"],
            "spend_min_usd": spend_min,
            "spend_max_usd": spend_max,
            "cap_amount": caps.get(window),
            "remaining_percent_bounds": {"lower": lower, "upper": upper},
            "attribution": attribution,
            "overlapping_attribution": row["overlapping"],
            "note": note,
        }

    return {
        "schema_version": SCHEMA_VERSION,
        "source": "receipt",
        "pool_id": POOL_ID,
        "scope_hash": scope_hash(scope_hint=scope_hint),
        "observed_at_utc": observed_at_utc or _now_utc(),
        "exact_balance_unavailable": True,
        "kind": "historical_spend_evidence",
        "note": (
            "Receipts and local stats are historical spend evidence only; they are "
            "never converted into a remaining balance."
        ),
        "windows": windows_out,
    }


def balance_state(records: Iterable[dict[str, Any]], now_utc: str | dt.datetime | None = None) -> str:
    """Return ``known`` only when fresh numeric remaining evidence exists."""
    for record in records:
        if is_stale(record, now_utc):
            continue
        if (
            record.get("exact_balance")
            and not record.get("discrepancy")
            and (record.get("remaining_percent") is not None or record.get("remaining_amount") is not None)
        ):
            return "known"
    return "unknown"


def effective_remaining_percent(
    records: Iterable[dict[str, Any]],
    now_utc: str | dt.datetime | None = None,
) -> float | None:
    """Minimum fresh remaining percent across windows; ``None`` when unknown.

    Mirrors the Antigravity pool rule: the lower window binds scheduling.
    """
    by_window: dict[str, list[float]] = {}
    for record in records:
        if is_stale(record, now_utc):
            continue
        percent = record.get("remaining_percent")
        window = record.get("window")
        if (
            record.get("exact_balance")
            and not record.get("discrepancy")
            and percent is not None
            and window in WINDOWS
        ):
            by_window.setdefault(window, []).append(float(percent))
    values = [min(items) for items in by_window.values() if items]
    return min(values) if values else None


def classify_runtime_failure(
    text: str,
    model_id: str,
    variant: str | None = None,
    observed_at_utc: str | None = None,
    pool_id: str = POOL_ID,
) -> dict[str, Any]:
    """Classify a runtime quota/rate-limit failure at the shared-pool level.

    The exact model and variant are retained inside the event.  Capability
    rejections (unsupported/not entitled model) are scoped to the exact model
    tuple and never cool the shared pool.
    """
    observed = _parse_utc(observed_at_utc) if observed_at_utc else dt.datetime.now(tz=dt.timezone.utc)
    observed_str = observed.isoformat()
    status_match = _STATUS_RE.search(text)
    status_hint = f"HTTP {status_match.group(1)}" if status_match else None

    rate = bool(_RATE_RE.search(text)) or (status_match and status_match.group(1) == "429")
    auth = bool(_AUTH_RE.search(text)) or (
        status_match and status_match.group(1) in ("401", "403") and not rate
    )
    quota = bool(_QUOTA_RE.search(text))
    location_restricted = bool(_LOCATION_RE.search(text))
    capability = bool(_CAPABILITY_RE.search(text))

    if rate:
        kind = "rate_limit"
        pool_level = True
        window_hint = _match_window_hint(text)
    elif auth:
        kind = "auth"
        pool_level = True
        window_hint = None
    elif quota:
        kind = "quota"
        pool_level = True
        window_hint = _match_window_hint(text)
    elif location_restricted:
        # Google/Gemini can reject an otherwise authenticated model because the
        # consumer API is unavailable in the account's serving region. This is
        # not a quota event and changing the Mac/server proxy does not prove a
        # recovery. Keep it exact-model scoped and require a supported-region
        # or enterprise/GCP configuration before another paid attempt.
        kind = "location_restricted"
        pool_level = False
        window_hint = None
    elif capability:
        kind = "capability"
        pool_level = False
        window_hint = None
    else:
        kind = "unclassified"
        pool_level = False
        window_hint = None

    reset_at_utc = None
    reset_estimated = False
    reset_delta_seconds: float | None = None
    retry = _RETRY_AFTER_RE.search(text)
    if retry:
        delta = dt.timedelta(seconds=float(retry.group(1)))
        reset_at_utc = (observed + delta).isoformat()
        reset_estimated = True
        reset_delta_seconds = float(retry.group(1))
    else:
        reset_in = _RESET_IN_RE.search(text)
        if reset_in:
            units = {"second": 1, "sec": 1, "s": 1, "minute": 60, "min": 60, "m": 60, "hour": 3600, "hr": 3600, "h": 3600}
            delta = dt.timedelta(seconds=float(reset_in.group(1)) * units[reset_in.group(2).lower()])
            reset_at_utc = (observed + delta).isoformat()
            reset_estimated = True
            reset_delta_seconds = float(reset_in.group(1)) * units[reset_in.group(2).lower()]
        else:
            reset_at = _RESET_AT_RE.search(text)
            if reset_at:
                try:
                    reset_at_utc = _parse_utc(reset_at.group(1)).isoformat()
                except (TypeError, ValueError):
                    reset_at_utc = None

    if window_hint is None and reset_delta_seconds is not None and reset_delta_seconds <= 24 * 3600:
        window_hint = "five_hour"

    event = {
        "model_id": model_id,
        "variant": variant,
        "pool_id": pool_id,
        "kind": kind,
        "pool_level": pool_level,
        "status_hint": status_hint,
        "window_hint": window_hint,
        "reset_at_utc": reset_at_utc,
        "reset_estimated": reset_estimated,
        "redacted_text": _redact_text(text),
    }
    if kind == "location_restricted":
        event.update(
            {
                "retryable": False,
                "route_change_required": True,
                "recovery_action": "gcp_project_or_supported_region",
            }
        )
    record = make_record(
        source="runtime_error",
        window=window_hint,
        observed_at_utc=observed_str,
        remaining_percent=None,
        remaining_amount=None,
        reset_at_utc=reset_at_utc,
        confidence=0.9 if pool_level else 0.7,
        ttl_seconds=RUNTIME_EVENT_TTL_SECONDS,
        discrepancy=False,
        attribution="unknown",
        exact_balance=False,
        overage_fallback_state="unknown",
        note=(
            f"Runtime failure classified as {kind} at "
            f"{'shared pool' if pool_level else 'exact model'} level; remaining "
            "balance is unknown and was not fabricated."
        ),
        event=event,
    )
    return {"record": record, "event": event}


def _match_window_hint(text: str) -> str | None:
    match = _WINDOW_HINT_RE.search(text)
    if not match:
        return None
    hint = match.group(0).lower()
    if "monthly" in hint:
        return "monthly"
    if "weekly" in hint:
        return "weekly"
    return "five_hour"


def effective_multiplier(
    model_id: str,
    model_multipliers: dict[str, float] | None,
    default_multiplier: float = 1.0,
) -> float:
    """Model-specific cost/usage multiplier with exact-over-family precedence.

    Exact model ID wins, then the longest key that is a prefix of the model ID
    (family or provider-wide), then the pool default.  Missing multipliers are
    never fabricated.
    """
    multipliers = {str(key): float(value) for key, value in (model_multipliers or {}).items()}
    if model_id in multipliers:
        return multipliers[model_id]
    prefixes = sorted(
        (key for key in multipliers if str(model_id).startswith(str(key))),
        key=len,
        reverse=True,
    )
    if prefixes:
        return multipliers[prefixes[0]]
    return float(default_multiplier)


def scale_cost(amount_usd: float | None, multiplier: float) -> float | None:
    """Apply a usage multiplier inside the shared pool; ``None`` stays ``None``."""
    if amount_usd is None:
        return None
    return float(amount_usd) * float(multiplier)


HEALTH_BANDS = (
    ("healthy", 70.0, 100.0),
    ("balanced", 40.0, 70.0),
    ("conserve", 15.0, 40.0),
    ("drain_preserve", 0.0, 15.0),
    ("blocked", None, 0.0),
)


def health_band(effective_percent: float | None) -> str:
    if effective_percent is None:
        return "unknown"
    for name, lower, upper in HEALTH_BANDS:
        if lower is None:
            if effective_percent <= upper:
                return name
        elif lower <= effective_percent < upper:
            return name
    return "healthy"


def pilot_decision(
    records: Iterable[dict[str, Any]],
    *,
    catalog_visible: bool = False,
    auth_state: str = "unknown",
    unknown_quota_policy: str | None = None,
    unknown_quota_pilot_percent: float | None = None,
    reserve_percent: float = 10.0,
    lanes: int = 1,
    lane_cost_cap_usd: float | None = None,
    lane_token_cap: int | None = None,
    now_utc: str | dt.datetime | None = None,
) -> dict[str, Any]:
    """Conservative pilot/cap decision; never ready from catalog visibility alone."""
    if lanes < 1:
        raise ValueError("lanes must be positive")
    if not 0.0 <= reserve_percent < 100.0:
        raise ValueError("reserve_percent must be in [0, 100)")
    if unknown_quota_pilot_percent is not None and not 0.0 < float(unknown_quota_pilot_percent) <= 100.0:
        raise ValueError("unknown_quota_pilot_percent must be in (0, 100]")

    fresh = [record for record in records if not is_stale(record, now_utc)]
    balance = balance_state(fresh, now_utc)
    effective = effective_remaining_percent(fresh, now_utc)
    blocked = any(
        record.get("exact_balance")
        and not record.get("discrepancy")
        and record.get("remaining_percent") is not None
        and float(record["remaining_percent"]) == 0.0
        for record in fresh
    )
    reasons: list[str] = []

    if blocked:
        reasons.append("A window reports exactly 0% remaining; shared pool blocked.")
    elif balance == "known":
        reasons.append("Fresh numeric remaining balance available from evidence records.")
    else:
        if unknown_quota_policy != "pilot":
            reasons.append(
                "Remaining balance is unknown and unknown_quota_policy is not 'pilot'; "
                "blocking instead of fabricating a balance."
            )
        elif not catalog_visible:
            reasons.append("Pilot requires catalog visibility; catalog is not visible.")
        elif auth_state != "configured":
            reasons.append("Pilot requires configured authentication; auth state is not 'configured'.")
        else:
            reasons.append(
                "Remaining balance unknown; explicit bounded pilot authorized with "
                f"pilot percent {unknown_quota_pilot_percent or 5.0:g}%."
            )

    if blocked:
        pilot_allowed = False
        decision_note = "Shared pool blocked by an exact 0% window."
    elif balance == "known":
        pilot_allowed = bool(effective is not None and effective > 0.0)
        decision_note = (
            f"Balance known ({effective:.4g}% effective); pilot "
            f"{'allowed' if pilot_allowed else 'withheld'}."
        )
    else:
        pilot_allowed = (
            unknown_quota_policy == "pilot"
            and catalog_visible
            and auth_state == "configured"
        )
        decision_note = (
            "Unknown balance; pilot allowed only because an explicit bounded "
            "pilot policy, catalog visibility, and configured authentication "
            "are all present."
        )

    ready_claim = balance == "known" and effective is not None and effective > reserve_percent and not blocked

    default_lane_cost = 2.0 if pilot_allowed else None
    default_lane_tokens = 500_000 if pilot_allowed else None
    per_lane = {
        "cost_cap_usd": lane_cost_cap_usd if lane_cost_cap_usd is not None else default_lane_cost,
        "token_cap": lane_token_cap if lane_token_cap is not None else default_lane_tokens,
        "max_attempts": 1,
    }

    return {
        "schema_version": SCHEMA_VERSION,
        "pool_id": POOL_ID,
        "balance_state": balance,
        "effective_remaining_percent": effective,
        "health_band": health_band(effective),
        "catalog_visible": bool(catalog_visible),
        "catalog_visibility_alone_does_not_set_ready": True,
        "pilot_allowed": pilot_allowed,
        "ready_claim": ready_claim,
        "blocked": blocked,
        "policy": {
            "unknown_quota_policy": unknown_quota_policy,
            "unknown_quota_pilot_percent": unknown_quota_pilot_percent,
            "reserve_percent": reserve_percent,
        },
        "per_lane_caps": per_lane,
        "reserve": {
            "percent": reserve_percent,
            "note": f"Reserve of {reserve_percent:g}% is excluded from ready_claim.",
        },
        "unknown_mapped_to_zero": False,
        "unknown_mapped_to_full": False,
        "note": decision_note,
        "reasons": reasons,
    }


def update_pool(pool: dict[str, Any], record: dict[str, Any]) -> dict[str, Any]:
    """Merge a quota-evidence record into the shared pool's quota state."""
    window = record.get("window")
    quota = pool.setdefault("quota", {"state": "unknown", "windows": {}})
    windows = quota.setdefault("windows", {})
    if window in WINDOWS:
        windows[window] = {
            "remaining_percent": record.get("remaining_percent"),
            "remaining_amount": record.get("remaining_amount"),
            "cap_amount": record.get("cap_amount"),
            "reset_at_utc": record.get("reset_at_utc"),
            "observed_at_utc": record.get("observed_at_utc"),
            "source": record.get("source"),
            "confidence": record.get("confidence"),
            "ttl_seconds": record.get("ttl_seconds"),
            "discrepancy": record.get("discrepancy"),
            "exact_balance": record.get("exact_balance"),
            "overage_fallback_state": record.get("overage_fallback_state"),
        }
    if record.get("remaining_percent") is not None or record.get("remaining_amount") is not None:
        quota["state"] = "known"
    quota["blocked"] = any(
        row.get("remaining_percent") == 0.0 for row in windows.values() if isinstance(row, dict)
    )
    if quota["blocked"]:
        quota["blocked_reason"] = "A fresh evidence window reports exactly 0% remaining."
        pool["health"] = "blocked"
    elif quota["state"] == "known":
        pool["health"] = "ready"
    return pool


def apply_pool_event(pool: dict[str, Any], event: dict[str, Any]) -> dict[str, Any]:
    """Apply a classified runtime event at the correct scope.

    Quota/rate/auth events cool or block the shared pool; capability and
    location events reject only the exact model tuple and leave pool health
    untouched.
    """
    events = pool.setdefault("recent_runtime_events", [])
    if event.get("pool_level"):
        pool["health"] = "cooldown"
        pool["runtime_state"] = {
            "rate_limit": "rate_limited",
            "quota": "quota_blocked",
            "auth": "auth_failed",
        }.get(event.get("kind"), "failed")
        pool["runtime_reason"] = (
            f"{event.get('kind')} at shared pool level; exact model "
            f"{event.get('model_id')}"
            + (f"/{event.get('variant')}" if event.get("variant") else "")
            + " retained in the event."
        )
        if event.get("kind") == "quota":
            quota = pool.setdefault("quota", {"state": "unknown", "windows": {}})
            quota["blocked"] = True
            quota.setdefault("blocked_reason", "Runtime quota failure at shared pool level.")
        if event.get("reset_at_utc") and event.get("window_hint") in WINDOWS:
            quota = pool.setdefault("quota", {"state": "unknown", "windows": {}})
            windows = quota.setdefault("windows", {})
            row = windows.setdefault(event["window_hint"], {})
            row.setdefault("reset_at_utc", event["reset_at_utc"])
            row["reset_estimated"] = bool(event.get("reset_estimated"))
    else:
        model_states = pool.setdefault("model_runtime_states", {})
        model_states[event.get("model_id")] = {
            "variant": event.get("variant"),
            "runtime_state": (
                "rejected"
                if event.get("kind") in {"capability", "location_restricted"}
                else "unknown"
            ),
            "kind": event.get("kind"),
            "pool_level": False,
            "reason": (
                "Location restriction requires a supported region or GCP/enterprise "
                "configuration before retry."
                if event.get("kind") == "location_restricted"
                else "Capability rejection affects only this exact model tuple."
            ),
        }
        for key in ("retryable", "route_change_required", "recovery_action"):
            if key in event:
                model_states[event.get("model_id")][key] = event[key]
    events.append(event)
    del events[:-5]
    return pool
