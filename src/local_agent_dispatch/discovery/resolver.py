"""Search-first evidence resolver for provider and host compatibility.

This module deliberately does not perform web requests, invoke a provider, or
read credentials.  It turns a question into a bounded search/probe plan and
resolves already-collected, redacted evidence.  A caller may use a separate
approved adapter to execute the returned probe plan.

The important invariant is that catalog visibility is not runtime acceptance,
and runtime acceptance is not quota readiness.  Conflicting or stale claims
remain explicit instead of being averaged into a fabricated ``ready`` value.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
from typing import Any, Iterable, Mapping, Sequence

SCHEMA_VERSION = 1

SOURCE_PRIORITY: dict[str, int] = {
    "official_source": 100,
    "official_docs": 95,
    "official_release": 90,
    "official_issue_pr": 82,
    "local_cli": 72,
    "runtime": 68,
    "manual": 50,
    "community": 10,
}

SENSITIVE_KEY_RE = re.compile(
    r"(?:^|[_-])(api[_-]?key|token|secret|password|credential|authorization|cookie|private[_-]?key)(?:$|[_-])",
    re.I,
)


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _iso(value: Any | None) -> str:
    if value is None:
        return _now().isoformat()
    if isinstance(value, dt.datetime):
        parsed = value
    else:
        parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc).isoformat()


def _safe_scalar(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        # URLs are useful provenance (for example two competing endpoint
        # claims), so preserve their host/path.  Credential-bearing query
        # values are still removed by the token/key patterns below.
        text = value
        text = re.sub(r"(?i)\bBearer\s+\S+", "Bearer <redacted>", text)
        text = re.sub(
            r"(?i)(api[-_]?key|token|secret|password|authorization)\s*[:=]\s*[^\s,;]+",
            r"\1=<redacted>",
            text,
        )
        return text[:1000]
    return str(value)[:1000]


def _redact(value: Any, path: str = "") -> Any:
    """Return JSON-safe metadata without credential-like fields or values."""
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for raw_key, raw_value in value.items():
            key = str(raw_key)
            if SENSITIVE_KEY_RE.search(key):
                result[key] = "<redacted>"
            else:
                result[key] = _redact(raw_value, f"{path}.{key}" if path else key)
        return result
    if isinstance(value, (list, tuple)):
        return [_redact(item, f"{path}[{index}]") for index, item in enumerate(value)]
    return _safe_scalar(value)


def _canonical(value: Any) -> str:
    return json.dumps(_redact(value), sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _source_kind(record: Mapping[str, Any]) -> str:
    return str(record.get("source_kind") or record.get("source") or "community")


def _scope_match(record: Mapping[str, Any], question: Mapping[str, Any]) -> bool:
    for key in ("provider", "model", "variant", "host"):
        expected = question.get(key)
        if expected is None:
            continue
        observed = record.get(key)
        if observed is not None and str(observed) != str(expected):
            return False
    return True


def _stale(record: Mapping[str, Any], now: dt.datetime) -> bool:
    try:
        observed = dt.datetime.fromisoformat(str(record["observed_at_utc"]).replace("Z", "+00:00"))
        if observed.tzinfo is None:
            observed = observed.replace(tzinfo=dt.timezone.utc)
        ttl = int(record.get("ttl_seconds", 0))
        return ttl <= 0 or observed.astimezone(dt.timezone.utc) + dt.timedelta(seconds=ttl) < now
    except (KeyError, TypeError, ValueError, OverflowError):
        return True


def _claim_value(record: Mapping[str, Any]) -> Any:
    if "claim" in record:
        return record.get("claim")
    if "value" in record:
        return record.get("value")
    if "status" in record:
        return record.get("status")
    return None


def _claim_key(record: Mapping[str, Any]) -> str:
    return _canonical(_claim_value(record))


def _rank(record: Mapping[str, Any], question: Mapping[str, Any], now: dt.datetime) -> tuple[int, int, float, str]:
    kind = _source_kind(record)
    version_bonus = 0
    requested_version = question.get("version")
    observed_version = record.get("version")
    if requested_version and observed_version:
        version_bonus = 20 if str(requested_version) == str(observed_version) else -20
    fresh_bonus = 10 if not _stale(record, now) else -100
    try:
        confidence = float(record.get("confidence", 0.0))
    except (TypeError, ValueError):
        confidence = 0.0
    return (SOURCE_PRIORITY.get(kind, 0) + version_bonus + fresh_bonus, int(not _stale(record, now)), confidence, str(record.get("observed_at_utc", "")))


def build_search_plan(
    *,
    provider: str,
    capability: str,
    version: str | None = None,
    model: str | None = None,
    host: str | None = None,
    official_domains: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Build deterministic search queries before any runtime probe.

    The plan is intentionally a set of hints, not search results.  A web
    adapter can execute it under its own domain/egress policy and return
    redacted source records to :func:`resolve_capability`.
    """
    provider_text = " ".join(item for item in (provider, version or "", model or "", capability) if item)
    domains = list(official_domains or (f"{provider}.com", f"github.com/{provider}"))
    queries = [
        {"source_kind": "official_docs", "query": f"site:{domains[0]} {provider_text}"},
        {"source_kind": "official_source", "query": f"site:{domains[-1]} {provider_text} endpoint API"},
        {"source_kind": "official_release", "query": f"{provider_text} release changelog"},
        {"source_kind": "official_issue_pr", "query": f"{provider_text} issue pull request {capability}"},
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "evidence_search_plan",
        "provider": provider,
        "capability": capability,
        "version": version,
        "model": model,
        "host": host,
        "official_domains": domains,
        "queries": queries,
        "source_priority": dict(SOURCE_PRIORITY),
        "network_side_effect": "read_only_search_only",
        "probe_requires_explicit_opt_in": True,
        "plan_digest": _digest({"provider": provider, "capability": capability, "version": version, "model": model, "host": host, "queries": queries}),
    }


def build_probe_plan(
    *,
    executable: Sequence[str],
    cwd: str | None = None,
    timeout_seconds: int = 20,
    side_effect_class: str = "read_only_local",
    credential_boundary: str = "none",
    requires_explicit_opt_in: bool = True,
) -> dict[str, Any]:
    """Describe an allowlisted bounded probe without executing it."""
    if not executable or any(not isinstance(item, str) or not item for item in executable):
        raise ValueError("probe executable must be a non-empty argv list")
    if timeout_seconds <= 0 or timeout_seconds > 300:
        raise ValueError("probe timeout must be in 1..300 seconds")
    if side_effect_class not in {"read_only_local", "read_only_authenticated", "runtime_smoke"}:
        raise ValueError(f"unsupported side_effect_class: {side_effect_class!r}")
    if credential_boundary not in {"none", "named_env", "auth_store", "operator_supplied"}:
        raise ValueError(f"unsupported credential_boundary: {credential_boundary!r}")
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "evidence_probe_plan",
        "argv": list(executable),
        "cwd": cwd,
        "timeout_seconds": int(timeout_seconds),
        "side_effect_class": side_effect_class,
        "credential_boundary": credential_boundary,
        "requires_explicit_opt_in": bool(requires_explicit_opt_in),
        "prompt_allowed": False,
        "network_route": "provider_default_or_declared",
        "plan_digest": _digest({"argv": list(executable), "cwd": cwd, "timeout_seconds": timeout_seconds, "side_effect_class": side_effect_class, "credential_boundary": credential_boundary}),
    }


def resolve_capability(
    question: Mapping[str, Any],
    records: Iterable[Mapping[str, Any]],
    *,
    now_utc: str | dt.datetime | None = None,
) -> dict[str, Any]:
    """Resolve one capability from redacted evidence records.

    ``status``/``claim`` values are kept as observed.  If fresh, in-scope
    records disagree, the result is ``conflict`` and the value is unknown.
    Stale records are retained for audit but cannot make a capability ready.
    """
    now = _now() if now_utc is None else dt.datetime.fromisoformat(str(now_utc).replace("Z", "+00:00")) if not isinstance(now_utc, dt.datetime) else now_utc
    if now.tzinfo is None:
        now = now.replace(tzinfo=dt.timezone.utc)
    capability = str(question.get("capability") or "")
    provider = question.get("provider")
    candidates: list[dict[str, Any]] = []
    discarded: list[dict[str, Any]] = []
    for raw in records:
        record = dict(_redact(dict(raw)))
        if record.get("capability") != capability or (provider is not None and record.get("provider") != provider):
            continue
        if not _scope_match(record, question):
            discarded.append({"reason": "scope_mismatch", "evidence_id": record.get("evidence_id")})
            continue
        record["stale"] = _stale(record, now)
        record["usable"] = not record["stale"] and _source_kind(record) in SOURCE_PRIORITY
        if record["usable"]:
            candidates.append(record)
        else:
            discarded.append({"reason": "stale_or_unknown_source", "evidence_id": record.get("evidence_id"), "source_kind": _source_kind(record)})

    ranked = sorted(candidates, key=lambda row: _rank(row, question, now), reverse=True)
    claim_groups: dict[str, list[dict[str, Any]]] = {}
    for row in ranked:
        claim_groups.setdefault(_claim_key(row), []).append(row)
    conflict = len(claim_groups) > 1
    selected = ranked[0] if ranked and not conflict else None
    if conflict:
        state = "conflict"
    elif selected is not None:
        state = "known"
    elif discarded:
        state = "stale_or_out_of_scope"
    else:
        state = "search_required"
    confidence = 0.0 if selected is None or conflict else float(selected.get("confidence", 0.0) or 0.0)
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "capability_resolution",
        "question": _redact(dict(question)),
        "capability": capability,
        "provider": provider,
        "state": state,
        "resolved": selected is not None,
        "value": None if selected is None else _claim_value(selected),
        "selected_evidence": selected,
        "candidate_count": len(candidates),
        "discarded": discarded,
        "conflict_claims": sorted(claim_groups) if conflict else [],
        "confidence": max(0.0, min(1.0, confidence)),
        "decision_digest": _digest({"question": question, "state": state, "value": None if selected is None else _claim_value(selected), "conflict_claims": sorted(claim_groups)}),
    }


def resolve_gate(
    records: Iterable[Mapping[str, Any]],
    *,
    required_statuses: Sequence[str],
    question: Mapping[str, Any] | None = None,
    now_utc: str | dt.datetime | None = None,
) -> dict[str, Any]:
    """Evaluate a readiness gate without treating visibility as readiness."""
    question = dict(question or {})
    question.setdefault("capability", "status")
    resolutions: dict[str, dict[str, Any]] = {}
    all_records = list(records)
    for required in required_statuses:
        scoped = [dict(item, capability="status", claim=required) for item in all_records if item.get("status") == required or item.get("claim") == required]
        resolutions[required] = resolve_capability(question, scoped, now_utc=now_utc)
    missing = [name for name, resolution in resolutions.items() if not resolution["resolved"]]
    ready = not missing and all(resolution["state"] == "known" for resolution in resolutions.values())
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "capability_gate",
        "ready": ready,
        "required_statuses": list(required_statuses),
        "missing": missing,
        "resolutions": resolutions,
        "note": "Catalog visibility alone never satisfies an accepted/quota/readiness gate.",
    }


__all__ = ["build_probe_plan", "build_search_plan", "resolve_capability", "resolve_gate"]
