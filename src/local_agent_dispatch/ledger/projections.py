"""Deterministic public projections over the provenance ledger.

Public projections redact prompt bodies, credentials, and raw pids, keeping
only references and digests. Missing values are preserved as the string
``"unknown"``; the projection never guesses a value and never drops an unknown
so that evidence gaps stay visible.
"""

from __future__ import annotations

import copy
from typing import Any, Mapping

from ..domain import events as ev
from ..domain.lifecycle import project_lifecycle
from .store import EventStore

SECRET_KEYS = frozenset(
    {
        "prompt_body",
        "context_body",
        "prompt",
        "prompt_text",
        "credentials",
        "credential",
        "api_key",
        "auth_token",
        "access_token",
        "secret",
        "password",
        "ssh_key",
        "pid",
    }
)

_SCALAR_SUMMARY_FIELDS = (
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
    "cps_digest",
    "source_digest",
    "worktree_digest",
    "execution_host",
    "workload_host",
    "mount",
    "route",
    "validator",
    "evidence_quality",
    "prompt_ref",
    "prompt_digest",
    "claim_id",
    "claim_contract_digest",
    "review_event_id",
)

_START_EVENT_TYPES = ("attempt.started",)
_END_EVENT_TYPES = (
    "attempt.completed",
    "attempt.failed",
    "attempt.abandoned",
    "attempt.review",
    "claim.promoted",
)


def redact_event(event: Mapping[str, Any]) -> dict[str, Any]:
    """Deep-copy an event with secret keys removed at every nesting level."""
    def _redact(node: Any) -> Any:
        if isinstance(node, dict):
            return {
                key: _redact(value)
                for key, value in node.items()
                if key not in SECRET_KEYS
            }
        if isinstance(node, list):
            return [_redact(item) for item in node]
        return copy.deepcopy(node)

    return _redact(dict(event))


def redacted_public_events(store: EventStore) -> list[dict[str, Any]]:
    return [redact_event(event) for event in store.events()]


def attempt_events(store: EventStore, attempt_id: str) -> list[dict[str, Any]]:
    """Redacted events for one attempt in causal append order."""
    return [
        redact_event(event)
        for event in store.project_attempt_chain(attempt_id)
    ]


def attempt_status(store: EventStore, attempt_id: str) -> str:
    """Deterministic status: last event in append order wins; no events is
    ``"unknown"``. Never inferred beyond what the ledger states."""
    chain = store.project_attempt_chain(attempt_id)
    if not chain:
        return "unknown"
    return project_lifecycle(chain)["status"]


def validation_outcome(store: EventStore, attempt_id: str) -> str:
    """``"passed"``/``"failed"`` from the latest validation event, else
    ``"unknown"`` (preserved, not guessed)."""
    outcome = "unknown"
    for event in store.project_attempt_chain(attempt_id):
        if event["event_type"] == "attempt.validation":
            outcome = event.get("outcome", "unknown")
    return outcome


def lifecycle_truth(store: EventStore, attempt_id: str) -> dict[str, Any]:
    """Project lifecycle facts as independent evidence booleans.

    A terminal controller event is deliberately not treated as validation or
    a public claim.  The fields are monotone facts over the causal chain;
    review and promotion remain separate so a later escalation cannot be
    hidden by an earlier approval.
    """
    chain = store.project_attempt_chain(attempt_id)
    projection = project_lifecycle(chain)
    return {
        field: projection[field]
        for field in (
            "planned",
            "executed",
            "completed",
            "validated",
            "reviewed",
            "review_decision",
            "claim_promoted",
        )
    }


def _first_value(chain: list[dict[str, Any]], key: str, default: Any = None) -> Any:
    for event in chain:
        if key in event:
            return event[key]
    return default


def attempt_summary(store: EventStore, attempt_id: str) -> dict[str, Any]:
    """Deterministic redacted summary; missing scalars become ``"unknown"``."""
    chain = store.project_attempt_chain(attempt_id)
    status = attempt_status(store, attempt_id)
    summary: dict[str, Any] = {
        "attempt_id": attempt_id,
        "status": status,
        "validation_outcome": validation_outcome(store, attempt_id),
        "lifecycle": lifecycle_truth(store, attempt_id),
        "event_ids": [event["event_id"] for event in chain],
        "sources": [],
        "artifact_digests": [],
        "claim_status": "not_promoted",
    }
    for field in _SCALAR_SUMMARY_FIELDS:
        value = _first_value(chain, field, None)
        if not isinstance(value, str) or not value:
            summary[field] = "unknown"
        else:
            summary[field] = value

    seen_sources: set[str] = set()
    for event in chain:
        source = event.get("source")
        if isinstance(source, str) and source not in seen_sources:
            seen_sources.add(source)
            summary["sources"].append(source)

    for event in chain:
        if event["event_type"] == "artifact.observed":
            digest_value = event.get("artifact_digest")
            if isinstance(digest_value, str) and digest_value not in summary["artifact_digests"]:
                summary["artifact_digests"].append(digest_value)

    if any(event["event_type"] == "claim.promoted" for event in chain):
        summary["claim_status"] = "promoted"

    confidence = _first_value(chain, "confidence", None)
    summary["confidence"] = (
        confidence if isinstance(confidence, (int, float)) else "unknown"
    )

    summary["started_at"] = "unknown"
    summary["ended_at"] = "unknown"
    summary["duration_seconds"] = "unknown"
    for event in chain:
        if event["event_type"] in _START_EVENT_TYPES:
            summary["started_at"] = event["timestamp"]
    for event in chain:
        if event["event_type"] in _END_EVENT_TYPES:
            summary["ended_at"] = event["timestamp"]
    if summary["started_at"] != "unknown" and summary["ended_at"] != "unknown":
        try:
            seconds = (
                ev.parse_iso(summary["ended_at"]) - ev.parse_iso(summary["started_at"])
            ).total_seconds()
            summary["duration_seconds"] = seconds
        except ValueError:
            summary["duration_seconds"] = "unknown"
    return summary


def project_public(store: EventStore) -> dict[str, Any]:
    """Full deterministic public projection: redacted events plus attempt
    summaries, in first-seen order. Identical stores project identically."""
    attempts = [
        attempt_summary(store, attempt_id) for attempt_id in store.attempt_ids()
    ]
    return {
        "schema_version": ev.SCHEMA_VERSION,
        "event_count": len(store),
        "attempt_ids": store.attempt_ids(),
        "events": redacted_public_events(store),
        "attempts": attempts,
    }


def has_secret_keys(node: Any) -> bool:
    """True if any secret key survives at any depth (used by tests/audits)."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key in SECRET_KEYS or isinstance(value, dict) and has_secret_keys(value):
                return True
            if isinstance(value, list) and any(has_secret_keys(item) for item in value):
                return True
    return False
