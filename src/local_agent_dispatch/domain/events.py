"""Causal provenance event model for the local-agent-dispatch ledger (v2).

Stdlib-only. Events are plain JSON-serializable dicts. The ledger boundary is
causal: every event references its causal parent (or explicit null), and the
store refuses orphans so state mutation and event append cannot diverge.
"""

from __future__ import annotations

import copy
import hashlib
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

SCHEMA_VERSION = 2

ATTEMPT_EVENT_TYPES: tuple[str, ...] = (
    "attempt.queued",
    "attempt.reserved",
    "attempt.claimed",
    "attempt.started",
    "attempt.heartbeat",
    "artifact.observed",
    "attempt.validation",
    "attempt.completed",
    "attempt.failed",
    "attempt.abandoned",
    "attempt.review",
    "claim.promoted",
    # Run-continuity records are causal EventV2 facts, not queue status
    # strings.  They remain prompt-free and can be replayed after a segment or
    # controller restart.
    "run.segment.started",
    "run.segment.finished",
    "run.segment.adopted",
    "checkpoint.recorded",
    "cleanup.intent",
)

EVENT_TYPES: tuple[str, ...] = ATTEMPT_EVENT_TYPES

ID_KINDS: tuple[str, ...] = (
    "mission",
    "task",
    "plan_revision",
    "assignment",
    "reservation",
    "attempt",
    "event",
    "observation",
    "artifact",
    "claim",
    "human_decision",
    "policy_version",
    "legacy",
    "reconcile",
)

PRIVACY_CLASSES: tuple[str, ...] = ("public", "internal", "private", "unknown")

REVIEW_DECISIONS: tuple[str, ...] = ("approve", "abandon", "reroute", "escalate")
VALIDATION_OUTCOMES: tuple[str, ...] = ("passed", "failed")

EVIDENCE_QUALITIES: tuple[str, ...] = (
    "full",
    "legacy_incomplete",
    "reconciled",
    "unknown",
)

_TIMESTAMP_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$"
)
_DIGEST_RE = re.compile(r"^(sha256:[0-9a-f]{64}|sha512:[0-9a-f]{128})$")

_DIGEST_FIELDS = (
    "cps_digest",
    "source_digest",
    "worktree_digest",
    "prompt_digest",
    "artifact_digest",
    "claim_contract_digest",
)

_STRING_REF_FIELDS = (
    "mission_id",
    "task_id",
    "plan_revision_id",
    "assignment_id",
    "reservation_id",
    "policy_version_id",
    "run_id",
    "segment_id",
    "checkpoint_id",
    "provider",
    "pool_id",
    "model_id",
    "model_variant",
    "execution_host",
    "workload_host",
    "mount",
    "route",
    "validator",
    "prompt_ref",
    "claim_id",
    "review_event_id",
)

_ATTEMPT_REQUIRED = ("attempt_id",)

_UUID_NAMESPACE = uuid.UUID("6f3c4b1e-7c2a-4d9e-8b51-0e2a9c7d4f16")


class ProvenanceValidationError(ValueError):
    """Raised when an event violates the provenance v2 contract."""


class StableIdError(ValueError):
    """Raised for an unknown stable ID kind."""


def digest(text: str) -> str:
    """Return a canonical sha256 content digest for a text body."""
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def stable_id(kind: str, *parts: str) -> str:
    """Deterministic, collision-resistant stable ID: ``<kind>:<uuid5>``.

    Identical inputs always produce identical IDs across machines, which makes
    re-imports and duplicates detectable without any shared sequence state.
    """
    if kind not in ID_KINDS:
        raise StableIdError(f"unknown stable ID kind: {kind!r}")
    joined = ":".join(parts)
    return f"{kind}:{uuid.uuid5(_UUID_NAMESPACE, joined)}"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_iso(timestamp: str) -> datetime:
    return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))


def new_event(
    *,
    event_type: str,
    source: str,
    idempotency_key: str,
    causal_parent: str | None,
    confidence: float,
    timestamp: str | None = None,
    privacy_class: str = "public",
    event_id: str | None = None,
    attempt_id: str | None = None,
    **payload: Any,
) -> dict[str, Any]:
    """Build a provenance event dict.

    ``event_id`` defaults to ``stable_id("event", idempotency_key)`` so that
    retries with the same idempotency key are recognised as the same event.
    """
    event: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "event_id": event_id or stable_id("event", idempotency_key),
        "event_type": event_type,
        "timestamp": timestamp or now_iso(),
        "causal_parent": causal_parent,
        "source": source,
        "confidence": confidence,
        "privacy_class": privacy_class,
        "idempotency_key": idempotency_key,
    }
    if attempt_id is not None:
        event["attempt_id"] = attempt_id
    event.update(payload)
    return event


def validate_event(event: Mapping[str, Any]) -> None:
    """Fail closed on any contract violation."""
    if not isinstance(event, Mapping):
        raise ProvenanceValidationError("event must be a mapping")

    if event.get("schema_version") != SCHEMA_VERSION:
        raise ProvenanceValidationError(
            f"unsupported schema_version: {event.get('schema_version')!r}"
        )

    event_type = event.get("event_type")
    if not isinstance(event_type, str) or event_type not in EVENT_TYPES:
        raise ProvenanceValidationError(
            f"unsupported event_type: {event_type!r}"
        )

    event_id = event.get("event_id")
    if not isinstance(event_id, str) or not event_id:
        raise ProvenanceValidationError("event_id must be a non-empty string")

    timestamp = event.get("timestamp")
    if not isinstance(timestamp, str) or not _TIMESTAMP_RE.match(timestamp):
        raise ProvenanceValidationError(
            f"timestamp must be RFC 3339: {timestamp!r}"
        )

    parent = event.get("causal_parent")
    if "causal_parent" not in event or (
        parent is not None and (not isinstance(parent, str) or not parent)
    ):
        raise ProvenanceValidationError(
            "causal_parent must be an event_id string or explicit null"
        )

    source = event.get("source")
    if not isinstance(source, str) or not source:
        raise ProvenanceValidationError("source must be a non-empty string")

    confidence = event.get("confidence")
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        raise ProvenanceValidationError("confidence must be a number")
    if not 0.0 <= float(confidence) <= 1.0:
        raise ProvenanceValidationError(
            f"confidence must be within [0, 1]: {confidence!r}"
        )

    privacy_class = event.get("privacy_class")
    if not isinstance(privacy_class, str) or privacy_class not in PRIVACY_CLASSES:
        raise ProvenanceValidationError(
            f"unsupported privacy_class: {privacy_class!r}"
        )

    idem = event.get("idempotency_key")
    if not isinstance(idem, str) or not idem:
        raise ProvenanceValidationError(
            "idempotency_key must be a non-empty string"
        )

    for field in _DIGEST_FIELDS:
        value = event.get(field)
        if value is not None and (
            not isinstance(value, str) or not _DIGEST_RE.match(value)
        ):
            raise ProvenanceValidationError(
                f"{field} must be a sha256/sha512 digest: {value!r}"
            )

    for field in _STRING_REF_FIELDS:
        value = event.get(field)
        if value is not None and (not isinstance(value, str) or not value):
            raise ProvenanceValidationError(
                f"{field} must be a non-empty string reference"
            )

    if event_type.startswith(("attempt.", "artifact.")):
        for field in _ATTEMPT_REQUIRED:
            value = event.get(field)
            if not isinstance(value, str) or not value:
                raise ProvenanceValidationError(
                    f"{event_type} requires a non-empty {field}"
                )

    if event_type == "artifact.observed":
        for field in ("artifact_id", "artifact_digest"):
            value = event.get(field)
            if not isinstance(value, str) or not value:
                raise ProvenanceValidationError(
                    f"{event_type} requires a non-empty {field}"
                )

    if event_type == "attempt.validation":
        outcome = event.get("outcome")
        if not isinstance(outcome, str) or outcome not in VALIDATION_OUTCOMES:
            raise ProvenanceValidationError(
                f"attempt.validation requires outcome in "
                f"{VALIDATION_OUTCOMES}: {outcome!r}"
            )

    if event_type == "attempt.review":
        decision = event.get("decision")
        if not isinstance(decision, str) or decision not in REVIEW_DECISIONS:
            raise ProvenanceValidationError(
                f"attempt.review requires decision in "
                f"{REVIEW_DECISIONS}: {decision!r}"
            )

    if event_type == "claim.promoted":
        for field in ("attempt_id", "claim_id", "review_event_id"):
            value = event.get(field)
            if not isinstance(value, str) or not value:
                raise ProvenanceValidationError(
                    f"claim.promoted requires a non-empty {field}"
                )
        digest_value = event.get("claim_contract_digest")
        if not isinstance(digest_value, str) or not _DIGEST_RE.match(digest_value):
            raise ProvenanceValidationError(
                "claim.promoted requires a claim_contract_digest"
            )
        if event.get("decision") != "approve":
            raise ProvenanceValidationError(
                "claim.promoted requires decision='approve'"
            )

    evidence_quality = event.get("evidence_quality")
    if evidence_quality is not None and evidence_quality not in EVIDENCE_QUALITIES:
        raise ProvenanceValidationError(
            f"unsupported evidence_quality: {evidence_quality!r}"
        )


def event_id_by_idempotency(event: Mapping[str, Any]) -> str:
    """Recompute the canonical event_id for an idempotency key."""
    return stable_id("event", event.get("idempotency_key", ""))


def iter_events(events: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Deterministic snapshot of an event iterable (deep copies)."""
    return [copy.deepcopy(dict(event)) for event in events]
