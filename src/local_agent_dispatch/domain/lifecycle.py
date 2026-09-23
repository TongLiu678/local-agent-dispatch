"""Explicit execution, validation, review, and claim lifecycle projection.

The dispatch controller stores more than one kind of completion evidence.  A
worker can finish execution without a validator having accepted its artifact,
and a validated artifact is still not a public claim until an approved review
has promoted it.  This module keeps those facts independent and can project
both EventV2 chains and the row evidence retained by the SQLite controller.

The projection is deliberately conservative: a validation result only counts
after execution completion, and the latest validation result wins.  Therefore
an old passing validation cannot hide a later failed re-check.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping


EVENT_STATUS: dict[str, str] = {
    "attempt.queued": "queued",
    "attempt.reserved": "reserved",
    "attempt.claimed": "claimed",
    "attempt.started": "started",
    "attempt.heartbeat": "started",
    "artifact.observed": "started",
    "attempt.validation": "started",
    "attempt.completed": "completed",
    "attempt.failed": "failed",
    "attempt.abandoned": "abandoned",
    "attempt.review": "review",
    "claim.promoted": "claim_promoted",
}

_EXECUTED_ATTEMPT_STATES = frozenset(
    {"running", "completed", "failed", "retry", "abandoned", "review"}
)
_JOB_EXECUTED_STATES = frozenset(
    {"running", "completed", "failed", "retry", "blocked", "pending"}
)


def _validation_outcome(value: Any) -> str:
    """Reduce a persisted validator result to an explicit outcome."""

    if not isinstance(value, Mapping):
        return "unknown"
    outcome = value.get("outcome") or value.get("status")
    if outcome in {"passed", "failed"}:
        return str(outcome)
    ok = value.get("ok")
    if ok is True:
        return "passed"
    if ok is False:
        return "failed"
    return "unknown"


def project_lifecycle(
    events: Iterable[Mapping[str, Any]] = (),
    *,
    job_status: str | None = None,
    attempt_status: str | None = None,
    validation: Any = None,
) -> dict[str, Any]:
    """Project independent lifecycle facts from event and row evidence.

    ``events`` must be in causal/append order.  ``job_status``,
    ``attempt_status`` and ``validation`` are optional SQLite row evidence;
    omitting them gives the EventV2-only projection used by the JSON ledger.
    The returned ``status`` is execution status (with review/promotion
    overlays), while ``validated`` and ``claim_promoted`` remain independent
    booleans.
    """

    chain = [dict(event) for event in events if isinstance(event, Mapping)]
    event_types = [str(event.get("event_type") or "") for event in chain]
    validation_events = [
        event for event in chain if event.get("event_type") == "attempt.validation"
    ]
    if validation_events:
        outcome = validation_events[-1].get("outcome")
        latest_validation = outcome if outcome in {"passed", "failed"} else "unknown"
    else:
        latest_validation = _validation_outcome(validation)

    raw_attempt = str(attempt_status or "").strip().lower()
    raw_job = str(job_status or "").strip().lower()
    event_completed = "attempt.completed" in event_types
    event_executed = any(
        event_type
        in {
            "attempt.started",
            "attempt.heartbeat",
            "artifact.observed",
            "attempt.validation",
            "attempt.completed",
            "attempt.failed",
            "attempt.abandoned",
        }
        for event_type in event_types
    )
    completed = event_completed or raw_attempt == "completed" or raw_job == "completed"
    executed = (
        event_executed
        or raw_attempt in _EXECUTED_ATTEMPT_STATES
        or raw_job in _JOB_EXECUTED_STATES
    )
    planned = bool(chain) or bool(raw_attempt) or bool(raw_job)

    reviews = [event for event in chain if event.get("event_type") == "attempt.review"]
    promoted = any(event.get("event_type") == "claim.promoted" for event in chain)
    review_decision = reviews[-1].get("decision", "unknown") if reviews else "unknown"
    validated = completed and latest_validation == "passed"

    if promoted:
        status = "claim_promoted"
    elif reviews:
        status = "review"
    elif raw_attempt in _EXECUTED_ATTEMPT_STATES or raw_attempt in {
        "queued",
        "reserved",
        "claimed",
    }:
        # A durable attempt row is stronger than the last validation event;
        # validation is allowed to arrive after execution completion.
        status = raw_attempt
    elif raw_job in _JOB_EXECUTED_STATES or raw_job in {"queued", "retry"}:
        status = raw_job
    elif chain:
        status = EVENT_STATUS.get(event_types[-1], "unknown")
    else:
        status = "unknown"

    execution_status = "completed" if completed else status
    if raw_attempt == "failed" or "attempt.failed" in event_types:
        execution_status = "failed"
    elif raw_attempt == "abandoned" or "attempt.abandoned" in event_types:
        execution_status = "abandoned"
    elif raw_attempt == "retry":
        execution_status = "retry"
    elif raw_attempt == "running" or raw_job == "running":
        execution_status = "running"

    return {
        "planned": planned,
        "executed": executed,
        "completed": completed,
        "validated": validated,
        "validation_outcome": latest_validation,
        "reviewed": bool(reviews),
        "review_decision": review_decision,
        "claim_promoted": promoted,
        "status": status,
        "execution_status": execution_status,
    }


__all__ = ["EVENT_STATUS", "project_lifecycle"]
