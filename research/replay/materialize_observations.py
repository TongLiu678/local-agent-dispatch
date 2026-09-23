"""Materialize estimator observations from attributed, validated attempts.

Only records that meet attribution and validation requirements become
observations: an exact model/provider/pool, a completed lifecycle, a recorded
artifact digest, and a passing validation (or none attempted). Everything else
is reported as excluded with a deterministic reason; unknown values are
preserved as ``"unknown"`` and legacy-incomplete evidence never becomes an
observation.
"""

from __future__ import annotations

from typing import Any

from local_agent_dispatch.domain import events as ev
from local_agent_dispatch.ledger.projections import attempt_summary
from local_agent_dispatch.ledger.store import EventStore

_OBSERVATION_FIELDS = (
    "attempt_id",
    "task_id",
    "mission_id",
    "plan_revision_id",
    "assignment_id",
    "policy_version_id",
    "model_id",
    "provider",
    "pool_id",
    "model_variant",
    "cps_digest",
    "execution_host",
    "workload_host",
    "mount",
    "route",
    "duration_seconds",
    "evidence_quality",
    "validation_outcome",
)


def _attribution_reasons(summary: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    if summary["model_id"] == "unknown":
        reasons.append("missing_model_id")
    if summary["provider"] == "unknown":
        reasons.append("missing_provider")
    if summary["pool_id"] == "unknown":
        reasons.append("missing_pool_id")
    return reasons


def materialize_estimator_observations(
    store: EventStore,
    *,
    require_validation: bool = True,
    require_claim_promotion: bool = False,
    exclude_legacy: bool = True,
) -> dict[str, Any]:
    """Deterministic, ordered extraction of estimator observations.

    The returned mapping contains ``observations`` and ``excluded`` lists;
    both are ordered by first-seen attempt order.
    """
    observations: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []

    for attempt_id in store.attempt_ids():
        summary = attempt_summary(store, attempt_id)
        reasons: list[str] = []

        if summary["status"] not in {"completed", "claim_promoted"}:
            reasons.append("not_completed")
        if exclude_legacy and summary["evidence_quality"] == "legacy_incomplete":
            reasons.append("legacy_incomplete")
        reasons.extend(_attribution_reasons(summary))
        if not summary["artifact_digests"]:
            reasons.append("no_artifact_digest")
        if require_validation:
            if summary["validation_outcome"] == "failed":
                reasons.append("validation_failed")
            elif summary["validation_outcome"] == "unknown":
                reasons.append("unvalidated")
        if require_claim_promotion and summary["claim_status"] != "promoted":
            reasons.append("claim_not_promoted")

        if reasons:
            excluded.append(
                {
                    "attempt_id": attempt_id,
                    "status": summary["status"],
                    "model_id": summary["model_id"],
                    "evidence_quality": summary["evidence_quality"],
                    "reason": sorted(set(reasons)),
                }
            )
            continue

        observation: dict[str, Any] = {
            field: summary[field] for field in _OBSERVATION_FIELDS
        }
        observation["artifact_digests"] = list(summary["artifact_digests"])
        observation["confidence"] = summary["confidence"]
        observation["sources"] = list(summary["sources"])
        observations.append(observation)

    return {
        "schema_version": ev.SCHEMA_VERSION,
        "observation_count": len(observations),
        "excluded_count": len(excluded),
        "observations": observations,
        "excluded": excluded,
    }
