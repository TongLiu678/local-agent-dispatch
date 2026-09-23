"""Pure outcome, lineage, and skill-evolution proposal data.

This module proposes metadata changes only.  It has no filesystem, package
installation, import, subprocess, network, or repository mutation capability.
Applying a proposal is a separate, explicitly authorized review boundary.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal

from ..packages.manifest import version_satisfies
from .composition import CompositionPlan, SkillIndexFreshnessError
from .models import (
    SKILL_SCHEMA_VERSION,
    SkillIndexSnapshot,
    SkillValidationError,
    _identifier,
    _number,
    _semantic_version,
    _strict_object,
    _string_tuple,
    _tag,
    _timestamp,
    parse_timestamp,
)


SKILL_OUTCOME_API_VERSION = "local-agent-dispatch.skill-outcome.v1"
SKILL_LINEAGE_API_VERSION = "local-agent-dispatch.skill-lineage.v1"
SKILL_EVOLUTION_API_VERSION = "local-agent-dispatch.skill-evolution-proposal.v1"

OutcomeStatus = Literal["success", "partial", "failure"]
EvolutionOperation = Literal["revise_metadata", "merge_metadata", "split_metadata"]
LineageOperation = Literal["create", "revise", "merge", "split"]


class EvolutionError(RuntimeError):
    """Fresh evidence cannot produce a safe evolution proposal."""


@dataclass(frozen=True, kw_only=True)
class SkillRef:
    skill_id: str
    version: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "skill_id", _identifier(self.skill_id, "skill_id"))
        object.__setattr__(self, "version", _semantic_version(self.version))

    def to_dict(self) -> dict[str, str]:
        return {"skill_id": self.skill_id, "version": self.version}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SkillRef":
        data = _strict_object(
            value,
            required=frozenset({"skill_id", "version"}),
            label="SkillRef",
        )
        return cls(skill_id=data["skill_id"], version=data["version"])


@dataclass(frozen=True, kw_only=True)
class SkillOutcome:
    outcome_id: str
    plan_id: str
    skills: tuple[SkillRef, ...]
    observed_at: str
    status: OutcomeStatus
    quality_score: float | None
    latency_ms: float | None
    actual_cost: float | None
    failure_codes: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    schema_version: int = SKILL_SCHEMA_VERSION
    api_version: str = SKILL_OUTCOME_API_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != 1 or isinstance(self.schema_version, bool):
            raise SkillValidationError("schema_version must equal 1")
        if self.api_version != SKILL_OUTCOME_API_VERSION:
            raise SkillValidationError("invalid outcome api_version")
        object.__setattr__(self, "outcome_id", _identifier(self.outcome_id, "outcome_id"))
        object.__setattr__(self, "plan_id", _identifier(self.plan_id, "plan_id"))
        object.__setattr__(self, "skills", tuple(self.skills))
        if not self.skills or not all(isinstance(item, SkillRef) for item in self.skills):
            raise SkillValidationError("skills must be a non-empty array of SkillRef")
        if len(set(self.skills)) != len(self.skills):
            raise SkillValidationError("skills must not contain duplicates")
        object.__setattr__(self, "observed_at", _timestamp(self.observed_at, "observed_at"))
        if not isinstance(self.status, str) or self.status not in {
            "success",
            "partial",
            "failure",
        }:
            raise SkillValidationError("status is not recognized")
        if self.quality_score is not None:
            object.__setattr__(
                self,
                "quality_score",
                _number(self.quality_score, "quality_score", minimum=0, maximum=1),
            )
        if self.latency_ms is not None:
            object.__setattr__(
                self, "latency_ms", _number(self.latency_ms, "latency_ms", minimum=0)
            )
        if self.actual_cost is not None:
            object.__setattr__(
                self, "actual_cost", _number(self.actual_cost, "actual_cost", minimum=0)
            )
        object.__setattr__(
            self,
            "failure_codes",
            _string_tuple(self.failure_codes, "failure_codes"),
        )
        object.__setattr__(
            self,
            "evidence_refs",
            _string_tuple(
                self.evidence_refs, "evidence_refs", item_validator=_identifier
            ),
        )
        if self.status == "failure" and not self.failure_codes:
            raise SkillValidationError("failure outcomes require a failure code")
        if self.status == "success" and self.failure_codes:
            raise SkillValidationError("success outcomes cannot contain failure codes")
        if not self.evidence_refs:
            raise SkillValidationError("outcomes require at least one evidence reference")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "api_version": self.api_version,
            "outcome_id": self.outcome_id,
            "plan_id": self.plan_id,
            "skills": [item.to_dict() for item in self.skills],
            "observed_at": self.observed_at,
            "status": self.status,
            "quality_score": self.quality_score,
            "latency_ms": self.latency_ms,
            "actual_cost": self.actual_cost,
            "failure_codes": list(self.failure_codes),
            "evidence_refs": list(self.evidence_refs),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SkillOutcome":
        fields = frozenset(
            {
                "schema_version",
                "api_version",
                "outcome_id",
                "plan_id",
                "skills",
                "observed_at",
                "status",
                "quality_score",
                "latency_ms",
                "actual_cost",
                "failure_codes",
                "evidence_refs",
            }
        )
        data = _strict_object(value, required=fields, label="SkillOutcome")
        if isinstance(data["skills"], (str, bytes)) or not isinstance(
            data["skills"], Sequence
        ):
            raise SkillValidationError("skills must be an array")
        return cls(
            schema_version=data["schema_version"],
            api_version=data["api_version"],
            outcome_id=data["outcome_id"],
            plan_id=data["plan_id"],
            skills=tuple(SkillRef.from_dict(item) for item in data["skills"]),
            observed_at=data["observed_at"],
            status=data["status"],
            quality_score=data["quality_score"],
            latency_ms=data["latency_ms"],
            actual_cost=data["actual_cost"],
            failure_codes=_string_tuple(data["failure_codes"], "failure_codes"),
            evidence_refs=_string_tuple(
                data["evidence_refs"], "evidence_refs", item_validator=_identifier
            ),
        )


@dataclass(frozen=True, kw_only=True)
class SkillEvolutionProposal:
    proposal_id: str
    created_at: str
    target: SkillRef
    operation: EvolutionOperation
    based_on_outcome_ids: tuple[str, ...]
    capability_additions: tuple[str, ...]
    capability_removals: tuple[str, ...]
    facet_additions: tuple[str, ...]
    facet_removals: tuple[str, ...]
    estimated_cost_delta: float
    uncertainty_delta: float
    rationale_codes: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    status: Literal["proposed"] = "proposed"
    schema_version: int = SKILL_SCHEMA_VERSION
    api_version: str = SKILL_EVOLUTION_API_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != 1 or isinstance(self.schema_version, bool):
            raise SkillValidationError("schema_version must equal 1")
        if self.api_version != SKILL_EVOLUTION_API_VERSION:
            raise SkillValidationError("invalid evolution proposal api_version")
        object.__setattr__(
            self, "proposal_id", _identifier(self.proposal_id, "proposal_id")
        )
        object.__setattr__(self, "created_at", _timestamp(self.created_at, "created_at"))
        if not isinstance(self.target, SkillRef):
            raise SkillValidationError("target must be a SkillRef")
        if not isinstance(self.operation, str) or self.operation not in {
            "revise_metadata",
            "merge_metadata",
            "split_metadata",
        }:
            raise SkillValidationError("operation is not recognized")
        for field_name in (
            "based_on_outcome_ids",
            "capability_additions",
            "capability_removals",
            "facet_additions",
            "facet_removals",
            "rationale_codes",
            "evidence_refs",
        ):
            if field_name in {
                "capability_additions",
                "capability_removals",
                "facet_additions",
                "facet_removals",
            }:
                validator = _tag
            else:
                validator = _identifier
            object.__setattr__(
                self,
                field_name,
                _string_tuple(
                    getattr(self, field_name),
                    field_name,
                    item_validator=validator,
                ),
            )
        if (
            not self.based_on_outcome_ids
            or not self.rationale_codes
            or not self.evidence_refs
        ):
            raise SkillValidationError(
                "proposal requires outcomes, rationale codes, and evidence references"
            )
        if set(self.capability_additions) & set(self.capability_removals):
            raise SkillValidationError("capability additions/removals overlap")
        if set(self.facet_additions) & set(self.facet_removals):
            raise SkillValidationError("facet additions/removals overlap")
        object.__setattr__(
            self,
            "estimated_cost_delta",
            _number(self.estimated_cost_delta, "estimated_cost_delta"),
        )
        object.__setattr__(
            self,
            "uncertainty_delta",
            _number(
                self.uncertainty_delta,
                "uncertainty_delta",
                minimum=-1,
                maximum=1,
            ),
        )
        if not isinstance(self.status, str) or self.status != "proposed":
            raise SkillValidationError("status must remain proposed")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "api_version": self.api_version,
            "proposal_id": self.proposal_id,
            "created_at": self.created_at,
            "target": self.target.to_dict(),
            "operation": self.operation,
            "based_on_outcome_ids": list(self.based_on_outcome_ids),
            "capability_additions": list(self.capability_additions),
            "capability_removals": list(self.capability_removals),
            "facet_additions": list(self.facet_additions),
            "facet_removals": list(self.facet_removals),
            "estimated_cost_delta": self.estimated_cost_delta,
            "uncertainty_delta": self.uncertainty_delta,
            "rationale_codes": list(self.rationale_codes),
            "evidence_refs": list(self.evidence_refs),
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SkillEvolutionProposal":
        fields = frozenset(
            {
                "schema_version",
                "api_version",
                "proposal_id",
                "created_at",
                "target",
                "operation",
                "based_on_outcome_ids",
                "capability_additions",
                "capability_removals",
                "facet_additions",
                "facet_removals",
                "estimated_cost_delta",
                "uncertainty_delta",
                "rationale_codes",
                "evidence_refs",
                "status",
            }
        )
        data = _strict_object(value, required=fields, label="SkillEvolutionProposal")
        return cls(
            schema_version=data["schema_version"],
            api_version=data["api_version"],
            proposal_id=data["proposal_id"],
            created_at=data["created_at"],
            target=SkillRef.from_dict(data["target"]),
            operation=data["operation"],
            based_on_outcome_ids=_string_tuple(
                data["based_on_outcome_ids"],
                "based_on_outcome_ids",
                item_validator=_identifier,
            ),
            capability_additions=_string_tuple(
                data["capability_additions"],
                "capability_additions",
                item_validator=_tag,
            ),
            capability_removals=_string_tuple(
                data["capability_removals"],
                "capability_removals",
                item_validator=_tag,
            ),
            facet_additions=_string_tuple(
                data["facet_additions"], "facet_additions", item_validator=_tag
            ),
            facet_removals=_string_tuple(
                data["facet_removals"], "facet_removals", item_validator=_tag
            ),
            estimated_cost_delta=data["estimated_cost_delta"],
            uncertainty_delta=data["uncertainty_delta"],
            rationale_codes=_string_tuple(
                data["rationale_codes"],
                "rationale_codes",
                item_validator=_identifier,
            ),
            evidence_refs=_string_tuple(
                data["evidence_refs"], "evidence_refs", item_validator=_identifier
            ),
            status=data["status"],
        )


@dataclass(frozen=True, kw_only=True)
class SkillLineage:
    lineage_id: str
    child: SkillRef
    parents: tuple[SkillRef, ...]
    operation: LineageOperation
    created_at: str
    proposal_id: str
    evidence_refs: tuple[str, ...]
    schema_version: int = SKILL_SCHEMA_VERSION
    api_version: str = SKILL_LINEAGE_API_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != 1 or isinstance(self.schema_version, bool):
            raise SkillValidationError("schema_version must equal 1")
        if self.api_version != SKILL_LINEAGE_API_VERSION:
            raise SkillValidationError("invalid lineage api_version")
        object.__setattr__(self, "lineage_id", _identifier(self.lineage_id, "lineage_id"))
        if not isinstance(self.child, SkillRef):
            raise SkillValidationError("child must be a SkillRef")
        object.__setattr__(self, "parents", tuple(self.parents))
        if not all(isinstance(item, SkillRef) for item in self.parents):
            raise SkillValidationError("parents must contain SkillRef values")
        if len(set(self.parents)) != len(self.parents):
            raise SkillValidationError("parents must not contain duplicates")
        if self.child in self.parents:
            raise SkillValidationError("child must not also be a parent")
        if not isinstance(self.operation, str) or self.operation not in {
            "create",
            "revise",
            "merge",
            "split",
        }:
            raise SkillValidationError("lineage operation is not recognized")
        expected_parent_count = {
            "create": (0, 0),
            "revise": (1, 1),
            "split": (1, 1),
            "merge": (2, None),
        }[self.operation]
        minimum, maximum = expected_parent_count
        if len(self.parents) < minimum or (
            maximum is not None and len(self.parents) > maximum
        ):
            if maximum is None:
                requirement = f"at least {minimum}"
            elif minimum == maximum:
                requirement = str(minimum)
            else:  # pragma: no cover - no ranged v1 operation
                requirement = f"between {minimum} and {maximum}"
            raise SkillValidationError(
                f"{self.operation} lineage requires {requirement} parent(s)"
            )
        object.__setattr__(self, "created_at", _timestamp(self.created_at, "created_at"))
        object.__setattr__(self, "proposal_id", _identifier(self.proposal_id, "proposal_id"))
        object.__setattr__(
            self,
            "evidence_refs",
            _string_tuple(
                self.evidence_refs, "evidence_refs", item_validator=_identifier
            ),
        )
        if not self.evidence_refs:
            raise SkillValidationError("lineage requires an evidence reference")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "api_version": self.api_version,
            "lineage_id": self.lineage_id,
            "child": self.child.to_dict(),
            "parents": [item.to_dict() for item in self.parents],
            "operation": self.operation,
            "created_at": self.created_at,
            "proposal_id": self.proposal_id,
            "evidence_refs": list(self.evidence_refs),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SkillLineage":
        fields = frozenset(
            {
                "schema_version",
                "api_version",
                "lineage_id",
                "child",
                "parents",
                "operation",
                "created_at",
                "proposal_id",
                "evidence_refs",
            }
        )
        data = _strict_object(value, required=fields, label="SkillLineage")
        parents = data["parents"]
        if isinstance(parents, (str, bytes)) or not isinstance(parents, Sequence):
            raise SkillValidationError("parents must be an array")
        return cls(
            schema_version=data["schema_version"],
            api_version=data["api_version"],
            lineage_id=data["lineage_id"],
            child=SkillRef.from_dict(data["child"]),
            parents=tuple(SkillRef.from_dict(item) for item in parents),
            operation=data["operation"],
            created_at=data["created_at"],
            proposal_id=data["proposal_id"],
            evidence_refs=_string_tuple(
                data["evidence_refs"], "evidence_refs", item_validator=_identifier
            ),
        )


@dataclass(frozen=True, kw_only=True)
class EvolutionPolicy:
    minimum_observations: int = 3
    failure_rate_threshold: float = 0.5
    quality_floor: float = 0.6
    outcome_ttl_seconds: int = 30 * 24 * 60 * 60

    def __post_init__(self) -> None:
        if (
            isinstance(self.minimum_observations, bool)
            or not isinstance(self.minimum_observations, int)
            or self.minimum_observations < 1
        ):
            raise SkillValidationError("minimum_observations must be an integer >= 1")
        _number(
            self.failure_rate_threshold,
            "failure_rate_threshold",
            minimum=0,
            maximum=1,
        )
        _number(self.quality_floor, "quality_floor", minimum=0, maximum=1)
        if (
            isinstance(self.outcome_ttl_seconds, bool)
            or not isinstance(self.outcome_ttl_seconds, int)
            or self.outcome_ttl_seconds < 1
        ):
            raise SkillValidationError("outcome_ttl_seconds must be an integer >= 1")


def _now(value: str | datetime) -> tuple[datetime, str]:
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise SkillValidationError("now must include timezone information")
        parsed = value.astimezone(timezone.utc)
        return parsed, parsed.isoformat()
    _timestamp(value, "now")
    return parse_timestamp(value), value


def propose_evolution(
    index: SkillIndexSnapshot,
    outcomes: Sequence[SkillOutcome],
    *,
    plans: Sequence[CompositionPlan],
    now: str | datetime,
    policy: EvolutionPolicy = EvolutionPolicy(),
) -> tuple[SkillEvolutionProposal, ...]:
    """Return deterministic review proposals; never apply or persist them."""

    state = index.freshness(now)
    if state != "fresh":
        raise SkillIndexFreshnessError(index.index_id, state)
    current, created_at = _now(now)
    if isinstance(outcomes, (str, bytes)) or not isinstance(outcomes, Sequence):
        raise EvolutionError("outcomes must be an array of SkillOutcome values")
    if not all(isinstance(item, SkillOutcome) for item in outcomes):
        raise EvolutionError("outcomes must contain SkillOutcome values")
    if len({item.outcome_id for item in outcomes}) != len(outcomes):
        raise EvolutionError("outcomes must have unique outcome ids")
    if isinstance(plans, (str, bytes)) or not isinstance(plans, Sequence):
        raise EvolutionError("plans must be an array of CompositionPlan values")
    if not all(isinstance(item, CompositionPlan) for item in plans):
        raise EvolutionError("plans must contain CompositionPlan values")
    if len({item.plan_id for item in plans}) != len(plans):
        raise EvolutionError("plans must have unique plan ids")
    plans_by_id = {item.plan_id: item for item in plans}
    referenced_plan_ids = {item.plan_id for item in outcomes}
    missing_plan_ids = sorted(referenced_plan_ids - plans_by_id.keys())
    if missing_plan_ids:
        raise EvolutionError(
            "outcome references unknown composition plan(s): "
            + ", ".join(missing_plan_ids)
        )
    reused_evidence: set[str] = set()
    for plan_id in sorted(referenced_plan_ids):
        plan = plans_by_id[plan_id]
        if (
            plan.index_id != index.index_id
            or plan.index_generated_at != index.generated_at
            or plan.index_source_digest != index.source_digest
        ):
            raise EvolutionError(
                f"composition plan {plan_id!r} is not bound to the supplied index"
            )
    indexed = {(item.skill_id, item.version): item for item in index.skills}
    grouped: dict[tuple[str, str], list[SkillOutcome]] = {}
    for outcome in outcomes:
        observed = parse_timestamp(outcome.observed_at)
        age = (current - observed).total_seconds()
        if age < 0:
            raise EvolutionError("future-dated outcome evidence is unknown")
        if age > policy.outcome_ttl_seconds:
            continue
        for reference in outcome.skills:
            identity = (reference.skill_id, reference.version)
            if identity not in indexed:
                raise EvolutionError(
                    f"outcome references unknown skill {reference.skill_id}@{reference.version}"
                )
        plan = plans_by_id[outcome.plan_id]
        if observed < parse_timestamp(plan.generated_at):
            raise EvolutionError("outcome predates its referenced composition plan")
        selected = {(item.skill_id, item.version) for item in plan.selected}
        referenced = {(item.skill_id, item.version) for item in outcome.skills}
        if not referenced <= selected:
            raise EvolutionError(
                f"outcome skill set is not contained in plan {outcome.plan_id!r}"
            )
        overlap = reused_evidence & set(outcome.evidence_refs)
        if overlap:
            raise EvolutionError(
                "outcomes must use independent evidence references: "
                + ", ".join(sorted(overlap))
            )
        reused_evidence.update(outcome.evidence_refs)
        for reference in outcome.skills:
            identity = (reference.skill_id, reference.version)
            grouped.setdefault(identity, []).append(outcome)

    proposals: list[SkillEvolutionProposal] = []
    for identity in sorted(grouped):
        evidence = sorted(grouped[identity], key=lambda item: item.outcome_id)
        if len(evidence) < policy.minimum_observations:
            continue
        failures = sum(item.status == "failure" for item in evidence)
        failure_rate = failures / len(evidence)
        quality_values = [
            item.quality_score for item in evidence if item.quality_score is not None
        ]
        mean_quality = (
            sum(quality_values) / len(quality_values) if quality_values else None
        )
        rationale: list[str] = []
        if failure_rate >= policy.failure_rate_threshold:
            rationale.append("high_failure_rate")
        if mean_quality is not None and mean_quality < policy.quality_floor:
            rationale.append("quality_below_floor")
        if not rationale:
            continue
        target = SkillRef(skill_id=identity[0], version=identity[1])
        outcome_ids = tuple(item.outcome_id for item in evidence)
        evidence_refs = tuple(
            sorted({reference for item in evidence for reference in item.evidence_refs})
        )
        payload = {
            "target": target.to_dict(),
            "outcomes": outcome_ids,
            "rationale": rationale,
        }
        digest = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        proposals.append(
            SkillEvolutionProposal(
                proposal_id="skill-proposal-" + digest[:20],
                created_at=created_at,
                target=target,
                operation="revise_metadata",
                based_on_outcome_ids=outcome_ids,
                capability_additions=(),
                capability_removals=(),
                facet_additions=(),
                facet_removals=(),
                estimated_cost_delta=0.0,
                uncertainty_delta=0.1,
                rationale_codes=tuple(rationale),
                evidence_refs=evidence_refs,
            )
        )
    return tuple(proposals)


def lineage_from_proposal(
    proposal: SkillEvolutionProposal,
    *,
    child_version: str,
    now: str | datetime,
) -> SkillLineage:
    """Create lineage data for a separately reviewed proposal application."""

    if not isinstance(proposal, SkillEvolutionProposal):
        raise TypeError("proposal must be a SkillEvolutionProposal")
    if proposal.operation != "revise_metadata":
        raise EvolutionError(
            "v1 lineage application supports revise_metadata only; merge and split "
            "require an explicit multi-parent application API"
        )
    _, created_at = _now(now)
    child = SkillRef(skill_id=proposal.target.skill_id, version=child_version)
    if not version_satisfies(child.version, f">{proposal.target.version}"):
        raise EvolutionError("child version must be greater than the parent version")
    payload = {
        "proposal_id": proposal.proposal_id,
        "child": child.to_dict(),
        "parent": proposal.target.to_dict(),
    }
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return SkillLineage(
        lineage_id="skill-lineage-" + digest[:20],
        child=child,
        parents=(proposal.target,),
        operation="revise",
        created_at=created_at,
        proposal_id=proposal.proposal_id,
        evidence_refs=proposal.evidence_refs,
    )


__all__ = [
    "EvolutionError",
    "EvolutionPolicy",
    "SKILL_EVOLUTION_API_VERSION",
    "SKILL_LINEAGE_API_VERSION",
    "SKILL_OUTCOME_API_VERSION",
    "SkillEvolutionProposal",
    "SkillLineage",
    "SkillOutcome",
    "SkillRef",
    "lineage_from_proposal",
    "propose_evolution",
]
