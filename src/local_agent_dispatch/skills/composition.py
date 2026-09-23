"""Deterministic, provider-free search and multi-skill composition.

The order of operations is security-relevant: freshness and hard constraints
are checked before any similarity or diversity score is calculated.  Scoring
never imports a skill, resolves an entrypoint, reads a body, or executes code.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from itertools import combinations
from typing import Any, Literal

from .models import (
    CompositionRequest,
    SELECTION_SIZES,
    SKILL_SCHEMA_VERSION,
    SkillDescriptor,
    SkillIndexSnapshot,
    SkillValidationError,
    _stable_cosine,
)


SKILL_PLAN_API_VERSION = "local-agent-dispatch.skill-composition-plan.v1"
FreshnessState = Literal["fresh", "stale", "unknown"]
MAX_COMPOSITION_CANDIDATES = 128
MAX_REQUIRED_CAPABILITIES = 16
MAX_COMPLETION_DP_STATES = 100_000
MAX_COMPLETION_DP_TRANSITIONS = 2_000_000


class CompositionError(RuntimeError):
    """The requested composition cannot be produced safely."""


class SkillIndexFreshnessError(CompositionError):
    def __init__(self, index_id: str, state: FreshnessState) -> None:
        self.index_id = index_id
        self.state = state
        super().__init__(f"skill index {index_id!r} is {state}; composition blocked")


class CompositionConstraintError(CompositionError):
    """Fresh candidates cannot satisfy all hard constraints."""


@dataclass
class _CompletionBudget:
    remaining: int = MAX_COMPLETION_DP_TRANSITIONS

    def consume(self) -> None:
        self.remaining -= 1
        if self.remaining < 0:
            raise CompositionConstraintError(
                "composition exceeds the bounded exact-completion work budget; "
                "prefilter the index with allowed_skill_ids"
            )


def _decimal_cost(value: float) -> Decimal:
    return Decimal(str(value))


def _within_budget(cost: Decimal | float, budget: float) -> bool:
    value = cost if isinstance(cost, Decimal) else _decimal_cost(cost)
    return value <= _decimal_cost(budget)


@dataclass(frozen=True, kw_only=True)
class SearchHit:
    skill_id: str
    version: str
    title: str
    description: str
    similarity: float
    matched_capabilities: tuple[str, ...]
    matched_facets: tuple[str, ...]
    estimated_cost: float
    uncertainty: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "skill_id": self.skill_id,
            "version": self.version,
            "title": self.title,
            "description": self.description,
            "similarity": self.similarity,
            "matched_capabilities": list(self.matched_capabilities),
            "matched_facets": list(self.matched_facets),
            "estimated_cost": self.estimated_cost,
            "uncertainty": self.uncertainty,
        }


@dataclass(frozen=True, kw_only=True)
class PlannedSkill:
    rank: int
    skill_id: str
    version: str
    similarity: float
    marginal_capabilities: tuple[str, ...]
    marginal_facets: tuple[str, ...]
    estimated_cost: float
    uncertainty: float
    selection_score: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "rank": self.rank,
            "skill_id": self.skill_id,
            "version": self.version,
            "similarity": self.similarity,
            "marginal_capabilities": list(self.marginal_capabilities),
            "marginal_facets": list(self.marginal_facets),
            "estimated_cost": self.estimated_cost,
            "uncertainty": self.uncertainty,
            "selection_score": self.selection_score,
        }


@dataclass(frozen=True, kw_only=True)
class ObjectiveBreakdown:
    required_coverage: float
    desired_facet_coverage: float
    mean_relevance: float
    complementarity: float
    redundancy: float
    normalized_cost: float
    mean_uncertainty: float
    total: float

    def to_dict(self) -> dict[str, float]:
        return {
            "required_coverage": self.required_coverage,
            "desired_facet_coverage": self.desired_facet_coverage,
            "mean_relevance": self.mean_relevance,
            "complementarity": self.complementarity,
            "redundancy": self.redundancy,
            "normalized_cost": self.normalized_cost,
            "mean_uncertainty": self.mean_uncertainty,
            "total": self.total,
        }


@dataclass(frozen=True, kw_only=True)
class CompositionPlan:
    plan_id: str
    request_id: str
    index_id: str
    index_generated_at: str
    index_source_digest: str
    generated_at: str
    k: int
    eligible_skill_count: int
    selected: tuple[PlannedSkill, ...]
    covered_capabilities: tuple[str, ...]
    covered_facets: tuple[str, ...]
    total_estimated_cost: float
    mean_uncertainty: float
    objective: ObjectiveBreakdown
    hard_filter_counts: tuple[tuple[str, int], ...]
    schema_version: int = SKILL_SCHEMA_VERSION
    api_version: str = SKILL_PLAN_API_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "api_version": self.api_version,
            "plan_id": self.plan_id,
            "request_id": self.request_id,
            "index_id": self.index_id,
            "index_generated_at": self.index_generated_at,
            "index_source_digest": self.index_source_digest,
            "generated_at": self.generated_at,
            "k": self.k,
            "eligible_skill_count": self.eligible_skill_count,
            "selected": [item.to_dict() for item in self.selected],
            "covered_capabilities": list(self.covered_capabilities),
            "covered_facets": list(self.covered_facets),
            "total_estimated_cost": self.total_estimated_cost,
            "mean_uncertainty": self.mean_uncertainty,
            "objective": self.objective.to_dict(),
            "hard_filter_counts": [
                {"reason": reason, "count": count}
                for reason, count in self.hard_filter_counts
            ],
        }


def _assert_usable(
    index: SkillIndexSnapshot, request: CompositionRequest, now: str | datetime
) -> None:
    state = index.freshness(now)
    if state != "fresh":
        raise SkillIndexFreshnessError(index.index_id, state)
    if len(request.query_embedding) != index.embedding_dimensions:
        raise CompositionConstraintError(
            "query embedding dimensions do not match the fresh index"
        )


def _supports(values: tuple[str, ...], requested: str) -> bool:
    return requested == "*" or "*" in values or requested in values


def _hard_filter(
    index: SkillIndexSnapshot, request: CompositionRequest
) -> tuple[tuple[SkillDescriptor, ...], tuple[tuple[str, int], ...]]:
    allowed = set(request.allowed_skill_ids)
    prohibited = set(request.prohibited_skill_ids)
    eligible: list[SkillDescriptor] = []
    counts: dict[str, int] = {}
    for skill in sorted(index.skills, key=lambda item: (item.skill_id, item.version)):
        reason: str | None = None
        if skill.availability != "available":
            reason = "availability_not_verified"
        elif allowed and skill.skill_id not in allowed:
            reason = "not_in_allowlist"
        elif skill.skill_id in prohibited:
            reason = "prohibited"
        elif not _supports(skill.platforms, request.platform):
            reason = "platform_mismatch"
        elif not _supports(skill.harnesses, request.harness):
            reason = "harness_mismatch"
        elif skill.uncertainty > request.max_skill_uncertainty:
            reason = "uncertainty_above_ceiling"
        elif not _within_budget(skill.estimated_cost, request.max_total_cost):
            reason = "individual_cost_above_budget"
        if reason is None:
            eligible.append(skill)
        else:
            counts[reason] = counts.get(reason, 0) + 1
    return tuple(eligible), tuple(sorted(counts.items()))


def _cosine(left: tuple[float, ...], right: tuple[float, ...]) -> float:
    return _stable_cosine(left, right)


def _jaccard_dissimilarity(left: set[str], right: set[str]) -> float:
    union = left | right
    if not union:
        return 0.0
    return 1.0 - (len(left & right) / len(union))


def search_skills(
    index: SkillIndexSnapshot,
    request: CompositionRequest,
    *,
    now: str | datetime,
    limit: int | None = None,
) -> tuple[SearchHit, ...]:
    """Return body-free search hits after freshness and hard filtering."""

    _assert_usable(index, request, now)
    requested_limit = request.k if limit is None else limit
    if isinstance(requested_limit, bool) or requested_limit not in SELECTION_SIZES:
        raise SkillValidationError("search limit must be exactly one of 3, 5, or 10")
    eligible, _ = _hard_filter(index, request)
    required = set(request.required_capabilities)
    desired = set(request.desired_facets)
    hits = [
        SearchHit(
            skill_id=skill.skill_id,
            version=skill.version,
            title=skill.title,
            description=skill.description,
            similarity=_cosine(request.query_embedding, skill.embedding),
            matched_capabilities=tuple(sorted(required & set(skill.capabilities))),
            matched_facets=tuple(sorted(desired & set(skill.facets))),
            estimated_cost=skill.estimated_cost,
            uncertainty=skill.uncertainty,
        )
        for skill in eligible
    ]
    hits.sort(
        key=lambda item: (
            -item.similarity,
            -len(item.matched_capabilities),
            -len(item.matched_facets),
            item.estimated_cost,
            item.skill_id,
            item.version,
        )
    )
    return tuple(hits[:requested_limit])


def _marginal_score(
    skill: SkillDescriptor,
    selected: tuple[SkillDescriptor, ...],
    request: CompositionRequest,
    covered_capabilities: set[str],
    covered_facets: set[str],
) -> tuple[float, tuple[str, ...], tuple[str, ...], float]:
    required = set(request.required_capabilities)
    desired = set(request.desired_facets)
    new_capabilities = tuple(
        sorted((set(skill.capabilities) & required) - covered_capabilities)
    )
    new_facets = tuple(sorted((set(skill.facets) & desired) - covered_facets))
    capability_gain = len(new_capabilities) / len(required)
    facet_gain = len(new_facets) / max(1, len(desired))
    relevance = (_cosine(request.query_embedding, skill.embedding) + 1.0) / 2.0
    if selected:
        complementarity = sum(
            _jaccard_dissimilarity(set(skill.facets), set(item.facets))
            for item in selected
        ) / len(selected)
        redundancy = sum(
            max(0.0, _cosine(skill.embedding, item.embedding)) for item in selected
        ) / len(selected)
    else:
        complementarity = 0.0
        redundancy = 0.0
    normalized_cost = (
        skill.estimated_cost / request.max_total_cost
        if request.max_total_cost > 0
        else 0.0
    )
    score = (
        100.0 * capability_gain
        + 30.0 * facet_gain
        + 12.0 * complementarity
        + 8.0 * relevance
        - 18.0 * redundancy
        - 5.0 * normalized_cost
        - 10.0 * skill.uncertainty
    )
    return round(score, 12), new_capabilities, new_facets, relevance


def _completion_remains_possible(
    *,
    candidate: SkillDescriptor,
    remaining: tuple[SkillDescriptor, ...],
    selected_count: int,
    selected_cost: Decimal,
    covered_capabilities: set[str],
    request: CompositionRequest,
    computation_budget: _CompletionBudget,
) -> bool:
    slots_after = request.k - selected_count - 1
    new_cost = selected_cost + _decimal_cost(candidate.estimated_cost)
    if not _within_budget(new_cost, request.max_total_cost):
        return False
    others = tuple(item for item in remaining if item is not candidate)
    if len(others) < slots_after:
        return False
    missing = set(request.required_capabilities) - (
        covered_capabilities | set(candidate.capabilities)
    )
    if slots_after == 0:
        return not missing
    minimum_completion_cost = _minimum_covering_completion_cost(
        others, missing, slots_after, computation_budget
    )
    return (
        minimum_completion_cost is not None
        and _within_budget(new_cost + minimum_completion_cost, request.max_total_cost)
    )


def _minimum_covering_completion_cost(
    candidates: tuple[SkillDescriptor, ...],
    missing: set[str],
    slots: int,
    computation_budget: _CompletionBudget,
) -> Decimal | None:
    """Exact bounded DP for the cheapest `slots`-skill covering completion."""

    if slots < 0 or len(candidates) < slots:
        return None
    ordered_capabilities = tuple(sorted(missing))
    bit_for = {name: 1 << index for index, name in enumerate(ordered_capabilities)}
    full_mask = (1 << len(ordered_capabilities)) - 1
    # Keep a deterministic cheapest representative for each (count, mask).
    states: dict[tuple[int, int], tuple[Decimal, tuple[tuple[str, str], ...]]] = {
        (0, 0): (Decimal(0), ())
    }
    for skill in sorted(candidates, key=lambda item: (item.skill_id, item.version)):
        skill_mask = 0
        for capability in skill.capabilities:
            skill_mask |= bit_for.get(capability, 0)
        updated = dict(states)
        for (count, mask), (cost, identities) in states.items():
            computation_budget.consume()
            if count >= slots:
                continue
            key = (count + 1, mask | skill_mask)
            choice = (
                cost + _decimal_cost(skill.estimated_cost),
                identities + ((skill.skill_id, skill.version),),
            )
            existing = updated.get(key)
            if existing is None or choice < existing:
                updated[key] = choice
        if len(updated) > MAX_COMPLETION_DP_STATES:
            raise CompositionConstraintError(
                "composition exceeds the bounded exact-completion state budget; "
                "reduce required capabilities or prefilter the index"
            )
        states = updated
    result = states.get((slots, full_mask))
    return None if result is None else result[0]


def _objective(
    selected: tuple[SkillDescriptor, ...], request: CompositionRequest
) -> ObjectiveBreakdown:
    required = set(request.required_capabilities)
    desired = set(request.desired_facets)
    covered_capabilities = set().union(*(set(item.capabilities) for item in selected))
    covered_facets = set().union(*(set(item.facets) for item in selected))
    required_coverage = len(required & covered_capabilities) / len(required)
    desired_coverage = len(desired & covered_facets) / max(1, len(desired))
    relevance = sum(
        (_cosine(request.query_embedding, item.embedding) + 1.0) / 2.0
        for item in selected
    ) / len(selected)
    pairs = tuple(combinations(selected, 2))
    if pairs:
        complementarity = sum(
            _jaccard_dissimilarity(set(left.facets), set(right.facets))
            for left, right in pairs
        ) / len(pairs)
        redundancy = sum(
            max(0.0, _cosine(left.embedding, right.embedding))
            for left, right in pairs
        ) / len(pairs)
    else:  # pragma: no cover - k is at least 3
        complementarity = redundancy = 0.0
    cost = sum(item.estimated_cost for item in selected)
    normalized_cost = cost / request.max_total_cost if request.max_total_cost > 0 else 0.0
    uncertainty = sum(item.uncertainty for item in selected) / len(selected)
    total = (
        100.0 * required_coverage
        + 30.0 * desired_coverage
        + 12.0 * complementarity
        + 8.0 * relevance
        - 18.0 * redundancy
        - 5.0 * normalized_cost
        - 10.0 * uncertainty
    )
    return ObjectiveBreakdown(
        required_coverage=round(required_coverage, 12),
        desired_facet_coverage=round(desired_coverage, 12),
        mean_relevance=round(relevance, 12),
        complementarity=round(complementarity, 12),
        redundancy=round(redundancy, 12),
        normalized_cost=round(normalized_cost, 12),
        mean_uncertainty=round(uncertainty, 12),
        total=round(total, 12),
    )


def compose_skills(
    index: SkillIndexSnapshot,
    request: CompositionRequest,
    *,
    now: str | datetime,
) -> CompositionPlan:
    """Select exactly 3, 5, or 10 skills using deterministic marginal utility."""

    _assert_usable(index, request, now)
    eligible, filter_counts = _hard_filter(index, request)
    if len(request.required_capabilities) > MAX_REQUIRED_CAPABILITIES:
        raise CompositionConstraintError(
            f"at most {MAX_REQUIRED_CAPABILITIES} required capabilities may be "
            "composed in one bounded request"
        )
    if len(eligible) > MAX_COMPOSITION_CANDIDATES:
        raise CompositionConstraintError(
            f"{len(eligible)} eligible skills exceed the bounded composition "
            f"candidate limit of {MAX_COMPOSITION_CANDIDATES}; prefilter the "
            "index with allowed_skill_ids"
        )
    if len(eligible) < request.k:
        raise CompositionConstraintError(
            f"only {len(eligible)} skills remain after hard filters; {request.k} required"
        )
    available_capabilities = set().union(
        *(set(skill.capabilities) for skill in eligible)
    )
    missing = set(request.required_capabilities) - available_capabilities
    if missing:
        raise CompositionConstraintError(
            "required capabilities are unavailable after hard filters: "
            + ", ".join(sorted(missing))
        )

    selected: list[SkillDescriptor] = []
    planned: list[PlannedSkill] = []
    remaining = list(eligible)
    covered_capabilities: set[str] = set()
    covered_facets: set[str] = set()
    selected_cost = Decimal(0)
    computation_budget = _CompletionBudget()
    while len(selected) < request.k:
        scored: list[
            tuple[float, str, str, SkillDescriptor, tuple[str, ...], tuple[str, ...]]
        ] = []
        remaining_tuple = tuple(remaining)
        for skill in remaining_tuple:
            if not _completion_remains_possible(
                candidate=skill,
                remaining=remaining_tuple,
                selected_count=len(selected),
                selected_cost=selected_cost,
                covered_capabilities=covered_capabilities,
                request=request,
                computation_budget=computation_budget,
            ):
                continue
            score, new_capabilities, new_facets, _ = _marginal_score(
                skill,
                tuple(selected),
                request,
                covered_capabilities,
                covered_facets,
            )
            scored.append(
                (
                    -score,
                    skill.skill_id,
                    skill.version,
                    skill,
                    new_capabilities,
                    new_facets,
                )
            )
        if not scored:
            raise CompositionConstraintError(
                "no deterministic completion satisfies coverage and cost constraints"
            )
        scored.sort(key=lambda item: (item[0], item[1], item[2]))
        negative_score, _, _, chosen, marginal_capabilities, marginal_facets = scored[0]
        selected.append(chosen)
        remaining.remove(chosen)
        selected_cost += _decimal_cost(chosen.estimated_cost)
        covered_capabilities.update(chosen.capabilities)
        covered_facets.update(chosen.facets)
        planned.append(
            PlannedSkill(
                rank=len(selected),
                skill_id=chosen.skill_id,
                version=chosen.version,
                similarity=_cosine(request.query_embedding, chosen.embedding),
                marginal_capabilities=marginal_capabilities,
                marginal_facets=marginal_facets,
                estimated_cost=chosen.estimated_cost,
                uncertainty=chosen.uncertainty,
                selection_score=round(-negative_score, 12),
            )
        )

    selected_tuple = tuple(selected)
    required = set(request.required_capabilities)
    if not required <= covered_capabilities:
        raise CompositionConstraintError("selected set does not cover every hard capability")
    if not _within_budget(selected_cost, request.max_total_cost):
        raise CompositionConstraintError("selected set exceeds the hard cost budget")
    objective = _objective(selected_tuple, request)
    if isinstance(now, datetime):
        if now.tzinfo is None or now.utcoffset() is None:
            raise SkillValidationError("now must include timezone information")
        generated_at = now.astimezone(timezone.utc).isoformat()
    else:
        # freshness() already validated the timestamp.
        generated_at = now
    fingerprint_payload = {
        "index_id": index.index_id,
        "source_digest": index.source_digest,
        "request": request.to_dict(),
        "selected": [(item.skill_id, item.version) for item in selected_tuple],
    }
    fingerprint = hashlib.sha256(
        json.dumps(
            fingerprint_payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    covered_required = tuple(sorted(required & covered_capabilities))
    covered_desired = tuple(sorted(set(request.desired_facets) & covered_facets))
    return CompositionPlan(
        plan_id="skill-plan-" + fingerprint[:24],
        request_id=request.request_id,
        index_id=index.index_id,
        index_generated_at=index.generated_at,
        index_source_digest=index.source_digest,
        generated_at=generated_at,
        k=request.k,
        eligible_skill_count=len(eligible),
        selected=tuple(planned),
        covered_capabilities=covered_required,
        covered_facets=covered_desired,
        total_estimated_cost=round(float(selected_cost), 12),
        mean_uncertainty=round(
            sum(item.uncertainty for item in selected_tuple) / len(selected_tuple), 12
        ),
        objective=objective,
        hard_filter_counts=filter_counts,
    )


__all__ = [
    "CompositionConstraintError",
    "CompositionError",
    "CompositionPlan",
    "ObjectiveBreakdown",
    "PlannedSkill",
    "SKILL_PLAN_API_VERSION",
    "SearchHit",
    "SkillIndexFreshnessError",
    "compose_skills",
    "search_skills",
]
