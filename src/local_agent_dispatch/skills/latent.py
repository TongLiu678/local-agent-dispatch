"""Body-free latent-space diagnostics for a fresh skill index.

The analysis consumes only already-validated :class:`SkillIndexSnapshot`
metadata.  It never reads a skill source path or instruction body, imports an
entrypoint, executes code, contacts a provider, or writes state.  Embeddings
are used transiently for cosine calculations and are absent from every result.
"""

from __future__ import annotations

import hashlib
import heapq
import json
import math
from dataclasses import dataclass
from datetime import datetime, timezone
from itertools import combinations
from typing import Any

from .composition import SkillIndexFreshnessError
from .models import (
    SKILL_SCHEMA_VERSION,
    SkillDescriptor,
    SkillIndexSnapshot,
    SkillValidationError,
    _stable_cosine,
)


SKILL_LATENT_ANALYSIS_API_VERSION = "local-agent-dispatch.skill-latent-analysis.v1"
MAX_ANALYSIS_LIMIT = 1000
MAX_PAIR_COUNT = 1_000_000
MAX_COSINE_OPERATIONS = 25_000_000


class LatentAnalysisError(RuntimeError):
    """A fresh index cannot be analyzed within the bounded v1 contract."""


@dataclass(frozen=True, kw_only=True)
class LatentPair:
    left_skill_id: str
    left_version: str
    right_skill_id: str
    right_version: str
    cosine: float
    redundant: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "left_skill_id": self.left_skill_id,
            "left_version": self.left_version,
            "right_skill_id": self.right_skill_id,
            "right_version": self.right_version,
            "cosine": self.cosine,
            "redundant": self.redundant,
        }


@dataclass(frozen=True, kw_only=True)
class RedundancyGroup:
    group_id: str
    members: tuple[tuple[str, str], ...]
    qualifying_pair_count: int
    minimum_qualifying_cosine: float
    maximum_qualifying_cosine: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "group_id": self.group_id,
            "members": [
                {"skill_id": skill_id, "version": version}
                for skill_id, version in self.members
            ],
            "qualifying_pair_count": self.qualifying_pair_count,
            "minimum_qualifying_cosine": self.minimum_qualifying_cosine,
            "maximum_qualifying_cosine": self.maximum_qualifying_cosine,
        }


@dataclass(frozen=True, kw_only=True)
class TagCoverage:
    name: str
    skill_count: int
    fraction: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "skill_count": self.skill_count,
            "fraction": self.fraction,
        }


@dataclass(frozen=True, kw_only=True)
class LatentAnalysis:
    analysis_id: str
    index_id: str
    index_generated_at: str
    analyzed_at: str
    analyzed_skill_count: int
    excluded_skill_counts: tuple[tuple[str, int], ...]
    pair_count: int
    limit: int
    pairs: tuple[LatentPair, ...]
    cosine_mean: float | None
    cosine_minimum: float | None
    cosine_maximum: float | None
    redundancy_threshold: float
    redundant_pair_count: int
    redundant_pairs: tuple[LatentPair, ...]
    redundant_groups: tuple[RedundancyGroup, ...]
    capability_coverage: tuple[TagCoverage, ...]
    facet_coverage: tuple[TagCoverage, ...]
    schema_version: int = SKILL_SCHEMA_VERSION
    api_version: str = SKILL_LATENT_ANALYSIS_API_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "api_version": self.api_version,
            "analysis_id": self.analysis_id,
            "index_id": self.index_id,
            "index_generated_at": self.index_generated_at,
            "analyzed_at": self.analyzed_at,
            "analyzed_skill_count": self.analyzed_skill_count,
            "excluded_skill_counts": [
                {"reason": reason, "count": count}
                for reason, count in self.excluded_skill_counts
            ],
            "pairwise": {
                "total_count": self.pair_count,
                "returned_count": len(self.pairs),
                "limit": self.limit,
                "truncated": self.pair_count > len(self.pairs),
                "cosine": {
                    "mean": self.cosine_mean,
                    "minimum": self.cosine_minimum,
                    "maximum": self.cosine_maximum,
                },
                "pairs": [pair.to_dict() for pair in self.pairs],
            },
            "redundancy": {
                "threshold": self.redundancy_threshold,
                "pair_count": self.redundant_pair_count,
                "returned_pair_count": len(self.redundant_pairs),
                "pairs_truncated": self.redundant_pair_count
                > len(self.redundant_pairs),
                "pairs": [pair.to_dict() for pair in self.redundant_pairs],
                "group_count": len(self.redundant_groups),
                "groups": [group.to_dict() for group in self.redundant_groups],
            },
            "coverage": {
                "unique_capability_count": len(self.capability_coverage),
                "capabilities": [
                    item.to_dict() for item in self.capability_coverage
                ],
                "unique_facet_count": len(self.facet_coverage),
                "facets": [item.to_dict() for item in self.facet_coverage],
            },
        }


class _RedundancySets:
    """Deterministic union-find with qualifying-edge aggregates."""

    def __init__(self, size: int) -> None:
        self.parent = list(range(size))
        self.edge_count = [0] * size
        self.edge_minimum: list[float | None] = [None] * size
        self.edge_maximum: list[float | None] = [None] * size

    def find(self, item: int) -> int:
        root = item
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[item] != item:
            parent = self.parent[item]
            self.parent[item] = root
            item = parent
        return root

    def add_edge(self, left: int, right: int, cosine: float) -> None:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root != right_root:
            root = min(left_root, right_root)
            child = max(left_root, right_root)
            self.parent[child] = root
            self.edge_count[root] += self.edge_count[child]
            minima = tuple(
                value
                for value in (self.edge_minimum[root], self.edge_minimum[child])
                if value is not None
            )
            maxima = tuple(
                value
                for value in (self.edge_maximum[root], self.edge_maximum[child])
                if value is not None
            )
            self.edge_minimum[root] = min(minima) if minima else None
            self.edge_maximum[root] = max(maxima) if maxima else None
            left_root = root
        else:
            left_root = self.find(left_root)
        self.edge_count[left_root] += 1
        current_minimum = self.edge_minimum[left_root]
        current_maximum = self.edge_maximum[left_root]
        self.edge_minimum[left_root] = (
            cosine if current_minimum is None else min(current_minimum, cosine)
        )
        self.edge_maximum[left_root] = (
            cosine if current_maximum is None else max(current_maximum, cosine)
        )


def _cosine(left: tuple[float, ...], right: tuple[float, ...]) -> float:
    return _stable_cosine(left, right)


def _validate_threshold(value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SkillValidationError("threshold must be a number")
    threshold = float(value)
    if not math.isfinite(threshold) or not 0.0 <= threshold <= 1.0:
        raise SkillValidationError("threshold must be finite and within [0, 1]")
    return threshold


def _validate_limit(value: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= MAX_ANALYSIS_LIMIT
    ):
        raise SkillValidationError(
            f"limit must be an integer within [1, {MAX_ANALYSIS_LIMIT}]"
        )
    return value


def _push_top_pair(
    heap: list[tuple[float, int, LatentPair]],
    pair: LatentPair,
    *,
    sequence: int,
    limit: int,
) -> None:
    # For equal cosine, earlier lexicographic pair iteration is better.  The
    # negative sequence makes a later pair the heap's worst entry.
    heapq.heappush(heap, (pair.cosine, -sequence, pair))
    if len(heap) > limit:
        heapq.heappop(heap)


def _sorted_pairs(
    heap: list[tuple[float, int, LatentPair]],
) -> tuple[LatentPair, ...]:
    return tuple(
        sorted(
            (item[2] for item in heap),
            key=lambda pair: (
                -pair.cosine,
                pair.left_skill_id,
                pair.left_version,
                pair.right_skill_id,
                pair.right_version,
            ),
        )
    )


def _coverage(
    skills: tuple[SkillDescriptor, ...], attribute: str
) -> tuple[TagCoverage, ...]:
    counts: dict[str, int] = {}
    for skill in skills:
        for name in getattr(skill, attribute):
            counts[name] = counts.get(name, 0) + 1
    denominator = len(skills)
    return tuple(
        TagCoverage(
            name=name,
            skill_count=counts[name],
            fraction=round(counts[name] / denominator, 12),
        )
        for name in sorted(counts)
    )


def _redundancy_groups(
    sets: _RedundancySets,
    skills: tuple[SkillDescriptor, ...],
    *,
    threshold: float,
) -> tuple[RedundancyGroup, ...]:
    members_by_root: dict[int, list[tuple[str, str]]] = {}
    for index, skill in enumerate(skills):
        root = sets.find(index)
        if sets.edge_count[root] > 0:
            members_by_root.setdefault(root, []).append((skill.skill_id, skill.version))

    groups: list[RedundancyGroup] = []
    for root, member_list in members_by_root.items():
        members = tuple(sorted(member_list))
        payload = {
            "members": members,
            "threshold": threshold,
        }
        digest = hashlib.sha256(
            json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()
        minimum = sets.edge_minimum[root]
        maximum = sets.edge_maximum[root]
        if minimum is None or maximum is None:  # pragma: no cover - invariant guard
            raise LatentAnalysisError("redundancy group is missing edge evidence")
        groups.append(
            RedundancyGroup(
                group_id="latent-group-" + digest[:20],
                members=members,
                qualifying_pair_count=sets.edge_count[root],
                minimum_qualifying_cosine=minimum,
                maximum_qualifying_cosine=maximum,
            )
        )
    groups.sort(key=lambda group: group.members)
    return tuple(groups)


def analyze_latent_space(
    index: SkillIndexSnapshot,
    *,
    now: str | datetime,
    threshold: float = 0.9,
    limit: int = 100,
) -> LatentAnalysis:
    """Analyze pair similarity, redundancy, and tag coverage without bodies."""

    if not isinstance(index, SkillIndexSnapshot):
        raise SkillValidationError("index must be a SkillIndexSnapshot")
    freshness = index.freshness(now)
    if freshness != "fresh":
        raise SkillIndexFreshnessError(index.index_id, freshness)
    threshold = _validate_threshold(threshold)
    limit = _validate_limit(limit)

    excluded: dict[str, int] = {}
    eligible: list[SkillDescriptor] = []
    for skill in sorted(index.skills, key=lambda item: (item.skill_id, item.version)):
        if skill.availability == "available":
            eligible.append(skill)
        else:
            reason = f"availability_{skill.availability}"
            excluded[reason] = excluded.get(reason, 0) + 1
    skills = tuple(eligible)
    if not skills:
        raise LatentAnalysisError("no available skills remain for latent analysis")

    pair_count = len(skills) * (len(skills) - 1) // 2
    operation_count = pair_count * index.embedding_dimensions
    if pair_count > MAX_PAIR_COUNT or operation_count > MAX_COSINE_OPERATIONS:
        raise LatentAnalysisError(
            "latent analysis exceeds the bounded v1 pairwise computation budget"
        )

    top_pairs: list[tuple[float, int, LatentPair]] = []
    redundant_top_pairs: list[tuple[float, int, LatentPair]] = []
    redundancy_sets = _RedundancySets(len(skills))
    cosine_total = 0.0
    cosine_minimum: float | None = None
    cosine_maximum: float | None = None
    redundant_pair_count = 0

    for sequence, (left_index, right_index) in enumerate(
        combinations(range(len(skills)), 2)
    ):
        left = skills[left_index]
        right = skills[right_index]
        cosine = _cosine(left.embedding, right.embedding)
        redundant = cosine >= threshold
        pair = LatentPair(
            left_skill_id=left.skill_id,
            left_version=left.version,
            right_skill_id=right.skill_id,
            right_version=right.version,
            cosine=cosine,
            redundant=redundant,
        )
        _push_top_pair(top_pairs, pair, sequence=sequence, limit=limit)
        cosine_total += cosine
        cosine_minimum = cosine if cosine_minimum is None else min(cosine_minimum, cosine)
        cosine_maximum = cosine if cosine_maximum is None else max(cosine_maximum, cosine)
        if redundant:
            redundant_pair_count += 1
            _push_top_pair(
                redundant_top_pairs,
                pair,
                sequence=sequence,
                limit=limit,
            )
            redundancy_sets.add_edge(left_index, right_index, cosine)

    analyzed_at = (
        now.astimezone(timezone.utc).isoformat() if isinstance(now, datetime) else now
    )
    fingerprint = {
        "index_id": index.index_id,
        "source_digest": index.source_digest,
        "analyzed_at": analyzed_at,
        "threshold": threshold,
        "limit": limit,
        "skills": [(skill.skill_id, skill.version) for skill in skills],
    }
    digest = hashlib.sha256(
        json.dumps(
            fingerprint,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    return LatentAnalysis(
        analysis_id="skill-latent-" + digest[:24],
        index_id=index.index_id,
        index_generated_at=index.generated_at,
        analyzed_at=analyzed_at,
        analyzed_skill_count=len(skills),
        excluded_skill_counts=tuple(sorted(excluded.items())),
        pair_count=pair_count,
        limit=limit,
        pairs=_sorted_pairs(top_pairs),
        cosine_mean=(
            round(cosine_total / pair_count, 12) if pair_count else None
        ),
        cosine_minimum=cosine_minimum,
        cosine_maximum=cosine_maximum,
        redundancy_threshold=threshold,
        redundant_pair_count=redundant_pair_count,
        redundant_pairs=_sorted_pairs(redundant_top_pairs),
        redundant_groups=_redundancy_groups(
            redundancy_sets, skills, threshold=threshold
        ),
        capability_coverage=_coverage(skills, "capabilities"),
        facet_coverage=_coverage(skills, "facets"),
    )


__all__ = [
    "LatentAnalysis",
    "LatentAnalysisError",
    "LatentPair",
    "MAX_ANALYSIS_LIMIT",
    "MAX_COSINE_OPERATIONS",
    "MAX_PAIR_COUNT",
    "RedundancyGroup",
    "SKILL_LATENT_ANALYSIS_API_VERSION",
    "TagCoverage",
    "analyze_latent_space",
]
