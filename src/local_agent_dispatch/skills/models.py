"""Strict provider-free contracts for skill discovery and composition.

Only bounded metadata enters these contracts.  A skill's instruction body,
prompt text, executable entrypoint, and source path are deliberately absent,
so indexing and planning cannot return or execute them by construction.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal


SKILL_SCHEMA_VERSION = 1
SKILL_INDEX_API_VERSION = "local-agent-dispatch.skill-index.v1"
SKILL_REQUEST_API_VERSION = "local-agent-dispatch.skill-composition-request.v1"
SELECTION_SIZES = frozenset({3, 5, 10})

Availability = Literal["available", "unknown", "disabled"]
EvidenceState = Literal["complete", "unknown"]

_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$")
_TAG_RE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,63}$")
_SEMVER_RE = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class SkillValidationError(ValueError):
    """Untrusted skill metadata violated a closed v1 contract."""


def _strict_object(
    value: Any,
    *,
    required: frozenset[str],
    optional: frozenset[str] = frozenset(),
    label: str,
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise SkillValidationError(f"{label} must be an object")
    if any(not isinstance(key, str) for key in value):
        raise SkillValidationError(f"{label} field names must be strings")
    missing = sorted(required - set(value))
    unknown = sorted(set(value) - required - optional)
    if missing:
        raise SkillValidationError(
            f"{label} is missing required field(s): {', '.join(missing)}"
        )
    if unknown:
        raise SkillValidationError(
            f"{label} contains unknown field(s): {', '.join(unknown)}"
        )
    return value


def _string(value: Any, label: str, *, maximum: int = 128) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SkillValidationError(f"{label} must be a non-empty string")
    text = value.strip()
    if len(text) > maximum:
        raise SkillValidationError(f"{label} must be at most {maximum} characters")
    return text


def _identifier(value: Any, label: str) -> str:
    text = _string(value, label)
    if not _IDENTIFIER_RE.fullmatch(text):
        raise SkillValidationError(f"{label} must be a bounded path-free identifier")
    return text


def _semantic_version(value: Any, label: str = "version") -> str:
    if not isinstance(value, str) or not _SEMVER_RE.fullmatch(value):
        raise SkillValidationError(f"{label} must be semantic version text")
    return value


def _tag(value: Any, label: str) -> str:
    text = _string(value, label, maximum=64)
    if not _TAG_RE.fullmatch(text):
        raise SkillValidationError(f"{label} must be a lowercase tag")
    return text


def _selector_tag(value: Any, label: str) -> str:
    if value == "*":
        return "*"
    return _tag(value, label)


def _string_tuple(
    value: Any,
    label: str,
    *,
    item_validator=_tag,
    nonempty: bool = False,
) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise SkillValidationError(f"{label} must be an array")
    result = tuple(item_validator(item, f"{label}[]") for item in value)
    if nonempty and not result:
        raise SkillValidationError(f"{label} must not be empty")
    if len(set(result)) != len(result):
        raise SkillValidationError(f"{label} must not contain duplicates")
    return result


def _number(
    value: Any,
    label: str,
    *,
    minimum: float | None = None,
    maximum: float | None = None,
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SkillValidationError(f"{label} must be a number")
    result = float(value)
    if not math.isfinite(result):
        raise SkillValidationError(f"{label} must be finite")
    if minimum is not None and result < minimum:
        raise SkillValidationError(f"{label} must be >= {minimum}")
    if maximum is not None and result > maximum:
        raise SkillValidationError(f"{label} must be <= {maximum}")
    return result


def _integer(value: Any, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise SkillValidationError(f"{label} must be an integer >= {minimum}")
    return value


def _timestamp(value: Any, label: str) -> str:
    text = _string(value, label, maximum=64)
    normalized = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise SkillValidationError(f"{label} must be an RFC 3339 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise SkillValidationError(f"{label} must include a timezone offset")
    return text


def parse_timestamp(value: str) -> datetime:
    normalized = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
    return datetime.fromisoformat(normalized).astimezone(timezone.utc)


def _vector(value: Any, label: str) -> tuple[float, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise SkillValidationError(f"{label} must be an array of numbers")
    if not 1 <= len(value) <= 4096:
        raise SkillValidationError(f"{label} dimensions must be within [1, 4096]")
    result = tuple(_number(item, f"{label}[]") for item in value)
    if not any(item != 0.0 for item in result):
        raise SkillValidationError(f"{label} must have a non-zero norm")
    return result


def _stable_cosine(left: tuple[float, ...], right: tuple[float, ...]) -> float:
    """Return cosine similarity without overflowing finite input vectors."""

    left_scale = max(abs(value) for value in left)
    right_scale = max(abs(value) for value in right)
    if left_scale == 0.0 or right_scale == 0.0:  # defensive internal guard
        raise SkillValidationError("cosine vectors must have non-zero norms")
    scaled_left = tuple(value / left_scale for value in left)
    scaled_right = tuple(value / right_scale for value in right)
    dot = math.fsum(a * b for a, b in zip(scaled_left, scaled_right))
    left_norm = math.sqrt(math.fsum(value * value for value in scaled_left))
    right_norm = math.sqrt(math.fsum(value * value for value in scaled_right))
    result = dot / (left_norm * right_norm)
    return round(max(-1.0, min(1.0, result)), 12)


def _validate_version(schema_version: Any, api_version: Any, expected_api: str) -> None:
    if (
        isinstance(schema_version, bool)
        or not isinstance(schema_version, int)
        or schema_version != SKILL_SCHEMA_VERSION
    ):
        raise SkillValidationError("schema_version must equal 1")
    if api_version != expected_api:
        raise SkillValidationError(f"api_version must equal {expected_api!r}")


@dataclass(frozen=True, kw_only=True)
class SkillDescriptor:
    """Body-free metadata and a precomputed latent vector for one skill."""

    skill_id: str
    version: str
    title: str
    description: str
    capabilities: tuple[str, ...]
    facets: tuple[str, ...]
    platforms: tuple[str, ...]
    harnesses: tuple[str, ...]
    estimated_cost: float
    uncertainty: float
    embedding: tuple[float, ...]
    availability: Availability = "available"
    schema_version: int = SKILL_SCHEMA_VERSION
    api_version: str = SKILL_INDEX_API_VERSION

    def __post_init__(self) -> None:
        _validate_version(self.schema_version, self.api_version, SKILL_INDEX_API_VERSION)
        object.__setattr__(self, "skill_id", _identifier(self.skill_id, "skill_id"))
        object.__setattr__(self, "version", _semantic_version(self.version))
        object.__setattr__(self, "title", _string(self.title, "title", maximum=120))
        description = _string(self.description, "description", maximum=280)
        if "\n" in description or "\r" in description:
            raise SkillValidationError("description must be one bounded line, not a body")
        object.__setattr__(self, "description", description)
        object.__setattr__(
            self,
            "capabilities",
            _string_tuple(self.capabilities, "capabilities", nonempty=True),
        )
        object.__setattr__(
            self, "facets", _string_tuple(self.facets, "facets", nonempty=True)
        )
        object.__setattr__(
            self,
            "platforms",
            _string_tuple(
                self.platforms,
                "platforms",
                item_validator=_selector_tag,
                nonempty=True,
            ),
        )
        object.__setattr__(
            self,
            "harnesses",
            _string_tuple(
                self.harnesses,
                "harnesses",
                item_validator=_selector_tag,
                nonempty=True,
            ),
        )
        object.__setattr__(
            self,
            "estimated_cost",
            _number(self.estimated_cost, "estimated_cost", minimum=0),
        )
        object.__setattr__(
            self,
            "uncertainty",
            _number(self.uncertainty, "uncertainty", minimum=0, maximum=1),
        )
        object.__setattr__(self, "embedding", _vector(self.embedding, "embedding"))
        if not isinstance(self.availability, str) or self.availability not in {
            "available",
            "unknown",
            "disabled",
        }:
            raise SkillValidationError("availability is not recognized")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "api_version": self.api_version,
            "skill_id": self.skill_id,
            "version": self.version,
            "title": self.title,
            "description": self.description,
            "capabilities": list(self.capabilities),
            "facets": list(self.facets),
            "platforms": list(self.platforms),
            "harnesses": list(self.harnesses),
            "estimated_cost": self.estimated_cost,
            "uncertainty": self.uncertainty,
            "embedding": list(self.embedding),
            "availability": self.availability,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SkillDescriptor":
        fields = frozenset(
            {
                "schema_version",
                "api_version",
                "skill_id",
                "version",
                "title",
                "description",
                "capabilities",
                "facets",
                "platforms",
                "harnesses",
                "estimated_cost",
                "uncertainty",
                "embedding",
                "availability",
            }
        )
        data = _strict_object(value, required=fields, label="SkillDescriptor")
        return cls(
            schema_version=data["schema_version"],
            api_version=data["api_version"],
            skill_id=_identifier(data["skill_id"], "skill_id"),
            version=_semantic_version(data["version"]),
            title=_string(data["title"], "title", maximum=120),
            description=_string(data["description"], "description", maximum=280),
            capabilities=_string_tuple(
                data["capabilities"], "capabilities", nonempty=True
            ),
            facets=_string_tuple(data["facets"], "facets", nonempty=True),
            platforms=_string_tuple(
                data["platforms"],
                "platforms",
                item_validator=_selector_tag,
                nonempty=True,
            ),
            harnesses=_string_tuple(
                data["harnesses"],
                "harnesses",
                item_validator=_selector_tag,
                nonempty=True,
            ),
            estimated_cost=_number(data["estimated_cost"], "estimated_cost", minimum=0),
            uncertainty=_number(
                data["uncertainty"], "uncertainty", minimum=0, maximum=1
            ),
            embedding=_vector(data["embedding"], "embedding"),
            availability=data["availability"],
        )


@dataclass(frozen=True, kw_only=True)
class SkillIndexSnapshot:
    index_id: str
    generated_at: str
    ttl_seconds: int | None
    evidence_state: EvidenceState
    source_digest: str
    embedding_model: str
    embedding_dimensions: int
    skills: tuple[SkillDescriptor, ...]
    schema_version: int = SKILL_SCHEMA_VERSION
    api_version: str = SKILL_INDEX_API_VERSION

    def __post_init__(self) -> None:
        _validate_version(self.schema_version, self.api_version, SKILL_INDEX_API_VERSION)
        object.__setattr__(self, "index_id", _identifier(self.index_id, "index_id"))
        object.__setattr__(
            self, "generated_at", _timestamp(self.generated_at, "generated_at")
        )
        if self.ttl_seconds is not None:
            object.__setattr__(
                self,
                "ttl_seconds",
                _integer(self.ttl_seconds, "ttl_seconds", minimum=1),
            )
        if not isinstance(self.evidence_state, str) or self.evidence_state not in {
            "complete",
            "unknown",
        }:
            raise SkillValidationError("evidence_state is not recognized")
        if not isinstance(self.source_digest, str) or not _SHA256_RE.fullmatch(
            self.source_digest
        ):
            raise SkillValidationError("source_digest must be a sha256 digest")
        object.__setattr__(
            self,
            "embedding_model",
            _identifier(self.embedding_model, "embedding_model"),
        )
        object.__setattr__(
            self,
            "embedding_dimensions",
            _integer(self.embedding_dimensions, "embedding_dimensions", minimum=1),
        )
        if self.embedding_dimensions > 4096:
            raise SkillValidationError("embedding_dimensions must be <= 4096")
        object.__setattr__(self, "skills", tuple(self.skills))
        if not self.skills:
            raise SkillValidationError("skills must not be empty")
        if not all(isinstance(skill, SkillDescriptor) for skill in self.skills):
            raise SkillValidationError("skills must contain SkillDescriptor values")
        skill_ids = [skill.skill_id for skill in self.skills]
        if len(set(skill_ids)) != len(skill_ids):
            raise SkillValidationError(
                "an active index must contain exactly one version per skill id"
            )
        if any(len(skill.embedding) != self.embedding_dimensions for skill in self.skills):
            raise SkillValidationError("every embedding must match embedding_dimensions")

    def freshness(self, now: str | datetime) -> Literal["fresh", "stale", "unknown"]:
        if self.evidence_state != "complete" or self.ttl_seconds is None:
            return "unknown"
        if isinstance(now, datetime):
            if now.tzinfo is None or now.utcoffset() is None:
                raise SkillValidationError("now must include timezone information")
            current = now.astimezone(timezone.utc)
        else:
            _timestamp(now, "now")
            current = parse_timestamp(now)
        age = (current - parse_timestamp(self.generated_at)).total_seconds()
        if age < 0:
            return "unknown"
        return "fresh" if age <= self.ttl_seconds else "stale"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "api_version": self.api_version,
            "index_id": self.index_id,
            "generated_at": self.generated_at,
            "ttl_seconds": self.ttl_seconds,
            "evidence_state": self.evidence_state,
            "source_digest": self.source_digest,
            "embedding_model": self.embedding_model,
            "embedding_dimensions": self.embedding_dimensions,
            "skills": [skill.to_dict() for skill in self.skills],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SkillIndexSnapshot":
        fields = frozenset(
            {
                "schema_version",
                "api_version",
                "index_id",
                "generated_at",
                "ttl_seconds",
                "evidence_state",
                "source_digest",
                "embedding_model",
                "embedding_dimensions",
                "skills",
            }
        )
        data = _strict_object(value, required=fields, label="SkillIndexSnapshot")
        if isinstance(data["skills"], (str, bytes)) or not isinstance(
            data["skills"], Sequence
        ):
            raise SkillValidationError("skills must be an array")
        ttl = data["ttl_seconds"]
        if ttl is not None:
            ttl = _integer(ttl, "ttl_seconds", minimum=1)
        return cls(
            schema_version=data["schema_version"],
            api_version=data["api_version"],
            index_id=_identifier(data["index_id"], "index_id"),
            generated_at=_timestamp(data["generated_at"], "generated_at"),
            ttl_seconds=ttl,
            evidence_state=data["evidence_state"],
            source_digest=data["source_digest"],
            embedding_model=_identifier(data["embedding_model"], "embedding_model"),
            embedding_dimensions=_integer(
                data["embedding_dimensions"], "embedding_dimensions", minimum=1
            ),
            skills=tuple(SkillDescriptor.from_dict(item) for item in data["skills"]),
        )


@dataclass(frozen=True, kw_only=True)
class CompositionRequest:
    request_id: str
    k: int
    required_capabilities: tuple[str, ...]
    desired_facets: tuple[str, ...]
    platform: str
    harness: str
    allowed_skill_ids: tuple[str, ...]
    prohibited_skill_ids: tuple[str, ...]
    max_total_cost: float
    max_skill_uncertainty: float
    query_embedding: tuple[float, ...]
    schema_version: int = SKILL_SCHEMA_VERSION
    api_version: str = SKILL_REQUEST_API_VERSION

    def __post_init__(self) -> None:
        _validate_version(self.schema_version, self.api_version, SKILL_REQUEST_API_VERSION)
        object.__setattr__(
            self, "request_id", _identifier(self.request_id, "request_id")
        )
        if (
            isinstance(self.k, bool)
            or not isinstance(self.k, int)
            or self.k not in SELECTION_SIZES
        ):
            raise SkillValidationError("k must be exactly one of 3, 5, or 10")
        object.__setattr__(
            self,
            "required_capabilities",
            _string_tuple(
                self.required_capabilities, "required_capabilities", nonempty=True
            ),
        )
        object.__setattr__(
            self,
            "desired_facets",
            _string_tuple(self.desired_facets, "desired_facets"),
        )
        object.__setattr__(self, "platform", _selector_tag(self.platform, "platform"))
        object.__setattr__(self, "harness", _selector_tag(self.harness, "harness"))
        object.__setattr__(
            self,
            "allowed_skill_ids",
            _string_tuple(
                self.allowed_skill_ids,
                "allowed_skill_ids",
                item_validator=_identifier,
            ),
        )
        object.__setattr__(
            self,
            "prohibited_skill_ids",
            _string_tuple(
                self.prohibited_skill_ids,
                "prohibited_skill_ids",
                item_validator=_identifier,
            ),
        )
        if set(self.allowed_skill_ids) & set(self.prohibited_skill_ids):
            raise SkillValidationError("allowed and prohibited skill ids must not overlap")
        object.__setattr__(
            self,
            "max_total_cost",
            _number(self.max_total_cost, "max_total_cost", minimum=0),
        )
        object.__setattr__(
            self,
            "max_skill_uncertainty",
            _number(
                self.max_skill_uncertainty,
                "max_skill_uncertainty",
                minimum=0,
                maximum=1,
            ),
        )
        object.__setattr__(
            self,
            "query_embedding",
            _vector(self.query_embedding, "query_embedding"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "api_version": self.api_version,
            "request_id": self.request_id,
            "k": self.k,
            "required_capabilities": list(self.required_capabilities),
            "desired_facets": list(self.desired_facets),
            "platform": self.platform,
            "harness": self.harness,
            "allowed_skill_ids": list(self.allowed_skill_ids),
            "prohibited_skill_ids": list(self.prohibited_skill_ids),
            "max_total_cost": self.max_total_cost,
            "max_skill_uncertainty": self.max_skill_uncertainty,
            "query_embedding": list(self.query_embedding),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CompositionRequest":
        fields = frozenset(
            {
                "schema_version",
                "api_version",
                "request_id",
                "k",
                "required_capabilities",
                "desired_facets",
                "platform",
                "harness",
                "allowed_skill_ids",
                "prohibited_skill_ids",
                "max_total_cost",
                "max_skill_uncertainty",
                "query_embedding",
            }
        )
        data = _strict_object(value, required=fields, label="CompositionRequest")
        return cls(
            schema_version=data["schema_version"],
            api_version=data["api_version"],
            request_id=_identifier(data["request_id"], "request_id"),
            k=data["k"],
            required_capabilities=_string_tuple(
                data["required_capabilities"],
                "required_capabilities",
                nonempty=True,
            ),
            desired_facets=_string_tuple(data["desired_facets"], "desired_facets"),
            platform=_selector_tag(data["platform"], "platform"),
            harness=_selector_tag(data["harness"], "harness"),
            allowed_skill_ids=_string_tuple(
                data["allowed_skill_ids"],
                "allowed_skill_ids",
                item_validator=_identifier,
            ),
            prohibited_skill_ids=_string_tuple(
                data["prohibited_skill_ids"],
                "prohibited_skill_ids",
                item_validator=_identifier,
            ),
            max_total_cost=_number(data["max_total_cost"], "max_total_cost", minimum=0),
            max_skill_uncertainty=_number(
                data["max_skill_uncertainty"],
                "max_skill_uncertainty",
                minimum=0,
                maximum=1,
            ),
            query_embedding=_vector(data["query_embedding"], "query_embedding"),
        )


__all__ = [
    "Availability",
    "CompositionRequest",
    "EvidenceState",
    "SELECTION_SIZES",
    "SKILL_INDEX_API_VERSION",
    "SKILL_REQUEST_API_VERSION",
    "SKILL_SCHEMA_VERSION",
    "SkillDescriptor",
    "SkillIndexSnapshot",
    "SkillValidationError",
    "parse_timestamp",
]
