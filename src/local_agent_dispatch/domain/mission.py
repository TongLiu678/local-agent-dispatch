"""MissionSpec v2 domain model.

A MissionSpec is a reviewable, provider-free contract compiled from a mission
statement.  Every extracted value carries its source (origin plus optional
character span), a confidence, and a ``hard|soft|unknown`` status so that a
human reviewer can see where each value came from and whether it is
negotiable.  Nothing in this module can execute a provider, run a shell
command, send a prompt, or touch the network.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

VALID_STATUSES: tuple[str, ...] = ("hard", "soft", "unknown")
VALID_EVIDENCE_LEVELS: tuple[str, ...] = ("E0", "E1", "E2", "E3", "E4")
VALID_RISKS: tuple[str, ...] = ("low", "medium", "high")
SUPPORTED_EFFORT_NAMES: tuple[str, ...] = ("low", "medium", "high", "xhigh", "max")
POLICY_EXCLUDED_MODEL_FAMILY: str = "deepseek"
OPENCODE_GO_POOL: str = "opencode.go"
MATERIALITY_OPTIONS: tuple[str, ...] = (
    "cost",
    "permissions",
    "data_location",
    "scientific_claims",
)
#: Write scopes that never touch user source files (used for the Git gate).
NON_CODE_WRITE_SCOPES: tuple[str, ...] = ("review/", "git/", ".lad/")


@dataclass(frozen=True)
class SourceRef:
    """Explicit source reference for an extracted value.

    ``origin`` is one of ``user_prompt``, ``structured_input``, or
    ``compiler``.  ``span`` is an optional ``[start, end)`` character span into
    the original text; structured input uses ``phrase`` as the JSON path.
    """

    origin: str
    span: Optional[tuple[int, int]] = None
    phrase: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"origin": self.origin}
        if self.span is not None:
            payload["span"] = [self.span[0], self.span[1]]
        if self.phrase is not None:
            payload["phrase"] = self.phrase
        return payload

    @classmethod
    def structured(cls, path: str) -> "SourceRef":
        return cls(origin="structured_input", phrase=path)

    @classmethod
    def compiler(cls, note: str) -> "SourceRef":
        return cls(origin="compiler", phrase=note)


@dataclass(frozen=True)
class Extracted:
    """A value plus provenance and negotiability metadata."""

    value: Any
    source: SourceRef
    confidence: float = 1.0
    status: str = "hard"

    def __post_init__(self) -> None:
        if self.status not in VALID_STATUSES:
            raise ValueError(f"invalid status {self.status!r}; use {VALID_STATUSES}")
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"confidence out of range: {self.confidence}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "source": self.source.to_dict(),
            "confidence": self.confidence,
            "status": self.status,
        }


@dataclass(frozen=True)
class Ambiguity:
    """A material ambiguity the compiler refuses to guess.

    ``materiality`` restricts reasons to those that can change cost,
    permissions, data location, or scientific claims.
    """

    field: str
    question: str
    materiality: tuple[str, ...]
    alternatives: tuple[str, ...] = ()
    source: Optional[SourceRef] = None

    def __post_init__(self) -> None:
        for item in self.materiality:
            if item not in MATERIALITY_OPTIONS:
                raise ValueError(f"invalid materiality {item!r}; use {MATERIALITY_OPTIONS}")

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "field": self.field,
            "question": self.question,
            "materiality": list(self.materiality),
            "alternatives": list(self.alternatives),
        }
        if self.source is not None:
            payload["source"] = self.source.to_dict()
        return payload


@dataclass(frozen=True)
class Rejection:
    """A fail-closed compile rejection (cycle, missing validator, ...)."""

    code: str
    field: str
    message: str
    source: Optional[SourceRef] = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"code": self.code, "field": self.field, "message": self.message}
        if self.source is not None:
            payload["source"] = self.source.to_dict()
        return payload


@dataclass
class ClaimEnvelope:
    """Allowed, deferred, and forbidden scientific claims."""

    allowed: list[str] = field(default_factory=list)
    deferred: list[str] = field(default_factory=list)
    forbidden: list[str] = field(default_factory=list)
    promotion_gate: Optional[Extracted] = None
    evidence_level: Optional[Extracted] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": list(self.allowed),
            "deferred": list(self.deferred),
            "forbidden": list(self.forbidden),
            "promotion_gate": self.promotion_gate.to_dict() if self.promotion_gate else None,
            "evidence_level": self.evidence_level.to_dict() if self.evidence_level else None,
        }


@dataclass
class MissionSpec:
    """The reviewable mission contract.

    Fields mirror ``schemas/mission_spec.schema.json`` (schema_version 2).
    ``dag_hints`` entries are ``Extracted`` values whose ``value`` is a node
    dict with at least ``id`` and ``depends_on``; ``policy`` maps policy-area
    names to ``Extracted`` values.
    """

    schema_version: int = 2
    mission_id: str = ""
    goal: Optional[Extracted] = None
    non_goals: list[Extracted] = field(default_factory=list)
    deliverables: list[Extracted] = field(default_factory=list)
    acceptance_tests: list[Extracted] = field(default_factory=list)
    claim_envelope: Optional[ClaimEnvelope] = None
    data_class: Optional[Extracted] = None
    dag_hints: list[Extracted] = field(default_factory=list)
    policy: dict[str, Extracted] = field(default_factory=dict)
    deadline: Optional[Extracted] = None
    quota_reserve: Optional[Extracted] = None
    git_authority: Optional[Extracted] = None
    cps_profiles: list[Extracted] = field(default_factory=list)
    checkpoints: list[Extracted] = field(default_factory=list)
    artifacts: list[Extracted] = field(default_factory=list)
    validators: list[Extracted] = field(default_factory=list)
    stop_conditions: list[Extracted] = field(default_factory=list)
    placement: Optional[Extracted] = None
    ambiguous: list[Ambiguity] = field(default_factory=list)
    compile: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "mission_id": self.mission_id,
            "goal": self.goal.to_dict() if self.goal else None,
            "non_goals": [item.to_dict() for item in self.non_goals],
            "deliverables": [item.to_dict() for item in self.deliverables],
            "acceptance_tests": [item.to_dict() for item in self.acceptance_tests],
            "claim_envelope": self.claim_envelope.to_dict() if self.claim_envelope else None,
            "data_class": self.data_class.to_dict() if self.data_class else None,
            "dag_hints": [item.to_dict() for item in self.dag_hints],
            "policy": {name: item.to_dict() for name, item in self.policy.items()},
            "deadline": self.deadline.to_dict() if self.deadline else None,
            "quota_reserve": self.quota_reserve.to_dict() if self.quota_reserve else None,
            "git_authority": self.git_authority.to_dict() if self.git_authority else None,
            "cps_profiles": [item.to_dict() for item in self.cps_profiles],
            "checkpoints": [item.to_dict() for item in self.checkpoints],
            "artifacts": [item.to_dict() for item in self.artifacts],
            "validators": [item.to_dict() for item in self.validators],
            "stop_conditions": [item.to_dict() for item in self.stop_conditions],
            "placement": self.placement.to_dict() if self.placement else None,
            "ambiguous": [item.to_dict() for item in self.ambiguous],
            "compile": dict(self.compile),
        }


def mission_nodes(spec: MissionSpec) -> list[dict[str, Any]]:
    """Return the DAG node dicts carried by ``spec.dag_hints``."""
    nodes: list[dict[str, Any]] = []
    for item in spec.dag_hints:
        value = item.value
        if isinstance(value, dict) and value.get("id"):
            nodes.append(value)
    return nodes


def compute_waves(nodes: list[dict[str, Any]]) -> tuple[list[list[str]], list[str]]:
    """Deterministic topological waves; leftover nodes indicate a cycle."""
    ids = [str(node.get("id", "")) for node in nodes]
    edges: dict[str, list[str]] = {node_id: [] for node_id in ids}
    indegree: dict[str, int] = {node_id: 0 for node_id in ids}
    for node in nodes:
        node_id = str(node.get("id", ""))
        for dep in node.get("depends_on", []) or []:
            dep = str(dep)
            if dep in edges:
                edges[dep].append(node_id)
                indegree[node_id] += 1
    waves: list[list[str]] = []
    ready = sorted(node_id for node_id, degree in indegree.items() if degree == 0)
    while ready:
        waves.append(sorted(ready))
        next_ready: set[str] = set()
        for node_id in ready:
            for child in edges.get(node_id, []):
                indegree[child] -= 1
                if indegree[child] == 0:
                    next_ready.add(child)
        ready = sorted(next_ready)
    cycle_nodes = sorted(node_id for node_id, degree in indegree.items() if degree > 0)
    return waves, cycle_nodes


def write_scope_is_unsafe(scope: str) -> bool:
    """True when a write scope escapes the project (absolute or ``..``)."""
    if not isinstance(scope, str) or not scope.strip():
        return True
    normalized = scope.strip().replace("\\", "/")
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:/", normalized):
        return True
    return ".." in normalized.split("/")


def validate_mission(spec: MissionSpec) -> list[Rejection]:
    """Fail-closed structural validation of a compiled MissionSpec.

    Called by the compiler after extraction; returns every material problem
    instead of guessing.
    """

    rejections: list[Rejection] = []

    if spec.goal is None:
        rejections.append(
            Rejection("missing_goal", "goal", "a mission without a goal cannot be reviewed")
        )
    if not spec.deliverables:
        rejections.append(
            Rejection(
                "missing_deliverables", "deliverables", "no deliverables were extracted"
            )
        )
    if spec.claim_envelope is None:
        rejections.append(
            Rejection(
                "missing_claim_envelope",
                "claim_envelope",
                "scientific claim boundary is required before dispatch",
            )
        )
    envelope = spec.claim_envelope
    if envelope is not None and envelope.evidence_level is not None:
        level = envelope.evidence_level.value
        if level not in VALID_EVIDENCE_LEVELS:
            rejections.append(
                Rejection(
                    "invalid_evidence_level",
                    "claim_envelope.evidence_level",
                    f"evidence level {level!r} is not in {VALID_EVIDENCE_LEVELS}",
                    source=envelope.evidence_level.source,
                )
            )

    nodes = mission_nodes(spec)
    _, cycle_nodes = compute_waves(nodes)
    if cycle_nodes:
        rejections.append(
            Rejection(
                "dag_cycle",
                "dag_hints",
                f"dependency cycle among nodes: {cycle_nodes}",
            )
        )
    node_ids = {str(node.get("id", "")) for node in nodes}
    for node in nodes:
        for dep in node.get("depends_on", []) or []:
            if str(dep) not in node_ids:
                rejections.append(
                    Rejection(
                        "unknown_dependency",
                        "dag_hints",
                        f"node {node.get('id')} depends on unknown node {dep!r}",
                    )
                )
        scope = node.get("write_scope")
        if scope is not None and write_scope_is_unsafe(str(scope)):
            rejections.append(
                Rejection(
                    "invalid_write_scope",
                    "dag_hints",
                    f"node {node.get('id')} has unsafe write_scope {scope!r}",
                )
            )

    effort = spec.policy.get("effort")
    if effort is not None and effort.value not in SUPPORTED_EFFORT_NAMES:
        rejections.append(
            Rejection(
                "unsupported_effort",
                "policy.effort",
                f"effort {effort.value!r} is not supported; supported: "
                f"{SUPPORTED_EFFORT_NAMES}; normalize highest-advertised to max",
                source=effort.source,
            )
        )

    validator_ids = {
        str(validator.value.get("id"))
        for validator in spec.validators
        if isinstance(validator.value, dict)
    }
    for node in nodes:
        if node.get("risk") == "high":
            refs = node.get("validator") or []
            if isinstance(refs, str):
                refs = [item.strip() for item in re.split(r"[;,]", refs) if item.strip()]
            if not refs or any(ref not in validator_ids for ref in refs):
                rejections.append(
                    Rejection(
                        "missing_validator_for_high_risk",
                        "dag_hints",
                        f"high-risk node {node.get('id')} requires a known validator "
                        f"(declared: {refs or None}; known: {sorted(validator_ids)})",
                    )
                )

    touches_code = any(
        (node.get("write_scope") or "") not in NON_CODE_WRITE_SCOPES for node in nodes
    )
    if touches_code:
        git = _git_decisions(spec)
        if git is None:
            rejections.append(
                Rejection(
                    "ambiguous_git_authority",
                    "git_authority",
                    "mission writes source paths but declares no commit/push authority",
                )
            )
        else:
            for verb in ("commit", "push"):
                if git.get(verb) in ("unknown", "conflicting"):
                    rejections.append(
                        Rejection(
                            "ambiguous_git_authority",
                            "git_authority",
                            f"git {verb} authority is ambiguous and must be reviewed",
                            source=spec.git_authority.source if spec.git_authority else None,
                        )
                    )

    placement = spec.placement.value if spec.placement else None
    if isinstance(placement, dict):
        workload_host = placement.get("workload_host")
        wrapper = placement.get("wrapper")
        if workload_host == "server" and wrapper in ("none", "absent"):
            rejections.append(
                Rejection(
                    "unwrapped_split_placement",
                    "placement",
                    "desktop-authenticated agent plus remote workload split placement "
                    "requires an explicit wrapper (e.g. remote_worker_client)",
                    source=spec.placement.source if spec.placement else None,
                )
            )

    override = spec.policy.get("policy_excluded_model_override")
    if override is not None and isinstance(override.value, dict) and override.value.get("allowed"):
        pool = override.value.get("pool")
        if pool != OPENCODE_GO_POOL:
            rejections.append(
                Rejection(
                    "invalid_quota_pool",
                    "policy.policy_excluded_model_override",
                    f"policy-excluded model must stay in the shared {OPENCODE_GO_POOL} "
                    f"pool, got {pool!r}",
                    source=override.source,
                )
            )

    return rejections


def _git_decisions(spec: MissionSpec) -> Optional[dict[str, str]]:
    if spec.git_authority is None or not isinstance(spec.git_authority.value, dict):
        return None
    return {
        verb: str(spec.git_authority.value.get(verb, {}).get("decision", "unknown"))
        for verb in ("commit", "push", "merge")
    }
