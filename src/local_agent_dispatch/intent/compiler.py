"""Provider-free mission compiler.

Turns a structured or natural-language mission into a reviewable
``MissionSpec`` plus a material ambiguity list.  This module never executes a
provider, never runs a shell command, never sends a prompt, and never touches
the network: it is pure pattern/structure extraction with fail-closed
validation.

Missions compile into a reviewable spec: goal and non-goals, deliverables,
DAG hints with write-scope-disjoint parallelism, a claim envelope (allowed,
deferred and forbidden claims with an explicit promotion gate), validators,
git authority, placement, checkpoints and stop conditions.  No domain-specific
mission is a privileged example; the explicit OpenCode Go DeepSeek override is
carried as a policy field pinned to the single ``opencode.go`` pool.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

from ..domain.mission import (
    Ambiguity,
    ClaimEnvelope,
    Extracted,
    MissionSpec,
    OPENCODE_GO_POOL,
    POLICY_EXCLUDED_MODEL_FAMILY,
    Rejection,
    SourceRef,
    SUPPORTED_EFFORT_NAMES,
    compute_waves,
    validate_mission,
)

COMPILER_VERSION = "0.1.0"
SCHEMA_VERSION = 2

_SCIENCE_KEYWORDS = re.compile(
    r"(?i)(science|scientific|physics|experiment|simulat|numerical|"
    r"model(?:ing|led)?|measurement|theorem|hypothesis|claim|validation|"
    r"benchmark)"
)
_EFFORT_TOKEN = re.compile(r"(?i)effort\s*[:=]?\s*([a-z][a-z0-9_-]*)")
_ULTRA_REQUESTED = re.compile(r"(?i)(effort\s*[:=]?\s*ultra|\bultra\s+(effort|variant))\b")
_HIGHEST_FLOOR = re.compile(r"(?i)(highest\s+advertised|highest|best|maximum|top)\b")
_DEADLINE_ISO = re.compile(r"(20\d{2}-\d{2}-\d{2})(?:[T ](\d{2}:\d{2}(?::\d{2})?Z?))?")
_EXACT_MODEL_ID = re.compile(r"(opencode-go/[a-z0-9][a-z0-9._-]*|deepseek[a-z0-9._-]*)")
_EXPLICIT_OVERRIDE = re.compile(r"(?i)explicit\s+(user\s+)?override")
_DEEPSEEK_MENTION = re.compile(r"(?i)deepseek")
_SCIENCE_CLAIM_PHRASE = re.compile(r"(?i)\bclaim\b")

_SECTION_ALIASES = {
    "mission": "goal",
    "goal": "goal",
    "objective": "goal",
    "non-goals": "non_goals",
    "non goals": "non_goals",
    "deliverables": "deliverables",
    "acceptance": "acceptance",
    "acceptance tests": "acceptance",
    "claims": "claims",
    "claim envelope": "claims",
    "claim boundary": "claims",
    "evidence": "evidence",
    "data": "data",
    "data class": "data",
    "dag": "dag",
    "task graph": "dag",
    "parallelism": "parallelism",
    "providers": "providers",
    "provider policy": "providers",
    "quality": "quality",
    "model policy": "quality",
    "git": "git",
    "git authority": "git",
    "placement": "placement",
    "placement policy": "placement",
    "deadline": "deadline",
    "quota": "quota",
    "quota reserve": "quota",
    "cps": "cps",
    "checkpoints": "checkpoints",
    "validators": "validators",
    "stop": "stop",
    "stop conditions": "stop",
    "artifacts": "artifacts",
}
_KNOWN_SECTIONS = frozenset(_SECTION_ALIASES.values())
_INLINE_HEADER = re.compile(r"^([A-Za-z][A-Za-z0-9 _/-]*?)\s*:\s*(.+)$")
_BULLET = re.compile(r"^\s*[-*]\s+(.+?)\s*$")
_DELIVERABLE = re.compile(r"^(?P<name>.+?)\s*\(\s*(?P<props>.*?)\s*\)\s*$")
_DAG_NODE = re.compile(r"^(?P<id>[A-Za-z][A-Za-z0-9_-]*)\s*:\s*(?P<rest>.+?)\s*$")
_VALIDATOR_LINE = re.compile(r"^\s*(?P<id>[A-Za-z0-9_-]+)\s*:\s*(?P<desc>.+?)\s*$")
_PROVIDER_BULLET = re.compile(r"^(?P<name>.+?)\s*\(\s*(?P<props>.*?)\s*\)\s*$")


@dataclass
class CompileResult:
    """A compiled mission plus its fail-closed rejections."""

    spec: MissionSpec
    rejected: list[Rejection]

    @property
    def ok(self) -> bool:
        return not self.rejected

    @property
    def ambiguous(self) -> list[Ambiguity]:
        return list(self.spec.ambiguous)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "spec": self.spec.to_dict(),
            "rejected": [item.to_dict() for item in self.rejected],
        }


@dataclass
class _Section:
    """One parsed mission section: header, body, bullets, and offsets."""

    name: str
    start: int
    end: int
    body: str = ""
    bullets: list[tuple[str, int]] = field(default_factory=list)


def _parse_sections(text: str) -> dict[str, _Section]:
    """Split mission text into known sections with character offsets."""
    sections: dict[str, _Section] = {}
    current: Optional[_Section] = None
    offset = 0
    for raw_line in text.split("\n"):
        line = raw_line.rstrip()
        stripped = line.strip()
        line_length = len(line) + 1
        section_name: Optional[str] = None
        if stripped.endswith(":") and _SECTION_ALIASES.get(stripped[:-1].strip().lower()):
            section_name = _SECTION_ALIASES[stripped[:-1].strip().lower()]
        else:
            match = _INLINE_HEADER.match(stripped)
            if match and _SECTION_ALIASES.get(match.group(1).strip().lower()):
                section_name = _SECTION_ALIASES[match.group(1).strip().lower()]
                body = match.group(2).strip()
                if current is not None and section_name != current.name:
                    current.end = offset
                if section_name not in sections:
                    sections[section_name] = _Section(
                        name=section_name,
                        start=offset,
                        end=offset + line_length,
                        body=body,
                    )
                current = sections[section_name]
                offset += line_length
                continue
        if section_name is not None:
            if current is not None:
                current.end = offset
            current = sections.setdefault(
                section_name,
                _Section(name=section_name, start=offset, end=offset + line_length),
            )
        elif current is not None:
            bullet = _BULLET.match(stripped)
            if bullet:
                current.bullets.append((bullet.group(1), offset))
            else:
                current.body = (current.body + " " + stripped).strip()
        offset += line_length
    if current is not None:
        current.end = len(text)
    return sections


def compile_mission(source: str | dict[str, Any], *, mission_id: Optional[str] = None) -> CompileResult:
    """Compile a mission from natural-language text or a structured dict.

    Provider-free and non-executing by construction: the result is a
    reviewable MissionSpec plus an ambiguity list.
    """
    if isinstance(source, str):
        return compile_text(source, mission_id=mission_id)
    if isinstance(source, dict):
        return compile_structured(source, mission_id=mission_id)
    raise TypeError(f"mission source must be str or dict, got {type(source).__name__}")


# --------------------------------------------------------------------------
# Text pipeline
# --------------------------------------------------------------------------

def compile_text(text: str, *, mission_id: Optional[str] = None) -> CompileResult:
    sections = _parse_sections(text)
    spec = MissionSpec(
        mission_id=mission_id or _slug(_section_body(sections, "goal") or "mission"),
        compile={
            "schema_version": SCHEMA_VERSION,
            "compiler_version": COMPILER_VERSION,
            "origin": "natural_language",
            "provider_free": True,
            "executes_nothing": True,
            "source_length": len(text),
        },
    )

    def lit(value: Any, source: SourceRef, status: str = "hard", confidence: float = 0.95) -> Extracted:
        return Extracted(value=value, source=source, status=status, confidence=confidence)

    _compile_sections_into(spec, sections, lit)
    _finalize(spec)
    return CompileResult(spec=spec, rejected=validate_mission(spec))


# --------------------------------------------------------------------------
# Structured pipeline
# --------------------------------------------------------------------------

def compile_structured(source: dict[str, Any], *, mission_id: Optional[str] = None) -> CompileResult:
    spec = MissionSpec(
        mission_id=mission_id or _slug(str(source.get("goal") or "mission")),
        compile={
            "schema_version": SCHEMA_VERSION,
            "compiler_version": COMPILER_VERSION,
            "origin": "structured_input",
            "provider_free": True,
            "executes_nothing": True,
            "source_keys": sorted(source),
        },
    )

    def lit(value: Any, source: SourceRef, status: str = "hard", confidence: float = 1.0) -> Extracted:
        return Extracted(value=value, source=source, status=status, confidence=confidence)

    ref = SourceRef.structured
    if source.get("goal"):
        spec.goal = lit(str(source["goal"]), ref("goal"))
    spec.non_goals = [lit(str(item), ref(f"non_goals[{i}]")) for i, item in enumerate(source.get("non_goals") or [])]
    spec.acceptance_tests = [
        lit(str(item), ref(f"acceptance_tests[{i}]")) for i, item in enumerate(source.get("acceptance_tests") or [])
    ]
    spec.deliverables = [
        _deliverable_from_dict(item, ref(f"deliverables[{i}]"), lit)
        for i, item in enumerate(source.get("deliverables") or [])
    ]
    spec.dag_hints = [
        _dag_node_from_dict(item, ref(f"dag[{i}]"), lit)
        for i, item in enumerate(source.get("dag") or [])
    ]
    spec.validators = [
        lit({"id": str(item.get("id")), "description": str(item.get("description"))}, ref(f"validators[{i}]"))
        for i, item in enumerate(source.get("validators") or [])
    ]
    spec.cps_profiles = [
        lit(dict(item), ref(f"cps[{i}]")) for i, item in enumerate(source.get("cps") or [])
    ]
    spec.checkpoints = [
        lit(str(item), ref(f"checkpoints[{i}]")) for i, item in enumerate(source.get("checkpoints") or [])
    ]
    spec.stop_conditions = [
        lit(str(item), ref(f"stop_conditions[{i}]")) for i, item in enumerate(source.get("stop_conditions") or [])
    ]
    spec.artifacts = [
        lit(dict(item), ref(f"artifacts[{i}]")) for i, item in enumerate(source.get("artifacts") or [])
    ]

    claims = source.get("claims") or {}
    _install_claims(spec, {
        "allowed": claims.get("allowed", []),
        "deferred": claims.get("deferred", []),
        "forbidden": claims.get("forbidden", []),
        "promotion_gate": claims.get("promotion_gate"),
        "evidence_level": source.get("evidence") or claims.get("evidence_level"),
    }, lit, ref)
    _install_evidence_ambiguity(spec, source.get("evidence") or claims.get("evidence_level"))

    data = source.get("data") or {}
    if data:
        spec.data_class = lit(
            {
                "classification": data.get("classification", "unknown"),
                "location": data.get("location", "unknown"),
                "route_gate": bool(data.get("route_gate", False)),
            },
            ref("data"),
            status="hard",
        )

    deadline = source.get("deadline")
    if deadline:
        parsed = _parse_deadline(str(deadline))
        if parsed:
            spec.deadline = lit(parsed, ref("deadline"))
        else:
            _add_ambiguity(
                spec,
                "deadline",
                f"deadline {deadline!r} could not be parsed as ISO; scheduling cannot be bounded",
                ("cost",),
                source=ref("deadline"),
            )
    else:
        _add_ambiguity(
            spec,
            "deadline",
            "no deadline stated; scheduling and reserve cannot be bounded",
            ("cost",),
        )

    quota = source.get("quota_reserve")
    if quota:
        percent = quota.get("percent") if isinstance(quota, dict) else quota
        spec.quota_reserve = lit(
            {"percent": float(percent), "pool": "mission-level"},
            ref("quota_reserve"),
            status="soft",
            confidence=0.8,
        )
    else:
        _add_ambiguity(
            spec,
            "quota_reserve",
            "quota reserve unspecified; unknown remains unknown and must be reviewed",
            ("cost",),
        )

    _install_policy(spec, source.get("policy") or {}, lit, ref)
    _install_git(spec, source.get("git"), lit, ref)
    _install_placement(spec, source.get("placement"), lit, ref)

    _finalize(spec)
    return CompileResult(spec=spec, rejected=validate_mission(spec))


# --------------------------------------------------------------------------
# Shared extraction
# --------------------------------------------------------------------------

def _compile_sections_into(
    spec: MissionSpec,
    sections: dict[str, _Section],
    lit: Any,
) -> None:
    ref = SourceRef

    goal_body = _section_body(sections, "goal")
    if goal_body:
        goal_section = sections.get("goal")
        spec.goal = lit(
            goal_body,
            ref(origin="user_prompt", span=(goal_section.start, goal_section.end) if goal_section else None, phrase=goal_body[:80]),
        )

    non_goals = sections.get("non_goals")
    if non_goals:
        for text, offset in non_goals.bullets:
            spec.non_goals.append(lit(text, ref(origin="user_prompt", span=(offset, offset + len(text)))))
    if not spec.non_goals:
        _add_ambiguity(
            spec,
            "non_goals",
            "no non-goals stated; claim and side-effect boundary is unknown",
            ("permissions", "scientific_claims"),
        )

    for name, description in (
        ("deliverables", spec.deliverables),
        ("acceptance", spec.acceptance_tests),
    ):
        section = sections.get(name)
        if not section:
            continue
        for text, offset in section.bullets:
            source = ref(origin="user_prompt", span=(offset, offset + len(text)))
            if name == "deliverables":
                description.append(_deliverable_from_text(text, source, lit))
            else:
                description.append(lit(text, source))

    _install_claims_from_sections(spec, sections, lit)
    _install_data_from_sections(spec, sections, lit)
    _install_dag_from_sections(spec, sections, lit)
    _install_validators_from_sections(spec, sections, lit)
    _install_providers_from_sections(spec, sections, lit)
    _install_quality_from_sections(spec, sections, lit)
    _install_git_from_sections(spec, sections, lit)
    _install_placement_from_sections(spec, sections, lit)

    deadline_section = sections.get("deadline")
    if deadline_section:
        parsed = _parse_deadline(deadline_section.body)
        if parsed:
            spec.deadline = lit(
                parsed,
                ref(origin="user_prompt", span=(deadline_section.start, deadline_section.end)),
            )
        else:
            _add_ambiguity(
                spec,
                "deadline",
                f"deadline {deadline_section.body!r} could not be parsed as ISO",
                ("cost",),
                source=ref(origin="user_prompt", span=(deadline_section.start, deadline_section.end)),
            )
    else:
        _add_ambiguity(
            spec,
            "deadline",
            "no deadline stated; scheduling and reserve cannot be bounded",
            ("cost",),
        )

    quota_section = sections.get("quota")
    if quota_section:
        percent = None
        for text, offset in quota_section.bullets:
            match = re.match(r"(?i)(?:reserve|percent)\s*[:=]?\s*(\d+(?:\.\d+)?)\s*%?", text)
            if match:
                percent = float(match.group(1))
                source = ref(origin="user_prompt", span=(offset, offset + len(text)))
        if percent is not None:
            spec.quota_reserve = lit(
                {"percent": percent, "pool": "mission-level"},
                source,
                status="soft",
                confidence=0.8,
            )
        else:
            _add_ambiguity(
                spec,
                "quota_reserve",
                "quota reserve given but not parsed as a percentage; keep unknown",
                ("cost",),
            )
    else:
        _add_ambiguity(
            spec,
            "quota_reserve",
            "quota reserve unspecified; unknown remains unknown and must be reviewed",
            ("cost",),
        )

    checkpoints = sections.get("checkpoints")
    if checkpoints:
        for text, offset in checkpoints.bullets:
            spec.checkpoints.append(lit(text, ref(origin="user_prompt", span=(offset, offset + len(text)))))
    stop = sections.get("stop")
    if stop:
        for text, offset in stop.bullets:
            spec.stop_conditions.append(lit(text, ref(origin="user_prompt", span=(offset, offset + len(text)))))
    cps = sections.get("cps")
    if cps:
        for text, offset in cps.bullets:
            role, _, description = text.partition(":")
            spec.cps_profiles.append(
                lit(
                    {"role": role.strip(), "description": description.strip()},
                    ref(origin="user_prompt", span=(offset, offset + len(text))),
                )
            )


def _install_claims_from_sections(spec: MissionSpec, sections: dict[str, _Section], lit: Any) -> None:
    ref = SourceRef
    claims_section = sections.get("claims")
    evidence_section = sections.get("evidence")
    evidence_value = _parse_evidence(evidence_section.body if evidence_section else "")
    evidence_source = (
        ref(origin="user_prompt", span=(evidence_section.start, evidence_section.end))
        if evidence_section
        else None
    )

    allowed: list[str] = []
    deferred: list[str] = []
    forbidden: list[str] = []
    promotion_gate: Optional[Extracted] = None
    if claims_section:
        for text, offset in claims_section.bullets:
            key, _, value = text.partition(":")
            key = key.strip().lower()
            if key in ("allowed", "deferred", "forbidden"):
                items = _split_list(value)
                target = {"allowed": allowed, "deferred": deferred, "forbidden": forbidden}[key]
                if not items or items == ["none"]:
                    items = []
                target.extend(items)
            elif key in ("promotion_gate", "gate"):
                promotion_gate = lit(
                    value.strip(),
                    ref(origin="user_prompt", span=(offset, offset + len(text))),
                )

    _install_claims(spec, {
        "allowed": allowed,
        "deferred": deferred,
        "forbidden": forbidden,
        "promotion_gate": promotion_gate.value if promotion_gate else None,
        "evidence_level": evidence_value,
    }, lit, ref)
    if evidence_source is not None and spec.claim_envelope is not None and evidence_value is not None:
        spec.claim_envelope.evidence_level = lit(evidence_value, evidence_source)
    _install_evidence_ambiguity(spec, evidence_value, source=evidence_source)


def _install_evidence_ambiguity(
    spec: MissionSpec,
    evidence_value: Optional[str],
    source: Optional[SourceRef] = None,
) -> None:
    del source  # evidence-level review is a finalize-time decision
    if evidence_value is None:
        _install_evidence_ambiguity_source(spec)


def _spec_prose(spec: MissionSpec) -> str:
    parts: list[str] = []
    if spec.goal is not None:
        parts.append(str(spec.goal.value))
    for item in spec.deliverables:
        value = item.value
        parts.append(str(value.get("description", "") if isinstance(value, dict) else value))
    for item in spec.non_goals:
        parts.append(str(item.value))
    for item in spec.acceptance_tests:
        parts.append(str(item.value))
    return " ".join(parts)


def _install_claims(
    spec: MissionSpec,
    claims: dict[str, Any],
    lit: Any,
    ref: Any,
) -> None:
    allowed = _split_list(claims.get("allowed") or [])
    deferred = _split_list(claims.get("deferred") or [])
    forbidden = _split_list(claims.get("forbidden") or [])
    gate = claims.get("promotion_gate")
    evidence = claims.get("evidence_level")
    evidence_value = _parse_evidence(str(evidence)) if evidence is not None else None

    if not allowed and not deferred and not forbidden and gate is None:
        mission_text = _spec_prose(spec)
        scientific = bool(_SCIENCE_KEYWORDS.search(mission_text)) or bool(
            _SCIENCE_CLAIM_PHRASE.search(mission_text)
        )
        if scientific:
            spec.claim_envelope = None
            return

    spec.claim_envelope = ClaimEnvelope(
        allowed=allowed,
        deferred=deferred,
        forbidden=forbidden,
        promotion_gate=lit(str(gate), SourceRef.compiler("promotion gate from mission claims")) if gate else None,
        evidence_level=lit(evidence_value, SourceRef.compiler("evidence tier from mission")) if evidence_value else None,
    )

def _install_evidence_ambiguity_source(spec: MissionSpec) -> None:
    envelope = spec.claim_envelope
    if envelope is None or envelope.evidence_level is not None:
        return
    if _SCIENCE_KEYWORDS.search(_spec_prose(spec)):
        _add_ambiguity(
            spec,
            "evidence_level",
            "scientific mission states no evidence level; evidence tier must be reviewed",
            ("scientific_claims",),
        )


def _install_data_from_sections(spec: MissionSpec, sections: dict[str, _Section], lit: Any) -> None:
    ref = SourceRef
    data_section = sections.get("data")
    if not data_section:
        return
    values: dict[str, Any] = {"classification": "unknown", "location": "unknown", "route_gate": False}
    for text, offset in data_section.bullets:
        key, _, value = text.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if key == "location":
            values["location"] = value.split("(")[0].strip()
        elif key == "classification":
            values["classification"] = value.split("(")[0].strip()
        elif key == "route_gate":
            values["route_gate"] = "required" in value.lower() or value.lower() in ("true", "yes")
    spec.data_class = lit(
        values,
        ref(origin="user_prompt", span=(data_section.start, data_section.end)),
    )


def _install_dag_from_sections(spec: MissionSpec, sections: dict[str, _Section], lit: Any) -> None:
    ref = SourceRef
    dag_section = sections.get("dag")
    if dag_section:
        for text, offset in dag_section.bullets:
            spec.dag_hints.append(
                _dag_node_from_text(text, ref(origin="user_prompt", span=(offset, offset + len(text))), lit)
            )
    else:
        order = [str(item.value.get("id", f"d{i}")) for i, item in enumerate(spec.deliverables) if isinstance(item.value, dict)]
        for index, item in enumerate(spec.deliverables):
            value = item.value
            node = {
                "id": value.get("id", f"d{index}"),
                "description": value.get("description", ""),
                "depends_on": [order[index - 1]] if index > 0 else [],
                "write_scope": value.get("write_scope"),
                "risk": value.get("risk", "low"),
                "parallel": False,
            }
            spec.dag_hints.append(
                Extracted(
                    value=node,
                    source=SourceRef.compiler(f"serial DAG inferred from deliverables[{index}]"),
                    status="soft",
                    confidence=0.6,
                )
            )
    _ensure_preflight(spec, lit)
    _install_parallelism_check(spec)
    _install_derived_artifacts(spec, lit, ref)


def _ensure_preflight(spec: MissionSpec, lit: Any) -> None:
    nodes = [str(item.value.get("id")) for item in spec.dag_hints if isinstance(item.value, dict)]
    if any(node_id in ("s0", "preflight") for node_id in nodes):
        return
    preflight = {
        "id": "s0",
        "description": "system/provider/host/mount/route preflight",
        "depends_on": [],
        "write_scope": ".lad/",
        "risk": "low",
        "parallel": True,
        "output_paths": [".lad/preflight.json"],
    }
    spec.dag_hints.insert(
        0,
        Extracted(
            value=preflight,
            source=SourceRef.compiler("system invariant: preflight precedes dispatch"),
            status="hard",
            confidence=1.0,
        ),
    )


def _install_parallelism_check(spec: MissionSpec) -> None:
    nodes = [item.value for item in spec.dag_hints if isinstance(item.value, dict)]
    for node in nodes:
        if node.get("write_scope") is None:
            node["write_scope"] = "unknown"
            _add_ambiguity(
                spec,
                "write_scope",
                f"node {node.get('id')} has no write scope; write safety cannot be bounded",
                ("permissions",),
            )

    waves, cycle_nodes = compute_waves(nodes)
    if cycle_nodes:
        return
    conflicts: list[str] = []
    for wave in waves:
        wave_nodes = [node for node in nodes if node.get("id") in wave]
        for i, first in enumerate(wave_nodes):
            for second in wave_nodes[i + 1:]:
                if not _write_scopes_disjoint(first.get("write_scope"), second.get("write_scope")):
                    first["parallel"] = False
                    second["parallel"] = False
                    conflicts.append(f"{first.get('id')}+{second.get('id')}")
    if conflicts:
        _add_ambiguity(
            spec,
            "parallelism",
            "parallel nodes have overlapping or unknown write scopes and were "
            f"serialized: {', '.join(sorted(set(conflicts)))}",
            ("permissions",),
        )


def _write_scopes_disjoint(first: Any, second: Any) -> bool:
    if not isinstance(first, str) or not isinstance(second, str):
        return False
    if first == "unknown" or second == "unknown":
        return False
    a = first.rstrip("/")
    b = second.rstrip("/")
    if a == b:
        return False
    return not (a.startswith(b + "/") or b.startswith(a + "/"))


def _install_derived_artifacts(spec: MissionSpec, lit: Any, ref: Any) -> None:
    ref = SourceRef
    existing = set()
    for item in spec.artifacts:
        if isinstance(item.value, dict) and item.value.get("path"):
            existing.add(str(item.value["path"]))
    for deliverable in spec.deliverables:
        value = deliverable.value
        if not isinstance(value, dict):
            continue
        for path in value.get("paths") or []:
            if path not in existing:
                spec.artifacts.append(
                    Extracted(
                        value={
                            "path": path,
                            "description": f"{value.get('description')} deliverable",
                            "digest": "unknown",
                            "source_node": value.get("id"),
                        },
                        source=ref.compiler("artifact derived from deliverable path"),
                        status="unknown",
                        confidence=0.6,
                    )
                )
                existing.add(path)
    for node in [item.value for item in spec.dag_hints if isinstance(item.value, dict)]:
        for path in node.get("output_paths") or []:
            if path not in existing:
                spec.artifacts.append(
                    Extracted(
                        value={
                            "path": path,
                            "description": f"{node.get('description')} output",
                            "digest": "unknown",
                            "source_node": node.get("id"),
                        },
                        source=ref.compiler(f"artifact derived from node {node.get('id')}"),
                        status="unknown",
                        confidence=0.6,
                    )
                )
                existing.add(path)


def _install_validators_from_sections(spec: MissionSpec, sections: dict[str, _Section], lit: Any) -> None:
    ref = SourceRef
    section = sections.get("validators")
    if not section:
        return
    for text, offset in section.bullets:
        match = _VALIDATOR_LINE.match(text)
        if match:
            spec.validators.append(
                lit(
                    {"id": match.group("id"), "description": match.group("desc")},
                    ref(origin="user_prompt", span=(offset, offset + len(text))),
                )
            )


def _install_providers_from_sections(spec: MissionSpec, sections: dict[str, _Section], lit: Any) -> None:
    ref = SourceRef
    section = sections.get("providers")
    if not section:
        spec.policy["provider_policy"] = Extracted(
            value={"providers": [], "selection": "unspecified"},
            source=SourceRef.compiler("provider selection left to the scheduler policy"),
            status="unknown",
            confidence=0.6,
        )
        return

    providers: list[dict[str, Any]] = []
    pools: dict[str, dict[str, Any]] = {}
    deepseek_override: Optional[dict[str, Any]] = None
    deepseek_source: Optional[SourceRef] = None
    for text, offset in section.bullets:
        match = _PROVIDER_BULLET.match(text)
        source = ref(origin="user_prompt", span=(offset, offset + len(text)))
        name = match.group("name").strip() if match else text
        props = match.group("props") if match else ""
        pool: Optional[str] = None
        role: str = ""
        override = False
        for part in props.split(";"):
            part = part.strip()
            key, _, value = part.partition(":")
            key = key.strip().lower()
            if key == "pool":
                pool = value.strip()
            elif key == "role":
                role = value.strip()
            elif _EXPLICIT_OVERRIDE.search(part):
                override = True
        provider = {"name": name, "pool": pool, "role": role}
        providers.append(provider)
        if pool:
            pools.setdefault(pool, {"members": [], "role": role})
            pools[pool]["members"].append(name)
        if _DEEPSEEK_MENTION.search(name):
            exact_match = _EXACT_MODEL_ID.search(text)
            exact_model = exact_match.group(1) if exact_match else None
            if exact_model and not exact_model.startswith("opencode-go/"):
                exact_model = f"opencode-go/{exact_model}"
            deepseek_override = {
                "allowed": override,
                "family": POLICY_EXCLUDED_MODEL_FAMILY,
                "exact_model": exact_model,
                "pool": pool or OPENCODE_GO_POOL,
                "model_role": "explicit_policy_override",
                "separate_quota_pool": False,
                "requires_review": True,
            }
            deepseek_source = source
            if not override:
                _add_ambiguity(
                    spec,
                    "policy_excluded_model_override",
                    "DeepSeek member mentioned without an explicit user override; "
                    "DeepSeek remains excluded from dispatch policy",
                    ("cost", "permissions"),
                    source=source,
                )

    if deepseek_override is not None and not deepseek_override["allowed"]:
        deepseek_override["allowed"] = False
    if deepseek_override is not None:
        spec.policy["policy_excluded_model_override"] = Extracted(
            value=deepseek_override,
            source=deepseek_source or SourceRef.compiler("policy-excluded model override"),
            status="soft",
            confidence=0.8,
        )
        if deepseek_override["pool"] != OPENCODE_GO_POOL:
            deepseek_override["pool"] = OPENCODE_GO_POOL
        if deepseek_override["allowed"] and deepseek_override["exact_model"] is None:
            _add_ambiguity(
                spec,
                "model_policy",
                "exact OpenCode Go DeepSeek member id must be confirmed against the "
                "live catalog before dispatch",
                ("cost",),
                source=deepseek_source,
            )

    spec.policy["provider_policy"] = Extracted(
        value={"providers": providers},
        source=section_source_from(section),
        status="soft",
        confidence=0.9,
    )
    spec.policy["pool_policy"] = Extracted(
        value={"pools": pools, "shared_pool_rule": "model brand never creates a separate quota pool"},
        source=SourceRef.compiler("shared quota pool policy"),
        status="hard",
        confidence=1.0,
    )

    for provider in providers:
        if provider["pool"] is None:
            _add_ambiguity(
                spec,
                "pool_policy",
                f"provider {provider['name']!r} has no quota pool; cost accounting cannot be bounded",
                ("cost",),
            )
        elif not _EXACT_MODEL_ID.search(str(provider["name"])) and not _DEEPSEEK_MENTION.search(
            str(provider["name"])
        ):
            _add_ambiguity(
                spec,
                "model_policy",
                f"exact model id for {provider['name']!r} must be resolved from the live "
                "catalog; a family name is not an id",
                ("cost",),
            )


def _install_policy(
    spec: MissionSpec,
    policy: dict[str, Any],
    lit: Any,
    ref: Any,
) -> None:
    """Install model/provider/pool policy from a structured mission."""
    providers: list[dict[str, Any]] = []
    pools: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(policy.get("providers") or []):
        if isinstance(item, dict):
            provider = {
                "name": str(item.get("name", "")),
                "pool": item.get("pool"),
                "role": str(item.get("role", "")),
            }
            override = bool(item.get("explicit_user_override", False))
        else:
            text = str(item)
            match = _PROVIDER_BULLET.match(text)
            name = match.group("name").strip() if match else text
            props = match.group("props") if match else ""
            pool = None
            role = ""
            override = False
            for part in props.split(";"):
                key, _, value = part.partition(":")
                key = key.strip().lower()
                if key == "pool":
                    pool = value.strip()
                elif key == "role":
                    role = value.strip()
                elif _EXPLICIT_OVERRIDE.search(part):
                    override = True
            provider = {"name": name, "pool": pool, "role": role}
        providers.append(provider)
        if provider.get("pool"):
            pools.setdefault(provider["pool"], {"members": [], "role": provider.get("role", "")})
            pools[provider["pool"]]["members"].append(provider["name"])
        if _DEEPSEEK_MENTION.search(str(provider["name"])):
            exact_model = None
            exact_match = _EXACT_MODEL_ID.search(str(provider["name"]))
            if exact_match:
                exact_model = exact_match.group(1)
            elif isinstance(policy.get("allow_policy_excluded_models"), list):
                for candidate in policy["allow_policy_excluded_models"]:
                    if "deepseek" in str(candidate).lower():
                        exact_model = str(candidate)
            if exact_model and not exact_model.startswith("opencode-go/"):
                exact_model = f"opencode-go/{exact_model}"
            allowed = bool(override or policy.get("allow_policy_excluded_models"))
            spec.policy["policy_excluded_model_override"] = Extracted(
                value={
                    "allowed": allowed,
                    "family": POLICY_EXCLUDED_MODEL_FAMILY,
                    "exact_model": exact_model,
                    "pool": provider.get("pool") or OPENCODE_GO_POOL,
                    "model_role": "explicit_policy_override",
                    "separate_quota_pool": False,
                    "requires_review": True,
                },
                source=ref("policy.providers"),
                status="soft",
                confidence=0.8,
            )
            if not allowed:
                _add_ambiguity(
                    spec,
                    "policy_excluded_model_override",
                    "DeepSeek member mentioned without allow_policy_excluded_models; "
                    "DeepSeek remains excluded from dispatch policy",
                    ("cost", "permissions"),
                    source=ref("policy.providers"),
                )
            elif exact_model is None:
                _add_ambiguity(
                    spec,
                    "model_policy",
                    "exact OpenCode Go DeepSeek member id must be confirmed against the "
                    "live catalog before dispatch",
                    ("cost",),
                    source=ref("policy.providers"),
                )

    if providers:
        spec.policy["provider_policy"] = Extracted(
            value={"providers": providers},
            source=ref("policy.providers"),
            status="soft",
            confidence=0.9,
        )
        spec.policy["pool_policy"] = Extracted(
            value={
                "pools": pools,
                "shared_pool_rule": "model brand never creates a separate quota pool",
            },
            source=ref("policy.pools"),
            status="hard",
            confidence=1.0,
        )

    effort = policy.get("effort")
    if effort:
        spec.policy["effort"] = Extracted(
            value=str(effort).lower(),
            source=ref("policy.effort"),
            status="hard",
            confidence=1.0,
        )
    floor = policy.get("quality_floor")
    if floor:
        spec.policy["quality_floor"] = Extracted(
            value=str(floor).lower(),
            source=ref("policy.quality_floor"),
            status="soft",
            confidence=0.9,
        )
        if not effort and _HIGHEST_FLOOR.search(str(floor)):
            spec.policy["effort"] = Extracted(
                value="max",
                source=SourceRef.compiler("highest advertised quality floor normalizes to max effort"),
                status="soft",
                confidence=0.7,
            )


def section_source_from(section: _Section) -> SourceRef:
    return SourceRef(origin="user_prompt", span=(section.start, section.end))


def _install_quality_from_sections(spec: MissionSpec, sections: dict[str, _Section], lit: Any) -> None:
    ref = SourceRef
    section = sections.get("quality")
    if not section:
        return
    text = section.body + " " + " ".join(item[0] for item in section.bullets)
    source = ref(origin="user_prompt", span=(section.start, section.end))

    if _ULTRA_REQUESTED.search(text):
        effort = "ultra"
    else:
        effort_match = _EFFORT_TOKEN.search(text)
        effort = effort_match.group(1).lower() if effort_match else None

    if effort == "ultra":
        spec.policy["effort"] = Extracted(
            value="ultra",
            source=source,
            status="hard",
            confidence=0.95,
        )
    elif effort is not None and effort not in SUPPORTED_EFFORT_NAMES:
        _add_ambiguity(
            spec,
            "effort",
            f"effort {effort!r} is not an advertised effort name; keep unknown",
            ("cost",),
            source=source,
        )
    elif effort is not None:
        spec.policy["effort"] = Extracted(
            value=effort,
            source=source,
            status="hard",
            confidence=0.95,
        )

    if _HIGHEST_FLOOR.search(text):
        floor = "highest_advertised"
        spec.policy["quality_floor"] = Extracted(
            value=floor,
            source=source,
            status="soft",
            confidence=0.8,
        )
        if "effort" not in spec.policy:
            spec.policy["effort"] = Extracted(
                value="max",
                source=SourceRef.compiler("highest advertised intelligence normalizes to max effort"),
                status="soft",
                confidence=0.7,
            )


def _install_git_from_sections(spec: MissionSpec, sections: dict[str, _Section], lit: Any) -> None:
    ref = SourceRef
    section = sections.get("git")
    if not section:
        return
    text = section.body + " " + " ".join(item[0] for item in section.bullets)
    source = ref(origin="user_prompt", span=(section.start, section.end))
    _install_git(spec, text, lit, ref, source=source)


def _install_git(
    spec: MissionSpec,
    git_input: Any,
    lit: Any,
    ref: Any,
    source: Optional[SourceRef] = None,
) -> None:
    if git_input is None:
        return
    if isinstance(git_input, dict):
        decisions = {
            verb: _git_decision_from_value(git_input.get(verb, "unknown"))
            for verb in ("commit", "push", "merge")
        }
        branch = git_input.get("branch")
    else:
        text = str(git_input)
        decisions = {verb: _git_decision_from_text(text, verb) for verb in ("commit", "push", "merge")}
        branch = None

    has_human_gate = any(
        "human commit gate" in str(item.value.get("description", "")) or "commit gate" in str(item.value.get("description", ""))
        for item in spec.dag_hints
        if isinstance(item.value, dict)
    )
    spec.git_authority = Extracted(
        value={
            "commit": {"decision": decisions["commit"]},
            "push": {"decision": decisions["push"]},
            "merge": {"decision": decisions["merge"]},
            "branch": branch,
            "human_commit_gate": has_human_gate,
        },
        source=source or SourceRef.compiler("git authority from structured input"),
        status="hard",
        confidence=0.9,
    )


def _git_decision_from_text(text: str, verb: str) -> str:
    deny = re.search(rf"(?i)never\s+{verb}|{verb}\s+[^;.]*?(?:forbidden|denied|not allowed|never)", text)
    review = re.search(rf"(?i){verb}\s+[^;.]*?(?:require\w*\s+review|review\s+required|approval|gate)", text)
    allow = re.search(rf"(?i){verb}\s+[^;.]*?(?:when appropriate|allowed|authorized|may|can|directly|ok)", text)
    if deny and not review and not allow:
        return "deny"
    if review:
        return "review_required"
    if allow or deny:
        return "allow" if allow else "deny"
    return "unknown"


def _git_decision_from_value(value: Any) -> str:
    if value is None:
        return "unknown"
    text = str(value).lower().strip()
    if text in ("deny", "no", "never", "forbidden"):
        return "deny"
    if text in ("review", "review_required", "approval", "gate"):
        return "review_required"
    if text in ("allow", "yes", "ok", "authorized"):
        return "allow"
    return "unknown"


def _install_placement_from_sections(spec: MissionSpec, sections: dict[str, _Section], lit: Any) -> None:
    ref = SourceRef
    section = sections.get("placement")
    if not section:
        return
    values: dict[str, str] = {"execution_host": "local", "workload_host": "unknown", "preference": "unknown", "wrapper": None}
    for text, offset in section.bullets:
        key, _, value = text.partition(":")
        key = key.strip().lower()
        value = value.split("(")[0].strip().lower()
        if key in ("execution_host", "workload_host", "preference", "wrapper"):
            values[key] = value
    _install_placement(spec, values, lit, ref, source=ref(origin="user_prompt", span=(section.start, section.end)))


def _install_placement(
    spec: MissionSpec,
    placement: Any,
    lit: Any,
    ref: Any,
    source: Optional[SourceRef] = None,
) -> None:
    if placement is None:
        return
    values = dict(placement)
    if values.get("execution_host") in (None, ""):
        values["execution_host"] = "local"
    spec.placement = Extracted(
        value=values,
        source=source or SourceRef.compiler("placement from structured input"),
        status="soft",
        confidence=0.85,
    )
    workload_host = values.get("workload_host")
    wrapper = values.get("wrapper")
    if workload_host == "server" and wrapper in (None, "unknown", "unspecified"):
        _add_ambiguity(
            spec,
            "placement",
            "server-first workload placement with desktop-authenticated agents "
            "requires a declared wrapper (e.g. remote_worker_client) before any "
            "split placement",
            ("permissions",),
            source=source,
        )


def _finalize(spec: MissionSpec) -> None:
    """Post-extraction inference: defaults, claim envelope, checkpoints."""
    _install_evidence_ambiguity_source(spec)
    _install_default_checkpoints(spec)
    _install_default_stop_conditions(spec)
    _install_default_cps(spec)


def _install_default_checkpoints(spec: MissionSpec) -> None:
    if spec.checkpoints:
        return
    gate_descriptions = [
        ("preflight", "s0", "preflight gate"),
        ("integration", "s2", "integration gate"),
        ("validation", "s4", "validation gate"),
        ("review", "s5", "independent review"),
        ("human gate", "s6", "human commit gate"),
    ]
    node_ids = [str(item.value.get("id")) for item in spec.dag_hints if isinstance(item.value, dict)]
    for _, node_id, label in gate_descriptions:
        if node_id in node_ids:
            spec.checkpoints.append(
                Extracted(
                    value=label,
                    source=SourceRef.compiler(f"checkpoint inferred from {node_id}"),
                    status="soft",
                    confidence=0.7,
                )
            )
    if not spec.checkpoints:
        spec.checkpoints.append(
            Extracted(
                value="preflight gate",
                source=SourceRef.compiler("default checkpoint"),
                status="soft",
                confidence=0.6,
            )
        )


def _install_default_stop_conditions(spec: MissionSpec) -> None:
    if spec.stop_conditions:
        return
    spec.stop_conditions.append(
        Extracted(
            value="claim-boundary expansion attempt stops the mission",
            source=SourceRef.compiler("claim boundary invariant"),
            status="hard",
            confidence=1.0,
        )
    )


def _install_default_cps(spec: MissionSpec) -> None:
    if spec.cps_profiles:
        return
    profiles = [
        {"role": "implementer", "description": "bounded write-scoped execution capsule"},
        {"role": "validator", "description": "deterministic validation capsule"},
    ]
    for item in spec.dag_hints:
        node = item.value
        if isinstance(node, dict) and node.get("risk") == "high":
            profiles.append(
                {"role": "independent_reviewer", "description": f"independent review of {node.get('id')}"}
            )
    if any("human commit gate" in str(item.value.get("description", "")) for item in spec.dag_hints if isinstance(item.value, dict)):
        profiles.append({"role": "human_gate", "description": "commit and push approval"})
    for profile in profiles:
        spec.cps_profiles.append(
            Extracted(
                value=profile,
                source=SourceRef.compiler("default CPS profile"),
                status="soft",
                confidence=0.6,
            )
        )


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _section_body(sections: dict[str, _Section], name: str) -> str:
    section = sections.get(name)
    return section.body if section else ""


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return (slug or "mission")[:60]


def _split_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if value is None:
        return []
    text = str(value)
    if text.strip().lower() in ("none", "n/a", "not applicable", "no claims"):
        return []
    parts = re.split(r"[;,]", text)
    return [item.strip() for item in parts if item.strip()]


def _parse_deadline(text: str) -> Optional[str]:
    match = _DEADLINE_ISO.search(text)
    if not match:
        return None
    date = match.group(1)
    time = match.group(2)
    return f"{date}T{time}" if time else date


def _parse_evidence(text: str) -> Optional[str]:
    match = re.search(r"(?i)\bE[0-4]\b", text)
    return match.group(0).upper() if match else None


def _add_ambiguity(
    spec: MissionSpec,
    field: str,
    question: str,
    materiality: tuple[str, ...],
    alternatives: tuple[str, ...] = (),
    source: Optional[SourceRef] = None,
) -> None:
    if any(item.field == field and item.question == question for item in spec.ambiguous):
        return
    spec.ambiguous.append(
        Ambiguity(
            field=field,
            question=question,
            materiality=materiality,
            alternatives=alternatives,
            source=source,
        )
    )


def _deliverable_from_text(text: str, source: SourceRef, lit: Any) -> Extracted:
    match = _DELIVERABLE.match(text)
    if not match:
        return lit(
            {"id": _slug(text), "description": text, "paths": [], "write_scope": None, "risk": "low"},
            source,
            status="soft",
            confidence=0.6,
        )
    props: dict[str, str] = {}
    for part in match.group("props").split(";"):
        key, _, value = part.partition(":")
        props[key.strip().lower()] = value.strip()
    name = match.group("name").strip()
    paths = [item.strip() for item in re.split(r"[,]", props.get("paths", props.get("path", ""))) if item.strip()]
    return lit(
        {
            "id": props.get("id", _slug(name)),
            "description": name,
            "paths": paths,
            "write_scope": props.get("write_scope"),
            "risk": props.get("risk", "low"),
        },
        source,
        status="hard" if props else "soft",
        confidence=0.95 if props else 0.6,
    )


def _deliverable_from_dict(item: dict[str, Any], source: SourceRef, lit: Any) -> Extracted:
    return lit(
        {
            "id": str(item.get("id", _slug(str(item.get("description", ""))))),
            "description": str(item.get("description", "")),
            "paths": list(item.get("paths") or []),
            "write_scope": item.get("write_scope"),
            "risk": item.get("risk", "low"),
        },
        source,
        status="hard",
        confidence=1.0,
    )


def _dag_node_from_text(text: str, source: SourceRef, lit: Any) -> Extracted:
    match = _DAG_NODE.match(text)
    if not match:
        return Extracted(
            value={"id": _slug(text), "description": text, "depends_on": [], "parallel": False},
            source=source,
            status="soft",
            confidence=0.6,
        )
    node: dict[str, Any] = {
        "id": match.group("id"),
        "depends_on": [],
        "parallel": False,
    }
    parts = match.group("rest").split(";")
    node["description"] = parts[0].strip()
    for part in parts[1:]:
        part = part.strip()
        if ":" not in part:
            if node.get("validator"):
                node["validator"] = f"{node['validator']}; {part}"
            continue
        key, _, value = part.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if key in ("depends", "deps"):
            node["depends_on"] = [item.strip() for item in re.split(r"[,]", value) if item.strip()]
        elif key in ("write_scope", "writes"):
            node["write_scope"] = value
        elif key == "risk":
            node["risk"] = value.lower()
        elif key == "validator":
            node["validator"] = value
        elif key == "parallel":
            node["parallel"] = value.lower() in ("true", "yes", "1")
        elif key in ("output_paths", "outputs"):
            node["output_paths"] = [item.strip() for item in re.split(r"[,]", value) if item.strip()]
        elif key in ("model_pool", "pool"):
            node["model_pool"] = value
        elif key in ("execution_host", "workload_host"):
            node[key] = value
        elif key == "claim_effect":
            node["claim_effect"] = value
        elif key in ("input_digest", "resource_estimate"):
            node[key] = value
    node.setdefault("risk", "low")
    node.setdefault("write_scope", None)
    node.setdefault("output_paths", [])
    node.setdefault("input_digest", "unknown")
    node.setdefault("resource_estimate", "unknown")
    node.setdefault("claim_effect", "none")
    return Extracted(
        value=node,
        source=source,
        status="hard",
        confidence=0.95,
    )


def _dag_node_from_dict(item: dict[str, Any], source: SourceRef, lit: Any) -> Extracted:
    node = {
        "id": str(item.get("id")),
        "description": str(item.get("description", "")),
        "depends_on": list(item.get("depends_on") or []),
        "write_scope": item.get("write_scope"),
        "risk": str(item.get("risk", "low")),
        "parallel": bool(item.get("parallel", False)),
        "validator": item.get("validator"),
        "output_paths": list(item.get("output_paths") or []),
        "input_digest": item.get("input_digest", "unknown"),
        "resource_estimate": item.get("resource_estimate", "unknown"),
        "claim_effect": item.get("claim_effect", "none"),
    }
    return Extracted(value=node, source=source, status="hard", confidence=1.0)
