"""ClaimContract: the evidence and claim boundary of a compiled mission.

The contract preserves the boundary the user stated in the mission: allowed
claims stay allowed, forbidden claims are never promoted, and deferred claims
require an explicit promotion gate with an independent validation program.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

from ..domain.mission import (
    ClaimEnvelope,
    MissionSpec,
    Rejection,
    VALID_EVIDENCE_LEVELS,
)

NON_CLAIM_MARKERS = ("none", "n/a", "not applicable", "no claims")


@dataclass(frozen=True)
class ClaimContract:
    """A frozen, non-negotiable claim boundary."""

    schema_version: int = 1
    claimable: tuple[str, ...] = ()
    deferred: tuple[str, ...] = ()
    forbidden: tuple[str, ...] = ()
    promotion_gates: tuple[tuple[str, str], ...] = ()
    evidence_level: str = "E0"
    non_goals_preserved: tuple[str, ...] = ()
    immutable: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "claimable": list(self.claimable),
            "deferred": list(self.deferred),
            "forbidden": list(self.forbidden),
            "promotion_gates": [
                {"claim": claim, "gate": gate} for claim, gate in self.promotion_gates
            ],
            "evidence_level": self.evidence_level,
            "non_goals_preserved": list(self.non_goals_preserved),
            "immutable": self.immutable,
        }


def _clean(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(text).lower()).strip()


def claim_status(contract: ClaimContract, claim: str) -> str:
    """Return ``allowed``, ``deferred``, ``forbidden``, or ``unknown``."""
    needle = _clean(claim)
    if not needle:
        return "unknown"
    for forbidden in contract.forbidden:
        if needle in _clean(forbidden) or _clean(forbidden) in needle:
            return "forbidden"
    for deferred in contract.deferred:
        if needle in _clean(deferred) or _clean(deferred) in needle:
            return "deferred"
    for allowed in contract.claimable:
        if needle in _clean(allowed) or _clean(allowed) in needle:
            return "allowed"
    return "unknown"


def claim_is_allowed(contract: ClaimContract, claim: str) -> bool:
    """Only explicit claimable entries are allowed; nothing is guessed."""
    return claim_status(contract, claim) == "allowed"


def promotion_gate_for(contract: ClaimContract, claim: str) -> Optional[str]:
    for deferred_claim, gate in contract.promotion_gates:
        if claim_status(contract, deferred_claim) == "deferred" and (
            _clean(claim) in _clean(deferred_claim)
            or _clean(deferred_claim) in _clean(claim)
        ):
            return gate
    return None


def build_claim_contract(spec: MissionSpec) -> ClaimContract:
    """Derive the immutable claim boundary from a compiled MissionSpec.

    Non-goals phrased as ``do not claim ...`` are preserved and folded into
    the forbidden set (deduplicated against the envelope's own forbidden
    entries) so the boundary survives downstream summaries.
    """

    envelope = spec.claim_envelope or ClaimEnvelope()
    forbidden = [str(item) for item in envelope.forbidden]
    preserved: list[str] = []
    for non_goal in spec.non_goals:
        text = str(non_goal.value)
        if "claim" in _clean(text):
            cleaned = _clean(text)
            if not any(
                cleaned in _clean(entry) or _clean(entry) in cleaned for entry in forbidden
            ):
                forbidden.append(text)
            preserved.append(text)

    gates: list[tuple[str, str]] = []
    if envelope.promotion_gate is not None:
        for claim in envelope.deferred:
            gates.append((str(claim), str(envelope.promotion_gate.value)))

    evidence_level = "E0"
    if envelope.evidence_level is not None and envelope.evidence_level.value in VALID_EVIDENCE_LEVELS:
        evidence_level = str(envelope.evidence_level.value)

    return ClaimContract(
        claimable=tuple(str(item) for item in envelope.allowed),
        deferred=tuple(str(item) for item in envelope.deferred),
        forbidden=tuple(forbidden),
        promotion_gates=tuple(gates),
        evidence_level=evidence_level,
        non_goals_preserved=tuple(preserved),
    )


def validate_claim_contract(contract: ClaimContract, spec: MissionSpec) -> list[Rejection]:
    """Verify the boundary is internally consistent and matches the mission."""

    rejections: list[Rejection] = []
    envelope = spec.claim_envelope or ClaimEnvelope()

    def overlaps(left: tuple[str, ...], right: tuple[str, ...]) -> list[str]:
        overlaps_found: list[str] = []
        for item in left:
            if any(
                _clean(item) == _clean(other) or _clean(other) == _clean(item)
                for other in right
            ):
                overlaps_found.append(item)
        return overlaps_found

    for claim in overlaps(contract.forbidden, contract.claimable):
        rejections.append(
            Rejection(
                "claim_boundary_overlap",
                "claim_envelope",
                f"claim {claim!r} appears in both forbidden and allowed sets",
            )
        )
    for claim in overlaps(contract.deferred, contract.claimable):
        rejections.append(
            Rejection(
                "claim_boundary_overlap",
                "claim_envelope",
                f"claim {claim!r} appears in both deferred and allowed sets",
            )
        )
    for claim in overlaps(contract.deferred, contract.forbidden):
        rejections.append(
            Rejection(
                "claim_boundary_overlap",
                "claim_envelope",
                f"claim {claim!r} appears in both forbidden and deferred sets",
            )
        )

    for claim in contract.deferred:
        if promotion_gate_for(contract, claim) is None:
            rejections.append(
                Rejection(
                    "missing_promotion_gate",
                    "claim_envelope.promotion_gate",
                    f"deferred claim {claim!r} has no promotion gate",
                )
            )

    if contract.evidence_level not in VALID_EVIDENCE_LEVELS:
        rejections.append(
            Rejection(
                "invalid_evidence_level",
                "claim_envelope.evidence_level",
                f"evidence level {contract.evidence_level!r} is not in "
                f"{VALID_EVIDENCE_LEVELS}",
            )
        )

    if envelope.forbidden and not any(
        _clean(item) in _clean(entry) or _clean(entry) in _clean(item)
        for item in contract.forbidden
        for entry in envelope.forbidden
    ):
        rejections.append(
            Rejection(
                "claim_boundary_dropped",
                "claim_envelope.forbidden",
                "mission-level forbidden claims were dropped from the contract",
            )
        )

    return rejections
