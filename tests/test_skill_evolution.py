"""Provider-free tests for outcome-driven skill evolution proposals."""

from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest
from dataclasses import replace
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from local_agent_dispatch.skills import (  # noqa: E402
    CompositionRequest,
    EvolutionError,
    EvolutionPolicy,
    SkillDescriptor,
    SkillEvolutionProposal,
    SkillIndexFreshnessError,
    SkillIndexSnapshot,
    SkillLineage,
    SkillOutcome,
    SkillRef,
    SkillValidationError,
    compose_skills,
    lineage_from_proposal,
    propose_evolution,
)


GENERATED = "2026-09-22T12:00:00+00:00"
NOW = "2026-09-22T12:05:00+00:00"


def descriptor(skill_id: str = "analysis-skill") -> SkillDescriptor:
    return SkillDescriptor(
        skill_id=skill_id,
        version="1.0.0",
        title="Analysis Skill",
        description="Bounded searchable metadata only.",
        capabilities=("analyze",),
        facets=("analysis",),
        platforms=("*",),
        harnesses=("*",),
        estimated_cost=1.0,
        uncertainty=0.2,
        embedding=(1.0, 0.0),
    )


def index(*, ttl_seconds: int | None = 600) -> SkillIndexSnapshot:
    return SkillIndexSnapshot(
        index_id="evolution-index",
        generated_at=GENERATED,
        ttl_seconds=ttl_seconds,
        evidence_state="complete",
        source_digest="sha256:" + "b" * 64,
        embedding_model="fixture-v1",
        embedding_dimensions=2,
        skills=(descriptor(), descriptor("support-a"), descriptor("support-b")),
    )


def plan(snapshot: SkillIndexSnapshot | None = None):
    source = snapshot or index()
    return compose_skills(
        source,
        CompositionRequest(
            request_id="evolution-request",
            k=3,
            required_capabilities=("analyze",),
            desired_facets=("analysis",),
            platform="linux",
            harness="cursor",
            allowed_skill_ids=(),
            prohibited_skill_ids=(),
            max_total_cost=3.0,
            max_skill_uncertainty=0.5,
            query_embedding=(1.0, 0.0),
        ),
        now=GENERATED,
    )


def outcome(
    number: int,
    *,
    status: str = "failure",
    quality: float | None = 0.3,
    skill_id: str = "analysis-skill",
    observed_at: str = "2026-09-22T12:04:00+00:00",
    plan_id: str | None = None,
    evidence_refs: tuple[str, ...] | None = None,
) -> SkillOutcome:
    return SkillOutcome(
        outcome_id=f"outcome-{number}",
        plan_id=plan_id or plan().plan_id,
        skills=(SkillRef(skill_id=skill_id, version="1.0.0"),),
        observed_at=observed_at,
        status=status,  # type: ignore[arg-type]
        quality_score=quality,
        latency_ms=100.0,
        actual_cost=1.0,
        failure_codes=("validator_failed",) if status == "failure" else (),
        evidence_refs=evidence_refs or (f"receipt-{number}",),
    )


class OutcomeContractTests(unittest.TestCase):
    def test_outcome_rejects_unknown_body_or_notes_fields(self) -> None:
        payload = outcome(1).to_dict()
        payload["body"] = "secret instructions"
        with self.assertRaisesRegex(SkillValidationError, "unknown field"):
            SkillOutcome.from_dict(payload)

        payload = outcome(1).to_dict()
        payload["notes"] = "unbounded prose"
        with self.assertRaisesRegex(SkillValidationError, "unknown field"):
            SkillOutcome.from_dict(payload)

    def test_failure_requires_a_machine_readable_failure_code(self) -> None:
        with self.assertRaisesRegex(SkillValidationError, "failure code"):
            SkillOutcome(
                outcome_id="invalid-outcome",
                plan_id="invalid-plan",
                skills=(SkillRef(skill_id="analysis-skill", version="1.0.0"),),
                observed_at=NOW,
                status="failure",
                quality_score=None,
                latency_ms=None,
                actual_cost=None,
                failure_codes=(),
                evidence_refs=(),
            )

    def test_every_outcome_requires_evidence(self) -> None:
        with self.assertRaisesRegex(SkillValidationError, "evidence reference"):
            SkillOutcome(
                outcome_id="invalid-evidence",
                plan_id=plan().plan_id,
                skills=(SkillRef(skill_id="analysis-skill", version="1.0.0"),),
                observed_at=NOW,
                status="success",
                quality_score=1.0,
                latency_ms=1.0,
                actual_cost=0.0,
                failure_codes=(),
                evidence_refs=(),
            )


class ProposalTests(unittest.TestCase):
    def test_proposal_is_deterministic_data_and_does_not_write(self) -> None:
        outcomes = (outcome(1), outcome(2), outcome(3, status="partial", quality=0.4))
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            before = tuple(root.iterdir())
            with mock.patch.object(
                pathlib.Path,
                "write_text",
                side_effect=AssertionError("proposal attempted a repository write"),
            ), mock.patch.object(
                pathlib.Path,
                "write_bytes",
                side_effect=AssertionError("proposal attempted a repository write"),
            ):
                first = propose_evolution(index(), outcomes, plans=(plan(),), now=NOW)
                second = propose_evolution(
                    index(), tuple(reversed(outcomes)), plans=(plan(),), now=NOW
                )
            after = tuple(root.iterdir())

        self.assertEqual(before, after)
        self.assertEqual(first, second)
        self.assertEqual(1, len(first))
        proposal = first[0]
        self.assertEqual("proposed", proposal.status)
        self.assertEqual("revise_metadata", proposal.operation)
        self.assertIn("high_failure_rate", proposal.rationale_codes)
        self.assertIn("quality_below_floor", proposal.rationale_codes)
        rendered = json.dumps(proposal.to_dict(), sort_keys=True)
        self.assertNotIn('"body"', rendered)
        self.assertNotIn("instructions", rendered)
        self.assertEqual(proposal, SkillEvolutionProposal.from_dict(proposal.to_dict()))

    def test_lineage_is_data_derived_from_reviewed_proposal(self) -> None:
        proposal = propose_evolution(
            index(),
            (outcome(1), outcome(2), outcome(3)),
            plans=(plan(),),
            now=NOW,
        )[0]
        lineage = lineage_from_proposal(
            proposal, child_version="1.1.0", now=NOW
        )
        self.assertEqual("revise", lineage.operation)
        self.assertEqual("1.1.0", lineage.child.version)
        self.assertEqual((proposal.target,), lineage.parents)
        self.assertEqual(proposal.proposal_id, lineage.proposal_id)
        self.assertEqual(lineage, SkillLineage.from_dict(lineage.to_dict()))
        with self.assertRaisesRegex(EvolutionError, "greater than"):
            lineage_from_proposal(proposal, child_version="1.0.0", now=NOW)
        with self.assertRaisesRegex(EvolutionError, "revise_metadata only"):
            lineage_from_proposal(
                replace(proposal, operation="merge_metadata"),
                child_version="2.0.0",
                now=NOW,
            )

    def test_insufficient_evidence_produces_no_proposal(self) -> None:
        proposals = propose_evolution(
            index(),
            (outcome(1, status="success", quality=0.9),),
            plans=(plan(),),
            now=NOW,
        )
        self.assertEqual((), proposals)

    def test_stale_or_unknown_index_fails_closed(self) -> None:
        stale = replace(index(), ttl_seconds=60)
        unknown = replace(index(), ttl_seconds=None)
        for snapshot, state in ((stale, "stale"), (unknown, "unknown")):
            with self.subTest(state=state), self.assertRaises(
                SkillIndexFreshnessError
            ) as caught:
                propose_evolution(
                    snapshot,
                    (outcome(1), outcome(2), outcome(3)),
                    plans=(plan(),),
                    now=NOW,
                )
            self.assertEqual(state, caught.exception.state)

    def test_unknown_skill_and_future_outcome_fail_closed(self) -> None:
        with self.assertRaisesRegex(EvolutionError, "unknown skill"):
            propose_evolution(
                index(),
                (
                    outcome(1, skill_id="missing-skill"),
                    outcome(2, skill_id="missing-skill"),
                    outcome(3, skill_id="missing-skill"),
                ),
                plans=(plan(),),
                now=NOW,
            )
        future = outcome(4, observed_at="2026-09-22T13:00:00+00:00")
        with self.assertRaisesRegex(EvolutionError, "future-dated"):
            propose_evolution(index(), (future,), plans=(plan(),), now=NOW)

    def test_old_outcomes_are_not_silently_treated_as_current(self) -> None:
        old = tuple(
            outcome(
                number,
                observed_at="2026-08-01T12:00:00+00:00",
            )
            for number in (1, 2, 3)
        )
        proposals = propose_evolution(
            index(),
            old,
            plans=(plan(),),
            now=NOW,
            policy=EvolutionPolicy(outcome_ttl_seconds=3600),
        )
        self.assertEqual((), proposals)

    def test_outcomes_are_bound_to_real_plan_and_independent_receipts(self) -> None:
        with self.assertRaisesRegex(EvolutionError, "unknown composition plan"):
            propose_evolution(
                index(),
                (outcome(1, plan_id="missing-plan"),),
                plans=(plan(),),
                now=NOW,
            )

        mismatched = replace(plan(), index_source_digest="sha256:" + "f" * 64)
        with self.assertRaisesRegex(EvolutionError, "not bound to the supplied index"):
            propose_evolution(
                index(),
                (outcome(1),),
                plans=(mismatched,),
                now=NOW,
            )

        duplicated_receipt = (
            outcome(1, evidence_refs=("shared-receipt",)),
            outcome(2, evidence_refs=("shared-receipt",)),
            outcome(3),
        )
        with self.assertRaisesRegex(EvolutionError, "independent evidence"):
            propose_evolution(
                index(), duplicated_receipt, plans=(plan(),), now=NOW
            )

    def test_lineage_parent_cardinality_and_identity_are_closed(self) -> None:
        parent = SkillRef(skill_id="analysis-skill", version="1.0.0")
        common = {
            "lineage_id": "lineage-fixture",
            "child": SkillRef(skill_id="analysis-skill", version="1.1.0"),
            "created_at": NOW,
            "proposal_id": "proposal-fixture",
            "evidence_refs": ("receipt-fixture",),
        }
        with self.assertRaisesRegex(SkillValidationError, "requires at least 2"):
            SkillLineage(parents=(parent,), operation="merge", **common)
        with self.assertRaisesRegex(SkillValidationError, "duplicates"):
            SkillLineage(parents=(parent, parent), operation="merge", **common)
        with self.assertRaisesRegex(SkillValidationError, "also be a parent"):
            SkillLineage(
                parents=(common["child"],),  # type: ignore[arg-type]
                operation="revise",
                **common,
            )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
