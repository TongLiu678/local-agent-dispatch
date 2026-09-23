"""Provider-free tests for latent skill search and diverse composition."""

from __future__ import annotations

import builtins
import json
import pathlib
import sys
import unittest
from dataclasses import replace
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from local_agent_dispatch.skills import (  # noqa: E402
    CompositionConstraintError,
    CompositionRequest,
    SkillDescriptor,
    SkillIndexFreshnessError,
    SkillIndexSnapshot,
    SkillValidationError,
    compose_skills,
    search_skills,
)


GENERATED = "2026-09-22T12:00:00+00:00"
NOW = "2026-09-22T12:01:00+00:00"


def skill(
    skill_id: str,
    *,
    embedding: tuple[float, ...],
    capabilities: tuple[str, ...] = ("analyze",),
    facets: tuple[str, ...] = ("analysis",),
    cost: float = 1.0,
    uncertainty: float = 0.1,
    platforms: tuple[str, ...] = ("*",),
    harnesses: tuple[str, ...] = ("*",),
    availability: str = "available",
) -> SkillDescriptor:
    return SkillDescriptor(
        skill_id=skill_id,
        version="1.0.0",
        title=skill_id.replace("-", " ").title(),
        description=f"Bounded metadata for {skill_id}.",
        capabilities=capabilities,
        facets=facets,
        platforms=platforms,
        harnesses=harnesses,
        estimated_cost=cost,
        uncertainty=uncertainty,
        embedding=embedding,
        availability=availability,  # type: ignore[arg-type]
    )


def index(
    skills: tuple[SkillDescriptor, ...],
    *,
    ttl_seconds: int | None = 300,
    evidence_state: str = "complete",
) -> SkillIndexSnapshot:
    return SkillIndexSnapshot(
        index_id="skill-index-fixture",
        generated_at=GENERATED,
        ttl_seconds=ttl_seconds,
        evidence_state=evidence_state,  # type: ignore[arg-type]
        source_digest="sha256:" + "a" * 64,
        embedding_model="fixture-v1",
        embedding_dimensions=2,
        skills=skills,
    )


def request(
    *,
    k: int = 3,
    required: tuple[str, ...] = ("analyze",),
    desired: tuple[str, ...] = ("analysis", "verification"),
    allowed: tuple[str, ...] = (),
    prohibited: tuple[str, ...] = (),
    platform: str = "linux",
    harness: str = "cursor",
    budget: float = 10.0,
) -> CompositionRequest:
    return CompositionRequest(
        request_id="request-fixture",
        k=k,
        required_capabilities=required,
        desired_facets=desired,
        platform=platform,
        harness=harness,
        allowed_skill_ids=allowed,
        prohibited_skill_ids=prohibited,
        max_total_cost=budget,
        max_skill_uncertainty=0.5,
        query_embedding=(1.0, 0.0),
    )


def diverse_skills() -> tuple[SkillDescriptor, ...]:
    return (
        skill("similar-a", embedding=(1.0, 0.0)),
        skill("similar-b", embedding=(0.999, 0.01)),
        skill("similar-c", embedding=(0.998, 0.02)),
        skill("complement", embedding=(0.0, 1.0), facets=("verification",)),
    )


class StrictSkillModelTests(unittest.TestCase):
    def test_body_and_unknown_fields_are_rejected(self) -> None:
        payload = skill("safe", embedding=(1.0, 0.0)).to_dict()
        payload["body"] = "DO NOT LEAK THIS BODY"
        with self.assertRaisesRegex(SkillValidationError, "unknown field"):
            SkillDescriptor.from_dict(payload)

    def test_only_supported_composition_sizes_are_accepted(self) -> None:
        for value in (0, 1, 2, 4, 6, 9, 11, True):
            with self.subTest(k=value), self.assertRaisesRegex(
                SkillValidationError, "3, 5, or 10"
            ):
                request(k=value)  # type: ignore[arg-type]

    def test_skill_versions_use_canonical_semver_identifiers(self) -> None:
        for version in ("1.0.0-01", "1.0.0-alpha..1", "1.0.0+build..1"):
            with self.subTest(version=version), self.assertRaisesRegex(
                SkillValidationError, "semantic version"
            ):
                replace(skill("invalid-version", embedding=(1.0, 0.0)), version=version)
        for value in (3, 5, 10):
            self.assertEqual(value, request(k=value).k)

    def test_index_requires_consistent_embedding_dimensions(self) -> None:
        with self.assertRaisesRegex(SkillValidationError, "embedding_dimensions"):
            index(
                (
                    skill("two-d", embedding=(1.0, 0.0)),
                    skill("three-d", embedding=(1.0, 0.0, 0.0)),
                )
            )

    def test_every_skill_schema_object_is_closed(self) -> None:
        schema_paths = sorted((ROOT / "schemas").glob("skill_*.schema.json"))
        self.assertTrue(schema_paths)

        def inspect(node: object) -> None:
            if isinstance(node, dict):
                if node.get("type") == "object":
                    self.assertIs(
                        False,
                        node.get("additionalProperties"),
                        msg=f"open schema object: {node}",
                    )
                for value in node.values():
                    inspect(value)
            elif isinstance(node, list):
                for value in node:
                    inspect(value)

        for path in schema_paths:
            with self.subTest(schema=path.name):
                inspect(json.loads(path.read_text(encoding="utf-8")))


class FreshnessAndHardConstraintTests(unittest.TestCase):
    def test_stale_and_unknown_indexes_fail_closed(self) -> None:
        base = index(diverse_skills())
        stale = replace(base, ttl_seconds=30)
        unknown_ttl = replace(base, ttl_seconds=None)
        unknown_evidence = replace(base, evidence_state="unknown")
        for snapshot, expected in (
            (stale, "stale"),
            (unknown_ttl, "unknown"),
            (unknown_evidence, "unknown"),
        ):
            with self.subTest(state=expected), self.assertRaises(
                SkillIndexFreshnessError
            ) as caught:
                compose_skills(snapshot, request(), now=NOW)
            self.assertEqual(expected, caught.exception.state)

    def test_hard_constraints_filter_before_similarity_scoring(self) -> None:
        candidates = (
            skill(
                "unavailable-perfect",
                embedding=(1.0, 0.0),
                availability="unknown",
            ),
            skill(
                "wrong-platform",
                embedding=(1.0, 0.0),
                platforms=("windows",),
            ),
            skill("prohibited", embedding=(1.0, 0.0)),
            skill("eligible-a", embedding=(0.8, 0.2)),
            skill("eligible-b", embedding=(0.7, 0.3), facets=("verification",)),
            skill("eligible-c", embedding=(0.6, 0.4), facets=("planning",)),
        )
        plan = compose_skills(
            index(candidates), request(prohibited=("prohibited",)), now=NOW
        )
        selected = {item.skill_id for item in plan.selected}
        self.assertEqual({"eligible-a", "eligible-b", "eligible-c"}, selected)
        counts = dict(plan.hard_filter_counts)
        self.assertEqual(1, counts["availability_not_verified"])
        self.assertEqual(1, counts["platform_mismatch"])
        self.assertEqual(1, counts["prohibited"])

    def test_missing_required_capability_fails_closed(self) -> None:
        with self.assertRaisesRegex(
            CompositionConstraintError, "required capabilities"
        ):
            compose_skills(
                index(diverse_skills()),
                request(required=("analyze", "deploy")),
                now=NOW,
            )

    def test_exact_decimal_budget_accepts_three_tenths(self) -> None:
        snapshot = index(
            tuple(
                skill(f"decimal-{number}", embedding=(1.0, number / 10.0), cost=0.1)
                for number in range(3)
            )
        )
        plan = compose_skills(snapshot, request(budget=0.3), now=NOW)
        self.assertEqual(3, len(plan.selected))
        self.assertEqual(0.3, plan.total_estimated_cost)

    def test_composition_work_is_bounded_before_exact_dp(self) -> None:
        many = tuple(
            skill(f"candidate-{number:03d}", embedding=(1.0, number / 1000.0))
            for number in range(129)
        )
        with self.assertRaisesRegex(
            CompositionConstraintError, "candidate limit.*prefilter"
        ):
            compose_skills(index(many), request(), now=NOW)

        capabilities = tuple(f"cap-{number}" for number in range(17))
        with self.assertRaisesRegex(
            CompositionConstraintError, "at most 16 required capabilities"
        ):
            compose_skills(
                index(diverse_skills()),
                request(required=capabilities),
                now=NOW,
            )


class DiversitySelectionTests(unittest.TestCase):
    def test_composer_materializes_each_supported_portfolio_size(self) -> None:
        candidates = tuple(
            skill(
                f"skill-{number}",
                embedding=(1.0, number / 20.0),
                facets=(("analysis", "verification", "planning")[number % 3],),
            )
            for number in range(10)
        )
        snapshot = index(candidates)
        for size in (3, 5, 10):
            with self.subTest(k=size):
                plan = compose_skills(
                    snapshot, request(k=size, budget=20.0), now=NOW
                )
                self.assertEqual(size, plan.k)
                self.assertEqual(size, len(plan.selected))

    def test_similarity_top_k_does_not_crowd_out_complementary_skill(self) -> None:
        snapshot = index(diverse_skills())
        task = request()
        hits = search_skills(snapshot, task, now=NOW)
        self.assertEqual(
            ("similar-a", "similar-b", "similar-c"),
            tuple(item.skill_id for item in hits),
        )

        plan = compose_skills(snapshot, task, now=NOW)
        selected = {item.skill_id for item in plan.selected}
        self.assertIn("complement", selected)
        self.assertIn("verification", plan.covered_facets)
        self.assertGreater(plan.objective.complementarity, 0)

    def test_composition_is_deterministic_across_input_order(self) -> None:
        skills = diverse_skills()
        forward = compose_skills(index(skills), request(), now=NOW)
        reverse = compose_skills(index(tuple(reversed(skills))), request(), now=NOW)
        self.assertEqual(forward.to_dict(), reverse.to_dict())

    def test_large_finite_embeddings_have_stable_cosine_values(self) -> None:
        huge = 1e308
        snapshot = index(
            (
                skill("same", embedding=(huge, huge)),
                skill("orthogonal", embedding=(huge, -huge)),
                skill("opposite", embedding=(-huge, -huge)),
            )
        )
        task = replace(request(), query_embedding=(huge, huge))
        similarities = {
            item.skill_id: item.similarity
            for item in search_skills(snapshot, task, now=NOW)
        }
        self.assertEqual(1.0, similarities["same"])
        self.assertEqual(0.0, similarities["orthogonal"])
        self.assertEqual(-1.0, similarities["opposite"])

    def test_search_and_plan_never_return_body_or_embedding(self) -> None:
        snapshot = index(diverse_skills())
        hits = search_skills(snapshot, request(), now=NOW)
        plan = compose_skills(snapshot, request(), now=NOW)
        self.assertNotIn('"body"', json.dumps(snapshot.to_dict(), sort_keys=True))
        rendered = json.dumps(
            {
                "search": [item.to_dict() for item in hits],
                "plan": plan.to_dict(),
            },
            sort_keys=True,
        )
        self.assertNotIn('"body"', rendered)
        self.assertNotIn('"embedding"', rendered)

    def test_search_and_composition_do_not_import_or_execute_skills(self) -> None:
        snapshot = index(diverse_skills())
        task = request()
        with mock.patch.object(
            builtins, "__import__", side_effect=AssertionError("unexpected import")
        ), mock.patch.object(
            builtins, "exec", side_effect=AssertionError("unexpected exec")
        ):
            self.assertEqual(3, len(search_skills(snapshot, task, now=NOW)))
            self.assertEqual(3, len(compose_skills(snapshot, task, now=NOW).selected))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
