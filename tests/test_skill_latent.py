"""Provider-free latent analysis API and CLI tests."""

from __future__ import annotations

import contextlib
import io
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

from local_agent_dispatch import cli  # noqa: E402
from local_agent_dispatch.skills import (  # noqa: E402
    LatentAnalysisError,
    SkillDescriptor,
    SkillIndexFreshnessError,
    SkillIndexSnapshot,
    SkillValidationError,
    analyze_latent_space,
)


GENERATED = "2026-09-22T12:00:00+00:00"
NOW = "2026-09-22T12:01:00+00:00"


def skill(
    skill_id: str,
    *,
    vector: tuple[float, float],
    capability: str = "analyze",
    facet: str = "analysis",
    availability: str = "available",
) -> SkillDescriptor:
    return SkillDescriptor(
        skill_id=skill_id,
        version="1.0.0",
        title=skill_id.upper(),
        description=f"Bounded metadata for {skill_id}.",
        capabilities=(capability,),
        facets=(facet,),
        platforms=("*",),
        harnesses=("*",),
        estimated_cost=1.0,
        uncertainty=0.1,
        embedding=vector,
        availability=availability,  # type: ignore[arg-type]
    )


def snapshot(
    *,
    skills: tuple[SkillDescriptor, ...] | None = None,
    ttl_seconds: int | None = 300,
) -> SkillIndexSnapshot:
    candidates = skills or (
        skill("angle-0", vector=(1.0, 0.0), facet="analysis"),
        skill(
            "angle-20",
            vector=(0.9396926208, 0.3420201433),
            facet="planning",
        ),
        skill(
            "angle-40",
            vector=(0.7660444431, 0.6427876097),
            capability="verify",
            facet="verification",
        ),
        skill(
            "unknown-skill",
            vector=(0.0, 1.0),
            availability="unknown",
        ),
    )
    return SkillIndexSnapshot(
        index_id="latent-index",
        generated_at=GENERATED,
        ttl_seconds=ttl_seconds,
        evidence_state="complete",
        source_digest="sha256:" + "d" * 64,
        embedding_model="fixture-v1",
        embedding_dimensions=2,
        skills=candidates,
    )


class LatentAnalysisApiTests(unittest.TestCase):
    def test_pairwise_redundancy_groups_and_coverage(self) -> None:
        analysis = analyze_latent_space(
            snapshot(), now=NOW, threshold=0.9, limit=2
        )
        payload = analysis.to_dict()

        self.assertEqual(3, payload["analyzed_skill_count"])
        self.assertEqual(
            [{"reason": "availability_unknown", "count": 1}],
            payload["excluded_skill_counts"],
        )
        self.assertEqual(3, payload["pairwise"]["total_count"])
        self.assertEqual(2, payload["pairwise"]["returned_count"])
        self.assertTrue(payload["pairwise"]["truncated"])
        self.assertAlmostEqual(
            0.9396926208, payload["pairwise"]["cosine"]["maximum"], places=9
        )
        self.assertAlmostEqual(
            0.7660444431, payload["pairwise"]["cosine"]["minimum"], places=9
        )
        self.assertEqual(2, payload["redundancy"]["pair_count"])
        self.assertEqual(1, payload["redundancy"]["group_count"])
        group = payload["redundancy"]["groups"][0]
        self.assertEqual(3, len(group["members"]))
        self.assertEqual(2, group["qualifying_pair_count"])

        capabilities = {
            item["name"]: (item["skill_count"], item["fraction"])
            for item in payload["coverage"]["capabilities"]
        }
        self.assertEqual((2, round(2 / 3, 12)), capabilities["analyze"])
        self.assertEqual((1, round(1 / 3, 12)), capabilities["verify"])
        rendered = json.dumps(payload, sort_keys=True)
        self.assertNotIn('"body"', rendered)
        self.assertNotIn('"instruction"', rendered)
        self.assertNotIn('"embedding"', rendered)

    def test_analysis_is_deterministic_across_index_order(self) -> None:
        base = snapshot()
        reversed_index = replace(base, skills=tuple(reversed(base.skills)))
        forward = analyze_latent_space(base, now=NOW, threshold=0.9, limit=10)
        reverse = analyze_latent_space(
            reversed_index, now=NOW, threshold=0.9, limit=10
        )
        self.assertEqual(forward.to_dict(), reverse.to_dict())

    def test_single_available_skill_has_null_pair_summary(self) -> None:
        analysis = analyze_latent_space(
            snapshot(skills=(skill("solo", vector=(1.0, 0.0)),)),
            now=NOW,
            threshold=0.9,
            limit=5,
        ).to_dict()
        self.assertEqual(0, analysis["pairwise"]["total_count"])
        self.assertEqual(
            {"mean": None, "minimum": None, "maximum": None},
            analysis["pairwise"]["cosine"],
        )
        self.assertEqual([], analysis["redundancy"]["groups"])

    def test_stale_unknown_and_unavailable_indexes_fail_closed(self) -> None:
        for candidate, state in (
            (replace(snapshot(), ttl_seconds=30), "stale"),
            (replace(snapshot(), ttl_seconds=None), "unknown"),
        ):
            with self.subTest(state=state), self.assertRaises(
                SkillIndexFreshnessError
            ) as caught:
                analyze_latent_space(candidate, now=NOW)
            self.assertEqual(state, caught.exception.state)

        unavailable = snapshot(
            skills=(
                skill(
                    "unknown-only",
                    vector=(1.0, 0.0),
                    availability="unknown",
                ),
            )
        )
        with self.assertRaisesRegex(LatentAnalysisError, "no available skills"):
            analyze_latent_space(unavailable, now=NOW)

    def test_threshold_limit_and_schema_are_closed(self) -> None:
        for threshold in (-0.1, 1.1, float("nan"), True):
            with self.subTest(threshold=threshold), self.assertRaises(
                SkillValidationError
            ):
                analyze_latent_space(snapshot(), now=NOW, threshold=threshold)  # type: ignore[arg-type]
        for limit in (0, 1001, True):
            with self.subTest(limit=limit), self.assertRaises(
                SkillValidationError
            ):
                analyze_latent_space(snapshot(), now=NOW, limit=limit)  # type: ignore[arg-type]

        schema = json.loads(
            (ROOT / "schemas" / "skill_latent_analysis.schema.json").read_text(
                encoding="utf-8"
            )
        )

        def inspect(node: object) -> None:
            if isinstance(node, dict):
                if node.get("type") == "object":
                    self.assertIs(False, node.get("additionalProperties"))
                for value in node.values():
                    inspect(value)
            elif isinstance(node, list):
                for value in node:
                    inspect(value)

        inspect(schema)


class LatentAnalysisCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        self.index_path = self.root / "index.json"
        self.index_path.write_text(
            json.dumps(snapshot().to_dict(), sort_keys=True), encoding="utf-8"
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_cli(
        self, *args: str, stdin: str = ""
    ) -> tuple[int, dict[str, object], str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
            mock.patch.object(sys, "stdin", io.StringIO(stdin)),
            mock.patch.object(
                cli.subprocess,
                "run",
                side_effect=AssertionError("skill analyze must not run subprocesses"),
            ),
        ):
            code = cli.main(list(args))
        rendered = stdout.getvalue()
        return code, json.loads(rendered), rendered, stderr.getvalue()

    def assert_canonical(self, rendered: str, payload: dict[str, object]) -> None:
        self.assertEqual(
            json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            + "\n",
            rendered,
        )
        self.assertEqual(1, len(rendered.splitlines()))

    def test_analyze_file_is_canonical_and_body_free(self) -> None:
        before = tuple(sorted(path.name for path in self.root.iterdir()))
        code, payload, rendered, stderr = self.run_cli(
            "skill",
            "analyze",
            "--index",
            str(self.index_path),
            "--now",
            NOW,
            "--threshold",
            "0.9",
            "--limit",
            "2",
        )
        after = tuple(sorted(path.name for path in self.root.iterdir()))

        self.assertEqual(0, code)
        self.assertTrue(payload["ok"])
        self.assertEqual("skill.analyze", payload["command"])
        self.assertTrue(payload["read_only"])
        self.assertFalse(payload["network_accessed"])
        self.assertFalse(payload["provider_contacted"])
        self.assertFalse(payload["skill_body_read"])
        self.assertFalse(payload["skill_imported"])
        self.assertFalse(payload["entrypoint_executed"])
        self.assertEqual(3, payload["analysis"]["pairwise"]["total_count"])
        self.assertEqual(before, after)
        self.assertNotIn('"body"', rendered)
        self.assertNotIn('"instruction"', rendered)
        self.assertNotIn('"embedding"', rendered)
        self.assert_canonical(rendered, payload)
        self.assertEqual("", stderr)

    def test_analyze_accepts_stdin(self) -> None:
        code, payload, rendered, stderr = self.run_cli(
            "skill",
            "analyze",
            "--index",
            "-",
            "--now",
            NOW,
            stdin=json.dumps(snapshot().to_dict()),
        )
        self.assertEqual(0, code)
        self.assertEqual(
            {"index": "stdin"}, payload["evidence_boundary"]["input_sources"]
        )
        self.assert_canonical(rendered, payload)
        self.assertEqual("", stderr)

    def test_invalid_input_threshold_and_freshness_return_json_exit_two(self) -> None:
        duplicate = self.root / "duplicate.json"
        duplicate.write_text(
            json.dumps(snapshot().to_dict(), sort_keys=True)[:-1]
            + ', "index_id": "shadowed"}',
            encoding="utf-8",
        )
        cases = (
            (
                ["--index", str(duplicate), "--now", NOW],
                "duplicate JSON key",
            ),
            (
                [
                    "--index",
                    str(self.index_path),
                    "--now",
                    NOW,
                    "--threshold",
                    "NaN",
                ],
                "threshold",
            ),
            (
                [
                    "--index",
                    str(self.index_path),
                    "--now",
                    NOW,
                    "--limit",
                    "0",
                ],
                "limit",
            ),
        )
        for arguments, expected in cases:
            with self.subTest(expected=expected):
                code, payload, rendered, stderr = self.run_cli(
                    "skill", "analyze", *arguments
                )
                self.assertEqual(2, code)
                self.assertFalse(payload["ok"])
                self.assertIn(expected, payload["error"]["message"])
                self.assert_canonical(rendered, payload)
                self.assertEqual("", stderr)

        stale = self.root / "stale.json"
        stale.write_text(
            json.dumps(replace(snapshot(), ttl_seconds=30).to_dict()),
            encoding="utf-8",
        )
        code, payload, rendered, _ = self.run_cli(
            "skill", "analyze", "--index", str(stale), "--now", NOW
        )
        self.assertEqual(2, code)
        self.assertIn("stale", payload["error"]["message"])
        self.assert_canonical(rendered, payload)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
