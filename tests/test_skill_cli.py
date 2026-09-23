"""Provider-free CLI coverage for body-free skill search and composition."""

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
    CompositionRequest,
    SkillDescriptor,
    SkillIndexSnapshot,
)


GENERATED = "2026-09-22T12:00:00+00:00"
NOW = "2026-09-22T12:01:00+00:00"


def descriptor(
    skill_id: str,
    *,
    vector: tuple[float, float],
    facet: str,
) -> SkillDescriptor:
    return SkillDescriptor(
        skill_id=skill_id,
        version="1.0.0",
        title=skill_id.replace("-", " ").title(),
        description=f"Bounded metadata for {skill_id}.",
        capabilities=("analyze",),
        facets=(facet,),
        platforms=("*",),
        harnesses=("*",),
        estimated_cost=1.0,
        uncertainty=0.1,
        embedding=vector,
    )


def index() -> SkillIndexSnapshot:
    return SkillIndexSnapshot(
        index_id="skill-cli-index",
        generated_at=GENERATED,
        ttl_seconds=300,
        evidence_state="complete",
        source_digest="sha256:" + "c" * 64,
        embedding_model="fixture-v1",
        embedding_dimensions=2,
        skills=(
            descriptor("similar-a", vector=(1.0, 0.0), facet="analysis"),
            descriptor("similar-b", vector=(0.99, 0.01), facet="analysis"),
            descriptor("similar-c", vector=(0.98, 0.02), facet="planning"),
            descriptor("complement", vector=(0.0, 1.0), facet="verification"),
        ),
    )


def request() -> CompositionRequest:
    return CompositionRequest(
        request_id="skill-cli-request",
        k=3,
        required_capabilities=("analyze",),
        desired_facets=("analysis", "verification"),
        platform="linux",
        harness="cursor",
        allowed_skill_ids=(),
        prohibited_skill_ids=(),
        max_total_cost=4.0,
        max_skill_uncertainty=0.5,
        query_embedding=(1.0, 0.0),
    )


class SkillCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        self.index_path = self.write_json("index.json", index().to_dict())
        self.request_path = self.write_json("request.json", request().to_dict())

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_json(self, name: str, payload: object) -> pathlib.Path:
        path = self.root / name
        path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
        return path

    def run_cli(
        self,
        *args: str,
        stdin: str = "",
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
                side_effect=AssertionError("skill CLI must not run subprocesses"),
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

    def assert_safe_boundary(self, payload: dict[str, object]) -> None:
        self.assertTrue(payload["read_only"])
        self.assertTrue(payload["offline"])
        self.assertFalse(payload["network_accessed"])
        self.assertFalse(payload["provider_contacted"])
        self.assertFalse(payload["provider_prompt_sent"])
        self.assertFalse(payload["skill_body_read"])
        self.assertFalse(payload["skill_imported"])
        self.assertFalse(payload["entrypoint_executed"])
        self.assertFalse(payload["filesystem_written"])

    def test_search_returns_canonical_body_free_hits(self) -> None:
        before = sorted(path.name for path in self.root.iterdir())
        code, payload, rendered, stderr = self.run_cli(
            "skill",
            "search",
            "--index",
            str(self.index_path),
            "--request",
            str(self.request_path),
            "--now",
            NOW,
        )
        after = sorted(path.name for path in self.root.iterdir())

        self.assertEqual(0, code)
        self.assertTrue(payload["ok"])
        self.assertEqual("skill.search", payload["command"])
        self.assertEqual(3, payload["limit"])
        self.assertEqual(3, len(payload["hits"]))
        self.assertEqual(before, after)
        self.assertNotIn('"body"', rendered)
        self.assertNotIn('"instruction"', rendered)
        self.assertNotIn('"embedding"', rendered)
        self.assert_safe_boundary(payload)
        self.assert_canonical(rendered, payload)
        self.assertEqual("", stderr)

    def test_compose_accepts_request_from_stdin_and_selects_complement(self) -> None:
        code, payload, rendered, stderr = self.run_cli(
            "skill",
            "compose",
            "--index",
            str(self.index_path),
            "--request",
            "-",
            "--now",
            NOW,
            stdin=json.dumps(request().to_dict()),
        )

        self.assertEqual(0, code)
        self.assertEqual("skill.compose", payload["command"])
        self.assertEqual(
            {"index": "local-file", "request": "stdin"},
            payload["evidence_boundary"]["input_sources"],
        )
        selected = {item["skill_id"] for item in payload["plan"]["selected"]}
        self.assertEqual(3, len(selected))
        self.assertIn("complement", selected)
        self.assertIn("verification", payload["plan"]["covered_facets"])
        self.assertNotIn('"body"', rendered)
        self.assertNotIn('"instruction"', rendered)
        self.assertNotIn('"embedding"', rendered)
        self.assert_safe_boundary(payload)
        self.assert_canonical(rendered, payload)
        self.assertEqual("", stderr)

    def test_index_can_be_read_from_stdin(self) -> None:
        code, payload, rendered, _ = self.run_cli(
            "skill",
            "search",
            "--index",
            "-",
            "--request",
            str(self.request_path),
            "--now",
            NOW,
            stdin=json.dumps(index().to_dict()),
        )

        self.assertEqual(0, code)
        self.assertEqual(
            {"index": "stdin", "request": "local-file"},
            payload["evidence_boundary"]["input_sources"],
        )
        self.assert_canonical(rendered, payload)

    def test_duplicate_and_unknown_fields_fail_closed_as_json(self) -> None:
        duplicate = self.root / "duplicate.json"
        duplicate.write_text(
            json.dumps(request().to_dict(), sort_keys=True)[:-1]
            + ', "request_id": "shadowed"}',
            encoding="utf-8",
        )
        duplicate_code, duplicate_payload, duplicate_rendered, duplicate_stderr = (
            self.run_cli(
                "skill",
                "search",
                "--index",
                str(self.index_path),
                "--request",
                str(duplicate),
                "--now",
                NOW,
            )
        )
        self.assertEqual(2, duplicate_code)
        self.assertFalse(duplicate_payload["ok"])
        self.assertIn("duplicate JSON key", duplicate_payload["error"]["message"])
        self.assert_canonical(duplicate_rendered, duplicate_payload)
        self.assertEqual("", duplicate_stderr)

        unknown_payload = request().to_dict()
        unknown_payload["body"] = "must not be accepted or echoed"
        unknown = self.write_json("unknown.json", unknown_payload)
        unknown_code, unknown_result, unknown_rendered, unknown_stderr = self.run_cli(
            "skill",
            "compose",
            "--index",
            str(self.index_path),
            "--request",
            str(unknown),
            "--now",
            NOW,
        )
        self.assertEqual(2, unknown_code)
        self.assertFalse(unknown_result["ok"])
        self.assertIn("unknown field", unknown_result["error"]["message"])
        self.assertNotIn("must not be accepted or echoed", unknown_rendered)
        self.assert_canonical(unknown_rendered, unknown_result)
        self.assertEqual("", unknown_stderr)

        nonstandard = self.root / "nonstandard-number.json"
        nonstandard.write_text(
            json.dumps(request().to_dict(), sort_keys=True).replace(
                '"max_total_cost": 4.0', '"max_total_cost": NaN'
            ),
            encoding="utf-8",
        )
        number_code, number_result, number_rendered, number_stderr = self.run_cli(
            "skill",
            "search",
            "--index",
            str(self.index_path),
            "--request",
            str(nonstandard),
            "--now",
            NOW,
        )
        self.assertEqual(2, number_code)
        self.assertIn("non-standard JSON number", number_result["error"]["message"])
        self.assert_canonical(number_rendered, number_result)
        self.assertEqual("", number_stderr)

    def test_stale_index_and_double_stdin_fail_closed(self) -> None:
        stale_path = self.write_json(
            "stale.json", replace(index(), ttl_seconds=30).to_dict()
        )
        stale_code, stale, stale_rendered, _ = self.run_cli(
            "skill",
            "compose",
            "--index",
            str(stale_path),
            "--request",
            str(self.request_path),
            "--now",
            NOW,
        )
        self.assertEqual(2, stale_code)
        self.assertFalse(stale["ok"])
        self.assertIn("stale", stale["error"]["message"])
        self.assert_canonical(stale_rendered, stale)

        double_code, double, double_rendered, double_stderr = self.run_cli(
            "skill",
            "search",
            "--index",
            "-",
            "--request",
            "-",
            "--now",
            NOW,
            stdin="{}",
        )
        self.assertEqual(2, double_code)
        self.assertFalse(double["ok"])
        self.assertIn("at most one skill input", double["error"]["message"])
        self.assert_canonical(double_rendered, double)
        self.assertEqual("", double_stderr)

    def test_non_object_and_remote_inputs_are_rejected(self) -> None:
        array_path = self.write_json("array.json", [])
        array_code, array_result, array_rendered, _ = self.run_cli(
            "skill",
            "search",
            "--index",
            str(array_path),
            "--request",
            str(self.request_path),
            "--now",
            NOW,
        )
        self.assertEqual(2, array_code)
        self.assertIn("must be a JSON object", array_result["error"]["message"])
        self.assert_canonical(array_rendered, array_result)

        remote_code, remote_result, remote_rendered, _ = self.run_cli(
            "skill",
            "compose",
            "--index",
            "https://example.invalid/index.json",
            "--request",
            str(self.request_path),
            "--now",
            NOW,
        )
        self.assertEqual(2, remote_code)
        self.assertIn("local file path", remote_result["error"]["message"])
        self.assert_canonical(remote_rendered, remote_result)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
