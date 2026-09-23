from __future__ import annotations

import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "research" / "corpus" / "generic-mission-benchmark-v1.json"


class GenericMissionBenchmarkTests(unittest.TestCase):
    def load(self) -> dict:
        return json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_fixture_has_forty_generic_records_and_holdout(self) -> None:
        payload = self.load()
        self.assertEqual(1, payload["schema_version"])
        self.assertEqual("provisional", payload["status"])
        rows = payload["items"]
        self.assertEqual(40, len(rows))
        self.assertEqual({"S0", "S1", "S2", "S3"}, {row["stratum"] for row in rows})
        for stratum in ("S0", "S1", "S2", "S3"):
            self.assertEqual(10, sum(row["stratum"] == stratum for row in rows))
        self.assertEqual(8, sum(row["split"] == "holdout" for row in rows))

    def test_dual_pass_and_adjudication_are_explicit(self) -> None:
        for row in self.load()["items"]:
            with self.subTest(mission=row["mission_id"]):
                self.assertEqual(row["annotator_a"], row["annotator_b"])
                self.assertEqual(row["annotator_a"], row["adjudicated"])
                self.assertEqual("resolved", row["adjudication"]["status"])
                self.assertEqual("provisional_machine_dual_pass", row["labeling_status"])
                self.assertTrue(row["goal"] and row["write_scope"] and row["validator"])

    def test_fixture_has_no_retired_domain_terms_or_private_paths(self) -> None:
        text = FIXTURE.read_text(encoding="utf-8").lower()
        for term in ("fem", "mpb", "pwe", "maxwell", "chern", "localizer", "/root/", "/users/"):
            self.assertNotIn(term, text)


if __name__ == "__main__":
    unittest.main()
