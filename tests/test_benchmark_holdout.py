from __future__ import annotations

import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "benchmark_holdout", ROOT / "scripts" / "benchmark_holdout.py"
)
assert SPEC and SPEC.loader
HOLDOUT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HOLDOUT)


class BenchmarkHoldoutTests(unittest.TestCase):
    def load(self) -> dict:
        return json.loads(
            (ROOT / "research/corpus/generic-mission-benchmark-v1.json").read_text(
                encoding="utf-8"
            )
        )

    def test_manifest_is_deterministic_and_does_not_promote_gold(self) -> None:
        corpus = self.load()
        first = HOLDOUT.build_manifest(corpus, corpus_path="research/corpus/generic-mission-benchmark-v1.json")
        second = HOLDOUT.build_manifest(corpus, corpus_path="research/corpus/generic-mission-benchmark-v1.json")
        self.assertEqual(first, second)
        self.assertEqual(8, first["holdout_count"])
        self.assertEqual(8, len(first["holdout_ids"]))
        self.assertEqual("provisional_machine_only", first["label_status"])
        self.assertFalse(first["human_gold_frozen"])
        self.assertEqual(64, len(first["corpus_sha256"]))
        self.assertEqual(64, len(first["holdout_sha256"]))

    def test_verify_rejects_corpus_drift_and_manifest_promotion(self) -> None:
        corpus = self.load()
        manifest = HOLDOUT.build_manifest(corpus)
        changed = json.loads(json.dumps(corpus))
        changed["items"][0]["goal"] = "changed"
        report = HOLDOUT.verify_manifest(changed, manifest)
        self.assertFalse(report["valid"])
        self.assertFalse(report["checks"]["corpus_sha256"])
        promoted = dict(manifest)
        promoted["human_gold_frozen"] = True
        self.assertFalse(HOLDOUT.verify_manifest(corpus, promoted)["valid"])

    def test_committed_manifest_verifies_against_corpus(self) -> None:
        corpus = self.load()
        manifest_path = ROOT / "research/corpus/generic-mission-benchmark-v1-holdout.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        report = HOLDOUT.verify_manifest(corpus, manifest)
        self.assertTrue(report["valid"], report)

    def test_unsupported_rule_fails_closed(self) -> None:
        corpus = self.load()
        corpus["holdout_rule"] = "random selection"
        with self.assertRaises(ValueError):
            HOLDOUT.build_manifest(corpus)

    def test_provenance_audit_does_not_call_machine_dual_pass_human_gold(self) -> None:
        report = HOLDOUT.audit_label_provenance(self.load())
        self.assertEqual(40, report["item_count"])
        self.assertEqual(40, report["machine_only_rows"])
        self.assertEqual(0, report["human_evidence_rows"])
        self.assertEqual(40, report["deterministic_projection_agreement_rows"])
        self.assertTrue(report["machine_placeholder"])
        self.assertFalse(report["human_gold_promoted"])
        self.assertFalse(report["promotion_allowed"])
        self.assertIn("no_recorded_human_provenance", report["reasons"])

    def test_blind_packet_is_label_free_and_digest_verifies(self) -> None:
        corpus = self.load()
        manifest = HOLDOUT.build_manifest(corpus)
        packet = HOLDOUT.build_blind_annotation_packet(corpus, manifest)
        self.assertEqual(8, packet["item_count"])
        self.assertEqual("unlabeled", packet["annotation_status"])
        self.assertEqual("none_recorded", packet["label_source"])
        self.assertFalse(packet["human_gold_frozen"])
        forbidden = {
            "annotator_a",
            "annotator_b",
            "adjudicated",
            "adjudication",
            "labeling_status",
            "split",
            "expected_ok",
        }
        for item in packet["items"]:
            self.assertEqual(
                {"mission_id", "task_kind", "goal", "deliverable_path", "write_scope", "validator", "claim_boundary"},
                set(item["task"]),
            )
            self.assertTrue(forbidden.isdisjoint(item["task"]))
        report = HOLDOUT.verify_blind_annotation_packet(corpus, manifest, packet)
        self.assertTrue(report["valid"], report)

    def test_blind_packet_rejects_task_label_injection_even_with_rehashed_packet(self) -> None:
        corpus = self.load()
        manifest = HOLDOUT.build_manifest(corpus)
        packet = HOLDOUT.build_blind_annotation_packet(corpus, manifest)
        packet["items"][0]["task"]["adjudicated"] = {"claim_risk": "high"}
        packet["packet_sha256"] = HOLDOUT.digest(HOLDOUT._blind_packet_core(packet))
        report = HOLDOUT.verify_blind_annotation_packet(corpus, manifest, packet)
        self.assertFalse(report["valid"])
        self.assertFalse(report["checks"]["items"])
        self.assertFalse(report["checks"]["no_extra_task_fields"])

    def test_blind_packet_rejects_holdout_digest_or_promotion_drift(self) -> None:
        corpus = self.load()
        manifest = HOLDOUT.build_manifest(corpus)
        packet = HOLDOUT.build_blind_annotation_packet(corpus, manifest)
        packet["holdout_sha256"] = "0" * 64
        report = HOLDOUT.verify_blind_annotation_packet(corpus, manifest, packet)
        self.assertFalse(report["valid"])
        self.assertFalse(report["checks"]["holdout_sha256"])

        promoted = HOLDOUT.build_blind_annotation_packet(corpus, manifest)
        promoted["human_gold_frozen"] = True
        promoted["packet_sha256"] = HOLDOUT.digest(HOLDOUT._blind_packet_core(promoted))
        report = HOLDOUT.verify_blind_annotation_packet(corpus, manifest, promoted)
        self.assertFalse(report["valid"])
        self.assertFalse(report["checks"]["human_gold_frozen"])

    def test_blind_packet_fails_closed_on_unclassified_corpus_field(self) -> None:
        corpus = self.load()
        corpus["items"][0]["new_target_label"] = "secret"
        with self.assertRaises(ValueError):
            HOLDOUT.build_blind_annotation_packet(corpus)

    def _annotation_input(self, corpus: dict) -> dict:
        holdout = [row for row in corpus["items"] if row["split"] == "holdout"]
        return {
            "annotator_id": "reviewer-a",
            "annotation_round": "independent-1",
            "annotations": [
                {"mission_id": row["mission_id"], "labels": dict(row["annotator_a"])}
                for row in holdout
            ],
        }

    def test_human_annotation_artifact_is_bound_and_unpromoted(self) -> None:
        corpus = self.load()
        manifest = HOLDOUT.build_manifest(corpus)
        blind = HOLDOUT.build_blind_annotation_packet(corpus, manifest)
        annotation = HOLDOUT.build_human_annotation_packet(
            corpus, manifest, blind, self._annotation_input(corpus)
        )
        report = HOLDOUT.verify_human_annotation_packet(
            corpus, manifest, blind, annotation
        )
        self.assertTrue(report["valid"], report)
        self.assertTrue(report["human_evidence_recorded"])
        self.assertFalse(report["human_gold_promoted"])
        self.assertFalse(report["promotion_allowed"])
        self.assertFalse(annotation["human_gold_frozen"])
        self.assertEqual(blind["packet_sha256"], annotation["source_packet_sha256"])
        self.assertEqual(8, annotation["item_count"])

    def test_human_annotation_rejects_unknown_fields_and_packet_drift(self) -> None:
        corpus = self.load()
        manifest = HOLDOUT.build_manifest(corpus)
        blind = HOLDOUT.build_blind_annotation_packet(corpus, manifest)
        raw = self._annotation_input(corpus)
        raw["annotations"][0]["labels"]["unexpected"] = "target"
        with self.assertRaises(ValueError):
            HOLDOUT.build_human_annotation_packet(corpus, manifest, blind, raw)

        valid = self._annotation_input(corpus)
        annotation = HOLDOUT.build_human_annotation_packet(
            corpus, manifest, blind, valid
        )
        drifted = json.loads(json.dumps(annotation))
        drifted["source_packet_sha256"] = "0" * 64
        drifted["annotation_sha256"] = HOLDOUT.digest(
            HOLDOUT._human_annotation_core(drifted)
        )
        report = HOLDOUT.verify_human_annotation_packet(
            corpus, manifest, blind, drifted
        )
        self.assertFalse(report["valid"])
        self.assertFalse(report["checks"]["source_packet_sha256"])

    def test_holdout_cli_exports_and_verifies_annotation_artifacts(self) -> None:
        corpus_path = ROOT / "research/corpus/generic-mission-benchmark-v1.json"
        manifest_path = ROOT / "research/corpus/generic-mission-benchmark-v1-holdout.json"
        corpus = self.load()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            blind_path = root / "blind.json"
            raw_path = root / "annotation-input.json"
            annotation_path = root / "annotation.json"
            raw_path.write_text(
                json.dumps(self._annotation_input(corpus), ensure_ascii=False),
                encoding="utf-8",
            )
            script = ROOT / "scripts" / "benchmark_holdout.py"

            def run(*args: str) -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    [sys.executable, str(script), *args],
                    cwd=ROOT,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )

            exported = run(
                "--corpus",
                str(corpus_path),
                "--manifest",
                str(manifest_path),
                "--blind-packet",
                "--output",
                str(blind_path),
            )
            self.assertEqual(0, exported.returncode, exported.stderr)
            verified_blind = run(
                "--corpus",
                str(corpus_path),
                "--manifest",
                str(manifest_path),
                "--verify-blind",
                "--packet",
                str(blind_path),
            )
            self.assertEqual(0, verified_blind.returncode, verified_blind.stderr)
            built = run(
                "--corpus",
                str(corpus_path),
                "--manifest",
                str(manifest_path),
                "--build-annotation",
                "--packet",
                str(blind_path),
                "--annotation-input",
                str(raw_path),
                "--output",
                str(annotation_path),
            )
            self.assertEqual(0, built.returncode, built.stderr)
            verified = run(
                "--corpus",
                str(corpus_path),
                "--manifest",
                str(manifest_path),
                "--verify-annotation",
                "--packet",
                str(blind_path),
                "--annotation",
                str(annotation_path),
            )
            self.assertEqual(0, verified.returncode, verified.stderr)
            report = json.loads(verified.stdout)
            self.assertTrue(report["valid"], report)
            self.assertFalse(report["human_gold_promoted"])


if __name__ == "__main__":
    unittest.main()
