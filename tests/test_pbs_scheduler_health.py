from __future__ import annotations

import datetime as dt
import json
import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import pbs_scheduler_health as health  # noqa: E402


QUEUE_OK = """Queue              Max   Tot   Ena   Str   Que   Run   Hld   Wat   Trn   Ext T
----------------   ---   ---   ---   ---   ---   ---   ---   ---   ---   --- -
workq                0    11   yes   yes     0     9     2     0     0     0 E
"""

NODE_OK = """compute-01
     state = free
     np = 20
     properties = workq
     jobs =
     status = opsys=linux,totmem=132973672kb,availmem=60000000kb,physmem=65864812kb,ncpus=20,loadave=1.33,state=free
"""

MEMINFO_COMPUTE_01 = """MemTotal:       65864812 kB
MemFree:         4091544 kB
MemAvailable:   63300000 kB
Buffers:          147448 kB
Cached:         59317048 kB
SReclaimable:     610008 kB
SwapTotal:      67108860 kB
SwapFree:       67029812 kB
"""


class PBSSchedulerHealthTests(unittest.TestCase):
    def test_verified_queue_and_node_are_admission_ready(self):
        report = health.scheduler_health_from_outputs(
            QUEUE_OK, NODE_OK, queue_name="workq", node_name="compute-01"
        )
        self.assertEqual("verified", report["status"])
        self.assertTrue(report["admission_ready"])
        self.assertEqual("workq", report["queue"]["name"])
        self.assertEqual(11, report["queue"]["total_jobs"])
        self.assertEqual(20, report["node"]["np"])
        self.assertTrue(report["node"]["memory_metadata_consistent"])
        self.assertTrue(report["transport_ready"])
        self.assertFalse(report["memory_admission_ready"])

    def test_queue_disabled_blocks_admission(self):
        text = QUEUE_OK.replace("yes   yes", "no    yes")
        report = health.scheduler_health_from_outputs(text, NODE_OK)
        self.assertEqual("blocked", report["status"])
        self.assertFalse(report["admission_ready"])
        self.assertIn("queue_disabled", report["issues"])

    def test_inconsistent_memory_metadata_is_degraded_and_not_ready(self):
        node = NODE_OK.replace("availmem=60000000kb", "availmem=160000000kb").replace(
            "jobs =", "jobs = 0/16215.node1, 1/16215.node1"
        )
        report = health.scheduler_health_from_outputs(QUEUE_OK, node)
        self.assertEqual("degraded", report["status"])
        self.assertFalse(report["admission_ready"])
        self.assertFalse(report["node"]["memory_metadata_consistent"])
        self.assertIn("availmem_exceeds_physmem", report["issues"])
        self.assertTrue(report["node"]["state_jobs_consistent"])
        self.assertNotIn("node_free_with_assigned_jobs", report["issues"])

    def test_meminfo_diagnoses_legacy_virtual_availmem_without_waiving_memory_gate(self):
        node = NODE_OK.replace("availmem=60000000kb", "availmem=130589896kb")
        report = health.scheduler_health_from_outputs(
            QUEUE_OK, node, meminfo_text=MEMINFO_COMPUTE_01
        )
        diagnostic = report["memory_diagnostic"]
        self.assertEqual("virtual_availmem_includes_swap", diagnostic["semantics"])
        self.assertTrue(diagnostic["physmem_matches_memtotal"])
        self.assertTrue(diagnostic["totmem_matches_memtotal_plus_swaptotal"])
        self.assertTrue(diagnostic["availmem_matches_free_virtual_estimate"])
        self.assertTrue(report["transport_ready"])
        self.assertFalse(report["memory_admission_ready"])
        self.assertFalse(diagnostic["memory_admission_waiver"])

    def test_free_node_with_partial_assignments_can_still_be_ready(self):
        node = NODE_OK.replace(
            "jobs =", "jobs = 5/15908.node1, 6/16274.node1"
        )
        report = health.scheduler_health_from_outputs(QUEUE_OK, node)
        self.assertEqual("verified", report["status"])
        self.assertTrue(report["admission_ready"])
        self.assertEqual(2, report["node"]["assigned_job_count"])
        self.assertTrue(report["node"]["state_jobs_consistent"])

    def test_missing_or_malformed_outputs_are_unknown(self):
        report = health.scheduler_health_from_outputs("", "")
        self.assertEqual("unknown", report["status"])
        self.assertFalse(report["admission_ready"])
        self.assertIn("queue_not_found", report["issues"])
        self.assertIn("node_not_found", report["issues"])

    def test_report_drops_raw_status_and_unbounded_output(self):
        report = health.scheduler_health_from_outputs(QUEUE_OK, NODE_OK)
        serialized = json.dumps(report, sort_keys=True)
        self.assertNotIn("opsys", serialized)
        self.assertNotIn("loadave", serialized)
        self.assertNotIn("16215.node1", serialized)

    def test_scheduler_health_receipt_requires_fresh_bound_verified_evidence(self):
        receipt = {
            "schema_version": 1,
            "kind": "center_pbs_health_live",
            "observed_at": "2026-09-01T00:00:00Z",
            "resource_host": "compute-01",
            "report": health.scheduler_health_from_outputs(
                QUEUE_OK, NODE_OK, meminfo_text=MEMINFO_COMPUTE_01
            ),
        }
        result = health.validate_scheduler_health_receipt(
            receipt,
            now_utc="2026-09-01T00:05:00Z",
            expected_queue="workq",
            expected_node="compute-01",
            expected_host="compute-01",
        )
        self.assertTrue(result["valid"])
        self.assertEqual("admit", result["decision"])
        self.assertEqual("scheduler_health_verified", result["reason"])
        self.assertEqual("compute-01", result["summary"]["host"])
        self.assertRegex(result["evidence_digest"], r"^[0-9a-f]{64}$")

    def test_scheduler_health_receipt_blocks_stale_or_memory_degraded_evidence(self):
        degraded = health.scheduler_health_from_outputs(
            QUEUE_OK,
            NODE_OK.replace("availmem=60000000kb", "availmem=130589896kb"),
            meminfo_text=MEMINFO_COMPUTE_01,
        )
        receipt = {
            "schema_version": 1,
            "kind": "center_pbs_health_live",
            "observed_at": "2026-08-31T23:00:00Z",
            "resource_host": "compute-01",
            "report": degraded,
        }
        result = health.validate_scheduler_health_receipt(
            receipt,
            now_utc=dt.datetime(2026, 9, 1, tzinfo=dt.timezone.utc),
            max_age_seconds=300,
            expected_host="compute-01",
        )
        self.assertFalse(result["valid"])
        self.assertEqual("block", result["decision"])
        self.assertIn("scheduler_health_stale", result["reasons"])
        self.assertIn("scheduler_health_memory_admission_ready_false", result["reasons"])
        self.assertIn("scheduler_health_issues_present", result["reasons"])

    def test_scheduler_health_receipt_rejects_node_and_host_transplant(self):
        receipt = {
            "schema_version": 1,
            "kind": "center_pbs_health_live",
            "observed_at": "2026-09-01T00:00:00Z",
            "resource_host": "westd",
            "report": health.scheduler_health_from_outputs(QUEUE_OK, NODE_OK),
        }
        result = health.validate_scheduler_health_receipt(
            receipt,
            now_utc="2026-09-01T00:01:00Z",
            expected_node="node14",
            expected_host="compute-01",
        )
        self.assertFalse(result["valid"])
        self.assertIn("scheduler_health_node_mismatch", result["reasons"])
        self.assertIn("scheduler_health_host_mismatch", result["reasons"])


if __name__ == "__main__":
    unittest.main()
