"""Provider-free tests for the WP2 mission compiler and claim contract.

Covers: a generic multi-adapter integration mission, material ambiguity
emission, claim boundary preservation, cycle detection, the policy-excluded
OpenCode Go DeepSeek override, path/write-scope fields, and the fail-closed
rejection rules.  No provider, network, or model prompt is ever contacted.
Retired domain fixtures are out of v3 scope and are not part of this suite.
"""

from __future__ import annotations

import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from local_agent_dispatch.domain.mission import (  # noqa: E402
    OPENCODE_GO_POOL,
    compute_waves,
    validate_mission,
)
from local_agent_dispatch.intent.claim_contract import (  # noqa: E402
    build_claim_contract,
    claim_is_allowed,
    claim_status,
    validate_claim_contract,
)
from local_agent_dispatch.intent.compiler import (  # noqa: E402
    CompileResult,
    compile_mission,
    compile_structured,
)

CORPUS_PATH = ROOT / "research" / "corpus" / "missions.jsonl"

MISSION_WITHOUT_OVERRIDE = """\
Goal: adapt the export output adapter into the shared schema.

Non-goals:
- no scientific claims

Deliverables:
- adapter (paths: adapters/export/output.py; write_scope: adapters/export/)

Acceptance:
- schema round-trip passes

Claims:
- allowed: none
- forbidden: scientific claims

Evidence: E1

Data:
- classification: public
- location: local

Dag:
- s0: preflight; depends: ; write_scope: .lad/; risk: low
- s1: adapter; depends: s0; write_scope: adapters/export/; risk: low; validator: schema_roundtrip

Validators:
- schema_roundtrip: schema conformance

Git: commit allowed; push review required

Placement:
- execution_host: local
- workload_host: local
- wrapper: none needed

Providers:
- opencode go deepseek-v4-flash (pool: opencode.go; role: bounded parallel adapter lanes)

Quality:
- floor: highest advertised

Deadline: 2026-08-20

Quota:
- reserve: 5%
"""

GENERIC_MISSION_ID = "generic-multi-adapter-integration"

GENERIC_MISSION_TEXT = """\
Goal: integrate alpha, beta, gamma, and delta output adapters behind one
schema with deterministic tests and a bounded release checklist.

Non-goals:
- do not claim production readiness
- do not release to public users
- do not download new data, models, or environments during execution
- do not expand the scope autonomously

Deliverables:
- alpha output adapter (paths: adapters/alpha/output.py; write_scope: adapters/alpha/)
- beta output adapter (paths: adapters/beta/output.py; write_scope: adapters/beta/)
- gamma output adapter (paths: adapters/gamma/output.py; write_scope: adapters/gamma/)
- delta output adapter (paths: adapters/delta/output.py; write_scope: adapters/delta/)
- interface/schema integration (paths: schemas/export.json; write_scope: schemas/)
- deterministic integration tests (paths: tests/test_export_schema.py; write_scope: tests/)

Acceptance:
- each adapter output round-trips its schema
- integration tests pass
- deterministic checks pass
- uncovered production, release, and certification conclusions are listed

Claims:
- allowed: adapter interfaces, schemas, deterministic tests, integration test implementation with validation evidence
- deferred: performance conclusions from integration results, operational significance of the schema
- forbidden: production deployment, public release, external certifications
- promotion_gate: independent validation program with review gate

Evidence: E1; all results labeled toy, public-data, simulator, or bounded fixtures.

Data:
- classification: public
- location: local

Dag:
- s0: system/provider/host/mount/route preflight; depends: ; write_scope: .lad/; risk: low; parallel: true
- s1a: alpha output adapter; depends: s0; write_scope: adapters/alpha/; risk: low; validator: schema_roundtrip; parallel: true
- s1b: beta output adapter; depends: s0; write_scope: adapters/beta/; risk: low; validator: schema_roundtrip; parallel: true
- s1c: gamma output adapter; depends: s0; write_scope: adapters/gamma/; risk: low; validator: schema_roundtrip; parallel: true
- s1d: delta output adapter; depends: s0; write_scope: adapters/delta/; risk: low; validator: schema_roundtrip; parallel: true
- s2: interface/schema integration; depends: s1a, s1b, s1c, s1d; write_scope: schemas/; risk: medium; validator: integration_tests
- s3: deterministic integration tests; depends: s2; write_scope: tests/; risk: high; validator: integration_tests; independent_review
- s4: schema conformance checks; depends: s2; write_scope: fixtures/; risk: low; validator: schema_roundtrip
- s5: independent review; depends: s3, s4; write_scope: review/; risk: medium; validator: independent_review
- s6: human commit gate; depends: s5; write_scope: git/; risk: high; validator: human_gate

Validators:
- schema_roundtrip: adapter output re-parses into the shared schema
- integration_tests: s2 passes the integration suite
- independent_review: reviewer from a different model family or a human
- human_gate: explicit user approval before commit/push

Parallelism: adapters run in parallel only when write scopes are disjoint;
then integration, deterministic tests, independent review, and human commit
gate.

Providers:
- antigravity gemini (pool: antigravity.gemini; role: broad work)
- opencode go deepseek-v4-flash (pool: opencode.go; explicit user override; role: bounded parallel adapter lanes)

Quality:
- floor: highest advertised
- effort: max; never ultra

Git: commit code when appropriate; push and merge require review.

Placement:
- execution_host: local (desktop-authenticated agent CLIs)
- workload_host: server (preferred)
- preference: server_first
- wrapper: unknown

Checkpoints:
- s0 preflight gate
- s2 integration gate
- s3 validation gate
- s4 conformance gate
- s5 independent review
- s6 human commit gate

Stop:
- any need for new data, model, environment, or long compute stops at a resource/route gate
- any claim-boundary expansion attempt stops

Cps:
- implementer: bounded write-scoped adapter capsule
- integrator: schema integration capsule
- independent_reviewer: reviewer family differs from implementer
- human_gate: commit and push approval
"""


def _compile_generic() -> CompileResult:
    return compile_mission(GENERIC_MISSION_TEXT, mission_id=GENERIC_MISSION_ID)


class GenericMissionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.result = _compile_generic()
        self.spec = self.result.spec

    def test_generic_compiles_provider_free_and_non_executing(self) -> None:
        self.assertTrue(self.result.ok, [item.code for item in self.result.rejected])
        self.assertEqual([], self.result.rejected)
        self.assertTrue(self.spec.compile["provider_free"])
        self.assertTrue(self.spec.compile["executes_nothing"])
        self.assertEqual("natural_language", self.spec.compile["origin"])
        self.assertEqual(GENERIC_MISSION_ID, self.spec.mission_id)
        self.assertEqual(2, self.spec.schema_version)
        self.assertIsNotNone(self.spec.goal)
        self.assertEqual(6, len(self.spec.deliverables))
        self.assertGreaterEqual(len(self.spec.non_goals), 3)

    def test_generic_dag_topology(self) -> None:
        nodes = [item.value for item in self.spec.dag_hints]
        waves, cycles = compute_waves(nodes)
        self.assertEqual([], cycles)
        self.assertEqual(
            [["s0"], ["s1a", "s1b", "s1c", "s1d"], ["s2"], ["s3", "s4"], ["s5"], ["s6"]],
            waves,
        )
        node_ids = {node["id"] for node in nodes}
        self.assertTrue({"s0", "s1a", "s1b", "s1c", "s1d", "s2", "s3", "s4", "s5", "s6"} <= node_ids)

    def test_generic_parallel_wave_write_scopes_are_disjoint(self) -> None:
        nodes = {item.value["id"]: item.value for item in self.spec.dag_hints}
        scopes = [nodes[node_id]["write_scope"] for node_id in ("s1a", "s1b", "s1c", "s1d")]
        self.assertEqual(
            ["adapters/alpha/", "adapters/beta/", "adapters/gamma/", "adapters/delta/"],
            scopes,
        )
        self.assertEqual(len(set(scopes)), len(scopes))
        for node_id in ("s1a", "s1b", "s1c", "s1d"):
            self.assertTrue(nodes[node_id].get("parallel"))

    def test_generic_claim_boundary_preserved(self) -> None:
        envelope = self.spec.claim_envelope
        self.assertIsNotNone(envelope)
        self.assertIn("production deployment", envelope.forbidden)
        self.assertIn("public release", envelope.forbidden)
        self.assertIn("external certifications", envelope.forbidden)
        self.assertNotIn("production deployment", envelope.allowed)
        self.assertNotIn("external certifications", envelope.allowed)
        self.assertEqual("E1", envelope.evidence_level.value)
        contract = build_claim_contract(self.spec)
        self.assertEqual([], validate_claim_contract(contract, self.spec))
        self.assertFalse(claim_is_allowed(contract, "production deployment"))
        self.assertEqual("forbidden", claim_status(contract, "external certifications"))
        self.assertEqual(
            "deferred",
            claim_status(contract, "performance conclusions from integration results"),
        )
        self.assertEqual("allowed", claim_status(contract, "deterministic tests"))
        self.assertTrue(any("independent" in gate for _, gate in contract.promotion_gates))

    def test_generic_deepseek_override_pinned_to_single_pool(self) -> None:
        override = self.spec.policy["policy_excluded_model_override"]
        self.assertTrue(override.value["allowed"])
        self.assertEqual("opencode-go/deepseek-v4-flash", override.value["exact_model"])
        self.assertEqual(OPENCODE_GO_POOL, override.value["pool"])
        self.assertEqual("explicit_policy_override", override.value["model_role"])
        self.assertFalse(override.value["separate_quota_pool"])
        self.assertTrue(override.value["requires_review"])
        pool_policy = self.spec.policy["pool_policy"].value
        self.assertIn(OPENCODE_GO_POOL, pool_policy["pools"])
        self.assertFalse(any("deepseek" in pool_id for pool_id in pool_policy["pools"]))
        self.assertFalse(any(item.code == "invalid_quota_pool" for item in self.result.rejected))

    def test_generic_git_authority_resolved_not_guessed(self) -> None:
        git = self.spec.git_authority.value
        self.assertEqual("allow", git["commit"]["decision"])
        self.assertEqual("review_required", git["push"]["decision"])
        self.assertEqual("review_required", git["merge"]["decision"])
        self.assertTrue(git["human_commit_gate"])
        self.assertFalse(any(item.code == "ambiguous_git_authority" for item in self.result.rejected))

    def test_generic_material_ambiguities_emitted_for_review(self) -> None:
        fields = {item.field for item in self.result.ambiguous}
        self.assertTrue({"deadline", "quota_reserve", "placement", "model_policy"} <= fields)
        for ambiguity in self.result.ambiguous:
            self.assertTrue(ambiguity.materiality)

    def test_generic_validators_cover_high_risk_nodes(self) -> None:
        high_risk = [item.value for item in self.spec.dag_hints if item.value.get("risk") == "high"]
        self.assertTrue(high_risk)
        for node in high_risk:
            self.assertTrue(node.get("validator"))
        self.assertFalse(any(item.code == "missing_validator_for_high_risk" for item in self.result.rejected))

    def test_generic_checkpoints_artifacts_stop_conditions(self) -> None:
        self.assertTrue(self.spec.checkpoints)
        self.assertTrue(self.spec.artifacts)
        self.assertTrue(any("claim" in str(item.value).lower() for item in self.spec.stop_conditions))
        self.assertTrue(self.spec.cps_profiles)

    def test_generic_serialization_round_trips(self) -> None:
        payload = self.spec.to_dict()
        text = json.dumps(payload)
        self.assertIn(GENERIC_MISSION_ID, text)
        self.assertEqual(2, json.loads(text)["schema_version"])
        second = _compile_generic()
        self.assertEqual(payload, second.spec.to_dict())


class AmbiguityTests(unittest.TestCase):
    def _mission_without_deadline_and_quota(self) -> str:
        mission = MISSION_WITHOUT_OVERRIDE
        mission = mission.replace("\nDeadline: 2026-08-20\n", "\n")
        quota_marker = mission.index("Quota:")
        return mission[:quota_marker].rstrip() + "\n"

    def test_material_ambiguity_is_emitted_not_guessed(self) -> None:
        result = compile_mission(self._mission_without_deadline_and_quota(), mission_id="ambig-test")
        fields = {item.field for item in result.ambiguous}
        self.assertIn("quota_reserve", fields)
        self.assertIn("deadline", fields)
        self.assertIn("policy_excluded_model_override", fields)
        self.assertIsNone(result.spec.deadline)

    def test_unknown_stays_unknown_never_fabricated(self) -> None:
        result = compile_mission(self._mission_without_deadline_and_quota(), mission_id="unknown-test")
        self.assertIsNone(result.spec.quota_reserve)
        self.assertIsNone(result.spec.deadline)

    def test_highest_advertised_normalizes_to_max_soft(self) -> None:
        result = compile_mission(MISSION_WITHOUT_OVERRIDE, mission_id="floor-test")
        effort = result.spec.policy["effort"]
        self.assertEqual("max", effort.value)
        self.assertEqual("soft", effort.status)
        self.assertFalse(any(item.code == "unsupported_effort" for item in result.rejected))

    def test_unsupported_effort_fails_closed(self) -> None:
        mission = MISSION_WITHOUT_OVERRIDE.replace(
            "Quality:\n- floor: highest advertised",
            "Quality:\n- floor: highest advertised\n- effort: ultra",
        )
        result = compile_mission(mission, mission_id="ultra-test")
        self.assertFalse(result.ok)
        self.assertEqual(["unsupported_effort"], [item.code for item in result.rejected])

    def test_missing_claim_envelope_rejected_for_scientific_mission(self) -> None:
        mission = MISSION_WITHOUT_OVERRIDE.replace("Claims:\n- allowed: none\n- forbidden: scientific claims\n\n", "")
        result = compile_mission(mission, mission_id="no-claims-test")
        self.assertFalse(result.ok)
        self.assertIn("missing_claim_envelope", [item.code for item in result.rejected])


class ClaimPreservationTests(unittest.TestCase):
    def test_forbidden_claims_never_promotable(self) -> None:
        result = _compile_generic()
        contract = build_claim_contract(result.spec)
        for claim in ("production deployment", "public release", "external certifications"):
            self.assertNotEqual("allowed", claim_status(contract, claim))
            self.assertFalse(claim_is_allowed(contract, claim))

    def test_deferred_claims_require_promotion_gate(self) -> None:
        result = _compile_generic()
        contract = build_claim_contract(result.spec)
        for claim in contract.deferred:
            self.assertTrue(any(claim in deferred for deferred, _ in contract.promotion_gates))
            self.assertEqual("deferred", claim_status(contract, claim))

    def test_deferred_without_gate_is_rejected(self) -> None:
        result = _compile_generic()
        contract = build_claim_contract(result.spec)
        contract = type(contract)(
            claimable=contract.claimable,
            deferred=("performance conclusions",),
            forbidden=contract.forbidden,
            promotion_gates=(),
            evidence_level=contract.evidence_level,
            non_goals_preserved=contract.non_goals_preserved,
        )
        codes = [item.code for item in validate_claim_contract(contract, result.spec)]
        self.assertIn("missing_promotion_gate", codes)

    def test_forbidden_allowed_overlap_is_rejected(self) -> None:
        result = _compile_generic()
        contract = build_claim_contract(result.spec)
        contract = type(contract)(
            claimable=("production deployment",),
            deferred=contract.deferred,
            forbidden=contract.forbidden,
            promotion_gates=contract.promotion_gates,
            evidence_level=contract.evidence_level,
            non_goals_preserved=contract.non_goals_preserved,
        )
        codes = [item.code for item in validate_claim_contract(contract, result.spec)]
        self.assertIn("claim_boundary_overlap", codes)

    def test_evidence_level_preserved_verbatim(self) -> None:
        result = _compile_generic()
        contract = build_claim_contract(result.spec)
        self.assertEqual("E1", contract.evidence_level)
        self.assertEqual("E1", result.spec.claim_envelope.evidence_level.value)

    def test_non_goal_claims_folded_into_forbidden(self) -> None:
        result = _compile_generic()
        contract = build_claim_contract(result.spec)
        self.assertTrue(contract.non_goals_preserved)
        self.assertEqual([], validate_claim_contract(contract, result.spec))


class CycleDetectionTests(unittest.TestCase):
    def _cycle_mission(self, edges: list[tuple[str, str]]) -> str:
        lines = ["Goal: cyclic mission", "", "Non-goals:", "- no scientific claims", "", "Deliverables:"]
        for source, target in edges:
            lines.append(f"- node {source} (paths: out/{source}.py; write_scope: out/{source}/)")
        lines += [
            "",
            "Claims:",
            "- allowed: none",
            "- forbidden: scientific claims",
            "",
            "Evidence: E1",
            "",
            "Dag:",
        ]
        for source, target in edges:
            lines.append(f"- {source}: node; depends: {target}; write_scope: out/{source}/; risk: low; validator: check")
        lines += [
            "",
            "Validators:",
            "- check: conformance",
            "",
            "Git: commit allowed; push review required",
            "",
            "Placement:",
            "- execution_host: local",
            "- workload_host: local",
            "- wrapper: none needed",
            "",
            "Deadline: 2026-08-20",
        ]
        return "\n".join(lines)

    def test_dag_cycle_rejected(self) -> None:
        mission = self._cycle_mission([("a", "b"), ("b", "a")])
        result = compile_mission(mission, mission_id="cycle-test")
        self.assertFalse(result.ok)
        self.assertIn("dag_cycle", [item.code for item in result.rejected])

    def test_self_dependency_rejected(self) -> None:
        mission = self._cycle_mission([("a", "a")])
        result = compile_mission(mission, mission_id="self-cycle-test")
        self.assertFalse(result.ok)
        self.assertIn("dag_cycle", [item.code for item in result.rejected])

    def test_unknown_dependency_rejected(self) -> None:
        mission = self._cycle_mission([("a", "missing")])
        result = compile_mission(mission, mission_id="unknown-dep-test")
        self.assertFalse(result.ok)
        self.assertIn("unknown_dependency", [item.code for item in result.rejected])


class PolicyExcludedModelTests(unittest.TestCase):
    def test_deepseek_without_explicit_override_stays_excluded(self) -> None:
        result = compile_mission(MISSION_WITHOUT_OVERRIDE, mission_id="no-override-test")
        self.assertTrue(result.ok)
        override = result.spec.policy["policy_excluded_model_override"]
        self.assertFalse(override.value["allowed"])
        self.assertEqual(OPENCODE_GO_POOL, override.value["pool"])
        fields = {item.field for item in result.ambiguous}
        self.assertIn("policy_excluded_model_override", fields)

    def test_structured_allowlist_enables_exact_override(self) -> None:
        result = compile_structured(
            {
                "goal": "wire export adapter",
                "non_goals": ["no scientific claims"],
                "deliverables": [
                    {"id": "s1", "description": "adapter", "paths": ["adapters/export/output.py"], "write_scope": "adapters/export/"}
                ],
                "claims": {"allowed": [], "deferred": [], "forbidden": ["scientific claims"], "evidence_level": "E1"},
                "dag": [{"id": "s1", "depends_on": [], "write_scope": "adapters/export/", "risk": "low", "validator": "check"}],
                "validators": [{"id": "check", "description": "schema conformance"}],
                "policy": {
                    "providers": ["opencode go deepseek-v4-flash (pool: opencode.go; role: bounded lanes)"],
                    "allow_policy_excluded_models": ["opencode-go/deepseek-v4-flash"],
                    "model_by_pool": {"opencode.go": ["opencode-go/deepseek-v4-flash"]},
                },
                "git": {"commit": "allow", "push": "review_required", "merge": "review_required"},
                "placement": {"execution_host": "local", "workload_host": "local", "wrapper": "none needed"},
                "deadline": "2026-08-20",
            },
            mission_id="structured-override-test",
        )
        self.assertTrue(result.ok, [item.code for item in result.rejected])
        override = result.spec.policy["policy_excluded_model_override"].value
        self.assertTrue(override["allowed"])
        self.assertEqual("opencode-go/deepseek-v4-flash", override["exact_model"])
        self.assertEqual(OPENCODE_GO_POOL, override["pool"])
        self.assertFalse(override["separate_quota_pool"])

    def test_override_never_creates_separate_pool(self) -> None:
        result = _compile_generic()
        pool_policy = result.spec.policy["pool_policy"].value
        self.assertEqual({OPENCODE_GO_POOL, "antigravity.gemini"}, set(pool_policy["pools"]))
        self.assertEqual(
            "model brand never creates a separate quota pool",
            pool_policy["shared_pool_rule"],
        )


class PathWriteScopeTests(unittest.TestCase):
    def _mission_with_dag(self, dag_lines: list[str]) -> str:
        base = MISSION_WITHOUT_OVERRIDE
        start = base.index("Dag:")
        end = base.index("Validators:")
        return base[:start] + "Dag:\n" + "\n".join(dag_lines) + "\n\n" + base[end:]

    def test_every_node_carries_write_scope_and_output_paths(self) -> None:
        result = _compile_generic()
        for item in result.spec.dag_hints:
            node = item.value
            self.assertTrue(node.get("write_scope"), node)
            self.assertIn("output_paths", node)

    def test_path_traversal_write_scope_rejected(self) -> None:
        mission = self._mission_with_dag(
            ["- s1: adapter; depends: ; write_scope: ../../etc; risk: low; validator: schema_roundtrip"]
        )
        result = compile_mission(mission, mission_id="traversal-test")
        self.assertFalse(result.ok)
        self.assertIn("invalid_write_scope", [item.code for item in result.rejected])

    def test_parallel_nodes_with_overlapping_write_scopes_are_serialized(self) -> None:
        mission = self._mission_with_dag(
            [
                "- s1a: adapter a; depends: ; write_scope: adapters/export/; risk: low; parallel: true",
                "- s1b: adapter b; depends: ; write_scope: adapters/export/; risk: low; parallel: true",
            ]
        )
        result = compile_mission(mission, mission_id="scope-conflict-test")
        self.assertTrue(result.ok)
        nodes = {item.value["id"]: item.value for item in result.spec.dag_hints}
        self.assertFalse(nodes["s1a"].get("parallel"))
        self.assertFalse(nodes["s1b"].get("parallel"))
        fields = {item.field for item in result.ambiguous}
        self.assertIn("parallelism", fields)

    def test_missing_write_scope_emits_ambiguity_not_guess(self) -> None:
        mission = self._mission_with_dag(
            ["- s1: adapter; depends: ; risk: low; validator: schema_roundtrip"]
        )
        result = compile_mission(mission, mission_id="missing-scope-test")
        self.assertTrue(result.ok)
        fields = {item.field for item in result.ambiguous}
        self.assertIn("write_scope", fields)
        node = next(item.value for item in result.spec.dag_hints if item.value["id"] == "s1")
        self.assertEqual("unknown", node["write_scope"])


class RejectionGateTests(unittest.TestCase):
    def test_missing_validator_for_high_risk_deliverable_rejected(self) -> None:
        mission = MISSION_WITHOUT_OVERRIDE.replace(
            "- s1: adapter; depends: s0; write_scope: adapters/export/; risk: low; validator: schema_roundtrip",
            "- s1: adapter; depends: s0; write_scope: adapters/export/; risk: high",
        )
        result = compile_mission(mission, mission_id="validator-gate-test")
        self.assertFalse(result.ok)
        self.assertIn("missing_validator_for_high_risk", [item.code for item in result.rejected])

    def test_unknown_validator_reference_rejected_for_high_risk(self) -> None:
        mission = MISSION_WITHOUT_OVERRIDE.replace(
            "- s1: adapter; depends: s0; write_scope: adapters/export/; risk: low; validator: schema_roundtrip",
            "- s1: adapter; depends: s0; write_scope: adapters/export/; risk: high; validator: nonexistent_check",
        )
        result = compile_mission(mission, mission_id="validator-ref-test")
        self.assertFalse(result.ok)
        self.assertIn("missing_validator_for_high_risk", [item.code for item in result.rejected])

    def test_ambiguous_git_authority_rejected(self) -> None:
        mission = MISSION_WITHOUT_OVERRIDE.replace("Git: commit allowed; push review required\n\n", "")
        result = compile_mission(mission, mission_id="git-gate-test")
        self.assertFalse(result.ok)
        self.assertIn("ambiguous_git_authority", [item.code for item in result.rejected])

    def test_unwrapped_split_placement_rejected(self) -> None:
        mission = MISSION_WITHOUT_OVERRIDE.replace(
            "Placement:\n- execution_host: local\n- workload_host: local\n- wrapper: none needed",
            "Placement:\n- execution_host: local\n- workload_host: server\n- wrapper: none",
        )
        result = compile_mission(mission, mission_id="split-gate-test")
        self.assertFalse(result.ok)
        self.assertIn("unwrapped_split_placement", [item.code for item in result.rejected])

    def test_split_placement_with_wrapper_is_allowed(self) -> None:
        mission = MISSION_WITHOUT_OVERRIDE.replace(
            "Placement:\n- execution_host: local\n- workload_host: local\n- wrapper: none needed",
            "Placement:\n- execution_host: local\n- workload_host: server\n- wrapper: remote_worker_client",
        )
        result = compile_mission(mission, mission_id="split-wrapper-test")
        self.assertTrue(result.ok, [item.code for item in result.rejected])
        fields = {item.field for item in result.ambiguous}
        self.assertNotIn("placement", fields)


class StructuredCompileTests(unittest.TestCase):
    def test_structured_compile_carries_explicit_sources(self) -> None:
        result = compile_structured(
            {
                "goal": "classify dispatch logs",
                "non_goals": ["no scientific claims"],
                "deliverables": [
                    {"id": "s1", "description": "classifier", "paths": ["reports/classification.py"], "write_scope": "reports/"}
                ],
                "claims": {"allowed": [], "deferred": [], "forbidden": ["scientific claims"], "evidence_level": "E1"},
                "dag": [{"id": "s1", "depends_on": [], "write_scope": "reports/", "risk": "low", "validator": "check"}],
                "validators": [{"id": "check", "description": "golden label match"}],
                "git": {"commit": "allow", "push": "review_required", "merge": "review_required"},
                "placement": {"execution_host": "local", "workload_host": "local", "wrapper": "none needed"},
                "deadline": "2026-08-20",
            },
            mission_id="structured-basic",
        )
        self.assertTrue(result.ok, [item.code for item in result.rejected])
        self.assertEqual("structured_input", result.spec.compile["origin"])
        self.assertEqual("structured_input", result.spec.goal.source.origin)
        self.assertIsNone(result.spec.goal.source.span)
        self.assertEqual("goal", result.spec.goal.source.phrase)

    def test_structured_and_text_agree_on_boundary(self) -> None:
        text_result = _compile_generic()
        structured = {
            "goal": str(text_result.spec.goal.value),
            "non_goals": [str(item.value) for item in text_result.spec.non_goals],
            "deliverables": [
                {
                    "id": item.value["id"],
                    "description": item.value["description"],
                    "paths": item.value.get("paths", []),
                    "write_scope": item.value.get("write_scope"),
                    "risk": item.value.get("risk", "low"),
                }
                for item in text_result.spec.deliverables
            ],
            "claims": {
                "allowed": text_result.spec.claim_envelope.allowed,
                "deferred": text_result.spec.claim_envelope.deferred,
                "forbidden": text_result.spec.claim_envelope.forbidden,
                "promotion_gate": str(text_result.spec.claim_envelope.promotion_gate.value),
                "evidence_level": "E1",
            },
            "dag": [dict(item.value) for item in text_result.spec.dag_hints],
            "validators": [dict(item.value) for item in text_result.spec.validators],
            "git": {
                "commit": text_result.spec.git_authority.value["commit"]["decision"],
                "push": text_result.spec.git_authority.value["push"]["decision"],
                "merge": text_result.spec.git_authority.value["merge"]["decision"],
            },
            "placement": text_result.spec.placement.value,
            "deadline": "2026-08-20",
        }
        structured_result = compile_structured(structured, mission_id="generic-structured")
        self.assertTrue(structured_result.ok, [item.code for item in structured_result.rejected])
        self.assertEqual(
            text_result.spec.claim_envelope.forbidden,
            structured_result.spec.claim_envelope.forbidden,
        )


class CorpusSweepTests(unittest.TestCase):
    def test_corpus_missions_compile_deterministically(self) -> None:
        self.assertTrue(CORPUS_PATH.is_file(), f"missing corpus: {CORPUS_PATH}")
        rows = [
            json.loads(line)
            for line in CORPUS_PATH.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self.assertGreaterEqual(len(rows), 10)
        for row in rows:
            with self.subTest(mission=row["mission_id"]):
                result = compile_mission(row["text"], mission_id=row["mission_id"])
                self.assertIsInstance(result, CompileResult)
                self.assertTrue(result.spec.compile["provider_free"])
                self.assertTrue(result.spec.compile["executes_nothing"])
                codes = [item.code for item in result.rejected]
                self.assertEqual(row["expected_ok"], result.ok, codes)
                self.assertEqual(sorted(row["expected_rejections"]), sorted(codes))
                ambiguity_fields = {item.field for item in result.ambiguous}
                for expected_field in row["expected_ambiguities"]:
                    self.assertIn(expected_field, ambiguity_fields, row["mission_id"])
                self.assertEqual(
                    result.spec.to_dict(),
                    compile_mission(row["text"], mission_id=row["mission_id"]).spec.to_dict(),
                )
                json.dumps(result.spec.to_dict())

    def test_corpus_compiles_match_schema_contract(self) -> None:
        for line in CORPUS_PATH.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            result = compile_mission(row["text"], mission_id=row["mission_id"])
            payload = result.spec.to_dict()
            self.assertEqual(2, payload["schema_version"])
            for key in (
                "goal", "non_goals", "deliverables", "acceptance_tests", "claim_envelope",
                "data_class", "dag_hints", "policy", "deadline", "quota_reserve",
                "git_authority", "cps_profiles", "checkpoints", "artifacts", "validators",
                "stop_conditions", "placement", "ambiguous", "compile",
            ):
                self.assertIn(key, payload)


if __name__ == "__main__":
    unittest.main()
