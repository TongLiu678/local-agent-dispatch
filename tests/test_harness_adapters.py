"""Provider-free tests for the reference AgentHarness adapters."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from local_agent_dispatch.adapters.harness import (  # noqa: E402
    CommandPlan,
    CursorAgentHarness,
    CursorCommandPlanner,
    RunnerInvocation,
    RunnerOutcome,
)
from local_agent_dispatch.plugins import (  # noqa: E402
    ArtifactReference,
    CancelRequest,
    CapabilityRequest,
    CollectRequest,
    Evidence,
    HeartbeatRequest,
    ObserveRequest,
    PluginRegistry,
    PrepareRequest,
    ResumeRequest,
    SubmitRequest,
    conformance_report,
)


MODEL = "cursor-model-fixture"
ARTIFACT = ArtifactReference(
    "artifact://fixture/result.json",
    role="result",
    digest="sha256:" + "0" * 64,
    media_type="application/json",
)


class FakeRunner:
    """Durable in-memory runner; it never starts a process or uses a provider."""

    def __init__(self) -> None:
        self.calls: list[RunnerInvocation] = []
        self.states: dict[str, str] = {}

    def __call__(self, invocation: RunnerInvocation) -> RunnerOutcome:
        self.calls.append(invocation)
        handle_id = invocation.handle.handle_id
        if invocation.operation == "submit":
            self.states.setdefault(handle_id, "running")
            return RunnerOutcome(
                status="accepted",
                error_class="none",
                external_handle_id="fixture-session-1",
                submitted_at="2026-01-01T00:00:00Z",
            )
        if handle_id not in self.states:
            return RunnerOutcome(
                status="error",
                error_class="not_found",
                reason="fixture handle not found",
            )
        if invocation.operation == "observe":
            return RunnerOutcome(status=self.states[handle_id], error_class="none")
        if invocation.operation == "heartbeat":
            return RunnerOutcome(status="running", error_class="none")
        if invocation.operation == "cancel":
            self.states[handle_id] = "cancelled"
            return RunnerOutcome(status="cancelled", error_class="cancelled")
        if invocation.operation == "collect":
            return RunnerOutcome(
                status="succeeded",
                error_class="none",
                artifact_references=invocation.request.artifact_references,
            )
        if invocation.operation == "resume":
            self.states[handle_id] = "running"
            return RunnerOutcome(status="running", error_class="none")
        raise AssertionError(f"unexpected fixture operation: {invocation.operation}")


class HarnessAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.workspace = Path(self.temporary.name).resolve()
        self.write_scope = self.workspace / "bounded"
        self.write_scope.mkdir()
        self.runner = FakeRunner()

    def options(self, **overrides: object) -> dict[str, object]:
        values: dict[str, object] = {
            "model": MODEL,
            "prompt": "bounded fixture task",
            "cursor_prompt_argv_authorized": True,
            "cursor_sandbox": "enabled",
            "workspace": str(self.workspace),
            "write_scope": "bounded",
        }
        values.update(overrides)
        return values

    def harness(
        self,
        *,
        auth: Evidence | None = None,
        catalog: Evidence | None = None,
        runner: FakeRunner | None = None,
    ) -> CursorAgentHarness:
        return CursorAgentHarness(
            runner=runner or self.runner,
            auth_evidence=auth or Evidence(
                "ready", {"authenticated": True}, source="fixture"
            ),
            catalog_evidence=catalog or Evidence(
                "ready", {"models": [MODEL, "another-exact-model"]}, source="fixture"
            ),
        )

    def submit_request(
        self,
        *,
        fence_token: int = 7,
        idempotency_key: str = "submit-fixture",
        preparation_id: str | None = None,
        options: dict[str, object] | None = None,
    ) -> SubmitRequest:
        return SubmitRequest(
            job_id="job-fixture",
            attempt_id="attempt-fixture",
            idempotency_key=idempotency_key,
            fence_token=fence_token,
            preparation_id=preparation_id,
            artifact_references=(ARTIFACT,),
            options=options or self.options(),
        )

    def test_construction_registration_and_capabilities_do_not_call_runner(self) -> None:
        harness = self.harness()
        self.assertEqual([], self.runner.calls)
        report = conformance_report(harness, expected_kind="agent_harness")
        self.assertTrue(report.ok, report.issues)
        registry = PluginRegistry()
        registry.register(harness)
        capabilities = harness.capabilities(CapabilityRequest(scope="fixture"))
        self.assertEqual("ready", capabilities.status)
        self.assertEqual((MODEL, "another-exact-model"), capabilities.data["models"])
        self.assertEqual([], self.runner.calls)

    def test_cursor_command_is_confined_redacted_and_never_privileged(self) -> None:
        planner = CursorCommandPlanner(catalog_models=(MODEL,))
        request = PrepareRequest(
            job_id="job-fixture",
            attempt_id="attempt-fixture",
            idempotency_key="prepare-fixture",
            fence_token=7,
            options=self.options(),
        )
        plan = planner(request)
        self.assertEqual(str(self.write_scope), plan.cwd)
        self.assertEqual(str(self.write_scope), plan.argv[plan.argv.index("--workspace") + 1])
        self.assertEqual(MODEL, plan.argv[plan.argv.index("--model") + 1])
        self.assertEqual("enabled", plan.argv[plan.argv.index("--sandbox") + 1])
        self.assertEqual(("--", "bounded fixture task"), plan.argv[-2:])
        self.assertNotIn("bounded fixture task", repr(plan))
        self.assertNotIn("bounded fixture task", str(plan.summary))
        for forbidden in ("--trust", "--force", "-f", "--yolo"):
            self.assertNotIn(forbidden, plan.argv)

    def test_command_metadata_cannot_override_redacted_receipt_fields(self) -> None:
        for reserved in ("command", "argv", "cwd"):
            with self.subTest(reserved=reserved), self.assertRaisesRegex(
                ValueError, "cannot override receipt fields"
            ):
                CommandPlan(
                    argv=("cursor-agent", "secret-prompt"),
                    cwd=str(self.workspace),
                    redacted_argv=("cursor-agent", "<redacted>"),
                    sensitive_argv_indices=(1,),
                    metadata={reserved: "secret-prompt"},
                )

    def test_cursor_planner_fails_closed_on_policy_or_catalog_mismatch(self) -> None:
        harness = self.harness()
        cases = (
            ({"model": "model-not-in-catalog"}, "capability"),
            ({"cursor_prompt_argv_authorized": False}, "authorization"),
            ({"cursor_sandbox": "disabled"}, "authorization"),
            ({"write_scope": "../escape"}, "validation"),
            ({"cursor_trust_workspace": True}, "authorization"),
            ({"cursor_force_commands": True}, "authorization"),
        )
        for index, (override, expected_error) in enumerate(cases):
            with self.subTest(override=override):
                result = harness.prepare(
                    PrepareRequest(
                        job_id=f"job-{index}",
                        attempt_id="attempt-fixture",
                        idempotency_key=f"prepare-{index}",
                        fence_token=7,
                        options=self.options(**override),
                    )
                )
                self.assertEqual("blocked", result.status)
                self.assertEqual(expected_error, result.error_class)
        self.assertEqual([], self.runner.calls)

    def test_prepare_and_submit_are_idempotent_without_duplicate_runner_call(self) -> None:
        harness = self.harness()
        prepare = harness.prepare(
            PrepareRequest(
                job_id="job-fixture",
                attempt_id="attempt-fixture",
                idempotency_key="prepare-fixture",
                fence_token=7,
                artifact_references=(ARTIFACT,),
                options=self.options(),
            )
        )
        self.assertEqual("ready", prepare.status)
        self.assertIsNotNone(prepare.preparation_id)
        self.assertEqual([], self.runner.calls)

        request = self.submit_request(preparation_id=prepare.preparation_id)
        first = harness.submit(request)
        second = harness.submit(request)
        self.assertEqual("accepted", first.status)
        self.assertEqual(first, second)
        self.assertEqual(first.handle, second.handle)
        self.assertEqual(["submit"], [call.operation for call in self.runner.calls])

        conflict = harness.submit(
            self.submit_request(
                preparation_id=prepare.preparation_id,
                options=self.options(prompt="different fixture task"),
            )
        )
        self.assertEqual("blocked", conflict.status)
        self.assertEqual("conflict", conflict.error_class)
        self.assertEqual(["submit"], [call.operation for call in self.runner.calls])

    def test_stale_fence_is_rejected_before_runner(self) -> None:
        harness = self.harness()
        submitted = harness.submit(self.submit_request(fence_token=7))
        assert submitted.handle is not None
        before = len(self.runner.calls)
        stale = harness.observe(
            ObserveRequest(
                job_id="job-fixture",
                attempt_id="attempt-fixture",
                idempotency_key="observe-stale",
                fence_token=6,
                handle=submitted.handle,
            )
        )
        self.assertEqual("blocked", stale.status)
        self.assertEqual("fenced", stale.error_class)
        self.assertEqual(before, len(self.runner.calls))

    def test_persisted_handle_supports_observe_resume_heartbeat_cancel_collect(self) -> None:
        first_adapter = self.harness()
        submitted = first_adapter.submit(self.submit_request())
        assert submitted.handle is not None
        self.assertEqual("fixture-session-1", submitted.handle.metadata["runner_handle_id"])

        # Reconstruct the adapter around the same durable runner.  No local
        # receipt or fence dictionary is shared with the first adapter.
        adapter = self.harness(runner=self.runner)
        observed = adapter.observe(
            ObserveRequest(
                job_id="job-fixture",
                attempt_id="attempt-fixture",
                idempotency_key="observe-fixture",
                fence_token=7,
                handle=submitted.handle,
            )
        )
        self.assertEqual("running", observed.status)

        resumed = adapter.resume(
            ResumeRequest(
                job_id="job-fixture",
                attempt_id="attempt-fixture",
                idempotency_key="resume-fixture",
                fence_token=8,
                handle=submitted.handle,
            )
        )
        self.assertEqual("running", resumed.status)
        assert resumed.handle is not None
        self.assertEqual(submitted.handle.handle_id, resumed.handle.handle_id)
        self.assertEqual(8, resumed.handle.fence_token)

        heartbeat = adapter.heartbeat(
            HeartbeatRequest(
                job_id="job-fixture",
                attempt_id="attempt-fixture",
                idempotency_key="heartbeat-fixture",
                fence_token=8,
                handle=resumed.handle,
            )
        )
        self.assertEqual("running", heartbeat.status)
        cancelled = adapter.cancel(
            CancelRequest(
                job_id="job-fixture",
                attempt_id="attempt-fixture",
                idempotency_key="cancel-fixture",
                fence_token=8,
                handle=resumed.handle,
                reason="fixture cleanup",
            )
        )
        self.assertEqual("cancelled", cancelled.status)
        collected = adapter.collect(
            CollectRequest(
                job_id="job-fixture",
                attempt_id="attempt-fixture",
                idempotency_key="collect-fixture",
                fence_token=8,
                handle=resumed.handle,
                artifact_references=(ARTIFACT,),
            )
        )
        self.assertEqual("succeeded", collected.status)
        self.assertEqual((ARTIFACT,), collected.artifact_references)
        self.assertEqual(
            ["submit", "observe", "resume", "heartbeat", "cancel", "collect"],
            [call.operation for call in self.runner.calls],
        )

    def test_unknown_auth_or_catalog_evidence_fails_closed(self) -> None:
        cases = (
            (
                Evidence("unknown", reason="fixture auth unknown"),
                Evidence("ready", {"models": [MODEL]}),
                "unknown",
                "unknown",
            ),
            (
                Evidence("ready", {"authenticated": True}),
                Evidence("unknown", reason="fixture catalog unknown"),
                "unknown",
                "unknown",
            ),
            (
                Evidence("ready", {"authenticated": False}),
                Evidence("ready", {"models": [MODEL]}),
                "blocked",
                "authentication",
            ),
        )
        for index, (auth, catalog, expected_status, expected_error) in enumerate(cases):
            with self.subTest(index=index):
                runner = FakeRunner()
                harness = self.harness(auth=auth, catalog=catalog, runner=runner)
                capability = harness.capabilities(CapabilityRequest())
                self.assertEqual(expected_status, capability.status)
                self.assertEqual(expected_error, capability.error_class)
                result = harness.submit(
                    self.submit_request(idempotency_key=f"submit-unknown-{index}")
                )
                self.assertEqual(expected_status, result.status)
                self.assertEqual(expected_error, result.error_class)
                self.assertEqual([], runner.calls)


if __name__ == "__main__":
    unittest.main()
