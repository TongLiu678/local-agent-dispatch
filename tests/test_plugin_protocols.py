"""Provider-free conformance tests for the package plugin boundary."""

from __future__ import annotations

import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from local_agent_dispatch.plugins import (  # noqa: E402
    PLUGIN_API_VERSION,
    PROTOCOL_METHODS,
    AgentHarness,
    ArtifactReference,
    ArtifactStore,
    BatchScheduler,
    CancelRequest,
    CancelResult,
    CapabilityRequest,
    CapabilityResult,
    CollectRequest,
    CollectResult,
    DiscoveryRequest,
    Evidence,
    ExecutionHandle,
    ExecutionRequest,
    ExecutionResult,
    HeartbeatRequest,
    HeartbeatResult,
    ObserveRequest,
    ObserveResult,
    PluginDescriptor,
    PluginRegistry,
    PluginRegistryError,
    PrepareRequest,
    PrepareResult,
    ProbeRequest,
    ProviderAdapter,
    ResumeRequest,
    ResumeResult,
    RuntimeAdapter,
    SubmitRequest,
    SubmitResult,
    SystemProbe,
    TransportAdapter,
    TransportRequest,
    ValidationRequest,
    ValidationResult,
    Validator,
    conformance_report,
)


class FakeSystemProbe:
    descriptor = PluginDescriptor(
        "fake-system",
        "system_probe",
        capabilities=("os", "cpu"),
    )

    def __init__(self) -> None:
        self.calls = 0

    def probe(self, request: ProbeRequest) -> Evidence:
        self.calls += 1
        return Evidence("ready", {"os": "fake"}, source="fixture")


class FakeProvider:
    descriptor = PluginDescriptor("fake-provider", "provider", capabilities=("catalog", "quota"))

    def discover_catalog(self, request: DiscoveryRequest) -> Evidence:
        return Evidence("ready", {"models": ["fake-model"]}, source="fixture")

    def discover_auth_state(self, request: DiscoveryRequest) -> Evidence:
        return Evidence("ready", {"configured": True}, source="fixture")

    def discover_quota(self, request: DiscoveryRequest) -> Evidence:
        return Evidence("unknown", reason="fixture does not model quota")

    def probe_runtime(self, request: DiscoveryRequest) -> Evidence:
        return Evidence("ready", {"runtime": "fake"}, source="fixture")

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        return ExecutionResult("ready", output="fake result")


class FakeRuntime:
    descriptor = PluginDescriptor("fake-runtime", "runtime", capabilities=("openai_compatible",))

    def probe(self, request: DiscoveryRequest) -> Evidence:
        return Evidence("ready", {"endpoint": "fixture"})

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        return ExecutionResult("ready", output="fixture")


class FakeTransport:
    descriptor = PluginDescriptor("fake-transport", "transport")

    def prepare(self, request: TransportRequest) -> Evidence:
        return Evidence("ready", {"prepared": True})

    def execute(self, request: TransportRequest) -> Evidence:
        return Evidence("ready", {"transferred": True})


class FakeValidator:
    descriptor = PluginDescriptor("fake-validator", "validator")

    def validate(self, request: ValidationRequest) -> ValidationResult:
        return ValidationResult("ready", passed=True, data={"fresh": True})


class CrashingProvider:
    descriptor = PluginDescriptor("crashing-provider", "provider")

    def discover_catalog(self, request: DiscoveryRequest) -> Evidence:
        raise RuntimeError("fixture provider failed")

    def discover_auth_state(self, request: DiscoveryRequest) -> Evidence:
        return Evidence("unknown")

    def discover_quota(self, request: DiscoveryRequest) -> Evidence:
        return Evidence("unknown")

    def probe_runtime(self, request: DiscoveryRequest) -> Evidence:
        return Evidence("unknown")

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        return ExecutionResult("error", reason="fixture")


class IncompletePlugin:
    descriptor = PluginDescriptor("incomplete", "provider")

    def discover_catalog(self, request: DiscoveryRequest) -> Evidence:
        return Evidence("unknown")


ARTIFACT = ArtifactReference(
    "artifact://fixture/result.json",
    role="result",
    digest="sha256:" + "0" * 64,
    media_type="application/json",
)


def execution_handle(plugin_id: str, *, fence_token: int = 7) -> ExecutionHandle:
    return ExecutionHandle(
        handle_id=f"{plugin_id}-handle",
        plugin_id=plugin_id,
        job_id="job-1",
        attempt_id="attempt-1",
        idempotency_key="submit-job-1-attempt-1",
        fence_token=fence_token,
    )


class FakeSchedulingLifecycle:
    """In-memory fixture whose operations are safe but observable in tests."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def capabilities(self, request: CapabilityRequest) -> CapabilityResult:
        self.calls.append("capabilities")
        return CapabilityResult(
            status="ready",
            capabilities=("submit", "resume"),
            source="fixture",
            error_class="none",
        )

    def prepare(self, request: PrepareRequest) -> PrepareResult:
        self.calls.append("prepare")
        return PrepareResult(
            status="ready",
            preparation_id="prepared-1",
            artifact_references=request.artifact_references,
            error_class="none",
        )

    def submit(self, request: SubmitRequest) -> SubmitResult:
        self.calls.append("submit")
        return SubmitResult(
            status="accepted",
            handle=execution_handle(self.descriptor.plugin_id, fence_token=int(request.fence_token)),
            artifact_references=request.artifact_references,
            error_class="none",
        )

    def observe(self, request: ObserveRequest) -> ObserveResult:
        self.calls.append("observe")
        return ObserveResult(status="running", handle=request.handle, error_class="none")

    def heartbeat(self, request: HeartbeatRequest) -> HeartbeatResult:
        self.calls.append("heartbeat")
        return HeartbeatResult(status="running", handle=request.handle, error_class="none")

    def cancel(self, request: CancelRequest) -> CancelResult:
        self.calls.append("cancel")
        return CancelResult(status="cancelled", handle=request.handle, error_class="cancelled")

    def collect(self, request: CollectRequest) -> CollectResult:
        self.calls.append("collect")
        return CollectResult(
            status="succeeded",
            handle=request.handle,
            artifact_references=(ARTIFACT,),
            error_class="none",
        )

    def resume(self, request: ResumeRequest) -> ResumeResult:
        self.calls.append("resume")
        return ResumeResult(status="running", handle=request.handle, error_class="none")


class FakeAgentHarness(FakeSchedulingLifecycle):
    descriptor = PluginDescriptor(
        "fake-harness",
        "agent_harness",
        capabilities=("submit", "resume"),
    )


class FakeBatchScheduler(FakeSchedulingLifecycle):
    descriptor = PluginDescriptor(
        "fake-scheduler",
        "batch_scheduler",
        capabilities=("submit", "cancel"),
    )


class FakeArtifactStore:
    descriptor = PluginDescriptor(
        "fake-artifacts",
        "artifact_store",
        capabilities=("prepare", "collect"),
    )

    def __init__(self) -> None:
        self.calls: list[str] = []

    def capabilities(self, request: CapabilityRequest) -> CapabilityResult:
        self.calls.append("capabilities")
        return CapabilityResult(
            status="ready",
            capabilities=("prepare", "collect"),
            error_class="none",
        )

    def prepare(self, request: PrepareRequest) -> PrepareResult:
        self.calls.append("prepare")
        return PrepareResult(
            status="ready",
            preparation_id="artifact-reservation-1",
            artifact_references=request.artifact_references,
            error_class="none",
        )

    def collect(self, request: CollectRequest) -> CollectResult:
        self.calls.append("collect")
        return CollectResult(
            status="succeeded",
            handle=request.handle,
            artifact_references=(ARTIFACT,),
            error_class="none",
        )


class IncompleteHarness(FakeSchedulingLifecycle):
    descriptor = PluginDescriptor("incomplete-harness", "agent_harness")
    resume = None


class PluginProtocolTests(unittest.TestCase):
    def test_legacy_v1_protocols_and_method_sets_are_unchanged(self) -> None:
        self.assertEqual("1", PLUGIN_API_VERSION)
        self.assertIsInstance(FakeSystemProbe(), SystemProbe)
        self.assertIsInstance(FakeProvider(), ProviderAdapter)
        self.assertIsInstance(FakeRuntime(), RuntimeAdapter)
        self.assertIsInstance(FakeTransport(), TransportAdapter)
        self.assertIsInstance(FakeValidator(), Validator)
        self.assertEqual(("probe",), PROTOCOL_METHODS["system_probe"])
        self.assertEqual(
            (
                "discover_catalog",
                "discover_auth_state",
                "discover_quota",
                "probe_runtime",
                "execute",
            ),
            PROTOCOL_METHODS["provider"],
        )
        self.assertEqual(("probe", "execute"), PROTOCOL_METHODS["runtime"])
        self.assertEqual(("prepare", "execute"), PROTOCOL_METHODS["transport"])
        self.assertEqual(("validate",), PROTOCOL_METHODS["validator"])

    def test_public_scheduling_protocols_have_provider_free_fakes(self) -> None:
        self.assertIsInstance(FakeAgentHarness(), AgentHarness)
        self.assertIsInstance(FakeBatchScheduler(), BatchScheduler)
        self.assertIsInstance(FakeArtifactStore(), ArtifactStore)
        self.assertEqual(
            (
                "capabilities",
                "prepare",
                "submit",
                "observe",
                "heartbeat",
                "cancel",
                "collect",
                "resume",
            ),
            PROTOCOL_METHODS["agent_harness"],
        )
        self.assertEqual(
            PROTOCOL_METHODS["agent_harness"],
            PROTOCOL_METHODS["batch_scheduler"],
        )
        self.assertEqual(
            ("capabilities", "prepare", "collect"),
            PROTOCOL_METHODS["artifact_store"],
        )

    def test_conformance_requires_only_static_metadata_and_methods(self) -> None:
        plugin = FakeSystemProbe()
        report = conformance_report(plugin)
        self.assertTrue(report.ok)
        self.assertEqual(("probe",), report.methods)
        self.assertEqual(0, plugin.calls)

    def test_registration_does_not_invoke_provider_operations(self) -> None:
        registry = PluginRegistry()
        provider = FakeProvider()
        registry.register(provider)
        self.assertEqual(("fake-provider",), tuple(item.plugin_id for item in registry.descriptors(kind="provider")))

    def test_registration_of_new_kinds_is_static_and_invokes_nothing(self) -> None:
        registry = PluginRegistry()
        plugins = (FakeAgentHarness(), FakeBatchScheduler(), FakeArtifactStore())
        reports = registry.register_many(plugins)
        self.assertTrue(all(report.ok for report in reports))
        self.assertEqual(([], [], []), tuple(plugin.calls for plugin in plugins))
        self.assertEqual(
            {"fake-harness", "fake-scheduler", "fake-artifacts"},
            {descriptor.plugin_id for descriptor in registry.descriptors()},
        )

    def test_conformance_does_not_evaluate_dynamic_descriptor_property(self) -> None:
        class DynamicDescriptor:
            @property
            def descriptor(self) -> PluginDescriptor:
                raise AssertionError("static conformance must not evaluate plugin properties")

            def probe(self, request: ProbeRequest) -> Evidence:
                return Evidence("unknown")

        report = conformance_report(DynamicDescriptor())
        self.assertFalse(report.ok)
        self.assertIn("missing_descriptor", {issue.code for issue in report.issues})

    def test_registry_scopes_duplicate_ids_by_kind_and_rejects_same_kind(self) -> None:
        registry = PluginRegistry()
        registry.register(FakeSystemProbe())
        # The same textual id is valid in another kind because the key is scoped.
        same_id_runtime = FakeRuntime()
        object.__setattr__(same_id_runtime, "descriptor", PluginDescriptor("fake-system", "runtime"))
        registry.register(same_id_runtime)
        with self.assertRaises(PluginRegistryError):
            registry.register(FakeSystemProbe())

    def test_incomplete_plugin_report_is_actionable(self) -> None:
        report = conformance_report(IncompletePlugin())
        self.assertFalse(report.ok)
        self.assertIn("missing_method", {issue.code for issue in report.issues})
        with self.assertRaises(PluginRegistryError):
            PluginRegistry().register(IncompletePlugin())

        harness_report = conformance_report(IncompleteHarness())
        self.assertFalse(harness_report.ok)
        self.assertIn("missing_method", {issue.code for issue in harness_report.issues})
        self.assertNotIn("resume", harness_report.methods)

    def test_register_many_isolates_bad_plugin(self) -> None:
        registry = PluginRegistry()
        reports = registry.register_many([FakeProvider(), IncompletePlugin(), FakeValidator()])
        self.assertEqual((True, False, True), tuple(report.ok for report in reports))
        self.assertEqual(
            {"fake-provider", "fake-validator"},
            {item.plugin_id for item in registry.descriptors()},
        )

    def test_invoke_converts_one_plugin_crash_to_local_failure(self) -> None:
        registry = PluginRegistry()
        registry.register(CrashingProvider())
        result = registry.invoke(
            "provider",
            "crashing-provider",
            "discover_catalog",
            DiscoveryRequest(),
        )
        self.assertFalse(result.ok)
        self.assertIn("RuntimeError", result.error or "")

        class ProviderWithSecretError(CrashingProvider):
            descriptor = PluginDescriptor("secret-provider", "provider")

            def discover_catalog(self, request: DiscoveryRequest) -> Evidence:
                raise RuntimeError("authorization: Bearer synthetic")

        registry.register(ProviderWithSecretError())
        redacted = registry.invoke(
            "provider", "secret-provider", "discover_catalog", DiscoveryRequest()
        )
        self.assertNotIn("synthetic", redacted.error or "")
        self.assertIn("<redacted>", redacted.error or "")

    def test_invoke_rejects_operations_outside_kind_contract(self) -> None:
        class ExtraProbe(FakeSystemProbe):
            def private_helper(self, request: ProbeRequest) -> Evidence:
                return Evidence("ready")

        registry = PluginRegistry()
        registry.register(ExtraProbe())
        with self.assertRaises(PluginRegistryError):
            registry.invoke("system_probe", "fake-system", "private_helper", ProbeRequest())

    def test_invalid_descriptor_is_rejected_without_provider_contact(self) -> None:
        class BadId:
            descriptor = PluginDescriptor("../escape", "system_probe")

            def probe(self, request: ProbeRequest) -> Evidence:
                raise AssertionError("must not be called during conformance")

        report = conformance_report(BadId())
        self.assertFalse(report.ok)
        self.assertIn("invalid_plugin_id", {issue.code for issue in report.issues})

    def test_evidence_unknown_is_not_ready(self) -> None:
        quota = FakeProvider().discover_quota(DiscoveryRequest())
        self.assertEqual("unknown", quota.status)
        self.assertNotEqual("ready", quota.status)

    def test_lifecycle_requests_require_version_idempotency_and_fencing(self) -> None:
        request = PrepareRequest(
            job_id="job-1",
            attempt_id="attempt-1",
            idempotency_key="prepare-job-1-attempt-1",
            fence_token=7,
            artifact_references=(ARTIFACT,),
        )
        self.assertEqual((ARTIFACT,), request.artifact_references)

        with self.assertRaises(ValueError):
            PrepareRequest(
                job_id="job-1",
                attempt_id="attempt-1",
                idempotency_key="",
                fence_token=7,
            )
        with self.assertRaises(ValueError):
            PrepareRequest(
                job_id="job-1",
                attempt_id="attempt-1",
                idempotency_key="prepare-1",
                fence_token=-1,
            )
        with self.assertRaises(ValueError):
            PrepareRequest(
                job_id="job-1",
                attempt_id="attempt-1",
                idempotency_key="prepare-1",
                fence_token=7,
                schema_version="future-version",
            )

    def test_submit_handle_and_reattach_request_keep_durable_identity(self) -> None:
        harness = FakeAgentHarness()
        submitted = harness.submit(
            SubmitRequest(
                job_id="job-1",
                attempt_id="attempt-1",
                idempotency_key="submit-job-1-attempt-1",
                fence_token=7,
                preparation_id="prepared-1",
                artifact_references=(ARTIFACT,),
            )
        )
        self.assertEqual("accepted", submitted.status)
        self.assertIsNotNone(submitted.handle)
        assert submitted.handle is not None
        resumed = harness.resume(
            ResumeRequest(
                job_id="job-1",
                attempt_id="attempt-1",
                idempotency_key="resume-job-1-attempt-1",
                fence_token=8,
                handle=submitted.handle,
                checkpoint_reference=ARTIFACT,
            )
        )
        self.assertEqual("running", resumed.status)
        self.assertEqual(submitted.handle.handle_id, resumed.handle.handle_id if resumed.handle else None)

        with self.assertRaises(ValueError):
            ObserveRequest(
                job_id="different-job",
                attempt_id="attempt-1",
                idempotency_key="observe-1",
                fence_token=8,
                handle=submitted.handle,
            )

    def test_lifecycle_results_require_classified_failures_and_artifact_references(self) -> None:
        failed = CollectResult(
            status="error",
            error_class="transport",
            reason="fixture transfer failed",
            artifact_references=(ARTIFACT,),
        )
        self.assertEqual("transport", failed.error_class)
        self.assertEqual((ARTIFACT,), failed.artifact_references)

        with self.assertRaises(ValueError):
            CollectResult(status="error", error_class="none")
        with self.assertRaises(ValueError):
            CollectResult(status="succeeded", error_class="transport")
        with self.assertRaises(TypeError):
            CollectResult(
                status="succeeded",
                error_class="none",
                artifact_references=("not-a-reference",),
            )

    def test_registry_can_explicitly_invoke_new_operation_after_registration(self) -> None:
        registry = PluginRegistry()
        harness = FakeAgentHarness()
        registry.register(harness)
        result = registry.invoke(
            "agent_harness",
            "fake-harness",
            "capabilities",
            CapabilityRequest(scope="fixture"),
        )
        self.assertTrue(result.ok)
        self.assertEqual(["capabilities"], harness.calls)
        self.assertIsInstance(result.value, CapabilityResult)


if __name__ == "__main__":
    unittest.main()
