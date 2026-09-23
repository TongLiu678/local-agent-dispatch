"""Provider-free tests for the WP1 causal provenance ledger slice."""

from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from local_agent_dispatch.domain import events as ev  # noqa: E402
from local_agent_dispatch.ledger.store import (  # noqa: E402
    DuplicateConflictError,
    EventStore,
    LivenessReconciler,
    OrphanEventError,
    SecretLeakError,
)
from local_agent_dispatch.ledger.projections import (  # noqa: E402
    attempt_status,
    attempt_summary,
    has_secret_keys,
    project_public,
    redact_event,
)
from research.replay import import_legacy_runs as legacy  # noqa: E402
from research.replay import materialize_observations as mat  # noqa: E402

SCHEMA = ROOT / "schemas" / "provenance_event.schema.json"


def attempt_chain(store: EventStore, attempt_id: str, *, model_id: str | None = None) -> None:
    """Append a fully closed, causally linked fake E2E attempt chain."""
    base = {
        "source": "adapter:opencode",
        "confidence": 1.0,
        "attempt_id": attempt_id,
        "task_id": ev.stable_id("task", "demo-task"),
        "mission_id": ev.stable_id("mission", "demo-mission"),
        "policy_version_id": ev.stable_id("policy_version", "policy-2026-08"),
        "provider": "opencode.go",
        "pool_id": "opencode.go",
        "model_id": model_id,
        "model_variant": "max",
        "cps_digest": ev.digest("cps-bundle-v1"),
        "execution_host": "localhost",
        "workload_host": "localhost",
        "mount": "/workspace",
        "route": "local-cli",
        "validator": "sha256-validator",
        "worktree_digest": ev.digest("worktree-state"),
    }
    steps: list[tuple[str, dict[str, object]]] = [
        ("attempt.queued", {}),
        ("attempt.reserved", {"reservation_id": ev.stable_id("reservation", attempt_id)}),
        ("attempt.claimed", {}),
        ("attempt.started", {}),
        ("attempt.heartbeat", {"pid": "4242"}),
        ("artifact.observed", {"artifact_id": ev.stable_id("artifact", attempt_id, "out"), "artifact_digest": ev.digest("artifact-body")}),
        ("attempt.validation", {"outcome": "passed"}),
        ("attempt.completed", {}),
    ]
    parent: str | None = None
    for index, (event_type, extra) in enumerate(steps):
        event = ev.new_event(
            event_type=event_type,
            source=base["source"],
            idempotency_key=ev.stable_id("event", attempt_id, str(index), event_type),
            causal_parent=parent,
            confidence=base["confidence"],
            timestamp=f"2026-08-12T0{index + 1}:00:00Z",
            privacy_class="public",
            attempt_id=attempt_id,
            **{k: v for k, v in base.items() if k not in ("source", "confidence", "attempt_id")},
            **extra,
        )
        store.append(event)
        parent = event["event_id"]


def base_event(**overrides) -> dict[str, object]:
    kwargs: dict[str, object] = {
        "event_type": "attempt.queued",
        "source": "test",
        "idempotency_key": "base-event-key",
        "causal_parent": None,
        "confidence": 1.0,
        "timestamp": "2026-08-12T00:00:00Z",
        "attempt_id": "attempt:base",
    }
    kwargs.update(overrides)
    return ev.new_event(**kwargs)


class StableIdTests(unittest.TestCase):
    def test_stable_id_is_deterministic_and_kind_prefixed(self):
        a = ev.stable_id("attempt", "run-1", "try-1")
        b = ev.stable_id("attempt", "run-1", "try-1")
        self.assertEqual(a, b)
        self.assertTrue(a.startswith("attempt:"))

    def test_stable_id_covers_all_required_kinds(self):
        for kind in (
            "mission",
            "task",
            "plan_revision",
            "assignment",
            "reservation",
            "attempt",
            "event",
            "observation",
            "artifact",
            "human_decision",
            "policy_version",
        ):
            ident = ev.stable_id(kind, "x")
            self.assertTrue(ident.startswith(f"{kind}:"))

    def test_unknown_kind_fails_closed(self):
        with self.assertRaises(ev.StableIdError):
            ev.stable_id("quota", "x")


class SchemaValidationTests(unittest.TestCase):
    def test_valid_event_passes_validation(self):
        ev.validate_event(base_event())

    def test_missing_required_field_fails(self):
        for field in (
            "schema_version",
            "event_id",
            "event_type",
            "timestamp",
            "causal_parent",
            "source",
            "confidence",
            "privacy_class",
            "idempotency_key",
        ):
            event = base_event()
            del event[field]
            with self.assertRaises(ev.ProvenanceValidationError):
                ev.validate_event(event)

    def test_causal_parent_must_be_present_or_explicit_null(self):
        ev.validate_event(base_event(causal_parent=None))
        ev.validate_event(base_event(causal_parent="event:some-parent"))
        with self.assertRaises(ev.ProvenanceValidationError):
            event = base_event()
            del event["causal_parent"]
            ev.validate_event(event)

    def test_unknown_event_type_rejected(self):
        with self.assertRaises(ev.ProvenanceValidationError):
            ev.validate_event(base_event(event_type="attempt.done"))

    def test_bad_timestamp_and_confidence_rejected(self):
        with self.assertRaises(ev.ProvenanceValidationError):
            ev.validate_event(base_event(timestamp="yesterday"))
        with self.assertRaises(ev.ProvenanceValidationError):
            ev.validate_event(base_event(confidence=1.5))
        with self.assertRaises(ev.ProvenanceValidationError):
            ev.validate_event(base_event(confidence=-0.1))

    def test_digests_and_references_are_typed(self):
        with self.assertRaises(ev.ProvenanceValidationError):
            ev.validate_event(base_event(cps_digest="not-a-digest"))
        with self.assertRaises(ev.ProvenanceValidationError):
            ev.validate_event(base_event(model_id=42))
        ev.validate_event(base_event(cps_digest=ev.digest("ok"), prompt_digest=ev.digest("ok")))

    def test_per_type_requirements(self):
        with self.assertRaises(ev.ProvenanceValidationError):
            ev.validate_event(base_event(event_type="artifact.observed"))
        with self.assertRaises(ev.ProvenanceValidationError):
            ev.validate_event(
                base_event(event_type="attempt.validation", outcome="pending")
            )
        with self.assertRaises(ev.ProvenanceValidationError):
            ev.validate_event(base_event(event_type="attempt.review", decision="maybe"))

    def test_unknown_evidence_quality_preserved_as_unknown_is_valid(self):
        ev.validate_event(base_event(evidence_quality="unknown"))
        with self.assertRaises(ev.ProvenanceValidationError):
            ev.validate_event(base_event(evidence_quality="made_up"))


class SchemaContractTests(unittest.TestCase):
    def test_json_schema_documents_required_fields(self):
        self.assertTrue(SCHEMA.exists())
        doc = json.loads(SCHEMA.read_text(encoding="utf-8"))
        self.assertEqual(2, doc["properties"]["schema_version"]["const"])
        required = set(doc["required"])
        self.assertEqual(
            {
                "schema_version",
                "event_id",
                "event_type",
                "timestamp",
                "causal_parent",
                "source",
                "confidence",
                "privacy_class",
                "idempotency_key",
            },
            required,
        )

    def test_json_schema_lists_all_attempt_event_types(self):
        doc = json.loads(SCHEMA.read_text(encoding="utf-8"))
        types = set(doc["properties"]["event_type"]["enum"])
        self.assertEqual(set(ev.ATTEMPT_EVENT_TYPES), types)
        self.assertIn("attempt.abandoned", types)
        self.assertIn("attempt.review", types)


class StoreIdempotencyTests(unittest.TestCase):
    def test_duplicate_event_id_with_identical_payload_is_idempotent(self):
        store = EventStore()
        event = base_event()
        self.assertEqual("appended", store.append(event))
        self.assertEqual("duplicate", store.append(event))
        self.assertEqual(1, len(store))

    def test_conflicting_duplicate_fails_closed(self):
        store = EventStore()
        store.append(base_event())
        with self.assertRaises(DuplicateConflictError):
            store.append(base_event(model_id="opencode-go/mimo-v2.5"))

    def test_orphan_event_rejected(self):
        store = EventStore()
        with self.assertRaises(OrphanEventError):
            store.append(base_event(causal_parent="event:missing-parent"))

    def test_root_events_allow_explicit_null_parent(self):
        store = EventStore()
        first = base_event()
        second = base_event(
            idempotency_key="second",
            causal_parent=first["event_id"],
            event_type="attempt.completed",
        )
        store.append(first)
        store.append(second)
        self.assertEqual(2, len(store))

    def test_secret_bodies_fail_closed(self):
        store = EventStore()
        with self.assertRaises(SecretLeakError):
            store.append(base_event(prompt_body="top secret prompt"))
        with self.assertRaises(SecretLeakError):
            store.append(base_event(credentials={"api_key": "sk-123"}))


class CausalOrderingTests(unittest.TestCase):
    def test_chain_closes_causally(self):
        store = EventStore()
        attempt_chain(store, "attempt:e2e", model_id="opencode-go/mimo-v2.5")
        ids = store.event_ids()
        for event in store.events():
            parent = event["causal_parent"]
            self.assertTrue(parent is None or parent in ids)
        self.assertEqual(8, len(store))
        self.assertEqual("completed", attempt_status(store, "attempt:e2e"))


class SecretRedactionTests(unittest.TestCase):
    def test_redaction_removes_secret_keys_and_keeps_references(self):
        event = base_event(
            prompt_ref="prompts/run-1.md",
            prompt_digest=ev.digest("prompt-body"),
            prompt_body="the actual prompt text",
            credentials={"api_key": "sk-123"},
            pid="4242",
        )
        redacted = redact_event(event)
        self.assertNotIn("prompt_body", redacted)
        self.assertNotIn("credentials", redacted)
        self.assertNotIn("pid", redacted)
        self.assertEqual("prompts/run-1.md", redacted["prompt_ref"])
        self.assertEqual(ev.digest("prompt-body"), redacted["prompt_digest"])
        self.assertFalse(has_secret_keys(redacted))

    def test_public_projection_never_contains_secrets(self):
        store = EventStore()
        attempt_chain(store, "attempt:secret", model_id="opencode-go/gpt-5.6-luna")
        legacy.import_legacy_json(
            store,
            [{"run_id": "legacy-with-data", "quota_percent": 33, "status": "failed"}],
        )
        heartbeat = ev.new_event(
            event_type="attempt.heartbeat",
            source="test",
            idempotency_key="secret-heartbeat",
            causal_parent=store.event_ids()[-1],
            confidence=1.0,
            attempt_id="attempt:secret",
            pid="4242",
            prompt_ref="prompts/run-1.md",
            prompt_digest=ev.digest("prompt-body"),
        )
        store.append(heartbeat)
        projection = project_public(store)
        self.assertFalse(has_secret_keys(projection))
        serialized = json.dumps(projection)
        self.assertNotIn("4242", serialized)
        self.assertNotIn("prompt-body", serialized)

        with self.assertRaises(SecretLeakError):
            store.append(
                base_event(prompt_body="should never persist", credentials={"api_key": "sk-123"})
            )


class LifecycleProjectionTests(unittest.TestCase):
    def test_summary_redacts_and_preserves_unknown_as_unknown(self):
        store = EventStore()
        attempt_chain(store, "attempt:unknown-model")
        summary = attempt_summary(store, "attempt:unknown-model")
        self.assertEqual("completed", summary["status"])
        self.assertEqual("unknown", summary["model_id"])
        self.assertEqual("unknown", summary["plan_revision_id"])
        self.assertEqual([ev.digest("artifact-body")], summary["artifact_digests"])
        self.assertEqual("unknown", summary["assignment_id"])
        self.assertNotIn("pid", summary)

    def test_summary_exact_attribution(self):
        store = EventStore()
        attempt_chain(store, "attempt:exact", model_id="opencode-go/mimo-v2.5")
        summary = attempt_summary(store, "attempt:exact")
        self.assertEqual("opencode-go/mimo-v2.5", summary["model_id"])
        self.assertEqual("opencode.go", summary["provider"])
        self.assertEqual("max", summary["model_variant"])
        self.assertEqual(ev.digest("cps-bundle-v1"), summary["cps_digest"])
        self.assertIsInstance(summary["duration_seconds"], (int, float))

    def test_projection_is_deterministic(self):
        store_a = EventStore()
        store_b = EventStore()
        attempt_chain(store_a, "attempt:det", model_id="opencode-go/mimo-v2.5")
        attempt_chain(store_b, "attempt:det", model_id="opencode-go/mimo-v2.5")
        self.assertEqual(project_public(store_a), project_public(store_b))

    def test_incomplete_attempt_stays_unknown_not_completed(self):
        store = EventStore()
        attempt_chain(store, "attempt:partial")
        last_id = store.event_ids()[-1]
        partial = ev.new_event(
            event_type="attempt.heartbeat",
            source="adapter:opencode",
            idempotency_key="partial-heartbeat",
            causal_parent=last_id,
            confidence=1.0,
            attempt_id="attempt:partial",
            model_id="opencode-go/mimo-v2.5",
            timestamp="2026-08-12T09:00:00Z",
        )
        store.append(partial)
        summary = attempt_summary(store, "attempt:partial")
        self.assertEqual("started", summary["status"])
        self.assertNotEqual("completed", summary["status"])


class LegacyImportTests(unittest.TestCase):
    def test_legacy_import_labels_evidence_incomplete(self):
        store = EventStore()
        report = legacy.import_legacy_json(
            store,
            [{"run_id": "legacy-1", "model": "gpt-5.6-luna", "status": "completed"}],
        )
        self.assertEqual(1, report["imported"])
        event = store.events()[0]
        self.assertEqual("legacy_incomplete", event["evidence_quality"])
        self.assertEqual("attempt.queued", event["event_type"])
        self.assertEqual("completed", event["legacy_evidence"]["status"])
        self.assertNotIn("status", event)

    def test_legacy_import_never_invents_model_quota_resources(self):
        store = EventStore()
        report = legacy.import_legacy_json(store, [{"run_id": "legacy-2"}])
        event = store.events()[0]
        self.assertNotIn("model_id", event)
        self.assertNotIn("quota", event)
        self.assertNotIn("resources", event)
        self.assertNotIn("model_variant", event)
        self.assertEqual(1, report["gaps"]["missing_model_id"])
        self.assertEqual(1, report["gaps"]["missing_quota"])
        self.assertEqual(1, report["gaps"]["missing_resources"])
        self.assertEqual(1, report["gaps"]["missing_terminal_state"])
        self.assertEqual("queued", attempt_status(store, event["attempt_id"]))

    def test_legacy_import_copies_only_existing_exact_values(self):
        store = EventStore()
        legacy.import_legacy_json(
            store,
            [{
                "run_id": "legacy-3",
                "model_id": "opencode-go/mimo-v2.5",
                "pool_id": "opencode.go",
                "quota_percent": 42,
                "resources": {"ram_gb": 64},
            }],
        )
        event = store.events()[0]
        self.assertEqual("opencode-go/mimo-v2.5", event["model_id"])
        self.assertEqual("opencode.go", event["pool_id"])
        self.assertEqual(42, event["legacy_evidence"]["quota_percent"])
        self.assertEqual({"ram_gb": 64}, event["legacy_evidence"]["resources"])

    def test_legacy_reimport_is_idempotent(self):
        store = EventStore()
        records = [{"run_id": "legacy-4", "model": "gpt-5.6-luna"}]
        first = legacy.import_legacy_json(store, records)
        second = legacy.import_legacy_json(store, records)
        self.assertEqual(1, first["imported"])
        self.assertEqual(1, second["duplicates"])
        self.assertEqual(1, len(store))

    def test_legacy_import_file_surface(self):
        store = EventStore()
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "legacy-runs.json"
            path.write_text(
                json.dumps({"runs": [{"id": "file-run", "status": "failed"}]}),
                encoding="utf-8",
            )
            report = legacy.import_legacy_file(store, path)
        self.assertEqual(1, report["imported"])
        event = store.events()[0]
        self.assertTrue(event["source"].startswith("legacy_import"))
        self.assertEqual("failed", event["legacy_evidence"]["status"])

    def test_legacy_projection_shows_unknown_model_and_no_terminal_state(self):
        store = EventStore()
        legacy.import_legacy_json(store, [{"run_id": "legacy-5"}])
        summary = attempt_summary(store, store.attempt_ids()[0])
        self.assertEqual("unknown", summary["model_id"])
        self.assertEqual("queued", summary["status"])
        self.assertEqual("legacy_incomplete", summary["evidence_quality"])


class LivenessReconcilerTests(unittest.TestCase):
    def make_stale_attempt(self, store: EventStore, attempt_id: str, pid: str | None = None) -> None:
        parent: str | None = None
        for index, (event_type, extra) in enumerate(
            [
                ("attempt.queued", {}),
                ("attempt.claimed", {}),
                ("attempt.started", {}),
                ("attempt.heartbeat", {}),
            ]
        ):
            payload = {"model_id": "opencode-go/mimo-v2.5", "task_id": ev.stable_id("task", attempt_id)}
            if pid is not None:
                payload["pid"] = pid
            event = ev.new_event(
                event_type=event_type,
                source="adapter:opencode",
                idempotency_key=ev.stable_id("event", attempt_id, str(index), event_type),
                causal_parent=parent,
                confidence=1.0,
                timestamp=f"2026-08-12T00:0{index}:00Z",
                privacy_class="public",
                attempt_id=attempt_id,
                **payload,
                **extra,
            )
            store.append(event)
            parent = event["event_id"]

    def test_dead_pid_becomes_explicit_abandoned(self):
        store = EventStore()
        self.make_stale_attempt(store, "attempt:dead", pid="9001")
        original = store.events()
        reconciler = LivenessReconciler(
            store, stale_after_seconds=60, now="2026-08-12T05:00:00Z"
        )
        created = reconciler.reconcile({"9001": False})
        self.assertEqual(1, len(created))
        abandoned = created[0]
        self.assertEqual("attempt.abandoned", abandoned["event_type"])
        self.assertEqual("stale_dead_pid", abandoned["reason"])
        self.assertTrue(abandoned["preserves_evidence"])
        self.assertEqual(store.events()[:-1], original)

    def test_unknown_pid_fails_closed_to_review(self):
        store = EventStore()
        self.make_stale_attempt(store, "attempt:ghost", pid="9002")
        reconciler = LivenessReconciler(
            store, stale_after_seconds=60, now="2026-08-12T05:00:00Z"
        )
        created = reconciler.reconcile({})
        self.assertEqual(1, len(created))
        self.assertEqual("attempt.review", created[0]["event_type"])
        self.assertEqual("stale_unconfirmed_pid", created[0]["reason"])
        self.assertEqual("review", attempt_status(store, "attempt:ghost"))

    def test_live_or_fresh_attempts_are_not_reconciled(self):
        store = EventStore()
        self.make_stale_attempt(store, "attempt:alive", pid="9003")
        reconciler = LivenessReconciler(
            store, stale_after_seconds=60, now="2026-08-12T05:00:00Z"
        )
        self.assertEqual([], reconciler.reconcile({"9003": True}))
        self.assertEqual(4, len(store))

        fresh = EventStore()
        self.make_stale_attempt(fresh, "attempt:fresh", pid="9004")
        fresh_reconciler = LivenessReconciler(
            fresh, stale_after_seconds=60, now="2026-08-12T00:03:00Z"
        )
        self.assertEqual([], fresh_reconciler.reconcile({"9004": False}))
        self.assertEqual(4, len(fresh))

    def test_completed_attempts_are_never_touched(self):
        store = EventStore()
        attempt_chain(store, "attempt:done", model_id="opencode-go/mimo-v2.5")
        reconciler = LivenessReconciler(
            store, stale_after_seconds=0, now="2026-08-12T23:00:00Z"
        )
        self.assertEqual([], reconciler.reconcile({}))

    def test_reconciled_legacy_attempt_keeps_legacy_evidence_quality(self):
        store = EventStore()
        legacy.import_legacy_json(store, [{"run_id": "legacy-stale", "pid": "7777"}])
        attempt_id = store.attempt_ids()[0]
        event = store.events()[0]
        heartbeat = ev.new_event(
            event_type="attempt.heartbeat",
            source="adapter:opencode",
            idempotency_key="legacy-stale-heartbeat",
            causal_parent=event["event_id"],
            confidence=1.0,
            timestamp="2026-08-12T00:00:01Z",
            attempt_id=attempt_id,
            pid="7777",
            evidence_quality="legacy_incomplete",
        )
        store.append(heartbeat)
        reconciler = LivenessReconciler(
            store, stale_after_seconds=60, now="2026-08-12T05:00:00Z"
        )
        created = reconciler.reconcile({"7777": False})
        self.assertEqual(1, len(created))
        self.assertEqual("legacy_incomplete", created[0]["evidence_quality"])
        self.assertEqual("attempt.abandoned", created[0]["event_type"])


class MaterializeObservationsTests(unittest.TestCase):
    def test_only_completed_validated_attributed_attempts_materialize(self):
        store = EventStore()
        attempt_chain(store, "attempt:good", model_id="opencode-go/mimo-v2.5")
        legacy.import_legacy_json(store, [{"run_id": "legacy-good"}])

        incomplete = EventStore()
        attempt_chain(incomplete, "attempt:good")
        legacy.import_legacy_json(incomplete, [{"run_id": "legacy-good"}])

        result = mat.materialize_estimator_observations(store)
        self.assertEqual(1, result["observation_count"])
        observation = result["observations"][0]
        self.assertEqual("attempt:good", observation["attempt_id"])
        self.assertEqual("opencode-go/mimo-v2.5", observation["model_id"])
        self.assertEqual("passed", observation["validation_outcome"])
        self.assertEqual(1, result["excluded_count"])
        excluded = result["excluded"][0]
        self.assertIn("legacy_incomplete", excluded["reason"])

        self.assertEqual(0, mat.materialize_estimator_observations(incomplete)["observation_count"])

    def test_unvalidated_and_failed_validation_excluded(self):
        store = EventStore()
        attempt_chain(store, "attempt:good", model_id="opencode-go/mimo-v2.5")
        last = store.events()[-1]
        bad_validation = ev.new_event(
            event_type="attempt.validation",
            source="validator",
            idempotency_key="bad-validation",
            causal_parent=last["event_id"],
            confidence=1.0,
            attempt_id="attempt:good",
            outcome="failed",
        )
        store.append(bad_validation)
        result = mat.materialize_estimator_observations(store)
        self.assertEqual(0, result["observation_count"])
        self.assertIn("validation_failed", result["excluded"][0]["reason"])

    def test_missing_attribution_excluded_not_guessed(self):
        store = EventStore()
        attempt_chain(store, "attempt:no-model")
        result = mat.materialize_estimator_observations(store)
        self.assertEqual(0, result["observation_count"])
        excluded = result["excluded"][0]
        self.assertIn("missing_model_id", excluded["reason"])


class PersistenceTests(unittest.TestCase):
    def test_jsonl_roundtrip_preserves_order_and_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "events.jsonl"
            store = EventStore(path=path)
            attempt_chain(store, "attempt:persist", model_id="opencode-go/mimo-v2.5")
            self.assertEqual(8, len(store))

            reloaded = EventStore.load_jsonl(path)
            self.assertEqual(store.events(), reloaded.events())
            self.assertEqual(store.event_ids(), reloaded.event_ids())
            self.assertEqual(
                project_public(store), project_public(reloaded)
            )

    def test_conflicting_duplicate_in_loaded_file_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "events.jsonl"
            store = EventStore(path=path)
            attempt_chain(store, "attempt:persist", model_id="opencode-go/mimo-v2.5")
            with path.open("a", encoding="utf-8") as handle:
                handle.write(
                    json.dumps(
                        {
                            "schema_version": 2,
                            "event_id": store.event_ids()[0],
                            "event_type": "attempt.queued",
                            "timestamp": "2026-08-12T00:00:00Z",
                            "causal_parent": None,
                            "source": "tampered",
                            "confidence": 1.0,
                            "privacy_class": "public",
                            "idempotency_key": "tampered",
                            "attempt_id": "attempt:tampered",
                        }
                    )
                    + "\n"
                )
            with self.assertRaises(DuplicateConflictError):
                EventStore.load_jsonl(path)


if __name__ == "__main__":
    unittest.main()
