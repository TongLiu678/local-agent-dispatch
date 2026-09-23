from __future__ import annotations

import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from local_agent_dispatch.domain import events as ev  # noqa: E402
from local_agent_dispatch.ledger.projections import (  # noqa: E402
    attempt_status,
    attempt_summary,
    lifecycle_truth,
)
from local_agent_dispatch.ledger.store import EventStore, ProvenanceStoreError  # noqa: E402
from research.replay.materialize_observations import (  # noqa: E402
    materialize_estimator_observations,
)


def _append(store: EventStore, event_type: str, parent: str | None, **payload: object) -> dict:
    event = ev.new_event(
        event_type=event_type,
        source="test:lifecycle",
        idempotency_key=f"lifecycle:{len(store)}:{event_type}",
        causal_parent=parent,
        confidence=1.0,
        timestamp=f"2026-08-13T00:{len(store):02d}:00Z",
        privacy_class="public",
        attempt_id="attempt:lifecycle",
        task_id=ev.stable_id("task", "lifecycle"),
        mission_id=ev.stable_id("mission", "lifecycle"),
        provider="opencode.go",
        pool_id="opencode.go",
        model_id="opencode-go/deepseek-v4-flash",
        model_variant="max",
        **payload,
    )
    store.append(event)
    return event


def _completed_store(*, with_validation: bool = True, validation_outcome: str = "passed") -> EventStore:
    store = EventStore()
    parent = None
    steps: list[tuple[str, dict[str, object]]] = [
        ("attempt.queued", {}),
        ("attempt.started", {}),
        (
            "artifact.observed",
            {
                "artifact_id": ev.stable_id("artifact", "lifecycle"),
                "artifact_digest": ev.digest("artifact"),
            },
        ),
    ]
    if with_validation:
        steps.append(("attempt.validation", {"outcome": validation_outcome}))
    steps.append(("attempt.completed", {}))
    for event_type, payload in steps:
        parent = _append(store, event_type, parent, **payload)["event_id"]
    return store


class ClaimLifecycleTests(unittest.TestCase):
    def test_promotion_requires_explicit_contract_fields(self) -> None:
        with self.assertRaises(ev.ProvenanceValidationError):
            ev.validate_event(
                ev.new_event(
                    event_type="claim.promoted",
                    source="test",
                    idempotency_key="missing-contract",
                    causal_parent=None,
                    confidence=1.0,
                    timestamp="2026-08-13T00:00:00Z",
                    attempt_id="attempt:lifecycle",
                )
            )

    def test_store_rejects_promotion_without_approved_review(self) -> None:
        store = _completed_store()
        parent = store.events()[-1]["event_id"]
        promotion = ev.new_event(
            event_type="claim.promoted",
            source="test:lifecycle",
            idempotency_key="promotion-without-review",
            causal_parent=parent,
            confidence=1.0,
            timestamp="2026-08-13T01:00:00Z",
            privacy_class="public",
            attempt_id="attempt:lifecycle",
            claim_id=ev.stable_id("claim", "lifecycle"),
            claim_contract_digest=ev.digest("claim-contract-v1"),
            review_event_id=parent,
            decision="approve",
        )
        with self.assertRaises(ProvenanceStoreError):
            store.append(promotion)

    def test_completion_validation_review_then_promotion_is_distinct(self) -> None:
        store = _completed_store()
        review = _append(
            store,
            "attempt.review",
            store.events()[-1]["event_id"],
            decision="approve",
        )
        promotion = ev.new_event(
            event_type="claim.promoted",
            source="test:lifecycle",
            idempotency_key="valid-promotion",
            causal_parent=review["event_id"],
            confidence=1.0,
            timestamp="2026-08-13T01:00:00Z",
            privacy_class="public",
            attempt_id="attempt:lifecycle",
            claim_id=ev.stable_id("claim", "lifecycle"),
            claim_contract_digest=ev.digest("claim-contract-v1"),
            review_event_id=review["event_id"],
            decision="approve",
        )
        store.append(promotion)
        summary = attempt_summary(store, "attempt:lifecycle")
        self.assertEqual("claim_promoted", attempt_status(store, "attempt:lifecycle"))
        self.assertEqual("promoted", summary["claim_status"])
        self.assertEqual("passed", summary["validation_outcome"])
        self.assertEqual(
            {
                "planned": True,
                "executed": True,
                "completed": True,
                "validated": True,
                "reviewed": True,
                "review_decision": "approve",
                "claim_promoted": True,
            },
            summary["lifecycle"],
        )

    def test_completed_with_validation_failed_is_not_validated_or_promoted(self) -> None:
        store = _completed_store(with_validation=True, validation_outcome="failed")
        truth = lifecycle_truth(store, "attempt:lifecycle")
        self.assertTrue(truth["completed"])
        self.assertTrue(truth["executed"])
        self.assertFalse(truth["validated"])
        self.assertFalse(truth["reviewed"])
        self.assertFalse(truth["claim_promoted"])

    def test_promotion_requires_validation_and_review(self) -> None:
        store = _completed_store(with_validation=False)
        review = _append(
            store,
            "attempt.review",
            store.events()[-1]["event_id"],
            decision="approve",
        )
        promotion = ev.new_event(
            event_type="claim.promoted",
            source="test:lifecycle",
            idempotency_key="promotion-without-validation",
            causal_parent=review["event_id"],
            confidence=1.0,
            timestamp="2026-08-13T01:00:00Z",
            privacy_class="public",
            attempt_id="attempt:lifecycle",
            claim_id=ev.stable_id("claim", "lifecycle"),
            claim_contract_digest=ev.digest("claim-contract-v1"),
            review_event_id=review["event_id"],
            decision="approve",
        )
        with self.assertRaises(ProvenanceStoreError):
            store.append(promotion)

    def test_materializer_can_require_claim_promotion(self) -> None:
        store = _completed_store()
        report = materialize_estimator_observations(
            store, require_claim_promotion=True
        )
        self.assertEqual(0, report["observation_count"])
        self.assertIn("claim_not_promoted", report["excluded"][0]["reason"])

    def test_later_non_approving_review_blocks_old_approval(self) -> None:
        store = _completed_store()
        first = _append(
            store,
            "attempt.review",
            store.events()[-1]["event_id"],
            decision="approve",
        )
        second = _append(
            store,
            "attempt.review",
            first["event_id"],
            decision="escalate",
        )
        promotion = ev.new_event(
            event_type="claim.promoted",
            source="test:lifecycle",
            idempotency_key="promotion-after-escalation",
            causal_parent=first["event_id"],
            confidence=1.0,
            timestamp="2026-08-13T01:00:00Z",
            privacy_class="public",
            attempt_id="attempt:lifecycle",
            claim_id=ev.stable_id("claim", "lifecycle"),
            claim_contract_digest=ev.digest("claim-contract-v1"),
            review_event_id=first["event_id"],
            decision="approve",
        )
        with self.assertRaises(ProvenanceStoreError):
            store.append(promotion)
        self.assertEqual("review", attempt_status(store, "attempt:lifecycle"))
        self.assertEqual(second["event_id"], store.events()[-1]["event_id"])

    def test_repeated_idempotent_promotion_does_not_duplicate(self) -> None:
        store = _completed_store()
        review = _append(
            store,
            "attempt.review",
            store.events()[-1]["event_id"],
            decision="approve",
        )
        promotion = ev.new_event(
            event_type="claim.promoted",
            source="test:lifecycle",
            idempotency_key="stable-promotion",
            causal_parent=review["event_id"],
            confidence=1.0,
            timestamp="2026-08-13T01:00:00Z",
            privacy_class="public",
            attempt_id="attempt:lifecycle",
            claim_id=ev.stable_id("claim", "lifecycle"),
            claim_contract_digest=ev.digest("claim-contract-v1"),
            review_event_id=review["event_id"],
            decision="approve",
        )
        duplicate = dict(promotion)
        duplicate["event_id"] = ev.stable_id("event", "stable-promotion", "duplicate")

        self.assertEqual("appended", store.append(promotion))
        self.assertEqual("duplicate", store.append(duplicate))
        promotions = [
            event for event in store.events() if event["event_type"] == "claim.promoted"
        ]
        self.assertEqual(1, len(promotions))


if __name__ == "__main__":
    unittest.main()
