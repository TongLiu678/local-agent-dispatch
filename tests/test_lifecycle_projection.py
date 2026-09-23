from __future__ import annotations

import importlib.util
import pathlib
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

from local_agent_dispatch.domain import events as ev  # noqa: E402
from local_agent_dispatch.domain.lifecycle import project_lifecycle  # noqa: E402
from local_agent_dispatch.ledger.store import EventStore, ProvenanceStoreError  # noqa: E402


_SPEC = importlib.util.spec_from_file_location(
    "sqlite_store_lifecycle_under_test", ROOT / "scripts" / "sqlite_store.py"
)
assert _SPEC and _SPEC.loader
sqlite_store = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = sqlite_store
_SPEC.loader.exec_module(sqlite_store)


def _event(
    event_type: str,
    *,
    attempt_id: str = "attempt:lifecycle-projection",
    parent: str | None = None,
    index: int = 0,
    **payload: object,
) -> dict[str, object]:
    return ev.new_event(
        event_type=event_type,
        source="test:lifecycle-projection",
        idempotency_key=f"lifecycle-projection:{index}:{event_type}",
        causal_parent=parent,
        confidence=1.0,
        timestamp=f"2026-08-14T00:{index:02d}:00Z",
        privacy_class="internal",
        attempt_id=attempt_id,
        **payload,
    )


def _chain(*steps: tuple[str, dict[str, object]]) -> list[dict[str, object]]:
    chain: list[dict[str, object]] = []
    parent: str | None = None
    for index, (event_type, payload) in enumerate(steps):
        event = _event(event_type, parent=parent, index=index, **payload)
        chain.append(event)
        parent = str(event["event_id"])
    return chain


class LifecycleProjectionTests(unittest.TestCase):
    def test_completion_is_not_validation_or_claim_promotion(self) -> None:
        projection = project_lifecycle(
            _chain(
                ("attempt.queued", {}),
                ("attempt.started", {}),
                ("attempt.completed", {}),
            )
        )
        self.assertTrue(projection["executed"])
        self.assertTrue(projection["completed"])
        self.assertFalse(projection["validated"])
        self.assertFalse(projection["claim_promoted"])

    def test_validation_before_completion_is_not_yet_validated(self) -> None:
        projection = project_lifecycle(
            _chain(
                ("attempt.queued", {}),
                ("attempt.started", {}),
                ("attempt.validation", {"outcome": "passed"}),
            )
        )
        self.assertFalse(projection["completed"])
        self.assertFalse(projection["validated"])
        self.assertEqual("passed", projection["validation_outcome"])

    def test_latest_validation_failure_invalidates_old_pass(self) -> None:
        projection = project_lifecycle(
            _chain(
                ("attempt.queued", {}),
                ("attempt.started", {}),
                ("attempt.validation", {"outcome": "passed"}),
                ("attempt.completed", {}),
                ("attempt.validation", {"outcome": "failed"}),
            )
        )
        self.assertTrue(projection["completed"])
        self.assertFalse(projection["validated"])
        self.assertEqual("failed", projection["validation_outcome"])
        self.assertEqual("started", projection["status"])

    def test_sqlite_row_projection_keeps_validation_separate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with sqlite_store.SQLiteStore(pathlib.Path(tmp) / "dispatch.sqlite3") as store:
                lease = store.acquire_controller_lease("projection-owner", ttl_seconds=30)
                store.create_job("projection-job", {"kind": "fake"})
                claim = store.claim_job(
                    "projection-job", "projection-owner", lease["fence_token"]
                )
                assert claim
                attempt_id = str(claim["attempt"]["attempt_id"])
                store.complete_job(
                    "projection-job",
                    attempt_id,
                    "projection-owner",
                    lease["fence_token"],
                    success=True,
                    validation=None,
                )
                projection = store.project_attempt_lifecycle(attempt_id)
                self.assertTrue(projection["completed"])
                self.assertFalse(projection["validated"])
                self.assertFalse(projection["claim_promoted"])

                # A validator result is accepted as validation evidence only
                # because it is persisted separately from execution status.
                store.create_job("projection-job-2", {"kind": "fake"})
                claim2 = store.claim_job(
                    "projection-job-2", "projection-owner", lease["fence_token"]
                )
                assert claim2
                attempt_id2 = str(claim2["attempt"]["attempt_id"])
                store.complete_job(
                    "projection-job-2",
                    attempt_id2,
                    "projection-owner",
                    lease["fence_token"],
                    success=True,
                    validation={"ok": True, "returncode": 0},
                )
                projected2 = store.project_attempt_lifecycle(attempt_id2)
                self.assertTrue(projected2["completed"])
                self.assertTrue(projected2["validated"])
                self.assertFalse(projected2["claim_promoted"])

    def test_event_store_rejects_promotion_after_latest_validation_failed(self) -> None:
        store = EventStore()
        chain = _chain(
            ("attempt.queued", {}),
            ("attempt.started", {}),
            ("attempt.validation", {"outcome": "passed"}),
            ("attempt.completed", {}),
            ("attempt.validation", {"outcome": "failed"}),
        )
        for event in chain:
            store.append(event)
        review = _event(
            "attempt.review",
            parent=str(chain[-1]["event_id"]),
            index=len(chain),
            decision="approve",
        )
        store.append(review)
        promotion = _event(
            "claim.promoted",
            parent=str(review["event_id"]),
            index=len(chain) + 1,
            claim_id=ev.stable_id("claim", "latest-validation-failed"),
            claim_contract_digest=ev.digest("claim-contract-v1"),
            review_event_id=str(review["event_id"]),
            decision="approve",
        )
        with self.assertRaises(ProvenanceStoreError):
            store.append(promotion)

    def test_sqlite_rejects_same_illegal_promotion_transition(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with sqlite_store.SQLiteStore(pathlib.Path(tmp) / "dispatch.sqlite3") as store:
                lease = store.acquire_controller_lease("promotion-owner", ttl_seconds=30)
                store.create_job("promotion-job", {"kind": "fake"})
                claim = store.claim_job(
                    "promotion-job", "promotion-owner", lease["fence_token"]
                )
                assert claim
                attempt_id = str(claim["attempt"]["attempt_id"])
                parent = store.list_provenance_events(attempt_id=attempt_id)[-1]["event_id"]
                passed = _event(
                    "attempt.validation",
                    attempt_id=attempt_id,
                    parent=str(parent),
                    index=10,
                    outcome="passed",
                )
                store.append_provenance_event(passed)
                completed = _event(
                    "attempt.completed",
                    attempt_id=attempt_id,
                    parent=str(passed["event_id"]),
                    index=11,
                )
                # The row transition is deliberately bypassed here: this is
                # a provenance-gate test, not a provider/controller test.
                store.append_provenance_event(completed)
                failed = _event(
                    "attempt.validation",
                    attempt_id=attempt_id,
                    parent=str(completed["event_id"]),
                    index=12,
                    outcome="failed",
                )
                store.append_provenance_event(failed)
                review = _event(
                    "attempt.review",
                    attempt_id=attempt_id,
                    parent=str(failed["event_id"]),
                    index=13,
                    decision="approve",
                )
                store.append_provenance_event(review)
                promotion = _event(
                    "claim.promoted",
                    attempt_id=attempt_id,
                    parent=str(review["event_id"]),
                    index=14,
                    claim_id=ev.stable_id("claim", "sqlite-latest-validation-failed"),
                    claim_contract_digest=ev.digest("claim-contract-v1"),
                    review_event_id=str(review["event_id"]),
                    decision="approve",
                )
                with self.assertRaises(sqlite_store.ProvenanceEventError):
                    store.append_provenance_event(promotion)


if __name__ == "__main__":
    unittest.main()
