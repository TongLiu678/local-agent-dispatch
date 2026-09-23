"""Append-only causal event store for provenance v2.

Fail-closed rules:
- duplicate ``event_id`` with an identical payload is an idempotent no-op;
- duplicate ``event_id`` with a differing payload raises ``DuplicateConflictError``;
- duplicate ``idempotency_key`` with equivalent payload is an idempotent no-op;
- duplicate ``idempotency_key`` with conflicting payload raises ``DuplicateConflictError``;
- an event whose ``causal_parent`` is neither null nor already present raises
  ``OrphanEventError``.

Prompt bodies and credentials must never be passed to the store; the store
additionally refuses the well-known secret keys so no leak path exists.
"""

from __future__ import annotations

import json
import pathlib
from typing import Any, Iterable, Iterator, Mapping

from ..domain import events as ev

_FORBIDDEN_SECRET_KEYS = frozenset(
    {
        "prompt_body",
        "context_body",
        "prompt",
        "prompt_text",
        "credentials",
        "credential",
        "api_key",
        "auth_token",
        "access_token",
        "secret",
        "password",
        "ssh_key",
    }
)

TERMINAL_EVENT_TYPES = (
    "attempt.completed",
    "attempt.failed",
    "attempt.abandoned",
    "attempt.review",
    "claim.promoted",
)


class ProvenanceStoreError(Exception):
    """Base error for ledger store violations."""


class DuplicateConflictError(ProvenanceStoreError):
    """A duplicate event_id arrived with conflicting content (fail closed)."""


class OrphanEventError(ProvenanceStoreError):
    """An event references a causal parent that is not present in the store."""


class SecretLeakError(ProvenanceStoreError):
    """An event tried to persist a prompt body or credential in the ledger."""


class EventStore:
    """In-memory append-only event store with optional JSONL persistence."""

    def __init__(self, path: str | pathlib.Path | None = None) -> None:
        self._events: list[dict[str, Any]] = []
        self._by_id: dict[str, dict[str, Any]] = {}
        self._by_idempotency: dict[str, dict[str, Any]] = {}
        self._path = pathlib.Path(path) if path is not None else None
        if self._path is not None and self._path.exists():
            for event in self._read_jsonl(self._path):
                self.append(event)

    @staticmethod
    def _read_jsonl(path: pathlib.Path) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ProvenanceStoreError(
                        f"corrupt JSONL at {path}:{line_number}: {exc}"
                    ) from exc
                events.append(payload)
        return events

    def append(self, event: Mapping[str, Any]) -> str:
        """Validate, then append. Returns ``"appended"`` or ``"duplicate"``."""
        ev.validate_event(event)
        record = dict(event)
        self._reject_secrets(record)

        event_id = record["event_id"]
        idempotency_key = record["idempotency_key"]
        existing = self._by_id.get(event_id)
        if existing is not None:
            if existing == record:
                return "duplicate"
            raise DuplicateConflictError(
                f"event_id {event_id!r} already present with conflicting "
                f"content (fail closed)"
            )
        existing_by_idempotency = self._by_idempotency.get(idempotency_key)
        if existing_by_idempotency is not None:
            if existing_by_idempotency.get("event_id") == event_id:
                return "duplicate"
            dedup_candidate = dict(existing_by_idempotency)
            dedup_candidate.pop("event_id", None)
            current_candidate = dict(record)
            current_candidate.pop("event_id", None)
            if dedup_candidate == current_candidate:
                return "duplicate"
            raise DuplicateConflictError(
                f"idempotency_key {idempotency_key!r} already present with "
                f"conflicting content (fail closed)"
            )

        parent = record["causal_parent"]
        if parent is not None and parent not in self._by_id:
            raise OrphanEventError(
                f"event {event_id!r} references missing causal parent "
                f"{parent!r}"
            )

        if record["event_type"] == "claim.promoted":
            self._validate_claim_promotion(record)

        self._events.append(record)
        self._by_id[event_id] = record
        self._by_idempotency[idempotency_key] = record
        if self._path is not None:
            with self._path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, sort_keys=True) + "\n")
        return "appended"

    def _validate_claim_promotion(self, record: Mapping[str, Any]) -> None:
        """Enforce the causal ClaimContract promotion gate.

        Completion and validation are evidence states, not a public claim.
        Promotion requires a passing validation and an explicit approved
        review, with that review as the immediate causal parent.
        """
        attempt_id = record.get("attempt_id")
        if not isinstance(attempt_id, str) or not attempt_id:
            raise ProvenanceStoreError("claim.promoted requires attempt_id")
        chain = self.project_attempt_chain(attempt_id)
        if not any(item.get("event_type") == "attempt.completed" for item in chain):
            raise ProvenanceStoreError(
                "claim.promoted requires a completed attempt"
            )
        validations = [
            item
            for item in chain
            if item.get("event_type") == "attempt.validation"
        ]
        if not validations or validations[-1].get("outcome") != "passed":
            raise ProvenanceStoreError(
                "claim.promoted requires the latest validation to pass"
            )
        reviews = [
            item
            for item in chain
            if item.get("event_type") == "attempt.review"
        ]
        if not reviews or reviews[-1].get("decision") != "approve":
            raise ProvenanceStoreError(
                "claim.promoted requires an approved review"
            )
        parent = record.get("causal_parent")
        latest_review = reviews[-1]
        if parent != latest_review.get("event_id"):
            raise ProvenanceStoreError(
                "claim.promoted causal_parent must be the approved review"
            )
        if record.get("review_event_id") != parent:
            raise ProvenanceStoreError(
                "claim.promoted review_event_id must match causal_parent"
            )

    def append_many(self, events: Iterable[Mapping[str, Any]]) -> list[str]:
        """Append a causally ordered batch; returns per-event outcomes."""
        return [self.append(event) for event in events]

    def _reject_secrets(self, record: dict[str, Any]) -> None:
        for key in _FORBIDDEN_SECRET_KEYS:
            if key in record:
                raise SecretLeakError(
                    f"refusing to persist secret key {key!r} in the ledger; "
                    f"store a prompt_ref and prompt_digest instead"
                )
        for value in record.values():
            if isinstance(value, dict):
                self._reject_secrets(value)

    def get(self, event_id: str) -> dict[str, Any] | None:
        record = self._by_id.get(event_id)
        return dict(record) if record is not None else None

    def events(self) -> list[dict[str, Any]]:
        return [dict(event) for event in self._events]

    def event_ids(self) -> list[str]:
        return [event["event_id"] for event in self._events]

    def attempt_ids(self) -> list[str]:
        """Attempt ids in first-seen order; unknown attempts skipped."""
        seen: list[str] = []
        known: set[str] = set()
        for event in self._events:
            attempt_id = event.get("attempt_id")
            if isinstance(attempt_id, str) and attempt_id and attempt_id not in known:
                known.add(attempt_id)
                seen.append(attempt_id)
        return seen

    def __iter__(self) -> Iterator[dict[str, Any]]:
        return iter(self.events())

    def __len__(self) -> int:
        return len(self._events)

    def write_jsonl(self, path: str | pathlib.Path | None = None) -> None:
        """Rewrite the full JSONL file (atomic-ish: tmp + replace)."""
        target = self._path if path is None else pathlib.Path(path)
        tmp = target.with_name(target.name + ".tmp")
        with tmp.open("w", encoding="utf-8") as handle:
            for event in self._events:
                handle.write(json.dumps(event, sort_keys=True) + "\n")
        tmp.replace(target)
        self._path = target

    @classmethod
    def load_jsonl(cls, path: str | pathlib.Path) -> "EventStore":
        return cls(path=path)

    def project_attempt_chain(self, attempt_id: str) -> list[dict[str, Any]]:
        """All events for one attempt, in causal append order."""
        return [
            event
            for event in self._events
            if event.get("attempt_id") == attempt_id
        ]


class LivenessReconciler:
    """Turns stale dead attempts into explicit ``abandoned``/``review`` events.

    Never mutates original evidence: it only appends new terminal events that
    reference the attempt and the last event of its causal chain.
    """

    def __init__(
        self,
        store: EventStore,
        *,
        stale_after_seconds: float = 600.0,
        now: str | None = None,
        confidence: float = 0.9,
    ) -> None:
        self._store = store
        self._stale_after = stale_after_seconds
        self._now = now if now is not None else ev.now_iso()
        self._confidence = confidence

    def reconcile(self, pid_alive: Mapping[str, bool]) -> list[dict[str, Any]]:
        """Emit terminal evidence for stale dead attempts.

        ``pid_alive`` maps exact process ids to ``True`` (alive) or ``False``
        (confirmed dead). Unknown/unseen pids fail closed to ``review`` rather
        than being guessed as dead.
        """
        now = ev.parse_iso(self._now)
        created: list[dict[str, Any]] = []
        for attempt_id in self._store.attempt_ids():
            chain = self._store.project_attempt_chain(attempt_id)
            if any(e["event_type"] in TERMINAL_EVENT_TYPES for e in chain):
                continue
            last = chain[-1]
            try:
                last_time = ev.parse_iso(last["timestamp"])
            except ValueError:
                last_time = now
            if (now - last_time).total_seconds() < self._stale_after:
                continue

            pid = last.get("pid") if isinstance(last.get("pid"), str) else None
            if pid is not None and pid_alive.get(pid) is True:
                continue
            dead = pid is not None and pid_alive.get(pid) is False

            event_type = "attempt.abandoned" if dead else "attempt.review"
            payload: dict[str, Any] = {
                "attempt_id": attempt_id,
                "reason": (
                    "stale_dead_pid" if dead else "stale_unconfirmed_pid"
                ),
                "preserves_evidence": True,
                "pid": pid,
            }
            if not dead:
                payload["decision"] = "escalate"
            for key in (
                "mission_id",
                "task_id",
                "plan_revision_id",
                "assignment_id",
                "reservation_id",
                "policy_version_id",
                "provider",
                "pool_id",
                "model_id",
                "model_variant",
            ):
                value = last.get(key)
                if isinstance(value, str):
                    payload[key] = value
            if "evidence_quality" in last:
                payload["evidence_quality"] = last["evidence_quality"]

            event = ev.new_event(
                event_type=event_type,
                source="liveness_reconciler",
                idempotency_key=ev.stable_id(
                    "event", "reconcile", event_type, attempt_id
                ),
                causal_parent=last["event_id"],
                confidence=self._confidence,
                timestamp=self._now,
                privacy_class=last.get("privacy_class", "public"),
                **payload,
            )
            self._store.append(event)
            created.append(event)
        return created
