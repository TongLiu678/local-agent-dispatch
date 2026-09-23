#!/usr/bin/env python3
"""Small, stdlib-only transactional store for local-agent-dispatch.

This module deliberately has no dependency on the JSON controller.  It is a
storage seam that can be adopted by the controller incrementally: callers put
JSON domain payloads in the rows, while queue transitions, attempts, events,
and controller leases are committed by SQLite transactions.

The public API is intentionally conservative.  A controller must hold a
controller lease and pass its ``owner_id``/``fence_token`` to claim and
complete operations.  A stale process therefore cannot mutate a queue after a
new controller has taken over, even when the old process is still alive.
"""

from __future__ import annotations

import contextlib
import datetime as _datetime
import hashlib
import json
import os
import pathlib
import re
import sqlite3
import sys
import threading
import time
import uuid
from typing import Any, Iterator, Mapping, Sequence


# ``sqlite_store.py`` is intentionally executable as a stand-alone script, but
# the normative EventV2 contract lives in the installable package.  Resolve
# that package lazily from this checkout without making provider/runtime code a
# dependency of the store.
try:  # pragma: no cover - the first branch is used by the packaged CLI
    from local_agent_dispatch.domain import events as _provenance_events
    from local_agent_dispatch.domain.lifecycle import project_lifecycle as _project_lifecycle
except ModuleNotFoundError:  # pragma: no cover - exercised by file-spec tests
    _SOURCE_ROOT = pathlib.Path(__file__).resolve().parents[1] / "src"
    if str(_SOURCE_ROOT) not in sys.path:
        sys.path.insert(0, str(_SOURCE_ROOT))
    from local_agent_dispatch.domain import events as _provenance_events
    from local_agent_dispatch.domain.lifecycle import project_lifecycle as _project_lifecycle

try:  # pragma: no cover - package-style imports use the first branch
    from remote_envelope import EnvelopeError as _EnvelopeError
    from remote_envelope import _validate_envelope
except ModuleNotFoundError:  # pragma: no cover - imported from the source tree
    _SCRIPT_ROOT = pathlib.Path(__file__).resolve().parent
    if str(_SCRIPT_ROOT) not in sys.path:
        sys.path.insert(0, str(_SCRIPT_ROOT))
    from remote_envelope import EnvelopeError as _EnvelopeError  # type: ignore
    from remote_envelope import _validate_envelope  # type: ignore


SCHEMA_VERSION = 7
DEFAULT_LEASE_SCOPE = "controller"
DEFAULT_LEASE_TTL_SECONDS = 90


class StoreError(RuntimeError):
    """Base class for durable store errors."""


class MigrationError(StoreError):
    """Raised when a database schema cannot be migrated safely."""


class LeaseConflict(StoreError):
    """Raised when another live controller owns a lease scope."""


class FencingError(StoreError):
    """Raised when an owner/fence pair is absent, expired, or stale."""


class JobConflict(StoreError):
    """Raised when an idempotent job insert conflicts with another payload."""


class JobTransitionError(StoreError):
    """Raised when a job or attempt transition is not valid."""


class ReservationConflict(StoreError):
    """Raised when a job already has an incompatible active reservation."""


class ReservationAdmissionError(StoreError):
    """Raised when a resource admission report rejects a reservation."""


class ProvenanceEventError(StoreError):
    """Base class for durable EventV2 violations."""


class ProvenanceEventConflict(ProvenanceEventError):
    """An event/idempotency key was reused with different content."""


class ProvenanceOrphanError(ProvenanceEventError):
    """An EventV2 record references a missing causal parent."""


class ProvenanceSecretError(ProvenanceEventError):
    """A prompt body or credential was offered to the durable ledger."""


def utc_now() -> str:
    """Return a sortable, timezone-aware UTC timestamp."""

    return _datetime.datetime.now(_datetime.timezone.utc).isoformat()


def _parse_time(value: str | None) -> _datetime.datetime | None:
    if not value:
        return None
    raw = str(value).strip()
    # Python 3.10's ``fromisoformat`` does not accept the RFC 3339 ``Z``
    # suffix even though newer runtimes do.  Normalize it before parsing so
    # durable retry/lease timestamps behave identically on legacy servers.
    if raw.endswith(("Z", "z")):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = _datetime.datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_datetime.timezone.utc)
    return parsed.astimezone(_datetime.timezone.utc)


def _is_expired(value: str | None, *, now: str | None = None) -> bool:
    parsed = _parse_time(value)
    if parsed is None:
        return True
    current = _parse_time(now) or _datetime.datetime.now(_datetime.timezone.utc)
    return parsed <= current


def _json(value: Any) -> str:
    return json.dumps(value if value is not None else {}, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _decode(value: str | None, default: Any = None) -> Any:
    if value is None:
        return default
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        # A malformed payload is evidence of corruption.  Keep the raw value
        # rather than silently dropping it; callers can fail closed explicitly.
        return value


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex}"


_CONTINUOUS_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_UNKNOWN_CONTINUOUS_DIGEST = "sha256:" + "0" * 64


def _continuous_digest(value: Any, field: str, *, allow_unknown: bool = False) -> str:
    if value is None and allow_unknown:
        return _UNKNOWN_CONTINUOUS_DIGEST
    if not isinstance(value, str) or not _CONTINUOUS_DIGEST_RE.fullmatch(value):
        raise ValueError(f"{field} must be a sha256:<64 lowercase hex> digest")
    return value


def _nonnegative_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field} must be a non-negative integer")
    return value


def _migration_checksum(sql: str) -> str:
    return hashlib.sha256(sql.encode("utf-8")).hexdigest()


# Keep migration text immutable.  Future migrations must be appended, never
# edited in place; the checksum in schema_migrations detects accidental edits.
_MIGRATIONS: tuple[tuple[int, str], ...] = (
    (
        1,
        """
CREATE TABLE jobs (
    job_id TEXT PRIMARY KEY,
    schema_version INTEGER NOT NULL DEFAULT 1,
    run_id TEXT,
    task_id TEXT,
    status TEXT NOT NULL DEFAULT 'queued',
    priority INTEGER NOT NULL DEFAULT 0,
    payload_json TEXT NOT NULL,
    created_at_utc TEXT NOT NULL,
    updated_at_utc TEXT NOT NULL,
    claimed_by TEXT,
    claim_fence INTEGER,
    lease_expires_at_utc TEXT,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    completed_at_utc TEXT,
    error_class TEXT,
    error_json TEXT,
    state_revision INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX jobs_runnable_idx
    ON jobs(status, priority DESC, created_at_utc, job_id);
CREATE INDEX jobs_lease_idx ON jobs(status, lease_expires_at_utc);

CREATE TABLE attempts (
    attempt_id TEXT PRIMARY KEY,
    schema_version INTEGER NOT NULL DEFAULT 1,
    job_id TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
    attempt_no INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'running',
    owner_id TEXT,
    fence_token INTEGER,
    lease_expires_at_utc TEXT,
    started_at_utc TEXT NOT NULL,
    finished_at_utc TEXT,
    payload_json TEXT NOT NULL DEFAULT '{}',
    result_json TEXT,
    artifact_manifest_json TEXT,
    validation_json TEXT,
    error_class TEXT,
    error_json TEXT,
    UNIQUE(job_id, attempt_no)
);
CREATE INDEX attempts_job_idx ON attempts(job_id, attempt_no);
CREATE INDEX attempts_lease_idx ON attempts(status, lease_expires_at_utc);

CREATE TABLE events (
    event_seq INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    schema_version INTEGER NOT NULL DEFAULT 1,
    job_id TEXT REFERENCES jobs(job_id) ON DELETE CASCADE,
    attempt_id TEXT REFERENCES attempts(attempt_id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    at_utc TEXT NOT NULL,
    owner_id TEXT,
    fence_token INTEGER,
    payload_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX events_job_idx ON events(job_id, event_seq);

CREATE TABLE leases (
    scope TEXT PRIMARY KEY,
    schema_version INTEGER NOT NULL DEFAULT 1,
    owner_id TEXT,
    fence_token INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'released',
    acquired_at_utc TEXT,
    heartbeat_at_utc TEXT,
    lease_expires_at_utc TEXT,
    released_at_utc TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX leases_status_idx ON leases(status, lease_expires_at_utc);
""",
    ),
    (
        2,
        """
ALTER TABLE jobs ADD COLUMN retry_at_utc TEXT;
CREATE INDEX jobs_retry_idx
    ON jobs(status, retry_at_utc, priority DESC, created_at_utc, job_id);
""",
    ),
    (
        3,
        """
CREATE TABLE reservations (
    reservation_id TEXT PRIMARY KEY,
    schema_version INTEGER NOT NULL DEFAULT 1,
    job_id TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
    scope TEXT NOT NULL DEFAULT 'controller',
    status TEXT NOT NULL DEFAULT 'active',
    owner_id TEXT NOT NULL,
    fence_token INTEGER NOT NULL,
    created_at_utc TEXT NOT NULL,
    updated_at_utc TEXT NOT NULL,
    lease_expires_at_utc TEXT NOT NULL,
    resource_json TEXT NOT NULL DEFAULT '{}',
    admission_json TEXT NOT NULL DEFAULT '{}',
    release_reason TEXT
);
CREATE INDEX reservations_job_idx ON reservations(job_id, status, scope);
CREATE INDEX reservations_lease_idx ON reservations(status, lease_expires_at_utc);
CREATE UNIQUE INDEX reservations_active_job_scope_idx
    ON reservations(job_id, scope) WHERE status = 'active';
""",
    ),
    (
        4,
        """
CREATE TABLE governor_state (
    scope TEXT PRIMARY KEY,
    schema_version INTEGER NOT NULL DEFAULT 1,
    state_json TEXT NOT NULL DEFAULT '{}',
    policy_json TEXT NOT NULL DEFAULT '{}',
    observed_at_utc TEXT,
    updated_at_utc TEXT NOT NULL,
    owner_id TEXT,
    fence_token INTEGER
);
""",
    ),
    (
        5,
        """
CREATE TABLE provenance_events (
    event_seq INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    schema_version INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    causal_parent TEXT,
    source TEXT NOT NULL,
    confidence REAL NOT NULL,
    privacy_class TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    job_id TEXT,
    attempt_id TEXT,
    event_json TEXT NOT NULL
);
CREATE INDEX provenance_events_parent_idx
    ON provenance_events(causal_parent, event_seq);
CREATE INDEX provenance_events_attempt_idx
    ON provenance_events(attempt_id, event_seq);
CREATE INDEX provenance_events_job_idx
    ON provenance_events(job_id, event_seq);
""",
    ),
    (
        6,
        """
CREATE TABLE transport_outbox (
    request_id TEXT PRIMARY KEY,
    schema_version INTEGER NOT NULL DEFAULT 1,
    job_id TEXT,
    attempt_id TEXT,
    target_id TEXT NOT NULL,
    operation TEXT NOT NULL,
    packet_digest TEXT NOT NULL,
    payload_digest TEXT NOT NULL,
    envelope_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at_utc TEXT NOT NULL,
    updated_at_utc TEXT NOT NULL,
    sent_at_utc TEXT,
    completed_at_utc TEXT,
    receipt_json TEXT,
    owner_id TEXT,
    fence_token INTEGER
);
CREATE INDEX transport_outbox_status_idx
    ON transport_outbox(status, updated_at_utc, request_id);
CREATE INDEX transport_outbox_job_idx
    ON transport_outbox(job_id, request_id);
""",
    ),
    (
        7,
        """
CREATE TABLE run_segments (
    segment_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    owner_id TEXT NOT NULL,
    fence_token INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'running',
    started_at_utc TEXT NOT NULL,
    finished_at_utc TEXT,
    scheduler_job_id TEXT,
    manifest_digest TEXT NOT NULL,
    capsule_digest TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE(run_id, sequence)
);
CREATE INDEX run_segments_run_idx
    ON run_segments(run_id, sequence);
CREATE INDEX run_segments_status_idx
    ON run_segments(status, started_at_utc);

CREATE TABLE checkpoints (
    checkpoint_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    job_id TEXT NOT NULL,
    attempt_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    owner_id TEXT NOT NULL,
    fence_token INTEGER NOT NULL,
    payload_digest TEXT NOT NULL,
    state_digest TEXT NOT NULL,
    artifact_manifest_json TEXT NOT NULL DEFAULT '[]',
    created_at_utc TEXT NOT NULL,
    segment_id TEXT,
    previous_state_digest TEXT,
    request_id TEXT,
    UNIQUE(attempt_id, sequence, state_digest)
);
CREATE INDEX checkpoints_attempt_idx
    ON checkpoints(attempt_id, sequence);
CREATE INDEX checkpoints_run_idx
    ON checkpoints(run_id, sequence);

CREATE TABLE cleanup_intents (
    cleanup_intent_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE,
    run_id TEXT NOT NULL,
    segment_id TEXT,
    attempt_id TEXT,
    owner_id TEXT NOT NULL,
    fence_token INTEGER NOT NULL,
    path_digest TEXT NOT NULL,
    action TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at_utc TEXT NOT NULL,
    updated_at_utc TEXT NOT NULL,
    payload_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX cleanup_intents_run_idx
    ON cleanup_intents(run_id, status, updated_at_utc);
""",
    ),
)


def _split_migration(sql: str) -> list[str]:
    """Split our controlled DDL into statements without a SQL dependency.

    Migration strings are source-controlled DDL with no quoted semicolons.  A
    tiny splitter keeps the module stdlib-only and lets us wrap each migration
    in one explicit transaction (``executescript`` would implicitly commit).
    """

    return [part.strip() for part in sql.split(";") if part.strip()]


class SQLiteStore:
    """A process-safe SQLite WAL store for one local dispatch database.

    The connection is safe for calls from one thread at a time.  Separate
    ``SQLiteStore`` instances (including separate processes) coordinate via
    SQLite's ``BEGIN IMMEDIATE`` transactions.  Long-running provider work is
    intentionally outside the transaction; only claim/complete state changes
    are short, atomic transactions.
    """

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        timeout_seconds: float = 30.0,
        busy_timeout_ms: int | None = None,
    ) -> None:
        self.path = str(path)
        if self.path not in {":memory:", ""} and not self.path.startswith("file:"):
            pathlib.Path(self.path).expanduser().parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            self.path,
            timeout=float(timeout_seconds),
            isolation_level=None,
            check_same_thread=False,
            uri=self.path.startswith("file:"),
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA busy_timeout=%d" % int(busy_timeout_ms or max(1000, timeout_seconds * 1000)))
        # WAL is persistent for file databases.  In-memory SQLite reports
        # ``memory``; that is the only expected non-WAL exception.
        journal = str(self._conn.execute("PRAGMA journal_mode=WAL").fetchone()[0]).lower()
        if self.path not in {":memory:", ""} and journal != "wal":
            self.close()
            raise StoreError(f"SQLite WAL could not be enabled for {self.path!r}: {journal}")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._migrate()

    @property
    def connection(self) -> sqlite3.Connection:
        """Expose the connection for read-only diagnostics and migrations."""

        return self._conn

    @property
    def schema_version(self) -> int:
        row = self._conn.execute("SELECT COALESCE(MAX(version), 0) FROM schema_migrations").fetchone()
        return int(row[0])

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "SQLiteStore":
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()

    def _migrate(self) -> None:
        with self._lock:
            self._conn.execute(
                """CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at_utc TEXT NOT NULL,
                    checksum TEXT NOT NULL
                )"""
            )
            rows = {
                int(row[0]): str(row[1])
                for row in self._conn.execute(
                    "SELECT version, checksum FROM schema_migrations"
                ).fetchall()
            }
            known = {version: _migration_checksum(sql) for version, sql in _MIGRATIONS}
            if any(version > SCHEMA_VERSION for version in rows):
                self.close()
                raise MigrationError("database schema is newer than this local-agent-dispatch build")
            for version, sql in _MIGRATIONS:
                if version in rows:
                    if rows[version] != known[version]:
                        raise MigrationError(f"migration {version} checksum mismatch")
                    continue
                try:
                    self._conn.execute("BEGIN EXCLUSIVE")
                    for statement in _split_migration(sql):
                        self._conn.execute(statement)
                    self._conn.execute(
                        "INSERT INTO schema_migrations(version, applied_at_utc, checksum) VALUES (?, ?, ?)",
                        (version, utc_now(), known[version]),
                    )
                    self._conn.execute("COMMIT")
                except Exception:
                    self._conn.execute("ROLLBACK")
                    raise

    @contextlib.contextmanager
    def _transaction(self) -> Iterator[sqlite3.Cursor]:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            cursor = self._conn.cursor()
            try:
                yield cursor
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
            else:
                self._conn.execute("COMMIT")

    @staticmethod
    def _lease_expiry(ttl_seconds: int | float, *, now: str | None = None) -> str:
        base = _parse_time(now) or _datetime.datetime.now(_datetime.timezone.utc)
        return (base + _datetime.timedelta(seconds=max(1.0, float(ttl_seconds)))).isoformat()

    @staticmethod
    def _row_dict(row: sqlite3.Row | Mapping[str, Any] | None) -> dict[str, Any] | None:
        if row is None:
            return None
        return dict(row)

    @classmethod
    def _decode_job_row(cls, row: sqlite3.Row | None) -> dict[str, Any] | None:
        result = cls._row_dict(row)
        if result is None:
            return None
        result["payload"] = _decode(result.pop("payload_json", None), {})
        result["error"] = _decode(result.pop("error_json", None), None)
        return result

    @classmethod
    def _decode_attempt_row(cls, row: sqlite3.Row | None) -> dict[str, Any] | None:
        result = cls._row_dict(row)
        if result is None:
            return None
        for column, key, default in (
            ("payload_json", "payload", {}),
            ("result_json", "result", None),
            ("artifact_manifest_json", "artifact_manifest", None),
            ("validation_json", "validation", None),
            ("error_json", "error", None),
        ):
            result[key] = _decode(result.pop(column, None), default)
        return result

    @classmethod
    def _decode_event_row(cls, row: sqlite3.Row | None) -> dict[str, Any] | None:
        result = cls._row_dict(row)
        if result is None:
            return None
        result["payload"] = _decode(result.pop("payload_json", None), {})
        return result

    @staticmethod
    def _decode_provenance_event_row(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        raw = row["event_json"]
        decoded = _decode(raw, None)
        if not isinstance(decoded, Mapping):
            raise ProvenanceEventError("provenance_events contains malformed event_json")
        return dict(decoded)

    @staticmethod
    def _decode_transport_row(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        result = dict(row)
        result["envelope"] = _decode(result.pop("envelope_json", None), {})
        result["receipt"] = _decode(result.pop("receipt_json", None), None)
        return result

    @staticmethod
    def _reject_provenance_secrets(value: Any, *, path: str = "event") -> None:
        """Reject prompt/credential material before it reaches SQLite.

        EventV2 permits references and digests, not bodies.  The recursive
        check intentionally errs on the side of blocking a suspicious key in
        nested payloads; callers can keep arbitrary safe metadata under other
        names.
        """

        forbidden = {
            "prompt_body", "context_body", "prompt", "prompt_text",
            "credentials", "credential", "api_key", "auth_token",
            "access_token", "secret", "password", "ssh_key",
        }
        if isinstance(value, Mapping):
            for key, item in value.items():
                if str(key).lower() in forbidden:
                    raise ProvenanceSecretError(
                        f"refusing to persist secret-like key {path}.{key}"
                    )
                SQLiteStore._reject_provenance_secrets(item, path=f"{path}.{key}")
        elif isinstance(value, (list, tuple)):
            for index, item in enumerate(value):
                SQLiteStore._reject_provenance_secrets(item, path=f"{path}[{index}]")

    def _validate_provenance_claim_tx(
        self,
        cursor: sqlite3.Cursor,
        record: Mapping[str, Any],
    ) -> None:
        """Apply the causal promotion gate inside the same SQLite transaction."""

        if record.get("event_type") != "claim.promoted":
            return
        attempt_id = str(record.get("attempt_id") or "")
        rows = cursor.execute(
            "SELECT event_json FROM provenance_events WHERE attempt_id = ? ORDER BY event_seq",
            (attempt_id,),
        ).fetchall()
        chain = [
            item for row in rows
            if isinstance((item := _decode(row[0], None)), Mapping)
        ]
        if not any(item.get("event_type") == "attempt.completed" for item in chain):
            raise ProvenanceEventError("claim.promoted requires a completed attempt")
        validations = [
            item
            for item in chain
            if item.get("event_type") == "attempt.validation"
        ]
        if not validations or validations[-1].get("outcome") != "passed":
            raise ProvenanceEventError(
                "claim.promoted requires the latest validation to pass"
            )
        reviews = [item for item in chain if item.get("event_type") == "attempt.review"]
        if not reviews or reviews[-1].get("decision") != "approve":
            raise ProvenanceEventError("claim.promoted requires an approved review")
        latest_review = reviews[-1]
        if record.get("causal_parent") != latest_review.get("event_id"):
            raise ProvenanceEventError(
                "claim.promoted causal_parent must be the approved review"
            )
        if record.get("review_event_id") != record.get("causal_parent"):
            raise ProvenanceEventError(
                "claim.promoted review_event_id must match causal_parent"
            )

    def _append_provenance_event_tx(
        self,
        cursor: sqlite3.Cursor,
        event: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Validate and append one EventV2 record within an open transaction."""

        record = dict(event)
        try:
            _provenance_events.validate_event(record)
        except Exception as exc:
            raise ProvenanceEventError(str(exc)) from exc
        self._reject_provenance_secrets(record)
        canonical = _json(record)
        event_id = str(record["event_id"])
        idempotency_key = str(record["idempotency_key"])
        existing = cursor.execute(
            "SELECT event_json FROM provenance_events WHERE event_id = ?",
            (event_id,),
        ).fetchone()
        if existing is not None:
            if str(existing["event_json"]) == canonical:
                return record
            raise ProvenanceEventConflict(
                f"event_id {event_id!r} already exists with conflicting content"
            )
        existing = cursor.execute(
            "SELECT event_json FROM provenance_events WHERE idempotency_key = ?",
            (idempotency_key,),
        ).fetchone()
        if existing is not None:
            if str(existing["event_json"]) == canonical:
                return record
            raise ProvenanceEventConflict(
                f"idempotency_key {idempotency_key!r} already exists with conflicting content"
            )
        parent = record.get("causal_parent")
        if parent is not None:
            parent_row = cursor.execute(
                "SELECT 1 FROM provenance_events WHERE event_id = ?",
                (str(parent),),
            ).fetchone()
            if parent_row is None:
                raise ProvenanceOrphanError(
                    f"event {event_id!r} references missing causal parent {parent!r}"
                )
        self._validate_provenance_claim_tx(cursor, record)
        cursor.execute(
            """INSERT INTO provenance_events
               (event_id, schema_version, event_type, timestamp, causal_parent,
                source, confidence, privacy_class, idempotency_key, job_id,
                attempt_id, event_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event_id,
                int(record["schema_version"]),
                str(record["event_type"]),
                str(record["timestamp"]),
                record.get("causal_parent"),
                str(record["source"]),
                float(record["confidence"]),
                str(record["privacy_class"]),
                idempotency_key,
                record.get("job_id"),
                record.get("attempt_id"),
                canonical,
            ),
        )
        return record

    def _latest_provenance_event_id_tx(
        self,
        cursor: sqlite3.Cursor,
        attempt_id: str,
    ) -> str | None:
        row = cursor.execute(
            "SELECT event_id FROM provenance_events WHERE attempt_id = ? ORDER BY event_seq DESC LIMIT 1",
            (str(attempt_id),),
        ).fetchone()
        return str(row[0]) if row is not None else None

    def _automatic_attempt_event(
        self,
        *,
        event_type: str,
        attempt_id: str,
        parent: str | None,
        job_id: str,
        timestamp: str,
        **payload: Any,
    ) -> dict[str, Any]:
        """Build a safe lifecycle event for controller-owned transitions."""

        record = _provenance_events.new_event(
            event_type=event_type,
            source="sqlite_store",
            idempotency_key=f"sqlite:{event_type}:{attempt_id}",
            causal_parent=parent,
            confidence=1.0,
            timestamp=timestamp,
            privacy_class="internal",
            attempt_id=attempt_id,
            **payload,
        )
        # ``job_id`` is an explicit correlation field, not a prompt-bearing
        # payload.  EventV2 allows forward-compatible extra properties.
        record["job_id"] = job_id
        return record

    @staticmethod
    def _decode_lease_row(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        result = dict(row)
        result["metadata"] = _decode(result.pop("metadata_json", None), {})
        # Keep the common spelling used by controller JSON packets.
        result["expires_at_utc"] = result.get("lease_expires_at_utc")
        result["lease_token"] = result.get("fence_token")
        return result

    @staticmethod
    def _decode_reservation_row(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        result = dict(row)
        result["resource_request"] = _decode(result.pop("resource_json", None), {})
        result["admission"] = _decode(result.pop("admission_json", None), {})
        result["expires_at_utc"] = result.get("lease_expires_at_utc")
        result["reservation_token"] = result.get("reservation_id")
        return result

    @staticmethod
    def _decode_governor_row(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        result = dict(row)
        result["state"] = _decode(result.pop("state_json", None), {})
        result["policy"] = _decode(result.pop("policy_json", None), {})
        return result

    @staticmethod
    def _decode_segment_row(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        result = dict(row)
        result["metadata"] = _decode(result.pop("metadata_json", None), {})
        return result

    @staticmethod
    def _decode_checkpoint_row(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        result = dict(row)
        result["artifact_manifest"] = _decode(result.pop("artifact_manifest_json", None), [])
        return result

    @staticmethod
    def _decode_cleanup_intent_row(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        result = dict(row)
        result["payload"] = _decode(result.pop("payload_json", None), {})
        return result

    def _assert_lease_tx(
        self,
        cursor: sqlite3.Cursor,
        scope: str,
        owner_id: str,
        fence_token: int,
        *,
        now: str | None = None,
    ) -> sqlite3.Row:
        row = cursor.execute("SELECT * FROM leases WHERE scope = ?", (scope,)).fetchone()
        current = now or utc_now()
        if (
            row is None
            or str(row["owner_id"] or "") != str(owner_id)
            or int(row["fence_token"] or 0) != int(fence_token)
            or str(row["status"]) != "active"
            or _is_expired(row["lease_expires_at_utc"], now=current)
        ):
            raise FencingError(f"stale or missing controller lease for scope {scope!r}")
        return row

    # ------------------------------------------------------------------
    # Controller leases and fencing
    # ------------------------------------------------------------------
    def acquire_controller_lease(
        self,
        owner_id: str,
        *,
        scope: str = DEFAULT_LEASE_SCOPE,
        ttl_seconds: int | float = DEFAULT_LEASE_TTL_SECONDS,
        metadata: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        if not str(owner_id).strip():
            raise ValueError("owner_id is required")
        scope = str(scope)
        current = utc_now()
        expiry = self._lease_expiry(ttl_seconds, now=current)
        with self._transaction() as cursor:
            row = cursor.execute("SELECT * FROM leases WHERE scope = ?", (scope,)).fetchone()
            if row is not None and str(row["status"]) == "active" and not _is_expired(
                row["lease_expires_at_utc"], now=current
            ):
                if str(row["owner_id"] or "") != str(owner_id):
                    raise LeaseConflict(f"lease scope {scope!r} is held by another controller")
                # Re-entrant acquisition by the same durable owner renews the
                # existing fencing epoch; a second process should use a
                # distinct owner id and cannot accidentally share it.
                cursor.execute(
                    """UPDATE leases
                       SET heartbeat_at_utc = ?, lease_expires_at_utc = ?, metadata_json = ?
                       WHERE scope = ? AND owner_id = ? AND status = 'active'""",
                    (current, expiry, _json(dict(metadata or _decode(row["metadata_json"], {}))), scope, owner_id),
                )
                updated = cursor.execute("SELECT * FROM leases WHERE scope = ?", (scope,)).fetchone()
                assert updated is not None
                return self._decode_lease_row(updated) or {}

            previous_fence = int(row["fence_token"] or 0) if row is not None else 0
            next_fence = previous_fence + 1
            if row is None:
                cursor.execute(
                    """INSERT INTO leases
                       (scope, owner_id, fence_token, status, acquired_at_utc,
                        heartbeat_at_utc, lease_expires_at_utc, released_at_utc, metadata_json)
                       VALUES (?, ?, ?, 'active', ?, ?, ?, NULL, ?)""",
                    (scope, owner_id, next_fence, current, current, expiry, _json(dict(metadata or {}))),
                )
            else:
                cursor.execute(
                    """UPDATE leases
                       SET owner_id = ?, fence_token = ?, status = 'active',
                           acquired_at_utc = ?, heartbeat_at_utc = ?,
                           lease_expires_at_utc = ?, released_at_utc = NULL, metadata_json = ?
                       WHERE scope = ?""",
                    (owner_id, next_fence, current, current, expiry, _json(dict(metadata or {})), scope),
                )
            updated = cursor.execute("SELECT * FROM leases WHERE scope = ?", (scope,)).fetchone()
            assert updated is not None
            return self._decode_lease_row(updated) or {}

    # Short alias useful to integrations that use ``lease`` terminology.
    acquire_lease = acquire_controller_lease

    def heartbeat_controller_lease(
        self,
        owner_id: str,
        fence_token: int,
        *,
        scope: str = DEFAULT_LEASE_SCOPE,
        ttl_seconds: int | float = DEFAULT_LEASE_TTL_SECONDS,
    ) -> dict[str, Any]:
        current = utc_now()
        expiry = self._lease_expiry(ttl_seconds, now=current)
        with self._transaction() as cursor:
            self._assert_lease_tx(cursor, scope, owner_id, fence_token, now=current)
            cursor.execute(
                """UPDATE leases SET heartbeat_at_utc = ?, lease_expires_at_utc = ?
                   WHERE scope = ? AND owner_id = ? AND fence_token = ? AND status = 'active'""",
                (current, expiry, scope, owner_id, int(fence_token)),
            )
            row = cursor.execute("SELECT * FROM leases WHERE scope = ?", (scope,)).fetchone()
            assert row is not None
            return self._decode_lease_row(row) or {}

    heartbeat_lease = heartbeat_controller_lease

    def heartbeat_job_lease(
        self,
        job_id: str,
        attempt_id: str,
        owner_id: str,
        fence_token: int,
        *,
        ttl_seconds: int | float = DEFAULT_LEASE_TTL_SECONDS,
        scope: str = DEFAULT_LEASE_SCOPE,
    ) -> dict[str, Any]:
        """Renew one claimed job and its running attempt atomically.

        Controller fencing alone is insufficient while provider work runs
        outside a transaction: a long attempt could outlive the row-level
        lease and be reclaimed by a second controller.  Both rows are
        renewed in one transaction and an expired/stale owner is rejected,
        so an old worker cannot revive a job after takeover.
        """
        current = utc_now()
        expiry = self._lease_expiry(ttl_seconds, now=current)
        with self._transaction() as cursor:
            self._assert_lease_tx(cursor, scope, owner_id, int(fence_token), now=current)
            job = cursor.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
            attempt = cursor.execute(
                "SELECT * FROM attempts WHERE attempt_id = ? AND job_id = ?",
                (attempt_id, job_id),
            ).fetchone()
            if (
                job is None
                or attempt is None
                or str(job["status"]) != "running"
                or str(job["claimed_by"] or "") != str(owner_id)
                or int(job["claim_fence"] or 0) != int(fence_token)
                or str(attempt["status"]) != "running"
                or str(attempt["owner_id"] or "") != str(owner_id)
                or int(attempt["fence_token"] or 0) != int(fence_token)
                or _is_expired(job["lease_expires_at_utc"], now=current)
                or _is_expired(attempt["lease_expires_at_utc"], now=current)
            ):
                raise FencingError(f"stale or missing job lease for {job_id!r}")
            cursor.execute(
                """UPDATE jobs SET lease_expires_at_utc = ?, updated_at_utc = ?
                   WHERE job_id = ? AND status = 'running' AND claimed_by = ? AND claim_fence = ?""",
                (expiry, current, job_id, owner_id, int(fence_token)),
            )
            cursor.execute(
                """UPDATE attempts SET lease_expires_at_utc = ?
                   WHERE attempt_id = ? AND status = 'running' AND owner_id = ? AND fence_token = ?""",
                (expiry, attempt_id, owner_id, int(fence_token)),
            )
            cursor.execute(
                """UPDATE reservations SET updated_at_utc = ?, lease_expires_at_utc = ?
                   WHERE job_id = ? AND scope = ? AND status = 'active'
                     AND owner_id = ? AND fence_token = ?""",
                (current, expiry, job_id, scope, owner_id, int(fence_token)),
            )
            return {
                "job": self._decode_job_row(
                    cursor.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
                ),
                "attempt": self._decode_attempt_row(
                    cursor.execute("SELECT * FROM attempts WHERE attempt_id = ?", (attempt_id,)).fetchone()
                ),
            }

    @contextlib.contextmanager
    def job_lease_heartbeat(
        self,
        job_id: str,
        attempt_id: str,
        owner_id: str,
        fence_token: int,
        *,
        ttl_seconds: int | float = DEFAULT_LEASE_TTL_SECONDS,
        heartbeat_interval_seconds: float | None = None,
        scope: str = DEFAULT_LEASE_SCOPE,
    ) -> Iterator[dict[str, Any]]:
        """Keep a running job lease alive while provider work is executing."""
        interval = heartbeat_interval_seconds
        if interval is None:
            interval = max(1.0, min(float(ttl_seconds) / 3.0, 30.0))
        if float(interval) <= 0:
            raise ValueError("heartbeat_interval_seconds must be positive")
        stop = threading.Event()
        lost = threading.Event()

        def beat() -> None:
            while not stop.wait(float(interval)):
                try:
                    self.heartbeat_job_lease(
                        job_id,
                        attempt_id,
                        owner_id,
                        int(fence_token),
                        ttl_seconds=ttl_seconds,
                        scope=scope,
                    )
                except (FencingError, sqlite3.Error):
                    # The foreground completion call will enforce the same
                    # fence.  Stop renewing rather than reviving a lease that
                    # a newer owner has legitimately taken over.
                    lost.set()
                    return

        thread = threading.Thread(target=beat, name="lad-sqlite-job-heartbeat", daemon=True)
        thread.start()
        try:
            yield {"lost": lost}
        finally:
            stop.set()
            thread.join(timeout=max(1.0, float(interval) + 0.5))

    def release_controller_lease(
        self,
        owner_id: str,
        fence_token: int,
        *,
        scope: str = DEFAULT_LEASE_SCOPE,
    ) -> dict[str, Any]:
        current = utc_now()
        with self._transaction() as cursor:
            row = cursor.execute("SELECT * FROM leases WHERE scope = ?", (scope,)).fetchone()
            if (
                row is None
                or str(row["owner_id"] or "") != str(owner_id)
                or int(row["fence_token"] or 0) != int(fence_token)
            ):
                raise FencingError(f"cannot release stale controller lease for scope {scope!r}")
            cursor.execute(
                """UPDATE leases SET status = 'released', released_at_utc = ?,
                   lease_expires_at_utc = ? WHERE scope = ? AND owner_id = ? AND fence_token = ?""",
                (current, current, scope, owner_id, int(fence_token)),
            )
            updated = cursor.execute("SELECT * FROM leases WHERE scope = ?", (scope,)).fetchone()
            assert updated is not None
            return self._decode_lease_row(updated) or {}

    release_lease = release_controller_lease

    @contextlib.contextmanager
    def controller_lease(
        self,
        owner_id: str,
        *,
        scope: str = DEFAULT_LEASE_SCOPE,
        ttl_seconds: int | float = DEFAULT_LEASE_TTL_SECONDS,
        heartbeat_interval_seconds: float | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> Iterator[dict[str, Any]]:
        lease = self.acquire_controller_lease(
            owner_id, scope=scope, ttl_seconds=ttl_seconds, metadata=metadata
        )
        stop = threading.Event()
        interval = heartbeat_interval_seconds
        if interval is None:
            interval = max(1.0, min(float(ttl_seconds) / 3.0, 30.0))

        def beat() -> None:
            while not stop.wait(float(interval)):
                try:
                    self.heartbeat_controller_lease(
                        owner_id,
                        int(lease["fence_token"]),
                        scope=scope,
                        ttl_seconds=ttl_seconds,
                    )
                except (FencingError, sqlite3.Error):
                    # The foreground operation observes the lease token on its
                    # next mutation.  Never let a daemon heartbeat hide the
                    # original provider exception.
                    return

        thread = threading.Thread(target=beat, name="lad-sqlite-lease-heartbeat", daemon=True)
        thread.start()
        try:
            yield lease
        finally:
            stop.set()
            thread.join(timeout=max(1.0, float(interval) + 0.5))
            try:
                self.release_controller_lease(
                    owner_id, int(lease["fence_token"]), scope=scope
                )
            except FencingError:
                # A newer owner may have fenced this context after a timeout;
                # preserving the newer lease is the safe outcome.
                pass

    # ------------------------------------------------------------------
    # Resource reservations
    # ------------------------------------------------------------------
    _RESOURCE_FIELDS = (
        "cpu_cores", "ram_gib", "gpu_count", "vram_gib_per_gpu",
        "new_disk_gib", "compute_minutes", "network_gib",
    )
    _HOST_RESOURCE_FIELDS = (
        "cpu_cores", "ram_gib", "gpu_count", "vram_gib_per_gpu", "new_disk_gib",
    )

    @staticmethod
    def _normalize_resource_request(request: Mapping[str, Any] | None) -> dict[str, Any]:
        """Keep reservation inputs numeric, bounded, and JSON serializable."""
        source = dict(request or {})
        result: dict[str, Any] = {}
        numeric = (
            "cpu_cores", "ram_gib", "gpu_count", "vram_gib_per_gpu",
            "new_disk_gib", "compute_minutes", "network_gib",
            # Slot requests are useful for a host or model-pool semaphore.
            # They remain optional so older packets without a pool capacity
            # continue to use the original resource contract.
            "slots", "concurrency", "host_slots", "pool_slots",
        )
        for key, value in source.items():
            if key not in numeric:
                # Preserve small placement identifiers, but never persist
                # arbitrary command/prompt material in the reservation row.
                if key in {"host_id", "pool_id", "mount_id", "write_scope"}:
                    result[key] = str(value)
                continue
            if value is None:
                continue
            try:
                parsed = float(value)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"resource request {key!r} must be numeric") from exc
            if parsed < 0:
                raise ValueError(f"resource request {key!r} must be non-negative")
            result[key] = int(parsed) if parsed.is_integer() else parsed
        # ``vram_gib`` is the planner-facing spelling.  Internally keep the
        # existing per-GPU field while accepting both forms at the boundary.
        if "vram_gib_per_gpu" not in result and "vram_gib" in source:
            value = source.get("vram_gib")
            try:
                parsed = float(value)
            except (TypeError, ValueError) as exc:
                raise ValueError("resource request 'vram_gib' must be numeric") from exc
            if parsed < 0:
                raise ValueError("resource request 'vram_gib' must be non-negative")
            result["vram_gib_per_gpu"] = int(parsed) if parsed.is_integer() else parsed
        if "new_disk_gib" not in result and "disk_gib" in source:
            value = source.get("disk_gib")
            try:
                parsed = float(value)
            except (TypeError, ValueError) as exc:
                raise ValueError("resource request 'disk_gib' must be numeric") from exc
            if parsed < 0:
                raise ValueError("resource request 'disk_gib' must be non-negative")
            result["new_disk_gib"] = int(parsed) if parsed.is_integer() else parsed
        return result

    @staticmethod
    def _normalize_capacity_map(value: Mapping[str, Any] | None) -> dict[str, float]:
        """Normalize a capacity map without persisting probe/command payloads.

        Capacity is an input to the admission transaction, not durable state.
        Keep the accepted vocabulary deliberately small so an accidental
        prompt, command, or credential cannot become part of an event row.
        ``vram_gib`` is accepted as an alias for ``vram_gib_per_gpu`` and
        ``capacity``/``allocatable`` are accepted as world-state wrappers.
        """
        source = dict(value or {})
        for wrapper in ("allocatable", "capacity", "resources"):
            nested = source.get(wrapper)
            if isinstance(nested, Mapping):
                source = {**dict(nested), **{k: v for k, v in source.items() if k not in {wrapper}}}
                break
        result: dict[str, float] = {}
        aliases = {
            "vram_gib": "vram_gib_per_gpu",
            "vram": "vram_gib_per_gpu",
            "disk_gib": "new_disk_gib",
            "host_slots": "slots",
            "pool_slots": "slots",
        }
        accepted = set(SQLiteStore._RESOURCE_FIELDS) | {"slots", "concurrency"}
        for raw_key, raw_value in source.items():
            key = aliases.get(str(raw_key), str(raw_key))
            if key not in accepted or raw_value is None:
                continue
            try:
                parsed = float(raw_value)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"capacity {raw_key!r} must be numeric") from exc
            if parsed < 0:
                raise ValueError(f"capacity {raw_key!r} must be non-negative")
            result[key] = parsed
        return result

    @classmethod
    def _capacity_groups(
        cls,
        resource_request: Mapping[str, Any],
        capacity: Mapping[str, Any] | None,
        *,
        host_capacity: Mapping[str, Any] | None = None,
        pool_capacity: Mapping[str, Any] | None = None,
    ) -> tuple[str | None, str | None, dict[str, float], dict[str, float], bool]:
        """Resolve host/pool capacity groups accepted by ``reserve_resources``.

        The public seam intentionally supports both a compact flat map and an
        explicit world-state shape::

            {"host_id": "bjb2", "pool_id": "opencode-go",
             "host": {"ram_gib": 32}, "pool": {"slots": 2}}

        Flat resource keys are treated as host capacity.  Supplying a
        capacity map enables checks for the dimensions it contains; omitting
        it preserves legacy reservation-only behavior during migration.
        """
        source = dict(capacity or {})
        host_id = str(resource_request.get("host_id") or source.get("host_id") or "") or None
        pool_id = str(resource_request.get("pool_id") or source.get("pool_id") or "") or None
        nested_host = host_capacity
        nested_pool = pool_capacity
        if nested_host is None:
            for key in ("host", "host_capacity", "host_resources"):
                candidate = source.get(key)
                if isinstance(candidate, Mapping):
                    nested_host = candidate
                    break
        if nested_pool is None:
            for key in ("pool", "pool_capacity", "pool_resources"):
                candidate = source.get(key)
                if isinstance(candidate, Mapping):
                    nested_pool = candidate
                    break
        host = cls._normalize_capacity_map(nested_host)
        pool = cls._normalize_capacity_map(nested_pool)
        # A flat map is a convenient host-capacity shorthand.  Do not copy
        # identifiers or nested maps into the resource dimensions.
        if nested_host is None:
            host = cls._normalize_capacity_map(source)
        if nested_pool is None:
            # ``pool_slots`` commonly arrives beside flat host resources.
            pool = cls._normalize_capacity_map({"slots": source.get("pool_slots")})
        enabled = capacity is not None or host_capacity is not None or pool_capacity is not None
        return host_id, pool_id, host, pool, enabled

    @staticmethod
    def _reservation_totals_tx(
        cursor: sqlite3.Cursor,
        *,
        scope: str,
        current: str,
        host_id: str | None = None,
        pool_id: str | None = None,
    ) -> tuple[dict[str, float], int]:
        """Sum active reservations for one host/pool inside the write txn."""
        rows = cursor.execute(
            """SELECT resource_json FROM reservations
               WHERE scope = ? AND status = 'active'
                 AND lease_expires_at_utc > ?""",
            (scope, current),
        ).fetchall()
        totals: dict[str, float] = {}
        count = 0
        for row in rows:
            request = _decode(row[0], {})
            if not isinstance(request, Mapping):
                continue
            # A legacy reservation without placement identity is unknown, not
            # free capacity.  Count it conservatively against a named host;
            # only a verified different host can be excluded.
            if host_id is not None and str(request.get("host_id") or "") not in {"", str(host_id)}:
                continue
            if pool_id is not None and str(request.get("pool_id") or "") not in {"", str(pool_id)}:
                continue
            count += 1
            for key in SQLiteStore._RESOURCE_FIELDS:
                value = request.get(key)
                if isinstance(value, (int, float)):
                    totals[key] = totals.get(key, 0.0) + float(value)
            # Slots are counted as a semaphore when the caller provides a
            # slot capacity.  A missing slot request means one reservation.
            slot_value = request.get("slots", request.get("concurrency"))
            if slot_value is None:
                slot_value = request.get("host_slots", request.get("pool_slots"))
            if isinstance(slot_value, (int, float)):
                totals["slots"] = totals.get("slots", 0.0) + float(slot_value)
            elif host_id is not None or pool_id is not None:
                totals["slots"] = totals.get("slots", 0.0) + 1.0
        return totals, count

    @classmethod
    def _capacity_admission(
        cls,
        request: Mapping[str, Any],
        *,
        host_id: str | None,
        pool_id: str | None,
        host_capacity: Mapping[str, float],
        pool_capacity: Mapping[str, float],
        host_totals: Mapping[str, float],
        pool_totals: Mapping[str, float],
        host_count: int,
        pool_count: int,
        enabled: bool,
    ) -> dict[str, Any]:
        """Return a machine-readable capacity decision before INSERT."""
        if not enabled:
            return {"allowed": True, "source": "reservation_store"}
        checks: list[dict[str, Any]] = []

        def check_group(
            group: str,
            capacities: Mapping[str, float],
            totals: Mapping[str, float],
            count: int,
            identifier: str | None,
            *,
            strict_missing: bool = False,
        ) -> None:
            # A capacity group without an identity is still valid for a
            # single/global pool, but a host/pool-specific request must name
            # its group so reservations cannot silently cross-contaminate.
            if not capacities and not strict_missing:
                return
            fields = cls._HOST_RESOURCE_FIELDS if group == "host" else cls._RESOURCE_FIELDS
            for key in fields:
                requested = request.get(key)
                if requested in (None, 0):
                    continue
                available = capacities.get(key)
                if available is None:
                    # Host resource evidence is a complete admission vector:
                    # an explicitly requested dimension that the probe could
                    # not measure is unknown and therefore fails closed.  Pool
                    # evidence may intentionally constrain only its slot
                    # semaphore, so its absent dimensions remain irrelevant.
                    if strict_missing:
                        checks.append({"group": group, "resource": key, "decision": "unknown", "reason": "capacity_unknown", "identifier": identifier})
                    continue
                projected = float(totals.get(key, 0.0)) + float(requested)
                checks.append({"group": group, "resource": key, "requested": float(requested), "reserved": float(totals.get(key, 0.0)), "capacity": float(available), "projected": projected, "decision": "admit" if projected <= available else "reject", "identifier": identifier})
            slot_capacity = capacities.get("slots", capacities.get("concurrency"))
            if slot_capacity is not None:
                requested_slots = request.get("slots", request.get("concurrency"))
                if requested_slots is None:
                    requested_slots = request.get("host_slots" if group == "host" else "pool_slots", 1)
                projected = float(totals.get("slots", 0.0)) + float(requested_slots)
                checks.append({"group": group, "resource": "slots", "requested": float(requested_slots), "reserved": float(totals.get("slots", 0.0)), "capacity": float(slot_capacity), "projected": projected, "decision": "admit" if projected <= slot_capacity else "reject", "identifier": identifier})

        # Apply host and pool checks independently.  A pool capacity may be a
        # model-pool semaphore while host capacity accounts for RAM/VRAM/etc.
        check_group(
            "host", host_capacity, host_totals, host_count, host_id,
            strict_missing=enabled,
        )
        check_group("pool", pool_capacity, pool_totals, pool_count, pool_id)
        rejected = [item for item in checks if item.get("decision") in {"reject", "unknown"}]
        return {
            "allowed": not rejected,
            "source": "reservation_store",
            "host_id": host_id,
            "pool_id": pool_id,
            "checks": checks,
            "reason": (rejected[0].get("reason") or f"{rejected[0].get('group')}_{rejected[0].get('resource')}_capacity_exceeded") if rejected else "capacity_available",
            "host_reserved_before": dict(host_totals),
            "pool_reserved_before": dict(pool_totals),
        }

    @staticmethod
    def _job_requires_reservation_payload(payload: Mapping[str, Any]) -> bool:
        # Legacy packets without an estimate remain runnable during migration.
        # Planner/bridge packets carry resource_request and therefore enter the
        # strict reservation path automatically.
        return bool(payload.get("resource_reservation_required") or payload.get("resource_request"))

    def _release_reservation_tx(
        self,
        cursor: sqlite3.Cursor,
        job_id: str,
        *,
        owner_id: str | None = None,
        fence_token: int | None = None,
        reason: str,
        current: str,
    ) -> int:
        where = "job_id = ? AND status = 'active'"
        params: list[Any] = [job_id]
        if owner_id is not None:
            where += " AND owner_id = ?"
            params.append(owner_id)
        if fence_token is not None:
            where += " AND fence_token = ?"
            params.append(int(fence_token))
        cursor.execute(
            f"""UPDATE reservations
                SET status = 'released', updated_at_utc = ?,
                    lease_expires_at_utc = ?, release_reason = ?
                WHERE {where}""",
            [current, current, reason, *params],
        )
        return int(cursor.rowcount or 0)

    @staticmethod
    def _prepare_reservation_inputs(
        resource_request: Mapping[str, Any] | None,
        admission: Mapping[str, Any] | None,
        capacity: Mapping[str, Any] | None,
    ) -> tuple[dict[str, Any], dict[str, Any], Mapping[str, Any] | None]:
        """Normalize the caller-facing reservation inputs before a txn.

        Capacity evidence is ephemeral.  It may be used by the transaction
        for admission, but only the bounded numeric result is persisted in the
        reservation row/event.  Keeping this preparation shared by
        ``reserve_resources`` and ``reserve_and_claim_job`` prevents the two
        APIs from drifting into different safety policies.
        """
        request = SQLiteStore._normalize_resource_request(resource_request)
        admission_obj = dict(admission or {})
        if admission_obj.get("allowed") is False:
            raise ReservationAdmissionError(
                str(admission_obj.get("reason") or "resource admission rejected")
            )
        # A caller may carry a structured capacity observation inside its
        # admission report.  This keeps older controller call sites concise
        # while still making the transaction own the final decision.
        if capacity is None and isinstance(admission_obj.get("capacity"), Mapping):
            capacity = admission_obj.get("capacity")  # type: ignore[assignment]
        # Never persist the raw nested object from an admission report: it may
        # contain host inventory fields (or command-like material) outside the
        # bounded dimensions accepted by ``_normalize_capacity_map``.
        if "capacity" in admission_obj:
            admission_obj.pop("capacity", None)
            admission_obj["capacity_evidence_supplied"] = True
        return request, admission_obj, capacity

    def _reserve_resources_tx(
        self,
        cursor: sqlite3.Cursor,
        *,
        job_id: str,
        owner_id: str,
        fence_token: int,
        request: dict[str, Any],
        admission_obj: dict[str, Any],
        capacity: Mapping[str, Any] | None,
        host_capacity: Mapping[str, Any] | None,
        pool_capacity: Mapping[str, Any] | None,
        current: str,
        expiry: str,
        scope: str,
        reservation_id: str,
        provenance_event: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Insert/reuse one reservation inside an already-open transaction."""
        job = cursor.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
        if job is None:
            raise JobTransitionError(f"job {job_id!r} does not exist")
        cursor.execute(
            """UPDATE reservations SET status = 'expired', updated_at_utc = ?,
               lease_expires_at_utc = ?, release_reason = 'lease_expired'
               WHERE status = 'active' AND lease_expires_at_utc <= ?""",
            (current, current, current),
        )
        host_id, pool_id, host_cap, pool_cap, capacity_enabled = self._capacity_groups(
            request,
            capacity,
            host_capacity=host_capacity,
            pool_capacity=pool_capacity,
        )
        # Placement identifiers belong to the request, not to ephemeral
        # capacity evidence.  Persist only the resolved identity.
        if host_id is not None:
            request["host_id"] = host_id
        if pool_id is not None:
            request["pool_id"] = pool_id
        active = cursor.execute(
            "SELECT * FROM reservations WHERE job_id = ? AND scope = ? AND status = 'active'",
            (job_id, scope),
        ).fetchone()
        if active is not None:
            existing = self._decode_reservation_row(active) or {}
            if (
                str(active["owner_id"] or "") == str(owner_id)
                and int(active["fence_token"] or 0) == int(fence_token)
                and existing.get("resource_request") == request
            ):
                return existing
            raise ReservationConflict(f"job {job_id!r} already has an active reservation")
        host_totals, host_count = self._reservation_totals_tx(
            cursor, scope=scope, current=current, host_id=host_id
        )
        pool_totals, pool_count = self._reservation_totals_tx(
            cursor, scope=scope, current=current, pool_id=pool_id
        )
        capacity_admission = self._capacity_admission(
            request,
            host_id=host_id,
            pool_id=pool_id,
            host_capacity=host_cap,
            pool_capacity=pool_cap,
            host_totals=host_totals,
            pool_totals=pool_totals,
            host_count=host_count,
            pool_count=pool_count,
            enabled=capacity_enabled,
        )
        if not capacity_admission.get("allowed", True):
            # Do not create a row/event for a rejected lane.  The caller can
            # retain its own provider/governor evidence for diagnostics.
            raise ReservationAdmissionError(
                str(capacity_admission.get("reason") or "resource capacity rejected")
            )
        if capacity_enabled:
            merged = dict(admission_obj)
            merged.update(capacity_admission)
            admission_obj = merged
        cursor.execute(
            """INSERT INTO reservations
               (reservation_id, schema_version, job_id, scope, status, owner_id,
                fence_token, created_at_utc, updated_at_utc, lease_expires_at_utc,
                resource_json, admission_json)
               VALUES (?, 1, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?)""",
            (
                reservation_id, job_id, scope, owner_id, int(fence_token), current,
                current, expiry, _json(request), _json(admission_obj),
            ),
        )
        self._append_event_tx(
            cursor,
            "reservation_created",
            job_id=job_id,
            owner_id=owner_id,
            fence_token=fence_token,
            payload={
                "reservation_id": reservation_id,
                "resource_request": request,
                "admission": admission_obj,
            },
        )
        if provenance_event is not None:
            self._append_provenance_event_tx(cursor, provenance_event)
        return self._decode_reservation_row(
            cursor.execute(
                "SELECT * FROM reservations WHERE reservation_id = ?", (reservation_id,)
            ).fetchone()
        ) or {}

    def reserve_resources(
        self,
        job_id: str,
        owner_id: str,
        fence_token: int,
        resource_request: Mapping[str, Any] | None,
        *,
        admission: Mapping[str, Any] | None = None,
        capacity: Mapping[str, Any] | None = None,
        host_capacity: Mapping[str, Any] | None = None,
        pool_capacity: Mapping[str, Any] | None = None,
        ttl_seconds: int | float = DEFAULT_LEASE_TTL_SECONDS,
        scope: str = DEFAULT_LEASE_SCOPE,
        reservation_id: str | None = None,
        provenance_event: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create one fenced reservation before a job is claimed.

        Capacity arithmetic is supplied by the Resource Governor or a remote
        host probe.  When ``capacity`` (or an explicit host/pool capacity) is
        supplied, the aggregate check and INSERT happen in this same
        ``BEGIN IMMEDIATE`` transaction.  A second controller therefore sees
        the first reservation before deciding whether the next lane fits.
        Omitting capacity preserves the migration-compatible reservation-only
        behavior; the store never guesses host capacity from an absent probe.
        """
        request, admission_obj, capacity = self._prepare_reservation_inputs(
            resource_request, admission, capacity
        )
        current = utc_now()
        expiry = self._lease_expiry(ttl_seconds, now=current)
        rid = str(reservation_id or _new_id("reservation"))
        with self._transaction() as cursor:
            self._assert_lease_tx(cursor, scope, owner_id, int(fence_token), now=current)
            return self._reserve_resources_tx(
                cursor,
                job_id=job_id,
                owner_id=owner_id,
                fence_token=int(fence_token),
                request=request,
                admission_obj=admission_obj,
                capacity=capacity,
                host_capacity=host_capacity,
                pool_capacity=pool_capacity,
                current=current,
                expiry=expiry,
                scope=scope,
                reservation_id=rid,
                provenance_event=provenance_event,
            )

    def reserve_and_claim_job(
        self,
        job_id: str,
        owner_id: str,
        fence_token: int,
        resource_request: Mapping[str, Any] | None,
        *,
        admission: Mapping[str, Any] | None = None,
        capacity: Mapping[str, Any] | None = None,
        host_capacity: Mapping[str, Any] | None = None,
        pool_capacity: Mapping[str, Any] | None = None,
        lease_ttl_seconds: int | float = DEFAULT_LEASE_TTL_SECONDS,
        scope: str = DEFAULT_LEASE_SCOPE,
        reservation_id: str | None = None,
        provenance_event: Mapping[str, Any] | None = None,
        governor_state: Mapping[str, Any] | None = None,
        governor_policy: Mapping[str, Any] | None = None,
        governor_observed_at_utc: str | None = None,
    ) -> dict[str, Any] | None:
        """Atomically reserve and claim one queued resource-bearing job.

        The old controller path committed a reservation and then issued a
        second transaction for ``claim_jobs``.  That left a narrow crash/race
        window where a durable promise existed without its attempt.  This
        method binds reservation creation, ``job_claimed`` and attempt events
        in one ``BEGIN IMMEDIATE`` transaction.  When ``governor_state`` is
        supplied, its fenced hysteresis update is committed in this same
        transaction as well; a failed reservation or claim rolls back all
        three pieces together.  It is intentionally a single-job primitive so
        the admission evidence remains easy to audit.
        """
        request, admission_obj, capacity = self._prepare_reservation_inputs(
            resource_request, admission, capacity
        )
        current = utc_now()
        expiry = self._lease_expiry(lease_ttl_seconds, now=current)
        rid = str(reservation_id or _new_id("reservation"))
        with self._transaction() as cursor:
            self._assert_lease_tx(cursor, scope, owner_id, int(fence_token), now=current)
            row = cursor.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
            if row is None:
                raise JobTransitionError(f"job {job_id!r} does not exist")
            runnable = str(row["status"]) == "queued" or (
                str(row["status"]) == "retry"
                and (row["retry_at_utc"] is None or _is_expired(row["retry_at_utc"], now=current))
            )
            if not runnable:
                return None
            reservation = self._reserve_resources_tx(
                cursor,
                job_id=job_id,
                owner_id=owner_id,
                fence_token=int(fence_token),
                request=request,
                admission_obj=admission_obj,
                capacity=capacity,
                host_capacity=host_capacity,
                pool_capacity=pool_capacity,
                current=current,
                expiry=expiry,
                scope=scope,
                reservation_id=rid,
                provenance_event=provenance_event,
            )
            # Re-read after the reservation helper, because an idempotent
            # reservation may have returned an existing row.
            current_row = cursor.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
            assert current_row is not None
            if not self._reservation_is_claimable_tx(
                cursor,
                current_row,
                owner_id=owner_id,
                fence_token=int(fence_token),
                scope=scope,
                current=current,
                require_reservation=True,
            ):
                raise ReservationAdmissionError("reservation is not claimable under current fence")
            claim = self._claim_row_tx(
                cursor,
                current_row,
                owner_id=owner_id,
                fence_token=int(fence_token),
                lease_ttl_seconds=lease_ttl_seconds,
                scope=scope,
                current=current,
            )
            if governor_state is not None:
                self._put_governor_state_tx(
                    cursor,
                    governor_state,
                    policy=governor_policy,
                    observed_at_utc=governor_observed_at_utc,
                    scope=scope,
                    owner_id=owner_id,
                    fence_token=int(fence_token),
                    current=current,
                )
            return {"reservation": reservation, "claim": claim}

    create_reservation = reserve_resources

    def heartbeat_reservation(
        self,
        job_id: str,
        owner_id: str,
        fence_token: int,
        *,
        ttl_seconds: int | float = DEFAULT_LEASE_TTL_SECONDS,
        scope: str = DEFAULT_LEASE_SCOPE,
    ) -> dict[str, Any]:
        current = utc_now()
        expiry = self._lease_expiry(ttl_seconds, now=current)
        with self._transaction() as cursor:
            self._assert_lease_tx(cursor, scope, owner_id, int(fence_token), now=current)
            row = cursor.execute(
                """SELECT * FROM reservations
                   WHERE job_id = ? AND scope = ? AND status = 'active'""",
                (job_id, scope),
            ).fetchone()
            if (
                row is None
                or str(row["owner_id"] or "") != str(owner_id)
                or int(row["fence_token"] or 0) != int(fence_token)
                or _is_expired(row["lease_expires_at_utc"], now=current)
            ):
                raise FencingError(f"stale or missing reservation for job {job_id!r}")
            cursor.execute(
                """UPDATE reservations SET updated_at_utc = ?, lease_expires_at_utc = ?
                   WHERE reservation_id = ? AND status = 'active'""",
                (current, expiry, row["reservation_id"]),
            )
            return self._decode_reservation_row(
                cursor.execute("SELECT * FROM reservations WHERE reservation_id = ?", (row["reservation_id"],)).fetchone()
            ) or {}

    def release_reservation(
        self,
        job_id: str,
        owner_id: str,
        fence_token: int,
        *,
        reason: str = "released",
        scope: str = DEFAULT_LEASE_SCOPE,
    ) -> int:
        current = utc_now()
        with self._transaction() as cursor:
            self._assert_lease_tx(cursor, scope, owner_id, int(fence_token), now=current)
            count = self._release_reservation_tx(
                cursor, job_id, owner_id=owner_id, fence_token=int(fence_token),
                reason=str(reason), current=current,
            )
            if count:
                self._append_event_tx(
                    cursor, "reservation_released", job_id=job_id,
                    owner_id=owner_id, fence_token=fence_token,
                    payload={"reason": str(reason)},
                )
            return count

    def list_reservations(
        self,
        job_id: str | None = None,
        *,
        statuses: Sequence[str] | None = None,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if job_id is not None:
            clauses.append("job_id = ?")
            params.append(str(job_id))
        if statuses:
            placeholders = ",".join("?" for _ in statuses)
            clauses.append(f"status IN ({placeholders})")
            params.extend(str(item) for item in statuses)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self._conn.execute(
            f"SELECT * FROM reservations{where} ORDER BY created_at_utc, reservation_id",
            tuple(params),
        ).fetchall()
        return [self._decode_reservation_row(row) or {} for row in rows]

    def active_resource_totals(self, *, scope: str = DEFAULT_LEASE_SCOPE) -> dict[str, float]:
        """Return conservative sums for active, non-expired reservations."""
        now = utc_now()
        totals: dict[str, float] = {}
        for row in self.list_reservations(statuses=("active",)):
            if str(row.get("scope")) != str(scope) or _is_expired(row.get("lease_expires_at_utc"), now=now):
                continue
            for key, value in dict(row.get("resource_request") or {}).items():
                if isinstance(value, (int, float)):
                    totals[key] = totals.get(key, 0.0) + float(value)
        return totals

    def get_governor_state(self, *, scope: str = DEFAULT_LEASE_SCOPE) -> dict[str, Any]:
        """Return the persisted hysteresis state for a controller scope."""
        row = self._conn.execute(
            "SELECT state_json FROM governor_state WHERE scope = ?", (scope,)
        ).fetchone()
        state = _decode(row[0], {}) if row is not None else {}
        return dict(state) if isinstance(state, Mapping) else {}

    def list_governor_states(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT scope, schema_version, state_json, policy_json, observed_at_utc, updated_at_utc, owner_id, fence_token FROM governor_state ORDER BY scope"
        ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["state"] = _decode(item.pop("state_json"), {})
            item["policy"] = _decode(item.pop("policy_json"), {})
            result.append(item)
        return result

    def _put_governor_state_tx(
        self,
        cursor: sqlite3.Cursor,
        state: Mapping[str, Any],
        *,
        policy: Mapping[str, Any] | None = None,
        observed_at_utc: str | None = None,
        scope: str = DEFAULT_LEASE_SCOPE,
        owner_id: str | None = None,
        fence_token: int | None = None,
        current: str | None = None,
    ) -> dict[str, Any]:
        """Upsert governor state inside a caller-owned SQLite transaction.

        The controller uses this helper from the same transaction that creates
        a reservation and claims a job.  Keeping the write primitive private
        prevents callers from accidentally committing the governor decision
        between admission and claim.  Identical state updates are no-ops so a
        controller's post-claim compatibility write does not create duplicate
        audit events.
        """
        if (owner_id is None) != (fence_token is None):
            raise FencingError("owner_id and fence_token must be supplied together")
        state_obj = dict(state)
        policy_obj = dict(policy or {})
        self._reject_provenance_secrets(state_obj, path="governor.state")
        self._reject_provenance_secrets(policy_obj, path="governor.policy")
        now = current or utc_now()
        if owner_id is not None:
            self._assert_lease_tx(cursor, scope, owner_id, int(fence_token), now=now)
        existing = cursor.execute(
            "SELECT * FROM governor_state WHERE scope = ?", (scope,)
        ).fetchone()
        if existing is not None:
            existing_state = _decode(existing["state_json"], {})
            existing_policy = _decode(existing["policy_json"], {})
            if (
                isinstance(existing_state, Mapping)
                and dict(existing_state) == state_obj
                and isinstance(existing_policy, Mapping)
                and dict(existing_policy) == policy_obj
                and existing["observed_at_utc"] == observed_at_utc
                and existing["owner_id"] == owner_id
                and (
                    existing["fence_token"] is None
                    if fence_token is None
                    else int(existing["fence_token"] or 0) == int(fence_token)
                )
            ):
                return self._decode_governor_row(existing) or {}
        cursor.execute(
            """INSERT INTO governor_state
               (scope, schema_version, state_json, policy_json,
                observed_at_utc, updated_at_utc, owner_id, fence_token)
               VALUES (?, 1, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(scope) DO UPDATE SET
                 state_json=excluded.state_json,
                 policy_json=excluded.policy_json,
                 observed_at_utc=excluded.observed_at_utc,
                 updated_at_utc=excluded.updated_at_utc,
                 owner_id=excluded.owner_id,
                 fence_token=excluded.fence_token""",
            (scope, _json(state_obj), _json(policy_obj),
             observed_at_utc, now, owner_id,
             int(fence_token) if fence_token is not None else None),
        )
        if owner_id is not None:
            self._append_event_tx(
                cursor,
                "governor_state_updated",
                owner_id=owner_id,
                fence_token=int(fence_token),
                payload={
                    "scope": scope,
                    "effective_tier": state_obj.get("effective_tier"),
                    "observed_tier": state_obj.get("observed_tier"),
                },
            )
        row = cursor.execute(
            "SELECT * FROM governor_state WHERE scope = ?", (scope,)
        ).fetchone()
        return self._decode_governor_row(row) or {}

    def put_governor_state(
        self,
        state: Mapping[str, Any],
        *,
        policy: Mapping[str, Any] | None = None,
        observed_at_utc: str | None = None,
        scope: str = DEFAULT_LEASE_SCOPE,
        owner_id: str | None = None,
        fence_token: int | None = None,
    ) -> dict[str, Any]:
        """Persist hysteresis state and audit it behind the controller fence."""
        with self._transaction() as cursor:
            return self._put_governor_state_tx(
                cursor,
                state,
                policy=policy,
                observed_at_utc=observed_at_utc,
                scope=scope,
                owner_id=owner_id,
                fence_token=fence_token,
            )

    # ------------------------------------------------------------------
    # Jobs and atomic claim/complete
    # ------------------------------------------------------------------
    def _enqueue_transport_tx(
        self,
        cursor: sqlite3.Cursor,
        envelope: Mapping[str, Any],
        *,
        owner_id: str,
        fence_token: int,
        job_id: str | None = None,
        attempt_id: str | None = None,
        scope: str = DEFAULT_LEASE_SCOPE,
        current: str,
    ) -> dict[str, Any]:
        """Insert one validated metadata-only envelope in the local outbox.

        This helper is called from an existing ``BEGIN IMMEDIATE`` transaction
        (normally the same transaction that creates a job).  It deliberately
        stores only the canonical envelope and a receipt, never a packet,
        prompt, argv, environment, or credential.
        """
        try:
            canonical = _validate_envelope(envelope)
        except _EnvelopeError as exc:
            raise StoreError(f"invalid transport envelope: {exc}") from exc
        request_id = str(canonical["request_id"])
        existing = cursor.execute(
            "SELECT * FROM transport_outbox WHERE request_id = ?", (request_id,)
        ).fetchone()
        if existing is not None:
            existing_envelope = _decode(existing["envelope_json"], {})
            if existing_envelope != canonical:
                raise JobConflict(
                    f"transport request {request_id!r} already exists with different content"
                )
            return self._decode_transport_row(existing) or {}
        cursor.execute(
            """INSERT INTO transport_outbox
               (request_id, schema_version, job_id, attempt_id, target_id, operation,
                packet_digest, payload_digest, envelope_json, status,
                created_at_utc, updated_at_utc, owner_id, fence_token)
               VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?)""",
            (
                request_id,
                job_id,
                attempt_id,
                canonical["target_id"],
                canonical["operation"],
                canonical["packet_digest"],
                canonical["payload_digest"],
                _json(canonical),
                current,
                current,
                owner_id,
                int(fence_token),
            ),
        )
        self._append_event_tx(
            cursor,
            "transport_enqueued",
            job_id=job_id,
            owner_id=owner_id,
            fence_token=int(fence_token),
            payload={
                "request_id": request_id,
                "target_id": canonical["target_id"],
                "operation": canonical["operation"],
                "payload_digest": canonical["payload_digest"],
            },
        )
        return self._decode_transport_row(
            cursor.execute(
                "SELECT * FROM transport_outbox WHERE request_id = ?", (request_id,)
            ).fetchone()
        ) or {}

    def create_job(
        self,
        job_id: str,
        payload: Mapping[str, Any] | None = None,
        *,
        run_id: str | None = None,
        task_id: str | None = None,
        priority: int = 0,
        status: str = "queued",
        owner_id: str | None = None,
        fence_token: int | None = None,
        scope: str = DEFAULT_LEASE_SCOPE,
        provenance_event: Mapping[str, Any] | None = None,
        transport_envelope: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Insert one job idempotently.

        Existing identical payloads return the existing row.  A different
        payload for the same id is a hard conflict, preventing accidental
        queue replacement after a controller restart.
        """

        if not str(job_id).strip():
            raise ValueError("job_id is required")
        if owner_id is not None or fence_token is not None:
            if owner_id is None or fence_token is None:
                raise FencingError("owner_id and fence_token must be supplied together")
        if transport_envelope is not None and (owner_id is None or fence_token is None):
            raise FencingError("transport_envelope requires a controller fence")
        payload_obj = dict(payload or {})
        current = utc_now()
        with self._transaction() as cursor:
            if owner_id is not None:
                self._assert_lease_tx(cursor, scope, owner_id, int(fence_token), now=current)
            existing = cursor.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
            if existing is not None:
                if _decode(existing["payload_json"], {}) != payload_obj:
                    raise JobConflict(f"job {job_id!r} already exists with a different payload")
                if transport_envelope is not None:
                    self._enqueue_transport_tx(
                        cursor,
                        transport_envelope,
                        owner_id=str(owner_id),
                        fence_token=int(fence_token),
                        job_id=str(job_id),
                        current=current,
                        scope=scope,
                    )
                return self._decode_job_row(existing) or {}
            cursor.execute(
                """INSERT INTO jobs
                   (job_id, schema_version, run_id, task_id, status, priority, payload_json,
                    created_at_utc, updated_at_utc, state_revision)
                   VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, 1)""",
                (job_id, run_id, task_id, status, int(priority), _json(payload_obj), current, current),
            )
            self._append_event_tx(
                cursor,
                "job_enqueued",
                job_id=job_id,
                owner_id=owner_id,
                fence_token=fence_token,
                payload={"status": status},
            )
            if provenance_event is not None:
                self._append_provenance_event_tx(cursor, provenance_event)
            if transport_envelope is not None:
                self._enqueue_transport_tx(
                    cursor,
                    transport_envelope,
                    owner_id=str(owner_id),
                    fence_token=int(fence_token),
                    job_id=str(job_id),
                    current=current,
                    scope=scope,
                )
            row = cursor.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
            return self._decode_job_row(row) or {}

    def requeue_job(
        self,
        job_id: str,
        owner_id: str,
        fence_token: int,
        *,
        payload: Mapping[str, Any] | None = None,
        priority: int | None = None,
        reason: str = "replan",
        scope: str = DEFAULT_LEASE_SCOPE,
    ) -> dict[str, Any]:
        """Fencedly put a terminal job back on the queue.

        A monitor/replan cycle deliberately produces a new packet for the
        same logical job.  Treating that packet as an ordinary insert makes a
        failed row either idempotently stay failed or raise ``JobConflict``.
        This explicit transition keeps the old attempts/events for audit,
        replaces only the approved payload, and preserves the attempt counter
        so the next claim receives a new monotonic attempt number.  Completed or running jobs are never requeued by
        this method.
        """

        if not str(job_id).strip():
            raise ValueError("job_id is required")
        if not str(reason).strip():
            raise ValueError("requeue reason is required")
        payload_obj = dict(payload) if payload is not None else None
        current = utc_now()
        with self._transaction() as cursor:
            self._assert_lease_tx(cursor, scope, owner_id, int(fence_token), now=current)
            existing = cursor.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
            if existing is None:
                raise JobTransitionError(f"job {job_id!r} does not exist")
            old_status = str(existing["status"])
            if old_status not in {"failed", "blocked", "pending", "retry"}:
                raise JobTransitionError(
                    f"job {job_id!r} with status {old_status!r} is not requeueable"
                )
            next_payload = (
                payload_obj if payload_obj is not None else _decode(existing["payload_json"], {})
            )
            if isinstance(next_payload, dict):
                # Attempt numbers remain globally monotonic for audit and the
                # UNIQUE(job_id, attempt_no) constraint.  The controller uses
                # this private marker to start the newly approved packet at
                # its first attempt instead of accidentally skipping to the
                # second fallback from the previous packet.
                next_payload["_lad_replan_base_attempt_count"] = int(
                    existing["attempt_count"] or 0
                )
            next_priority = int(existing["priority"] if priority is None else priority)
            cursor.execute(
                """UPDATE jobs SET status = 'queued', priority = ?, payload_json = ?,
                   updated_at_utc = ?, completed_at_utc = NULL, claimed_by = NULL,
                   claim_fence = NULL, lease_expires_at_utc = NULL, retry_at_utc = NULL,
                   error_class = NULL, error_json = NULL, state_revision = state_revision + 1
                   WHERE job_id = ? AND status IN ('failed', 'blocked', 'pending', 'retry')""",
                (next_priority, _json(next_payload), current, job_id),
            )
            if cursor.rowcount != 1:
                raise JobTransitionError(f"job {job_id!r} changed before requeue")
            self._release_reservation_tx(
                cursor,
                job_id,
                reason="job_requeued",
                current=current,
            )
            self._append_event_tx(
                cursor,
                "job_requeued",
                job_id=job_id,
                owner_id=owner_id,
                fence_token=fence_token,
                payload={"from_status": old_status, "reason": str(reason)},
            )
            row = cursor.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
            return self._decode_job_row(row) or {}

    enqueue_job = create_job

    def import_legacy_job(
        self,
        job_id: str,
        attempt_id: str,
        payload: Mapping[str, Any] | None,
        *,
        run_id: str | None = None,
        task_id: str | None = None,
        status: str = "review",
        attempt_payload: Mapping[str, Any] | None = None,
        attempt_status: str = "review",
        attempt_no: int = 1,
        observed_at_utc: str | None = None,
        provenance_event: Mapping[str, Any],
        reconciliation_event: Mapping[str, Any] | None = None,
        owner_id: str,
        fence_token: int,
        scope: str = DEFAULT_LEASE_SCOPE,
    ) -> dict[str, Any]:
        """Atomically import one metadata-only legacy job snapshot.

        This is intentionally a narrow migration seam, not a lifecycle
        replayer.  It creates one synthetic ``review`` attempt and one root
        EventV2 ``attempt.queued`` record.  The legacy status and liveness are
        carried as evidence in the payload/event; no terminal attempt event,
        lease, result, artifact, or completion timestamp is fabricated.

        The controller fence is required because migration writes queue state
        and provenance in one ``BEGIN IMMEDIATE`` transaction.  Re-imports
        with the same stable ids are idempotent; conflicting payloads fail
        closed via ``JobConflict``/``ProvenanceEventConflict``.  When supplied,
        ``reconciliation_event`` must be an ``attempt.abandoned`` or
        ``attempt.review`` child of the imported root event.  This records
        confirmed-dead versus unresolved liveness without fabricating a
        completion, artifact, or successful execution.
        """

        if not str(job_id).strip() or not str(attempt_id).strip():
            raise ValueError("job_id and attempt_id are required")
        if not isinstance(provenance_event, Mapping):
            raise TypeError("provenance_event must be an EventV2 mapping")
        if reconciliation_event is not None and not isinstance(reconciliation_event, Mapping):
            raise TypeError("reconciliation_event must be an EventV2 mapping")
        event_attempt = str(provenance_event.get("attempt_id") or "")
        if event_attempt != str(attempt_id):
            raise ProvenanceEventError(
                "legacy provenance_event.attempt_id must match the imported attempt"
            )
        event_job = provenance_event.get("job_id")
        if event_job is not None and str(event_job) != str(job_id):
            raise ProvenanceEventError(
                "legacy provenance_event.job_id must match the imported job"
            )
        if isinstance(attempt_no, bool) or int(attempt_no) < 1:
            raise ValueError("attempt_no must be a positive integer")
        job_payload = dict(payload or {})
        attempt_obj = dict(attempt_payload or {})
        # The importer is already metadata-only, but keep this public seam
        # fail-closed if a future caller accidentally offers secret material.
        self._reject_provenance_secrets(job_payload)
        self._reject_provenance_secrets(attempt_obj)
        current = utc_now()
        observed = str(observed_at_utc or provenance_event.get("timestamp") or current)

        with self._transaction() as cursor:
            self._assert_lease_tx(cursor, scope, owner_id, int(fence_token), now=current)
            existing = cursor.execute(
                "SELECT * FROM jobs WHERE job_id = ?", (str(job_id),)
            ).fetchone()
            if existing is not None:
                if _decode(existing["payload_json"], {}) != job_payload:
                    raise JobConflict(
                        f"legacy job {job_id!r} already exists with a different payload"
                    )
                if str(existing["run_id"] or "") != str(run_id or ""):
                    raise JobConflict(
                        f"legacy job {job_id!r} already exists with a different run_id"
                    )
                if str(existing["task_id"] or "") != str(task_id or ""):
                    raise JobConflict(
                        f"legacy job {job_id!r} already exists with a different task_id"
                    )
            else:
                cursor.execute(
                    """INSERT INTO jobs
                       (job_id, schema_version, run_id, task_id, status, priority,
                        payload_json, created_at_utc, updated_at_utc, state_revision)
                       VALUES (?, 1, ?, ?, ?, 0, ?, ?, ?, 1)""",
                    (
                        str(job_id),
                        run_id,
                        task_id,
                        str(status),
                        _json(job_payload),
                        observed,
                        observed,
                    ),
                )

            existing_attempt = cursor.execute(
                "SELECT * FROM attempts WHERE attempt_id = ?", (str(attempt_id),)
            ).fetchone()
            if existing_attempt is not None:
                if str(existing_attempt["job_id"]) != str(job_id):
                    raise JobConflict(
                        f"legacy attempt {attempt_id!r} belongs to another job"
                    )
                if int(existing_attempt["attempt_no"] or 0) != int(attempt_no):
                    raise JobConflict(
                        f"legacy attempt {attempt_id!r} already has another attempt_no"
                    )
                if _decode(existing_attempt["payload_json"], {}) != attempt_obj:
                    raise JobConflict(
                        f"legacy attempt {attempt_id!r} already has a different payload"
                    )
            else:
                cursor.execute(
                    """INSERT INTO attempts
                       (attempt_id, schema_version, job_id, attempt_no, status,
                        owner_id, fence_token, lease_expires_at_utc, started_at_utc,
                        payload_json)
                       VALUES (?, 1, ?, ?, ?, NULL, NULL, NULL, ?, ?)""",
                    (
                        str(attempt_id),
                        str(job_id),
                        int(attempt_no),
                        str(attempt_status),
                        observed,
                        _json(attempt_obj),
                    ),
                )
            # The legacy dispatch event table has a foreign key to both the
            # job and attempt rows, so append it only after both metadata rows
            # exist.  The whole import remains one transaction.
            self._append_event_tx(
                cursor,
                "legacy_job_imported",
                event_id=_provenance_events.stable_id(
                    "event", "legacy_job_imported", str(job_id), str(attempt_id)
                ),
                job_id=str(job_id),
                attempt_id=str(attempt_id),
                owner_id=owner_id,
                fence_token=int(fence_token),
                payload={
                    "evidence_quality": "legacy_incomplete",
                    "legacy_status": job_payload.get("legacy_status"),
                    "legacy_liveness": job_payload.get("legacy_liveness", "unknown"),
                    "import_policy": job_payload.get("import_policy"),
                },
            )
            record = self._append_provenance_event_tx(cursor, provenance_event)
            if reconciliation_event is not None:
                child = dict(reconciliation_event)
                if str(child.get("attempt_id") or "") != str(attempt_id):
                    raise ProvenanceEventError(
                        "legacy reconciliation_event.attempt_id must match the imported attempt"
                    )
                if child.get("causal_parent") != record.get("event_id"):
                    raise ProvenanceEventError(
                        "legacy reconciliation_event must be causally parented by attempt.queued"
                    )
                if child.get("event_type") not in {"attempt.abandoned", "attempt.review"}:
                    raise ProvenanceEventError(
                        "legacy reconciliation_event must be attempt.abandoned or attempt.review"
                    )
                self._append_provenance_event_tx(cursor, child)
                # Existing imports may have been created before liveness
                # reconciliation was added.  Upgrade only the synthetic
                # review attempt; never overwrite a real terminal state.
                desired = "abandoned" if child.get("event_type") == "attempt.abandoned" else "review"
                cursor.execute(
                    """UPDATE attempts SET status = ?
                       WHERE attempt_id = ? AND status IN ('review', 'running')""",
                    (desired, str(attempt_id)),
                )
            return {
                "job": self._decode_job_row(
                    cursor.execute(
                        "SELECT * FROM jobs WHERE job_id = ?", (str(job_id),)
                    ).fetchone()
                )
                or {},
                "attempt": self._decode_attempt_row(
                    cursor.execute(
                        "SELECT * FROM attempts WHERE attempt_id = ?", (str(attempt_id),)
                    ).fetchone()
                )
                or {},
                "provenance_event": record,
                "idempotent": existing is not None and existing_attempt is not None,
            }

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        row = self._conn.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
        return self._decode_job_row(row)

    def list_transport_outbox(
        self,
        *,
        statuses: Sequence[str] | None = None,
        job_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Read controller-owned transport envelopes without opening SSH."""
        clauses: list[str] = []
        params: list[Any] = []
        if statuses:
            placeholders = ",".join("?" for _ in statuses)
            clauses.append(f"status IN ({placeholders})")
            params.extend(str(item) for item in statuses)
        if job_id is not None:
            clauses.append("job_id = ?")
            params.append(str(job_id))
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self._conn.execute(
            f"SELECT * FROM transport_outbox{where} ORDER BY created_at_utc, request_id",
            tuple(params),
        ).fetchall()
        return [self._decode_transport_row(row) or {} for row in rows]

    @staticmethod
    def _normalize_transport_receipt(
        request_id: str,
        receipt: Mapping[str, Any],
    ) -> tuple[str, dict[str, Any]]:
        """Validate and reduce a remote receipt before it enters a transaction."""

        request_id = str(request_id)
        if not request_id or not isinstance(receipt, Mapping):
            raise StoreError("request_id and receipt are required")
        status = str(receipt.get("status") or "")
        if status not in {"accepted", "completed", "failed"}:
            raise StoreError("transport receipt status is invalid")
        if status == "completed" and not receipt.get("result_digest"):
            raise StoreError("completed transport receipt requires result_digest")
        if status == "failed" and not receipt.get("error_code"):
            raise StoreError("failed transport receipt requires error_code")
        safe_receipt = {
            key: receipt[key]
            for key in (
                "schema_version", "receipt_version", "request_id", "idempotency_key",
                "payload_digest", "status", "effect_count", "result_digest",
                "error_code", "receipt_digest", "observed_at",
                # Execution-stage evidence is deliberately flat and
                # allow-listed.  It lets the controller distinguish the
                # worker's envelope acceptance from a PBS submission/status
                # receipt without persisting arbitrary remote JSON.
                "executor", "executor_stage", "pbs_job_id", "run_root",
                "submission_digest", "worker_receipt_digest",
                # The fixed PBS wrapper checks the submitting controller
                # owner on later status reads.  This is a bounded opaque id,
                # not a credential, and is required for cross-lease
                # reconciliation.
                "pbs_owner_id",
                "provider_execution", "network_execution",
                "run_id", "segment_id", "sequence", "manifest_digest", "capsule_digest",
                # Terminal promotion evidence is carried only after the PBS
                # wrapper has independently rehashed the declared artifacts.
                # Keep both fields nested and allow-listed so arbitrary remote
                # JSON never enters the controller ledger.
                "artifact_manifest", "validation",
            )
            if key in receipt
        }
        return status, safe_receipt

    def _record_transport_receipt_tx(
        self,
        cursor: sqlite3.Cursor,
        request_id: str,
        status: str,
        safe_receipt: Mapping[str, Any],
        *,
        owner_id: str,
        fence_token: int,
        scope: str,
        current: str,
    ) -> tuple[sqlite3.Row, bool]:
        """Record a receipt inside a caller-owned transaction.

        The boolean reports whether this call changed the outbox row.  A
        matching terminal replay is returned unchanged so a caller can still
        complete a parent attempt that was interrupted after the transport
        write but before lifecycle promotion.
        """

        self._assert_lease_tx(cursor, scope, owner_id, int(fence_token), now=current)
        row = cursor.execute(
            "SELECT * FROM transport_outbox WHERE request_id = ?", (request_id,)
        ).fetchone()
        if row is None:
            raise JobTransitionError(f"transport request {request_id!r} does not exist")
        envelope = _decode(row["envelope_json"], {})
        if str(safe_receipt.get("request_id") or request_id) != request_id:
            raise StoreError("transport receipt request_id mismatch")
        if safe_receipt.get("payload_digest") not in {None, envelope.get("payload_digest")}:
            raise StoreError("transport receipt payload_digest mismatch")
        old_status = str(row["status"])
        if old_status in {"completed", "failed"}:
            old_receipt = _decode(row["receipt_json"], {})
            if old_receipt != dict(safe_receipt):
                raise JobConflict("transport request already has a conflicting terminal receipt")
            return row, False
        if status == "accepted" and old_status not in {"pending", "accepted"}:
            raise JobTransitionError("transport receipt transition is invalid")
        cursor.execute(
            """UPDATE transport_outbox
               SET status = ?, updated_at_utc = ?, sent_at_utc = COALESCE(sent_at_utc, ?),
                   completed_at_utc = CASE WHEN ? IN ('completed', 'failed') THEN ? ELSE completed_at_utc END,
                   receipt_json = ?
               WHERE request_id = ?""",
            (
                status,
                current,
                current,
                status,
                current,
                _json(safe_receipt),
                request_id,
            ),
        )
        self._append_event_tx(
            cursor,
            "transport_receipt",
            job_id=row["job_id"],
            owner_id=owner_id,
            fence_token=int(fence_token),
            payload={
                "request_id": request_id,
                "status": status,
                "receipt_digest": safe_receipt.get("receipt_digest"),
            },
        )
        updated = cursor.execute(
            "SELECT * FROM transport_outbox WHERE request_id = ?", (request_id,)
        ).fetchone()
        assert updated is not None
        return updated, True

    def bind_transport_attempt(
        self,
        request_id: str,
        job_id: str,
        attempt_id: str,
        owner_id: str,
        fence_token: int,
        *,
        scope: str = DEFAULT_LEASE_SCOPE,
    ) -> dict[str, Any]:
        """Bind an outbox row to a running, fenced parent attempt.

        Job creation may persist a transport envelope before the controller
        has generated its SQLite attempt id.  This explicit binding closes
        that gap without rewriting the immutable envelope or its digest.
        """

        request_id = str(request_id)
        job_id = str(job_id)
        attempt_id = str(attempt_id)
        if not request_id or not job_id or not attempt_id:
            raise ValueError("request_id, job_id, and attempt_id are required")
        current = utc_now()
        with self._transaction() as cursor:
            self._assert_lease_tx(cursor, scope, owner_id, int(fence_token), now=current)
            row = cursor.execute(
                "SELECT * FROM transport_outbox WHERE request_id = ?", (request_id,)
            ).fetchone()
            if row is None:
                raise JobTransitionError(f"transport request {request_id!r} does not exist")
            if str(row["job_id"] or "") != job_id:
                raise JobTransitionError("transport request belongs to another job")
            existing_attempt = str(row["attempt_id"] or "")
            if existing_attempt and existing_attempt != attempt_id:
                raise JobConflict("transport request is already bound to another attempt")
            job = cursor.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
            attempt = cursor.execute(
                "SELECT * FROM attempts WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            if job is None or attempt is None or str(attempt["job_id"]) != job_id:
                raise JobTransitionError("job or attempt does not exist")
            if (
                str(job["status"]) != "running"
                or str(job["claimed_by"] or "") != str(owner_id)
                or int(job["claim_fence"] or 0) != int(fence_token)
                or str(attempt["status"]) != "running"
                or str(attempt["owner_id"] or "") != str(owner_id)
                or int(attempt["fence_token"] or 0) != int(fence_token)
            ):
                raise FencingError("job attempt is not owned by the supplied controller fence")
            if not existing_attempt:
                cursor.execute(
                    "UPDATE transport_outbox SET attempt_id = ?, updated_at_utc = ? WHERE request_id = ?",
                    (attempt_id, current, request_id),
                )
                self._append_event_tx(
                    cursor,
                    "transport_attempt_bound",
                    job_id=job_id,
                    attempt_id=attempt_id,
                    owner_id=owner_id,
                    fence_token=int(fence_token),
                    payload={"request_id": request_id, "attempt_id": attempt_id},
                )
            updated = cursor.execute(
                "SELECT * FROM transport_outbox WHERE request_id = ?", (request_id,)
            ).fetchone()
            assert updated is not None
            return self._decode_transport_row(updated) or {}

    def record_transport_receipt(
        self,
        request_id: str,
        receipt: Mapping[str, Any],
        *,
        owner_id: str,
        fence_token: int,
        scope: str = DEFAULT_LEASE_SCOPE,
    ) -> dict[str, Any]:
        """Fencedly record an accepted/terminal remote receipt.

        The receipt is intentionally reduced to the allow-listed fields used
        for idempotency and outcome evidence.  A conflicting terminal receipt
        is never overwritten.
        """
        status, safe_receipt = self._normalize_transport_receipt(request_id, receipt)
        current = utc_now()
        with self._transaction() as cursor:
            row, _ = self._record_transport_receipt_tx(
                cursor,
                str(request_id),
                status,
                safe_receipt,
                owner_id=owner_id,
                fence_token=int(fence_token),
                scope=scope,
                current=current,
            )
            return self._decode_transport_row(row) or {}

    def record_transport_receipt_and_complete(
        self,
        request_id: str,
        receipt: Mapping[str, Any],
        *,
        owner_id: str,
        fence_token: int,
        validation: Mapping[str, Any] | None = None,
        artifact_manifest: Any | None = None,
        result: Any | None = None,
        error_class: str | None = None,
        error: Any = None,
        scope: str = DEFAULT_LEASE_SCOPE,
    ) -> dict[str, Any]:
        """Record a terminal receipt and finish its bound attempt atomically.

        This is an explicit promotion API.  A completed transport receipt is
        not enough by itself: the outbox must be bound to a currently running
        attempt under the same controller fence, and successful promotion must
        carry a passing validation record plus an artifact manifest.  Unbound
        legacy envelopes remain transport-only through
        :meth:`record_transport_receipt`.
        """

        status, safe_receipt = self._normalize_transport_receipt(request_id, receipt)
        if status not in {"completed", "failed"}:
            raise StoreError("lifecycle promotion requires a terminal transport receipt")
        if status == "completed":
            if not isinstance(validation, Mapping) or validation.get("ok") is not True:
                raise StoreError("completed transport promotion requires validation.ok=true")
            if artifact_manifest is None:
                raise StoreError("completed transport promotion requires artifact_manifest")
        current = utc_now()
        with self._transaction() as cursor:
            row, receipt_changed = self._record_transport_receipt_tx(
                cursor,
                str(request_id),
                status,
                safe_receipt,
                owner_id=owner_id,
                fence_token=int(fence_token),
                scope=scope,
                current=current,
            )
            job_id = str(row["job_id"] or "")
            attempt_id = str(row["attempt_id"] or "")
            if not job_id or not attempt_id:
                raise JobTransitionError(
                    "terminal transport receipt is not bound to a parent job attempt"
                )
            job = cursor.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
            attempt = cursor.execute(
                "SELECT * FROM attempts WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            if job is None or attempt is None or str(attempt["job_id"]) != job_id:
                raise JobTransitionError("bound parent job or attempt does not exist")
            if str(attempt["status"]) in {"completed", "failed", "retry"}:
                if str(job["status"]) != str(attempt["status"]):
                    raise JobTransitionError("bound job and attempt have conflicting terminal states")
                return {
                    "transport": self._decode_transport_row(row) or {},
                    "job": self._decode_job_row(job) or {},
                    "attempt": self._decode_attempt_row(attempt) or {},
                    "lifecycle_promoted": True,
                    "idempotent": True,
                    "receipt_changed": receipt_changed,
                }
            if (
                str(job["status"]) != "running"
                or str(job["claimed_by"] or "") != str(owner_id)
                or int(job["claim_fence"] or 0) != int(fence_token)
                or str(attempt["status"]) != "running"
                or str(attempt["owner_id"] or "") != str(owner_id)
                or int(attempt["fence_token"] or 0) != int(fence_token)
            ):
                raise FencingError("bound job attempt is owned by a different controller fence")
            success = status == "completed"
            terminal_status = "completed" if success else "failed"
            terminal_error_class = None if success else (error_class or "remote_transport_failed")
            terminal_error = None if success else (
                error if error is not None else {
                    "error_code": safe_receipt.get("error_code"),
                    "request_id": str(request_id),
                }
            )
            terminal_result = result if result is not None else {
                "transport_request_id": str(request_id),
                "receipt_digest": safe_receipt.get("receipt_digest"),
                "result_digest": safe_receipt.get("result_digest"),
                "pbs_job_id": safe_receipt.get("pbs_job_id"),
            }
            cursor.execute(
                """UPDATE attempts SET status = ?, finished_at_utc = ?, result_json = ?,
                   artifact_manifest_json = ?, validation_json = ?, error_class = ?, error_json = ?,
                   lease_expires_at_utc = NULL
                   WHERE attempt_id = ? AND status = 'running' AND owner_id = ? AND fence_token = ?""",
                (
                    terminal_status,
                    current,
                    _json(terminal_result) if terminal_result is not None else None,
                    _json(artifact_manifest) if artifact_manifest is not None else None,
                    _json(validation) if validation is not None else None,
                    terminal_error_class,
                    _json(terminal_error) if terminal_error is not None else None,
                    attempt_id,
                    owner_id,
                    int(fence_token),
                ),
            )
            cursor.execute(
                """UPDATE jobs SET status = ?, updated_at_utc = ?, completed_at_utc = ?,
                   claimed_by = NULL, claim_fence = NULL, lease_expires_at_utc = NULL,
                   retry_at_utc = NULL, error_class = ?, error_json = ?,
                   state_revision = state_revision + 1
                   WHERE job_id = ? AND status = 'running' AND claimed_by = ? AND claim_fence = ?""",
                (
                    terminal_status,
                    current,
                    current if success else None,
                    terminal_error_class,
                    _json(terminal_error) if terminal_error is not None else None,
                    job_id,
                    owner_id,
                    int(fence_token),
                ),
            )
            if cursor.rowcount != 1:
                raise FencingError("job completion lost its controller fence")
            reservation_released = self._release_reservation_tx(
                cursor,
                job_id,
                owner_id=owner_id,
                fence_token=int(fence_token),
                reason="job_terminal",
                current=current,
            )
            self._append_event_tx(
                cursor,
                "job_completed" if success else "job_failed",
                job_id=job_id,
                attempt_id=attempt_id,
                owner_id=owner_id,
                fence_token=int(fence_token),
                payload={
                    "success": success,
                    "retryable": False,
                    "transport_request_id": str(request_id),
                    "receipt_digest": safe_receipt.get("receipt_digest"),
                    "reservation_released": reservation_released,
                },
            )
            parent = self._latest_provenance_event_id_tx(cursor, attempt_id)
            terminal_event = self._automatic_attempt_event(
                event_type="attempt.completed" if success else "attempt.failed",
                attempt_id=attempt_id,
                parent=parent,
                job_id=job_id,
                timestamp=current,
                outcome="passed" if success else "failed",
                error_class=terminal_error_class,
                retryable=False,
            )
            self._append_provenance_event_tx(cursor, terminal_event)
            updated_job = cursor.execute(
                "SELECT * FROM jobs WHERE job_id = ?", (job_id,)
            ).fetchone()
            updated_attempt = cursor.execute(
                "SELECT * FROM attempts WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            updated_transport = cursor.execute(
                "SELECT * FROM transport_outbox WHERE request_id = ?", (str(request_id),)
            ).fetchone()
            assert updated_job is not None and updated_attempt is not None and updated_transport is not None
            return {
                "transport": self._decode_transport_row(updated_transport) or {},
                "job": self._decode_job_row(updated_job) or {},
                "attempt": self._decode_attempt_row(updated_attempt) or {},
                "lifecycle_promoted": True,
                "idempotent": False,
                "receipt_changed": receipt_changed,
            }

    def list_jobs(self, *, statuses: Sequence[str] | None = None) -> list[dict[str, Any]]:
        if statuses:
            placeholders = ",".join("?" for _ in statuses)
            rows = self._conn.execute(
                f"SELECT * FROM jobs WHERE status IN ({placeholders}) ORDER BY priority DESC, created_at_utc, job_id",
                tuple(str(item) for item in statuses),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM jobs ORDER BY priority DESC, created_at_utc, job_id"
            ).fetchall()
        return [self._decode_job_row(row) or {} for row in rows]

    def next_retry_at_utc(self, *, now: str | None = None) -> str | None:
        """Return the earliest valid future retry wake for this queue.

        A durable controller may keep a queue alive for many hours.  Without
        a persisted wake hint, a transiently failed job would be scanned on
        every short poll even though its ``retry_at_utc`` is still in the
        future.  Ignore malformed timestamps rather than letting lexical
        SQLite ordering turn corrupt state into a long sleep; the normal
        claim path remains the authority for eligibility.
        """

        current = _parse_time(now) or _datetime.datetime.now(_datetime.timezone.utc)
        rows = self._conn.execute(
            """SELECT retry_at_utc FROM jobs
               WHERE status = 'retry' AND retry_at_utc IS NOT NULL"""
        ).fetchall()
        candidates: list[tuple[_datetime.datetime, str]] = []
        for row in rows:
            raw = str(row[0] or "")
            parsed = _parse_time(raw)
            if parsed is not None and parsed > current:
                candidates.append((parsed, raw))
        if not candidates:
            return None
        return min(candidates, key=lambda item: item[0])[1]

    def expired_running_jobs(self, *, now: str | None = None) -> list[dict[str, Any]]:
        """Return running jobs whose durable lease has expired.

        This is a read-only handoff used by the controller to collect explicit
        process-liveness evidence before recovery.  The store deliberately
        does not inspect PIDs or execute host commands itself.
        """

        current = now or utc_now()
        rows = self._conn.execute(
            """SELECT * FROM jobs WHERE status = 'running'
               AND (lease_expires_at_utc IS NULL OR lease_expires_at_utc <= ?)
               ORDER BY priority DESC, created_at_utc, job_id""",
            (current,),
        ).fetchall()
        records: list[dict[str, Any]] = []
        for row in rows:
            job = self._decode_job_row(row) or {}
            attempts = self.list_attempts(str(row["job_id"]))
            running = [item for item in attempts if str(item.get("status")) == "running"]
            records.append({"job": job, "attempt": running[-1] if running else None})
        return records

    def _claim_row_tx(
        self,
        cursor: sqlite3.Cursor,
        row: sqlite3.Row,
        *,
        owner_id: str,
        fence_token: int,
        lease_ttl_seconds: int | float,
        scope: str,
        current: str,
        provenance_event: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        job_id = str(row["job_id"])
        old_status = str(row["status"])
        attempt_no = int(row["attempt_count"] or 0) + 1
        attempt_id = _new_id("attempt")
        expiry = self._lease_expiry(lease_ttl_seconds, now=current)
        if old_status == "running":
            cursor.execute(
                """UPDATE attempts SET status = 'abandoned', finished_at_utc = ?,
                   error_class = COALESCE(error_class, 'controller_restarted')
                   WHERE job_id = ? AND status = 'running'""",
                (current, job_id),
            )
        updated = cursor.execute(
            """UPDATE jobs SET status = 'running', claimed_by = ?, claim_fence = ?,
               lease_expires_at_utc = ?, attempt_count = ?, updated_at_utc = ?,
               retry_at_utc = NULL, state_revision = state_revision + 1,
               error_class = NULL, error_json = NULL
               WHERE job_id = ? AND (status = 'queued'
                  OR status = 'retry' AND (retry_at_utc IS NULL OR retry_at_utc <= ?))""",
            (owner_id, int(fence_token), expiry, attempt_no, current, job_id, current),
        )
        if updated.rowcount != 1:
            raise JobTransitionError(f"job {job_id!r} is no longer claimable")
        cursor.execute(
            """INSERT INTO attempts
               (attempt_id, schema_version, job_id, attempt_no, status, owner_id, fence_token,
                lease_expires_at_utc, started_at_utc, payload_json)
               VALUES (?, 1, ?, ?, 'running', ?, ?, ?, ?, ?)""",
            (attempt_id, job_id, attempt_no, owner_id, int(fence_token), expiry, current, row["payload_json"]),
        )
        self._append_event_tx(
            cursor,
            "job_claimed",
            job_id=job_id,
            attempt_id=attempt_id,
            owner_id=owner_id,
            fence_token=fence_token,
            payload={"attempt_no": attempt_no, "reclaimed": old_status == "running", "scope": scope},
        )
        if provenance_event is not None:
            expected_attempt = str(provenance_event.get("attempt_id") or "")
            if expected_attempt != attempt_id:
                raise ProvenanceEventError(
                    "claim provenance_event.attempt_id must match the durable attempt id"
                )
            self._append_provenance_event_tx(cursor, provenance_event)
        else:
            parent: str | None = None
            reservation = cursor.execute(
                """SELECT reservation_id FROM reservations
                   WHERE job_id = ? AND scope = ? AND status = 'active'
                   ORDER BY created_at_utc DESC LIMIT 1""",
                (job_id, scope),
            ).fetchone()
            if reservation is not None:
                reserved = self._automatic_attempt_event(
                    event_type="attempt.reserved",
                    attempt_id=attempt_id,
                    parent=None,
                    job_id=job_id,
                    timestamp=current,
                    reservation_id=str(reservation["reservation_id"]),
                )
                self._append_provenance_event_tx(cursor, reserved)
                parent = str(reserved["event_id"])
            claimed_event = self._automatic_attempt_event(
                event_type="attempt.claimed",
                attempt_id=attempt_id,
                parent=parent,
                job_id=job_id,
                timestamp=current,
                attempt_no=attempt_no,
                scope=scope,
            )
            self._append_provenance_event_tx(cursor, claimed_event)
        claimed = cursor.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
        return {
            "job": self._decode_job_row(claimed),
            "attempt": self._decode_attempt_row(
                cursor.execute("SELECT * FROM attempts WHERE attempt_id = ?", (attempt_id,)).fetchone()
            ),
        }

    def _reservation_is_claimable_tx(
        self,
        cursor: sqlite3.Cursor,
        row: sqlite3.Row,
        *,
        owner_id: str,
        fence_token: int,
        scope: str,
        current: str,
        require_reservation: bool,
    ) -> bool:
        payload = _decode(row["payload_json"], {})
        if not isinstance(payload, Mapping) or not self._job_requires_reservation_payload(payload):
            return True
        if not require_reservation:
            return True
        reservation = cursor.execute(
            """SELECT 1 FROM reservations
               WHERE job_id = ? AND scope = ? AND status = 'active'
                 AND owner_id = ? AND fence_token = ?
                 AND lease_expires_at_utc > ?""",
            (row["job_id"], scope, owner_id, int(fence_token), current),
        ).fetchone()
        return reservation is not None

    def claim_job(
        self,
        job_id: str,
        owner_id: str,
        fence_token: int,
        *,
        lease_ttl_seconds: int | float = DEFAULT_LEASE_TTL_SECONDS,
        scope: str = DEFAULT_LEASE_SCOPE,
        require_reservation: bool = False,
        provenance_event: Mapping[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        current = utc_now()
        with self._transaction() as cursor:
            self._assert_lease_tx(cursor, scope, owner_id, int(fence_token), now=current)
            row = cursor.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
            if row is None:
                return None
            runnable = str(row["status"]) == "queued" or (
                str(row["status"]) == "retry"
                and (row["retry_at_utc"] is None or _is_expired(
                    row["retry_at_utc"], now=current
                ))
            )
            if not runnable:
                return None
            if not self._reservation_is_claimable_tx(
                cursor, row, owner_id=owner_id, fence_token=int(fence_token),
                scope=scope, current=current, require_reservation=require_reservation,
            ):
                return None
            return self._claim_row_tx(
                cursor,
                row,
                owner_id=owner_id,
                fence_token=int(fence_token),
                lease_ttl_seconds=lease_ttl_seconds,
                scope=scope,
                current=current,
                provenance_event=provenance_event,
            )

    def claim_next_job(
        self,
        owner_id: str,
        fence_token: int,
        *,
        lease_ttl_seconds: int | float = DEFAULT_LEASE_TTL_SECONDS,
        scope: str = DEFAULT_LEASE_SCOPE,
        require_reservation: bool = False,
    ) -> dict[str, Any] | None:
        claimed = self.claim_jobs(
            owner_id,
            fence_token,
            max_jobs=1,
            lease_ttl_seconds=lease_ttl_seconds,
            scope=scope,
            require_reservation=require_reservation,
        )
        return claimed[0] if claimed else None

    def claim_jobs(
        self,
        owner_id: str,
        fence_token: int,
        *,
        max_jobs: int = 1,
        lease_ttl_seconds: int | float = DEFAULT_LEASE_TTL_SECONDS,
        scope: str = DEFAULT_LEASE_SCOPE,
        require_reservation: bool = False,
        provenance_events: Mapping[str, Mapping[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Atomically claim up to ``max_jobs`` independent lanes.

        The controller may hand each returned claim to a worker lane while
        keeping one controller lease/fence.  Selection and all claim rows are
        committed in one short ``BEGIN IMMEDIATE`` transaction, so a second
        process (or a restarted controller) cannot receive the same job.  The
        legacy ``claim_next_job`` API delegates to this method with
        ``max_jobs=1``.
        """

        if isinstance(max_jobs, bool) or int(max_jobs) < 1:
            raise ValueError("max_jobs must be a positive integer")
        limit = min(int(max_jobs), 1024)
        if provenance_events is not None and not isinstance(provenance_events, Mapping):
            raise TypeError("provenance_events must map job_id to EventV2 records")
        current = utc_now()
        with self._transaction() as cursor:
            self._assert_lease_tx(cursor, scope, owner_id, int(fence_token), now=current)
            # Read a bounded candidate window and filter reservation-bearing
            # packets inside the same transaction.  Legacy packets without a
            # resource request remain compatible during migration; planner
            # packets cannot bypass the reservation gate.
            rows = cursor.execute(
                """SELECT * FROM jobs
                   WHERE status = 'queued'
                      OR (status = 'retry' AND
                          (retry_at_utc IS NULL OR retry_at_utc <= ?))
                   ORDER BY priority DESC, created_at_utc, job_id LIMIT ?""",
                (current, min(1024, max(limit, limit * 8))),
            ).fetchall()
            selected: list[sqlite3.Row] = []
            for row in rows:
                if not self._reservation_is_claimable_tx(
                    cursor, row, owner_id=owner_id, fence_token=int(fence_token),
                    scope=scope, current=current, require_reservation=require_reservation,
                ):
                    continue
                selected.append(row)
                if len(selected) >= limit:
                    break
            return [
                self._claim_row_tx(
                    cursor,
                    row,
                    owner_id=owner_id,
                    fence_token=int(fence_token),
                    lease_ttl_seconds=lease_ttl_seconds,
                    scope=scope,
                    current=current,
                    provenance_event=(provenance_events or {}).get(str(row["job_id"])),
                )
                for row in selected
            ]

    # Alternate spelling used by worker-pool adapters.
    claim_next_jobs = claim_jobs

    def complete_job(
        self,
        job_id: str,
        attempt_id: str,
        owner_id: str,
        fence_token: int,
        *,
        success: bool,
        result: Any = None,
        artifact_manifest: Any = None,
        validation: Any = None,
        error_class: str | None = None,
        error: Any = None,
        retryable: bool = False,
        retry_delay_seconds: float | None = None,
        retry_at_utc: str | None = None,
        scope: str = DEFAULT_LEASE_SCOPE,
        provenance_event: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Atomically complete one attempt and its parent job.

        ``success`` is intentionally supplied by the controller after its
        validation/artifact gates.  This layer stores evidence and enforces
        ownership/fencing; it never guesses whether a provider result is valid.
        """

        current = utc_now()
        with self._transaction() as cursor:
            self._assert_lease_tx(cursor, scope, owner_id, int(fence_token), now=current)
            job = cursor.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
            attempt = cursor.execute("SELECT * FROM attempts WHERE attempt_id = ?", (attempt_id,)).fetchone()
            if job is None or attempt is None or str(attempt["job_id"]) != str(job_id):
                raise JobTransitionError("job or attempt does not exist")
            if str(attempt["status"]) != "running":
                # Same-owner duplicate completion is safe and idempotent.  A
                # stale owner still had to pass _assert_lease_tx above.
                if str(attempt["owner_id"] or "") == str(owner_id) and int(attempt["fence_token"] or 0) == int(fence_token):
                    return self._decode_job_row(job) or {}
                raise JobTransitionError(f"attempt {attempt_id!r} is already terminal")
            if (
                str(job["status"]) != "running"
                or str(job["claimed_by"] or "") != str(owner_id)
                or int(job["claim_fence"] or 0) != int(fence_token)
                or str(attempt["owner_id"] or "") != str(owner_id)
                or int(attempt["fence_token"] or 0) != int(fence_token)
            ):
                raise FencingError("job is owned by a different controller fence")
            terminal_status = "completed" if success else ("retry" if retryable else "failed")
            attempt_status = "completed" if success else ("retry" if retryable else "failed")
            next_retry_at = None
            if retryable:
                if retry_at_utc is not None:
                    next_retry_at = str(retry_at_utc)
                elif retry_delay_seconds is not None:
                    next_retry_at = self._lease_expiry(
                        max(0.0, float(retry_delay_seconds)), now=current
                    )
            cursor.execute(
                """UPDATE attempts SET status = ?, finished_at_utc = ?, result_json = ?,
                   artifact_manifest_json = ?, validation_json = ?, error_class = ?, error_json = ?,
                   lease_expires_at_utc = NULL
                   WHERE attempt_id = ? AND status = 'running' AND owner_id = ? AND fence_token = ?""",
                (
                    attempt_status,
                    current,
                    _json(result) if result is not None else None,
                    _json(artifact_manifest) if artifact_manifest is not None else None,
                    _json(validation) if validation is not None else None,
                    error_class,
                    _json(error) if error is not None else None,
                    attempt_id,
                    owner_id,
                    int(fence_token),
                ),
            )
            cursor.execute(
                """UPDATE jobs SET status = ?, updated_at_utc = ?, completed_at_utc = ?,
                   claimed_by = NULL, claim_fence = NULL, lease_expires_at_utc = NULL,
                   retry_at_utc = ?, error_class = ?, error_json = ?,
                   state_revision = state_revision + 1
                   WHERE job_id = ? AND status = 'running' AND claimed_by = ? AND claim_fence = ?""",
                (
                    terminal_status,
                    current,
                    current if success else None,
                    next_retry_at,
                    error_class,
                    _json(error) if error is not None else None,
                    job_id,
                    owner_id,
                    int(fence_token),
                ),
            )
            if cursor.rowcount != 1:
                raise FencingError("job completion lost its controller fence")
            reservation_released = self._release_reservation_tx(
                cursor,
                job_id,
                owner_id=owner_id,
                fence_token=int(fence_token),
                reason="job_terminal" if not retryable else "job_retry",
                current=current,
            )
            self._append_event_tx(
                cursor,
                "job_completed" if success else ("job_retry" if retryable else "job_failed"),
                job_id=job_id,
                attempt_id=attempt_id,
                owner_id=owner_id,
                fence_token=fence_token,
                payload={
                    "success": bool(success),
                    "retryable": bool(retryable),
                    "error_class": error_class,
                    "retry_at_utc": next_retry_at,
                    "reservation_released": reservation_released,
                },
            )
            if provenance_event is not None:
                expected_attempt = str(provenance_event.get("attempt_id") or "")
                if expected_attempt != attempt_id:
                    raise ProvenanceEventError(
                        "complete provenance_event.attempt_id must match the durable attempt id"
                    )
                self._append_provenance_event_tx(cursor, provenance_event)
            else:
                parent = self._latest_provenance_event_id_tx(cursor, attempt_id)
                terminal_event = self._automatic_attempt_event(
                    event_type="attempt.completed" if success else "attempt.failed",
                    attempt_id=attempt_id,
                    parent=parent,
                    job_id=job_id,
                    timestamp=current,
                    outcome="passed" if success else "failed",
                    error_class=error_class,
                    retryable=bool(retryable),
                )
                self._append_provenance_event_tx(cursor, terminal_event)
            updated = cursor.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
            return self._decode_job_row(updated) or {}

    def recover_expired_jobs(
        self,
        owner_id: str,
        fence_token: int,
        *,
        scope: str = DEFAULT_LEASE_SCOPE,
        status: str = "retry",
        liveness_by_job: Mapping[str, str] | None = None,
        strict_liveness: bool = True,
    ) -> int:
        """Recover expired rows only after explicit process-liveness evidence.

        ``dead`` is the only evidence that permits a retry/queue transition
        when ``strict_liveness`` is enabled.  ``alive`` and ``unknown`` become
        a fenced ``blocked`` row requiring review; the store never guesses
        that an expired lease means the provider process has stopped.
        """

        if status not in {"retry", "failed", "queued"}:
            raise ValueError("recovery status must be retry, queued, or failed")
        evidence_map = {str(key): str(value) for key, value in (liveness_by_job or {}).items()}
        invalid = set(evidence_map.values()) - {"dead", "alive", "unknown"}
        if invalid:
            raise ValueError(f"invalid process-liveness evidence: {sorted(invalid)}")
        current = utc_now()
        count = 0
        with self._transaction() as cursor:
            self._assert_lease_tx(cursor, scope, owner_id, int(fence_token), now=current)
            rows = cursor.execute(
                """SELECT job_id FROM jobs WHERE status = 'running'
                   AND (lease_expires_at_utc IS NULL OR lease_expires_at_utc <= ?)""",
                (current,),
            ).fetchall()
            for row in rows:
                job_id = str(row["job_id"])
                evidence = evidence_map.get(job_id, "unknown")
                next_status = status
                error_class = "controller_restarted"
                error_payload: dict[str, Any] = {"status": status, "liveness": evidence}
                event_type = "job_recovered"
                if strict_liveness and evidence != "dead":
                    next_status = "blocked"
                    error_class = (
                        "orphan_process_alive" if evidence == "alive"
                        else "recovery_liveness_unknown"
                    )
                    error_payload = {
                        "status": "blocked",
                        "requested_status": status,
                        "liveness": evidence,
                        "reason": error_class,
                    }
                    event_type = "job_recovery_blocked"
                cursor.execute(
                    """UPDATE attempts SET status = 'abandoned', finished_at_utc = ?,
                       error_class = COALESCE(error_class, ?),
                       lease_expires_at_utc = NULL
                       WHERE job_id = ? AND status = 'running'""",
                    (current, error_class, job_id),
                )
                cursor.execute(
                    """UPDATE jobs SET status = ?, updated_at_utc = ?, claimed_by = NULL,
                       claim_fence = NULL, lease_expires_at_utc = NULL, retry_at_utc = NULL,
                       error_class = ?, error_json = ?, state_revision = state_revision + 1
                       WHERE job_id = ? AND status = 'running'""",
                    (next_status, current, error_class, _json(error_payload), job_id),
                )
                if cursor.rowcount:
                    self._release_reservation_tx(
                        cursor,
                        job_id,
                        reason="recovery",
                        current=current,
                    )
                    count += 1
                    self._append_event_tx(
                        cursor,
                        event_type,
                        job_id=job_id,
                        owner_id=owner_id,
                        fence_token=fence_token,
                        payload=error_payload,
                    )
        return count

    # Names used by restart supervisors in early prototypes.  Keep these
    # aliases so an adapter can migrate without changing its recovery logic.
    recover_stale_jobs = recover_expired_jobs

    # ------------------------------------------------------------------
    # Continuous-run segments, checkpoints, and cleanup intents
    # ------------------------------------------------------------------
    @staticmethod
    def _segment_id(run_id: str, sequence: int, manifest_digest: str) -> str:
        seed = f"{run_id}:{sequence}:{manifest_digest}".encode("utf-8")
        return "segment-" + hashlib.sha256(seed).hexdigest()[:32]

    @staticmethod
    def _checkpoint_id(
        run_id: str,
        job_id: str,
        attempt_id: str,
        sequence: int,
        state_digest: str,
    ) -> str:
        seed = f"{run_id}:{job_id}:{attempt_id}:{sequence}:{state_digest}".encode("utf-8")
        return "checkpoint-" + hashlib.sha256(seed).hexdigest()[:32]

    def _active_segment_tx(
        self,
        cursor: sqlite3.Cursor,
        run_id: str,
        *,
        owner_id: str,
        fence_token: int,
    ) -> sqlite3.Row | None:
        row = cursor.execute(
            """SELECT * FROM run_segments
               WHERE run_id = ? AND status IN ('running', 'closing')
               ORDER BY sequence DESC LIMIT 1""",
            (str(run_id),),
        ).fetchone()
        if row is not None and (
            str(row["owner_id"]) != str(owner_id)
            or int(row["fence_token"]) != int(fence_token)
        ):
            raise FencingError(f"run {run_id!r} is owned by another segment fence")
        return row

    @staticmethod
    def _continuous_event(
        *,
        event_type: str,
        idempotency_key: str,
        timestamp: str,
        run_id: str,
        causal_parent: str | None = None,
        **payload: Any,
    ) -> dict[str, Any]:
        record = _provenance_events.new_event(
            event_type=event_type,
            source="sqlite_store",
            idempotency_key=idempotency_key,
            causal_parent=causal_parent,
            confidence=1.0,
            timestamp=timestamp,
            privacy_class="internal",
            **payload,
        )
        record["run_id"] = str(run_id)
        return record

    def begin_run_segment(
        self,
        run_id: str,
        owner_id: str,
        fence_token: int,
        *,
        sequence: int | None = None,
        manifest_digest: str | None = None,
        capsule_digest: str | None = None,
        scheduler_job_id: str | None = None,
        segment_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        scope: str = DEFAULT_LEASE_SCOPE,
    ) -> dict[str, Any]:
        """Open one bounded scheduler segment behind the controller fence."""

        if not str(run_id).strip() or not str(owner_id).strip():
            raise ValueError("run_id and owner_id are required")
        if isinstance(sequence, bool) or (sequence is not None and (not isinstance(sequence, int) or sequence < 1)):
            raise ValueError("segment sequence must be a positive integer")
        manifest = _continuous_digest(manifest_digest, "manifest_digest", allow_unknown=True)
        capsule = None if capsule_digest is None else _continuous_digest(capsule_digest, "capsule_digest")
        metadata_obj = dict(metadata or {})
        self._reject_provenance_secrets(metadata_obj, path="segment.metadata")
        current = utc_now()
        with self._transaction() as cursor:
            self._assert_lease_tx(cursor, scope, owner_id, int(fence_token), now=current)
            if sequence is None:
                row = cursor.execute(
                    "SELECT COALESCE(MAX(sequence), 0) FROM run_segments WHERE run_id = ?",
                    (str(run_id),),
                ).fetchone()
                sequence = int(row[0] or 0) + 1
            existing = cursor.execute(
                "SELECT * FROM run_segments WHERE run_id = ? AND sequence = ?",
                (str(run_id), int(sequence)),
            ).fetchone()
            if existing is not None:
                compatible = (
                    str(existing["owner_id"]) == str(owner_id)
                    and int(existing["fence_token"]) == int(fence_token)
                    and str(existing["manifest_digest"]) == manifest
                    and (existing["capsule_digest"] or None) == capsule
                )
                if not compatible:
                    raise JobConflict(f"run segment {run_id!r}/{sequence} conflicts with existing metadata")
                return self._decode_segment_row(existing) or {}
            active = self._active_segment_tx(
                cursor, str(run_id), owner_id=owner_id, fence_token=int(fence_token)
            )
            if active is not None:
                raise JobTransitionError(f"run {run_id!r} already has an active segment")
            segment = str(segment_id or self._segment_id(str(run_id), int(sequence), manifest))
            if not segment or any(ch.isspace() for ch in segment):
                raise ValueError("segment_id is invalid")
            cursor.execute(
                """INSERT INTO run_segments
                   (segment_id, run_id, sequence, owner_id, fence_token, status,
                    started_at_utc, scheduler_job_id, manifest_digest, capsule_digest, metadata_json)
                   VALUES (?, ?, ?, ?, ?, 'running', ?, ?, ?, ?, ?)""",
                (
                    segment,
                    str(run_id),
                    int(sequence),
                    str(owner_id),
                    int(fence_token),
                    current,
                    str(scheduler_job_id) if scheduler_job_id else None,
                    manifest,
                    capsule,
                    _json(metadata_obj),
                ),
            )
            self._append_event_tx(
                cursor,
                "segment.started",
                event_id=f"segment-started:{segment}",
                owner_id=owner_id,
                fence_token=int(fence_token),
                payload={
                    "run_id": str(run_id),
                    "segment_id": segment,
                    "sequence": int(sequence),
                    "manifest_digest": manifest,
                    "capsule_digest": capsule,
                },
            )
            event = self._continuous_event(
                event_type="run.segment.started",
                idempotency_key=f"sqlite:segment.started:{segment}",
                timestamp=current,
                run_id=str(run_id),
                segment_id=segment,
                sequence=int(sequence),
                manifest_digest=manifest,
                capsule_digest=capsule,
            )
            self._append_provenance_event_tx(cursor, event)
            return self._decode_segment_row(
                cursor.execute("SELECT * FROM run_segments WHERE segment_id = ?", (segment,)).fetchone()
            ) or {}

    def append_checkpoint(
        self,
        *,
        run_id: str,
        job_id: str,
        attempt_id: str,
        owner_id: str,
        fence_token: int,
        sequence: int | None = None,
        payload_digest: str,
        state_digest: str,
        artifact_manifest: Any = None,
        segment_id: str | None = None,
        previous_state_digest: str | None = None,
        request_id: str | None = None,
        scope: str = DEFAULT_LEASE_SCOPE,
    ) -> dict[str, Any]:
        """Append one prompt-free checkpoint and its causal EventV2 fact."""

        for field, value in (("run_id", run_id), ("job_id", job_id), ("attempt_id", attempt_id)):
            if not str(value).strip():
                raise ValueError(f"{field} is required")
        payload_hash = _continuous_digest(payload_digest, "payload_digest")
        state_hash = _continuous_digest(state_digest, "state_digest")
        previous_hash = None if previous_state_digest is None else _continuous_digest(
            previous_state_digest, "previous_state_digest"
        )
        manifest_obj = artifact_manifest if artifact_manifest is not None else []
        self._reject_provenance_secrets(manifest_obj, path="checkpoint.artifact_manifest")
        artifact_json = _json(manifest_obj)
        request = str(request_id or f"checkpoint:{run_id}:{attempt_id}:{sequence or 0}:{state_hash}")
        if not request.strip() or any(ch.isspace() for ch in request):
            raise ValueError("request_id is invalid")
        current = utc_now()
        with self._transaction() as cursor:
            self._assert_lease_tx(cursor, scope, owner_id, int(fence_token), now=current)
            segment = self._active_segment_tx(
                cursor, str(run_id), owner_id=owner_id, fence_token=int(fence_token)
            )
            if segment is not None:
                active_segment_id = str(segment["segment_id"])
                if segment_id is not None and str(segment_id) != active_segment_id:
                    raise FencingError("checkpoint segment_id does not match active segment")
                segment_id = active_segment_id
            elif segment_id is not None:
                row = cursor.execute(
                    "SELECT * FROM run_segments WHERE segment_id = ?", (str(segment_id),)
                ).fetchone()
                if row is None:
                    raise JobTransitionError("checkpoint references an unknown segment")
                if (
                    str(row["owner_id"]) != str(owner_id)
                    or int(row["fence_token"]) != int(fence_token)
                ):
                    raise FencingError("checkpoint segment fence is stale")
                if str(row["status"]) not in {"running", "closing"}:
                    raise JobTransitionError("checkpoint references a terminal segment")
            attempt_row = cursor.execute(
                "SELECT * FROM attempts WHERE attempt_id = ? AND job_id = ?",
                (str(attempt_id), str(job_id)),
            ).fetchone()
            if attempt_row is None:
                raise JobTransitionError("checkpoint attempt does not exist for the job")
            # Check the idempotent key before enforcing adjacency.  A retry
            # of sequence N must return the existing row even though the
            # latest sequence is already N; otherwise a lost response would
            # be misclassified as a gap/rollback.
            if sequence is not None:
                existing = cursor.execute(
                    """SELECT * FROM checkpoints
                       WHERE attempt_id = ? AND sequence = ? AND state_digest = ?""",
                    (str(attempt_id), int(sequence), state_hash),
                ).fetchone()
                if existing is not None:
                    if (
                        str(existing["payload_digest"]) != payload_hash
                        or str(existing["owner_id"]) != str(owner_id)
                        or int(existing["fence_token"]) != int(fence_token)
                    ):
                        raise JobConflict("checkpoint replay has conflicting identity or digest")
                    return self._decode_checkpoint_row(existing) or {}
            latest = cursor.execute(
                """SELECT * FROM checkpoints WHERE attempt_id = ?
                   ORDER BY sequence DESC LIMIT 1""",
                (str(attempt_id),),
            ).fetchone()
            if sequence is None:
                sequence = int(latest["sequence"]) + 1 if latest is not None else 1
            if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
                raise ValueError("checkpoint sequence must be a positive integer")
            if latest is not None:
                expected = int(latest["sequence"]) + 1
                if sequence != expected:
                    raise JobTransitionError("checkpoint sequence is not adjacent")
                if previous_hash is None:
                    previous_hash = str(latest["state_digest"])
                if previous_hash != str(latest["state_digest"]):
                    raise JobConflict("checkpoint previous_state_digest does not match the latest checkpoint")
            elif previous_hash is not None:
                raise JobConflict("first checkpoint cannot reference a previous state digest")
            existing = cursor.execute(
                """SELECT * FROM checkpoints
                   WHERE attempt_id = ? AND sequence = ? AND state_digest = ?""",
                (str(attempt_id), int(sequence), state_hash),
            ).fetchone()
            if existing is not None:
                if (
                    str(existing["payload_digest"]) != payload_hash
                    or str(existing["owner_id"]) != str(owner_id)
                    or int(existing["fence_token"]) != int(fence_token)
                ):
                    raise JobConflict("checkpoint replay has conflicting identity or digest")
                return self._decode_checkpoint_row(existing) or {}
            sequence_conflict = cursor.execute(
                "SELECT 1 FROM checkpoints WHERE attempt_id = ? AND sequence = ? LIMIT 1",
                (str(attempt_id), int(sequence)),
            ).fetchone()
            if sequence_conflict is not None:
                raise JobConflict("checkpoint sequence already contains a different state digest")
            checkpoint_id = self._checkpoint_id(
                str(run_id), str(job_id), str(attempt_id), int(sequence), state_hash
            )
            cursor.execute(
                """INSERT INTO checkpoints
                   (checkpoint_id, run_id, job_id, attempt_id, sequence, owner_id,
                    fence_token, payload_digest, state_digest, artifact_manifest_json,
                    created_at_utc, segment_id, previous_state_digest, request_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    checkpoint_id,
                    str(run_id),
                    str(job_id),
                    str(attempt_id),
                    int(sequence),
                    str(owner_id),
                    int(fence_token),
                    payload_hash,
                    state_hash,
                    artifact_json,
                    current,
                    segment_id,
                    previous_hash,
                    request,
                ),
            )
            self._append_event_tx(
                cursor,
                "checkpoint.recorded",
                event_id=f"checkpoint-recorded:{checkpoint_id}",
                job_id=str(job_id),
                attempt_id=str(attempt_id),
                owner_id=owner_id,
                fence_token=int(fence_token),
                payload={
                    "run_id": str(run_id),
                    "checkpoint_id": checkpoint_id,
                    "sequence": int(sequence),
                    "payload_digest": payload_hash,
                    "state_digest": state_hash,
                    "segment_id": segment_id,
                },
            )
            parent = self._latest_provenance_event_id_tx(cursor, str(attempt_id))
            event = self._continuous_event(
                event_type="checkpoint.recorded",
                idempotency_key=f"sqlite:checkpoint.recorded:{checkpoint_id}",
                timestamp=current,
                run_id=str(run_id),
                segment_id=segment_id,
                checkpoint_id=checkpoint_id,
                job_id=str(job_id),
                attempt_id=str(attempt_id),
                sequence=int(sequence),
                payload_digest=payload_hash,
                state_digest=state_hash,
                causal_parent=parent,
            )
            self._append_provenance_event_tx(cursor, event)
            return self._decode_checkpoint_row(
                cursor.execute(
                    "SELECT * FROM checkpoints WHERE checkpoint_id = ?", (checkpoint_id,)
                ).fetchone()
            ) or {}

    def finish_run_segment(
        self,
        run_id: str,
        owner_id: str,
        fence_token: int,
        *,
        segment_id: str | None = None,
        sequence: int | None = None,
        status: str = "finished",
        reason: str | None = None,
        scope: str = DEFAULT_LEASE_SCOPE,
    ) -> dict[str, Any]:
        """Close a segment exactly once after its checkpoint/receipt flush."""

        if status not in {"finished", "failed", "aborted", "blocked"}:
            raise ValueError("segment terminal status is invalid")
        current = utc_now()
        with self._transaction() as cursor:
            self._assert_lease_tx(cursor, scope, owner_id, int(fence_token), now=current)
            clauses = ["run_id = ?"]
            params: list[Any] = [str(run_id)]
            if segment_id is not None:
                clauses.append("segment_id = ?")
                params.append(str(segment_id))
            if sequence is not None:
                clauses.append("sequence = ?")
                params.append(int(sequence))
            row = cursor.execute(
                f"SELECT * FROM run_segments WHERE {' AND '.join(clauses)} ORDER BY sequence DESC LIMIT 1",
                tuple(params),
            ).fetchone()
            if row is None:
                raise JobTransitionError("run segment does not exist")
            if str(row["owner_id"]) != str(owner_id) or int(row["fence_token"]) != int(fence_token):
                raise FencingError("segment fence is stale")
            current_status = str(row["status"])
            if current_status not in {"running", "closing"}:
                if current_status == status:
                    return self._decode_segment_row(row) or {}
                raise JobTransitionError("run segment is already terminal")
            cursor.execute(
                """UPDATE run_segments
                   SET status = ?, finished_at_utc = ?
                   WHERE segment_id = ? AND owner_id = ? AND fence_token = ?
                     AND status IN ('running', 'closing')""",
                (status, current, str(row["segment_id"]), str(owner_id), int(fence_token)),
            )
            if cursor.rowcount != 1:
                raise FencingError("segment finish lost its fence")
            payload = {
                "run_id": str(run_id),
                "segment_id": str(row["segment_id"]),
                "sequence": int(row["sequence"]),
                "status": status,
                "reason": str(reason) if reason else None,
            }
            self._append_event_tx(
                cursor,
                "segment.finished",
                event_id=f"segment-finished:{row['segment_id']}:{status}",
                owner_id=owner_id,
                fence_token=int(fence_token),
                payload=payload,
            )
            event = self._continuous_event(
                event_type="run.segment.finished",
                idempotency_key=f"sqlite:segment.finished:{row['segment_id']}:{status}",
                timestamp=current,
                run_id=str(run_id),
                segment_id=str(row["segment_id"]),
                sequence=int(row["sequence"]),
                status=status,
                reason=str(reason) if reason else None,
            )
            self._append_provenance_event_tx(cursor, event)
            return self._decode_segment_row(
                cursor.execute(
                    "SELECT * FROM run_segments WHERE segment_id = ?", (str(row["segment_id"]),)
                ).fetchone()
            ) or {}

    def adopt_run_segment(
        self,
        run_id: str,
        owner_id: str,
        fence_token: int,
        *,
        segment_id: str | None = None,
        sequence: int | None = None,
        expected_owner_id: str | None = None,
        expected_fence_token: int | None = None,
        manifest_digest: str | None = None,
        capsule_digest: str | None = None,
        scope: str = DEFAULT_LEASE_SCOPE,
    ) -> dict[str, Any]:
        """Transfer an active segment to the current controller fence.

        Adoption is only possible behind a newly acquired controller lease;
        an old process with the previous fence therefore loses all subsequent
        mutations.  The segment identity and checkpoint chain are preserved,
        avoiding a duplicate PBS submission after a controller restart.
        """

        if not str(run_id).strip() or not str(owner_id).strip():
            raise ValueError("run_id and owner_id are required")
        if segment_id is None and sequence is None:
            raise ValueError("segment_id or sequence is required")
        manifest = None if manifest_digest is None else _continuous_digest(manifest_digest, "manifest_digest")
        capsule = None if capsule_digest is None else _continuous_digest(capsule_digest, "capsule_digest")
        current = utc_now()
        with self._transaction() as cursor:
            self._assert_lease_tx(cursor, scope, owner_id, int(fence_token), now=current)
            clauses = ["run_id = ?", "status IN ('running', 'closing')"]
            params: list[Any] = [str(run_id)]
            if segment_id is not None:
                clauses.append("segment_id = ?")
                params.append(str(segment_id))
            if sequence is not None:
                clauses.append("sequence = ?")
                params.append(int(sequence))
            row = cursor.execute(
                f"SELECT * FROM run_segments WHERE {' AND '.join(clauses)} ORDER BY sequence DESC LIMIT 1",
                tuple(params),
            ).fetchone()
            if row is None:
                raise JobTransitionError("active run segment does not exist")
            if manifest is not None and str(row["manifest_digest"]) != manifest:
                raise JobConflict("run segment manifest digest does not match adoption")
            if capsule is not None and (row["capsule_digest"] or None) != capsule:
                raise JobConflict("run segment capsule digest does not match adoption")
            old_owner = str(row["owner_id"])
            old_fence = int(row["fence_token"])
            if old_owner == str(owner_id) and old_fence == int(fence_token):
                return self._decode_segment_row(row) or {}
            if expected_owner_id is not None and old_owner != str(expected_owner_id):
                raise FencingError("run segment owner changed during adoption")
            if expected_fence_token is not None and old_fence != int(expected_fence_token):
                raise FencingError("run segment fence changed during adoption")
            cursor.execute(
                """UPDATE run_segments
                   SET owner_id = ?, fence_token = ?
                   WHERE segment_id = ? AND owner_id = ? AND fence_token = ?
                     AND status IN ('running', 'closing')""",
                (str(owner_id), int(fence_token), str(row["segment_id"]), old_owner, old_fence),
            )
            if cursor.rowcount != 1:
                raise FencingError("run segment adoption lost its source fence")
            payload = {
                "run_id": str(run_id),
                "segment_id": str(row["segment_id"]),
                "sequence": int(row["sequence"]),
                "previous_owner_id": old_owner,
                "previous_fence_token": old_fence,
                "owner_id": str(owner_id),
                "fence_token": int(fence_token),
            }
            self._append_event_tx(
                cursor,
                "segment.adopted",
                event_id=f"segment-adopted:{row['segment_id']}:{int(fence_token)}",
                owner_id=owner_id,
                fence_token=int(fence_token),
                payload=payload,
            )
            event = self._continuous_event(
                event_type="run.segment.adopted",
                idempotency_key=f"sqlite:segment.adopted:{row['segment_id']}:{int(fence_token)}",
                timestamp=current,
                run_id=str(run_id),
                segment_id=str(row["segment_id"]),
                sequence=int(row["sequence"]),
                previous_owner_id=old_owner,
                previous_fence_token=old_fence,
                owner_id=str(owner_id),
                fence_token=int(fence_token),
            )
            self._append_provenance_event_tx(cursor, event)
            return self._decode_segment_row(
                cursor.execute(
                    "SELECT * FROM run_segments WHERE segment_id = ?", (str(row["segment_id"]),)
                ).fetchone()
            ) or {}

    def record_cleanup_intent(
        self,
        *,
        run_id: str,
        owner_id: str,
        fence_token: int,
        path_digest: str,
        action: str = "review",
        attempt_id: str | None = None,
        segment_id: str | None = None,
        request_id: str | None = None,
        payload: Mapping[str, Any] | None = None,
        scope: str = DEFAULT_LEASE_SCOPE,
    ) -> dict[str, Any]:
        """Durably record a cleanup proposal without deleting anything."""

        _continuous_digest(path_digest, "path_digest")
        if not isinstance(action, str) or not re.fullmatch(r"[a-z0-9._:-]{1,128}", action):
            raise ValueError("cleanup action is invalid")
        body = dict(payload or {})
        self._reject_provenance_secrets(body, path="cleanup.payload")
        request = str(request_id or f"cleanup:{run_id}:{path_digest}:{action}")
        current = utc_now()
        intent_id = "cleanup-" + hashlib.sha256(request.encode("utf-8")).hexdigest()[:32]
        with self._transaction() as cursor:
            self._assert_lease_tx(cursor, scope, owner_id, int(fence_token), now=current)
            existing = cursor.execute(
                "SELECT * FROM cleanup_intents WHERE request_id = ?", (request,)
            ).fetchone()
            if existing is not None:
                if (
                    str(existing["path_digest"]) != str(path_digest)
                    or str(existing["action"]) != str(action)
                ):
                    raise JobConflict("cleanup request_id conflicts with existing intent")
                return self._decode_cleanup_intent_row(existing) or {}
            cursor.execute(
                """INSERT INTO cleanup_intents
                   (cleanup_intent_id, request_id, run_id, segment_id, attempt_id,
                    owner_id, fence_token, path_digest, action, status,
                    created_at_utc, updated_at_utc, payload_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?)""",
                (
                    intent_id,
                    request,
                    str(run_id),
                    str(segment_id) if segment_id else None,
                    str(attempt_id) if attempt_id else None,
                    str(owner_id),
                    int(fence_token),
                    str(path_digest),
                    action,
                    current,
                    current,
                    _json(body),
                ),
            )
            event_payload = {
                "run_id": str(run_id),
                "cleanup_intent_id": intent_id,
                "path_digest": str(path_digest),
                "action": action,
                "segment_id": str(segment_id) if segment_id else None,
                "attempt_id": str(attempt_id) if attempt_id else None,
            }
            self._append_event_tx(
                cursor,
                "cleanup.intent",
                event_id=f"cleanup-intent:{intent_id}",
                owner_id=owner_id,
                fence_token=int(fence_token),
                payload=event_payload,
            )
            event = self._continuous_event(
                event_type="cleanup.intent",
                idempotency_key=f"sqlite:cleanup.intent:{request}",
                timestamp=current,
                run_id=str(run_id),
                segment_id=event_payload["segment_id"],
                attempt_id=event_payload["attempt_id"],
                cleanup_intent_id=intent_id,
                path_digest=str(path_digest),
                action=action,
            )
            self._append_provenance_event_tx(cursor, event)
            return self._decode_cleanup_intent_row(
                cursor.execute(
                    "SELECT * FROM cleanup_intents WHERE cleanup_intent_id = ?", (intent_id,)
                ).fetchone()
            ) or {}

    def list_run_segments(self, run_id: str | None = None) -> list[dict[str, Any]]:
        if run_id is None:
            rows = self._conn.execute(
                "SELECT * FROM run_segments ORDER BY run_id, sequence"
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM run_segments WHERE run_id = ? ORDER BY sequence",
                (str(run_id),),
            ).fetchall()
        return [self._decode_segment_row(row) or {} for row in rows]

    def list_running_attempts(
        self,
        *,
        run_id: str | None = None,
        owner_id: str | None = None,
        fence_token: int | None = None,
    ) -> list[dict[str, Any]]:
        """Return live attempts for checkpoint/admission decisions.

        This is intentionally a bounded read-only query.  A continuous-run
        supervisor uses it to prove that there is no in-flight controller
        work before declaring a checkpoint flush complete; it must never infer
        quiescence from an absent callback alone.
        """

        clauses = ["a.status = 'running'", "j.status = 'running'"]
        params: list[Any] = []
        if run_id is not None:
            clauses.append("j.run_id = ?")
            params.append(str(run_id))
        if owner_id is not None:
            clauses.append("a.owner_id = ?")
            params.append(str(owner_id))
        if fence_token is not None:
            clauses.append("a.fence_token = ?")
            params.append(int(fence_token))
        rows = self._conn.execute(
            """SELECT a.*, j.run_id AS job_run_id
               FROM attempts AS a
               JOIN jobs AS j ON j.job_id = a.job_id
               WHERE """ + " AND ".join(clauses) +
            " ORDER BY a.started_at_utc, a.attempt_id",
            tuple(params),
        ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["payload"] = _decode(item.pop("payload_json", None), {})
            item["result"] = _decode(item.pop("result_json", None), None)
            item["artifact_manifest"] = _decode(item.pop("artifact_manifest_json", None), None)
            item["validation"] = _decode(item.pop("validation_json", None), None)
            item["error"] = _decode(item.pop("error_json", None), None)
            result.append(item)
        return result

    def list_checkpoints(
        self,
        *,
        run_id: str | None = None,
        attempt_id: str | None = None,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if run_id is not None:
            clauses.append("run_id = ?")
            params.append(str(run_id))
        if attempt_id is not None:
            clauses.append("attempt_id = ?")
            params.append(str(attempt_id))
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self._conn.execute(
            f"SELECT * FROM checkpoints{where} ORDER BY run_id, attempt_id, sequence",
            tuple(params),
        ).fetchall()
        return [self._decode_checkpoint_row(row) or {} for row in rows]

    def list_cleanup_intents(
        self,
        *,
        run_id: str | None = None,
        statuses: Sequence[str] | None = None,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if run_id is not None:
            clauses.append("run_id = ?")
            params.append(str(run_id))
        if statuses:
            placeholders = ",".join("?" for _ in statuses)
            clauses.append(f"status IN ({placeholders})")
            params.extend(str(item) for item in statuses)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self._conn.execute(
            f"SELECT * FROM cleanup_intents{where} ORDER BY created_at_utc, cleanup_intent_id",
            tuple(params),
        ).fetchall()
        return [self._decode_cleanup_intent_row(row) or {} for row in rows]

    # ------------------------------------------------------------------
    # Events, attempts, and restart snapshots
    # ------------------------------------------------------------------
    def _append_event_tx(
        self,
        cursor: sqlite3.Cursor,
        event_type: str,
        *,
        event_id: str | None = None,
        job_id: str | None = None,
        attempt_id: str | None = None,
        owner_id: str | None = None,
        fence_token: int | None = None,
        payload: Any = None,
        at_utc: str | None = None,
    ) -> dict[str, Any]:
        event_id = event_id or _new_id("event")
        at_utc = at_utc or utc_now()
        cursor.execute(
            """INSERT OR IGNORE INTO events
               (event_id, schema_version, job_id, attempt_id, event_type, at_utc, owner_id, fence_token, payload_json)
               VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?)""",
            (event_id, job_id, attempt_id, event_type, at_utc, owner_id, fence_token, _json(payload)),
        )
        row = cursor.execute("SELECT * FROM events WHERE event_id = ?", (event_id,)).fetchone()
        assert row is not None
        return self._decode_event_row(row) or {}

    def append_event(
        self,
        event_type: str,
        *,
        event_id: str | None = None,
        job_id: str | None = None,
        attempt_id: str | None = None,
        owner_id: str | None = None,
        fence_token: int | None = None,
        scope: str = DEFAULT_LEASE_SCOPE,
        payload: Any = None,
    ) -> dict[str, Any]:
        with self._transaction() as cursor:
            if owner_id is not None or fence_token is not None:
                if owner_id is None or fence_token is None:
                    raise FencingError("owner_id and fence_token must be supplied together")
                self._assert_lease_tx(cursor, scope, owner_id, int(fence_token))
            return self._append_event_tx(
                cursor,
                event_type,
                event_id=event_id,
                job_id=job_id,
                attempt_id=attempt_id,
                owner_id=owner_id,
                fence_token=fence_token,
                payload=payload,
            )

    def append_provenance_event(
        self,
        event: Mapping[str, Any],
        *,
        owner_id: str | None = None,
        fence_token: int | None = None,
        scope: str = DEFAULT_LEASE_SCOPE,
    ) -> dict[str, Any]:
        """Append one validated EventV2 record behind the controller fence.

        This is the public seam for imports and controller transitions that do
        not yet have a specialised method.  The operation is idempotent by
        both ``event_id`` and ``idempotency_key`` and fails closed on orphan or
        secret-bearing records.
        """

        if (owner_id is None) != (fence_token is None):
            raise FencingError("owner_id and fence_token must be supplied together")
        current = utc_now()
        with self._transaction() as cursor:
            if owner_id is not None:
                self._assert_lease_tx(cursor, scope, owner_id, int(fence_token), now=current)
            return self._append_provenance_event_tx(cursor, event)

    def get_provenance_event(self, event_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT event_json FROM provenance_events WHERE event_id = ?",
            (str(event_id),),
        ).fetchone()
        return self._decode_provenance_event_row(row)

    def list_provenance_events(
        self,
        *,
        job_id: str | None = None,
        attempt_id: str | None = None,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if job_id is not None:
            clauses.append("job_id = ?")
            params.append(str(job_id))
        if attempt_id is not None:
            clauses.append("attempt_id = ?")
            params.append(str(attempt_id))
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self._conn.execute(
            f"SELECT event_json FROM provenance_events{where} ORDER BY event_seq",
            tuple(params),
        ).fetchall()
        return [self._decode_provenance_event_row(row) or {} for row in rows]

    def get_attempt(self, attempt_id: str) -> dict[str, Any] | None:
        row = self._conn.execute("SELECT * FROM attempts WHERE attempt_id = ?", (attempt_id,)).fetchone()
        return self._decode_attempt_row(row)

    def project_attempt_lifecycle(self, attempt_id: str) -> dict[str, Any]:
        """Project independent lifecycle facts for one durable attempt.

        SQLite keeps execution status and validator output in separate columns
        and keeps normative EventV2 records in ``provenance_events``.  This
        read-only seam joins those sources without treating a terminal job row
        as a validated result or public claim.
        """

        attempt = self.get_attempt(attempt_id)
        if attempt is None:
            return _project_lifecycle()
        job = self.get_job(str(attempt.get("job_id") or ""))
        events = self.list_provenance_events(attempt_id=str(attempt_id))
        return _project_lifecycle(
            events,
            job_status=(job or {}).get("status"),
            attempt_status=attempt.get("status"),
            validation=attempt.get("validation"),
        )

    def list_attempts(self, job_id: str | None = None) -> list[dict[str, Any]]:
        if job_id is None:
            rows = self._conn.execute(
                "SELECT * FROM attempts ORDER BY job_id, attempt_no"
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM attempts WHERE job_id = ? ORDER BY attempt_no", (job_id,)
            ).fetchall()
        return [self._decode_attempt_row(row) or {} for row in rows]

    def list_events(self, job_id: str | None = None) -> list[dict[str, Any]]:
        if job_id is None:
            rows = self._conn.execute("SELECT * FROM events ORDER BY event_seq").fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM events WHERE job_id = ? ORDER BY event_seq", (job_id,)
            ).fetchall()
        return [self._decode_event_row(row) or {} for row in rows]

    def get_lease(self, *, scope: str = DEFAULT_LEASE_SCOPE) -> dict[str, Any] | None:
        row = self._conn.execute("SELECT * FROM leases WHERE scope = ?", (scope,)).fetchone()
        return self._decode_lease_row(row)

    def snapshot(self) -> dict[str, Any]:
        """Return a restart-safe, JSON-serializable view of durable state."""

        return {
            "schema_version": self.schema_version,
            "jobs": self.list_jobs(),
            "attempts": self.list_attempts(),
            "events": self.list_events(),
            "provenance_events": self.list_provenance_events(),
            "reservations": self.list_reservations(),
            "transport_outbox": self.list_transport_outbox(),
            "run_segments": self.list_run_segments(),
            "checkpoints": self.list_checkpoints(),
            "cleanup_intents": self.list_cleanup_intents(),
            "governor_state": self.list_governor_states(),
            "leases": [
                self._decode_lease_row(row) or {}
                for row in self._conn.execute("SELECT * FROM leases ORDER BY scope").fetchall()
            ],
        }

    rebuild_state = snapshot


__all__ = [
    "DEFAULT_LEASE_SCOPE",
    "DEFAULT_LEASE_TTL_SECONDS",
    "FencingError",
    "JobConflict",
    "JobTransitionError",
    "LeaseConflict",
    "MigrationError",
    "ProvenanceEventConflict",
    "ProvenanceEventError",
    "ProvenanceOrphanError",
    "ProvenanceSecretError",
    "ReservationAdmissionError",
    "ReservationConflict",
    "SCHEMA_VERSION",
    "SQLiteStore",
    "StoreError",
    "utc_now",
]


if __name__ == "__main__":  # pragma: no cover - diagnostic convenience
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", default="dispatch.sqlite3")
    args = parser.parse_args()
    with SQLiteStore(args.path) as store:
        print(json.dumps({"path": args.path, **store.snapshot()}, ensure_ascii=False, indent=2))
