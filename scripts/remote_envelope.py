#!/usr/bin/env python3
"""Provider-free transactional envelope/outbox/inbox boundary.

The controller and a remote worker must not share SQLite WAL or rely on a
single SSH process staying alive.  This module provides the smallest durable
protocol needed between them:

* an envelope contains only an allow-listed task summary and a packet digest;
* ``request_id`` plus ``payload_digest`` makes retries idempotent;
* a conflicting reuse of a request id fails closed;
* outbox/inbox/receipt writes are atomic and protected by one spool lock;
* accepting or completing an envelope records a receipt, but never executes a
  provider, shell, SSH command, or irreversible side effect.

The real worker can use this seam to transport a prepared packet.  Prompt
text, argv, environment values, credentials, and arbitrary payloads are
intentionally not representable in the durable envelope.
"""

from __future__ import annotations

import contextlib
import datetime as _dt
import hashlib
import json
import os
import pathlib
import re
import time
import uuid
from typing import Any, Iterator, Mapping

try:  # direct script import
    from portable_file_lock import exclusive_file_lock
except ImportError:  # pragma: no cover - package-style fallback
    from .portable_file_lock import exclusive_file_lock  # type: ignore


SCHEMA_VERSION = 1
ENVELOPE_VERSION = 1
RECEIPT_VERSION = 1

# ``payload_digest`` covers the allow-listed summary only.  It is not enough
# to identify an envelope: a retry with the same summary but a different
# packet, destination, or operation must fail closed rather than being
# treated as an idempotent delivery.  ``created_at`` is intentionally absent
# because a controller may rebuild the same request after a process restart.
_ENVELOPE_IDENTITY_FIELDS = (
    "request_id",
    "idempotency_key",
    "source_id",
    "target_id",
    "operation",
    "packet_digest",
    "payload_digest",
)

_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_OPERATION_RE = re.compile(r"[a-z][a-z0-9_.-]{0,63}\Z")
_WINDOWS_RESERVED_STEMS = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}
_SECRET_KEY_RE = re.compile(
    r"(?:secret|token|password|api[_-]?key|credential|authorization|bearer|private[_-]?key)",
    re.IGNORECASE,
)
_SUMMARY_KEYS = {
    "job_id",
    "packet_id",
    "attempt_id",
    # Optional bounded-run identity.  These fields let a controller recover
    # segment receipts from the SQLite outbox after its JSON sidecar is lost;
    # they do not carry prompts, commands, or credentials.
    "run_id",
    "segment_id",
    "sequence",
    "manifest_digest",
    "capsule_digest",
    "model",
    "variant",
    "provider",
    "pool_id",
    "host_id",
    "execution_host",
    "workload_host",
    "write_scope",
    "required_artifact_count",
    "validation_required",
    "resource_digest",
    "placement_digest",
}
_RECEIPT_STATUSES = {"accepted", "completed", "failed"}


class EnvelopeError(ValueError):
    """Raised when an envelope or receipt violates the durable contract."""


def _utc_at(epoch_seconds: float) -> str:
    return _dt.datetime.fromtimestamp(float(epoch_seconds), _dt.timezone.utc).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


def _utc_now() -> str:
    return _utc_at(time.time())


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()


def _safe_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise EnvelopeError(f"{field} is invalid")
    return value


def _safe_operation(value: Any) -> str:
    if not isinstance(value, str) or not _OPERATION_RE.fullmatch(value):
        raise EnvelopeError("operation is invalid")
    return value


def _reject_secret_key(key: Any, path: str) -> None:
    if _SECRET_KEY_RE.search(str(key)):
        raise EnvelopeError(f"{path}: secret-like field is not accepted")


def _summary_value(value: Any, path: str) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        if isinstance(value, str) and len(value) > 256:
            raise EnvelopeError(f"{path} is too long")
        return value
    if isinstance(value, list):
        if len(value) > 32:
            raise EnvelopeError(f"{path} has too many values")
        return [_summary_value(item, f"{path}[]") for item in value]
    raise EnvelopeError(f"{path} contains an unsupported value")


def _sanitize_summary(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise EnvelopeError("payload_summary must be an object")
    result: dict[str, Any] = {}
    for key, child in value.items():
        _reject_secret_key(key, f"payload_summary.{key}")
        if key not in _SUMMARY_KEYS:
            raise EnvelopeError(f"payload_summary field is not allow-listed: {key}")
        result[str(key)] = _summary_value(child, f"payload_summary.{key}")
    return result


def _validate_envelope(envelope: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(envelope, Mapping):
        raise EnvelopeError("envelope must be an object")
    if envelope.get("schema_version") != SCHEMA_VERSION:
        raise EnvelopeError("unsupported envelope schema_version")
    if envelope.get("envelope_version") != ENVELOPE_VERSION:
        raise EnvelopeError("unsupported envelope_version")
    request_id = _safe_id(envelope.get("request_id"), "request_id")
    _safe_id(envelope.get("source_id"), "source_id")
    _safe_id(envelope.get("target_id"), "target_id")
    _safe_operation(envelope.get("operation"))
    packet_digest = envelope.get("packet_digest")
    if not isinstance(packet_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", packet_digest):
        raise EnvelopeError("packet_digest must be a lowercase SHA-256 digest")
    summary = _sanitize_summary(envelope.get("payload_summary"))
    expected_payload_digest = _digest(summary)
    if envelope.get("payload_digest") != expected_payload_digest:
        raise EnvelopeError("payload_digest does not match payload_summary")
    idempotency_key = _safe_id(envelope.get("idempotency_key") or request_id, "idempotency_key")
    created_at = envelope.get("created_at")
    if not isinstance(created_at, str) or not created_at:
        raise EnvelopeError("created_at is required")
    # Rebuild a canonical object, dropping unknown keys before persistence.
    return {
        "schema_version": SCHEMA_VERSION,
        "envelope_version": ENVELOPE_VERSION,
        "request_id": request_id,
        "idempotency_key": idempotency_key,
        "source_id": str(envelope["source_id"]),
        "target_id": str(envelope["target_id"]),
        "operation": str(envelope["operation"]),
        "packet_digest": packet_digest,
        "payload_summary": summary,
        "payload_digest": expected_payload_digest,
        "created_at": created_at,
    }


def build_envelope(
    *,
    request_id: str,
    source_id: str,
    target_id: str,
    operation: str,
    packet_digest: str,
    payload_summary: Mapping[str, Any],
    idempotency_key: str | None = None,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Build and validate a metadata-only transport envelope."""
    summary = _sanitize_summary(payload_summary)
    envelope = {
        "schema_version": SCHEMA_VERSION,
        "envelope_version": ENVELOPE_VERSION,
        "request_id": request_id,
        "idempotency_key": idempotency_key or request_id,
        "source_id": source_id,
        "target_id": target_id,
        "operation": operation,
        "packet_digest": packet_digest,
        "payload_summary": summary,
        "payload_digest": _digest(summary),
        "created_at": created_at or _utc_now(),
    }
    return _validate_envelope(envelope)


def _atomic_write(path: pathlib.Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with tmp.open("w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        with contextlib.suppress(OSError):
            directory_fd = os.open(str(path.parent), os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        with contextlib.suppress(FileNotFoundError):
            tmp.unlink()


@contextlib.contextmanager
def _lock(root: pathlib.Path) -> Iterator[None]:
    root.mkdir(parents=True, exist_ok=True)
    lock_path = root / ".envelope.lock"
    with exclusive_file_lock(lock_path):
        yield


def _safe_root(root: pathlib.Path | str) -> pathlib.Path:
    try:
        resolved = pathlib.Path(root).expanduser().resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        raise EnvelopeError("invalid envelope root") from exc
    if resolved == pathlib.Path(resolved.anchor):
        raise EnvelopeError("envelope root may not be filesystem root")
    return resolved


def _request_path(root: pathlib.Path, folder: str, request_id: str) -> pathlib.Path:
    _safe_id(request_id, "request_id")
    # The protocol deliberately permits ``:`` in stable IDs, while Windows
    # forbids it in a filename.  Windows also aliases reserved DOS device
    # names and strips trailing dots.  Keep already-portable names readable,
    # but map every non-portable component to a bounded, collision-resistant
    # name in the same way on every OS.  The canonical request_id remains in
    # the signed JSON body and is revalidated when the file is read.
    stem = request_id
    base = stem.split(".", 1)[0].upper()
    if ":" in stem or stem.endswith((".", " ")) or base in _WINDOWS_RESERVED_STEMS:
        readable = re.sub(r"[^A-Za-z0-9_.-]", "_", stem).rstrip(". ")[:48]
        readable = readable or "request"
        digest = hashlib.sha256(stem.encode("utf-8")).hexdigest()
        stem = f"{readable}-{digest}"
    return root / folder / f"{stem}.json"


def _read_json(path: pathlib.Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError) as exc:
        raise EnvelopeError(f"invalid durable JSON: {path.name}") from exc
    if not isinstance(value, dict):
        raise EnvelopeError(f"durable JSON is not an object: {path.name}")
    return value


def _assert_same_envelope(
    existing: Mapping[str, Any],
    candidate: Mapping[str, Any],
) -> None:
    """Reject a request-id collision that is not a true retry.

    The outbox and inbox are independent durable copies.  Comparing only the
    summary digest would allow a changed packet digest or route to masquerade
    as an idempotent retry.  Keep this check centralized so enqueue, receive,
    status, and pending reconciliation all enforce the same identity fence.
    """
    if any(existing.get(field) != candidate.get(field) for field in _ENVELOPE_IDENTITY_FIELDS):
        raise EnvelopeError("request_id already exists with a different envelope identity")


def _receipt(
    envelope: Mapping[str, Any],
    *,
    status: str,
    effect_count: int,
    result_digest: str | None = None,
    error_code: str | None = None,
    duplicate: bool = False,
) -> dict[str, Any]:
    if status not in _RECEIPT_STATUSES:
        raise EnvelopeError("invalid receipt status")
    if not isinstance(effect_count, int) or effect_count < 0:
        raise EnvelopeError("effect_count must be a non-negative integer")
    value: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "receipt_version": RECEIPT_VERSION,
        "request_id": envelope["request_id"],
        "idempotency_key": envelope["idempotency_key"],
        "payload_digest": envelope["payload_digest"],
        "status": status,
        "effect_count": effect_count,
        "duplicate": bool(duplicate),
        "observed_at": _utc_now(),
    }
    if result_digest is not None:
        if not isinstance(result_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", result_digest):
            raise EnvelopeError("result_digest must be a lowercase SHA-256 digest")
        value["result_digest"] = result_digest
    if error_code is not None:
        if not isinstance(error_code, str) or not re.fullmatch(r"[a-z0-9_.-]{1,80}", error_code):
            raise EnvelopeError("error_code is invalid")
        value["error_code"] = error_code
    value["receipt_digest"] = _digest(value)
    return value


def _validate_receipt(
    envelope: Mapping[str, Any],
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate a durable receipt against its envelope and digest.

    Receipts are the acknowledgement boundary between two independent
    spools.  Treating a JSON object with only a matching ``request_id`` as an
    acknowledgement would allow a truncated, stale, or hand-edited receipt
    to promote a controller row.  The durable digest is calculated before
    the transient ``duplicate`` flag is added to a replay response, so a
    retry can be recognized without rewriting the receipt.
    """
    if not isinstance(receipt, Mapping):
        raise EnvelopeError("envelope receipt is not an object")
    allowed = {
        "schema_version",
        "receipt_version",
        "request_id",
        "idempotency_key",
        "payload_digest",
        "status",
        "effect_count",
        "duplicate",
        "observed_at",
        "result_digest",
        "error_code",
        "receipt_digest",
    }
    unknown = set(receipt) - allowed
    if unknown:
        raise EnvelopeError("envelope receipt contains an unsupported field")
    if receipt.get("schema_version") != SCHEMA_VERSION:
        raise EnvelopeError("unsupported receipt schema_version")
    if receipt.get("receipt_version") != RECEIPT_VERSION:
        raise EnvelopeError("unsupported receipt_version")
    if receipt.get("request_id") != envelope.get("request_id"):
        raise EnvelopeError("envelope receipt request_id mismatch")
    if receipt.get("idempotency_key") != envelope.get("idempotency_key"):
        raise EnvelopeError("envelope receipt idempotency_key mismatch")
    if receipt.get("payload_digest") != envelope.get("payload_digest"):
        raise EnvelopeError("envelope receipt payload_digest mismatch")
    status = receipt.get("status")
    if status not in _RECEIPT_STATUSES:
        raise EnvelopeError("envelope receipt status is invalid")
    effect_count = receipt.get("effect_count")
    if isinstance(effect_count, bool) or not isinstance(effect_count, int) or effect_count < 0:
        raise EnvelopeError("envelope receipt effect_count is invalid")
    if not isinstance(receipt.get("duplicate"), bool):
        raise EnvelopeError("envelope receipt duplicate flag is invalid")
    observed_at = receipt.get("observed_at")
    if not isinstance(observed_at, str) or not observed_at:
        raise EnvelopeError("envelope receipt observed_at is invalid")
    result_digest = receipt.get("result_digest")
    if result_digest is not None and (
        not isinstance(result_digest, str)
        or not re.fullmatch(r"[0-9a-f]{64}", result_digest)
    ):
        raise EnvelopeError("envelope receipt result_digest is invalid")
    error_code = receipt.get("error_code")
    if error_code is not None and (
        not isinstance(error_code, str)
        or not re.fullmatch(r"[a-z0-9_.-]{1,80}", error_code)
    ):
        raise EnvelopeError("envelope receipt error_code is invalid")
    if status == "completed" and result_digest is None:
        raise EnvelopeError("completed receipt requires result_digest")
    if status == "completed" and error_code is not None:
        raise EnvelopeError("completed receipt cannot contain error_code")
    if status == "failed" and not error_code:
        raise EnvelopeError("failed receipt requires error_code")
    if status == "failed" and result_digest is not None:
        raise EnvelopeError("failed receipt cannot contain result_digest")
    if status == "accepted" and (result_digest is not None or error_code is not None):
        raise EnvelopeError("accepted receipt cannot contain terminal outcome evidence")
    receipt_digest = receipt.get("receipt_digest")
    if not isinstance(receipt_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", receipt_digest):
        raise EnvelopeError("envelope receipt receipt_digest is invalid")
    digest_input = dict(receipt)
    digest_input.pop("receipt_digest", None)
    if _digest(digest_input) != receipt_digest:
        raise EnvelopeError("envelope receipt digest mismatch")
    return dict(receipt)


class EnvelopeStore:
    """Single-writer filesystem store for controller outbox and worker inbox."""

    def __init__(self, root: pathlib.Path | str):
        self.root = _safe_root(root)
        self.outbox = self.root / "outbox"
        self.inbox = self.root / "inbox"
        self.receipts = self.root / "receipts"

    def enqueue(self, envelope: Mapping[str, Any]) -> dict[str, Any]:
        canonical = _validate_envelope(envelope)
        path = _request_path(self.root, "outbox", canonical["request_id"])
        with _lock(self.root):
            existing = _read_json(path)
            if existing is not None:
                existing = _validate_envelope(existing)
                _assert_same_envelope(existing, canonical)
                return {"status": "pending", "duplicate": True, "envelope": existing}
            _atomic_write(path, canonical)
            return {"status": "pending", "duplicate": False, "envelope": canonical}

    def receive(self, envelope: Mapping[str, Any]) -> dict[str, Any]:
        canonical = _validate_envelope(envelope)
        inbox_path = _request_path(self.root, "inbox", canonical["request_id"])
        outbox_path = _request_path(self.root, "outbox", canonical["request_id"])
        receipt_path = _request_path(self.root, "receipts", canonical["request_id"])
        with _lock(self.root):
            # The controller normally leaves its outbox copy in place until
            # reconciliation.  Check it before accepting a new inbox copy;
            # otherwise a changed packet could create a split-brain request
            # that only a later status/pending scan would discover.
            outbox = _read_json(outbox_path)
            if outbox is not None:
                outbox = _validate_envelope(outbox)
                _assert_same_envelope(outbox, canonical)
            existing = _read_json(inbox_path)
            if existing is not None:
                existing = _validate_envelope(existing)
                _assert_same_envelope(existing, canonical)
                receipt = _read_json(receipt_path)
                if receipt is None:
                    receipt = _receipt(existing, status="accepted", effect_count=0)
                    _atomic_write(receipt_path, receipt)
                else:
                    receipt = _validate_receipt(existing, receipt)
                receipt["duplicate"] = True
                return {"status": receipt.get("status", "accepted"), "duplicate": True, "receipt": receipt}
            _atomic_write(inbox_path, canonical)
            receipt = _receipt(canonical, status="accepted", effect_count=0)
            _atomic_write(receipt_path, receipt)
            return {"status": "accepted", "duplicate": False, "receipt": receipt}

    def complete(
        self,
        request_id: str,
        *,
        status: str = "completed",
        result_digest: str | None = None,
        error_code: str | None = None,
    ) -> dict[str, Any]:
        request_id = _safe_id(request_id, "request_id")
        if status not in {"completed", "failed"}:
            raise EnvelopeError("completion status must be completed or failed")
        if status == "completed" and result_digest is None:
            raise EnvelopeError("completed receipt requires result_digest")
        if status == "failed" and not error_code:
            raise EnvelopeError("failed receipt requires error_code")
        if status == "completed" and error_code is not None:
            raise EnvelopeError("completed receipt cannot contain error_code")
        if status == "failed" and result_digest is not None:
            raise EnvelopeError("failed receipt cannot contain result_digest")
        inbox_path = _request_path(self.root, "inbox", request_id)
        receipt_path = _request_path(self.root, "receipts", request_id)
        with _lock(self.root):
            envelope = _read_json(inbox_path)
            if envelope is None:
                raise EnvelopeError("cannot complete an envelope that was not received")
            envelope = _validate_envelope(envelope)
            outbox = _read_json(_request_path(self.root, "outbox", request_id))
            if outbox is not None:
                outbox = _validate_envelope(outbox)
                _assert_same_envelope(outbox, envelope)
            existing = _read_json(receipt_path)
            if existing is not None:
                existing = _validate_receipt(envelope, existing)
            if existing is not None and existing.get("status") in {"completed", "failed"}:
                if (
                    existing.get("status") != status
                    or existing.get("result_digest") != result_digest
                    or existing.get("error_code") != error_code
                ):
                    raise EnvelopeError("request_id already has a conflicting terminal receipt")
                replay = dict(existing)
                replay["duplicate"] = True
                return {"status": replay["status"], "duplicate": True, "receipt": replay}
            receipt = _receipt(
                envelope,
                status=status,
                effect_count=1,
                result_digest=result_digest,
                error_code=error_code,
            )
            _atomic_write(receipt_path, receipt)
            return {"status": status, "duplicate": False, "receipt": receipt}

    def status(self, request_id: str) -> dict[str, Any]:
        """Read one metadata-only envelope receipt without executing it.

        The worker's status endpoint is intentionally a read-only query over
        the durable inbox/outbox and receipt files.  It does not infer a
        provider outcome and does not promote an ``accepted`` receipt to a
        terminal state.  A request that is unknown to this spool fails closed.
        """

        request_id = _safe_id(request_id, "request_id")
        with _lock(self.root):
            inbox_envelope = _read_json(_request_path(self.root, "inbox", request_id))
            outbox_envelope = _read_json(_request_path(self.root, "outbox", request_id))
            if inbox_envelope is not None and outbox_envelope is not None:
                inbox_envelope = _validate_envelope(inbox_envelope)
                outbox_envelope = _validate_envelope(outbox_envelope)
                _assert_same_envelope(inbox_envelope, outbox_envelope)
                envelope = inbox_envelope
            else:
                envelope = inbox_envelope or outbox_envelope
            if envelope is None:
                raise EnvelopeError("envelope request_id is not present in this spool")
            if not isinstance(envelope, dict):  # defensive: both branches are JSON objects
                raise EnvelopeError("durable envelope is not an object")
            envelope = _validate_envelope(envelope)
            receipt = _read_json(_request_path(self.root, "receipts", request_id))
            if receipt is None:
                # A durable envelope without a receipt is recoverable and is
                # deliberately reported as pending rather than fabricated as
                # accepted.  The caller can retry receive before reconciling.
                return {
                    "status": "pending",
                    "request_id": request_id,
                    "receipt": None,
                    "envelope": {
                        "request_id": envelope["request_id"],
                        "target_id": envelope["target_id"],
                        "operation": envelope["operation"],
                        "packet_digest": envelope["packet_digest"],
                        "payload_digest": envelope["payload_digest"],
                    },
                }
            # Validate the durable receipt against the envelope before exposing
            # it to the controller.  This catches partial/corrupt spool writes
            # without returning arbitrary JSON from the worker.
            receipt = _validate_receipt(envelope, receipt)
            status = receipt["status"]
            return {
                "status": status,
                "request_id": request_id,
                "receipt": receipt,
                "envelope": {
                    "request_id": envelope["request_id"],
                    "target_id": envelope["target_id"],
                    "operation": envelope["operation"],
                    "packet_digest": envelope["packet_digest"],
                    "payload_digest": envelope["payload_digest"],
                },
            }

    def pending(self) -> list[dict[str, Any]]:
        """Return bounded metadata for envelopes not yet terminally receipted.

        A controller sees an outbox row while a worker sees an inbox row.  The
        union is intentional: after a connection drops between receive and
        completion, either side can discover the same request without needing
        a shared database.
        """
        with _lock(self.root):
            rows: list[dict[str, Any]] = []
            envelopes: dict[str, dict[str, Any]] = {}
            for folder in (self.outbox, self.inbox):
                for path in folder.glob("*.json") if folder.is_dir() else []:
                    envelope = _read_json(path)
                    if envelope is None:
                        continue
                    envelope = _validate_envelope(envelope)
                    request_id = str(envelope["request_id"])
                    existing = envelopes.get(request_id)
                    if existing is not None:
                        _assert_same_envelope(existing, envelope)
                    else:
                        envelopes[request_id] = envelope
            for request_id in sorted(envelopes):
                envelope = envelopes[request_id]
                if envelope is None:
                    continue
                receipt = _read_json(_request_path(self.root, "receipts", envelope["request_id"]))
                if receipt is not None:
                    receipt = _validate_receipt(envelope, receipt)
                if receipt is not None and receipt.get("status") in {"completed", "failed"}:
                    continue
                rows.append(
                    {
                        "request_id": envelope["request_id"],
                        "target_id": envelope["target_id"],
                        "operation": envelope["operation"],
                        "packet_digest": envelope["packet_digest"],
                        "payload_digest": envelope["payload_digest"],
                        "status": "pending" if receipt is None else receipt.get("status", "accepted"),
                    }
                )
            return rows


__all__ = ["EnvelopeError", "EnvelopeStore", "build_envelope"]
