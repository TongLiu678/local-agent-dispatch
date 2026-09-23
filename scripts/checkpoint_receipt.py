#!/usr/bin/env python3
"""Durable, prompt-free checkpoint receipts for resumable runs.

The receipt is deliberately smaller than a task packet.  It binds a run and
attempt to the packet/capsule digests, a monotonically increasing sequence,
the current fence, progress and artifact *metadata*.  It never persists a
prompt, argv, environment, credential, or artifact contents.  Receipts are
written with an fsync followed by an atomic rename, and a receipt's
``state_digest`` is the link used by the next checkpoint in the chain.

This module is stdlib-only and does not invoke a provider, scheduler, SSH, or
shell.  It can therefore be used by both provider-free replay and a remote
worker without making the worker a second control plane.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import pathlib
import re
import tempfile
from typing import Any, Mapping


SCHEMA_VERSION = 1
_ID = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_RELATIVE_PATH = re.compile(r"^[^/\\][^\\]*$")
_SECRET_KEY = re.compile(
    r"(?:prompt|argv|environment|env|token|secret|password|api[_-]?key|credential|authorization|private[_-]?key)",
    re.IGNORECASE,
)
_SAFE_METADATA_KEYS = {"fence_token"}
_STOP_STATUSES = {"pending", "running", "validated", "failed", "censored", "unknown"}
_REQUIRED = (
    "checkpoint_id",
    "run_id",
    "job_id",
    "attempt_id",
    "sequence",
    "previous_checkpoint_digest",
    "packet_digest",
    "capsule_digest",
    "progress_digest",
    "artifact_manifest",
    "observed_at",
    "validator_state",
    "state_digest",
)


class CheckpointError(ValueError):
    """Raised when a checkpoint is unsafe, incomplete, or tampered with."""


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    except (TypeError, ValueError) as exc:
        raise CheckpointError("checkpoint contains non-JSON data") from exc


def _sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _utc_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _timestamp(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CheckpointError(f"{field} must be an ISO-8601 timestamp")
    try:
        parsed = _dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CheckpointError(f"{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise CheckpointError(f"{field} must include a timezone")
    return value


def _id(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise CheckpointError(f"{field} is invalid")
    return value


def _digest(value: Any, field: str, *, required: bool = True) -> str | None:
    if value is None and not required:
        return None
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise CheckpointError(f"{field} must be a sha256:<64 lowercase hex> digest")
    return value


def _reject_sensitive(value: Any, path: str = "checkpoint") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if str(key) not in _SAFE_METADATA_KEYS and _SECRET_KEY.search(str(key)):
                raise CheckpointError(f"{path}: sensitive field is not allowed: {key}")
            _reject_sensitive(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_sensitive(child, f"{path}[{index}]")


def _relative_path(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or value.startswith(("/", "\\")):
        raise CheckpointError(f"{field} must be a relative path")
    path = pathlib.PurePosixPath(value.replace("\\", "/"))
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise CheckpointError(f"{field} must not escape its artifact root")
    return "/".join(path.parts)


def _artifact_manifest(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, (list, tuple)):
        raise CheckpointError("artifact_manifest must be a list")
    result: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        if not isinstance(item, Mapping):
            raise CheckpointError(f"artifact_manifest[{index}] must be an object")
        allowed = {"path", "bytes", "digest", "status"}
        unknown = set(item) - allowed
        if unknown:
            raise CheckpointError(f"artifact_manifest[{index}] has unknown fields: {sorted(unknown)}")
        row: dict[str, Any] = {"path": _relative_path(item.get("path"), f"artifact_manifest[{index}].path")}
        size = item.get("bytes", 0)
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise CheckpointError(f"artifact_manifest[{index}].bytes must be non-negative")
        row["bytes"] = size
        if "digest" in item:
            row["digest"] = _digest(item.get("digest"), f"artifact_manifest[{index}].digest")
        status = item.get("status", "observed")
        if not isinstance(status, str) or status not in {"observed", "missing", "partial", "validated"}:
            raise CheckpointError(f"artifact_manifest[{index}].status is invalid")
        row["status"] = status
        result.append(row)
    return result


def _validator_state(value: Any) -> dict[str, Any]:
    if value is None:
        return {"status": "unknown"}
    if not isinstance(value, Mapping):
        raise CheckpointError("validator_state must be an object")
    state = dict(value)
    status = state.get("status", "unknown")
    if not isinstance(status, str) or status not in _STOP_STATUSES:
        raise CheckpointError("validator_state.status is invalid")
    _reject_sensitive(state, "validator_state")
    return state


def _state_payload(receipt: Mapping[str, Any]) -> dict[str, Any]:
    return {key: receipt[key] for key in receipt if key != "state_digest"}


def _receipt_from_payload(payload: Mapping[str, Any], *, previous: Mapping[str, Any] | None) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        raise CheckpointError("checkpoint payload must be an object")
    _reject_sensitive(payload)
    for field in ("run_id", "job_id", "attempt_id"):
        _id(payload.get(field), field)
    sequence = payload.get("sequence")
    if sequence is None:
        sequence = int(previous.get("sequence", 0)) + 1 if previous else 1
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
        raise CheckpointError("sequence must be a positive integer")
    if previous:
        expected_sequence = int(previous["sequence"]) + 1
        if sequence != expected_sequence:
            raise CheckpointError("checkpoint sequence is not adjacent to the previous receipt")
    previous_digest = payload.get("previous_checkpoint_digest")
    if previous is None:
        if previous_digest not in (None, ""):
            _digest(previous_digest, "previous_checkpoint_digest")
            raise CheckpointError("the first checkpoint cannot reference a previous receipt")
        previous_digest = None
    else:
        expected_digest = previous.get("state_digest")
        if previous_digest is None:
            previous_digest = expected_digest
        if previous_digest != expected_digest:
            raise CheckpointError("previous_checkpoint_digest does not match the latest receipt")
        _digest(previous_digest, "previous_checkpoint_digest")

    receipt: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "receipt_type": "local-agent-dispatch.checkpoint",
        "run_id": payload["run_id"],
        "job_id": payload["job_id"],
        "attempt_id": payload["attempt_id"],
        "sequence": sequence,
        "previous_checkpoint_digest": previous_digest,
        "packet_digest": _digest(payload.get("packet_digest"), "packet_digest"),
        "capsule_digest": _digest(payload.get("capsule_digest"), "capsule_digest"),
        "progress_digest": _digest(payload.get("progress_digest"), "progress_digest"),
        "artifact_manifest": _artifact_manifest(payload.get("artifact_manifest")),
        "observed_at": _timestamp(payload.get("observed_at", _utc_now()), "observed_at"),
        "validator_state": _validator_state(payload.get("validator_state")),
    }
    owner_digest = _digest(payload.get("owner_digest"), "owner_digest", required=False)
    if owner_digest is not None:
        receipt["owner_digest"] = owner_digest
    fence_token = payload.get("fence_token")
    if fence_token is not None:
        if isinstance(fence_token, bool) or not isinstance(fence_token, int) or fence_token < 0:
            raise CheckpointError("fence_token must be a non-negative integer")
        receipt["fence_token"] = fence_token
    checkpoint_id = payload.get("checkpoint_id")
    if checkpoint_id is None:
        checkpoint_id = "cp-" + hashlib.sha256(_canonical(receipt)).hexdigest()[:32]
    receipt["checkpoint_id"] = _id(checkpoint_id, "checkpoint_id")
    receipt["state_digest"] = _sha256(_state_payload(receipt))
    return receipt


def _latest_checkpoint(directory: pathlib.Path) -> dict[str, Any] | None:
    candidates = sorted(directory.glob("checkpoint-*.json"))
    if not candidates:
        return None
    latest_path = candidates[-1]
    try:
        value = json.loads(latest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CheckpointError("latest checkpoint is unreadable") from exc
    if not isinstance(value, Mapping):
        raise CheckpointError("latest checkpoint is not an object")
    validate_checkpoint(value, expected_attempt_id=str(value.get("attempt_id", "")))
    return dict(value)


def _fsync_directory(directory: pathlib.Path) -> None:
    try:
        descriptor = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)


def _atomic_json(path: pathlib.Path, receipt: Mapping[str, Any]) -> None:
    directory = path.parent
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".partial", dir=directory)
    temporary = pathlib.Path(temporary_name)
    try:
        data = json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _fsync_directory(directory)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def write_checkpoint(root: pathlib.Path, payload: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and durably append one checkpoint in ``root``.

    ``root`` is a local attempt directory.  The function is idempotent for an
    already-written ``checkpoint_id`` with identical content and rejects a
    conflicting overwrite or a broken sequence/hash chain.
    """

    if not isinstance(root, pathlib.Path):
        root = pathlib.Path(root)
    try:
        root = root.expanduser().resolve(strict=False)
        root.mkdir(parents=True, exist_ok=True)
        directory = root / "checkpoints"
        directory.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise CheckpointError("checkpoint root is not writable") from exc
    previous = _latest_checkpoint(directory)
    receipt = _receipt_from_payload(payload, previous=previous)
    path = directory / f"checkpoint-{receipt['sequence']:020d}.json"
    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CheckpointError("existing checkpoint is unreadable") from exc
        if existing != receipt:
            raise CheckpointError("checkpoint sequence already contains a conflicting receipt")
        return dict(existing)
    _atomic_json(path, receipt)
    return dict(receipt)


def validate_checkpoint(receipt: Mapping[str, Any], *, expected_attempt_id: str) -> dict[str, Any]:
    """Validate a receipt and return a small report; tampering raises."""

    if not isinstance(receipt, Mapping):
        raise CheckpointError("checkpoint receipt must be an object")
    missing = [field for field in _REQUIRED if field not in receipt]
    if missing:
        raise CheckpointError("checkpoint missing: " + ",".join(missing))
    if receipt.get("schema_version") != SCHEMA_VERSION:
        raise CheckpointError("checkpoint schema_version is unsupported")
    if receipt.get("receipt_type") != "local-agent-dispatch.checkpoint":
        raise CheckpointError("checkpoint receipt_type is invalid")
    _reject_sensitive(receipt)
    attempt_id = _id(receipt.get("attempt_id"), "attempt_id")
    if attempt_id != expected_attempt_id:
        raise CheckpointError("checkpoint attempt_id does not match the expected attempt")
    for field in ("checkpoint_id", "run_id", "job_id"):
        _id(receipt.get(field), field)
    sequence = receipt.get("sequence")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
        raise CheckpointError("checkpoint sequence is invalid")
    previous = receipt.get("previous_checkpoint_digest")
    if previous is not None:
        _digest(previous, "previous_checkpoint_digest")
    for field in ("packet_digest", "capsule_digest", "progress_digest", "state_digest"):
        _digest(receipt.get(field), field)
    if "owner_digest" in receipt:
        _digest(receipt.get("owner_digest"), "owner_digest")
    if "fence_token" in receipt:
        token = receipt.get("fence_token")
        if isinstance(token, bool) or not isinstance(token, int) or token < 0:
            raise CheckpointError("fence_token is invalid")
    _timestamp(receipt.get("observed_at"), "observed_at")
    _artifact_manifest(receipt.get("artifact_manifest"))
    _validator_state(receipt.get("validator_state"))
    expected_state = _sha256(_state_payload(receipt))
    if receipt.get("state_digest") != expected_state:
        raise CheckpointError("checkpoint state_digest does not match its contents")
    return {
        "valid": True,
        "checkpoint_id": receipt["checkpoint_id"],
        "attempt_id": attempt_id,
        "sequence": sequence,
        "state_digest": receipt["state_digest"],
    }


def resume_eligibility(
    checkpoint: Mapping[str, Any],
    *,
    packet_digest: str,
    capsule_digest: str,
    active_fence: int,
) -> dict[str, Any]:
    """Return whether a checkpoint can safely resume the active attempt."""

    reasons: list[str] = []
    try:
        validate_checkpoint(checkpoint, expected_attempt_id=str(checkpoint.get("attempt_id", "")))
    except CheckpointError as exc:
        return {"allowed": False, "reasons": [str(exc)]}
    if not _DIGEST.fullmatch(packet_digest):
        reasons.append("packet_digest_invalid")
    elif checkpoint.get("packet_digest") != packet_digest:
        reasons.append("packet_digest_mismatch")
    if not _DIGEST.fullmatch(capsule_digest):
        reasons.append("capsule_digest_invalid")
    elif checkpoint.get("capsule_digest") != capsule_digest:
        reasons.append("capsule_digest_mismatch")
    if isinstance(active_fence, bool) or not isinstance(active_fence, int) or active_fence < 0:
        reasons.append("active_fence_invalid")
    elif "fence_token" not in checkpoint:
        reasons.append("checkpoint_fence_missing")
    elif checkpoint.get("fence_token") != active_fence:
        reasons.append("fence_token_mismatch")
    return {
        "allowed": not reasons,
        "reasons": reasons,
        "checkpoint_id": checkpoint.get("checkpoint_id"),
        "sequence": checkpoint.get("sequence"),
    }


__all__ = [
    "CheckpointError",
    "SCHEMA_VERSION",
    "write_checkpoint",
    "validate_checkpoint",
    "resume_eligibility",
]
