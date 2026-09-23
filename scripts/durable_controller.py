#!/usr/bin/env python3
"""Small, provider-free supervisor for resumable PBS scheduler segments.

The supervisor is deliberately an orchestration seam, not a provider runner.
It binds one run/segment to its manifest and project capsule, writes a durable
submission intent before asking PBS to create a job, and never submits the same
segment twice when the acknowledgement is lost.  The controller, checkpoint,
and PBS implementations are injected so the same state machine can be tested
without SSH, qsub, or a model prompt.

Production deployments should keep the SQLite WAL on the controller-local
filesystem and inject a client backed by ``pbs_controller_bridge``.  The
default command-line surface is dry-run only; no credentials or arbitrary
shell command is accepted here.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import inspect
import json
import os
import pathlib
import re
import sys
import tempfile
from typing import Any, Callable, Mapping


_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@+=,-]{0,191}\Z")
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_STATUSES = {"pending", "accepted", "completed", "failed", "submitted_unknown"}


class DurableControllerError(RuntimeError):
    """Raised when a segment cannot be advanced without guessing."""


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


def _safe_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise DurableControllerError(f"{field} is invalid")
    return value


def _digest_value(value: Any, field: str, *, allow_missing: bool = False) -> str | None:
    if value is None and allow_missing:
        return None
    if not isinstance(value, str):
        raise DurableControllerError(f"{field} is invalid")
    if _DIGEST_RE.fullmatch(value):
        return value
    # A few older manifests carry an unprefixed SHA-256.  Normalize it at the
    # boundary instead of allowing two identities for the same segment.
    if re.fullmatch(r"[0-9a-f]{64}", value):
        return "sha256:" + value
    raise DurableControllerError(f"{field} is invalid")


def _parse_utc(value: Any, field: str) -> dt.datetime:
    if not isinstance(value, str) or not value.strip():
        raise DurableControllerError(f"{field} is required")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError as exc:
        raise DurableControllerError(f"{field} is not an ISO timestamp") from exc
    if parsed.tzinfo is None:
        raise DurableControllerError(f"{field} must include a timezone")
    return parsed.astimezone(dt.timezone.utc)


def _iso(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _now_from_clock(clock: Any) -> dt.datetime:
    """Read the common fake-clock shapes used by provider-free tests."""

    candidate: Any
    for name in ("now_utc", "now"):
        method = getattr(clock, name, None)
        if callable(method):
            candidate = method()
            break
    else:
        candidate = clock() if callable(clock) else clock
    if isinstance(candidate, dt.datetime):
        parsed = candidate
    elif isinstance(candidate, str):
        parsed = _parse_utc(candidate, "clock.now")
    else:
        raise DurableControllerError("clock must return an aware datetime or ISO timestamp")
    if parsed.tzinfo is None:
        raise DurableControllerError("clock timestamp must include a timezone")
    return parsed.astimezone(dt.timezone.utc)


def _atomic_json(path: pathlib.Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        try:
            directory_fd = os.open(path.parent, os.O_RDONLY)
        except OSError:
            directory_fd = None
        if directory_fd is not None:
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _read_json(path: pathlib.Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return dict(value) if isinstance(value, Mapping) else None


def _invoke(method: Callable[..., Any], values: Mapping[str, Any]) -> Any:
    """Call an injected method using only parameters it explicitly accepts."""

    try:
        signature = inspect.signature(method)
    except (TypeError, ValueError):
        return method(**dict(values))
    parameters = signature.parameters
    if any(parameter.kind == inspect.Parameter.VAR_KEYWORD for parameter in parameters.values()):
        return method(**dict(values))
    accepted = {key: value for key, value in values.items() if key in parameters}
    return method(**accepted)


def _mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


class DurableControllerSupervisor:
    """Drive bounded segments while preserving idempotency and fence context.

    ``controller`` owns the transactional state.  It may expose any of the
    following optional methods: ``begin_run_segment``, ``append_checkpoint`` or
    ``flush_checkpoints``, ``finish_run_segment``, ``heartbeat`` and
    ``reconcile``.  ``pbs_client`` exposes ``submit`` and optionally ``status``.
    Missing optional methods are represented as explicit provider-free
    observations; they never cause a second external submission.
    """

    def __init__(
        self,
        *,
        controller: Any,
        manifest: Mapping[str, Any],
        capsule: Mapping[str, Any],
        pbs_client: Any,
        clock: Any,
        run_root: pathlib.Path | str | None = None,
        owner_id: str | None = None,
        execute: bool = False,
        rollover_guard_seconds: int | None = None,
    ) -> None:
        if not isinstance(manifest, Mapping) or not isinstance(capsule, Mapping):
            raise DurableControllerError("manifest and capsule must be objects")
        self.controller = controller
        self.manifest = dict(manifest)
        self.capsule = dict(capsule)
        self.pbs_client = pbs_client
        self.clock = clock
        self.run_id = _safe_id(self.manifest.get("run_id"), "manifest.run_id")
        self.segment_seconds = self._positive_int(
            self.manifest.get("segment_seconds", 3600), "manifest.segment_seconds", 86400
        )
        guard = rollover_guard_seconds
        if guard is None:
            guard = self.manifest.get("rollover_guard_seconds", min(300, max(30, self.segment_seconds // 10)))
        self.rollover_guard_seconds = self._nonnegative_int(guard, "rollover_guard_seconds", self.segment_seconds)
        self.planned_end = (
            _parse_utc(self.manifest["planned_end_at"], "manifest.planned_end_at")
            if self.manifest.get("planned_end_at") is not None
            else None
        )
        self.manifest_digest = _digest_value(
            self.manifest.get("manifest_digest") or self.manifest.get("source_digest"),
            "manifest_digest",
            allow_missing=True,
        ) or _digest(self.manifest)
        self.capsule_digest = _digest_value(
            self.capsule.get("capsule_spec_digest") or self.capsule.get("capsule_digest"),
            "capsule_digest",
            allow_missing=True,
        ) or _digest(self.capsule)
        self.owner_id = _safe_id(owner_id or f"durable-controller-{self.run_id}", "owner_id")
        self.execute = bool(execute)
        root_value = run_root or self.manifest.get("run_root") or self.capsule.get("run_root")
        self.run_root = pathlib.Path(str(root_value)).expanduser() if root_value else None
        self._active: dict[str, Any] | None = None
        self._next_sequence = 1
        self._submissions: dict[int, dict[str, Any]] = {}
        self._pending_ack: dict[int, dict[str, Any]] = {}
        self._state = "created"
        self._last_observed_now: dt.datetime | None = None
        self._load_submission_state()

    @staticmethod
    def _positive_int(value: Any, field: str, maximum: int) -> int:
        if isinstance(value, bool):
            raise DurableControllerError(f"{field} is invalid")
        try:
            parsed = int(value)
        except (TypeError, ValueError) as exc:
            raise DurableControllerError(f"{field} is invalid") from exc
        if parsed < 1 or parsed > maximum:
            raise DurableControllerError(f"{field} is outside the supported range")
        return parsed

    @staticmethod
    def _nonnegative_int(value: Any, field: str, maximum: int) -> int:
        if isinstance(value, bool):
            raise DurableControllerError(f"{field} is invalid")
        try:
            parsed = int(value)
        except (TypeError, ValueError) as exc:
            raise DurableControllerError(f"{field} is invalid") from exc
        if parsed < 0 or parsed > maximum:
            raise DurableControllerError(f"{field} is outside the supported range")
        return parsed

    @property
    def current_segment(self) -> dict[str, Any] | None:
        return dict(self._active) if self._active is not None else None

    @property
    def state(self) -> str:
        """Expose the bounded supervisor state for a durable run loop."""

        return self._state

    def _segment_id(self, sequence: int) -> str:
        return _safe_id(f"{self.run_id}:segment:{sequence}", "segment_id")

    def _submission_digest(self, sequence: int) -> str:
        return _digest(
            {
                "run_id": self.run_id,
                "segment_id": self._segment_id(sequence),
                "sequence": sequence,
                "manifest_digest": self.manifest_digest,
                "capsule_digest": self.capsule_digest,
                "owner_id": self.owner_id,
            }
        )

    def _receipt_path(self, sequence: int) -> pathlib.Path | None:
        return self.run_root / "segments" / f"segment-{sequence:06d}.submission.json" if self.run_root else None

    def _intent_path(self, sequence: int) -> pathlib.Path | None:
        return self.run_root / "segments" / f"segment-{sequence:06d}.submission.intent.json" if self.run_root else None

    def _load_submission_state(self) -> None:
        # SQLite is the controller source of truth when an adapter supplies a
        # recovery seam.  JSON sidecars remain a portable fallback, but must
        # never silently override a conflicting durable receipt.
        loader = getattr(self.controller, "restore_run_state", None)
        if callable(loader):
            state = _mapping(
                _invoke(
                    loader,
                    {
                        "run_id": self.run_id,
                        "owner_id": self.owner_id,
                        "manifest_digest": self.manifest_digest,
                        "capsule_digest": self.capsule_digest,
                    },
                )
            )
            restored = state.get("submissions")
            if isinstance(restored, list):
                for candidate in restored:
                    if not isinstance(candidate, Mapping):
                        continue
                    self._register_submission(candidate, source="sqlite")
            segments = state.get("segments")
            if isinstance(segments, list):
                controller_fence = getattr(self.controller, "fence_token", None)
                for candidate in segments:
                    if not isinstance(candidate, Mapping):
                        continue
                    try:
                        sequence = int(candidate.get("sequence"))
                    except (TypeError, ValueError):
                        continue
                    if sequence < 1:
                        continue
                    self._next_sequence = max(self._next_sequence, sequence + 1)
                    if self._active is not None or candidate.get("status") not in {"running", "closing"}:
                        continue
                    if candidate.get("owner_id") not in {None, self.owner_id}:
                        continue
                    if controller_fence is not None and candidate.get("fence_token") not in {None, int(controller_fence)}:
                        continue
                    if candidate.get("manifest_digest") not in {None, self.manifest_digest}:
                        continue
                    if candidate.get("capsule_digest") not in {None, self.capsule_digest}:
                        continue
                    if candidate.get("segment_id") not in {None, self._segment_id(sequence)}:
                        continue
                    self._active = dict(candidate)
                    self._state = "running"
        if self.run_root is None:
            return
        directory = self.run_root / "segments"
        try:
            paths = sorted(directory.glob("segment-*.submission.json"))
        except OSError:
            paths = []
        for path in paths:
            receipt = _read_json(path)
            if not receipt:
                continue
            self._register_submission(receipt, source=str(path))

    def _register_submission(self, receipt: Mapping[str, Any], *, source: str) -> None:
        """Validate and merge one recovered submission receipt."""

        try:
            sequence = int(receipt.get("sequence"))
        except (TypeError, ValueError):
            return
        if sequence < 1:
            return
        if receipt.get("run_id") not in {None, self.run_id}:
            raise DurableControllerError(f"{source} receipt belongs to another run")
        expected = self._submission_digest(sequence)
        if (
            receipt.get("receipt_type") == "local-agent-dispatch.segment-submission"
            and receipt.get("submission_digest") not in {None, expected}
        ):
            raise DurableControllerError(f"{source} receipt conflicts with manifest/capsule")
        candidate = dict(receipt)
        candidate.setdefault("run_id", self.run_id)
        candidate.setdefault("segment_id", self._segment_id(sequence))
        candidate.setdefault("sequence", sequence)
        candidate.setdefault("manifest_digest", self.manifest_digest)
        candidate.setdefault("capsule_digest", self.capsule_digest)
        # PBS bridge receipts use the worker's submission-file digest, which
        # is a different identity from this supervisor's deterministic
        # segment digest.  Preserve the remote value for provenance while
        # normalizing the supervisor-facing idempotency key.
        if candidate.get("receipt_type") != "local-agent-dispatch.segment-submission":
            remote_digest = candidate.get("submission_digest")
            if remote_digest not in {None, expected}:
                candidate["remote_submission_digest"] = remote_digest
            candidate["submission_digest"] = expected
        else:
            candidate.setdefault("submission_digest", expected)
        previous = self._submissions.get(sequence)
        if previous is not None and previous != candidate:
            # A durable SQLite receipt and a JSON sidecar for the same
            # sequence must describe one identity.  Preserve the conflict
            # instead of choosing whichever source happened to be read last.
            stable_fields = (
                "submission_digest", "pbs_job_id", "idempotency_key", "run_id",
                "segment_id", "sequence", "manifest_digest", "capsule_digest",
            )
            if any(
                previous.get(field) is not None
                and candidate.get(field) is not None
                and previous.get(field) != candidate.get(field)
                for field in stable_fields
            ):
                raise DurableControllerError(f"conflicting receipts for segment {sequence}")
            merged = dict(previous)
            merged.update(candidate)
            candidate = merged
        self._submissions[sequence] = candidate
        self._next_sequence = max(self._next_sequence, sequence + 1)

    def _persist_intent(self, sequence: int, payload: Mapping[str, Any]) -> None:
        path = self._intent_path(sequence)
        if path is not None:
            _atomic_json(path, payload)

    def _persist_receipt(self, sequence: int, payload: Mapping[str, Any]) -> None:
        self._submissions[sequence] = dict(payload)
        self._next_sequence = max(self._next_sequence, sequence + 1)
        path = self._receipt_path(sequence)
        if path is not None:
            _atomic_json(path, payload)
        intent = self._intent_path(sequence)
        if intent is not None:
            _atomic_json(intent, {**dict(payload), "receipt_type": "submission-intent", "status": "submitted"})

    def _open_segment(self, sequence: int | None = None) -> dict[str, Any]:
        if self._active is not None:
            return dict(self._active)
        seq = int(sequence or self._next_sequence)
        segment_id = self._segment_id(seq)
        started = _now_from_clock(self.clock)
        values = {
            "run_id": self.run_id,
            "owner_id": self.owner_id,
            "fence_token": int(getattr(self.controller, "fence_token", 1) or 1),
            "sequence": seq,
            "segment_id": segment_id,
            "manifest_digest": self.manifest_digest,
            "capsule_digest": self.capsule_digest,
            "metadata": {"started_at_utc": _iso(started), "supervisor": "durable_controller_v1"},
        }
        method = getattr(self.controller, "begin_run_segment", None)
        if callable(method):
            result = _mapping(_invoke(method, values))
            if result:
                values.update({key: result[key] for key in ("segment_id", "sequence", "fence_token", "started_at_utc", "status") if key in result})
        values.setdefault("status", "running")
        values.setdefault("started_at_utc", _iso(started))
        self._active = values
        self._next_sequence = max(self._next_sequence, seq + 1)
        self._state = "running"
        return dict(values)

    @staticmethod
    def _remote_payload(value: Any) -> dict[str, Any]:
        outer = _mapping(value)
        remote = outer.get("remote")
        if not isinstance(remote, Mapping):
            return outer
        merged = dict(remote)
        # The outer client report describes the controller's transport stage;
        # the nested worker report may describe only the worker stage.  Keep
        # the stronger fact when an actual SSH/PBS call happened.
        for key in ("provider_execution", "network_execution"):
            if key in outer:
                merged[key] = bool(outer.get(key)) or bool(merged.get(key))
        return merged

    def _submission_values(self, sequence: int) -> dict[str, Any]:
        segment_id = self._segment_id(sequence)
        job_id = str(self.manifest.get("job_id") or segment_id)
        values: dict[str, Any] = {
            "run_id": self.run_id,
            "segment_id": segment_id,
            "sequence": sequence,
            "owner_id": self.owner_id,
            "owner": self.owner_id,
            # PBSWorkerClient names the remote unit a job; use an explicit
            # manifest job_id when supplied and otherwise the deterministic
            # segment id.  This keeps status reconciliation stable across
            # controller restarts.
            "job_id": job_id,
            # ``PBSWorkerClient`` and other fixed transport adapters require
            # the immutable request identity on both submit and status.  The
            # older generic supervisor values omitted it, so an execute-mode
            # loop could only work with permissive test doubles.  Allow an
            # explicitly prepared request id and otherwise derive one from
            # the stable run/segment identity; never use a fresh UUID here.
            "request_id": str(
                self.manifest.get("request_id") or f"{job_id}:segment:{sequence}"
            ),
            "manifest_digest": self.manifest_digest,
            "capsule_digest": self.capsule_digest,
            "idempotency_key": f"{self.run_id}:segment:{sequence}",
            "submission_digest": self._submission_digest(sequence),
            "run_root": str(self.run_root) if self.run_root else None,
            "execute": True,
        }
        target_id = self.manifest.get("target_id") or self.manifest.get("execution_host") or self.manifest.get("host_id")
        if target_id is not None:
            values["host_id"] = target_id
        payload_digest = self.manifest.get("payload_digest") or self.manifest.get("packet_digest")
        if isinstance(payload_digest, str):
            values["payload_digest"] = payload_digest[7:] if payload_digest.startswith("sha256:") else payload_digest
        return values

    def _status_for_pending(self, sequence: int, intent: Mapping[str, Any]) -> dict[str, Any] | None:
        hint = self._pending_ack.get(sequence)
        if hint:
            return dict(hint)
        method = getattr(self.pbs_client, "status", None)
        if not callable(method):
            return None
        values = self._submission_values(sequence)
        values["execute"] = True
        values["pbs_job_id"] = intent.get("pbs_job_id")
        return self._remote_payload(_invoke(method, values))

    def _make_receipt(self, sequence: int, remote: Mapping[str, Any]) -> dict[str, Any]:
        status = str(remote.get("status") or "accepted")
        if status not in _STATUSES:
            raise DurableControllerError("PBS returned an invalid segment status")
        pbs_job_id = remote.get("pbs_job_id") or remote.get("job_id")
        if status in {"accepted", "pending", "completed", "failed"} and not isinstance(pbs_job_id, str):
            raise DurableControllerError("PBS receipt has no stable job id")
        values = self._submission_values(sequence)
        receipt = {
            "schema_version": 1,
            "receipt_type": "local-agent-dispatch.segment-submission",
            "provider_execution": bool(remote.get("provider_execution", False)),
            "network_execution": bool(remote.get("network_execution", False)),
            "run_id": self.run_id,
            "segment_id": values["segment_id"],
            "sequence": sequence,
            "owner_id": self.owner_id,
            "manifest_digest": self.manifest_digest,
            "capsule_digest": self.capsule_digest,
            "idempotency_key": values["idempotency_key"],
            "submission_digest": values["submission_digest"],
            "pbs_job_id": pbs_job_id,
            "run_root": values["run_root"],
            "status": status,
            "observed_at_utc": _iso(_now_from_clock(self.clock)),
        }
        for key in ("queue", "host_id", "result_digest", "worker_receipt_digest", "error_code"):
            if remote.get(key) is not None:
                receipt[key] = remote[key]
        receipt["receipt_digest"] = _digest(receipt)
        return receipt

    def submit_segment(self, *, execute: bool, simulate_ack_loss: bool = False) -> dict[str, Any]:
        """Submit or recover the current segment without duplicate qsub."""

        segment = self._open_segment()
        sequence = int(segment["sequence"])
        submission_digest = self._submission_digest(sequence)
        existing = self._submissions.get(sequence)
        if existing is None:
            receipt_path = self._receipt_path(sequence)
            existing = _read_json(receipt_path) if receipt_path is not None else None
            if existing:
                self._submissions[sequence] = existing
        if existing is not None:
            if existing.get("submission_digest") != submission_digest:
                raise DurableControllerError("existing segment receipt conflicts with manifest/capsule")
            return {**existing, "idempotent": True, "action": "reuse_submission_receipt"}

        intent_path = self._intent_path(sequence)
        intent = _read_json(intent_path) if intent_path is not None else None
        if intent is not None:
            if intent.get("submission_digest") != submission_digest:
                raise DurableControllerError("existing submission intent conflicts with segment identity")
            if intent.get("status") in {"submitting", "submitted_unknown"}:
                recovered = self._status_for_pending(sequence, intent)
                if recovered and str(recovered.get("status") or "") in {"accepted", "pending", "completed", "failed"}:
                    receipt = self._make_receipt(sequence, recovered)
                    self._persist_receipt(sequence, receipt)
                    return {**receipt, "idempotent": True, "action": "reconcile_submission_intent"}
                return {
                    **dict(intent),
                    "status": "submitted_unknown",
                    "idempotent": True,
                    "action": "reconcile_before_retry",
                }

        values = self._submission_values(sequence)
        plan = {
            "schema_version": 1,
            "receipt_type": "local-agent-dispatch.segment-submission-intent",
            "status": "planned" if not execute else "submitting",
            "provider_execution": False,
            "network_execution": False,
            **{key: value for key, value in values.items() if value is not None and key != "execute"},
            "created_at_utc": _iso(_now_from_clock(self.clock)),
        }
        if not execute:
            return {**plan, "dry_run": True, "action": "plan_submission"}
        self._persist_intent(sequence, plan)
        submit = getattr(self.pbs_client, "submit", None)
        if not callable(submit):
            return {**plan, "status": "blocked", "action": "missing_pbs_submit"}
        try:
            remote = self._remote_payload(_invoke(submit, values))
        except Exception as exc:  # keep the intent for safe reconciliation
            return {
                **plan,
                "status": "submitted_unknown",
                "action": "reconcile_before_retry",
                "error_class": type(exc).__name__,
            }
        if simulate_ack_loss:
            self._pending_ack[sequence] = dict(remote)
            unknown = {**plan, "status": "submitted_unknown", "action": "ack_lost", "remote_status": remote.get("status")}
            if remote.get("pbs_job_id") is not None:
                unknown["pbs_job_id"] = remote["pbs_job_id"]
            self._persist_intent(sequence, unknown)
            return unknown
        receipt = self._make_receipt(sequence, remote)
        self._persist_receipt(sequence, receipt)
        return {**receipt, "idempotent": False, "action": "submitted"}

    def reconcile(self) -> dict[str, Any]:
        """Reconcile accepted/unknown PBS receipts without issuing submissions."""

        results: list[dict[str, Any]] = []
        for sequence, receipt in sorted(self._submissions.items()):
            if receipt.get("status") in {"completed", "failed"}:
                continue
            method = getattr(self.pbs_client, "status", None)
            if not callable(method):
                results.append({"sequence": sequence, "status": receipt.get("status"), "action": "await_status"})
                continue
            remote = self._remote_payload(_invoke(method, self._submission_values(sequence)))
            if str(remote.get("status") or "") not in {"completed", "failed"}:
                results.append({"sequence": sequence, "status": remote.get("status") or receipt.get("status"), "action": "await_terminal"})
                continue
            updated = self._make_receipt(sequence, remote)
            self._persist_receipt(sequence, updated)
            results.append({"sequence": sequence, "status": updated["status"], "action": "terminal_receipt"})
        method = getattr(self.controller, "reconcile", None)
        controller_result = _mapping(_invoke(method, {"run_id": self.run_id, "owner_id": self.owner_id})) if callable(method) else {}
        return {"schema_version": 1, "run_id": self.run_id, "provider_execution": False, "results": results, "controller": controller_result}

    def _checkpoint(self) -> dict[str, Any]:
        values = {
            "run_id": self.run_id,
            "segment_id": self._active.get("segment_id") if self._active else None,
            "sequence": self._active.get("sequence") if self._active else None,
            "owner_id": self.owner_id,
            "fence_token": self._active.get("fence_token") if self._active else 1,
        }
        for name in ("checkpoint_and_flush", "flush_checkpoints", "checkpoint"):
            method = getattr(self.controller, name, None)
            if callable(method):
                result = _mapping(_invoke(method, values))
                marker = result.get("checkpoint_flushed", result.get("flushed"))
                if marker is None:
                    return {
                        "checkpoint_flushed": False,
                        "method": name,
                        "reason": "checkpoint_result_missing_flush_marker",
                        **result,
                    }
                return {"checkpoint_flushed": bool(marker), "method": name, **result}
        # A missing checkpoint adapter is not proof of quiescence.  A narrow
        # optional probe may establish that no work is running; otherwise the
        # rollover is blocked rather than manufacturing a fake checkpoint.
        for name in ("has_pending_work", "pending_work"):
            method = getattr(self.controller, name, None)
            if not callable(method):
                continue
            result = _invoke(method, values)
            if isinstance(result, Mapping):
                pending = result.get("pending")
                if pending is None:
                    pending = result.get("has_pending_work")
                if pending is False:
                    return {"checkpoint_flushed": True, "method": name, "synthetic": False, **dict(result)}
                return {"checkpoint_flushed": False, "method": name, "reason": "pending_work", **dict(result)}
            if result is False:
                return {"checkpoint_flushed": True, "method": name, "synthetic": False}
            if result is True:
                return {"checkpoint_flushed": False, "method": name, "reason": "pending_work"}
        return {
            "checkpoint_flushed": False,
            "method": "checkpoint_adapter_missing",
            "synthetic": False,
            "reason": "cannot_prove_quiescence",
        }

    def _finish(self, *, status: str = "finished", reason: str | None = None) -> dict[str, Any]:
        if self._active is None:
            return {}
        values = {
            "run_id": self.run_id,
            "segment_id": self._active.get("segment_id"),
            "sequence": self._active.get("sequence"),
            "owner_id": self.owner_id,
            "fence_token": self._active.get("fence_token", 1),
            "status": status,
            "reason": reason,
        }
        method = getattr(self.controller, "finish_run_segment", None)
        result = _mapping(_invoke(method, values)) if callable(method) else {}
        finished = {"status": status, "segment_id": self._active.get("segment_id"), **result}
        self._active = None
        return finished

    def checkpoint_and_roll(self) -> dict[str, Any]:
        """Flush the current segment before creating the next one."""

        checkpoint = self._checkpoint()
        if not checkpoint.get("checkpoint_flushed"):
            self._state = "blocked"
            return {"action": "blocked_checkpoint", **checkpoint, "provider_execution": False}
        finished = self._finish(status="finished", reason="segment_rollover")
        now = self._last_observed_now or _now_from_clock(self.clock)
        # Do not open a fresh segment when the run itself is inside the final
        # rollover guard.  The last checkpoint is the durable handoff for the
        # planned end; starting a segment that cannot finish would create a
        # misleading "running" receipt.
        if self.planned_end is not None and (
            now >= self.planned_end
            or (self.planned_end - now).total_seconds() <= self.rollover_guard_seconds
        ):
            self._state = "finished"
            return {
                "action": "checkpoint_and_roll",
                "checkpoint_flushed": True,
                "finished": finished,
                "next_segment": None,
                "reason": "planned_end",
                "provider_execution": False,
            }
        next_segment = self._open_segment()
        submission = self.submit_segment(execute=self.execute)
        return {
            "action": "checkpoint_and_roll",
            "checkpoint_flushed": True,
            "finished": finished,
            "next_segment": next_segment,
            "submission": submission,
            "provider_execution": False,
        }

    def tick(self, now_utc: str | None = None) -> dict[str, Any]:
        """Run one bounded monitor tick; never infer a new user task."""

        if self._state in {"stopped", "finished", "blocked"}:
            return {"action": self._state, "provider_execution": False}
        if self._active is None:
            self.start()
        assert self._active is not None
        now = _parse_utc(now_utc, "now_utc") if now_utc is not None else _now_from_clock(self.clock)
        self._last_observed_now = now
        heartbeat = getattr(self.controller, "heartbeat", None)
        heartbeat_result = _mapping(_invoke(heartbeat, {"run_id": self.run_id, "segment_id": self._active.get("segment_id"), "owner_id": self.owner_id, "fence_token": self._active.get("fence_token", 1)})) if callable(heartbeat) else {}
        reconciliation = self.reconcile()
        started = _parse_utc(str(self._active.get("started_at_utc")), "segment.started_at_utc")
        segment_deadline = started + dt.timedelta(seconds=self.segment_seconds)
        deadline = min(segment_deadline, self.planned_end) if self.planned_end is not None else segment_deadline
        remaining = (deadline - now).total_seconds()
        if remaining <= self.rollover_guard_seconds:
            rolled = self.checkpoint_and_roll()
            return {
                "action": "checkpoint_and_roll",
                "now_utc": _iso(now),
                "remaining_seconds": max(0, int(remaining)),
                "heartbeat": heartbeat_result,
                "reconciliation": reconciliation,
                **rolled,
            }
        return {
            "action": "continue",
            "now_utc": _iso(now),
            "remaining_seconds": int(remaining),
            "segment_id": self._active.get("segment_id"),
            "heartbeat": heartbeat_result,
            "reconciliation": reconciliation,
            "checkpoint_flushed": False,
            "provider_execution": False,
        }

    def start(self) -> dict[str, Any]:
        if self._state in {"stopped", "finished", "blocked"}:
            return {"action": self._state, "provider_execution": False}
        segment = self._open_segment()
        submission = self.submit_segment(execute=self.execute)
        return {"action": "segment_started", "segment": segment, "submission": submission, "provider_execution": False}

    def stop(self, reason: str) -> dict[str, Any]:
        if not isinstance(reason, str) or not reason.strip():
            raise DurableControllerError("stop reason is required")
        checkpoint = self._checkpoint() if self._active is not None else {"checkpoint_flushed": True, "method": "no_active_segment"}
        if not checkpoint.get("checkpoint_flushed"):
            self._state = "blocked"
            return {"action": "blocked_checkpoint", **checkpoint, "reason": reason, "provider_execution": False}
        finished = self._finish(status="aborted", reason=reason)
        self._state = "stopped"
        return {"action": "stopped", "reason": reason, "checkpoint_flushed": True, "finished": finished, "provider_execution": False}


class _NoopPBS:
    """Dry-run adapter used only by the CLI; it never claims a PBS job."""

    def submit(self, **_: Any) -> dict[str, Any]:
        return {"status": "pending", "pbs_job_id": "dry-run"}


def _load_object(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DurableControllerError(f"cannot read JSON object: {path}") from exc
    if not isinstance(value, Mapping):
        raise DurableControllerError(f"JSON object required: {path}")
    return dict(value)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("start", "tick", "stop"))
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--capsule", required=True)
    parser.add_argument("--run-root")
    parser.add_argument("--now-utc")
    parser.add_argument("--reason", default="operator_stop")
    parser.add_argument("--execute", action="store_true", help="requires an injected production PBS client; CLI remains dry-run")
    args = parser.parse_args(argv)
    try:
        manifest = _load_object(pathlib.Path(args.manifest).expanduser())
        capsule = _load_object(pathlib.Path(args.capsule).expanduser())
        if args.execute:
            raise DurableControllerError("CLI has no production PBS client; use the reviewed controller wrapper")
        # A command-line invocation is a read-only plan/status boundary.  A
        # production daemon must inject SQLite/PBS adapters explicitly.
        class Controller:
            pass
        controller = Controller()
        supervisor = DurableControllerSupervisor(
            controller=controller,
            manifest=manifest,
            capsule=capsule,
            pbs_client=_NoopPBS(),
            clock=lambda: args.now_utc or dt.datetime.now(dt.timezone.utc),
            run_root=args.run_root,
            execute=False,
        )
        if args.operation == "start":
            report = supervisor.start()
        elif args.operation == "tick":
            report = supervisor.tick(now_utc=args.now_utc)
        else:
            report = supervisor.stop(args.reason)
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    except DurableControllerError as exc:
        print(json.dumps({"ok": False, "error": str(exc), "provider_execution": False}, sort_keys=True))
        return 2


__all__ = ["DurableControllerError", "DurableControllerSupervisor"]


if __name__ == "__main__":
    raise SystemExit(main())
