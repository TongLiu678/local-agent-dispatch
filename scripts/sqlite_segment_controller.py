#!/usr/bin/env python3
"""SQLite-backed segment adapter for the continuous-run supervisor.

The JSON sidecars used by :mod:`durable_controller` are useful interchange
artifacts, but they are not the controller's source of truth.  This adapter
binds the supervisor to one SQLite store and one controller lease/fence.  It
keeps recovery database-first, makes checkpoint quiescence fail closed, and
never opens an SSH/provider session by itself.
"""

from __future__ import annotations

import inspect
from collections.abc import Mapping
from typing import Any, Callable

from sqlite_store import FencingError, SQLiteStore, StoreError


class SQLiteSegmentControllerError(StoreError):
    """Raised when the supervisor/SQLite identity contract is invalid."""


def _invoke(method: Callable[..., Any], values: Mapping[str, Any]) -> Any:
    """Pass only parameters accepted by an injected callback."""

    try:
        signature = inspect.signature(method)
    except (TypeError, ValueError):
        return method(**dict(values))
    parameters = signature.parameters
    if any(parameter.kind == inspect.Parameter.VAR_KEYWORD for parameter in parameters.values()):
        return method(**dict(values))
    return method(**{key: value for key, value in values.items() if key in parameters})


class SQLiteSegmentControllerAdapter:
    """Provide the durable-controller seam over an already-held SQLite lease.

    The caller owns the store and lease context, for example::

        with SQLiteStore(db) as store:
            with store.controller_lease("owner") as lease:
                adapter = SQLiteSegmentControllerAdapter(
                    store, owner_id="owner", fence_token=lease["fence_token"]
                )
                supervisor = DurableControllerSupervisor(..., controller=adapter)

    Keeping the lease context outside this object makes takeover explicit and
    avoids a second hidden heartbeat thread.  Every mutating operation still
    passes the owner/fence pair to SQLite, so a stale supervisor is rejected.
    """

    def __init__(
        self,
        store: SQLiteStore,
        *,
        owner_id: str,
        fence_token: int,
        scope: str = "controller",
        checkpoint_callback: Callable[..., Any] | None = None,
    ) -> None:
        if not isinstance(store, SQLiteStore):
            raise TypeError("store must be a SQLiteStore")
        if not isinstance(owner_id, str) or not owner_id.strip():
            raise SQLiteSegmentControllerError("owner_id is required")
        if isinstance(fence_token, bool) or not isinstance(fence_token, int) or fence_token < 1:
            raise SQLiteSegmentControllerError("fence_token must be a positive integer")
        if not isinstance(scope, str) or not scope.strip():
            raise SQLiteSegmentControllerError("scope is required")
        self.store = store
        self.owner_id = owner_id
        self._fence_token = int(fence_token)
        self.scope = scope
        self.checkpoint_callback = checkpoint_callback

    @property
    def fence_token(self) -> int:
        return self._fence_token

    def _identity(
        self,
        values: Mapping[str, Any],
        *,
        require_segment: bool = False,
    ) -> dict[str, Any]:
        owner = str(values.get("owner_id") or self.owner_id)
        fence_value = values.get("fence_token")
        if fence_value is None:
            fence_value = self._fence_token
        try:
            fence = int(fence_value)
        except (TypeError, ValueError) as exc:
            raise SQLiteSegmentControllerError("fence_token is invalid") from exc
        if owner != self.owner_id or fence != self._fence_token:
            raise FencingError("segment controller identity does not match its held lease")
        run_id = str(values.get("run_id") or "")
        if not run_id.strip():
            raise SQLiteSegmentControllerError("run_id is required")
        segment_id = values.get("segment_id")
        if require_segment and not str(segment_id or "").strip():
            raise SQLiteSegmentControllerError("segment_id is required")
        return {
            "run_id": run_id,
            "owner_id": owner,
            "fence_token": fence,
            "segment_id": str(segment_id) if segment_id is not None else None,
        }

    def begin_run_segment(self, **values: Any) -> dict[str, Any]:
        identity = self._identity(values)
        accepted = {
            **identity,
            "sequence": values.get("sequence"),
            "manifest_digest": values.get("manifest_digest"),
            "capsule_digest": values.get("capsule_digest"),
            "scheduler_job_id": values.get("scheduler_job_id"),
            "segment_id": values.get("segment_id"),
            "metadata": values.get("metadata"),
            "scope": self.scope,
        }
        return self.store.begin_run_segment(**accepted)

    def heartbeat(self, **values: Any) -> dict[str, Any]:
        identity = self._identity(values, require_segment=True)
        lease = self.store.heartbeat_controller_lease(
            identity["owner_id"],
            identity["fence_token"],
            scope=self.scope,
        )
        return {
            "ok": True,
            "segment_id": identity["segment_id"],
            "fence_token": identity["fence_token"],
            "lease": lease,
        }

    def append_checkpoint(self, **values: Any) -> dict[str, Any]:
        identity = self._identity(values, require_segment=True)
        accepted = {
            **identity,
            "job_id": values.get("job_id"),
            "attempt_id": values.get("attempt_id"),
            "sequence": values.get("sequence"),
            "payload_digest": values.get("payload_digest"),
            "state_digest": values.get("state_digest"),
            "artifact_manifest": values.get("artifact_manifest"),
            "previous_state_digest": values.get("previous_state_digest"),
            "request_id": values.get("request_id"),
            "scope": self.scope,
        }
        return self.store.append_checkpoint(**accepted)

    def checkpoint_and_flush(self, **values: Any) -> dict[str, Any]:
        """Flush injected checkpoint work or prove database quiescence.

        A missing callback is safe only when no running attempt is owned by
        this controller.  If live work exists, returning ``False`` blocks the
        segment rollover instead of manufacturing a checkpoint.
        """

        identity = self._identity(values, require_segment=True)
        callback = self.checkpoint_callback
        if callable(callback):
            result = _invoke(callback, {**dict(values), **identity})
            if not isinstance(result, Mapping):
                return {
                    "checkpoint_flushed": False,
                    "method": "checkpoint_callback",
                    "reason": "invalid_checkpoint_callback_result",
                }
            flushed = bool(result.get("checkpoint_flushed", result.get("flushed", False)))
            return {
                "checkpoint_flushed": flushed,
                "method": "checkpoint_callback",
                **dict(result),
            }

        # Do not filter by the *new* fence here.  A crashed predecessor may
        # still own a running attempt under its old fence; treating that row
        # as absent would allow a duplicate segment to start.  Rows without a
        # run_id are conservatively considered relevant as well.
        running = [
            item
            for item in self.store.list_running_attempts()
            if item.get("job_run_id") in {None, identity["run_id"]}
        ]
        if running:
            return {
                "checkpoint_flushed": False,
                "method": "checkpoint_adapter_missing",
                "reason": "running_attempts_require_checkpoint_callback",
                "running_attempts": [
                    {
                        "job_id": item.get("job_id"),
                        "attempt_id": item.get("attempt_id"),
                        "run_id": item.get("job_run_id"),
                    }
                    for item in running
                ],
            }
        return {
            "checkpoint_flushed": True,
            "method": "sqlite_quiescent",
            "synthetic": False,
            "checkpoint_count": 0,
            "reason": "no_running_attempts",
        }

    def finish_run_segment(self, **values: Any) -> dict[str, Any]:
        identity = self._identity(values, require_segment=True)
        return self.store.finish_run_segment(
            identity["run_id"],
            identity["owner_id"],
            identity["fence_token"],
            segment_id=identity["segment_id"],
            sequence=values.get("sequence"),
            status=str(values.get("status") or "finished"),
            reason=values.get("reason"),
            scope=self.scope,
        )

    @staticmethod
    def _row_segment_context(row: Mapping[str, Any]) -> dict[str, Any]:
        envelope = row.get("envelope")
        summary = envelope.get("payload_summary") if isinstance(envelope, Mapping) else None
        return dict(summary) if isinstance(summary, Mapping) else {}

    def _transport_rows_for_run(self, run_id: str, segments: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
        segment_ids = {str(item.get("segment_id")) for item in segments}
        selected: list[dict[str, Any]] = []
        # Terminal rows are included as well: after a controller restart a
        # completed PBS segment must be reused, never resubmitted.
        for row in self.store.list_transport_outbox(
            statuses=("pending", "accepted", "completed", "failed")
        ):
            context = self._row_segment_context(row)
            if str(context.get("run_id") or "") == run_id or str(context.get("segment_id") or "") in segment_ids:
                selected.append(row)
        return selected

    def restore_run_state(
        self,
        *,
        run_id: str,
        owner_id: str | None = None,
        fence_token: int | None = None,
        manifest_digest: str | None = None,
        capsule_digest: str | None = None,
    ) -> dict[str, Any]:
        identity = self._identity(
            {"run_id": run_id, "owner_id": owner_id, "fence_token": fence_token},
        )
        segments = self.store.list_run_segments(identity["run_id"])
        # A crashed controller may leave a running segment under an expired
        # fence.  Once this adapter holds the newer lease, adopt only rows
        # whose manifest/Capsule identity is explicitly supplied.  This is an
        # atomic ownership transfer, not a blind "mark stale" operation.
        for segment in segments:
            if segment.get("status") not in {"running", "closing"}:
                continue
            if (
                str(segment.get("owner_id")) == self.owner_id
                and int(segment.get("fence_token") or 0) == self._fence_token
            ):
                continue
            if manifest_digest is None:
                continue
            if capsule_digest is None and segment.get("capsule_digest"):
                continue
            self.store.adopt_run_segment(
                identity["run_id"],
                self.owner_id,
                self._fence_token,
                segment_id=str(segment.get("segment_id")),
                expected_owner_id=str(segment.get("owner_id")),
                expected_fence_token=int(segment.get("fence_token")),
                manifest_digest=manifest_digest,
                capsule_digest=capsule_digest,
                scope=self.scope,
            )
        segments = self.store.list_run_segments(identity["run_id"])
        submissions: list[dict[str, Any]] = []
        for row in self._transport_rows_for_run(identity["run_id"], segments):
            receipt = row.get("receipt")
            if not isinstance(receipt, Mapping) or not receipt.get("pbs_job_id"):
                continue
            context = self._row_segment_context(row)
            if manifest_digest and context.get("manifest_digest") not in {None, manifest_digest}:
                continue
            if capsule_digest and context.get("capsule_digest") not in {None, capsule_digest}:
                continue
            sequence = receipt.get("sequence", context.get("sequence"))
            try:
                sequence = int(sequence)
            except (TypeError, ValueError):
                continue
            item = dict(receipt)
            item.setdefault("run_id", identity["run_id"])
            item.setdefault("segment_id", context.get("segment_id"))
            item.setdefault("sequence", sequence)
            item.setdefault("manifest_digest", context.get("manifest_digest"))
            item.setdefault("capsule_digest", context.get("capsule_digest"))
            submissions.append(item)
        return {
            "schema_version": 1,
            "run_id": identity["run_id"],
            "segments": segments,
            "submissions": submissions,
            "transport_rows": self._transport_rows_for_run(identity["run_id"], segments),
            "source": "sqlite",
        }

    def reconcile(
        self,
        *,
        run_id: str,
        owner_id: str | None = None,
        fence_token: int | None = None,
        **_: Any,
    ) -> dict[str, Any]:
        identity = self._identity(
            {"run_id": run_id, "owner_id": owner_id, "fence_token": fence_token},
        )
        segments = self.store.list_run_segments(identity["run_id"])
        transport = self._transport_rows_for_run(identity["run_id"], segments)
        return {
            "source": "sqlite",
            "run_id": identity["run_id"],
            "active_segments": [
                item for item in segments if item.get("status") in {"running", "closing"}
            ],
            "segment_count": len(segments),
            "transport_pending": sum(1 for item in transport if item.get("status") == "pending"),
            "transport_accepted": sum(1 for item in transport if item.get("status") == "accepted"),
            "transport_rows": transport,
        }


__all__ = ["SQLiteSegmentControllerAdapter", "SQLiteSegmentControllerError"]
