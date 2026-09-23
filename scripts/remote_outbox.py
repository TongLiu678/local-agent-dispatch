#!/usr/bin/env python3
"""Bounded controller-side delivery for the SQLite remote envelope outbox.

This module opens the SSH transport only when ``execute=True``.  The default
is a read-only dry-run that validates target identity and reports pending
request IDs.  A delivery records only the worker's metadata receipt under the
same controller lease/fence; it never runs OpenCode or infers a new task.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import uuid
from typing import Any, Callable, Mapping

SCRIPT_ROOT = pathlib.Path(__file__).resolve().parent
if str(SCRIPT_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPT_ROOT))

from remote_worker_client import ClientError, RemoteWorkerClient  # noqa: E402
from sqlite_store import SQLiteStore, StoreError  # noqa: E402


class OutboxError(RuntimeError):
    """Raised when a bounded outbox delivery request is invalid."""


def _safe_limit(value: Any) -> int:
    try:
        limit = int(value)
    except (TypeError, ValueError) as exc:
        raise OutboxError("max_items must be an integer") from exc
    if limit < 1 or limit > 128:
        raise OutboxError("max_items must be between 1 and 128")
    return limit


def _receipt_from_report(report: Mapping[str, Any]) -> Mapping[str, Any] | None:
    remote = report.get("remote")
    if isinstance(remote, Mapping):
        receipt = remote.get("receipt")
        if isinstance(receipt, Mapping):
            return receipt
    receipt = report.get("receipt")
    return receipt if isinstance(receipt, Mapping) else None


def sync_once(
    db_path: pathlib.Path | str,
    *,
    inventory: pathlib.Path | str | Mapping[str, Any] | None = None,
    execute: bool = False,
    max_items: int = 32,
    owner_id: str | None = None,
    lease_ttl_seconds: int = 90,
    client: Any | None = None,
    client_factory: Callable[[Any], Any] | None = None,
) -> dict[str, Any]:
    """Deliver a bounded batch of pending envelopes.

    ``client``/``client_factory`` are test seams.  Production callers pass an
    inventory and receive a normal :class:`RemoteWorkerClient`; no provider
    credentials or packet bodies are loaded by this function.
    """
    limit = _safe_limit(max_items)
    path = pathlib.Path(db_path).expanduser().resolve()
    if execute and inventory is None and client is None and client_factory is None:
        raise OutboxError("execute requires a private SSH inventory or transport client")
    if client is None:
        if client_factory is not None:
            client = client_factory(inventory)
        else:
            client = RemoteWorkerClient(inventory)  # type: ignore[arg-type]
    owner = owner_id or f"remote-outbox-{uuid.uuid4().hex[:12]}"
    results: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    with SQLiteStore(path) as store:
        with store.controller_lease(owner, ttl_seconds=max(30, int(lease_ttl_seconds))) as lease:
            fence = int(lease["fence_token"])
            # ``accepted`` means the worker receipt is durably recorded locally;
            # do not redeliver it on every poll.  A separate reconciliation
            # operation may explicitly inspect accepted rows if needed.
            rows = store.list_transport_outbox(statuses=("pending",))[:limit]
            for row in rows:
                request_id = str(row.get("request_id") or "")
                envelope = row.get("envelope")
                target_id = str((envelope or {}).get("target_id") or "")
                summary = {
                    "request_id": request_id,
                    "target_id": target_id,
                    "operation": (envelope or {}).get("operation"),
                    "status_before": row.get("status"),
                    "dry_run": not execute,
                    "provider_execution": False,
                }
                if not request_id or not isinstance(envelope, Mapping) or not target_id:
                    errors.append({**summary, "error": "malformed_outbox_row"})
                    continue
                if not execute:
                    # The client builds and validates the exact SSH argv, but
                    # does not open a session in dry-run mode.
                    try:
                        preview = client.envelope_receive(
                            host_id=target_id, envelope=envelope, execute=False
                        )
                        summary["command_digest"] = preview.get("command_digest")
                        results.append(summary)
                    except (ClientError, ValueError, TypeError) as exc:
                        errors.append({**summary, "error": type(exc).__name__})
                    continue
                try:
                    report = client.envelope_receive(
                        host_id=target_id, envelope=envelope, execute=True
                    )
                    receipt = _receipt_from_report(report)
                    if receipt is None:
                        raise OutboxError("worker response did not contain an accepted receipt")
                    stored = store.record_transport_receipt(
                        request_id,
                        receipt,
                        owner_id=owner,
                        fence_token=fence,
                    )
                    results.append({
                        **summary,
                        "status_after": stored.get("status"),
                        "receipt_digest": (stored.get("receipt") or {}).get("receipt_digest"),
                    })
                except (ClientError, StoreError, OutboxError, RuntimeError, OSError, ValueError, TypeError) as exc:
                    # A transport failure does not turn the task into a
                    # failed provider attempt; it remains pending for retry.
                    errors.append({**summary, "error": type(exc).__name__})
    return {
        "schema_version": 1,
        "backend": "sqlite",
        "db_path": str(path),
        "execute_requested": bool(execute),
        "provider_execution": False,
        "controller_owner": owner,
        "attempted": len(results) + len(errors),
        "delivered": len(results) if execute else 0,
        "planned": len(results) if not execute else 0,
        "results": results,
        "errors": errors,
        "ok": not errors,
    }


def reconcile_once(
    db_path: pathlib.Path | str,
    *,
    inventory: pathlib.Path | str | Mapping[str, Any] | None = None,
    execute: bool = False,
    max_items: int = 32,
    owner_id: str | None = None,
    lease_ttl_seconds: int = 90,
    client: Any | None = None,
    client_factory: Callable[[Any], Any] | None = None,
) -> dict[str, Any]:
    """Reconcile controller ``accepted`` rows from a worker status query.

    This is deliberately separate from :func:`sync_once`: an accepted receipt
    means the worker durably received an envelope, not that its work reached a
    terminal state.  Reconciliation only asks for the metadata-only receipt;
    it never sends a prompt, starts a provider, or promotes an absent receipt.
    The controller lease/fence protects every terminal write and retries remain
    idempotent through ``SQLiteStore.record_transport_receipt``.
    """

    limit = _safe_limit(max_items)
    path = pathlib.Path(db_path).expanduser().resolve()
    if execute and inventory is None and client is None and client_factory is None:
        raise OutboxError("execute requires a private SSH inventory or transport client")
    if client is None:
        if client_factory is not None:
            client = client_factory(inventory)
        else:
            client = RemoteWorkerClient(inventory)  # type: ignore[arg-type]
    owner = owner_id or f"remote-reconcile-{uuid.uuid4().hex[:12]}"
    results: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    with SQLiteStore(path) as store:
        with store.controller_lease(owner, ttl_seconds=max(30, int(lease_ttl_seconds))) as lease:
            fence = int(lease["fence_token"])
            rows = store.list_transport_outbox(statuses=("accepted",))[:limit]
            for row in rows:
                request_id = str(row.get("request_id") or "")
                envelope = row.get("envelope")
                target_id = str((envelope or {}).get("target_id") or "")
                summary = {
                    "request_id": request_id,
                    "target_id": target_id,
                    "operation": (envelope or {}).get("operation"),
                    "status_before": row.get("status"),
                    "dry_run": not execute,
                    "provider_execution": False,
                    "reconcile": True,
                }
                if not request_id or not isinstance(envelope, Mapping) or not target_id:
                    errors.append({**summary, "error": "malformed_outbox_row"})
                    continue
                try:
                    report = client.envelope_status(
                        host_id=target_id,
                        request_id=request_id,
                        execute=execute,
                    )
                    remote = report.get("remote") if isinstance(report, Mapping) else None
                    remote_status = remote.get("status") if isinstance(remote, Mapping) else None
                    receipt = _receipt_from_report(report)
                    summary["remote_status"] = remote_status
                    if not execute:
                        if isinstance(report, Mapping):
                            summary["command_digest"] = report.get("command_digest")
                        results.append(summary)
                        continue
                    if receipt is None:
                        # ``pending`` is valid after an interrupted receive;
                        # preserve the accepted row and let a later poll retry.
                        if remote_status in {"pending", "accepted"}:
                            results.append(summary)
                            continue
                        raise OutboxError("worker status did not contain a receipt")
                    stored = store.record_transport_receipt(
                        request_id,
                        receipt,
                        owner_id=owner,
                        fence_token=fence,
                    )
                    results.append({
                        **summary,
                        "status_after": stored.get("status"),
                        "receipt_digest": (stored.get("receipt") or {}).get("receipt_digest"),
                    })
                except (ClientError, StoreError, OutboxError, RuntimeError, OSError, ValueError, TypeError) as exc:
                    # A disconnected or stale worker never turns an accepted
                    # row into failed; preserve it for the next reconciliation.
                    errors.append({**summary, "error": type(exc).__name__})
    return {
        "schema_version": 1,
        "backend": "sqlite",
        "db_path": str(path),
        "execute_requested": bool(execute),
        "provider_execution": False,
        "controller_owner": owner,
        "attempted": len(results) + len(errors),
        "reconciled": len(results) if execute else 0,
        "planned": len(results) if not execute else 0,
        "results": results,
        "errors": errors,
        "ok": not errors,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True)
    parser.add_argument("--inventory")
    parser.add_argument("--execute", action="store_true", help="open SSH and deliver envelopes")
    parser.add_argument("--reconcile", action="store_true", help="query accepted rows instead of delivering pending rows")
    parser.add_argument("--max-items", type=int, default=32)
    parser.add_argument("--owner-id")
    args = parser.parse_args(argv)
    try:
        operation = reconcile_once if args.reconcile else sync_once
        report = operation(
            args.db,
            inventory=args.inventory,
            execute=args.execute,
            max_items=args.max_items,
            owner_id=args.owner_id,
        )
    except (OutboxError, ClientError, StoreError, OSError, ValueError) as exc:
        print(json.dumps({"schema_version": 1, "ok": False, "error": type(exc).__name__}, sort_keys=True))
        return 2
    print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
