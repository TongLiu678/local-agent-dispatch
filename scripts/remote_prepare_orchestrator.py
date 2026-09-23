#!/usr/bin/env python3
"""Provider-free SQLite to remote-worker prepare/receipt orchestration.

The SQLite transport outbox deliberately stores a metadata-only envelope while
the job table retains the approved task packet.  ``remote_outbox`` delivers
the envelope, but that path alone does not prove that the corresponding task
packet reached the remote worker's ``prepare`` boundary.  This module joins
those two durable records behind one small, injectable seam:

``SQLite job packet -> RemoteWorkerClient.prepare -> envelope_receive ->
SQLite transport receipt``

It is provider-free.  The default is a read-only plan; opening SSH requires
``execute=True`` and an explicit inventory/client.  Tests inject a fake client,
so the controller-to-worker identity and receipt contract can be exercised
without a provider, network, or real remote mutation.
"""

from __future__ import annotations

import hashlib
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


class PrepareOrchestratorError(RuntimeError):
    """Raised when the approved packet/transport identity cannot be joined."""


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()


def _safe_limit(value: Any) -> int:
    try:
        limit = int(value)
    except (TypeError, ValueError) as exc:
        raise PrepareOrchestratorError("max_items must be an integer") from exc
    if limit < 1 or limit > 128:
        raise PrepareOrchestratorError("max_items must be between 1 and 128")
    return limit


def _mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise PrepareOrchestratorError(f"{field} must be an object")
    return value


def _packet_digest_binding(packet: Mapping[str, Any], envelope: Mapping[str, Any]) -> str:
    """Bind a stored packet to the digest that was enqueued with its envelope.

    ``SQLiteController.enqueue`` adds the non-task ``packet_validation`` audit
    marker after ``enqueue_remote`` builds the envelope.  Accept that one
    known controller mutation, while rejecting every other packet mutation.
    """

    expected = envelope.get("packet_digest")
    if not isinstance(expected, str) or len(expected) != 64:
        raise PrepareOrchestratorError("transport envelope packet_digest is invalid")
    current = _digest(packet)
    if current == expected:
        return "exact"
    projected = dict(packet)
    projected.pop("packet_validation", None)
    if _digest(projected) == expected:
        return "controller_packet_validation_omitted"
    raise PrepareOrchestratorError("SQLite packet digest does not match transport envelope")


def _packet_identity(packet: Mapping[str, Any], envelope: Mapping[str, Any], *, target_id: str) -> dict[str, Any]:
    summary = _mapping(envelope.get("payload_summary"), "envelope.payload_summary")
    job_id = str(packet.get("job_id") or "")
    packet_id = str(packet.get("packet_id") or "")
    if not job_id or job_id != str(summary.get("job_id") or ""):
        raise PrepareOrchestratorError("packet/envelope job_id mismatch")
    if not packet_id or packet_id != str(summary.get("packet_id") or ""):
        raise PrepareOrchestratorError("packet/envelope packet_id mismatch")
    attempts = packet.get("attempts")
    if not isinstance(attempts, list) or not attempts or not isinstance(attempts[0], Mapping):
        raise PrepareOrchestratorError("approved packet must contain one prepared attempt")
    attempt = attempts[0]
    attempt_id = str(attempt.get("attempt_id") or "")
    if not attempt_id or attempt_id != str(summary.get("attempt_id") or ""):
        raise PrepareOrchestratorError("packet/envelope attempt_id mismatch")
    split_remote = bool(
        isinstance(packet.get("desktop_split_placement"), Mapping)
        and packet.get("execution_transport") == "local"
        and packet.get("workload_transport") == "ssh"
    )
    host_id = str(
        packet.get("workload_host")
        if split_remote
        else (attempt.get("host_id") or packet.get("execution_host") or "")
    )
    if host_id != target_id:
        raise PrepareOrchestratorError("packet attempt host does not match envelope target")
    for field in ("provider", "pool_id", "model", "variant"):
        packet_value = attempt.get(field, packet.get(field))
        if field in summary and packet_value != summary.get(field):
            raise PrepareOrchestratorError(f"packet/envelope {field} mismatch")
    return {
        "job_id": job_id,
        "packet_id": packet_id,
        "attempt_id": attempt_id,
        "target_id": target_id,
        "packet_digest": str(envelope["packet_digest"]),
    }


def _receipt_from_report(report: Mapping[str, Any]) -> Mapping[str, Any] | None:
    remote = report.get("remote")
    if isinstance(remote, Mapping) and isinstance(remote.get("receipt"), Mapping):
        return remote["receipt"]
    receipt = report.get("receipt")
    return receipt if isinstance(receipt, Mapping) else None


def _validate_prepare_report(
    report: Mapping[str, Any],
    identity: Mapping[str, Any],
    *,
    expected_transport_digest: str,
) -> str:
    remote = _mapping(report.get("remote"), "prepare.remote")
    if remote.get("status") != "prepared":
        raise PrepareOrchestratorError("remote prepare did not return prepared")
    for field in ("job_id", "packet_id"):
        if remote.get(field) != identity[field]:
            raise PrepareOrchestratorError(f"remote prepare {field} mismatch")
    digest = remote.get("packet_digest")
    if not isinstance(digest, str) or len(digest) != 64:
        raise PrepareOrchestratorError("remote prepare packet_digest is invalid")
    if digest != expected_transport_digest:
        raise PrepareOrchestratorError("remote prepare packet_digest differs from client projection")
    return digest


def _validate_receipt(receipt: Mapping[str, Any], envelope: Mapping[str, Any], request_id: str) -> None:
    if str(receipt.get("request_id") or request_id) != request_id:
        raise PrepareOrchestratorError("remote receipt request_id mismatch")
    if receipt.get("payload_digest") != envelope.get("payload_digest"):
        raise PrepareOrchestratorError("remote receipt payload_digest mismatch")
    if receipt.get("status") not in {"accepted", "completed", "failed"}:
        raise PrepareOrchestratorError("remote receipt status is invalid")


def prepare_once(
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
    """Prepare pending SQLite packets and record remote metadata receipts.

    The method never invokes a provider.  ``execute=False`` performs only the
    packet/envelope join and client dry-run calls.  ``execute=True`` is an
    explicit transport mutation and records the worker's accepted/terminal
    receipt under the controller lease.  A transport failure leaves the
    outbox row pending for an idempotent retry.
    """

    limit = _safe_limit(max_items)
    path = pathlib.Path(db_path).expanduser().resolve()
    if execute and inventory is None and client is None and client_factory is None:
        raise PrepareOrchestratorError("execute requires a private SSH inventory or transport client")
    if client is None:
        if client_factory is not None:
            client = client_factory(inventory)
        else:
            client = RemoteWorkerClient(inventory)  # type: ignore[arg-type]
    owner = owner_id or f"remote-prepare-{uuid.uuid4().hex[:12]}"
    results: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    with SQLiteStore(path) as store:
        with store.controller_lease(owner, ttl_seconds=max(30, int(lease_ttl_seconds))) as lease:
            fence = int(lease["fence_token"])
            rows = store.list_transport_outbox(statuses=("pending",))[:limit]
            for row in rows:
                envelope = row.get("envelope")
                request_id = str(row.get("request_id") or "")
                target_id = str((envelope or {}).get("target_id") or "")
                summary: dict[str, Any] = {
                    "request_id": request_id,
                    "job_id": str(row.get("job_id") or ""),
                    "target_id": target_id,
                    "status_before": row.get("status"),
                    "dry_run": not execute,
                    "provider_execution": False,
                    "ssh_prompt_sent": False,
                }
                try:
                    if not request_id or not isinstance(envelope, Mapping) or not target_id:
                        raise PrepareOrchestratorError("malformed transport outbox row")
                    job = store.get_job(str(row.get("job_id") or ""))
                    if not isinstance(job, Mapping):
                        raise PrepareOrchestratorError("transport outbox job is missing")
                    if str(job.get("status") or "") not in {"queued", "running", "retry"}:
                        raise PrepareOrchestratorError("transport outbox job is not approved for prepare")
                    packet = _mapping(job.get("payload"), "SQLite job payload")
                    digest_mode = _packet_digest_binding(packet, envelope)
                    identity = _packet_identity(packet, envelope, target_id=target_id)
                    prepared = client.prepare(
                        host_id=target_id,
                        packet=packet,
                        execute=execute,
                    )
                    summary["packet_digest_binding"] = digest_mode
                    if not execute:
                        preview_digest = prepared.get("packet_digest")
                        if not isinstance(preview_digest, str) or len(preview_digest) != 64:
                            raise PrepareOrchestratorError("client prepare projection digest is invalid")
                        summary.update({
                            "status_after": "pending",
                            "prepared": True,
                            "receipted": False,
                            "transport_packet_digest": preview_digest,
                            "prepare_command_digest": prepared.get("command_digest"),
                        })
                        results.append(summary)
                        continue
                    # Ask the same client for its deterministic transport
                    # projection before the SSH mutation.  It binds the
                    # remote manifest digest to the exact redacted/mapped
                    # packet that was approved locally without conflating it
                    # with the controller envelope digest.
                    preview = client.prepare(
                        host_id=target_id,
                        packet=packet,
                        execute=False,
                    )
                    preview_digest = preview.get("packet_digest")
                    if not isinstance(preview_digest, str) or len(preview_digest) != 64:
                        raise PrepareOrchestratorError("client prepare projection digest is invalid")
                    prepared_digest = _validate_prepare_report(
                        prepared,
                        identity,
                        expected_transport_digest=preview_digest,
                    )
                    received = client.envelope_receive(
                        host_id=target_id,
                        envelope=envelope,
                        execute=True,
                    )
                    receipt = _receipt_from_report(received)
                    if receipt is None:
                        raise PrepareOrchestratorError("remote receive did not return a receipt")
                    _validate_receipt(receipt, envelope, request_id)
                    stored = store.record_transport_receipt(
                        request_id,
                        receipt,
                        owner_id=owner,
                        fence_token=fence,
                    )
                    summary.update({
                        "status_after": stored.get("status"),
                        "prepared": True,
                        "receipted": True,
                        "transport_packet_digest": preview_digest,
                        "prepared_packet_digest": prepared_digest,
                        "receipt_digest": (stored.get("receipt") or {}).get("receipt_digest"),
                    })
                    results.append(summary)
                except (ClientError, StoreError, PrepareOrchestratorError, RuntimeError, OSError, ValueError, TypeError) as exc:
                    # Preserve the pending row; only the bounded exception
                    # class is exposed to keep prompt/credential material out
                    # of controller summaries.
                    errors.append({**summary, "error": type(exc).__name__})
    return {
        "schema_version": 1,
        "backend": "sqlite",
        "db_path": str(path),
        "execute_requested": bool(execute),
        "provider_execution": False,
        "controller_owner": owner,
        "attempted": len(results) + len(errors),
        "prepared": sum(1 for row in results if row.get("prepared")),
        "receipted": sum(1 for row in results if row.get("receipted")),
        "planned": len(results) if not execute else 0,
        "results": results,
        "errors": errors,
        "ok": not errors,
    }


__all__ = ["PrepareOrchestratorError", "prepare_once"]
