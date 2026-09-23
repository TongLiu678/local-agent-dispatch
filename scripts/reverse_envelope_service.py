#!/usr/bin/env python3
"""Loopback-only JSON bridge for the provider-free remote envelope spool.

The bridge is deliberately narrower than an SSH command runner.  It accepts
only fixed envelope operations and delegates to ``remote_worker``.  A worker
host may expose it on loopback while a project-owned reverse SSH tunnel makes
the controller's loopback the only reachable endpoint.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import socketserver
from typing import Any, Mapping

from remote_worker import (  # type: ignore
    WorkerError,
    complete_envelope,
    envelope_status,
    pending_envelopes,
    receive_envelope,
)


SCHEMA_VERSION = 1
MAX_FRAME_BYTES = 131_072
_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_ALLOWED_OPERATIONS = {
    "envelope-receive",
    "envelope-status",
    "envelope-pending",
    "envelope-complete",
}
_FORBIDDEN_KEYS = {
    "prompt",
    "argv",
    "environment",
    "env",
    "token",
    "password",
    "secret",
    "authorization",
    "private_key",
}


class BridgeError(ValueError):
    """Raised for an invalid or unsafe bridge request."""


def _safe_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise BridgeError(f"{field} is invalid")
    return value


def _safe_digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise BridgeError(f"{field} is invalid")
    return value


def _reject_forbidden_keys(value: Any, path: str = "request") -> None:
    if isinstance(value, Mapping):
        for raw_key, child in value.items():
            key = str(raw_key)
            lowered = key.lower()
            if lowered in _FORBIDDEN_KEYS or lowered.endswith("_token") or "credential" in lowered:
                raise BridgeError(f"{path}.{key} is not allowed")
            _reject_forbidden_keys(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_forbidden_keys(child, f"{path}[{index}]")


def _safe_output(value: Any) -> Any:
    """Project worker output to bounded metadata without prompt-like fields."""

    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for raw_key, child in value.items():
            key = str(raw_key)
            lowered = key.lower()
            if lowered in _FORBIDDEN_KEYS or lowered in {"prompt", "argv", "environment", "env"}:
                continue
            result[key] = _safe_output(child)
        return result
    if isinstance(value, list):
        return [_safe_output(child) for child in value[:256]]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return None


def _encoded_size(value: Mapping[str, Any]) -> int:
    try:
        return len(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    except (TypeError, ValueError) as exc:
        raise BridgeError("request is not JSON serializable") from exc


def _validate_request(request: Any, *, max_frame_bytes: int) -> dict[str, Any]:
    if not isinstance(request, Mapping):
        raise BridgeError("request must be an object")
    if _encoded_size(request) > max_frame_bytes:
        raise BridgeError("request exceeds frame limit")
    _reject_forbidden_keys(request)
    if request.get("schema_version") != SCHEMA_VERSION:
        raise BridgeError("unsupported schema_version")
    rpc_id = _safe_id(request.get("request_id"), "request_id")
    operation = request.get("operation")
    if not isinstance(operation, str) or operation not in _ALLOWED_OPERATIONS:
        raise BridgeError("operation is not allowed")
    allowed = {
        "schema_version",
        "request_id",
        "operation",
        "envelope",
        "target_request_id",
        "completion_status",
        "result_digest",
        "error_code",
    }
    if any(str(key) not in allowed for key in request):
        raise BridgeError("request contains unsupported fields")
    canonical: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "request_id": rpc_id,
        "operation": operation,
    }
    if operation == "envelope-receive":
        envelope = request.get("envelope")
        if not isinstance(envelope, Mapping):
            raise BridgeError("envelope is required")
        canonical["envelope"] = dict(envelope)
    elif operation in {"envelope-status", "envelope-complete"}:
        canonical["target_request_id"] = _safe_id(request.get("target_request_id"), "target_request_id")
    if operation == "envelope-complete":
        status = request.get("completion_status")
        if status not in {"completed", "failed"}:
            raise BridgeError("completion_status is invalid")
        canonical["completion_status"] = status
        if request.get("result_digest") is not None:
            canonical["result_digest"] = _safe_digest(request["result_digest"], "result_digest")
        if request.get("error_code") is not None:
            error_code = request["error_code"]
            if not isinstance(error_code, str) or not re.fullmatch(r"[a-z0-9_.:-]{1,80}\Z", error_code):
                raise BridgeError("error_code is invalid")
            canonical["error_code"] = error_code
    return canonical


class BridgeService:
    """Dispatch fixed envelope operations against one durable worker spool."""

    def __init__(self, spool_root: pathlib.Path | str, *, max_frame_bytes: int = MAX_FRAME_BYTES):
        self.spool_root = pathlib.Path(spool_root).expanduser().resolve()
        if self.spool_root == pathlib.Path(self.spool_root.anchor):
            raise BridgeError("spool_root may not be filesystem root")
        if max_frame_bytes < 1024 or max_frame_bytes > MAX_FRAME_BYTES:
            raise BridgeError("max_frame_bytes is invalid")
        self.max_frame_bytes = int(max_frame_bytes)

    def handle_request(self, request: Any) -> dict[str, Any]:
        try:
            canonical = _validate_request(request, max_frame_bytes=self.max_frame_bytes)
            operation = canonical["operation"]
            if operation == "envelope-receive":
                result = receive_envelope(self.spool_root, canonical["envelope"])
            elif operation == "envelope-status":
                result = envelope_status(self.spool_root, canonical["target_request_id"])
            elif operation == "envelope-pending":
                result = pending_envelopes(self.spool_root)
            else:
                result = complete_envelope(
                    self.spool_root,
                    canonical["target_request_id"],
                    status=canonical["completion_status"],
                    result_digest=canonical.get("result_digest"),
                    error_code=canonical.get("error_code"),
                )
            response = {
                "schema_version": SCHEMA_VERSION,
                "request_id": canonical["request_id"],
                "operation": operation,
                "status": "ok",
                "result": _safe_output(result),
            }
            if _encoded_size(response) > self.max_frame_bytes:
                raise BridgeError("response exceeds frame limit")
            return response
        except (BridgeError, WorkerError, OSError, TypeError, ValueError) as exc:
            return {
                "schema_version": SCHEMA_VERSION,
                "request_id": request.get("request_id") if isinstance(request, Mapping) else None,
                "status": "error",
                "error": type(exc).__name__,
            }


class _RequestHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:  # pragma: no cover - exercised by integration tests
        service: BridgeService = self.server.bridge_service  # type: ignore[attr-defined]
        self.connection.settimeout(10.0)
        frame = self.rfile.readline(service.max_frame_bytes + 1)
        if not frame or len(frame) > service.max_frame_bytes:
            response = {"schema_version": SCHEMA_VERSION, "status": "error", "error": "frame_limit"}
        else:
            try:
                request = json.loads(frame.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                response = {"schema_version": SCHEMA_VERSION, "status": "error", "error": "invalid_json"}
            else:
                response = service.handle_request(request)
        encoded = (json.dumps(response, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        self.wfile.write(encoded[: service.max_frame_bytes])


class LoopbackBridgeServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, bind: str, port: int, service: BridgeService):
        if bind not in {"127.0.0.1", "::1"}:
            raise BridgeError("bridge must bind to loopback")
        self.bridge_service = service
        super().__init__((bind, port), _RequestHandler)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="loopback-only reverse envelope worker")
    parser.add_argument("--spool", required=True)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--max-frame-bytes", type=int, default=MAX_FRAME_BYTES)
    args = parser.parse_args(argv)
    service = BridgeService(args.spool, max_frame_bytes=args.max_frame_bytes)
    with LoopbackBridgeServer(args.bind, args.port, service) as server:
        print(json.dumps({"schema_version": 1, "status": "listening", "bind": args.bind, "port": args.port}, sort_keys=True), flush=True)
        server.serve_forever(poll_interval=0.5)
    return 0


__all__ = ["BridgeError", "BridgeService", "LoopbackBridgeServer", "MAX_FRAME_BYTES"]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
