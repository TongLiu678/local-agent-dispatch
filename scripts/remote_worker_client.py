#!/usr/bin/env python3
"""Bounded SSH transport for the provider-free :mod:`remote_worker` seam.

The worker itself is deliberately a local spool contract.  This module adds a
small, auditable transport boundary around it without turning the dispatch
skill into a generic SSH command runner:

* inventory entries are explicit SSH hosts with a bounded port and absolute,
  shell-safe remote paths;
* the remote command is assembled as an argv list, never through ``shell=True``
  or string concatenation;
* a prepared (prompt/argv/credential-redacted) task packet travels on SSH
  stdin with ``--packet -``;
* every operation is dry-run by default and requires ``execute=True`` (or the
  CLI's explicit ``--execute``) before opening SSH;
* stdout is parsed as JSON and stderr is reduced to a length/digest, so raw
  prompt, argv, token, or provider output cannot become a local log;
* execution-host and workload-host placement are carried as evidence.  A
  split placement requires a declared wrapper, but this seam never executes
  that wrapper.

It is intentionally provider-free.  ``fake-execute`` exercises the same
remote worker lease/artifact/handoff contract and is suitable for CI using a
fake ``ssh`` binary; it is not a provider fallback.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import os
import pathlib
import posixpath
import re
import subprocess
import sys
from typing import Any, Callable, Mapping, Sequence

try:  # direct script import
    from remote_envelope import EnvelopeError, build_envelope
except ImportError:  # pragma: no cover - package-style fallback
    from .remote_envelope import EnvelopeError, build_envelope  # type: ignore


SCHEMA_VERSION = 1
_HOST_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_USER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}\Z")
_HOSTNAME_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,252})\Z")
_SAFE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_LEASE_RE = re.compile(r"[A-Fa-f0-9]{8,256}\Z")
_REMOTE_SEGMENT_RE = re.compile(r"[A-Za-z0-9_+@=,:.-]+\Z")
# SSH executes the final command through the remote user's shell.  An
# explicitly configured interpreter may therefore be either an absolute
# path (validated by ``_remote_path``) or a simple executable name.  Keep the
# latter deliberately narrower than a general shell token: no whitespace,
# quoting, expansion, or command separators are accepted.
_REMOTE_COMMAND_RE = re.compile(r"[A-Za-z0-9_./+-]+\Z")
_SECRET_RE = re.compile(
    r"(?:secret|password|api[_-]?key|credential|authorization|access[_-]?key)",
    re.IGNORECASE,
)
_DROP_PACKET_KEYS = {"prompt", "argv", "environment", "env"}
_SAFE_NUMERIC_TOKEN_KEYS = {
    "tokens",
    "input_tokens",
    "output_tokens",
    "total_tokens",
    "estimated_input_tokens",
    "estimated_output_tokens",
}
_OPERATIONS = {
    "bootstrap",
    "prepare",
    "status",
    "recover",
    "process-identity",
    "handoff",
    "resume",
    "fake-execute",
    "fake-service",
    "envelope-receive",
    "envelope-complete",
    "envelope-status",
    "envelope-pending",
}
_PACKET_PATH_FIELDS = {
    "workspace",
    "project_path",
    "worktree_path",
    "prompt_file",
    "result_source_path",
    "output_path",
    "runtime_state_path",
    "watch_path",
    "require_path",
    "remote_workspace",
}
_PROCESS_IDENTITY_KEYS = {
    "pid",
    "start_time",
    "process_group",
    "run_id",
    "owned_by_dispatch",
    "liveness_state",
    "observed_at_utc",
    "ttl_seconds",
}


class ClientError(ValueError):
    """Raised when a transport request cannot be made safely."""


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()


def _text(value: Any, field: str, *, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value or any(char in value for char in "\0\r\n"):
        raise ClientError(f"{field} is invalid")
    if pattern is not None and not pattern.fullmatch(value):
        raise ClientError(f"{field} is invalid")
    return value


def _remote_path(value: Any, field: str) -> str:
    """Validate a remote absolute path before it is placed in SSH argv.

    OpenSSH receives command arguments through a remote shell.  We therefore
    accept only absolute paths whose individual components are a conservative
    shell-safe character set and reject ``..``, whitespace, quoting, and
    expansion characters.  This is stricter than a normal filesystem path on
    purpose; paths with spaces can be supported by a future fixed bootstrap
    protocol without weakening this seam.
    """

    value = _text(value, field)
    if not value.startswith("/") or value == "/":
        raise ClientError(f"{field} must be a non-root absolute path")
    pieces = value.split("/")
    if any(piece in {"", ".", ".."} for piece in pieces[1:]):
        raise ClientError(f"{field} contains an unsafe path component")
    if any(not _REMOTE_SEGMENT_RE.fullmatch(piece) for piece in pieces[1:]):
        raise ClientError(f"{field} contains an unsafe path component")
    return value


def _local_path(value: Any, field: str) -> str:
    if isinstance(value, pathlib.Path):
        value = str(value)
    value = _text(value, field)
    return str(pathlib.Path(value).expanduser())


def _remote_worker_python(value: Any, field: str) -> str:
    """Validate the interpreter used for the fixed remote worker bundle.

    Most hosts expose ``python3`` on PATH, but older PBS compute nodes may
    only provide a project-local compatible interpreter.  The inventory must
    be able to declare that interpreter without weakening the fixed-command
    remote-shell boundary.
    """

    if isinstance(value, str) and value.startswith("/"):
        return _remote_path(value, field)
    value = _text(value, field, pattern=_REMOTE_COMMAND_RE)
    return value


def _host_row(row: Mapping[str, Any], *, expected_id: str | None = None) -> dict[str, Any]:
    if not isinstance(row, Mapping):
        raise ClientError("host inventory entries must be objects")
    host_id = _text(row.get("host_id"), "host_id", pattern=_HOST_ID_RE)
    if expected_id is not None and host_id != expected_id:
        raise ClientError("host inventory identity mismatch")
    transport = row.get("transport")
    if transport != "ssh":
        raise ClientError(f"host {host_id} must use transport=ssh")
    hostname = _text(row.get("hostname"), f"host {host_id} hostname", pattern=_HOSTNAME_RE)
    # A port is mandatory here.  It prevents a stale/default SSH target from
    # being selected when an inventory contains several provider endpoints.
    try:
        port = int(row.get("port"))
    except (TypeError, ValueError) as exc:
        raise ClientError(f"host {host_id} port is invalid") from exc
    if port < 1 or port > 65535:
        raise ClientError(f"host {host_id} port is outside 1..65535")
    user = _text(row.get("user") or "root", f"host {host_id} user", pattern=_USER_RE)
    worker_script = _remote_path(
        row.get("worker_script") or row.get("remote_worker_script"),
        f"host {host_id} worker_script",
    )
    project_path = _remote_path(
        row.get("project_path") or row.get("remote_project_path"),
        f"host {host_id} project_path",
    )
    spool_path = _remote_path(
        row.get("spool_path") or row.get("remote_spool_path"),
        f"host {host_id} spool_path",
    )
    script_parent = posixpath.dirname(worker_script)
    schema_dir: str | None = None
    if row.get("schema_dir") is not None:
        schema_dir = _remote_path(row.get("schema_dir"), f"host {host_id} schema_dir")
    elif posixpath.basename(script_parent) == "scripts":
        schema_dir = posixpath.normpath(
            posixpath.join(posixpath.dirname(script_parent), "schemas")
        )
    normalized: dict[str, Any] = {
        "host_id": host_id,
        "transport": "ssh",
        "hostname": hostname,
        "user": user,
        "port": port,
        "worker_python": _remote_worker_python(
            row.get("worker_python") or "python3", f"host {host_id} worker_python"
        ),
        "worker_script": worker_script,
        "project_path": project_path,
        "spool_path": spool_path,
    }
    if schema_dir is not None:
        normalized["schema_dir"] = schema_dir
    if row.get("identity_file") is not None:
        normalized["identity_file"] = _local_path(
            row.get("identity_file"), f"host {host_id} identity_file"
        )
    # A small number of legacy cluster gateways still offer only ssh-rsa for
    # host-key/signature negotiation.  This compatibility escape hatch is
    # explicit per host and maps to two fixed OpenSSH options; arbitrary SSH
    # option injection remains unsupported.
    if row.get("ssh_legacy_rsa") is not None:
        if not isinstance(row.get("ssh_legacy_rsa"), bool):
            raise ClientError(f"host {host_id} ssh_legacy_rsa must be boolean")
        normalized["ssh_legacy_rsa"] = bool(row["ssh_legacy_rsa"])
    # These fields are informational and are intentionally copied only after
    # validation.  No arbitrary inventory key is allowed to become a command
    # option (for example, ``ssh_options`` or a remote shell fragment).
    if row.get("tags") is not None:
        tags = row.get("tags")
        if not isinstance(tags, list) or not all(isinstance(item, str) for item in tags):
            raise ClientError(f"host {host_id} tags must be a string list")
        normalized["tags"] = list(tags)
    return normalized


def _local_host_row(row: Mapping[str, Any], *, expected_id: str | None = None) -> dict[str, Any]:
    """Normalize an explicit controller row for desktop/remote split packets.

    Local rows are never SSH targets and never contribute command arguments.
    They are retained only as an identity witness so a packet cannot claim a
    different execution host. Desktop CLI/auth evidence remains in the
    validated split contract; credentials are not loaded here.
    """

    if not isinstance(row, Mapping):
        raise ClientError("local inventory entries must be objects")
    host_id = _text(row.get("host_id"), "host_id", pattern=_HOST_ID_RE)
    if expected_id is not None and host_id != expected_id:
        raise ClientError("host inventory identity mismatch")
    if row.get("transport") != "local":
        raise ClientError(f"host {host_id} must use transport=local")
    normalized: dict[str, Any] = {"host_id": host_id, "transport": "local"}
    for key in ("project_path", "workspace"):
        value = row.get(key)
        if value is None:
            continue
        text = _local_path(value, f"host {host_id} {key}")
        if not pathlib.Path(text).is_absolute():
            raise ClientError(f"host {host_id} {key} must be absolute")
        normalized[key] = text
    return normalized


def _is_local_controller(value: Any) -> bool:
    """Return whether an inventory row explicitly describes the controller."""

    return isinstance(value, Mapping) and value.get("transport") == "local"


def load_inventory(
    path: pathlib.Path | str, *, include_local: bool = False
) -> dict[str, dict[str, Any]]:
    """Load and strictly validate a private host inventory."""

    path = pathlib.Path(path).expanduser()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ClientError("host inventory is not valid JSON") from exc
    raw_hosts: Any
    if isinstance(payload, dict):
        raw_hosts = payload.get("hosts", payload)
    else:
        raw_hosts = payload
    rows: list[Mapping[str, Any]] = []
    if isinstance(raw_hosts, list):
        rows = raw_hosts
    elif isinstance(raw_hosts, dict):
        for host_id, value in raw_hosts.items():
            if not isinstance(value, Mapping):
                raise ClientError("host inventory map values must be objects")
            row = dict(value)
            row.setdefault("host_id", host_id)
            rows.append(row)
    else:
        raise ClientError("host inventory must contain a hosts list or object")
    if not rows:
        raise ClientError("host inventory must contain at least one host")
    result: dict[str, dict[str, Any]] = {}
    ssh_count = 0
    for row in rows:
        # The shared private inventory also describes the local controller.
        # This transport only accepts SSH targets, so keep the controller
        # metadata out of the remote-host map instead of failing before the
        # requested SSH host can be selected. Unknown transports remain a
        # validation error below; only an explicit local entry is skipped.
        if _is_local_controller(row):
            if include_local:
                normalized_local = _local_host_row(row)
                local_id = normalized_local["host_id"]
                if local_id in result:
                    raise ClientError(f"duplicate host_id: {local_id}")
                result[local_id] = normalized_local
            continue
        normalized = _host_row(row)
        host_id = normalized["host_id"]
        if host_id in result:
            raise ClientError(f"duplicate host_id: {host_id}")
        result[host_id] = normalized
        ssh_count += 1
    if ssh_count == 0:
        raise ClientError("host inventory must contain at least one SSH host")
    return result


def _is_secret_key(key: str) -> bool:
    lowered = key.lower()
    if lowered in _SAFE_NUMERIC_TOKEN_KEYS:
        return False
    return bool(_SECRET_RE.search(lowered) or lowered == "token" or lowered.endswith("_token"))


def _redact(value: Any, path: str, removed: list[str]) -> Any:
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for raw_key, child in value.items():
            key = str(raw_key)
            # A split packet may carry one allow-listed remote validator.  Its
            # argv is a validation contract (already shell-restricted by
            # desktop_split_placement), not a provider prompt.  Preserve it
            # so the contract digest remains stable; all other argv fields
            # remain redacted as before.
            keep_validator_argv = key.lower() == "argv" and path.endswith("remote_validator")
            if (key.lower() in _DROP_PACKET_KEYS and not keep_validator_argv) or _is_secret_key(key):
                removed.append(path + "." + key)
                continue
            result[key] = _redact(child, path + "." + key, removed)
        return result
    if isinstance(value, list):
        return [_redact(child, f"{path}[{index}]", removed) for index, child in enumerate(value)]
    return copy.deepcopy(value)


def redacted_packet(packet: Mapping[str, Any]) -> tuple[dict[str, Any], int]:
    """Return a deep-redacted packet and count removed sensitive fields.

    Field names are not returned to callers because even a path such as
    ``attempts[0].argv`` is unnecessarily useful to a log scraper.  The
    worker performs its own schema and path checks after receiving the packet.
    """

    if not isinstance(packet, Mapping):
        raise ClientError("task packet must be an object")
    removed: list[str] = []
    cleaned = _redact(packet, "packet", removed)
    if not isinstance(cleaned, dict):  # pragma: no cover - Mapping always maps
        raise ClientError("task packet must be an object")
    for field in ("packet_id", "job_id"):
        _text(cleaned.get(field), f"packet {field}", pattern=_SAFE_ID_RE)
    return cleaned, len(removed)


def _process_identity_payload(identity: Mapping[str, Any]) -> dict[str, Any]:
    """Keep only non-secret process identity fields for SSH stdin."""

    if not isinstance(identity, Mapping):
        raise ClientError("process_identity must be an object")
    unknown = {str(key) for key in identity if str(key) not in _PROCESS_IDENTITY_KEYS}
    if unknown:
        raise ClientError("process_identity contains unsupported fields")
    payload = {str(key): copy.deepcopy(identity[key]) for key in _PROCESS_IDENTITY_KEYS if key in identity}
    if "owned_by_dispatch" in payload and payload["owned_by_dispatch"] is not True:
        raise ClientError("process_identity must prove ownership")
    return payload


def _canonical_envelope(envelope: Mapping[str, Any]) -> dict[str, Any]:
    """Validate/canonicalize the metadata-only envelope before transport."""

    if not isinstance(envelope, Mapping):
        raise ClientError("envelope must be an object")
    try:
        canonical = build_envelope(
            request_id=envelope.get("request_id"),
            source_id=envelope.get("source_id"),
            target_id=envelope.get("target_id"),
            operation=envelope.get("operation"),
            packet_digest=envelope.get("packet_digest"),
            payload_summary=envelope.get("payload_summary"),
            idempotency_key=envelope.get("idempotency_key"),
            created_at=envelope.get("created_at"),
        )
    except (EnvelopeError, TypeError, AttributeError) as exc:
        raise ClientError("envelope is invalid") from exc
    if canonical.get("operation") == "execute.prepared":
        summary = canonical.get("payload_summary") or {}
        if not isinstance(summary.get("model"), str) or not summary["model"].strip():
            raise ClientError("prepared envelope requires an exact model")
        gemini_null_variant = (
            summary.get("provider") == "antigravity"
            and summary.get("pool_id") == "antigravity.gemini"
            and summary.get("model") == "gemini-3.6-flash-high"
            and summary.get("variant") is None
        )
        if (
            not isinstance(summary.get("variant"), str)
            or not summary["variant"].strip()
        ) and not gemini_null_variant:
            raise ClientError("prepared envelope requires an exact variant")
    return canonical


def _under_posix_root(value: str, root: str) -> bool:
    """Return whether an absolute POSIX path is inside ``root``."""
    normalized = posixpath.normpath(value)
    normalized_root = posixpath.normpath(root)
    return normalized == normalized_root or normalized.startswith(normalized_root + "/")


def _map_packet_paths(packet: Mapping[str, Any], host: Mapping[str, Any]) -> dict[str, Any]:
    """Map local absolute packet paths into the selected remote project root.

    A task packet is normally captured on the Mac, while ``remote_worker``
    validates it against the server's ``project_path``.  Sending the local
    ``/Users/...`` path verbatim would therefore fail closed (or leak a local
    path into a remote manifest).  Only the contract's known path fields are
    translated; arbitrary strings and command arguments are never rewritten.
    Absolute paths outside the captured local workspace are rejected instead
    of guessed or copied.
    """
    cleaned = copy.deepcopy(dict(packet))
    remote_root = str(host["project_path"])
    local_root: pathlib.Path | None = None
    # Prefer an absolute workspace/project/worktree path that is not already
    # the remote root.  Packets produced by a remote resume may already carry
    # server paths and need no local-root mapping.
    for key in ("workspace", "project_path", "worktree_path"):
        value = cleaned.get(key)
        if not isinstance(value, str) or not value.strip():
            continue
        candidate = pathlib.Path(value).expanduser()
        if not candidate.is_absolute() or _under_posix_root(value, remote_root):
            continue
        try:
            local_root = candidate.resolve(strict=False)
        except (OSError, RuntimeError, ValueError) as exc:
            raise ClientError(f"packet {key} is not a valid local path") from exc
        break

    def map_one(value: Any, field: str) -> Any:
        if not isinstance(value, str) or not value.strip():
            return value
        candidate = pathlib.Path(value).expanduser()
        if not candidate.is_absolute():
            return value
        # A packet may be produced by a worker already running on the target;
        # preserve a path that is already inside that host's project root.
        if _under_posix_root(value, remote_root):
            return value
        if local_root is None:
            raise ClientError(f"packet {field} absolute path cannot be mapped to remote project")
        try:
            resolved = candidate.resolve(strict=False)
            relative = resolved.relative_to(local_root)
        except (OSError, RuntimeError, ValueError) as exc:
            raise ClientError(f"packet {field} escapes the local workspace") from exc
        suffix = relative.as_posix()
        return posixpath.join(remote_root, suffix) if suffix != "." else remote_root

    def visit(value: Any, path: str) -> Any:
        if isinstance(value, Mapping):
            result: dict[str, Any] = {}
            for key, child in value.items():
                name = str(key)
                if name in _PACKET_PATH_FIELDS:
                    result[name] = map_one(child, f"{path}.{name}")
                elif name == "required_artifacts" and isinstance(child, list):
                    result[name] = [map_one(item, f"{path}.{name}") for item in child]
                elif name == "attempts" and isinstance(child, list):
                    result[name] = [visit(item, f"{path}.attempts[{index}]") for index, item in enumerate(child)]
                else:
                    result[name] = visit(child, f"{path}.{name}")
            return result
        if isinstance(value, list):
            return [visit(child, f"{path}[{index}]") for index, child in enumerate(value)]
        return value

    mapped = visit(cleaned, "packet")
    if not isinstance(mapped, dict):  # pragma: no cover - visit preserves dict input
        raise ClientError("mapped task packet is not an object")
    return mapped


def _project_split_packet_for_remote(packet: Mapping[str, Any]) -> dict[str, Any]:
    """Drop desktop-only evidence before sending the workload packet.

    The local workspace and desktop auth belong to the controller-side split
    contract.  The remote worker needs only the already-redacted workload
    fields; retaining the full contract would leak a local absolute path and
    would make a transport projection look like a new signed contract.
    """

    projected = copy.deepcopy(dict(packet))
    contract = projected.pop("desktop_split_placement", None)
    if isinstance(contract, Mapping):
        digest = contract.get("contract_digest")
        if isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest):
            projected["desktop_split_contract_digest"] = digest
        projected["placement_mode"] = "desktop_cli_remote_workload"
    return projected


def _packet_placement(
    packet: Mapping[str, Any],
    host_id: str,
    hosts: Mapping[str, Mapping[str, Any]],
    local_hosts: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Validate and preserve execution/workload host placement evidence."""

    attempts = packet.get("attempts")
    first = attempts[0] if isinstance(attempts, list) and attempts and isinstance(attempts[0], Mapping) else {}
    execution_host = packet.get("execution_host") or first.get("execution_host") or host_id
    workload_host = packet.get("workload_host") or first.get("workload_host") or execution_host
    execution_host = _text(execution_host, "execution_host", pattern=_HOST_ID_RE)
    workload_host = _text(workload_host, "workload_host", pattern=_HOST_ID_RE)
    local_hosts = local_hosts or {}
    split_contract = packet.get("desktop_split_placement")
    if isinstance(split_contract, Mapping):
        # Validate the projected contract before it reaches the remote worker.
        # This is structural only; it never probes either host or starts a
        # local CLI.  Import lazily to keep the transport usable as a small
        # standalone bundle on older remote checkouts.
        try:
            from desktop_split_placement import validate_desktop_split_placement_packet
        except ImportError as exc:  # pragma: no cover - bundled worker fallback
            raise ClientError("desktop split validator is unavailable") from exc
        try:
            validate_desktop_split_placement_packet(packet)
        except Exception as exc:
            raise ClientError(f"desktop split placement is invalid: {exc}") from exc
        if packet.get("execution_transport") != "local" or packet.get("workload_transport") != "ssh":
            raise ClientError("desktop split transport dimensions are invalid")
        if execution_host not in local_hosts:
            raise ClientError("desktop split execution_host is not a local inventory host")
        if workload_host != host_id:
            raise ClientError("selected host does not match packet workload_host")
        if workload_host not in hosts or hosts[workload_host].get("transport") != "ssh":
            raise ClientError("desktop split workload_host must be an SSH inventory host")
        split = True
        execution_transport = "local"
        workload_transport = "ssh"
    else:
        if execution_host != host_id:
            raise ClientError("selected host does not match packet execution_host")
        if execution_host not in hosts or workload_host not in hosts:
            raise ClientError("packet placement references a host missing from inventory")
        if hosts[execution_host].get("transport") != "ssh":
            raise ClientError("execution_host must be an SSH inventory host")
        if hosts[workload_host].get("transport") != "ssh":
            raise ClientError("workload_host must be an SSH inventory host")
        split = execution_host != workload_host
        execution_transport = "ssh"
        workload_transport = "ssh"
    wrapper = packet.get("workload_wrapper") or first.get("workload_wrapper")
    if split and not isinstance(wrapper, str):
        raise ClientError("split placement requires a declared workload_wrapper")
    if isinstance(wrapper, str):
        _text(wrapper, "workload_wrapper")
        if any(char in wrapper for char in "\0\r\n;&|`$<>\"'"):
            raise ClientError("workload_wrapper contains unsafe shell syntax")
    return {
        "execution_host": execution_host,
        "workload_host": workload_host,
        "split_placement": split,
        "execution_transport": execution_transport,
        "workload_transport": workload_transport,
        "workload_wrapper_declared": bool(wrapper),
    }


def _safe_job_id(value: Any, field: str = "job_id") -> str:
    return _text(value, field, pattern=_SAFE_ID_RE)


def _safe_digest(value: Any, field: str = "digest") -> str:
    return _text(value, field, pattern=re.compile(r"[0-9a-f]{64}\Z"))


def _safe_owner(value: Any) -> str:
    return _text(value, "owner", pattern=_SAFE_ID_RE)


def _safe_lease(value: Any) -> str:
    return _text(value, "lease_token", pattern=_LEASE_RE)


def _safe_output_payload(value: Any) -> Any:
    """Drop accidental sensitive keys from a remote JSON response."""

    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for raw_key, child in value.items():
            key = str(raw_key)
            if key.lower() in _DROP_PACKET_KEYS or _is_secret_key(key):
                continue
            result[key] = _safe_output_payload(child)
        return result
    if isinstance(value, list):
        return [_safe_output_payload(child) for child in value]
    return value


def _stderr_evidence(stderr: bytes) -> dict[str, Any]:
    # Do not include stderr text.  Provider errors often echo prompts or
    # command fragments, and this client is deliberately a log-safe boundary.
    return {"bytes": len(stderr), "sha256": hashlib.sha256(stderr).hexdigest()}


def _command(
    host: Mapping[str, Any], operation: str, *, timeout: float = 20.0, **kwargs: Any
) -> list[str]:
    if operation not in _OPERATIONS:
        raise ClientError("unsupported remote worker operation")
    argv = [
        "-o",
        "BatchMode=yes",
        "-o",
        f"ConnectTimeout={max(1, int(timeout))}",
        "-o",
        "ServerAliveInterval=3",
        "-o",
        "ServerAliveCountMax=1",
    ]
    if host.get("identity_file"):
        argv.extend(["-i", str(host["identity_file"])])
    if host.get("ssh_legacy_rsa") is True:
        argv.extend([
            "-o", "HostKeyAlgorithms=+ssh-rsa",
            "-o", "PubkeyAcceptedAlgorithms=+ssh-rsa",
        ])
    argv.extend(["-p", str(host["port"])])
    target = f"{host['user']}@{host['hostname']}"
    argv.append(target)
    if operation == "bootstrap":
        # The bootstrap program is sent as the SSH stdin stream and is
        # deliberately independent of the worker bundle being installed.
        argv.extend([str(host.get("worker_python") or "python3"), "-"])
        return argv
    # The interpreter and ``worker_script`` are separate argv items.  Both
    # have already passed conservative validators above.  The worker imports
    # its schema helper from the sibling scripts directory; the fixed bundle
    # layout is checked by bootstrap and inventory parsing.
    argv.extend([
        str(host.get("worker_python") or "python3"),
        str(host["worker_script"]),
        operation,
        "--spool",
        str(host["spool_path"]),
    ])
    if operation == "prepare":
        argv.extend(["--packet", "-", "--project-root", str(host["project_path"])])
    elif operation == "envelope-receive":
        argv.extend(["--envelope", "-"])
    elif operation == "envelope-complete":
        argv.extend([
            "--request-id",
            _safe_job_id(kwargs.get("request_id"), "request_id"),
            "--status",
            _text(kwargs.get("completion_status"), "status", pattern=re.compile(r"(?:completed|failed)\Z")),
        ])
        if kwargs.get("result_digest") is not None:
            argv.extend(["--result-digest", _safe_digest(kwargs["result_digest"], "result_digest")])
        if kwargs.get("error_code") is not None:
            argv.extend(["--error-code", _text(kwargs["error_code"], "error_code", pattern=re.compile(r"[a-z0-9_.-]{1,80}\Z"))])
    elif operation == "envelope-status":
        argv.extend(["--request-id", _safe_job_id(kwargs.get("request_id"), "request_id")])
    elif operation in {"status", "recover", "process-identity", "handoff", "resume"}:
        job_id = kwargs.get("job_id")
        if job_id is not None:
            argv.extend(["--job-id", _safe_job_id(job_id)])
    if operation == "process-identity":
        argv.extend([
            "--owner",
            _safe_owner(kwargs.get("owner")),
            "--lease-token",
            _safe_lease(kwargs.get("lease_token")),
            "--identity",
            "-",
        ])
    if operation in {"handoff", "resume"}:
        # stdout is captured locally; never pass a remote output path.
        pass
    elif operation == "fake-execute":
        argv.extend(["--job-id", _safe_job_id(kwargs.get("job_id")), "--owner", _safe_owner(kwargs.get("owner"))])
        if kwargs.get("lease_token"):
            argv.extend(["--lease-token", _safe_lease(kwargs["lease_token"])])
    elif operation == "fake-service":
        argv.extend(["--job-id", _safe_job_id(kwargs.get("job_id")), "--owner", _safe_owner(kwargs.get("owner"))])
        try:
            poll_seconds = float(kwargs.get("poll_seconds", 1.0))
        except (TypeError, ValueError) as exc:
            raise ClientError("poll_seconds is invalid") from exc
        if poll_seconds < 0.01 or poll_seconds > 3600:
            raise ClientError("poll_seconds must be between 0.01 and 3600 seconds")
        try:
            max_idle_rounds = int(kwargs.get("max_idle_rounds", 0))
            lease_seconds = int(kwargs.get("lease_seconds", 90))
        except (TypeError, ValueError) as exc:
            raise ClientError("fake-service timing values are invalid") from exc
        if max_idle_rounds < 0:
            raise ClientError("max_idle_rounds must be zero or positive")
        if lease_seconds < 1 or lease_seconds > 86400:
            raise ClientError("lease_seconds must be between 1 and 86400")
        argv.extend([
            "--poll-seconds", str(poll_seconds),
            "--max-idle-rounds", str(max_idle_rounds),
            "--lease-seconds", str(lease_seconds),
        ])
    if operation in {"recover", "resume"} and kwargs.get("require_process_identity"):
        argv.append("--require-process-identity")
    return argv


Runner = Callable[..., subprocess.CompletedProcess[bytes]]


_BOOTSTRAP_FILE_NAMES = (
    "scripts/remote_worker.py",
    "scripts/remote_envelope.py",
    "scripts/portable_file_lock.py",
    "scripts/dispatch_schema.py",
)
_BOOTSTRAP_MAX_FILE_BYTES = 2 * 1024 * 1024
_BOOTSTRAP_MAX_TOTAL_BYTES = 4 * 1024 * 1024


def _bundle_source_root(source_root: pathlib.Path | str | None) -> tuple[pathlib.Path, pathlib.Path]:
    """Resolve a repository or scripts directory for the fixed worker bundle."""

    candidate = pathlib.Path(source_root or pathlib.Path(__file__).resolve().parent).expanduser()
    candidate = candidate.resolve()
    if (candidate / "remote_worker.py").is_file():
        scripts_dir = candidate
        project_root = candidate.parent
    elif (candidate / "scripts" / "remote_worker.py").is_file():
        project_root = candidate
        scripts_dir = candidate / "scripts"
    else:
        raise ClientError("worker bundle source must contain scripts/remote_worker.py")
    for relative in _BOOTSTRAP_FILE_NAMES:
        if not (project_root / relative).is_file():
            raise ClientError(f"worker bundle is missing {relative}")
    schemas = sorted((project_root / "schemas").glob("*.schema.json"))
    if not schemas:
        raise ClientError("worker bundle is missing schemas/*.schema.json")
    return project_root, scripts_dir


def _bundle_payload(
    host: Mapping[str, Any], source_root: pathlib.Path | str | None
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Build a bounded, content-addressed bundle for the remote worker."""

    project_root, _scripts_dir = _bundle_source_root(source_root)
    worker_script = str(host["worker_script"])
    expected_worker = posixpath.join(
        posixpath.dirname(posixpath.dirname(worker_script)), "scripts", "remote_worker.py"
    )
    if posixpath.normpath(worker_script) != posixpath.normpath(expected_worker):
        raise ClientError("worker_script must be <worker_root>/scripts/remote_worker.py")
    remote_root = posixpath.dirname(posixpath.dirname(worker_script))
    if not host.get("schema_dir"):
        raise ClientError(
            "bootstrap requires schema_dir or worker_script under <worker_root>/scripts"
        )
    schema_dir = str(host["schema_dir"])
    if posixpath.normpath(schema_dir) != posixpath.join(remote_root, "schemas"):
        raise ClientError("schema_dir must be <worker_root>/schemas")

    relative_names = list(_BOOTSTRAP_FILE_NAMES)
    relative_names.extend(
        f"schemas/{path.name}"
        for path in sorted((project_root / "schemas").glob("*.schema.json"))
    )
    files: list[dict[str, Any]] = []
    total_bytes = 0
    for relative in relative_names:
        path = project_root / relative
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise ClientError(f"worker bundle file cannot be read: {relative}") from exc
        if len(data) > _BOOTSTRAP_MAX_FILE_BYTES:
            raise ClientError(f"worker bundle file is too large: {relative}")
        total_bytes += len(data)
        if total_bytes > _BOOTSTRAP_MAX_TOTAL_BYTES:
            raise ClientError("worker bundle exceeds the bounded transfer size")
        files.append({
            "path": relative,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "content_b64": base64.b64encode(data).decode("ascii"),
        })
    manifest = [
        {key: row[key] for key in ("path", "bytes", "sha256")}
        for row in files
    ]
    payload = {
        "schema_version": SCHEMA_VERSION,
        "root": remote_root,
        "files": files,
        "manifest": manifest,
        "bundle_digest": _digest(manifest),
    }
    return payload, manifest


def _bootstrap_source(payload: Mapping[str, Any]) -> bytes:
    """Return a fixed Python program with the bundle embedded as data."""

    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    source = r'''#!/usr/bin/env python3
import base64
import hashlib
import json
import os
import pathlib
import tempfile

payload = json.loads(%r)
root = pathlib.Path(payload["root"])
if not root.is_absolute() or str(root) == "/":
    raise SystemExit("invalid bootstrap root")
root.mkdir(parents=True, exist_ok=True)
rows = payload.get("files")
if not isinstance(rows, list) or not rows:
    raise SystemExit("invalid bootstrap file list")
written = []
for row in rows:
    relative = row.get("path")
    if not isinstance(relative, str) or not relative or relative.startswith("/"):
        raise SystemExit("invalid bootstrap path")
    parts = pathlib.PurePosixPath(relative).parts
    if ".." in parts or "." in parts or any(not part for part in parts):
        raise SystemExit("unsafe bootstrap path")
    target = root.joinpath(*parts)
    resolved = target.resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError:
        raise SystemExit("bootstrap path escaped root")
    if target.is_symlink():
        raise SystemExit("refusing to overwrite symlink")
    try:
        data = base64.b64decode(row["content_b64"], validate=True)
    except Exception as exc:
        raise SystemExit("invalid bootstrap content") from exc
    if len(data) != int(row["bytes"]):
        raise SystemExit("bootstrap byte count mismatch")
    if hashlib.sha256(data).hexdigest() != row["sha256"]:
        raise SystemExit("bootstrap digest mismatch")
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=".lad-worker-", dir=str(target.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, target)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
    if target.suffix == ".py":
        target.chmod(0o755 if target.name == "remote_worker.py" else 0o644)
    written.append({"path": relative, "bytes": len(data), "sha256": row["sha256"]})
print(json.dumps({"schema_version": 1, "status": "bootstrapped", "files": written,
                  "bundle_digest": payload.get("bundle_digest")}, sort_keys=True))
''' % encoded
    return source.encode("utf-8")


class RemoteWorkerClient:
    """Transport client with explicit dry-run and execution gates."""

    def __init__(
        self,
        inventory: pathlib.Path | str | Mapping[str, Mapping[str, Any]],
        *,
        ssh_executable: str = "ssh",
        timeout: float = 30.0,
        runner: Runner | None = None,
    ) -> None:
        local_hosts: dict[str, dict[str, Any]] = {}
        if isinstance(inventory, Mapping):
            raw_hosts: Any = inventory.get("hosts", inventory)
            if isinstance(raw_hosts, list):
                hosts = {}
                for value in raw_hosts:
                    if _is_local_controller(value):
                        normalized_local = _local_host_row(value)
                        local_id = str(normalized_local["host_id"])
                        if local_id in local_hosts:
                            raise ClientError(f"duplicate host_id: {local_id}")
                        local_hosts[local_id] = normalized_local
                        continue
                    normalized = _host_row(value)
                    host_id = str(normalized["host_id"])
                    if host_id in hosts:
                        raise ClientError(f"duplicate host_id: {host_id}")
                    hosts[host_id] = normalized
            elif isinstance(raw_hosts, Mapping):
                hosts = {}
                for key, value in raw_hosts.items():
                    if _is_local_controller(value):
                        normalized_local = _local_host_row(dict(value), expected_id=str(key))
                        local_id = str(normalized_local["host_id"])
                        if local_id in local_hosts:
                            raise ClientError(f"duplicate host_id: {local_id}")
                        local_hosts[local_id] = normalized_local
                        continue
                    hosts[str(key)] = _host_row(dict(value), expected_id=str(key))
            else:
                raise ClientError("host inventory must contain a hosts list or object")
        else:
            loaded = load_inventory(inventory, include_local=True)
            hosts = {key: value for key, value in loaded.items() if value.get("transport") == "ssh"}
            local_hosts = {
                key: value for key, value in loaded.items() if value.get("transport") == "local"
            }
        if not hosts:
            raise ClientError("host inventory must contain at least one SSH host")
        if timeout < 1 or timeout > 900:
            raise ClientError("timeout must be between 1 and 900 seconds")
        self.hosts = hosts
        self.local_hosts = local_hosts
        self.ssh_executable = _local_path(ssh_executable, "ssh_executable")
        self.timeout = float(timeout)
        self._runner = runner or subprocess.run

    def _host(self, host_id: str) -> dict[str, Any]:
        host_id = _text(host_id, "host_id", pattern=_HOST_ID_RE)
        try:
            return self.hosts[host_id]
        except KeyError as exc:
            raise ClientError("host_id is not present in the private inventory") from exc

    def bootstrap(
        self,
        *,
        host_id: str,
        source_root: pathlib.Path | str | None = None,
        execute: bool = False,
    ) -> dict[str, Any]:
        """Install the fixed worker/schema bundle on a verified SSH host.

        This is intentionally separate from worker operations: it can run
        before ``remote_worker.py`` exists, transfers only an allow-listed
        provider-free bundle, and never copies credentials or task packets.
        """

        host = self._host(host_id)
        payload, manifest = _bundle_payload(host, source_root)
        command = _command(host, "bootstrap", timeout=self.timeout)
        report: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "client": "remote_worker_client",
            "operation": "bootstrap",
            "dry_run": not execute,
            "executed": bool(execute),
            "provider_execution": False,
            "host_id": host_id,
            "stdin_transport": "fixed_worker_bundle",
            "bundle_digest": payload["bundle_digest"],
            "files": manifest,
            "bytes": sum(int(row["bytes"]) for row in manifest),
        }
        if not execute:
            report["command_digest"] = _digest(command)
            return report
        try:
            completed = self._runner(
                [self.ssh_executable, *command],
                input=_bootstrap_source(payload),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.timeout,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ClientError("remote worker bootstrap timed out") from exc
        except (OSError, ValueError) as exc:
            raise ClientError("remote worker bootstrap could not start") from exc
        stdout = completed.stdout if isinstance(completed.stdout, bytes) else str(completed.stdout or "").encode()
        stderr = completed.stderr if isinstance(completed.stderr, bytes) else str(completed.stderr or "").encode()
        if completed.returncode != 0:
            raise ClientError(
                "remote worker bootstrap failed "
                + json.dumps(
                    {"returncode": int(completed.returncode), "stderr": _stderr_evidence(stderr)},
                    sort_keys=True,
                )
            )
        try:
            remote_payload = json.loads(stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ClientError("remote worker bootstrap returned invalid JSON") from exc
        if not isinstance(remote_payload, Mapping):
            raise ClientError("remote worker bootstrap returned a non-object JSON value")
        if remote_payload.get("status") != "bootstrapped":
            raise ClientError("remote worker bootstrap did not report bootstrapped")
        report["remote"] = _safe_output_payload(remote_payload)
        if stderr:
            report["stderr"] = _stderr_evidence(stderr)
        return report

    def _request(
        self,
        operation: str,
        *,
        host_id: str,
        packet: Mapping[str, Any] | None = None,
        envelope: Mapping[str, Any] | None = None,
        job_id: str | None = None,
        request_id: str | None = None,
        completion_status: str = "completed",
        result_digest: str | None = None,
        error_code: str | None = None,
        owner: str | None = None,
        lease_token: str | None = None,
        process_identity: Mapping[str, Any] | None = None,
        require_process_identity: bool = False,
        poll_seconds: float = 1.0,
        max_idle_rounds: int = 0,
        lease_seconds: int = 90,
        execute: bool = False,
        output: pathlib.Path | str | None = None,
    ) -> dict[str, Any]:
        if operation not in _OPERATIONS:
            raise ClientError("unsupported remote worker operation")
        host = self._host(host_id)
        cleaned: dict[str, Any] | None = None
        canonical_envelope: dict[str, Any] | None = None
        redaction_count = 0
        placement: dict[str, Any]
        if packet is not None:
            cleaned, redaction_count = redacted_packet(packet)
            if operation == "prepare":
                # Validate the split contract while its local workspace still
                # matches the contract projection.  Path mapping below is a
                # transport-only rewrite for the remote worker and must not
                # be mistaken for a new placement decision.
                placement = _packet_placement(cleaned, host_id, self.hosts, self.local_hosts)
                # The packet is captured locally but validated against the
                # remote inventory's project root by remote_worker.  Translate
                # only known contract paths before computing the transmitted
                # digest; arbitrary strings/argv remain untouched.
                cleaned = _map_packet_paths(cleaned, host)
                if isinstance(cleaned.get("desktop_split_placement"), Mapping):
                    cleaned = _project_split_packet_for_remote(cleaned)
            else:
                placement = _packet_placement(cleaned, host_id, self.hosts, self.local_hosts)
        else:
            # Operations after prepare still report both placement dimensions
            # when inventory declares them.  The default is the selected SSH
            # host; no guess is made about an unrecorded workload host.
            placement = {
                "execution_host": host_id,
                "workload_host": host_id,
                "split_placement": False,
                "execution_transport": "ssh",
                "workload_transport": "ssh",
                "workload_wrapper_declared": False,
            }
        if envelope is not None:
            if operation != "envelope-receive":
                raise ClientError("envelope is only accepted for envelope-receive")
            canonical_envelope = _canonical_envelope(envelope)
            if canonical_envelope.get("target_id") != host_id:
                raise ClientError("envelope target_id does not match selected host")
        if operation == "envelope-receive" and canonical_envelope is None:
            raise ClientError("envelope-receive requires an envelope")
        if operation == "envelope-complete" and request_id is None:
            raise ClientError("envelope-complete requires request_id")
        if operation == "envelope-status" and request_id is None:
            raise ClientError("envelope-status requires request_id")
        if operation == "prepare" and cleaned is None:
            raise ClientError("prepare requires a task packet")
        identity_payload: dict[str, Any] | None = None
        if operation == "process-identity":
            if process_identity is None:
                raise ClientError("process-identity requires process_identity")
            identity_payload = _process_identity_payload(process_identity)
        elif process_identity is not None:
            raise ClientError("process_identity is only accepted for process-identity")
        if operation != "prepare" and packet is not None:
            # A packet is useful for placement evidence, but its contents are
            # not sent for status/recover/handoff/fake-execute.
            pass
        command = _command(
            host,
            operation,
            timeout=self.timeout,
            job_id=job_id,
            owner=owner,
            lease_token=lease_token,
            request_id=request_id,
            completion_status=completion_status,
            result_digest=result_digest,
            error_code=error_code,
            poll_seconds=poll_seconds,
            max_idle_rounds=max_idle_rounds,
            lease_seconds=lease_seconds,
            require_process_identity=require_process_identity,
        )
        report: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "client": "remote_worker_client",
            "operation": operation,
            "dry_run": not execute,
            "executed": bool(execute),
            "host_id": host_id,
            "execution_host": placement["execution_host"],
            "workload_host": placement["workload_host"],
            "placement": placement,
            "stdin_transport": (
                "redacted_packet"
                if operation == "prepare"
                else "redacted_envelope"
                if operation == "envelope-receive"
                else "process_identity"
                if operation == "process-identity"
                else "empty"
            ),
            "redactions_applied": redaction_count,
        }
        if operation == "fake-service":
            # Keep the evidence explicit in both dry-run and execute reports;
            # callers must not mistake this fixture service for a provider
            # continuation or a quota workaround.
            report.update({
                "chat_independent": True,
                "provider_execution": False,
                "service_boundary": "provider_free_fixture",
            })
        elif operation == "envelope-status":
            report.update({
                "provider_execution": False,
                "status_query": True,
            })
        if cleaned is not None:
            report["packet_digest"] = _digest(cleaned)
        if canonical_envelope is not None:
            summary = canonical_envelope.get("payload_summary") or {}
            report["envelope_digest"] = _digest(canonical_envelope)
            report["model"] = summary.get("model")
            report["variant"] = summary.get("variant")
        if identity_payload is not None:
            report["process_identity_digest"] = _digest(identity_payload)
        if not execute:
            # Do not expose raw remote argv in a dry-run report.  The command
            # is auditable through operation/host/path evidence without making
            # an accidental log of shell-adjacent arguments.
            report["command_digest"] = _digest(command)
            return report
        stdin_payload = b""
        if operation == "prepare" and cleaned is not None:
            stdin_payload = (
                json.dumps(cleaned, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                + "\n"
            ).encode("utf-8")
        elif operation == "envelope-receive" and canonical_envelope is not None:
            stdin_payload = (
                json.dumps(canonical_envelope, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                + "\n"
            ).encode("utf-8")
        elif operation == "process-identity" and identity_payload is not None:
            stdin_payload = (
                json.dumps(identity_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                + "\n"
            ).encode("utf-8")
        argv = [self.ssh_executable, *command]
        try:
            completed = self._runner(
                argv,
                input=stdin_payload,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.timeout,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ClientError("remote worker transport timed out") from exc
        except (OSError, ValueError) as exc:
            raise ClientError("remote worker transport could not start") from exc
        stdout = completed.stdout if isinstance(completed.stdout, bytes) else str(completed.stdout or "").encode()
        stderr = completed.stderr if isinstance(completed.stderr, bytes) else str(completed.stderr or "").encode()
        if completed.returncode != 0:
            raise ClientError(
                "remote worker command failed "
                + json.dumps(
                    {"returncode": int(completed.returncode), "stderr": _stderr_evidence(stderr)},
                    sort_keys=True,
                )
            )
        try:
            remote_payload = json.loads(stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ClientError("remote worker returned invalid JSON") from exc
        if not isinstance(remote_payload, Mapping):
            raise ClientError("remote worker returned a non-object JSON value")
        report["remote"] = _safe_output_payload(remote_payload)
        if stderr:
            report["stderr"] = _stderr_evidence(stderr)
        if output is not None:
            target = pathlib.Path(_local_path(output, "output"))
            target.parent.mkdir(parents=True, exist_ok=True)
            temporary = target.with_name(f".{target.name}.tmp")
            try:
                temporary.write_text(
                    json.dumps(report["remote"], ensure_ascii=False, sort_keys=True, indent=2) + "\n",
                    encoding="utf-8",
                )
                os.replace(temporary, target)
            finally:
                temporary.unlink(missing_ok=True)
            report["output_written"] = str(target)
        return report

    def prepare(
        self,
        *,
        host_id: str,
        packet: Mapping[str, Any],
        execute: bool = False,
    ) -> dict[str, Any]:
        return self._request("prepare", host_id=host_id, packet=packet, execute=execute)

    def envelope_receive(
        self,
        *,
        host_id: str,
        envelope: Mapping[str, Any],
        execute: bool = False,
    ) -> dict[str, Any]:
        """Deliver one validated metadata-only envelope; dry-run by default."""

        return self._request(
            "envelope-receive",
            host_id=host_id,
            envelope=envelope,
            execute=execute,
        )

    def envelope_complete(
        self,
        *,
        host_id: str,
        request_id: str,
        status: str = "completed",
        result_digest: str | None = None,
        error_code: str | None = None,
        execute: bool = False,
    ) -> dict[str, Any]:
        """Write a terminal envelope receipt; never execute the referenced job."""

        return self._request(
            "envelope-complete",
            host_id=host_id,
            request_id=request_id,
            completion_status=status,
            result_digest=result_digest,
            error_code=error_code,
            execute=execute,
        )

    def envelope_pending(
        self,
        *,
        host_id: str,
        execute: bool = False,
    ) -> dict[str, Any]:
        """List pending metadata-only envelope rows; dry-run by default."""

        return self._request("envelope-pending", host_id=host_id, execute=execute)

    def envelope_status(
        self,
        *,
        host_id: str,
        request_id: str,
        execute: bool = False,
    ) -> dict[str, Any]:
        """Read one metadata-only envelope receipt; never execute a provider."""

        return self._request(
            "envelope-status",
            host_id=host_id,
            request_id=request_id,
            execute=execute,
        )

    def status(
        self,
        *,
        host_id: str,
        job_id: str | None = None,
        packet: Mapping[str, Any] | None = None,
        execute: bool = False,
    ) -> dict[str, Any]:
        return self._request(
            "status", host_id=host_id, packet=packet, job_id=job_id, execute=execute
        )

    def recover(
        self,
        *,
        host_id: str,
        job_id: str | None = None,
        packet: Mapping[str, Any] | None = None,
        require_process_identity: bool = True,
        execute: bool = False,
    ) -> dict[str, Any]:
        return self._request(
            "recover",
            host_id=host_id,
            packet=packet,
            job_id=job_id,
            execute=execute,
            require_process_identity=require_process_identity,
        )

    def record_process_identity(
        self,
        *,
        host_id: str,
        job_id: str,
        owner: str,
        lease_token: str,
        process_identity: Mapping[str, Any],
        execute: bool = False,
    ) -> dict[str, Any]:
        """Send a bounded process-liveness witness over SSH stdin."""

        return self._request(
            "process-identity",
            host_id=host_id,
            job_id=job_id,
            owner=owner,
            lease_token=lease_token,
            process_identity=process_identity,
            execute=execute,
        )

    def handoff(
        self,
        *,
        host_id: str,
        job_id: str,
        packet: Mapping[str, Any] | None = None,
        execute: bool = False,
        output: pathlib.Path | str | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "handoff",
            host_id=host_id,
            packet=packet,
            job_id=job_id,
            execute=execute,
            output=output,
        )

    def resume(
        self,
        *,
        host_id: str,
        job_id: str,
        packet: Mapping[str, Any] | None = None,
        require_process_identity: bool = True,
        execute: bool = False,
        output: pathlib.Path | str | None = None,
    ) -> dict[str, Any]:
        """Atomically recover an expired remote lease and fetch its handoff.

        The operation is intentionally separate from ``handoff``: a later
        controller reconnecting after chat/SSH loss needs one fenced remote
        transaction that cannot race a new claim between recovery and status.
        """
        return self._request(
            "resume",
            host_id=host_id,
            packet=packet,
            job_id=job_id,
            execute=execute,
            output=output,
            require_process_identity=require_process_identity,
        )

    def fake_execute(
        self,
        *,
        host_id: str,
        job_id: str,
        owner: str,
        lease_token: str | None = None,
        packet: Mapping[str, Any] | None = None,
        execute: bool = False,
        output: pathlib.Path | str | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "fake-execute",
            host_id=host_id,
            packet=packet,
            job_id=job_id,
            owner=owner,
            lease_token=lease_token,
            execute=execute,
            output=output,
        )

    def fake_service(
        self,
        *,
        host_id: str,
        job_id: str,
        owner: str,
        packet: Mapping[str, Any] | None = None,
        poll_seconds: float = 1.0,
        max_idle_rounds: int = 0,
        lease_seconds: int = 90,
        execute: bool = False,
        output: pathlib.Path | str | None = None,
    ) -> dict[str, Any]:
        """Run the explicit provider-free fake service on an SSH host.

        This method is a transport seam for CI and service-manager smoke
        tests.  It never dispatches a provider and remains dry-run by default.
        A production remote runtime must supply a separately reviewed adapter.
        """
        return self._request(
            "fake-service",
            host_id=host_id,
            packet=packet,
            job_id=job_id,
            owner=owner,
            execute=execute,
            output=output,
            poll_seconds=poll_seconds,
            max_idle_rounds=max_idle_rounds,
            lease_seconds=lease_seconds,
        )


def _packet_from_path(path: str) -> dict[str, Any]:
    try:
        if path == "-":
            payload = json.load(sys.stdin)
        else:
            payload = json.loads(pathlib.Path(path).expanduser().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ClientError("task packet is not valid JSON") from exc
    if not isinstance(payload, Mapping):
        raise ClientError("task packet must be an object")
    return dict(payload)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Bounded SSH transport for remote_worker.py")
    sub = parser.add_subparsers(dest="operation", required=True)

    def common(command: argparse.ArgumentParser) -> None:
        command.add_argument("--inventory", required=True, help="private JSON host inventory")
        command.add_argument("--host-id", required=True)
        command.add_argument("--ssh-bin", default="ssh", help=argparse.SUPPRESS)
        command.add_argument("--timeout", type=float, default=30.0)
        command.add_argument("--execute", action="store_true", help="open SSH; default is dry-run")

    bootstrap = sub.add_parser(
        "bootstrap",
        help="install the fixed worker/schema bundle over SSH",
    )
    common(bootstrap)
    bootstrap.add_argument(
        "--source-root",
        help="local repository or scripts root; defaults to this package's scripts directory",
    )

    prepare = sub.add_parser("prepare", help="transport a redacted packet over SSH stdin")
    common(prepare)
    prepare.add_argument("--packet", required=True)

    envelope_receive = sub.add_parser(
        "envelope-receive",
        aliases=["receive-envelope"],
        help="transport one metadata-only envelope over SSH stdin",
    )
    common(envelope_receive)
    envelope_receive.add_argument("--envelope", required=True)
    envelope_complete = sub.add_parser(
        "envelope-complete",
        aliases=["complete-envelope"],
        help="record a terminal metadata-only envelope receipt",
    )
    common(envelope_complete)
    envelope_complete.add_argument("--request-id", required=True)
    envelope_complete.add_argument("--status", choices=("completed", "failed"), default="completed")
    envelope_complete.add_argument("--result-digest")
    envelope_complete.add_argument("--error-code")
    envelope_status = sub.add_parser(
        "envelope-status",
        aliases=["status-envelope"],
        help="read one metadata-only envelope receipt",
    )
    common(envelope_status)
    envelope_status.add_argument("--request-id", required=True)
    envelope_pending = sub.add_parser(
        "envelope-pending",
        aliases=["pending-envelopes"],
        help="list pending metadata-only envelope rows",
    )
    common(envelope_pending)

    for name in ("status", "recover"):
        command = sub.add_parser(name, help=f"run remote worker {name}")
        common(command)
        command.add_argument("--job-id")
        command.add_argument("--packet", help="optional redacted packet for placement evidence")
        if name == "recover":
            command.add_argument(
                "--require-process-identity",
                action=argparse.BooleanOptionalAction,
                default=True,
                help="require fresh exited/not-found process evidence before reclaim",
            )

    process_identity = sub.add_parser(
        "process-identity",
        help="record a fenced PID/process-group liveness observation",
    )
    common(process_identity)
    process_identity.add_argument("--job-id", required=True)
    process_identity.add_argument("--owner", required=True)
    process_identity.add_argument("--lease-token", required=True)
    process_identity.add_argument("--identity", required=True)

    handoff = sub.add_parser("handoff", aliases=["resume-handoff"], help="retrieve a safe resume handoff")
    common(handoff)
    handoff.add_argument("--job-id", required=True)
    handoff.add_argument("--packet", help="optional redacted packet for placement evidence")
    handoff.add_argument("--output")
    resume = sub.add_parser(
        "resume",
        aliases=["recover-handoff"],
        help="atomically recover an expired lease and retrieve its safe handoff",
    )
    common(resume)
    resume.add_argument("--job-id", required=True)
    resume.add_argument("--packet", help="optional redacted packet for placement evidence")
    resume.add_argument("--output")
    resume.add_argument(
        "--require-process-identity",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="require fresh exited/not-found process evidence before reclaim",
    )

    fake = sub.add_parser("fake-execute", aliases=["fake-run"], help="run the bounded fake executor")
    common(fake)
    fake.add_argument("--job-id", required=True)
    fake.add_argument("--owner", required=True)
    fake.add_argument("--lease-token")
    fake.add_argument("--packet", help="optional redacted packet for placement evidence")
    fake.add_argument("--output")
    service = sub.add_parser(
        "fake-service",
        aliases=["fake-daemon"],
        help="run one provider-free fake job as an independent service smoke",
    )
    common(service)
    service.add_argument("--job-id", required=True)
    service.add_argument("--owner", required=True)
    service.add_argument("--poll-seconds", type=float, default=1.0)
    service.add_argument("--max-idle-rounds", type=int, default=0)
    service.add_argument("--lease-seconds", type=int, default=90)
    service.add_argument("--packet", help="optional redacted packet for placement evidence")
    service.add_argument("--output")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        client = RemoteWorkerClient(
            args.inventory,
            ssh_executable=args.ssh_bin,
            timeout=args.timeout,
        )
        if args.operation == "bootstrap":
            report = client.bootstrap(
                host_id=args.host_id,
                source_root=args.source_root,
                execute=args.execute,
            )
        elif args.operation == "prepare":
            report = client.prepare(
                host_id=args.host_id,
                packet=_packet_from_path(args.packet),
                execute=args.execute,
            )
        elif args.operation in {"envelope-receive", "receive-envelope"}:
            report = client.envelope_receive(
                host_id=args.host_id,
                envelope=_packet_from_path(args.envelope),
                execute=args.execute,
            )
        elif args.operation in {"envelope-complete", "complete-envelope"}:
            report = client.envelope_complete(
                host_id=args.host_id,
                request_id=args.request_id,
                status=args.status,
                result_digest=args.result_digest,
                error_code=args.error_code,
                execute=args.execute,
            )
        elif args.operation in {"envelope-status", "status-envelope"}:
            report = client.envelope_status(
                host_id=args.host_id,
                request_id=args.request_id,
                execute=args.execute,
            )
        elif args.operation in {"envelope-pending", "pending-envelopes"}:
            report = client.envelope_pending(host_id=args.host_id, execute=args.execute)
        elif args.operation == "status":
            report = client.status(
                host_id=args.host_id,
                job_id=args.job_id,
                packet=_packet_from_path(args.packet) if args.packet else None,
                execute=args.execute,
            )
        elif args.operation == "recover":
            report = client.recover(
                host_id=args.host_id,
                job_id=args.job_id,
                packet=_packet_from_path(args.packet) if args.packet else None,
                require_process_identity=args.require_process_identity,
                execute=args.execute,
            )
        elif args.operation == "process-identity":
            report = client.record_process_identity(
                host_id=args.host_id,
                job_id=args.job_id,
                owner=args.owner,
                lease_token=args.lease_token,
                process_identity=_packet_from_path(args.identity),
                execute=args.execute,
            )
        elif args.operation in {"handoff", "resume-handoff"}:
            report = client.handoff(
                host_id=args.host_id,
                job_id=args.job_id,
                packet=_packet_from_path(args.packet) if args.packet else None,
                require_process_identity=args.require_process_identity,
                execute=args.execute,
                output=args.output,
            )
        elif args.operation in {"resume", "recover-handoff"}:
            report = client.resume(
                host_id=args.host_id,
                job_id=args.job_id,
                require_process_identity=args.require_process_identity,
                packet=_packet_from_path(args.packet) if args.packet else None,
                execute=args.execute,
                output=args.output,
            )
        elif args.operation in {"fake-service", "fake-daemon"}:
            report = client.fake_service(
                host_id=args.host_id,
                job_id=args.job_id,
                owner=args.owner,
                packet=_packet_from_path(args.packet) if args.packet else None,
                poll_seconds=args.poll_seconds,
                max_idle_rounds=args.max_idle_rounds,
                lease_seconds=args.lease_seconds,
                execute=args.execute,
                output=args.output,
            )
        else:
            report = client.fake_execute(
                host_id=args.host_id,
                job_id=args.job_id,
                owner=args.owner,
                lease_token=args.lease_token,
                packet=_packet_from_path(args.packet) if args.packet else None,
                execute=args.execute,
                output=args.output,
            )
        print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
        return 0
    except (ClientError, OSError) as exc:
        # ``str(exc)`` is built only from generic validation/evidence strings;
        # raw packet/SSH stdout/stderr is intentionally never printed.
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
