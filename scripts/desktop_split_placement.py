#!/usr/bin/env python3
"""Compile a provider-free desktop-CLI/remote-workload placement contract.

``remote_cli_placement`` describes a CLI that is authenticated on an SSH
host.  That is deliberately different from the server-first arrangement used
by the research plan: a local, desktop-authenticated Codex/Antigravity CLI is
the control/execution surface while a remote host owns the workload, writable
artifacts, validator, and receipt.  This module makes that distinction
explicit without starting a CLI, opening SSH, sending a prompt, or persisting
credentials.

The contract is a dry-run projection only.  A later reviewed runner may use
it to send a small envelope to a remote workload wrapper; this module is not a
provider adapter and cannot make a location-restricted model ready.
"""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import json
import pathlib
import re
import shlex
from collections.abc import Mapping
from pathlib import PurePosixPath
from typing import Any

try:
    import remote_cli_placement as _remote_cli
    from remote_resource_evidence import validate_remote_resource_evidence
except ImportError:  # pragma: no cover - package-style embedding
    from . import remote_cli_placement as _remote_cli  # type: ignore
    from .remote_resource_evidence import validate_remote_resource_evidence  # type: ignore


SCHEMA_VERSION = 1
CONTRACT_TYPE = "local-agent-dispatch.desktop-split-placement"
CONTRACT_VERSION = "0.1.0"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9_.:-]+$")
_DESKTOP_ROUTES: dict[tuple[str, str], dict[str, Any]] = {
    ("codex.spark", "codex"): {
        "cli_name": "codex",
        "model": "gpt-5.3-codex-spark",
        "variant": "xhigh",
    },
    ("antigravity.gemini", "antigravity"): {
        "cli_name": "agy",
        "model": "gemini-3.6-flash-high",
        "variant": None,
    },
}


class DesktopSplitPlacementError(ValueError):
    """Raised when a desktop/remote split cannot be admitted."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _now(value: str | dt.datetime | None) -> dt.datetime:
    if value is None:
        return dt.datetime.now(tz=dt.timezone.utc)
    if isinstance(value, dt.datetime):
        parsed = value
    else:
        try:
            parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError as exc:
            raise DesktopSplitPlacementError("now_utc must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise DesktopSplitPlacementError("now_utc must be timezone-aware")
    return parsed.astimezone(dt.timezone.utc)


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DesktopSplitPlacementError(f"{field} is required")
    value = value.strip()
    if any(char in value for char in "\0\r\n"):
        raise DesktopSplitPlacementError(f"{field} contains control characters")
    return value


def _safe_id(value: Any, field: str) -> str:
    text = _text(value, field)
    if not _SAFE_ID.fullmatch(text):
        raise DesktopSplitPlacementError(f"{field} contains unsafe identifier characters")
    return text


def _safe_abs(value: Any, field: str, *, allow_root: bool = False) -> str:
    text = _text(value, field)
    if not text.startswith("/") or (text == "/" and not allow_root):
        raise DesktopSplitPlacementError(f"{field} must be an absolute POSIX path")
    if any(part in {"", ".", ".."} for part in text.split("/")[1:]):
        raise DesktopSplitPlacementError(f"{field} contains an unsafe path component")
    return str(PurePosixPath(text))


def _confined(value: Any, root: str, field: str, *, allow_root: bool = False) -> str:
    raw = _text(value, field)
    if "//" in raw or any(part in {".", ".."} for part in raw.split("/")):
        raise DesktopSplitPlacementError(f"{field} contains an unsafe path component")
    candidate = PurePosixPath(raw) if raw.startswith("/") else PurePosixPath(root) / raw
    try:
        relative = candidate.relative_to(PurePosixPath(root))
    except ValueError as exc:
        raise DesktopSplitPlacementError(f"{field} escapes remote project_path") from exc
    if not allow_root and str(relative) in {"", "."}:
        raise DesktopSplitPlacementError(f"{field} may not equal its root")
    return str(candidate)


def _confined_local_path(value: Any, root: str, field: str) -> pathlib.Path:
    """Resolve a local path below the execution workspace.

    Local macOS paths may pass through a symlinked temporary directory (for
    example ``/var/tmp`` → ``/private/var/tmp``), so lexical POSIX checks are
    not sufficient here.  Resolve both sides before comparing and reject
    traversal components and symlinks that leave the workspace.
    """

    raw = _text(value, field)
    if "//" in raw or any(part in {".", ".."} for part in raw.replace("\\", "/").split("/")):
        raise DesktopSplitPlacementError(f"{field} contains an unsafe path component")
    try:
        root_path = pathlib.Path(root).expanduser().resolve(strict=False)
        candidate = pathlib.Path(raw).expanduser()
        if not candidate.is_absolute():
            candidate = root_path / candidate
        resolved = candidate.resolve(strict=False)
        resolved.relative_to(root_path)
    except (OSError, RuntimeError, ValueError) as exc:
        raise DesktopSplitPlacementError(f"{field} escapes local_workspace") from exc
    return resolved


def _relative(path: str, root: str, field: str) -> str:
    try:
        relative = PurePosixPath(path).relative_to(PurePosixPath(root))
    except ValueError as exc:
        raise DesktopSplitPlacementError(f"{field} is not below remote_workspace") from exc
    value = str(relative)
    if value in {"", "."}:
        raise DesktopSplitPlacementError(f"{field} may not equal remote_workspace")
    return value


def _fresh(observed: Any, ttl: Any, *, now: dt.datetime, field: str) -> dict[str, Any]:
    observed_text = _text(observed, f"{field}.observed_at_utc")
    try:
        parsed = dt.datetime.fromisoformat(observed_text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise DesktopSplitPlacementError(f"{field}.observed_at_utc is invalid") from exc
    if parsed.tzinfo is None:
        raise DesktopSplitPlacementError(f"{field}.observed_at_utc requires timezone")
    try:
        seconds = float(ttl)
    except (TypeError, ValueError) as exc:
        raise DesktopSplitPlacementError(f"{field}.ttl_seconds is invalid") from exc
    if seconds <= 0 or seconds > 86400:
        raise DesktopSplitPlacementError(f"{field}.ttl_seconds is outside the allowed range")
    age = (now - parsed.astimezone(dt.timezone.utc)).total_seconds()
    if age > seconds:
        raise DesktopSplitPlacementError(f"{field} evidence is stale")
    if age < -60:
        raise DesktopSplitPlacementError(f"{field} evidence is from the future")
    return {
        "observed_at_utc": parsed.astimezone(dt.timezone.utc).isoformat(),
        "ttl_seconds": seconds,
    }


def _split_route_summary(route: Mapping[str, Any], host_id: str, now: dt.datetime) -> dict[str, Any]:
    """Validate the redacted route evidence used by desktop split packets.

    ``compute_resource_probe`` deliberately stores no egress IP.  The split
    packet therefore proves provider/kind/target/freshness, while the private
    preflight report retains the live route verification details.  This is a
    different contract from the older remote-CLI placement record, which may
    include a private egress address.
    """

    if not isinstance(route, Mapping):
        raise DesktopSplitPlacementError("route_evidence must be an object")
    if route.get("provider") != "racknerd":
        raise DesktopSplitPlacementError("route_evidence.provider must be racknerd")
    if route.get("kind") != "workload":
        raise DesktopSplitPlacementError("route_evidence.kind must be workload")
    if route.get("target_host_id") != host_id:
        raise DesktopSplitPlacementError("route_evidence target host mismatch")
    if route.get("verified") is not True:
        raise DesktopSplitPlacementError("route_evidence is not verified")
    status = route.get("status")
    if status not in {"direct", "verified"}:
        raise DesktopSplitPlacementError("route_evidence status is not direct/verified")
    fresh = _fresh(route.get("observed_at_utc"), route.get("ttl_seconds"), now=now, field="route_evidence")
    source = _text(route.get("source"), "route_evidence.source")
    if "racknerd" not in source.lower():
        raise DesktopSplitPlacementError("route_evidence source is not RackNerd verification")
    # Never copy a private egress address into the packet.  The returned
    # summary is the stable, redacted evidence shape consumed at ingress.
    return {
        "provider": "racknerd",
        "kind": "workload",
        "status": "direct",
        "verified": True,
        "target_host_id": host_id,
        **fresh,
        "source": source,
    }


def _wrapper(value: Any, field: str) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise DesktopSplitPlacementError(f"{field} is required")
    name = _text(value.get("name"), f"{field}.name")
    version = _text(value.get("version"), f"{field}.version")
    digest = _text(value.get("sha256"), f"{field}.sha256").lower()
    if not _HEX64.fullmatch(digest):
        raise DesktopSplitPlacementError(f"{field}.sha256 must be a lowercase SHA-256")
    if value.get("mode") != "dry-run":
        raise DesktopSplitPlacementError(f"{field}.mode must be dry-run")
    return {"name": name, "version": version, "sha256": digest, "mode": "dry-run"}


def _validator(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise DesktopSplitPlacementError(f"{field} is required")
    projected = _wrapper(value, field)
    raw_argv = value.get("argv")
    if isinstance(raw_argv, str):
        argv = shlex.split(raw_argv)
    elif isinstance(raw_argv, list) and all(isinstance(item, str) and item for item in raw_argv):
        argv = list(raw_argv)
    else:
        raise DesktopSplitPlacementError(f"{field}.argv must be a non-empty argv")
    if not argv:
        raise DesktopSplitPlacementError(f"{field}.argv must not be empty")
    executable = pathlib.PurePosixPath(argv[0]).name.lower()
    if executable in {"sh", "bash", "zsh", "fish", "cmd", "powershell", "pwsh"}:
        if any(item in {"-c", "/c", "-command"} for item in argv[1:]):
            raise DesktopSplitPlacementError(f"{field}.argv may not invoke a shell")
    projected["argv"] = argv
    return projected


def _local_cli(host: Mapping[str, Any], assignment: Mapping[str, Any], now: dt.datetime) -> dict[str, Any]:
    host_id = _safe_id(host.get("host_id"), "local_host.host_id")
    if host.get("transport") != "local":
        raise DesktopSplitPlacementError("desktop execution host must use transport=local")
    if host_id != _safe_id(assignment.get("execution_host"), "assignment.execution_host"):
        raise DesktopSplitPlacementError("assignment.execution_host does not match local host")
    cli = host.get("desktop_cli") or host.get("cli")
    if not isinstance(cli, Mapping):
        raise DesktopSplitPlacementError("local_host requires desktop_cli evidence")
    pool = _text(assignment.get("pool_id"), "assignment.pool_id")
    provider = _text(assignment.get("provider"), "assignment.provider")
    expected = _DESKTOP_ROUTES.get((pool, provider))
    if expected is None:
        raise DesktopSplitPlacementError("unsupported desktop model pool/provider route")
    if _text(cli.get("name"), "desktop_cli.name") != expected["cli_name"]:
        raise DesktopSplitPlacementError("desktop_cli.name is not the exact route CLI")
    path = _safe_abs(cli.get("path"), "desktop_cli.path")
    if cli.get("install_state") != "installed":
        raise DesktopSplitPlacementError("desktop_cli is not installed")
    auth = cli.get("auth")
    if not isinstance(auth, Mapping) or auth.get("state") != "authenticated" or auth.get("scope") != "local_desktop":
        raise DesktopSplitPlacementError("desktop CLI auth evidence must be authenticated/local_desktop")
    if auth.get("host_id") not in (None, host_id):
        raise DesktopSplitPlacementError("desktop CLI auth belongs to another host")
    fresh = _fresh(auth.get("observed_at_utc"), auth.get("ttl_seconds"), now=now, field="desktop_cli.auth")
    return {
        "name": expected["cli_name"],
        "path": path,
        "version": _text(cli.get("version"), "desktop_cli.version"),
        "install_state": "installed",
        "auth": {
            "state": "authenticated",
            "scope": "local_desktop",
            "host_id": host_id,
            **fresh,
            "source": _text(auth.get("source"), "desktop_cli.auth.source"),
        },
    }


def _remote_host(host: Mapping[str, Any], assignment: Mapping[str, Any]) -> tuple[str, str]:
    host_id = _safe_id(host.get("host_id"), "workload_host.host_id")
    if host_id != _safe_id(assignment.get("workload_host"), "assignment.workload_host"):
        raise DesktopSplitPlacementError("assignment.workload_host does not match workload host")
    if host.get("transport") != "ssh":
        raise DesktopSplitPlacementError("workload_host must use transport=ssh")
    if host.get("reachable") is not True:
        raise DesktopSplitPlacementError("workload_host reachability is not verified")
    return host_id, _safe_abs(host.get("project_path"), "workload_host.project_path")


def _reject_secret_and_prompt(value: Any, path: str = "input") -> None:
    # Reuse the remote CLI contract's conservative recursive checks.  It is
    # intentionally called before projection so raw credentials/prompts never
    # enter the returned contract or an exception payload.
    _remote_cli._reject_secret_keys(value, path)
    _remote_cli._reject_inline_prompts(value, path)


def build_desktop_split_contract(
    assignment: Mapping[str, Any],
    local_host: Mapping[str, Any],
    workload_host: Mapping[str, Any],
    route_evidence: Mapping[str, Any],
    remote_resource_evidence: Mapping[str, Any],
    *,
    now_utc: str | dt.datetime | None = None,
) -> dict[str, Any]:
    """Return an admitted dry-run split contract or a deterministic block."""

    base: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "contract_type": CONTRACT_TYPE,
        "contract_version": CONTRACT_VERSION,
        "read_only": True,
        "dry_run": True,
        "provider_execution": False,
        "model_prompts_sent": False,
        "ssh_prompt_sent": False,
        "decision": "block",
        "valid": False,
        "reasons": [],
        "contract": None,
    }
    try:
        _reject_secret_and_prompt(assignment, "assignment")
        _reject_secret_and_prompt(local_host, "local_host")
        _reject_secret_and_prompt(workload_host, "workload_host")
        _reject_secret_and_prompt(route_evidence, "route_evidence")
        _reject_secret_and_prompt(remote_resource_evidence, "remote_resource_evidence")
        now = _now(now_utc)
        pool_id = _text(assignment.get("pool_id"), "assignment.pool_id")
        provider = _text(assignment.get("provider"), "assignment.provider")
        expected = _DESKTOP_ROUTES.get((pool_id, provider))
        if expected is None:
            raise DesktopSplitPlacementError("unsupported desktop model pool/provider route")
        model = _text(assignment.get("model"), "assignment.model")
        if model != expected["model"]:
            raise DesktopSplitPlacementError("assignment.model is not the exact approved model")
        if "variant" not in assignment or assignment.get("variant") != expected["variant"]:
            raise DesktopSplitPlacementError("assignment.variant is not the exact approved variant")
        execution_host = _safe_id(assignment.get("execution_host"), "assignment.execution_host")
        workload_id, project_path = _remote_host(workload_host, assignment)
        if execution_host == workload_id:
            raise DesktopSplitPlacementError("desktop split requires distinct local and workload hosts")
        local_cli = _local_cli(local_host, assignment, now)
        local_workspace = _safe_abs(assignment.get("local_workspace"), "assignment.local_workspace")
        remote_workspace = _confined(assignment.get("remote_workspace"), project_path, "assignment.remote_workspace")
        write_scope_path = _confined(assignment.get("write_scope"), remote_workspace, "assignment.write_scope")
        write_scope = _relative(write_scope_path, remote_workspace, "write_scope")
        receipt = _confined(assignment.get("receipt_path"), remote_workspace, "assignment.receipt_path")
        receipt_relative = _relative(receipt, remote_workspace, "receipt_path")
        if not PurePosixPath(receipt_relative).parts[:2] == (".lad", "receipts"):
            raise DesktopSplitPlacementError("receipt_path must be below remote_workspace/.lad/receipts")
        artifacts = assignment.get("remote_required_artifacts")
        if not isinstance(artifacts, list) or not artifacts or not all(isinstance(item, str) and item for item in artifacts):
            raise DesktopSplitPlacementError("remote_required_artifacts must be a non-empty list")
        remote_artifacts = [_confined(item, remote_workspace, "remote_required_artifact") for item in artifacts]
        result_source = _confined(assignment.get("remote_result_source_path"), remote_workspace, "remote_result_source_path")
        workload_wrapper = _wrapper(assignment.get("workload_wrapper"), "workload_wrapper")
        validator = _validator(assignment.get("remote_validator"), "remote_validator")
        route = _split_route_summary(route_evidence, workload_id, now)
        packet_shape = {
            "schema_version": 1,
            "job_id": _text(assignment.get("job_id"), "assignment.job_id"),
            "execution_host": execution_host,
            "workload_host": workload_id,
            "remote_workspace": remote_workspace,
            "write_scope": write_scope,
            "attempts": [{"host_id": workload_id, "transport": "ssh", "workspace": remote_workspace}],
        }
        request = assignment.get("resource_request") or {}
        if not isinstance(request, Mapping):
            raise DesktopSplitPlacementError("resource_request must be an object")
        resource_report = validate_remote_resource_evidence(
            remote_resource_evidence,
            packet=packet_shape,
            request=request,
            now_utc=now.isoformat(),
        )
        if not resource_report.get("valid"):
            raise DesktopSplitPlacementError(
                "remote resource evidence blocked: " + ",".join(resource_report.get("reasons") or ["unknown"])
            )
        resource_summary = copy.deepcopy(resource_report["summary"])
        resource_summary["capacity"] = copy.deepcopy(resource_report.get("capacity", {}).get("host", {}))
        contract: dict[str, Any] = {
            "job_id": packet_shape["job_id"],
            "attempt_id": _text(assignment.get("attempt_id"), "assignment.attempt_id"),
            "provider": provider,
            "pool_id": pool_id,
            "model": model,
            "variant": assignment.get("variant"),
            "execution_host": execution_host,
            "execution_transport": "local",
            "workload_host": workload_id,
            "workload_transport": "ssh",
            "workload_project_path": project_path,
            "local_workspace": local_workspace,
            "remote_workspace": remote_workspace,
            "write_scope": write_scope,
            "write_scope_path": write_scope_path,
            "receipt": {"path": receipt, "relative_path": receipt_relative, "format": "json", "status": "required_pending"},
            "remote_required_artifacts": remote_artifacts,
            "remote_result_source_path": result_source,
            "desktop_cli": local_cli,
            "workload_wrapper": workload_wrapper,
            "remote_validator": validator,
            "route_evidence": route,
            "remote_resource_evidence": resource_summary,
            # The packet carries the bounded evidence summary below, not the
            # pre-projection validator input.  Digest exactly what is
            # persisted so the ingress validator can bind the receipt to the
            # packet without trusting a producer-supplied digest.
            "resource_evidence_digest": _digest(resource_summary),
            "placement_mode": "desktop_cli_remote_workload",
        }
        contract["contract_digest"] = _digest(contract)
        base.update({"decision": "admit", "valid": True, "contract": contract})
    except (DesktopSplitPlacementError, ValueError) as exc:
        base["reasons"] = [str(exc)]
    return base


def validate_desktop_split_placement_packet(
    packet: Mapping[str, Any], *, now_utc: str | dt.datetime | None = None
) -> None:
    """Validate a projected split packet at every durable ingress.

    ``attach_desktop_split_contract`` already checks the contract's
    self-digest, but a self-consistent forged contract could otherwise bypass
    the builder.  This validator repeats the bounded route, path, receipt,
    validator, and resource-evidence checks against the *projected packet*.
    It is provider-free and does not probe either host.
    """

    if not isinstance(packet, Mapping):
        raise DesktopSplitPlacementError("desktop split packet must be an object")
    contract = packet.get("desktop_split_placement")
    if contract is None:
        return
    if not isinstance(contract, Mapping):
        raise DesktopSplitPlacementError("desktop_split_placement must be an object")
    digest = contract.get("contract_digest")
    if not isinstance(digest, str) or not _HEX64.fullmatch(digest):
        raise DesktopSplitPlacementError("desktop split contract digest is invalid")
    unsigned = {key: value for key, value in contract.items() if key != "contract_digest"}
    if digest != _digest(unsigned):
        raise DesktopSplitPlacementError("desktop split contract digest mismatch")

    # A packet may be persisted before it is claimed.  When no observation
    # clock is supplied, validate the structural projection against its own
    # observation timestamp and leave freshness to the claim-time resource
    # admission gate.  Tests and explicit audits can pass ``now_utc`` to
    # enforce the TTL immediately.
    route_observed = (
        packet.get("desktop_split_placement", {}).get("route_evidence", {}).get("observed_at_utc")
        if isinstance(packet.get("desktop_split_placement"), Mapping)
        else None
    )
    now = _now(now_utc if now_utc is not None else route_observed)
    pool_id = _text(contract.get("pool_id"), "contract.pool_id")
    provider = _text(contract.get("provider"), "contract.provider")
    expected = _DESKTOP_ROUTES.get((pool_id, provider))
    if expected is None:
        raise DesktopSplitPlacementError("unsupported desktop model pool/provider route")
    if contract.get("model") != expected["model"] or contract.get("variant") != expected["variant"]:
        raise DesktopSplitPlacementError("desktop split exact model/variant validation failed")

    execution_host = _safe_id(contract.get("execution_host"), "contract.execution_host")
    workload_host = _safe_id(contract.get("workload_host"), "contract.workload_host")
    if execution_host == workload_host:
        raise DesktopSplitPlacementError("desktop split requires distinct local and workload hosts")
    if contract.get("execution_transport") != "local":
        raise DesktopSplitPlacementError("desktop split execution_transport must be local")
    if contract.get("workload_transport") != "ssh":
        raise DesktopSplitPlacementError("desktop split workload_transport must be ssh")
    if contract.get("placement_mode") != "desktop_cli_remote_workload":
        raise DesktopSplitPlacementError("desktop split placement_mode is invalid")

    _safe_abs(contract.get("local_workspace"), "contract.local_workspace")
    project_path = _safe_abs(contract.get("workload_project_path"), "contract.workload_project_path")
    remote_workspace = _confined(
        contract.get("remote_workspace"), project_path, "contract.remote_workspace"
    )
    write_scope_path = _confined(
        contract.get("write_scope_path"), remote_workspace, "contract.write_scope_path"
    )
    write_scope = _relative(write_scope_path, remote_workspace, "contract.write_scope")
    if contract.get("write_scope") != write_scope:
        raise DesktopSplitPlacementError("desktop split write_scope path mismatch")

    receipt = contract.get("receipt")
    if not isinstance(receipt, Mapping):
        raise DesktopSplitPlacementError("desktop split receipt is required")
    receipt_path = _confined(receipt.get("path"), remote_workspace, "receipt.path")
    receipt_relative = _relative(receipt_path, remote_workspace, "receipt.path")
    if receipt.get("relative_path") != receipt_relative:
        raise DesktopSplitPlacementError("desktop split receipt relative path mismatch")
    if PurePosixPath(receipt_relative).parts[:2] != (".lad", "receipts"):
        raise DesktopSplitPlacementError("desktop split receipt must be below .lad/receipts")
    if receipt.get("format") != "json" or receipt.get("status") != "required_pending":
        raise DesktopSplitPlacementError("desktop split receipt status/format is invalid")

    artifacts = contract.get("remote_required_artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise DesktopSplitPlacementError("desktop split remote_required_artifacts are required")
    remote_artifacts = [
        _confined(item, remote_workspace, "remote_required_artifact") for item in artifacts
    ]
    result_source = _confined(
        contract.get("remote_result_source_path"), remote_workspace, "remote_result_source_path"
    )
    wrapper = _wrapper(contract.get("workload_wrapper"), "workload_wrapper")
    validator = _validator(contract.get("remote_validator"), "remote_validator")
    route = _split_route_summary(contract.get("route_evidence"), workload_host, now)

    cli = contract.get("desktop_cli")
    if not isinstance(cli, Mapping) or cli.get("name") != expected["cli_name"]:
        raise DesktopSplitPlacementError("desktop split desktop_cli does not match exact route")
    _safe_abs(cli.get("path"), "desktop_cli.path")
    if cli.get("install_state") != "installed":
        raise DesktopSplitPlacementError("desktop split desktop_cli is not installed")
    auth = cli.get("auth")
    if (
        not isinstance(auth, Mapping)
        or auth.get("state") != "authenticated"
        or auth.get("scope") != "local_desktop"
        or auth.get("host_id") != execution_host
    ):
        raise DesktopSplitPlacementError("desktop split local authentication evidence is invalid")

    evidence = contract.get("remote_resource_evidence")
    if not isinstance(evidence, Mapping):
        raise DesktopSplitPlacementError("desktop split remote resource evidence is required")
    if contract.get("resource_evidence_digest") != _digest(evidence):
        raise DesktopSplitPlacementError("desktop split resource evidence digest mismatch")
    request = packet.get("resource_request") or {}
    if not isinstance(request, Mapping):
        raise DesktopSplitPlacementError("desktop split resource_request must be an object")
    evidence_packet = {
        "execution_host": execution_host,
        "workload_host": workload_host,
        "remote_workspace": remote_workspace,
        "write_scope": write_scope,
        "attempts": [{"host_id": workload_host, "transport": "ssh", "workspace": remote_workspace}],
    }
    evidence_clock = now_utc
    if evidence_clock is None:
        evidence_clock = evidence.get("observed_at_utc")
    report = validate_remote_resource_evidence(
        evidence,
        packet=evidence_packet,
        request=request,
        now_utc=evidence_clock,
    )
    if not report.get("valid"):
        raise DesktopSplitPlacementError(
            "desktop split remote resource evidence blocked: "
            + ",".join(report.get("reasons") or ["unknown"])
        )

    # Bind the contract's allow-listed projection to the packet and its first
    # attempt.  A packet that only has a valid contract digest but stale or
    # mismatched projection must not reach SQLite or a remote worker.
    packet_fields = {
        "job_id": contract.get("job_id"),
        "pool_id": pool_id,
        "provider": provider,
        "model": expected["model"],
        "variant": expected["variant"],
        "execution_host": execution_host,
        "workload_host": workload_host,
        "execution_transport": "local",
        "workload_transport": "ssh",
        "workspace": contract.get("local_workspace"),
        "remote_workspace": remote_workspace,
        "write_scope": write_scope,
        "required_artifacts": remote_artifacts,
        "result_source_path": result_source,
        "remote_required_artifacts": remote_artifacts,
        "remote_result_source_path": result_source,
        "workload_wrapper": wrapper["name"],
        "remote_validator": validator,
        "remote_resource_evidence": dict(evidence),
        "data_route": route,
        "receipt_path": receipt_path,
    }
    for field, expected_value in packet_fields.items():
        if packet.get(field) != expected_value:
            raise DesktopSplitPlacementError(f"desktop split packet.{field} mismatch")
    for field in ("provider_execution", "model_prompts_sent", "ssh_prompt_sent"):
        if packet.get(field) is not False:
            raise DesktopSplitPlacementError(f"desktop split packet.{field} must be false")
    if packet.get("validation_argv") != validator["argv"]:
        raise DesktopSplitPlacementError("desktop split packet validator mismatch")

    attempts = packet.get("attempts")
    if not isinstance(attempts, list) or not attempts or not isinstance(attempts[0], Mapping):
        raise DesktopSplitPlacementError("desktop split packet requires a prepared attempt")
    attempt = attempts[0]
    attempt_fields = {
        "attempt_id": contract.get("attempt_id"),
        "pool_id": pool_id,
        "provider": provider,
        "model": expected["model"],
        "variant": expected["variant"],
        "transport": "local",
        "host_id": execution_host,
        "workload_host": workload_host,
        "workload_transport": "ssh",
        "workspace": contract.get("local_workspace"),
        "remote_workspace": remote_workspace,
        "write_scope": write_scope,
        "workload_wrapper": wrapper["name"],
        "remote_required_artifacts": remote_artifacts,
        "remote_result_source_path": result_source,
        "remote_validator": validator,
        "receipt_path": receipt_path,
    }
    for field, expected_value in attempt_fields.items():
        if attempt.get(field) != expected_value:
            raise DesktopSplitPlacementError(f"desktop split attempt.{field} mismatch")

    # The desktop CLI's prompt is read on the execution host.  Bind its
    # source to the same local workspace as the split contract before the
    # packet reaches SQLite or the SSH transport; otherwise a planner packet
    # with a stale/mismatched workspace would fail only during remote path
    # projection, after durable enqueue.
    prompt_file = attempt.get("prompt_file")
    if prompt_file is not None:
        _confined_local_path(
            prompt_file, contract["local_workspace"], "desktop attempt.prompt_file"
        )


def attach_desktop_split_contract(
    packet: Mapping[str, Any], contract_report_or_contract: Mapping[str, Any]
) -> dict[str, Any]:
    """Attach a validated split contract without executing either side."""

    if not isinstance(packet, Mapping):
        raise DesktopSplitPlacementError("packet must be an object")
    _reject_secret_and_prompt(packet, "packet")
    report = contract_report_or_contract
    contract = report.get("contract") if isinstance(report.get("contract"), Mapping) else report
    if not isinstance(contract, Mapping) or ("contract" in report and report.get("decision") != "admit"):
        raise DesktopSplitPlacementError("an admitted desktop split contract is required")
    unsigned = {key: value for key, value in contract.items() if key != "contract_digest"}
    if contract.get("contract_digest") != _digest(unsigned):
        raise DesktopSplitPlacementError("desktop split contract digest mismatch")
    attempts = packet.get("attempts")
    if not isinstance(attempts, list) or not attempts or not isinstance(attempts[0], Mapping):
        raise DesktopSplitPlacementError("packet requires one attempt to attach desktop split placement")
    result = copy.deepcopy(dict(packet))
    attempt = copy.deepcopy(dict(attempts[0]))
    existing_attempt_id = attempt.get("attempt_id")
    if existing_attempt_id not in (None, "", contract.get("attempt_id")):
        raise DesktopSplitPlacementError("packet attempt_id conflicts with desktop split contract")
    attempt["attempt_id"] = contract["attempt_id"]
    for field in ("job_id", "pool_id", "provider", "model", "variant", "execution_host", "workload_host"):
        if field in contract:
            existing = result.get(field)
            if existing not in (None, "", contract[field]):
                raise DesktopSplitPlacementError(f"packet.{field} conflicts with desktop split contract")
            result[field] = contract[field]
    result.update({
        "execution_transport": "local",
        "workload_transport": "ssh",
        "workspace": contract["local_workspace"],
        "remote_workspace": contract["remote_workspace"],
        "write_scope": contract["write_scope"],
        "required_artifacts": copy.deepcopy(contract["remote_required_artifacts"]),
        "result_source_path": contract["remote_result_source_path"],
        "remote_required_artifacts": copy.deepcopy(contract["remote_required_artifacts"]),
        "remote_result_source_path": contract["remote_result_source_path"],
        "receipt_path": contract["receipt"]["path"],
        "workload_wrapper": contract["workload_wrapper"]["name"],
        "remote_validator": copy.deepcopy(contract["remote_validator"]),
        "remote_resource_evidence": copy.deepcopy(contract["remote_resource_evidence"]),
        "data_route": copy.deepcopy(contract["route_evidence"]),
        "desktop_split_placement": copy.deepcopy(dict(contract)),
        "provider_execution": False,
        "model_prompts_sent": False,
        "ssh_prompt_sent": False,
    })
    attempt.update({
        "transport": "local",
        "host_id": contract["execution_host"],
        "pool_id": contract["pool_id"],
        "provider": contract["provider"],
        "model": contract["model"],
        "variant": contract["variant"],
        "workload_host": contract["workload_host"],
        "workload_transport": "ssh",
        "workspace": contract["local_workspace"],
        "remote_workspace": contract["remote_workspace"],
        "write_scope": contract["write_scope"],
        "workload_wrapper": contract["workload_wrapper"]["name"],
        "remote_required_artifacts": copy.deepcopy(contract["remote_required_artifacts"]),
        "remote_result_source_path": contract["remote_result_source_path"],
        "receipt_path": contract["receipt"]["path"],
        "remote_validator": copy.deepcopy(contract["remote_validator"]),
    })
    result["attempts"] = [attempt, *copy.deepcopy(list(attempts[1:]))]
    validate_desktop_split_placement_packet(result)
    return result


def _load(path: str) -> Any:
    return json.loads(pathlib.Path(path).expanduser().read_text(encoding="utf-8"))


def _dump(payload: Any, output: str | None) -> None:
    encoded = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if output:
        pathlib.Path(output).expanduser().write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    build = sub.add_parser("build", help="compile a provider-free desktop split contract")
    for name in ("assignment", "local-host", "workload-host", "route", "resource-evidence"):
        build.add_argument(f"--{name}", required=True)
    build.add_argument("--now-utc")
    build.add_argument("--output")
    attach = sub.add_parser("attach", help="attach an admitted split contract")
    attach.add_argument("--packet", required=True)
    attach.add_argument("--contract", required=True)
    attach.add_argument("--output")
    args = parser.parse_args(argv)
    try:
        if args.operation == "build":
            report = build_desktop_split_contract(
                _load(args.assignment), _load(args.local_host), _load(args.workload_host),
                _load(args.route), _load(args.resource_evidence), now_utc=args.now_utc,
            )
            _dump(report, args.output)
            return 0 if report["valid"] else 2
        _dump(attach_desktop_split_contract(_load(args.packet), _load(args.contract)), args.output)
        return 0
    except (OSError, json.JSONDecodeError, DesktopSplitPlacementError) as exc:
        _dump({"schema_version": SCHEMA_VERSION, "contract_type": CONTRACT_TYPE, "read_only": True,
               "dry_run": True, "provider_execution": False, "model_prompts_sent": False,
               "decision": "block", "valid": False, "reasons": [f"{type(exc).__name__}: {exc}"]}, args.output)
        return 2


__all__ = [
    "CONTRACT_TYPE", "CONTRACT_VERSION", "SCHEMA_VERSION",
    "DesktopSplitPlacementError", "attach_desktop_split_contract",
    "build_desktop_split_contract", "validate_desktop_split_placement_packet", "main",
]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
