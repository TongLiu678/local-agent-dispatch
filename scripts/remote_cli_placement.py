#!/usr/bin/env python3
"""Compile a provider-free placement contract for a remote authenticated CLI.

This module is deliberately a sidecar contract, not a provider adapter.  It
lets a planner assignment and a task packet describe a CLI that is installed
and authenticated *on an SSH host* while keeping local desktop credentials
out of the placement evidence.  The default command is a dry-run compiler: it
does not open SSH, execute a CLI, call a provider, or write a receipt.

The contract is intentionally strict for the explicitly approved remote CLI routes:

* ``codex.luna`` -> ``codex`` / ``gpt-5.6-sol`` / ``max`` (current user route);
* ``codex.spark`` -> ``codex`` / ``gpt-5.3-codex-spark`` / ``xhigh``;
* ``antigravity.gemini`` -> ``agy`` / ``gemini-3.6-flash-high`` / no variant.

No model fallback is implied.  A later reviewed adapter may consume the
compiled packet extension, but this file only validates and projects
allow-listed metadata.
"""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import ipaddress
import json
import pathlib
import re
from collections.abc import Mapping
from pathlib import PurePosixPath
from typing import Any


SCHEMA_VERSION = 1
CONTRACT_TYPE = "local-agent-dispatch.remote-cli-placement"
CONTRACT_VERSION = "0.1.0"
MAX_TTL_SECONDS = 86400.0
MAX_CLOCK_SKEW_SECONDS = 60.0
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_SECRET_KEY = re.compile(
    r"(?:secret|token|password|api[_-]?key|credential|authorization)", re.I
)
_INLINE_PROMPT_KEYS = {"prompt", "prompt_text", "prompt_payload", "messages"}
_REMOTE_CLI_ROUTES: dict[tuple[str, str], dict[str, Any]] = {
    ("codex.luna", "codex"): {
        "cli_name": "codex",
        "model": "gpt-5.6-sol",
        "variant": "max",
    },
    ("codex.spark", "codex"): {
        "cli_name": "codex",
        "model": "gpt-5.3-codex-spark",
        "variant": "xhigh",
    },
    ("antigravity.gemini", "antigravity"): {
        "cli_name": "agy",
        "model": "gemini-3.6-flash-high",
        # The Gemini effort is encoded in the exact model slug.  ``None`` is
        # still an exact variant value and must be present in the assignment.
        "variant": None,
    },
}


class RemoteCliPlacementError(ValueError):
    """Raised when a packet cannot carry a safe remote CLI contract."""


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


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
            raise RemoteCliPlacementError("now_utc must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise RemoteCliPlacementError("now_utc must be timezone-aware")
    return parsed.astimezone(dt.timezone.utc)


def _timestamp(value: Any, field: str) -> dt.datetime:
    if not isinstance(value, str) or not value.strip():
        raise RemoteCliPlacementError(f"{field} is required")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RemoteCliPlacementError(f"{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise RemoteCliPlacementError(f"{field} must include a timezone")
    return parsed.astimezone(dt.timezone.utc)


def _number(value: Any, field: str) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise RemoteCliPlacementError(f"{field} must be numeric") from exc
    if parsed <= 0 or parsed > MAX_TTL_SECONDS:
        raise RemoteCliPlacementError(f"{field} is outside the allowed TTL range")
    return parsed


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RemoteCliPlacementError(f"{field} is required")
    return value.strip()


def _reject_secret_keys(value: Any, path: str = "input") -> None:
    """Reject credential-shaped fields before any input can be projected."""

    if isinstance(value, Mapping):
        for key, child in value.items():
            if _SECRET_KEY.search(str(key)):
                raise RemoteCliPlacementError(f"{path} contains a secret-like field")
            _reject_secret_keys(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_secret_keys(child, f"{path}[{index}]")


def _reject_inline_prompts(value: Any, path: str = "packet") -> None:
    """Keep raw provider prompts out of the placement projection."""

    if isinstance(value, Mapping):
        for key, child in value.items():
            if str(key).lower() in _INLINE_PROMPT_KEYS:
                raise RemoteCliPlacementError(
                    f"{path}.{key} is an inline prompt; use a reviewed prompt_file"
                )
            _reject_inline_prompts(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_inline_prompts(child, f"{path}[{index}]")


def _safe_abs(value: Any, field: str, *, allow_root: bool = False) -> str:
    raw_value = _text(value, field)
    if "\x00" in raw_value or "\r" in raw_value or "\n" in raw_value:
        raise RemoteCliPlacementError(f"{field} contains control characters")
    # Preserve lexical components instead of allowing PurePosixPath to hide a
    # traversal or duplicate separator in an input packet.
    if not raw_value.startswith("/") or raw_value == "/" and not allow_root:
        raise RemoteCliPlacementError(f"{field} must be an absolute POSIX path")
    parts = raw_value.split("/")
    if any(part in {"", ".", ".."} for part in parts[1:]):
        raise RemoteCliPlacementError(f"{field} contains an unsafe path component")
    return str(PurePosixPath(raw_value))


def _confined_path(value: Any, root: str, field: str, *, allow_root: bool = False) -> str:
    root_path = _safe_abs(root, "project_path", allow_root=False)
    raw = _text(value, field)
    if "\x00" in raw or "\r" in raw or "\n" in raw:
        raise RemoteCliPlacementError(f"{field} contains control characters")
    if "//" in raw or any(part in {".", ".."} for part in raw.split("/")):
        raise RemoteCliPlacementError(f"{field} contains an unsafe path component")
    candidate = PurePosixPath(raw) if raw.startswith("/") else PurePosixPath(root_path) / raw
    try:
        relative = candidate.relative_to(PurePosixPath(root_path))
    except ValueError as exc:
        raise RemoteCliPlacementError(f"{field} escapes project_path") from exc
    if not allow_root and str(relative) in {"", "."}:
        raise RemoteCliPlacementError(f"{field} may not equal project_path")
    return str(candidate)


def _relative(path: str, root: str, field: str) -> str:
    try:
        value = PurePosixPath(path).relative_to(PurePosixPath(root))
    except ValueError as exc:
        raise RemoteCliPlacementError(f"{field} is not below remote_workspace") from exc
    result = str(value)
    if result in {"", "."}:
        raise RemoteCliPlacementError(f"{field} may not equal remote_workspace")
    return result


def _cli_row(host: Mapping[str, Any]) -> Mapping[str, Any]:
    row = host.get("remote_cli") or host.get("cli")
    if not isinstance(row, Mapping):
        raise RemoteCliPlacementError("host requires a remote_cli object")
    return row


def _auth_row(cli: Mapping[str, Any]) -> Mapping[str, Any]:
    row = cli.get("auth")
    if not isinstance(row, Mapping):
        raise RemoteCliPlacementError("remote_cli requires an auth evidence object")
    return row


def _check_fresh(
    observed_at: Any,
    ttl_seconds: Any,
    *,
    now: dt.datetime,
    label: str,
) -> tuple[str, float]:
    observed = _timestamp(observed_at, f"{label}.observed_at_utc")
    ttl = _number(ttl_seconds, f"{label}.ttl_seconds")
    age = (now - observed).total_seconds()
    if age > ttl:
        raise RemoteCliPlacementError(f"{label} evidence is stale")
    if age < -MAX_CLOCK_SKEW_SECONDS:
        raise RemoteCliPlacementError(f"{label} evidence is from the future")
    return observed.isoformat(), ttl


def _validate_wrapper(value: Any, field: str) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise RemoteCliPlacementError(f"{field} is required")
    name = _text(value.get("name"), f"{field}.name")
    version = _text(value.get("version"), f"{field}.version")
    digest = _text(value.get("sha256"), f"{field}.sha256").lower()
    if not _HEX64.fullmatch(digest):
        raise RemoteCliPlacementError(f"{field}.sha256 must be a lowercase SHA-256")
    mode = value.get("mode")
    if mode != "dry-run":
        raise RemoteCliPlacementError(f"{field}.mode must be dry-run")
    return {"name": name, "version": version, "sha256": digest, "mode": "dry-run"}


def _route_summary(route: Mapping[str, Any], host_id: str, now: dt.datetime) -> dict[str, Any]:
    if route.get("provider") != "racknerd":
        raise RemoteCliPlacementError("route evidence must name provider=racknerd")
    if route.get("status") != "verified" or route.get("verified") is not True:
        raise RemoteCliPlacementError("RackNerd route evidence is not verified")
    if route.get("kind") not in {"control", "execution", "workload", "artifact", "bulk_data"}:
        raise RemoteCliPlacementError("route evidence has an unsupported kind")
    target = _text(route.get("target_host_id"), "route.target_host_id")
    if target != host_id:
        raise RemoteCliPlacementError("route target_host_id does not match execution_host")
    egress_ip = _text(route.get("egress_ip"), "route.egress_ip")
    try:
        egress_ip = str(ipaddress.ip_address(egress_ip))
    except ValueError as exc:
        raise RemoteCliPlacementError("route.egress_ip must be an IP address") from exc
    observed_at, ttl = _check_fresh(
        route.get("observed_at_utc"), route.get("ttl_seconds"), now=now, label="route"
    )
    source = _text(route.get("source"), "route.source")
    return {
        "provider": "racknerd",
        "kind": route["kind"],
        "status": "verified",
        "verified": True,
        "target_host_id": target,
        "egress_ip": egress_ip,
        "observed_at_utc": observed_at,
        "ttl_seconds": ttl,
        "source": source,
    }


def _validate_host(
    host: Mapping[str, Any], assignment: Mapping[str, Any], now: dt.datetime
) -> tuple[str, str, dict[str, Any]]:
    host_id = _text(host.get("host_id"), "host.host_id")
    if host.get("transport") != "ssh":
        raise RemoteCliPlacementError("remote CLI execution_host must use transport=ssh")
    execution_host = _text(assignment.get("execution_host"), "assignment.execution_host")
    if execution_host != host_id:
        raise RemoteCliPlacementError("assignment.execution_host does not match host.host_id")
    if assignment.get("execution_transport") != "ssh":
        raise RemoteCliPlacementError("remote CLI placement requires execution_transport=ssh")
    project_path = _safe_abs(host.get("project_path"), "host.project_path")
    cli = _cli_row(host)
    expected = _REMOTE_CLI_ROUTES.get(
        (_text(assignment.get("pool_id"), "assignment.pool_id"), _text(assignment.get("provider"), "assignment.provider"))
    )
    if expected is None:
        raise RemoteCliPlacementError("unsupported remote CLI pool/provider pair")
    cli_name = _text(cli.get("name"), "remote_cli.name")
    if cli_name != expected["cli_name"]:
        raise RemoteCliPlacementError("remote_cli.name is not the exact route CLI")
    cli_path = _safe_abs(cli.get("path"), "remote_cli.path")
    version = _text(cli.get("version"), "remote_cli.version")
    if cli.get("install_state") != "installed":
        raise RemoteCliPlacementError("remote_cli install_state is not installed")
    auth = _auth_row(cli)
    if auth.get("state") != "authenticated":
        raise RemoteCliPlacementError("remote CLI auth evidence is not authenticated")
    if auth.get("scope") != "remote_host":
        raise RemoteCliPlacementError(
            "remote CLI auth scope must be remote_host; local desktop auth is not accepted"
        )
    if auth.get("host_id") not in (None, host_id):
        raise RemoteCliPlacementError("remote CLI auth evidence belongs to another host")
    auth_observed, auth_ttl = _check_fresh(
        auth.get("observed_at_utc"), auth.get("ttl_seconds"), now=now, label="remote_cli.auth"
    )
    auth_source = _text(auth.get("source"), "remote_cli.auth.source")
    return project_path, host_id, {
        "name": cli_name,
        "path": cli_path,
        "version": version,
        "install_state": "installed",
        "auth": {
            "state": "authenticated",
            "scope": "remote_host",
            "host_id": host_id,
            "observed_at_utc": auth_observed,
            "ttl_seconds": auth_ttl,
            "source": auth_source,
        },
    }


def build_remote_cli_contract(
    assignment: Mapping[str, Any],
    host: Mapping[str, Any],
    route_evidence: Mapping[str, Any],
    *,
    receipt_path: str | None = None,
    now_utc: str | dt.datetime | None = None,
) -> dict[str, Any]:
    """Validate and return a redacted, dry-run-only remote CLI contract."""

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
        _reject_secret_keys(assignment, "assignment")
        _reject_secret_keys(host, "host")
        _reject_secret_keys(route_evidence, "route_evidence")
        now = _now(now_utc)
        project_path, host_id, cli = _validate_host(host, assignment, now)
        pool_id = _text(assignment.get("pool_id"), "assignment.pool_id")
        provider = _text(assignment.get("provider"), "assignment.provider")
        expected = _REMOTE_CLI_ROUTES[(pool_id, provider)]
        model = _text(assignment.get("model"), "assignment.model")
        if model != expected["model"]:
            raise RemoteCliPlacementError("assignment.model is not the exact approved model")
        if "variant" not in assignment:
            raise RemoteCliPlacementError("assignment.variant is required even when it is null")
        variant = assignment.get("variant")
        if variant != expected["variant"]:
            raise RemoteCliPlacementError("assignment.variant is not the exact approved variant")
        job_id = _text(assignment.get("job_id"), "assignment.job_id")
        attempt_id = _text(assignment.get("attempt_id"), "assignment.attempt_id")
        remote_workspace = _confined_path(
            assignment.get("remote_workspace"), project_path, "assignment.remote_workspace"
        )
        write_scope_path = _confined_path(
            assignment.get("write_scope"), remote_workspace, "assignment.write_scope"
        )
        write_scope = _relative(write_scope_path, remote_workspace, "write_scope")
        receipt_raw = receipt_path if receipt_path is not None else assignment.get("receipt_path")
        receipt = _confined_path(receipt_raw, remote_workspace, "receipt_path")
        receipt_relative = _relative(receipt, remote_workspace, "receipt_path")
        receipt_parts = PurePosixPath(receipt_relative).parts
        if len(receipt_parts) < 3 or receipt_parts[0:2] != (".lad", "receipts"):
            raise RemoteCliPlacementError("receipt_path must be below remote_workspace/.lad/receipts")
        wrapper = _validate_wrapper(
            assignment.get("remote_cli_wrapper") or assignment.get("wrapper"),
            "remote_cli_wrapper",
        )
        workload_host = str(assignment.get("workload_host") or host_id)
        workload_transport = str(assignment.get("workload_transport") or "ssh")
        if workload_transport != "ssh":
            raise RemoteCliPlacementError("remote CLI workload_transport must be ssh")
        workload_wrapper: dict[str, str] | None = None
        if workload_host != host_id:
            workload_wrapper = _validate_wrapper(
                assignment.get("workload_wrapper"), "workload_wrapper"
            )
        route = _route_summary(route_evidence, host_id, now)
        route_path = route_evidence.get("project_path")
        if route_path is not None and _safe_abs(route_path, "route.project_path") != project_path:
            raise RemoteCliPlacementError("route.project_path does not match host.project_path")
        contract: dict[str, Any] = {
            "job_id": job_id,
            "attempt_id": attempt_id,
            "provider": provider,
            "pool_id": pool_id,
            "model": model,
            "variant": variant,
            "execution_host": host_id,
            "execution_transport": "ssh",
            "workload_host": workload_host,
            "workload_transport": workload_transport,
            "host": {
                "host_id": host_id,
                "transport": "ssh",
                "project_path": project_path,
            },
            "project_path": project_path,
            "remote_workspace": remote_workspace,
            "write_scope": write_scope,
            "write_scope_path": write_scope_path,
            "receipt": {
                "path": receipt,
                "relative_path": receipt_relative,
                "format": "json",
                "status": "required_pending",
            },
            "cli": cli,
            "wrapper": wrapper,
            "route_evidence": route,
        }
        if workload_wrapper is not None:
            contract["workload_wrapper"] = workload_wrapper
        contract["contract_digest"] = _digest(contract)
        base.update(
            {
                "decision": "admit",
                "valid": True,
                "reasons": [],
                "contract": contract,
            }
        )
    except RemoteCliPlacementError as exc:
        base["reasons"] = [str(exc)]
    return base


def attach_remote_cli_contract(
    packet: Mapping[str, Any], contract_report_or_contract: Mapping[str, Any]
) -> dict[str, Any]:
    """Project an admitted contract into a packet without executing it.

    The returned packet uses ``adapter=remote_cli`` as an explicit future
    adapter marker.  Existing provider adapters must not treat this marker as
    executable until a separately reviewed runner consumes the contract.
    """

    if not isinstance(packet, Mapping):
        raise RemoteCliPlacementError("packet must be an object")
    _reject_inline_prompts(packet)
    report = contract_report_or_contract
    is_report = isinstance(report.get("contract"), Mapping)
    contract = report.get("contract") if is_report else report
    if not isinstance(contract, Mapping):
        raise RemoteCliPlacementError("an admitted remote CLI contract is required")
    if is_report and report.get("decision") != "admit":
        raise RemoteCliPlacementError("an admitted remote CLI contract is required")
    if contract.get("contract_digest") != _digest({k: v for k, v in contract.items() if k != "contract_digest"}):
        raise RemoteCliPlacementError("remote CLI contract digest mismatch")
    attempts = packet.get("attempts")
    if not isinstance(attempts, list) or not attempts or not isinstance(attempts[0], Mapping):
        raise RemoteCliPlacementError("packet requires one attempt to attach remote CLI placement")
    result = copy.deepcopy(dict(packet))
    attempt = copy.deepcopy(dict(attempts[0]))
    for field in ("model", "variant", "pool_id", "provider", "execution_host", "workload_host"):
        expected = contract.get(field)
        existing = result.get(field)
        if existing not in (None, "", expected):
            raise RemoteCliPlacementError(f"packet.{field} conflicts with remote CLI contract")
        if field in {"model", "variant", "pool_id", "provider", "execution_host", "workload_host"}:
            result[field] = expected
    result["execution_transport"] = "ssh"
    result["workload_transport"] = str(contract["workload_transport"])
    result["workspace"] = str(contract["remote_workspace"])
    result["remote_workspace"] = str(contract["remote_workspace"])
    result["write_scope"] = str(contract["write_scope"])
    result["remote_cli_placement"] = copy.deepcopy(dict(contract))
    result["provider_execution"] = False
    result["model_prompts_sent"] = False
    result["ssh_prompt_sent"] = False
    attempt.update(
        {
            "adapter": "remote_cli",
            "transport": "ssh",
            "host_id": contract["execution_host"],
            "provider": contract["provider"],
            "pool_id": contract["pool_id"],
            "model": contract["model"],
            "variant": contract["variant"],
            "workspace": contract["remote_workspace"],
            "remote_workspace": contract["remote_workspace"],
            "write_scope": contract["write_scope"],
            "receipt_path": contract["receipt"]["path"],
            "remote_cli_wrapper": copy.deepcopy(contract["wrapper"]),
        }
    )
    result["attempts"] = [attempt, *copy.deepcopy(list(attempts[1:]))]
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
    build = sub.add_parser("build", help="compile a provider-free placement contract")
    build.add_argument("--assignment", required=True)
    build.add_argument("--host", required=True)
    build.add_argument("--route", required=True)
    build.add_argument("--receipt-path")
    build.add_argument("--now-utc")
    build.add_argument("--output")
    attach = sub.add_parser("attach", help="attach an admitted contract to a packet")
    attach.add_argument("--packet", required=True)
    attach.add_argument("--contract", required=True)
    attach.add_argument("--output")
    args = parser.parse_args(argv)
    try:
        if args.operation == "build":
            report = build_remote_cli_contract(
                _load(args.assignment),
                _load(args.host),
                _load(args.route),
                receipt_path=args.receipt_path,
                now_utc=args.now_utc,
            )
            _dump(report, args.output)
            return 0 if report["valid"] else 2
        packet = attach_remote_cli_contract(_load(args.packet), _load(args.contract))
        _dump(packet, args.output)
        return 0
    except (OSError, json.JSONDecodeError, RemoteCliPlacementError) as exc:
        _dump(
            {
                "schema_version": SCHEMA_VERSION,
                "contract_type": CONTRACT_TYPE,
                "read_only": True,
                "dry_run": True,
                "provider_execution": False,
                "model_prompts_sent": False,
                "ssh_prompt_sent": False,
                "decision": "block",
                "valid": False,
                "reasons": [f"{type(exc).__name__}: {exc}"],
            },
            getattr(args, "output", None),
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
