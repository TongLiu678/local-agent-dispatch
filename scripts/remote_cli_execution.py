#!/usr/bin/env python3
"""Execute one approved Codex/Antigravity CLI attempt on a server.

``remote_cli_placement.py`` deliberately stops at a provider-free placement
contract.  This module is the separately reviewed execution boundary for a
later server canary.  It is still dry-run by default and refuses execution
unless all of the following are bound to the same contract digest:

* the exact approved pool/model/variant;
* fresh remote-authentication and RackNerd route evidence;
* a short-lived approval containing quota and capacity receipt digests; and
* an explicit ``--execute`` flag.

Prompts are read from a confined file, never put in argv, and receipts contain
only digests, byte counts, status and stable error classes.  The adapter does
not log in, download models, inspect credentials, or select a fallback model.
It is safe to run its provider-free tests on the controller while the cluster
is unreachable.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
from collections.abc import Mapping
from typing import Any, Callable


SCHEMA_VERSION = 1
MAX_TTL_SECONDS = 86400.0
MAX_PROMPT_BYTES = 8 * 1024 * 1024
MAX_TIMEOUT_SECONDS = 24 * 3600
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SECRET_KEY = re.compile(
    r"(?:secret|token|password|api[_-]?key|credential|authorization|private[_-]?key)",
    re.I,
)
_PROMPT_KEY = {"prompt", "prompt_text", "prompt_payload", "messages"}
_ROUTES: dict[tuple[str, str], dict[str, Any]] = {
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


class RemoteCliExecutionError(ValueError):
    """Raised when a server provider attempt cannot pass its execution gate."""


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise RemoteCliExecutionError("execution payload is not JSON-serializable") from exc


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise RemoteCliExecutionError(f"{field} must be a sha256:<64 lowercase hex> digest")
    return value


def _plain_digest(value: Any, field: str) -> str:
    if isinstance(value, str) and _HEX64.fullmatch(value):
        return value
    if isinstance(value, str) and _SHA256.fullmatch(value):
        return value[7:]
    raise RemoteCliExecutionError(f"{field} must be a SHA-256 digest")


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RemoteCliExecutionError(f"{field} is required")
    if any(char in value for char in "\0\r\n"):
        raise RemoteCliExecutionError(f"{field} contains control characters")
    return value.strip()


def _safe_id(value: Any, field: str) -> str:
    text = _text(value, field)
    if not _ID.fullmatch(text):
        raise RemoteCliExecutionError(f"{field} is invalid")
    return text


def _reject_sensitive(value: Any, path: str = "input") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            key_text = str(key)
            if _SECRET_KEY.search(key_text):
                raise RemoteCliExecutionError(f"{path} contains a secret-like field")
            if key_text.lower() in _PROMPT_KEY:
                raise RemoteCliExecutionError(f"{path}.{key_text} contains inline prompt text")
            _reject_sensitive(child, f"{path}.{key_text}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_sensitive(child, f"{path}[{index}]")


def _now(value: str | dt.datetime | None) -> dt.datetime:
    if value is None:
        return dt.datetime.now(tz=dt.timezone.utc)
    if isinstance(value, dt.datetime):
        parsed = value
    else:
        try:
            parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError as exc:
            raise RemoteCliExecutionError("now_utc must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise RemoteCliExecutionError("now_utc must include a timezone")
    return parsed.astimezone(dt.timezone.utc)


def _timestamp(value: Any, field: str) -> dt.datetime:
    if not isinstance(value, str) or not value.strip():
        raise RemoteCliExecutionError(f"{field} is required")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RemoteCliExecutionError(f"{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise RemoteCliExecutionError(f"{field} must include a timezone")
    return parsed.astimezone(dt.timezone.utc)


def _fresh(observed_at: Any, ttl_seconds: Any, *, now: dt.datetime, field: str) -> str:
    observed = _timestamp(observed_at, f"{field}.observed_at_utc")
    try:
        ttl = float(ttl_seconds)
    except (TypeError, ValueError) as exc:
        raise RemoteCliExecutionError(f"{field}.ttl_seconds is invalid") from exc
    if not 0 < ttl <= MAX_TTL_SECONDS:
        raise RemoteCliExecutionError(f"{field}.ttl_seconds is outside the allowed range")
    age = (now - observed).total_seconds()
    if age > ttl:
        raise RemoteCliExecutionError(f"{field} evidence is stale")
    if age < -60:
        raise RemoteCliExecutionError(f"{field} evidence is from the future")
    return observed.isoformat()


def _abs_path(value: Any, field: str) -> pathlib.Path:
    if isinstance(value, os.PathLike):
        value = os.fspath(value)
    raw = _text(value, field)
    path = pathlib.Path(raw).expanduser()
    if not path.is_absolute() or any(part in {".", ".."} for part in path.parts):
        raise RemoteCliExecutionError(f"{field} must be an absolute normalized path")
    try:
        return path.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise RemoteCliExecutionError(f"{field} cannot be resolved") from exc


def _confined(value: Any, root: pathlib.Path, field: str, *, allow_root: bool = False) -> pathlib.Path:
    candidate = _abs_path(value, field)
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise RemoteCliExecutionError(f"{field} escapes remote_workspace") from exc
    if not allow_root and str(relative) in {"", "."}:
        raise RemoteCliExecutionError(f"{field} may not equal remote_workspace")
    return candidate


def _load_json(path: pathlib.Path | str, field: str) -> dict[str, Any]:
    try:
        value = json.loads(pathlib.Path(path).expanduser().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RemoteCliExecutionError(f"{field} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise RemoteCliExecutionError(f"{field} must be an object")
    return value


def _validate_contract(contract: Mapping[str, Any], *, now: dt.datetime) -> dict[str, Any]:
    if not isinstance(contract, Mapping):
        raise RemoteCliExecutionError("contract must be an object")
    _reject_sensitive(contract, "contract")
    if contract.get("schema_version") != SCHEMA_VERSION:
        raise RemoteCliExecutionError("contract schema_version is unsupported")
    contract_digest = _plain_digest(contract.get("contract_digest"), "contract_digest")
    unsigned = {key: value for key, value in contract.items() if key != "contract_digest"}
    if _digest(unsigned) != contract_digest:
        raise RemoteCliExecutionError("contract digest mismatch")
    provider = _text(contract.get("provider"), "contract.provider")
    pool_id = _text(contract.get("pool_id"), "contract.pool_id")
    route = _ROUTES.get((pool_id, provider))
    if route is None:
        raise RemoteCliExecutionError("contract provider/pool is not an approved server route")
    model = _text(contract.get("model"), "contract.model")
    variant = contract.get("variant")
    if model != route["model"] or variant != route["variant"]:
        raise RemoteCliExecutionError("contract exact model/variant is not approved")
    if contract.get("execution_transport") != "ssh":
        raise RemoteCliExecutionError("contract execution_transport must be ssh")
    host_id = _safe_id(contract.get("execution_host"), "contract.execution_host")
    workspace = _abs_path(contract.get("remote_workspace"), "contract.remote_workspace")
    if not workspace.is_dir():
        raise RemoteCliExecutionError("remote_workspace does not exist")
    write_scope = _confined(contract.get("write_scope_path"), workspace, "contract.write_scope_path")
    cli = contract.get("cli")
    if not isinstance(cli, Mapping):
        raise RemoteCliExecutionError("contract.cli is required")
    cli_name = _text(cli.get("name"), "contract.cli.name")
    if cli_name != route["cli_name"]:
        raise RemoteCliExecutionError("contract CLI name does not match route")
    cli_path = _abs_path(cli.get("path"), "contract.cli.path")
    if not cli_path.is_file() or not os.access(cli_path, os.X_OK):
        raise RemoteCliExecutionError("contract CLI is not executable")
    if cli.get("install_state") != "installed":
        raise RemoteCliExecutionError("contract CLI is not marked installed")
    auth = cli.get("auth")
    if not isinstance(auth, Mapping) or auth.get("state") != "authenticated" or auth.get("scope") != "remote_host":
        raise RemoteCliExecutionError("contract CLI auth is not remote-host authenticated")
    if auth.get("host_id") not in (None, host_id):
        raise RemoteCliExecutionError("contract CLI auth belongs to another host")
    auth_observed = _fresh(auth.get("observed_at_utc"), auth.get("ttl_seconds"), now=now, field="contract.cli.auth")
    route_evidence = contract.get("route_evidence")
    if not isinstance(route_evidence, Mapping):
        raise RemoteCliExecutionError("contract.route_evidence is required")
    if route_evidence.get("provider") != "racknerd" or route_evidence.get("status") != "verified" or route_evidence.get("verified") is not True:
        raise RemoteCliExecutionError("RackNerd route evidence is not verified")
    if route_evidence.get("target_host_id") != host_id:
        raise RemoteCliExecutionError("route target host does not match contract")
    try:
        egress_ip = str(ipaddress.ip_address(_text(route_evidence.get("egress_ip"), "route.egress_ip")))
    except ValueError as exc:
        raise RemoteCliExecutionError("route.egress_ip is invalid") from exc
    route_observed = _fresh(route_evidence.get("observed_at_utc"), route_evidence.get("ttl_seconds"), now=now, field="route")
    receipt = contract.get("receipt")
    if not isinstance(receipt, Mapping):
        raise RemoteCliExecutionError("contract.receipt is required")
    receipt_path = _confined(receipt.get("path"), workspace, "contract.receipt.path")
    try:
        receipt_relative = receipt_path.relative_to(workspace)
    except ValueError as exc:  # pragma: no cover - _confined already checks
        raise RemoteCliExecutionError("receipt path escapes remote_workspace") from exc
    if len(receipt_relative.parts) < 3 or receipt_relative.parts[:2] != (".lad", "receipts"):
        raise RemoteCliExecutionError("receipt path must be below .lad/receipts")
    project_id = _safe_id(contract.get("project_id") or host_id, "contract.project_id")
    return {
        "contract_digest": contract_digest,
        "provider": provider,
        "pool_id": pool_id,
        "model": model,
        "variant": variant,
        "execution_host": host_id,
        "project_id": project_id,
        "remote_workspace": workspace,
        "write_scope_path": write_scope,
        "cli_path": cli_path,
        "auth_observed_at_utc": auth_observed,
        "route_observed_at_utc": route_observed,
        "route_egress_ip": egress_ip,
        "receipt_path": receipt_path,
        "attempt_id": _safe_id(contract.get("attempt_id"), "contract.attempt_id"),
    }


def _validate_authorization(
    authorization: Mapping[str, Any], context: Mapping[str, Any], *, now: dt.datetime
) -> dict[str, Any]:
    if not isinstance(authorization, Mapping):
        raise RemoteCliExecutionError("authorization must be an object")
    _reject_sensitive(authorization, "authorization")
    if authorization.get("schema_version") != SCHEMA_VERSION:
        raise RemoteCliExecutionError("authorization schema_version is unsupported")
    if authorization.get("approved") is not True or authorization.get("decision") != "allow_provider_execution":
        raise RemoteCliExecutionError("explicit provider execution approval is required")
    if _plain_digest(authorization.get("contract_digest"), "authorization.contract_digest") != context["contract_digest"]:
        raise RemoteCliExecutionError("authorization contract digest mismatch")
    for field, expected in (
        ("provider", context["provider"]),
        ("pool_id", context["pool_id"]),
        ("model", context["model"]),
        ("variant", context["variant"]),
        ("attempt_id", context["attempt_id"]),
    ):
        if authorization.get(field) != expected:
            raise RemoteCliExecutionError(f"authorization {field} mismatch")
    run_id = _safe_id(authorization.get("run_id"), "authorization.run_id")
    observed = _fresh(
        authorization.get("observed_at_utc"), authorization.get("ttl_seconds"), now=now, field="authorization"
    )
    quota_digest = _sha256(authorization.get("quota_snapshot_digest"), "authorization.quota_snapshot_digest")
    capacity_digest = _sha256(authorization.get("capacity_receipt_digest"), "authorization.capacity_receipt_digest")
    return {
        "authorization_digest": _digest(dict(authorization)),
        "run_id": run_id,
        "observed_at_utc": observed,
        "quota_snapshot_digest": quota_digest,
        "capacity_receipt_digest": capacity_digest,
    }


def _build_argv(context: Mapping[str, Any], *, result_path: pathlib.Path) -> list[str]:
    provider = str(context["provider"])
    if provider == "codex":
        argv = [
            str(context["cli_path"]),
            "exec",
            "--json",
            "--model",
            str(context["model"]),
            "--cd",
            str(context["remote_workspace"]),
            "--sandbox",
            "workspace-write",
            "--output-last-message",
            str(result_path),
            "-",
        ]
        if context.get("variant"):
            argv.extend(["-c", f'model_reasoning_effort="{context["variant"]}"'])
        return argv
    if provider == "antigravity":
        return [
            str(context["cli_path"]),
            "--print",
            "--model",
            str(context["model"]),
            "--output-format",
            "json",
            "--input-format",
            "text",
            "--mode",
            "accept-edits",
            "--project",
            str(context["project_id"]),
        ]
    raise RemoteCliExecutionError("unsupported provider execution route")


def _extract_text(raw: str) -> str:
    chunks: list[str] = []
    for line in raw.splitlines():
        try:
            event = json.loads(line)
        except (TypeError, ValueError):
            continue
        if not isinstance(event, Mapping):
            continue
        if event.get("type") == "error":
            raise RemoteCliExecutionError("provider emitted an error event")
        candidates: list[Any] = []
        if event.get("type") == "text":
            candidates.extend([event.get("text"), (event.get("part") or {}).get("text") if isinstance(event.get("part"), Mapping) else None])
        if event.get("type") == "item.completed":
            item = event.get("item")
            if isinstance(item, Mapping):
                candidates.extend([item.get("text"), item.get("content")])
        if event.get("type") in {"assistant", "message", "result"}:
            candidates.extend([event.get("text"), event.get("content"), event.get("message")])
        # Antigravity releases have emitted both typed stream records and a
        # single JSON object with a top-level ``response``/``output`` field.
        # Accept only these known text-bearing fields; never persist the raw
        # event object in a receipt.
        candidates.extend([event.get("response"), event.get("output")])
        for candidate in candidates:
            if isinstance(candidate, str) and candidate.strip():
                chunks.append(candidate)
            elif isinstance(candidate, list):
                for part in candidate:
                    if isinstance(part, Mapping) and isinstance(part.get("text"), str):
                        chunks.append(part["text"])
    return "".join(chunks).strip()


def _atomic_write(path: pathlib.Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
    temporary = pathlib.Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
            if not text.endswith("\n"):
                handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _file_digest(path: pathlib.Path) -> tuple[int, str]:
    data = path.read_bytes()
    return len(data), hashlib.sha256(data).hexdigest()


def run_once(
    contract: Mapping[str, Any],
    *,
    authorization: Mapping[str, Any] | None = None,
    prompt_file: pathlib.Path | str,
    result_source: pathlib.Path | str,
    execute: bool = False,
    timeout_seconds: int = 3600,
    now_utc: str | dt.datetime | None = None,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    """Build or execute one exact server CLI attempt.

    ``execute=False`` never opens the provider CLI and returns only a command
    digest.  Tests can inject ``runner``; production uses ``subprocess.run``
    with ``shell=False`` and a bounded timeout.
    """

    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or not 1 <= timeout_seconds <= MAX_TIMEOUT_SECONDS:
        raise RemoteCliExecutionError("timeout_seconds is outside 1..86400")
    now = _now(now_utc)
    context = _validate_contract(contract, now=now)
    prompt_path = _confined(prompt_file, context["remote_workspace"], "prompt_file")
    result_path = _confined(result_source, context["remote_workspace"], "result_source")
    if not result_path.is_relative_to(context["write_scope_path"]):
        raise RemoteCliExecutionError("result_source is outside contract write scope")
    try:
        prompt_bytes = prompt_path.read_bytes()
    except OSError as exc:
        raise RemoteCliExecutionError("prompt_file cannot be read") from exc
    if len(prompt_bytes) > MAX_PROMPT_BYTES:
        raise RemoteCliExecutionError("prompt_file exceeds the bounded size")
    try:
        prompt = prompt_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RemoteCliExecutionError("prompt_file must be UTF-8") from exc
    argv = _build_argv(context, result_path=result_path)
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "status": "planned" if not execute else "blocked",
        "provider": context["provider"],
        "pool_id": context["pool_id"],
        "model": context["model"],
        "variant": context["variant"],
        "execution_host": context["execution_host"],
        "contract_digest": context["contract_digest"],
        "command_digest": _digest(argv),
        "prompt_bytes": len(prompt_bytes),
        "provider_execution": False,
        "model_prompts_sent": False,
        "read_only": not execute,
    }
    if not execute:
        return report
    if authorization is None:
        raise RemoteCliExecutionError("authorization is required with --execute")
    auth = _validate_authorization(authorization, context, now=now)
    if result_path.exists():
        raise RemoteCliExecutionError("result_source already exists; refusing stale overwrite")
    started = dt.datetime.now(tz=dt.timezone.utc)
    try:
        completed = runner(
            argv,
            cwd=str(context["remote_workspace"]),
            input=prompt,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout_seconds,
            shell=False,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        )
    except subprocess.TimeoutExpired as exc:
        report.update({
            "status": "timed_out",
            "returncode": 124,
            "provider_execution": True,
            "model_prompts_sent": True,
            "authorization_digest": auth["authorization_digest"],
        })
        _write_receipt(context, auth, report, started=started)
        return report
    except (OSError, TypeError) as exc:
        raise RemoteCliExecutionError("provider CLI could not be started") from exc
    raw_stdout = completed.stdout if isinstance(completed.stdout, str) else str(completed.stdout or "")
    if completed.returncode != 0:
        report.update({
            "status": "failed",
            "returncode": int(completed.returncode),
            "error_code": "provider_nonzero",
            "provider_execution": True,
            "model_prompts_sent": True,
            "authorization_digest": auth["authorization_digest"],
        })
        _write_receipt(context, auth, report, started=started)
        return report
    if result_path.is_file():
        try:
            result_text = result_path.read_text(encoding="utf-8").strip()
        except (OSError, UnicodeDecodeError):
            result_text = ""
            result_error = "result_unreadable"
        else:
            result_error = "result_empty" if not result_text else None
    else:
        try:
            result_text = _extract_text(raw_stdout)
        except RemoteCliExecutionError:
            result_text = ""
            result_error = "provider_error_event"
        else:
            result_error = "result_missing" if not result_text else None
        if result_text:
            _atomic_write(result_path, result_text)
    if not result_text:
        report.update({
            "status": "failed",
            "returncode": 2,
            "error_code": result_error or "result_missing",
            "provider_execution": True,
            "model_prompts_sent": True,
            "authorization_digest": auth["authorization_digest"],
        })
        _write_receipt(context, auth, report, started=started)
        return report
    result_bytes, result_sha256 = _file_digest(result_path)
    report.update({
        "status": "completed",
        "returncode": int(completed.returncode),
        "result_bytes": result_bytes,
        "result_sha256": result_sha256,
        "provider_execution": True,
        "model_prompts_sent": True,
        "authorization_digest": auth["authorization_digest"],
        "quota_snapshot_digest": auth["quota_snapshot_digest"],
        "capacity_receipt_digest": auth["capacity_receipt_digest"],
    })
    _write_receipt(context, auth, report, started=started)
    return report


def _write_receipt(
    context: Mapping[str, Any], authorization: Mapping[str, Any], report: Mapping[str, Any], *, started: dt.datetime
) -> None:
    receipt = {
        "schema_version": SCHEMA_VERSION,
        "receipt_type": "local-agent-dispatch.remote_cli_execution",
        "status": report.get("status"),
        "run_id": authorization.get("run_id"),
        "attempt_id": context.get("attempt_id"),
        "provider": context.get("provider"),
        "pool_id": context.get("pool_id"),
        "model": context.get("model"),
        "variant": context.get("variant"),
        "execution_host": context.get("execution_host"),
        "contract_digest": context.get("contract_digest"),
        "authorization_digest": authorization.get("authorization_digest"),
        "command_digest": report.get("command_digest"),
        "provider_execution": bool(report.get("provider_execution")),
        "model_prompts_sent": bool(report.get("model_prompts_sent")),
        "result_bytes": report.get("result_bytes"),
        "result_sha256": report.get("result_sha256"),
        "error_code": report.get("error_code"),
        "started_at_utc": started.isoformat(),
        "completed_at_utc": dt.datetime.now(tz=dt.timezone.utc).isoformat(),
    }
    receipt["receipt_digest"] = "sha256:" + _digest(receipt)
    _atomic_write(pathlib.Path(context["receipt_path"]), json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2))


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", required=True)
    parser.add_argument("--authorization")
    parser.add_argument("--prompt-file", required=True)
    parser.add_argument("--result-source", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=3600)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    try:
        contract = _load_json(args.contract, "contract")
        authorization = _load_json(args.authorization, "authorization") if args.authorization else None
        report = run_once(
            contract,
            authorization=authorization,
            prompt_file=args.prompt_file,
            result_source=args.result_source,
            execute=args.execute,
            timeout_seconds=args.timeout_seconds,
        )
        print(json.dumps(report, ensure_ascii=False, sort_keys=True))
        return 0 if report.get("status") in {"planned", "completed"} else 2
    except (OSError, RemoteCliExecutionError, ValueError) as exc:
        print(json.dumps({"schema_version": SCHEMA_VERSION, "status": "blocked", "error_code": type(exc).__name__}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(_main())


__all__ = ["RemoteCliExecutionError", "run_once"]
