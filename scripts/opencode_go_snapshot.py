#!/usr/bin/env python3
"""Snapshot OpenCode Go discovery signals without sending a model prompt."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
from typing import Any


PROVIDER_ID = "opencode-go"
POOL_ID = "opencode.go"
ANSI_RE = re.compile(
    r"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))"
)
MODEL_LINE_RE = re.compile(r"(?m)^\s*(opencode-go/[^\s]+)\s*$")
VERSION_RE = re.compile(r"\b(?:v)?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)\b")
SAFE_MODEL_FIELDS = (
    "id",
    "providerID",
    "name",
    "family",
    "api",
    "status",
    "cost",
    "limit",
    "capabilities",
    "release_date",
    "variants",
)
SENSITIVE_KEYS = {
    "authorization",
    "proxyauthorization",
    "cookie",
    "setcookie",
    "credential",
    "credentials",
    "password",
    "passwd",
    "secret",
    "token",
    "accesstoken",
    "refreshtoken",
    "idtoken",
    "sessiontoken",
    "apikey",
    "privatekey",
    "header",
    "headers",
    "option",
    "options",
}


def strip_ansi(text: str) -> str:
    """Remove terminal control sequences while retaining printable CLI text."""
    return ANSI_RE.sub("", text).replace("\r", "\n").replace("\b", "")


def redact_diagnostic(text: str, limit: int = 1200) -> str:
    """Return a bounded diagnostic with common credential shapes removed."""
    clean = strip_ansi(text)
    clean = re.sub(r"(?i)\bBearer\s+\S+", "Bearer <redacted>", clean)
    clean = re.sub(
        r"(?i)(api[-_]?key|token|secret|password|authorization)\s*[:=]\s*[^\s,;]+",
        r"\1=<redacted>",
        clean,
    )
    clean = re.sub(
        r'(?i)("(?:api[-_]?key|token|secret|password|authorization)"\s*:\s*)"[^"]*"',
        r'\1"<redacted>"',
        clean,
    )
    return clean.strip()[-limit:]


def is_sensitive_key(key: Any) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
    return normalized in SENSITIVE_KEYS


def safe_nested(value: Any) -> Any:
    """Copy catalog metadata while dropping credential-bearing key families."""
    if isinstance(value, dict):
        return {
            str(key): safe_nested(item)
            for key, item in value.items()
            if not is_sensitive_key(key)
        }
    if isinstance(value, list):
        return [safe_nested(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def parse_version(raw: str) -> str | None:
    match = VERSION_RE.search(strip_ansi(raw))
    return match.group(1) if match else None


def parse_auth_provider(raw: str) -> dict[str, Any]:
    """Detect only the OpenCode Go provider row, never credential contents."""
    clean = strip_ansi(raw)
    match = re.search(r"(?im)^.*?OpenCode\s+Go(?:\s+([A-Za-z0-9_-]+))?\s*$", clean)
    credential_type = match.group(1).lower() if match and match.group(1) else None
    return {
        "provider_id": PROVIDER_ID,
        "display_name": "OpenCode Go",
        "state": "configured" if match else "absent",
        "configured": bool(match),
        "credential_type": credential_type,
        "credential_values_inspected": False,
    }


def safe_model_record(full_id: str, metadata: dict[str, Any] | None) -> dict[str, Any]:
    local_id = full_id.split("/", 1)[1]
    source = metadata if isinstance(metadata, dict) else {}
    safe_metadata = {
        field: safe_nested(source[field]) for field in SAFE_MODEL_FIELDS if field in source
    }
    omitted = sorted(key for key in source if is_sensitive_key(key))
    return {
        "model_id": full_id,
        "provider_id": PROVIDER_ID,
        "id": str(source.get("id") or local_id),
        "catalog_state": "visible",
        "runtime_state": "unknown",
        "metadata": safe_metadata,
        "omitted_sensitive_metadata_fields": omitted,
    }


def parse_verbose_catalog(raw: str) -> dict[str, Any]:
    """Parse `opencode models opencode-go --verbose` model/JSON pairs."""
    clean = strip_ansi(raw)
    matches = list(MODEL_LINE_RE.finditer(clean))
    decoder = json.JSONDecoder()
    records: dict[str, dict[str, Any]] = {}
    parse_errors: list[str] = []
    for index, match in enumerate(matches):
        full_id = match.group(1)
        segment_end = matches[index + 1].start() if index + 1 < len(matches) else len(clean)
        segment = clean[match.end() : segment_end]
        metadata: dict[str, Any] | None = None
        brace = segment.find("{")
        if brace >= 0:
            try:
                candidate, _ = decoder.raw_decode(segment[brace:])
                if isinstance(candidate, dict):
                    metadata = candidate
            except json.JSONDecodeError:
                parse_errors.append(full_id)
        records[full_id] = safe_model_record(full_id, metadata)
    models = [records[key] for key in sorted(records)]
    return {
        "provider_id": PROVIDER_ID,
        "state": "visible" if models else "absent",
        "model_count": len(models),
        "models": models,
        "metadata_parse_failures": sorted(parse_errors),
        "metadata_safety": (
            "Verbose catalog metadata is allow-listed; headers, options, and "
            "credential-like fields are omitted."
        ),
    }


def parse_human_number(display: str) -> int | None:
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)([KMB]?)", display.replace(",", ""), re.I)
    if not match:
        return None
    scale = {"": 1, "K": 1_000, "M": 1_000_000, "B": 1_000_000_000}
    return int(round(float(match.group(1)) * scale[match.group(2).upper()]))


def parse_cost(display: str) -> float | None:
    try:
        return float(display.replace("$", "").replace(",", ""))
    except ValueError:
        return None


def normalized_stats_lines(raw: str) -> list[str]:
    lines: list[str] = []
    for raw_line in strip_ansi(raw).splitlines():
        line = raw_line.strip().strip("│").strip()
        if not line or not re.search(r"[A-Za-z0-9]", line):
            continue
        lines.append(line)
    return lines


def parse_local_stats(raw: str) -> dict[str, Any]:
    """Parse local historical `opencode stats`; it is not remaining quota."""
    overview: dict[str, Any] = {}
    totals: dict[str, Any] = {}
    models: list[dict[str, Any]] = []
    section: str | None = None
    current_model: dict[str, Any] | None = None
    overview_fields = {"Sessions": "sessions", "Messages": "messages", "Days": "days"}
    total_fields = {
        "Avg Tokens/Session": "average_tokens_per_session_approx",
        "Median Tokens/Session": "median_tokens_per_session_approx",
        "Cache Write": "cache_write_tokens_approx",
        "Cache Read": "cache_read_tokens_approx",
        "Input": "input_tokens_approx",
        "Output": "output_tokens_approx",
    }
    model_fields = {
        "Input Tokens": "input_tokens_approx",
        "Output Tokens": "output_tokens_approx",
        "Cache Read": "cache_read_tokens_approx",
        "Cache Write": "cache_write_tokens_approx",
        "Messages": "messages",
    }

    for line in normalized_stats_lines(raw):
        if line in {"OVERVIEW", "COST & TOKENS", "MODEL USAGE", "TOOL USAGE"}:
            section = line
            current_model = None
            continue
        if section == "OVERVIEW":
            for label, field in overview_fields.items():
                match = re.fullmatch(rf"{re.escape(label)}\s+([0-9,]+)", line)
                if match:
                    overview[field] = int(match.group(1).replace(",", ""))
                    break
        elif section == "COST & TOKENS":
            match = re.fullmatch(r"Total Cost\s+(\$[0-9.,]+)", line)
            if match:
                totals["total_cost_usd"] = parse_cost(match.group(1))
                continue
            match = re.fullmatch(r"Avg Cost/Day\s+(\$[0-9.,]+)", line)
            if match:
                totals["average_cost_per_day_usd"] = parse_cost(match.group(1))
                continue
            for label, field in total_fields.items():
                match = re.fullmatch(rf"{re.escape(label)}\s+([0-9.,]+[KMB]?)", line, re.I)
                if match:
                    totals[field] = parse_human_number(match.group(1))
                    break
        elif section == "MODEL USAGE":
            if re.fullmatch(r"[A-Za-z0-9_.-]+/[^\s]+", line):
                current_model = {"model_id": line}
                models.append(current_model)
                continue
            if current_model is None:
                continue
            match = re.fullmatch(r"Cost\s+(\$[0-9.,]+)", line)
            if match:
                current_model["cost_usd"] = parse_cost(match.group(1))
                continue
            for label, field in model_fields.items():
                match = re.fullmatch(rf"{re.escape(label)}\s+([0-9.,]+[KMB]?)", line, re.I)
                if match:
                    current_model[field] = parse_human_number(match.group(1))
                    break

    models.sort(key=lambda row: str(row.get("model_id")))
    go_models = [row for row in models if str(row.get("model_id", "")).startswith("opencode-go/")]
    state = "visible" if overview or totals or models else "empty"
    return {
        "state": state,
        "kind": "local_historical_usage",
        "overview": overview,
        "cost_and_tokens": totals,
        "models": models,
        "opencode_go_models": go_models,
        "note": "Historical local stats are not evidence of remaining subscription quota.",
    }


def run_readonly(
    argv: list[str], timeout: float, *, env_overrides: dict[str, str] | None = None
) -> dict[str, Any]:
    env = os.environ.copy()
    env.update({"NO_COLOR": "1", "CLICOLOR": "0", "TERM": "dumb"})
    # Discovery is read-only. Disable background update/model fetch and
    # pruning so a snapshot cannot create network traffic or mutate the
    # selected OpenCode history while collecting local evidence.
    env.update(
        {
            "OPENCODE_DISABLE_AUTOUPDATE": "1",
            "OPENCODE_DISABLE_MODELS_FETCH": "1",
            "OPENCODE_DISABLE_PRUNE": "1",
        }
    )
    if env_overrides:
        env.update(env_overrides)
    try:
        completed = subprocess.run(
            argv,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
            env=env,
        )
        return {
            "ok": completed.returncode == 0,
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "ok": False,
            "returncode": None,
            "stdout": exc.stdout or "",
            "stderr": exc.stderr or "",
            "timed_out": True,
        }
    except OSError as exc:
        return {
            "ok": False,
            "returncode": None,
            "stdout": "",
            "stderr": str(exc),
            "timed_out": False,
        }


def public_command_status(name: str, result: dict[str, Any]) -> dict[str, Any]:
    error = ""
    if not result.get("ok"):
        error = redact_diagnostic(str(result.get("stderr") or ""))
    return {
        "name": name,
        "ok": bool(result.get("ok")),
        "returncode": result.get("returncode"),
        "timed_out": bool(result.get("timed_out")),
        "error": error or None,
    }


def unknown_quota() -> dict[str, Any]:
    return {
        "state": "unknown",
        "five_hour": {"remaining_percent": None, "reset_at": None},
        "weekly": {"remaining_percent": None, "reset_at": None},
        "monthly": {"remaining_percent": None, "reset_at": None},
        "evidence": (
            "No machine-readable remaining-quota evidence was returned by the "
            "read-only OpenCode CLI probes."
        ),
    }


def _link_server_auth(runtime_root: pathlib.Path, auth_data_root: pathlib.Path) -> dict[str, Any]:
    """Link a server-local auth file into an isolated runtime data root.

    The snapshot must keep the mutable OpenCode database selected by
    ``runtime_root``.  ``auth_data_root`` is only an operator-supplied source
    for the existing server credential; replacing ``XDG_DATA_HOME`` with it
    would silently switch the history database and mix unrelated sessions.
    This helper never opens or copies credential bytes.
    """
    source = auth_data_root.expanduser().resolve() / "opencode" / "auth.json"
    if not source.is_file():
        raise FileNotFoundError("server OpenCode auth.json is missing")
    target_root = runtime_root.expanduser().resolve() / "data" / "opencode"
    target_root.mkdir(parents=True, exist_ok=True)
    target = target_root / "auth.json"
    if target.exists() or target.is_symlink():
        if not target.is_symlink() or target.resolve(strict=False) != source:
            raise ValueError("runtime auth path already exists with a different target")
        state = "existing_link"
    else:
        target.symlink_to(source)
        state = "created_link"
    return {
        "state": state,
        "source": "server-local",
        "target": "runtime-local-link",
    }


def build_snapshot(
    opencode: str,
    version_result: dict[str, Any],
    auth_result: dict[str, Any],
    catalog_result: dict[str, Any],
    stats_result: dict[str, Any],
    runtime_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    version = parse_version(str(version_result.get("stdout") or version_result.get("stderr") or ""))
    auth = parse_auth_provider(str(auth_result.get("stdout") or ""))
    if not auth_result.get("ok"):
        auth["state"] = "unknown"
        auth["configured"] = None
        auth["credential_type"] = None
    catalog = parse_verbose_catalog(str(catalog_result.get("stdout") or ""))
    if not catalog_result.get("ok"):
        catalog["state"] = "unknown"
    stats = parse_local_stats(str(stats_result.get("stdout") or ""))
    if not stats_result.get("ok"):
        stats["state"] = "unknown"

    members = [row["model_id"] for row in catalog["models"]]
    catalog_state = str(catalog.get("state"))
    availability = (
        "catalog_visible_runtime_unknown"
        if catalog_state == "visible"
        else "catalog_not_visible_runtime_unknown"
    )
    if auth.get("state") == "absent":
        pool_health = "blocked"
    else:
        pool_health = "unknown"
    historical_go_usage = bool(stats.get("opencode_go_models"))
    core_command_results = (version_result, auth_result, catalog_result)

    return {
        "schema_version": 1,
        # Historical stats is optional diagnostics.  Failure to render it must
        # not erase successful installation/auth/catalog discovery.
        "ok": all(bool(result.get("ok")) for result in core_command_results),
        "source": "read-only OpenCode CLI discovery; no model prompt",
        "fetched_at_utc": dt.datetime.now(tz=dt.timezone.utc).isoformat(),
        "cli": {
            "name": "opencode",
            "path": opencode,
            "version": version,
            "installed": bool(version_result.get("ok") and version),
        },
        "runtime_context": runtime_context
        or {
            "mode": "inherited_environment",
            "runtime_root": None,
            "evidence": "The caller did not pin HOME/XDG/TMPDIR; results are context-local.",
        },
        "auth": auth,
        "catalog": catalog,
        "stats": stats,
        "pools": {
            POOL_ID: {
                "pool_id": POOL_ID,
                "provider_id": PROVIDER_ID,
                "health": pool_health,
                "auth_state": auth.get("state"),
                "catalog_state": catalog_state,
                "runtime_state": "unknown",
                "runtime_reason": "No model prompt was sent by this snapshot.",
                "availability_state": availability,
                "shared_members": members,
                "historical_local_usage_observed": historical_go_usage,
                "quota": unknown_quota(),
                "dispatch_evidence": "candidate_only",
            }
        },
        "commands": [
            public_command_status("version", version_result),
            public_command_status("providers_list", auth_result),
            public_command_status("models_opencode_go_verbose", catalog_result),
            public_command_status("stats_local", stats_result),
        ],
        "security": {
            "model_prompt_sent": False,
            "credential_file_directly_read_by_snapshot": False,
            "credential_values_requested_from_cli": False,
            "credential_values_inspected": False,
            "credential_values_emitted": False,
        },
        "note": (
            "Catalog visibility, configured authentication, historical local usage, "
            "current runtime eligibility, and remaining subscription quota are "
            "separate evidence classes."
        ),
    }


def collect_snapshot(
    opencode: str,
    timeout: float,
    stats_days: int,
    stats_models: int | None,
    runtime_root: str | None = None,
    auth_data_root: str | None = None,
    history_data_root: str | None = None,
) -> dict[str, Any]:
    env_overrides: dict[str, str] = {}
    runtime_context: dict[str, Any]
    if runtime_root:
        root = pathlib.Path(runtime_root).expanduser()
        env_overrides = {
            "HOME": str(root / "home"),
            "XDG_CONFIG_HOME": str(root / "config"),
            "XDG_DATA_HOME": str(root / "data"),
            "XDG_STATE_HOME": str(root / "state"),
            "XDG_CACHE_HOME": str(root / "cache"),
            "TMPDIR": str(root / "tmp"),
        }
        runtime_context = {
            "mode": "pinned_runtime_root",
            "runtime_root": str(root),
            "environment_paths": {key: value for key, value in env_overrides.items()},
            "evidence": "All read-only probes used the same explicit HOME/XDG/TMPDIR context.",
        }
    else:
        runtime_context = {
            "mode": "inherited_environment",
            "runtime_root": None,
            "evidence": "The caller did not pin HOME/XDG/TMPDIR; results are context-local.",
        }
    if auth_data_root:
        auth_root = pathlib.Path(auth_data_root).expanduser()
        runtime_context["auth_data_root"] = str(auth_root)
        runtime_context["auth_evidence"] = (
            "server-local auth source supplied by operator; credential bytes are "
            "not read or copied"
        )
        if runtime_root:
            try:
                runtime_context["auth_link"] = _link_server_auth(
                    pathlib.Path(runtime_root), auth_root
                )
            except (OSError, ValueError) as exc:
                runtime_context["auth_link"] = {
                    "state": "blocked",
                    "reason": type(exc).__name__,
                }
        else:
            runtime_context["auth_link"] = {
                "state": "not_linked",
                "reason": "runtime_root_required_to_isolate_history",
            }
    else:
        runtime_context["auth_data_root"] = None
    if env_overrides:
        runtime_context["environment_paths"] = dict(env_overrides)
    history_env = dict(env_overrides)
    if history_data_root:
        history_data = pathlib.Path(history_data_root).expanduser().resolve()
        history_env["XDG_DATA_HOME"] = str(history_data)
        runtime_context["history_data_root"] = str(history_data)
        runtime_context["history_evidence"] = (
            "Historical stats were read from an explicitly supplied XDG_DATA_HOME; "
            "this is local spend evidence and is separate from remaining quota."
        )
    else:
        runtime_context["history_data_root"] = None
    version_result = run_readonly([opencode, "--version"], timeout, env_overrides=env_overrides)
    auth_result = run_readonly(
        [opencode, "--pure", "providers", "list"], timeout, env_overrides=env_overrides
    )
    catalog_result = run_readonly(
        [opencode, "--pure", "models", PROVIDER_ID, "--verbose"],
        timeout,
        env_overrides=env_overrides,
    )
    # OpenCode v1.18.x treats ``--pure stats`` as an isolated/empty history
    # context. Keep providers/catalog probes pure, but let stats read the
    # explicitly selected local XDG database; otherwise real sessions are
    # silently reported as zero. The read-only environment above prevents
    # update/model-fetch/prune side effects.
    stats_argv = [opencode, "stats", "--days", str(stats_days), "--models"]
    if stats_models is not None:
        stats_argv.append(str(stats_models))
    stats_result = run_readonly(
        stats_argv,
        timeout,
        env_overrides=history_env if history_data_root else env_overrides,
    )
    return build_snapshot(
        opencode,
        version_result,
        auth_result,
        catalog_result,
        stats_result,
        runtime_context,
    )


def emit_result(result: dict[str, Any], output: str | None) -> None:
    rendered = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if not output:
        print(rendered, end="")
        return
    target = pathlib.Path(output).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(target.suffix + ".tmp")
    temporary.write_text(rendered, encoding="utf-8")
    temporary.replace(target)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--opencode", default=shutil.which("opencode") or "opencode")
    parser.add_argument(
        "--runtime-root",
        help="Pin HOME/XDG/TMPDIR to <root>/{home,config,data,state,cache,tmp}; never reads credential values.",
    )
    parser.add_argument(
        "--auth-data-root",
        help="Use an existing server-local OpenCode XDG data root for auth discovery while keeping mutable state under --runtime-root.",
    )
    parser.add_argument(
        "--history-data-root",
        help=(
            "Read local historical stats from this explicit XDG_DATA_HOME while "
            "keeping discovery/auth commands in the selected runtime context."
        ),
    )
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--stats-days", type=int, default=30)
    parser.add_argument(
        "--stats-models",
        type=int,
        default=None,
        help="Limit model rows; the default asks OpenCode for all local model stats.",
    )
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    if args.stats_days <= 0:
        parser.error("--stats-days must be positive")
    if args.stats_models is not None and args.stats_models <= 0:
        parser.error("--stats-models must be positive")
    return args


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    result = collect_snapshot(
        args.opencode,
        args.timeout,
        args.stats_days,
        args.stats_models,
        args.runtime_root,
        args.auth_data_root,
        args.history_data_root,
    )
    emit_result(result, args.output)
    return 0 if result.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
