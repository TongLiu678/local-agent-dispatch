#!/usr/bin/env python3
"""Provider-free OpenCode Go quota-evidence snapshot for the planner.

Runs the existing read-only OpenCode snapshot commands and/or imports an
explicit, user-supplied read-only console snapshot. It never sends a model
prompt or emits auth credential values. With ``--usage-api`` it calls the
official OpenCode Go usage endpoint by default (or an explicitly supplied
compatible HTTPS endpoint). Output is stable, redacted JSON suitable for the
planner.

The machine-readable OpenCode CLI snapshot does not expose the current
remaining five-hour/weekly/monthly balance. The authenticated official usage
endpoint does; if it is unavailable, the result remains ``unknown``. Unknown
is never mapped to zero or full.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import pathlib
import shutil
import sys
import urllib.error
import urllib.request
from typing import Any

HERE = pathlib.Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
EVIDENCE_PATH = REPO_ROOT / "src" / "local_agent_dispatch" / "quota" / "evidence.py"
SNAPSHOT_PATH = HERE / "opencode_go_snapshot.py"

POOL_ID = "opencode.go"
PROVIDER_ID = "opencode-go"
KIND = "opencode_go_quota_evidence"
# Merged into the OpenCode console service on 2026-08-11.  Keep this as a
# named, documented endpoint rather than accepting an arbitrary guessed URL.
OFFICIAL_USAGE_ENDPOINT = "https://opencode.ai/zen/go/v1/usage"


def _load_module(name: str, path: pathlib.Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load module from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _default_snapshot() -> Any:
    return _load_module("opencode_go_snapshot", SNAPSHOT_PATH)


def _default_evidence() -> Any:
    return _load_module("quota_evidence", EVIDENCE_PATH)


def _load_json(path: pathlib.Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: cannot read {path}: {exc}")


def _load_opencode_go_key(path: pathlib.Path) -> str:
    """Read one configured key only for an explicit authenticated usage call.

    The value is held in memory for the request and is never logged, returned,
    or persisted.  The default path is never read unless the caller opts into
    ``--usage-use-auth-store``.
    """
    data = _load_json(path)
    if not isinstance(data, dict):
        raise SystemExit("error: OpenCode auth store must be a JSON object")
    entry = data.get("opencode-go")
    if not isinstance(entry, dict) or not isinstance(entry.get("key"), str) or not entry["key"]:
        raise SystemExit("error: OpenCode auth store has no configured opencode-go key")
    return entry["key"]


def _fetch_usage_api(endpoint: str, api_key: str, timeout: float) -> dict[str, Any]:
    """Fetch an explicitly verified read-only usage endpoint without logging auth."""
    request = urllib.request.Request(
        endpoint,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/json",
            "User-Agent": "local-agent-dispatch-quota-evidence/1",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(256_000)
            parsed = json.loads(raw)
            if not isinstance(parsed, dict):
                raise ValueError("usage API response is not a JSON object")
            return {"ok": True, "http_status": int(response.status), "body": parsed}
    except urllib.error.HTTPError as exc:
        # Preserve only status and a bounded, redacted body; never emit headers
        # because they may contain authentication material.
        raw = exc.read(8_000)
        body_text = raw.decode("utf-8", "replace")
        body_text = evidence_redact_text(body_text)
        return {"ok": False, "http_status": int(exc.code), "error": body_text}
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return {"ok": False, "error_type": type(exc).__name__, "error": str(exc)[:500]}


def evidence_redact_text(text: str) -> str:
    """Small local redactor used before importing the evidence module."""
    import re
    text = re.sub(r"(?i)Bearer\s+\S+", "Bearer <redacted>", text)
    return re.sub(
        r"(?i)(api[-_]?key|token|secret|password|authorization)\s*[:=]\s*[^\s,;]+",
        r"\1=<redacted>",
        text,
    )[-1000:]


def _parse_multiplier_pairs(values: list[str]) -> dict[str, float]:
    multipliers: dict[str, float] = {}
    for pair in values:
        if "=" not in pair:
            raise SystemExit(f"error: --model-multiplier expects model=value, got {pair!r}")
        model, _, raw_value = pair.partition("=")
        try:
            multiplier = float(raw_value)
        except ValueError:
            raise SystemExit(f"error: non-numeric multiplier for {model!r}")
        if multiplier < 0.0:
            raise SystemExit(f"error: multiplier must not be negative for {model!r}")
        multipliers[model] = multiplier
    return multipliers


def build_bundle(
    evidence: Any,
    *,
    discovery: dict[str, Any] | None,
    console_result: dict[str, Any] | None,
    spend: dict[str, Any] | None,
    runtime_events: list[dict[str, Any]],
    records: list[dict[str, Any]],
    overage_fallback_state: str,
    model_multipliers: dict[str, float],
    pilot_args: dict[str, Any],
    usage_api_result: dict[str, Any] | None = None,
    usage_api_credential_source: str | None = None,
    now_utc: str | None = None,
) -> dict[str, Any]:
    pool_record: dict[str, Any] = {}
    if discovery is not None:
        pools = discovery.get("pools") or {}
        pool_record = pools.get(POOL_ID) or {}
        auth_state = str(pool_record.get("auth_state") or discovery.get("auth", {}).get("state") or "unknown")
    else:
        auth_state = "unknown"
    catalog_state = str(pool_record.get("catalog_state") or "unknown")
    catalog_visible = catalog_state == "visible"

    balance = evidence.balance_state(records, now_utc)
    pilot = evidence.pilot_decision(
        records,
        catalog_visible=catalog_visible,
        auth_state=auth_state,
        unknown_quota_policy=pilot_args["unknown_quota_policy"],
        unknown_quota_pilot_percent=pilot_args["unknown_quota_pilot_percent"],
        reserve_percent=pilot_args["reserve_percent"],
        lanes=pilot_args["lanes"],
        lane_cost_cap_usd=pilot_args["lane_cost_cap_usd"],
        lane_token_cap=pilot_args["lane_token_cap"],
        now_utc=now_utc,
    )

    history_summary = None
    if discovery is not None:
        stats = discovery.get("stats") or {}
        if stats.get("state") == "visible" or stats.get("state") == "empty":
            overview = stats.get("overview") or {}
            tokens = stats.get("cost_and_tokens") or {}
            if overview or tokens or stats.get("models"):
                history_summary = {
                    "kind": "local_historical_usage",
                    "state": stats.get("state"),
                    "overview": overview,
                    "cost_and_tokens": tokens,
                    "opencode_go_models": stats.get("opencode_go_models") or [],
                    "note": stats.get("note")
                    or "Local historical stats are spend evidence only, not remaining quota.",
                    "attribution": "unknown",
                    "attribution_note": (
                        "Concurrent consumers of the shared opencode.go pool are not "
                        "attributable from local stats; spend is labeled confounded/unknown."
                    ),
                }

    note = (
        "The machine-readable OpenCode CLI snapshot does not expose remaining "
        "five-hour/weekly/monthly balance; use the authenticated official usage "
        "endpoint or a console snapshot."
    )
    zen_balance = None
    if console_result is not None:
        note = "Console snapshot imported; records are account-level evidence."
        zen_balance = console_result.get("zen_balance")
    if usage_api_result is not None and usage_api_result.get("ok"):
        note = (
            "Official OpenCode Go usage API imported; percentages are account-level "
            "shared-pool evidence."
        )
    elif usage_api_result is not None and not usage_api_result.get("ok"):
        note += " Official usage API probe failed; balance evidence was not fabricated."
    if spend is not None:
        note += " Spend bounds from receipts are historical evidence only."

    security = {
        "model_prompt_sent": False,
        "credential_values_inspected": usage_api_credential_source is not None,
        "credential_values_emitted": False,
        "undocumented_balance_endpoint_called": False,
        "documented_usage_endpoint_called": bool(usage_api_result is not None),
        "usage_api_credential_source": usage_api_credential_source,
        "note": (
            "Catalog and stats commands are read-only. An authenticated usage "
            "probe is opt-in and requires a user-supplied endpoint; its credential "
            "value is held in memory only and never emitted."
        ),
    }

    return {
        "schema_version": evidence.SCHEMA_VERSION,
        "kind": KIND,
        "fetched_at_utc": now_utc or evidence.now_utc(),
        "pool_id": POOL_ID,
        "provider_id": PROVIDER_ID,
        "scope_hash": evidence.scope_hash(scope_hint="cli-snapshot"),
        "balance_state": balance,
        "records": records,
        "spend_bounds": spend,
        "overage_fallback_state": overage_fallback_state,
        "zen_balance": zen_balance,
        "usage_api": usage_api_result,
        "runtime_context": (discovery or {}).get(
            "runtime_context",
            {
                "mode": "inherited_environment",
                "runtime_root": None,
                "evidence": (
                    "The caller did not pin HOME/XDG/TMPDIR; quota evidence is "
                    "context-local."
                ),
            },
        ),
        "history_summary": history_summary,
        "runtime_events": runtime_events,
        "model_usage_multipliers": model_multipliers,
        "pilot": pilot,
        "security": security,
        "commands": (discovery or {}).get("commands", []),
        "note": note,
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--opencode", default=shutil.which("opencode") or "opencode")
    parser.add_argument(
        "--runtime-root",
        help=(
            "Pin OpenCode discovery to <root>/{home,config,data,state,cache,tmp}; "
            "the root is also recorded in the evidence bundle."
        ),
    )
    parser.add_argument(
        "--auth-data-root",
        help=(
            "Server-local OpenCode XDG data root containing auth.json. When used "
            "with --runtime-root, only a symlink is created inside the isolated "
            "runtime; credential values are never emitted."
        ),
    )
    parser.add_argument(
        "--history-data-root",
        help=(
            "Read local historical stats from this explicit XDG_DATA_HOME; this "
            "does not change account-level quota evidence."
        ),
    )
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--stats-days", type=int, default=30)
    parser.add_argument("--stats-models", type=int, default=None)
    parser.add_argument(
        "--skip-discovery",
        action="store_true",
        help="Do not run OpenCode CLI commands (offline/provider-free mode).",
    )
    parser.add_argument(
        "--console",
        metavar="PATH",
        help="Import an explicit user-supplied read-only console snapshot JSON.",
    )
    parser.add_argument(
        "--usage-api",
        action="store_true",
        help=(
            "Call the official OpenCode Go usage endpoint (read-only; explicit "
            "opt-in)."
        ),
    )
    parser.add_argument(
        "--usage-endpoint",
        default=OFFICIAL_USAGE_ENDPOINT,
        help=(
            "HTTPS usage endpoint. Defaults to the official OpenCode Go endpoint; "
            "override only with a separately verified compatible endpoint."
        ),
    )
    parser.add_argument(
        "--usage-api-key-env",
        metavar="ENV",
        help="Environment variable containing the Go API key for --usage-api.",
    )
    parser.add_argument(
        "--usage-use-auth-store",
        action="store_true",
        help="Explicitly use the local OpenCode auth store for --usage-api; never logs the key.",
    )
    parser.add_argument(
        "--usage-auth-file",
        default=str(pathlib.Path.home() / ".local/share/opencode/auth.json"),
        help="Auth store path used only with --usage-use-auth-store.",
    )
    parser.add_argument(
        "--receipts",
        metavar="PATH",
        help="JSON list of before/after usage receipts used as spend evidence only.",
    )
    parser.add_argument(
        "--failure-text",
        metavar="TEXT",
        help="Classify one runtime failure string (e.g. a 429 with reset hint).",
    )
    parser.add_argument(
        "--failure-model",
        metavar="MODEL",
        default="unknown",
        help="Exact model id to retain in the classified failure event.",
    )
    parser.add_argument("--failure-variant", metavar="VARIANT", default=None)
    parser.add_argument(
        "--model-multiplier",
        action="append",
        default=[],
        metavar="MODEL=W",
        help="Model-specific cost/usage multiplier inside the shared pool (repeatable).",
    )
    parser.add_argument("--pilot-lanes", type=int, default=1)
    parser.add_argument("--pilot-lane-cost-cap-usd", type=float, default=None)
    parser.add_argument("--pilot-lane-token-cap", type=int, default=None)
    parser.add_argument(
        "--unknown-quota-policy",
        choices=["pilot", "block"],
        default=None,
        help="Explicit planner policy for an unknown remaining balance.",
    )
    parser.add_argument("--unknown-quota-pilot-percent", type=float, default=None)
    parser.add_argument("--reserve-percent", type=float, default=10.0)
    parser.add_argument("--output")
    parser.add_argument(
        "--now-utc",
        help=(
            "Evaluation timestamp for deterministic fixture/replay imports. "
            "If omitted, use the current UTC time."
        ),
    )
    args = parser.parse_args(argv)
    if args.usage_api and bool(args.usage_api_key_env) == bool(args.usage_use_auth_store):
        parser.error("--usage-api requires exactly one of --usage-api-key-env or --usage-use-auth-store")
    if args.usage_endpoint and not str(args.usage_endpoint).startswith("https://"):
        parser.error("--usage-endpoint must use https://")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    if args.now_utc:
        try:
            evidence = _default_evidence()
            evidence._parse_utc(args.now_utc)
        except (TypeError, ValueError) as exc:
            parser.error(f"--now-utc must be ISO-8601: {exc}")
    if args.stats_days <= 0:
        parser.error("--stats-days must be positive")
    if args.stats_models is not None and args.stats_models <= 0:
        parser.error("--stats-models must be positive")
    if args.pilot_lanes < 1:
        parser.error("--pilot-lanes must be positive")
    if args.unknown_quota_pilot_percent is not None and not 0.0 < args.unknown_quota_pilot_percent <= 100.0:
        parser.error("--unknown-quota-pilot-percent must be in (0, 100]")
    if not 0.0 <= args.reserve_percent < 100.0:
        parser.error("--reserve-percent must be in [0, 100)")
    return args


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    evidence = _default_evidence()

    discovery = None
    if not args.skip_discovery:
        snapshot_module = _default_snapshot()
        discovery = snapshot_module.collect_snapshot(
            args.opencode,
            args.timeout,
            args.stats_days,
            args.stats_models,
            args.runtime_root,
            args.auth_data_root,
            args.history_data_root,
        )

    records: list[dict[str, Any]] = []
    console_result = None
    overage_fallback_state = "unknown"
    usage_api_result: dict[str, Any] | None = None
    usage_api_credential_source: str | None = None
    if args.usage_api:
        if args.usage_api_key_env:
            api_key = os.environ.get(args.usage_api_key_env)
            if not api_key:
                print(f"error: usage API key environment variable is unset: {args.usage_api_key_env}", file=sys.stderr)
                return 3
            usage_api_credential_source = f"env:{args.usage_api_key_env}"
        else:
            api_key = _load_opencode_go_key(pathlib.Path(args.usage_auth_file).expanduser())
            usage_api_credential_source = "opencode_auth_store"
        usage_api_result = _fetch_usage_api(args.usage_endpoint, api_key, args.timeout)
        if usage_api_result.get("ok"):
            try:
                parsed_api = evidence.parse_usage_api_response(
                    usage_api_result["body"],
                    observed_at_utc=args.now_utc,
                    endpoint=args.usage_endpoint,
                )
            except ValueError as exc:
                usage_api_result = {
                    "ok": False,
                    "error_type": "invalid_response",
                    "error": str(exc)[:500],
                }
            else:
                usage_api_result["parsed"] = parsed_api
                records.extend(parsed_api["records"])
                overage_fallback_state = parsed_api["overage_fallback_state"]
    if args.console:
        try:
            console_result = evidence.parse_console_snapshot(_load_json(pathlib.Path(args.console)))
        except ValueError as exc:
            print(f"error: console import refused: {exc}", file=sys.stderr)
            return 3
        records.extend(console_result["records"])
        overage_fallback_state = console_result["overage_fallback_state"]

    spend = None
    if args.receipts:
        receipts = _load_json(pathlib.Path(args.receipts))
        if not isinstance(receipts, list):
            print("error: --receipts must point to a JSON array", file=sys.stderr)
            return 1
        spend = evidence.spend_bounds(receipts)

    runtime_events: list[dict[str, Any]] = []
    if args.failure_text:
        classified = evidence.classify_runtime_failure(
            args.failure_text, model_id=args.failure_model, variant=args.failure_variant
        )
        runtime_events.append(classified["event"])
        records.append(classified["record"])

    bundle = build_bundle(
        evidence,
        discovery=discovery,
        console_result=console_result,
        spend=spend,
        runtime_events=runtime_events,
        records=records,
        overage_fallback_state=overage_fallback_state,
        model_multipliers=_parse_multiplier_pairs(args.model_multiplier),
        pilot_args={
            "unknown_quota_policy": args.unknown_quota_policy,
            "unknown_quota_pilot_percent": args.unknown_quota_pilot_percent,
            "reserve_percent": args.reserve_percent,
            "lanes": args.pilot_lanes,
            "lane_cost_cap_usd": args.pilot_lane_cost_cap_usd,
            "lane_token_cap": args.pilot_lane_token_cap,
        },
        usage_api_result=usage_api_result,
        usage_api_credential_source=usage_api_credential_source,
        now_utc=args.now_utc,
    )
    rendered = json.dumps(bundle, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        target = pathlib.Path(args.output).expanduser()
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_suffix(target.suffix + ".tmp")
        temporary.write_text(rendered, encoding="utf-8")
        temporary.replace(target)
    else:
        sys.stdout.write(rendered)

    if console_result is not None or runtime_events:
        return 0
    if usage_api_result is not None and usage_api_result.get("ok"):
        return 0
    if discovery is not None and discovery.get("ok"):
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
