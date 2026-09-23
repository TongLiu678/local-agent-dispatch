#!/usr/bin/env python3
"""Aggregate OpenCode historical session usage across explicit runtime roots.

This command is deliberately not a quota probe.  It runs only the local
``db path`` and ``stats`` commands in each operator-supplied XDG context.  It
does not read auth files, send prompts, call a provider, or infer remaining Go
allowance.  Explicit roots are required because OpenCode stores history in a
local SQLite database selected by ``XDG_DATA_HOME``; there is no global account
history index for the CLI to discover automatically.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
import pathlib
import shutil
import sys
from typing import Any, Iterable, Mapping


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
_SPEC = importlib.util.spec_from_file_location(
    "opencode_go_snapshot", SCRIPT_DIR / "opencode_go_snapshot.py"
)
assert _SPEC and _SPEC.loader
_SNAPSHOT = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_SNAPSHOT)

SCHEMA_VERSION = 1
PROVIDER_ID = "opencode-go"


def _env_for_runtime(root: pathlib.Path) -> dict[str, str]:
    root = root.expanduser().resolve()
    return {
        "HOME": str(root / "home"),
        "XDG_CONFIG_HOME": str(root / "config"),
        "XDG_DATA_HOME": str(root / "data"),
        "XDG_STATE_HOME": str(root / "state"),
        "XDG_CACHE_HOME": str(root / "cache"),
        "TMPDIR": str(root / "tmp"),
    }


def _db_path_hash(raw: str) -> str | None:
    value = raw.strip()
    if not value or "\n" in value or "\r" in value:
        return None
    return hashlib.sha256(value.encode("utf-8", "surrogateescape")).hexdigest()


def _numeric_add(target: dict[str, float | int], source: Mapping[str, Any]) -> None:
    for key, value in source.items():
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            continue
        target[key] = target.get(key, 0) + value


def _aggregate_models(rows: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for row in rows:
        model_id = row.get("model_id")
        if not isinstance(model_id, str) or not model_id:
            continue
        current = merged.setdefault(model_id, {"model_id": model_id})
        _numeric_add(current, row)
    return [merged[key] for key in sorted(merged)]


def _runtime_label(root: pathlib.Path, index: int) -> str:
    # Labels are for human correlation only; do not emit the private path.
    name = root.name.strip()
    return name or f"runtime-{index:02d}"


def collect_history(
    opencode: str,
    runtime_roots: Iterable[pathlib.Path | str | None],
    *,
    include_current: bool = False,
    stats_days: int = 30,
    stats_models: int | None = None,
    timeout: float = 20.0,
    project: str | None = None,
    labels: Iterable[str] = (),
) -> dict[str, Any]:
    roots = list(runtime_roots)
    explicit_roots = list(roots)
    if include_current:
        roots = [None, *explicit_roots]
    elif not roots:
        roots = [None]
    label_values = list(labels)
    if label_values and len(label_values) != len(explicit_roots):
        raise ValueError("--label must be supplied once per --runtime-root")
    if include_current and label_values:
        label_values = ["current-environment", *label_values]

    contexts: list[dict[str, Any]] = []
    seen_db: dict[str, str] = {}
    unique_stats: list[dict[str, Any]] = []
    for index, raw_root in enumerate(roots, start=1):
        root = pathlib.Path(raw_root).expanduser().resolve() if raw_root else None
        env = _env_for_runtime(root) if root else None
        label = label_values[index - 1] if label_values else (
            _runtime_label(root, index) if root else "current-environment"
        )
        db_result = _SNAPSHOT.run_readonly(
            [opencode, "--pure", "db", "path"], timeout, env_overrides=env
        )
        # Do not pass ``--pure`` to stats: OpenCode v1.18.x uses an isolated
        # history context for that form and returns zero sessions. The
        # snapshot's probes are read-only and opencode_go_snapshot.run_readonly
        # disables update/model-fetch/prune side effects.
        stats_argv = [opencode, "stats", "--days", str(stats_days), "--models"]
        if stats_models is not None:
            stats_argv.append(str(stats_models))
        if project is not None:
            stats_argv.extend(["--project", project])
        stats_result = _SNAPSHOT.run_readonly(
            stats_argv, timeout, env_overrides=env
        )
        parsed = _SNAPSHOT.parse_local_stats(
            str(stats_result.get("stdout") or "")
        )
        if not stats_result.get("ok"):
            parsed["state"] = "unknown"
        db_output = str(db_result.get("stdout") or "").strip()
        db_hash = _db_path_hash(db_output)
        duplicate_of = seen_db.get(db_hash) if db_hash else None
        if db_hash and duplicate_of is None and stats_result.get("ok"):
            seen_db[db_hash] = label
            unique_stats.append(parsed)
        contexts.append(
            {
                "context_id": label,
                "runtime_pinned": root is not None,
                "db_state": "visible" if db_hash else "unknown",
                "db_path_sha256": db_hash,
                "duplicate_of_context": duplicate_of,
                "stats": parsed,
                "commands": {
                    "db_path": {
                        "ok": bool(db_result.get("ok")),
                        "returncode": db_result.get("returncode"),
                        "timed_out": bool(db_result.get("timed_out")),
                    },
                    "stats": _SNAPSHOT.public_command_status("stats", stats_result),
                },
            }
        )

    overview: dict[str, float | int] = {}
    totals: dict[str, float | int] = {}
    models: list[Mapping[str, Any]] = []
    for stats in unique_stats:
        _numeric_add(overview, stats.get("overview") or {})
        _numeric_add(totals, stats.get("cost_and_tokens") or {})
        models.extend(stats.get("opencode_go_models") or [])
    successful = sum(
        1 for context in contexts
        if context["commands"]["stats"]["ok"]
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "opencode_go_historical_usage",
        "provider_id": PROVIDER_ID,
        "observed_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "contexts": contexts,
        "aggregate": {
            "deduplicated_context_count": len(unique_stats),
            "successful_context_count": successful,
            "overview": overview,
            "cost_and_tokens": totals,
            "opencode_go_models": _aggregate_models(models),
        },
        "quota": {
            "state": "unknown",
            "five_hour": {"remaining_percent": None, "reset_at": None},
            "weekly": {"remaining_percent": None, "reset_at": None},
            "monthly": {"remaining_percent": None, "reset_at": None},
        },
        "deduplication": {
            "key": "sha256(db path reported by each explicit XDG context)",
            "same_db_is_counted_once": True,
            "cross_path_copies_may_still_be_duplicates": True,
        },
        "security": {
            "model_prompt_sent": False,
            "credential_file_read": False,
            "credential_values_emitted": False,
            "raw_db_path_emitted": False,
        },
        "note": (
            "Historical stats are local session spend evidence, not current Go "
            "balance. Only explicitly supplied runtime roots were inspected; "
            "missing roots and unlisted databases remain unknown."
        ),
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--opencode", default=shutil.which("opencode") or "opencode")
    parser.add_argument(
        "--runtime-root",
        action="append",
        default=[],
        help="Explicit OpenCode runtime root; repeat for each isolated history database.",
    )
    parser.add_argument(
        "--include-current",
        action="store_true",
        help="Also inspect the inherited current OpenCode runtime before explicit roots.",
    )
    parser.add_argument("--label", action="append", default=[])
    parser.add_argument("--project", default=None)
    parser.add_argument("--stats-days", type=int, default=30)
    parser.add_argument("--stats-models", type=int, default=None)
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    if args.stats_days <= 0 or args.timeout <= 0:
        parser.error("stats-days and timeout must be positive")
    if args.stats_models is not None and args.stats_models <= 0:
        parser.error("stats-models must be positive")
    if args.label and len(args.label) != len(args.runtime_root):
        parser.error("--label must be supplied once per --runtime-root")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(list(argv or sys.argv[1:]))
    result = collect_history(
        args.opencode,
        args.runtime_root,
        include_current=args.include_current,
        stats_days=args.stats_days,
        stats_models=args.stats_models,
        timeout=args.timeout,
        project=args.project,
        labels=args.label,
    )
    rendered = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        target = pathlib.Path(args.output).expanduser()
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_suffix(target.suffix + ".tmp")
        temporary.write_text(rendered, encoding="utf-8")
        temporary.replace(target)
    else:
        sys.stdout.write(rendered)
    return 0 if result["aggregate"]["successful_context_count"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
