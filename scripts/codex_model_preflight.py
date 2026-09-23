#!/usr/bin/env python3
"""Validate a Codex model/effort pair against the live local model cache."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any


PRESETS: dict[str, tuple[str, str]] = {
    "luna-max": ("gpt-5.6-luna", "max"),
    "luna-deep": ("gpt-5.6-luna", "max"),
    "luna-ultra": ("gpt-5.6-luna", "ultra"),
    # Sol is an explicit task-local route.  It shares the Codex account
    # bucket with the other GPT-5.6 tiers, but must never silently normalize
    # to Luna or Spark when the caller selected it.
    "sol-max": ("gpt-5.6-sol", "max"),
    "spark-fast": ("gpt-5.3-codex-spark", "xhigh"),
}


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--preset", choices=sorted(PRESETS))
    source.add_argument("--model")
    parser.add_argument("--effort", help="Required with --model")
    parser.add_argument(
        "--cache",
        default=str(pathlib.Path.home() / ".codex" / "models_cache.json"),
    )
    return parser.parse_args(argv)


def load_models(path: pathlib.Path) -> dict[str, list[str]]:
    payload: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    result: dict[str, list[str]] = {}
    for item in payload.get("models", []):
        slug = item.get("slug")
        if not slug:
            continue
        result[str(slug)] = [
            str(level["effort"])
            for level in item.get("supported_reasoning_levels", [])
            if isinstance(level, dict) and level.get("effort")
        ]
    return result


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.preset:
        requested_model, requested_effort = PRESETS[args.preset]
    else:
        if not args.effort:
            raise SystemExit("--effort is required with --model")
        requested_model, requested_effort = args.model, args.effort

    cache_path = pathlib.Path(args.cache).expanduser()
    models = load_models(cache_path)
    supported = models.get(requested_model)
    if supported is None:
        print(
            json.dumps(
                {
                    "ok": False,
                    "requested_model": requested_model,
                    "requested_effort": requested_effort,
                    "error": "model_not_in_live_cache",
                    "cache": str(cache_path),
                },
                ensure_ascii=False,
            )
        )
        return 2

    resolved_effort = requested_effort
    normalized = False
    note = ""
    if requested_effort not in supported:
        if args.preset == "luna-ultra" and "max" in supported:
            resolved_effort = "max"
            normalized = True
            note = "Luna does not advertise ultra; normalized luna-ultra to Luna/max."
        else:
            print(
                json.dumps(
                    {
                        "ok": False,
                        "requested_model": requested_model,
                        "requested_effort": requested_effort,
                        "supported_efforts": supported,
                        "error": "effort_not_supported_by_model",
                        "cache": str(cache_path),
                    },
                    ensure_ascii=False,
                )
            )
            return 2

    print(
        json.dumps(
            {
                "ok": True,
                "requested_model": requested_model,
                "requested_effort": requested_effort,
                "model": requested_model,
                "effort": resolved_effort,
                "supported_efforts": supported,
                "normalized": normalized,
                "note": note,
                "cache": str(cache_path),
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
