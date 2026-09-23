#!/usr/bin/env python3
"""Read Codex account rate limits and token usage without sending a model prompt."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pathlib
import select
import shutil
import subprocess
import sys
import time
from typing import Any


def utc_iso(timestamp: int | None) -> str | None:
    if timestamp is None:
        return None
    return dt.datetime.fromtimestamp(timestamp, tz=dt.timezone.utc).isoformat()


def send_message(proc: subprocess.Popen[bytes], payload: dict[str, Any]) -> None:
    if proc.stdin is None:
        raise RuntimeError("codex app-server stdin is unavailable")
    proc.stdin.write((json.dumps(payload, separators=(",", ":")) + "\n").encode())
    proc.stdin.flush()


def read_responses(
    proc: subprocess.Popen[bytes], expected_ids: set[int], timeout: float
) -> tuple[dict[int, dict[str, Any]], list[str]]:
    if proc.stdout is None:
        raise RuntimeError("codex app-server stdout is unavailable")
    deadline = time.monotonic() + timeout
    responses: dict[int, dict[str, Any]] = {}
    diagnostics: list[str] = []
    buffer = b""
    while expected_ids - responses.keys() and time.monotonic() < deadline:
        wait = max(0.05, min(0.5, deadline - time.monotonic()))
        readable, _, _ = select.select([proc.stdout], [], [], wait)
        if not readable:
            if proc.poll() is not None:
                break
            continue
        chunk = os.read(proc.stdout.fileno(), 65536)
        if not chunk:
            break
        buffer += chunk
        while b"\n" in buffer:
            raw, buffer = buffer.split(b"\n", 1)
            if not raw.strip():
                continue
            try:
                message = json.loads(raw)
            except json.JSONDecodeError:
                diagnostics.append(raw.decode("utf-8", errors="replace")[-1000:])
                continue
            request_id = message.get("id")
            if isinstance(request_id, int) and request_id in expected_ids:
                responses[request_id] = message
    return responses, diagnostics


def request_snapshot(codex: str, timeout: float) -> dict[str, Any]:
    proc = subprocess.Popen(
        [codex, "app-server", "--stdio"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    diagnostics: list[str] = []
    try:
        send_message(
            proc,
            {
                "id": 1,
                "method": "initialize",
                "params": {
                    "clientInfo": {
                        "name": "local-agent-dispatch",
                        "title": "Local Agent Dispatch",
                        "version": "1.0",
                    },
                    "capabilities": {"experimentalApi": True},
                },
            },
        )
        initialized, init_diagnostics = read_responses(proc, {1}, timeout)
        diagnostics.extend(init_diagnostics)
        if 1 not in initialized:
            raise RuntimeError("codex app-server initialize timed out")
        if initialized[1].get("error"):
            raise RuntimeError(f"codex app-server initialize failed: {initialized[1]['error']}")

        send_message(proc, {"method": "initialized"})
        send_message(proc, {"id": 2, "method": "account/rateLimits/read"})
        send_message(proc, {"id": 3, "method": "account/usage/read"})
        replies, reply_diagnostics = read_responses(proc, {2, 3}, timeout)
        diagnostics.extend(reply_diagnostics)
        if 2 not in replies:
            raise RuntimeError("account/rateLimits/read timed out")

        rate_reply = replies[2]
        usage_reply = replies.get(3, {})
        if rate_reply.get("error"):
            raise RuntimeError(f"account/rateLimits/read failed: {rate_reply['error']}")
        return {
            "rate_limits": rate_reply.get("result"),
            "token_usage": usage_reply.get("result"),
            "token_usage_error": usage_reply.get("error"),
            "diagnostics": diagnostics,
        }
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)


def normalize_window(window: dict[str, Any] | None) -> dict[str, Any] | None:
    if not window:
        return None
    used = window.get("usedPercent")
    return {
        "used_percent": used,
        "remaining_percent": max(0, 100 - used) if isinstance(used, int) else None,
        "window_minutes": window.get("windowDurationMins"),
        "resets_at": window.get("resetsAt"),
        "resets_at_utc": utc_iso(window.get("resetsAt")),
    }


def normalize_limit(snapshot: dict[str, Any]) -> dict[str, Any]:
    primary = normalize_window(snapshot.get("primary"))
    secondary = normalize_window(snapshot.get("secondary"))
    remaining = [
        window["remaining_percent"]
        for window in (primary, secondary)
        if window and window.get("remaining_percent") is not None
    ]
    effective = min(remaining) if remaining else None
    reached = snapshot.get("rateLimitReachedType")
    spend_reached = snapshot.get("spendControlReached") is True
    if reached or spend_reached or effective == 0:
        health = "blocked"
    elif effective is None:
        health = "unknown"
    elif effective < 10:
        health = "conserve"
    elif effective < 20:
        health = "degraded"
    elif effective < 40:
        health = "balanced"
    else:
        health = "ready"
    return {
        "limit_id": snapshot.get("limitId"),
        "limit_name": snapshot.get("limitName"),
        "plan_type": snapshot.get("planType"),
        "health": health,
        "effective_remaining_percent": effective,
        "primary": primary,
        "secondary": secondary,
        "rate_limit_reached_type": reached,
        "spend_control_reached": snapshot.get("spendControlReached"),
        "individual_limit": snapshot.get("individualLimit"),
        "credits": snapshot.get("credits"),
    }


def scheduler_pool_id(limit_id: str, snapshot: dict[str, Any]) -> str:
    limit_name = str(snapshot.get("limit_name") or "").lower()
    if limit_id == "codex_bengalfox" or "spark" in limit_name:
        return "codex.spark"
    if limit_id == "codex":
        return "codex.luna"
    return f"codex.{limit_id}"


def normalize(
    payload: dict[str, Any], codex: str, include_full_token_history: bool
) -> dict[str, Any]:
    rate_limits = payload.get("rate_limits") or {}
    by_id = rate_limits.get("rateLimitsByLimitId") or {}
    normalized_by_id = {
        str(limit_id): normalize_limit(snapshot)
        for limit_id, snapshot in by_id.items()
        if isinstance(snapshot, dict)
    }
    legacy = rate_limits.get("rateLimits")
    if not normalized_by_id and isinstance(legacy, dict):
        normalized_by_id[legacy.get("limitId") or "codex"] = normalize_limit(legacy)

    scheduler_pools = {
        scheduler_pool_id(limit_id, snapshot): {
            "pool_id": scheduler_pool_id(limit_id, snapshot),
            **snapshot,
        }
        for limit_id, snapshot in normalized_by_id.items()
    }
    token_usage = payload.get("token_usage") or {}
    daily = token_usage.get("dailyUsageBuckets") or []
    compact_token_usage = {
        "summary": token_usage.get("summary"),
        "recent_daily_usage": daily[-14:],
    }
    if include_full_token_history:
        compact_token_usage["daily_usage_buckets"] = daily

    return {
        "ok": bool(normalized_by_id),
        "source": "codex app-server account/rateLimits/read + account/usage/read",
        "codex": codex,
        "fetched_at_utc": dt.datetime.now(tz=dt.timezone.utc).isoformat(),
        "pools": scheduler_pools,
        "limits_by_id": normalized_by_id,
        "rate_limit_reset_credits": rate_limits.get("rateLimitResetCredits"),
        "token_usage": compact_token_usage,
        "token_usage_error": payload.get("token_usage_error"),
        "diagnostics": payload.get("diagnostics") or [],
        "note": (
            "Rate-limit windows are scheduling capacity. Token activity is historical "
            "usage and must not be treated as remaining quota."
        ),
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codex", default=shutil.which("codex") or "codex")
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--full-token-history", action="store_true")
    parser.add_argument("--output")
    return parser.parse_args(argv)


def emit_result(result: dict[str, Any], output: str | None) -> None:
    rendered = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if not output:
        print(rendered, end="")
        return
    target = pathlib.Path(output).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(target.suffix + ".tmp")
    temporary.write_text(rendered, encoding="utf-8")
    temporary.replace(target)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        payload = request_snapshot(args.codex, args.timeout)
        result = normalize(payload, args.codex, args.full_token_history)
    except Exception as exc:
        result = {
            "ok": False,
            "source": "codex app-server",
            "codex": args.codex,
            "error": str(exc),
        }
    emit_result(result, args.output)
    return 0 if result.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
