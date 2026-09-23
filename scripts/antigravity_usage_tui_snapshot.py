#!/usr/bin/env python3
"""Capture Antigravity CLI's interactive /usage model-quota panel."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import pty
import re
import select
import signal
import struct
import subprocess
import termios
import time
from pathlib import Path


ANSI_RE = re.compile(
    r"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))"
)


def strip_ansi(text: str) -> str:
    text = ANSI_RE.sub("", text).replace("\r", "\n")
    # Remove the common spinner/backspace noise without trying to emulate the
    # entire terminal. Quota labels and numbers remain intact.
    text = text.replace("\b", "")
    text = re.sub(r"[ \t]+", " ", text)
    return re.sub(r"\n{3,}", "\n\n", text)


def read_available(fd: int, timeout: float) -> str:
    end = time.monotonic() + timeout
    chunks: list[bytes] = []
    while time.monotonic() < end:
        wait = max(0.05, min(0.25, end - time.monotonic()))
        readable, _, _ = select.select([fd], [], [], wait)
        if not readable:
            continue
        try:
            data = os.read(fd, 16384)
        except OSError:
            break
        if not data:
            break
        chunks.append(data)
    return b"".join(chunks).decode("utf-8", errors="ignore")


def read_until(fd: int, timeout: float, markers: tuple[str, ...]) -> str:
    end = time.monotonic() + timeout
    chunks: list[bytes] = []
    lowered = tuple(marker.lower() for marker in markers)
    while time.monotonic() < end:
        chunk = read_available(fd, min(0.6, max(0.05, end - time.monotonic())))
        if chunk:
            chunks.append(chunk.encode("utf-8", errors="ignore"))
            clean = strip_ansi(b"".join(chunks).decode("utf-8", errors="ignore")).lower()
            if any(marker in clean for marker in lowered):
                break
    return b"".join(chunks).decode("utf-8", errors="ignore")


def parse_limit(block: str, label: str) -> tuple[float | None, str | None]:
    match = re.search(
        rf"{label}.{{0,500}}?([0-9]+(?:\.[0-9]+)?)%.{{0,200}}?"
        rf"(Quota available|Quota unavailable|Quota exhausted|Limit reached|"
        rf"[0-9]+(?:\.[0-9]+)?%\s+remaining(?:\s*[·|-]\s*Refreshes in\s*[^\n]+)?|"
        rf"Refreshes in\s*[^\n]+)",
        block,
        re.I | re.S,
    )
    if not match:
        return None, None
    status = match.group(2).strip(" |") or None
    return float(match.group(1)), status


def parse_group(clean: str, heading: str, next_heading: str | None) -> dict:
    starts = [match.start() for match in re.finditer(re.escape(heading), clean, re.I)]
    if not starts:
        return {
            "weekly_percent_displayed": None,
            "weekly_status": None,
            "five_hour_percent_displayed": None,
            "five_hour_status": None,
        }
    block = clean[starts[-1] :]
    if next_heading:
        boundary = re.search(re.escape(next_heading), block[len(heading) :], re.I)
        if boundary:
            block = block[: len(heading) + boundary.start()]
    weekly, weekly_status = parse_limit(block, "Weekly Limit")
    five_hour, five_hour_status = parse_limit(block, "Five Hour Limit")
    return {
        "weekly_percent_displayed": weekly,
        "weekly_status": weekly_status,
        "five_hour_percent_displayed": five_hour,
        "five_hour_status": five_hour_status,
    }


def enrich_group(group: dict) -> dict:
    """Add the conservative scheduler view for a shared quota group."""
    values = [
        value
        for value in (
            group.get("weekly_percent_displayed"),
            group.get("five_hour_percent_displayed"),
        )
        if value is not None
    ]
    effective = min(values) if len(values) == 2 else None
    statuses = [
        str(status).lower()
        for status in (group.get("weekly_status"), group.get("five_hour_status"))
        if status
    ]
    if effective is None:
        health = "unknown"
    elif effective <= 0 or any(
        marker in status for status in statuses for marker in ("exhaust", "unavailable", "limit reached")
    ):
        health = "blocked"
    elif len(statuses) == 2 and all(
        "available" in status or "remaining" in status for status in statuses
    ):
        health = "ready"
    else:
        health = "degraded"
    def reset_minutes(status: str | None) -> int | None:
        if not status:
            return None
        match = re.search(
            r"Refreshes in\s*(?:(\d+)h)?\s*(?:(\d+)m)?",
            status,
            re.I,
        )
        if not match or not any(match.groups()):
            return None
        return int(match.group(1) or 0) * 60 + int(match.group(2) or 0)

    return {
        **group,
        "effective_percent_displayed": effective,
        "effective_basis": "minimum of weekly and five-hour displayed percentages",
        "weekly_refresh_minutes": reset_minutes(group.get("weekly_status")),
        "five_hour_refresh_minutes": reset_minutes(group.get("five_hour_status")),
        "health": health,
    }


def parse_usage(raw: str) -> dict:
    clean = strip_ansi(raw)
    redacted = re.sub(
        r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}",
        "<redacted-account>",
        clean,
        flags=re.I,
    )
    gemini = enrich_group(parse_group(clean, "GEMINI MODELS", "CLAUDE AND GPT MODELS"))
    other = enrich_group(parse_group(clean, "CLAUDE AND GPT MODELS", None))
    percentages = [
        gemini["weekly_percent_displayed"],
        gemini["five_hour_percent_displayed"],
        other["weekly_percent_displayed"],
        other["five_hour_percent_displayed"],
    ]
    statuses = [
        gemini["weekly_status"],
        gemini["five_hour_status"],
        other["weekly_status"],
        other["five_hour_status"],
    ]
    status_bar = re.findall(r"AI:\s*([^\n]+)", clean)
    any_available = any(
        status and ("available" in status.lower() or "remaining" in status.lower())
        for status in statuses
    )
    any_exhausted = any(
        status and any(word in status.lower() for word in ("exhaust", "unavailable", "limit reached"))
        for status in statuses
    )
    if any_available:
        availability: bool | None = True
    elif any_exhausted:
        availability = False
    else:
        availability = None
    panel_found = "Models & Quota" in clean
    result = {
        "ok": panel_found and any(value is not None for value in percentages),
        "source": "/usage",
        "model_quota_available": availability,
        "pools": {
            "antigravity.gemini": {
                "ui_group": "GEMINI MODELS",
                "schedulable_models": [
                    "gemini-3.6-flash-high",
                    "gemini-3.6-flash-medium",
                    "gemini-3.6-flash-low",
                    "gemini-3.1-pro-high",
                    "gemini-3.1-pro-low",
                ],
                **gemini,
            },
            "antigravity.claude_gpt": {
                "ui_group": "CLAUDE AND GPT MODELS",
                "schedulable_models": [
                    "claude-opus-4-6-thinking",
                    "claude-sonnet-4-6",
                    "gpt-oss-120b-medium",
                ],
                "note": "All listed models are eligible and share this UI group's weekly and five-hour quota.",
                **other,
            },
        },
        "g1_credit_status_bar": status_bar[-1].strip() if status_bar else None,
        "note": (
            "g1_credit_status_bar is a separate wallet signal. Schedule each /usage "
            "group from its own weekly and five-hour limits."
        ),
        "raw_excerpt": redacted[-8000:],
    }
    return result


def capture(cwd: Path, timeout: float) -> dict:
    master, slave = pty.openpty()
    # A tall PTY keeps both quota groups visible instead of requiring fragile
    # page-down automation.
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 72, 132, 0, 0))
    env = os.environ.copy()
    env["TERM"] = "xterm-256color"
    proc = subprocess.Popen(
        ["antigravity"],
        cwd=str(cwd),
        stdin=slave,
        stdout=slave,
        stderr=slave,
        env=env,
        start_new_session=True,
    )
    os.close(slave)

    raw = ""
    ready = False
    attempts = 0
    deadline = time.monotonic() + timeout
    try:
        startup_budget = min(60.0, max(20.0, timeout - 15.0))
        startup = read_until(master, startup_budget, ("for shortcuts", "AI:"))
        raw += startup
        startup_clean = strip_ansi(startup)
        ready = "for shortcuts" in startup_clean or "AI:" in startup_clean

        if ready:
            for attempt in range(2):
                attempts += 1
                os.write(master, b"/usage\r")
                remaining = max(0.0, deadline - time.monotonic() - 2.0)
                if remaining <= 0:
                    break
                raw += read_until(
                    master,
                    min(12.0, remaining),
                    ("CLAUDE AND GPT MODELS", "Five Hour Limit"),
                )
                # Give the full-screen renderer a moment to finish drawing all
                # rows even after the first marker appears.
                raw += read_available(master, min(2.0, max(0.0, deadline - time.monotonic())))
                if parse_usage(raw)["ok"]:
                    break
                if attempt == 0:
                    os.write(master, b"\x1b")
                    raw += read_available(master, 0.8)

        try:
            os.write(master, b"\x1b")
            raw += read_available(master, 0.4)
            os.write(master, b"/exit\r")
            raw += read_available(master, 1.0)
        except OSError:
            pass
    finally:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
        try:
            os.close(master)
        except OSError:
            pass

    result = parse_usage(raw)
    result["cwd"] = str(cwd)
    result["tui_ready"] = ready
    result["command_attempts"] = attempts
    if not result["ok"]:
        clean = strip_ansi(raw)
        if not ready and ("Signing in" in clean or "not signed in" in clean):
            result["failure_reason"] = "authentication_not_ready_before_timeout"
        elif not ready:
            result["failure_reason"] = "tui_prompt_not_ready_before_timeout"
        elif "Models & Quota" not in clean:
            result["failure_reason"] = "usage_panel_not_rendered"
        else:
            result["failure_reason"] = "usage_panel_format_changed_or_limits_hidden"
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cwd", default=os.getcwd())
    parser.add_argument("--timeout", type=float, default=75.0)
    args = parser.parse_args(argv)
    cwd = Path(args.cwd).expanduser().resolve()
    try:
        result = capture(cwd, args.timeout)
    except Exception as exc:
        result = {"ok": False, "error": str(exc), "cwd": str(cwd), "source": "/usage"}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
