#!/usr/bin/env python3
"""Run one local OpenCode task and publish only its final text response."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import sys
import tempfile
from typing import Any


def text_from_events(raw: str) -> str:
    """Extract assistant text from OpenCode's JSONL event stream."""
    chunks: list[str] = []
    for line in raw.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if not isinstance(event, dict) or event.get("type") != "text":
            continue
        part = event.get("part") or {}
        text = part.get("text") if isinstance(part, dict) else None
        if isinstance(text, str) and text:
            chunks.append(text)
    return "".join(chunks).strip()


def error_from_events(raw: str) -> str | None:
    """Return a bounded diagnostic when OpenCode emits an explicit error event."""
    for line in raw.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if not isinstance(event, dict) or event.get("type") != "error":
            continue
        value = event.get("error") or event.get("message") or "OpenCode error event"
        if isinstance(value, (dict, list)):
            value = json.dumps(value, ensure_ascii=False, sort_keys=True)
        return str(value)[-1200:]
    return None


def atomic_write_text(path: pathlib.Path, text: str) -> None:
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
        temporary.replace(path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def load_prompt(args: argparse.Namespace) -> str:
    if bool(args.prompt) == bool(args.prompt_file):
        raise ValueError("provide exactly one of --prompt or --prompt-file")
    if args.prompt_file:
        path = pathlib.Path(args.prompt_file).expanduser().resolve()
        if not path.is_file():
            raise ValueError(f"prompt file does not exist: {path}")
        return path.read_text(encoding="utf-8")
    return str(args.prompt)


def build_argv(args: argparse.Namespace) -> list[str]:
    if not str(args.model).startswith("opencode-go/"):
        raise ValueError("OpenCode Go adapter requires an opencode-go/<model-id> model")
    argv = [
        "opencode",
        "run",
        "--model",
        str(args.model),
        "--format",
        "json",
        "--dir",
        str(pathlib.Path(args.cwd).expanduser().resolve()),
    ]
    if args.pure:
        argv.append("--pure")
    if args.variant:
        argv.extend(["--variant", str(args.variant)])
    if args.auto_approve:
        argv.append("--auto")
    return argv


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cwd", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--variant")
    parser.add_argument("--prompt")
    parser.add_argument("--prompt-file")
    parser.add_argument("--result-source", required=True)
    parser.add_argument("--pure", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--auto-approve", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        cwd = pathlib.Path(args.cwd).expanduser().resolve()
        if not cwd.is_dir():
            raise ValueError(f"workspace does not exist: {cwd}")
        prompt = load_prompt(args)
        command = build_argv(args)
        completed = subprocess.run(
            command,
            cwd=str(cwd),
            input=prompt,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        raw = completed.stdout or ""
        if raw:
            print(raw, end="" if raw.endswith("\n") else "\n")
        if completed.stderr:
            print(completed.stderr, file=sys.stderr, end="" if completed.stderr.endswith("\n") else "\n")
        if completed.returncode != 0:
            return completed.returncode
        event_error = error_from_events(raw)
        if event_error:
            print(f"OpenCode emitted an error event: {event_error}", file=sys.stderr)
            return 2
        final_text = text_from_events(raw)
        if not final_text:
            print("OpenCode returned no final text event", file=sys.stderr)
            return 2
        atomic_write_text(pathlib.Path(args.result_source).expanduser().resolve(), final_text)
        return 0
    except (OSError, ValueError) as exc:
        print(f"opencode guarded run: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
