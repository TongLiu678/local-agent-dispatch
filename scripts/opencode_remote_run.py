#!/usr/bin/env python3
"""Run one OpenCode Go task on a remote host through stdin.

This is the server-side execution boundary for an authenticated OpenCode
installation.  The task text is read only from stdin, never from argv; the
wrapper writes the final text to a confined remote artifact and returns only a
small hash/size summary.  It does not perform login, quota discovery, SSH, or
model installation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
from typing import Any


MODEL_RE = re.compile(r"opencode-go/[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
SAFE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
SCHEMA_VERSION = 1


def _confined(path_value: str, root: pathlib.Path, field: str) -> pathlib.Path:
    if not isinstance(path_value, str) or not path_value.strip():
        raise ValueError(f"{field} is required")
    root = root.expanduser().resolve(strict=False)
    path = pathlib.Path(path_value).expanduser()
    if not path.is_absolute():
        path = root / path
    path = path.resolve(strict=False)
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"{field} escapes cwd") from exc
    return path


def _server_path(path_value: str, field: str) -> pathlib.Path:
    """Validate a server-local absolute path without reading its contents."""
    if not isinstance(path_value, str) or not path_value.strip():
        raise ValueError(f"{field} is required")
    if any(char in path_value for char in "\0\r\n"):
        raise ValueError(f"{field} contains control characters")
    path = pathlib.Path(path_value).expanduser()
    if not path.is_absolute():
        raise ValueError(f"{field} must be absolute")
    return path.resolve(strict=False)


def _link_auth_data(cwd: pathlib.Path, auth_data_root: str | None) -> dict[str, Any]:
    """Expose only a symlink to server auth inside this lane's data root.

    OpenCode keeps mutable databases and locks below XDG_DATA_HOME.  Sharing
    that directory across lanes is unsafe, so the lane owns its data root and
    receives only a read-only auth-file link.  No credential bytes are read or
    copied by this helper.
    """
    if not auth_data_root:
        return {"state": "not_configured"}
    source_root = _server_path(auth_data_root, "auth_data_root")
    source = source_root / "opencode" / "auth.json"
    if not source.is_file():
        raise ValueError("server OpenCode auth.json is missing")
    lane_data = os.environ.get("XDG_DATA_HOME", "").strip()
    if not lane_data:
        raise ValueError("XDG_DATA_HOME is required when auth_data_root is configured")
    target_root = _server_path(lane_data, "XDG_DATA_HOME") / "opencode"
    target_root.mkdir(parents=True, exist_ok=True)
    target = target_root / "auth.json"
    if target.exists() or target.is_symlink():
        if not target.is_symlink() or target.resolve(strict=False) != source:
            raise ValueError("lane auth path already exists with a different target")
    else:
        target.symlink_to(source)
    return {"state": "linked", "target": "lane-local", "source": "server-local"}


def _atomic_write(path: pathlib.Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    temporary = pathlib.Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            if not text.endswith("\n"):
                handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _event_text(raw: str) -> str:
    chunks: list[str] = []
    for line in raw.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if not isinstance(event, dict) or event.get("type") != "text":
            continue
        part = event.get("part")
        # OpenCode 1.18 emits the final text as a top-level ``text`` field;
        # older releases wrapped it in ``part.text``.  Accept both wire
        # shapes so a successful run is not misreported as result_source_missing.
        value = part.get("text") if isinstance(part, dict) else event.get("text")
        if isinstance(value, str) and value:
            chunks.append(value)
    return "".join(chunks).strip()


def _event_error(raw: str) -> str | None:
    for line in raw.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if isinstance(event, dict) and event.get("type") == "error":
            return "OpenCode emitted an error event"
    return None


def _summary(status: str, result: pathlib.Path | None = None, *, returncode: int | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {"schema_version": SCHEMA_VERSION, "status": status}
    if returncode is not None:
        payload["returncode"] = int(returncode)
    if result is not None and result.is_file():
        data = result.read_bytes()
        payload.update({"result_bytes": len(data), "result_sha256": hashlib.sha256(data).hexdigest()})
    return payload


def build_argv(args: argparse.Namespace, cwd: pathlib.Path) -> list[str]:
    model = str(args.model)
    if not MODEL_RE.fullmatch(model):
        raise ValueError("model must be an exact opencode-go/<model-id>")
    binary = str(args.opencode_bin)
    if not binary or any(char in binary for char in "\0\r\n"):
        raise ValueError("opencode_bin is invalid")
    command = [binary, "run", "--model", model, "--format", "json", "--dir", str(cwd)]
    if args.pure:
        command.append("--pure")
    if args.variant:
        variant = str(args.variant)
        if not SAFE_ID_RE.fullmatch(variant):
            raise ValueError("variant is invalid")
        command.extend(["--variant", variant])
    if args.auto_approve:
        command.append("--auto")
    return command


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cwd", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--result-source", required=True)
    parser.add_argument("--opencode-bin", default="opencode")
    parser.add_argument("--auth-data-root")
    parser.add_argument("--variant")
    parser.add_argument("--pure", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--auto-approve", action="store_true")
    parser.add_argument("--timeout-seconds", type=int, default=3600)
    parser.add_argument("--max-prompt-bytes", type=int, default=8 * 1024 * 1024)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        cwd = pathlib.Path(args.cwd).expanduser().resolve(strict=False)
        if not cwd.is_dir():
            raise ValueError("cwd must be an existing directory")
        result = _confined(str(args.result_source), cwd, "result_source")
        auth_link = _link_auth_data(cwd, args.auth_data_root)
        if args.timeout_seconds < 1 or args.timeout_seconds > 24 * 3600:
            raise ValueError("timeout_seconds is outside 1..86400")
        if args.max_prompt_bytes < 1 or args.max_prompt_bytes > 64 * 1024 * 1024:
            raise ValueError("max_prompt_bytes is outside 1..67108864")
        prompt_bytes = sys.stdin.buffer.read(args.max_prompt_bytes + 1)
        if len(prompt_bytes) > args.max_prompt_bytes:
            raise ValueError("stdin task exceeds max_prompt_bytes")
        prompt = prompt_bytes.decode("utf-8")
        command = build_argv(args, cwd)
        completed = subprocess.run(
            command,
            cwd=str(cwd),
            input=prompt,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=args.timeout_seconds,
        )
        if completed.returncode != 0:
            print(json.dumps(_summary("failed", returncode=completed.returncode), sort_keys=True))
            return int(completed.returncode or 2)
        if _event_error(completed.stdout or ""):
            print(json.dumps(_summary("failed", returncode=2), sort_keys=True))
            return 2
        final_text = _event_text(completed.stdout or "")
        if not final_text:
            print(json.dumps(_summary("failed", returncode=2), sort_keys=True))
            return 2
        _atomic_write(result, final_text)
        summary = _summary("completed", result)
        summary["auth_link"] = auth_link
        print(json.dumps(summary, sort_keys=True))
        return 0
    except subprocess.TimeoutExpired:
        print(json.dumps(_summary("timed_out", returncode=124), sort_keys=True))
        return 124
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        print(f"opencode remote run: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
