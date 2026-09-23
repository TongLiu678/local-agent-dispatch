#!/usr/bin/env python3
"""Run a deterministic, provider-free baseline twice.

This is an M0 evidence tool, not a general task runner.  It accepts an argv
list, never invokes a shell, strips credential-like environment variables,
does not persist command output, and records only output digests and exit
facts.  A baseline is a gate only when both runs agree and the workspace was
not mutated by the command.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import signal
import subprocess
import sys
from typing import Any, Iterable, Sequence


SCHEMA_VERSION = 1
REPORT_TYPE = "local-agent-dispatch.m0_baseline"
DEFAULT_TIMEOUT_SECONDS = 600.0

_SECRET_ENV = re.compile(
    r"(?:API_KEY|APIKEY|TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE_KEY|AUTH)$",
    re.IGNORECASE,
)
_PROVIDER_EXECUTABLES = {
    "antigravity",
    "codex",
    "cursor",
    "cursor-agent",
    "opencode",
    "ssh",
    "scp",
    "rsync",
    "curl",
    "wget",
}
_SHELL_EXECUTABLES = {
    "bash",
    "cmd",
    "fish",
    "powershell",
    "pwsh",
    "sh",
    "zsh",
}
_PYTHON_EXECUTABLE = re.compile(r"^python(?:3(?:\.[0-9]+)?)?$", re.IGNORECASE)
_UNITTEST_TIMING = re.compile(rb"(?m)^(Ran [0-9]+ tests in )[0-9]+(?:\.[0-9]+)?s$")
_ISO_TIMESTAMP = re.compile(
    rb"20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    rb"(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})"
)
_TEMP_PATH = re.compile(
    rb"/(?:private/)?(?:var/folders/[^/]+/[^/]+/T|tmp)/tmp[A-Za-z0-9._-]+"
    rb"|/(?:[^/\s]+/)*LAD_TEST_TMP/tmp[A-Za-z0-9._-]+"
)
_PACKET_DIGEST = re.compile(rb"(\"packet_digest\"\s*:\s*\")[0-9a-f]{64}(\")")
_MONITOR_LOOP_TIMING = re.compile(
    rb"(\"(?:loop_elapsed_seconds|loop_remaining_seconds)\"\s*:\s*)"
    rb"[0-9]+(?:\.[0-9]+)?"
)


def _canonical(payload: Any) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _digest_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _stable_output(payload: bytes) -> bytes:
    """Normalize only known harness metadata, never arbitrary result text."""
    payload = _UNITTEST_TIMING.sub(rb"\1<elapsed>s", payload)
    payload = _ISO_TIMESTAMP.sub(b"<timestamp>", payload)
    payload = _TEMP_PATH.sub(b"<temp-path>", payload)
    payload = _PACKET_DIGEST.sub(rb"\1<packet-digest>\2", payload)
    return _MONITOR_LOOP_TIMING.sub(rb"\1<runtime>", payload)


def _git(repo: pathlib.Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout.strip()


def _safe_relative(value: str) -> str:
    path = pathlib.PurePosixPath(value.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ValueError(f"unsafe repository path: {value!r}")
    return path.as_posix()


def _status_rows(repo: pathlib.Path) -> tuple[tuple[str, str], ...]:
    raw = subprocess.run(
        ["git", "status", "--porcelain", "-z"],
        cwd=repo,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout
    rows: list[tuple[str, str]] = []
    parts = raw.split(b"\0")
    index = 0
    while index < len(parts):
        entry = parts[index]
        index += 1
        if not entry:
            continue
        code = entry[:2].decode("ascii", errors="replace")
        path = entry[3:].decode("utf-8", errors="surrogateescape")
        if code[0] in {"R", "C"} and index < len(parts):
            path = parts[index].decode("utf-8", errors="surrogateescape")
            index += 1
        rows.append((_safe_relative(path), code))
    return tuple(sorted(rows))


def _source_snapshot(repo: pathlib.Path) -> dict[str, Any]:
    rows = _status_rows(repo)
    return {
        "head": _git(repo, "rev-parse", "HEAD"),
        "working_tree_dirty": bool(rows),
        "status": [{"path": path, "code": code} for path, code in rows],
    }


def _fixture_snapshot(repo: pathlib.Path, paths: Iterable[str]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for raw in sorted(set(paths)):
        relative = _safe_relative(raw)
        path = repo / relative
        resolved = path.resolve()
        if repo not in resolved.parents and resolved != repo:
            raise ValueError(f"fixture escapes repository: {raw!r}")
        if not path.is_file():
            raise ValueError(f"fixture is not a regular file: {raw!r}")
        data = path.read_bytes()
        result.append(
            {"path": relative, "bytes": len(data), "sha256": _digest_bytes(data)}
        )
    return result


def _argv_name(argv: Sequence[str]) -> str:
    if not argv or any(not isinstance(item, str) or not item for item in argv):
        raise ValueError("command must be a non-empty argv list of strings")
    if any("\x00" in item for item in argv):
        raise ValueError("command contains NUL")
    return pathlib.Path(argv[0]).name.lower()


def validate_command(argv: Sequence[str]) -> tuple[str, ...]:
    """Validate the bounded command contract before any child is spawned."""
    normalized = tuple(argv)
    name = _argv_name(normalized)
    if name in _PROVIDER_EXECUTABLES:
        raise ValueError(f"provider/network executable is not allowed: {name}")
    if name in _SHELL_EXECUTABLES:
        raise ValueError(f"shell executable is not allowed: {name}")
    if not _PYTHON_EXECUTABLE.fullmatch(name):
        raise ValueError(
            "M0 baseline command must use a Python interpreter; use a separate "
            f"bounded harness for {name!r}"
        )
    return normalized


def _clean_environment() -> dict[str, str]:
    env: dict[str, str] = {}
    for key, value in os.environ.items():
        upper = key.upper()
        if _SECRET_ENV.search(upper) or upper.endswith(("_KEY", "_TOKEN", "_SECRET")):
            continue
        env[key] = value
    env.update(
        {
            "CI": "1",
            "NO_COLOR": "1",
            "PYTHONHASHSEED": "0",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )
    return env


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    if os.name == "nt":
        process.kill()
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def _run_once(
    repo: pathlib.Path,
    argv: Sequence[str],
    timeout_seconds: float,
) -> dict[str, Any]:
    process = subprocess.Popen(
        list(argv),
        cwd=repo,
        env=_clean_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=os.name != "nt",
    )
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_process_group(process)
        stdout, stderr = process.communicate()
    stable_stdout = _stable_output(stdout)
    stable_stderr = _stable_output(stderr)
    return {
        "returncode": None if timed_out else process.returncode,
        "timed_out": timed_out,
        "stdout_bytes": len(stable_stdout),
        "stderr_bytes": len(stable_stderr),
        "stdout_sha256": _digest_bytes(stable_stdout),
        "stderr_sha256": _digest_bytes(stable_stderr),
    }


def build_report(
    repo: pathlib.Path | str,
    command: Sequence[str],
    *,
    repeats: int = 2,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    fixture_paths: Iterable[str] = (),
    require_clean: bool = False,
) -> dict[str, Any]:
    """Run a bounded command and return a deterministic evidence report."""
    root = pathlib.Path(repo).expanduser().resolve()
    git_root = pathlib.Path(_git(root, "rev-parse", "--show-toplevel")).resolve()
    if git_root != root:
        raise ValueError("repo must be the canonical Git root")
    if repeats != 2:
        raise ValueError("M0 baseline requires exactly two repetitions")
    if timeout_seconds <= 0 or timeout_seconds > 3600:
        raise ValueError("timeout_seconds must be in (0, 3600]")
    argv = validate_command(command)
    source = _source_snapshot(root)
    fixtures = _fixture_snapshot(root, fixture_paths)
    runs: list[dict[str, Any]] = []
    mutations: list[bool] = []
    for _ in range(repeats):
        before = _status_rows(root)
        runs.append(_run_once(root, argv, timeout_seconds))
        after = _status_rows(root)
        mutations.append(before != after)
    passed = all(run["returncode"] == 0 and not run["timed_out"] for run in runs)
    byte_stable = runs[0] == runs[1]
    workspace_mutated = any(mutations)
    reasons: list[str] = []
    if not passed:
        reasons.append("command_failed_or_timed_out")
    if not byte_stable:
        reasons.append("repeated_outputs_differ")
    if workspace_mutated:
        reasons.append("command_mutated_workspace")
    if require_clean and source["working_tree_dirty"]:
        reasons.append("workspace_was_dirty")
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "report_type": REPORT_TYPE,
        "evidence_ceiling": "provider_free_replay_only",
        "provider_execution": False,
        "network_execution": False,
        "command": list(argv),
        "timeout_seconds": timeout_seconds,
        "environment_policy": {
            "pythonhashseed": "0",
            "bytecode_disabled": True,
            "credential_like_environment_removed": True,
            "shell": False,
        },
        "output_normalization": [
            "unittest_duration_line",
            "iso_timestamp",
            "temporary_path",
            "packet_digest_field",
            "monitor_loop_timing",
        ],
        "source": source,
        "fixtures": fixtures,
        "runs": runs,
        "byte_stable": byte_stable,
        "workspace_mutated": workspace_mutated,
        "gate": "pass" if passed and byte_stable and not reasons else "blocked",
        "blocking_reasons": reasons,
    }
    report["report_sha256"] = _digest_bytes(_canonical(report))
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=".")
    parser.add_argument(
        "--command-json",
        required=True,
        help="JSON argv array; shell strings and provider/network commands are rejected",
    )
    parser.add_argument("--fixture", action="append", default=[])
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--require-clean", action="store_true")
    parser.add_argument("--output", default="-")
    args = parser.parse_args(argv)
    try:
        command = json.loads(args.command_json)
        report = build_report(
            args.repo,
            command,
            timeout_seconds=args.timeout,
            fixture_paths=args.fixture,
            require_clean=args.require_clean,
        )
    except (OSError, subprocess.CalledProcessError, TypeError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    text = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output == "-":
        print(text, end="")
    else:
        output = pathlib.Path(args.output).expanduser()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
    return 0 if report["gate"] == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
