#!/usr/bin/env python3
"""Observe dispatched workers for a few minutes and emit feedback for replanning."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pathlib
import re
import shlex
import subprocess
import sys
import time
from typing import Any


QUOTA_RE = re.compile(
    r"usage limit|rate.?limit|quota (?:exhausted|unavailable)|spend limit",
    re.I,
)
CAPABILITY_RE = re.compile(
    r"cannot use this model|unsupported model|not entitled|model (?:is )?not available",
    re.I,
)
LOCATION_RE = re.compile(
    r"user\s+location\s+is\s+not\s+supported|location\s+is\s+not\s+supported|"
    r"(?:unsupported|unavailable)\s+(?:country|region|location)|"
    r"(?:country|region|location)\s+(?:is\s+)?not\s+supported|"
    r"not\s+available\s+in\s+(?:your\s+)?location|geographic(?:al)?\s+(?:restriction|block)",
    re.I,
)
AUTH_RE = re.compile(r"unauthorized|forbidden|authentication|login required|invalid_grant", re.I)
NETWORK_RE = re.compile(
    r"tls|connection (?:failed|reset)|network socket|timed? out|dns|econn",
    re.I,
)
CONTROLLER_TIMEOUT_RE = re.compile(
    r"(?:continuity|sqlite) controller[^\n]*(?:timed? out|timeout)",
    re.I,
)
RESOURCE_RE = re.compile(
    r"local launch blocked|resource admission|free_bytes_below_floor|free_percent_below_floor|filesystem_evidence_unknown",
    re.I,
)

REMOTE_OBSERVER = r'''
worker_pid=$1
pid_path=$2
log_path=$3
shift 3
if [ -n "$pid_path" ] && [ -f "$pid_path" ]; then
  read -r worker_pid < "$pid_path" || worker_pid=
fi
case "$worker_pid" in
  ''|*[!0-9]*) worker_pid= ;;
esac
printf 'PID_VALUE|%s\n' "$worker_pid"
if [ -z "$worker_pid" ]; then
  printf 'PID|unknown\n'
elif kill -0 "$worker_pid" 2>/dev/null; then
  printf 'PID|1\n'
else
  printf 'PID|0\n'
fi
file_index=-1
for observed_path in "$log_path" "$@"; do
  if [ -n "$observed_path" ] && [ -f "$observed_path" ]; then
    file_size=$(wc -c < "$observed_path" 2>/dev/null | tr -d ' ')
    file_mtime=$(stat -c %Y "$observed_path" 2>/dev/null || stat -f %m "$observed_path" 2>/dev/null || printf 0)
    printf 'FILE|%s|1|%s|%s\n' "$file_index" "${file_size:-0}" "${file_mtime:-0}"
  else
    printf 'FILE|%s|0|0|0\n' "$file_index"
  fi
  file_index=$((file_index + 1))
done
printf 'TAIL_BEGIN\n'
if [ -n "$log_path" ] && [ -f "$log_path" ]; then
  tail -c 65536 "$log_path" 2>/dev/null || true
fi
'''


def now_utc() -> dt.datetime:
    return dt.datetime.now(tz=dt.timezone.utc)


def iso_now() -> str:
    return now_utc().isoformat()


def load_json(path: str) -> dict[str, Any]:
    payload = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("state must be a JSON object")
    return payload


def atomic_write(path: str, payload: dict[str, Any]) -> None:
    target = pathlib.Path(path).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(target.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    temporary.replace(target)


def resolve_path(value: str, root: pathlib.Path) -> pathlib.Path:
    """Resolve an observation path strictly below the declared project root."""
    root_resolved = root.expanduser().resolve(strict=False)
    path = pathlib.Path(value).expanduser()
    candidate = path if path.is_absolute() else root_resolved / path
    resolved = candidate.resolve(strict=False)
    try:
        resolved.relative_to(root_resolved)
    except ValueError as exc:
        raise ValueError("monitor path escapes project root") from exc
    return resolved


def remote_path(value: str, root: str) -> str:
    """Resolve a remote observation path below the inventory project root."""
    root_path = pathlib.PurePosixPath(str(root))
    if not root_path.is_absolute() or str(root_path) == "/":
        raise ValueError("remote project root must be a non-root absolute path")
    raw = pathlib.PurePosixPath(str(value))
    candidate = raw if raw.is_absolute() else root_path / raw
    normalized = pathlib.PurePosixPath(os.path.normpath(str(candidate)))
    try:
        normalized.relative_to(root_path)
    except ValueError as exc:
        raise ValueError("remote monitor path escapes project root") from exc
    return str(normalized)


def _path_security_observation(worker: dict[str, Any], message: str) -> dict[str, Any]:
    """Return a redacted terminal observation without touching rejected paths."""
    return {
        "worker_id": worker.get("worker_id") or worker.get("job_id"),
        "job_id": worker.get("job_id"),
        "pool_id": worker.get("pool_id"),
        "provider": worker.get("provider"),
        "model": worker.get("model"),
        "variant": worker.get("variant"),
        "attempt_id": worker.get("attempt_id"),
        "execution_host": worker.get("execution_host") or "local_mac",
        "workload_host": worker.get("workload_host") or worker.get("execution_host") or "local_mac",
        "pid_alive": None,
        "status": "failed",
        "progressed": False,
        "error_class": "path",
        "error_origin": "monitor_security",
        "error_message": message,
        "artifact_ready": False,
        "completion_verified": False,
        "completion_reason": "monitor_path_rejected",
        "required_artifacts": [],
        "progress_files": [],
        "fingerprint": {},
        "observed_at_utc": iso_now(),
    }


def ssh_argv(host: dict[str, Any], timeout: float) -> list[str]:
    hostname = str(host.get("hostname") or "")
    if not hostname or any(char in hostname for char in "\n\r\0"):
        raise ValueError("remote worker host requires a safe hostname")
    user = str(host.get("user") or "")
    target = f"{user}@{hostname}" if user else hostname
    argv = [
        "ssh", "-o", "BatchMode=yes", "-o", f"ConnectTimeout={max(1, int(timeout))}",
        "-o", "ServerAliveInterval=3", "-o", "ServerAliveCountMax=1",
    ]
    if host.get("port"):
        argv.extend(["-p", str(int(host["port"]))])
    if host.get("identity_file"):
        argv.extend(["-i", str(pathlib.Path(str(host["identity_file"])).expanduser())])
    argv.append(target)
    return argv


def pid_alive(pid: Any) -> bool | None:
    if pid in (None, ""):
        return None
    try:
        os.kill(int(pid), 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        # Windows' ``os.kill(pid, 0)`` may report WinError 87 even for a PID
        # observed in a controller breadcrumb.  That is neither proof of
        # liveness nor proof of exit, so preserve an explicit unknown instead
        # of tearing down the whole observation pass.
        return None
    except (TypeError, ValueError):
        return None
    return True


def file_fact(path: pathlib.Path) -> dict[str, Any]:
    try:
        stat = path.stat()
    except FileNotFoundError:
        return {"path": str(path), "exists": False, "size": 0, "mtime": None}
    return {
        "path": str(path),
        "exists": True,
        "size": stat.st_size,
        "mtime": stat.st_mtime,
    }


def completion_evidence(worker: dict[str, Any]) -> tuple[bool, str]:
    """Return whether an upstream controller proved completion.

    A monitor can observe a dead PID and a non-empty file, but that is not
    enough to distinguish a fresh artifact from one left by an earlier run.
    Completion therefore requires explicit validator success *and* a
    controller-produced freshness/hash gate.  The monitor never executes an
    arbitrary validation command itself.
    """
    validation = worker.get("validation") or worker.get("validation_result")
    validation_ok = bool(
        worker.get("validation_ok") is True
        or (isinstance(validation, dict) and validation.get("ok") is True)
    )
    freshness_ok = bool(
        worker.get("artifact_freshness_verified") is True
        or worker.get("artifact_fresh") is True
    )
    if validation_ok and freshness_ok:
        return True, "validator_and_freshness_verified"
    if not validation_ok:
        return False, "validation_not_verified"
    return False, "artifact_freshness_not_verified"


def durable_controller_status(
    worker: dict[str, Any],
    completion_verified: bool,
    artifact_ready: bool,
) -> str | None:
    """Honor terminal/controller state without inventing runtime health.

    ``controller_monitor_adapter`` projects SQLite rows into workers.  A
    terminal failed/queued/running row is stronger than the absence of a PID
    or log breadcrumb: otherwise a failed job with no telemetry would look
    like a fresh healthy worker.  Completed rows still require the monitor's
    independent validator + freshness evidence before becoming completed.
    """
    status = str(worker.get("controller_status") or "").strip().lower()
    if status == "completed":
        if completion_verified:
            return "completed"
        if artifact_ready:
            return "artifact_ready_needs_validation"
        return "unknown"
    if status in {"failed", "retry", "blocked"}:
        return "failed"
    if status in {"running", "queued", "deferred"}:
        return "unknown" if status == "running" else status
    return None


def tail_text(path: pathlib.Path, size: int = 65536) -> str:
    try:
        with path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            length = handle.tell()
            handle.seek(max(0, length - size))
            return handle.read().decode("utf-8", errors="replace")
    except (FileNotFoundError, IsADirectoryError, PermissionError):
        return ""


def classify_error(text: str) -> str | None:
    # Controller-owned timeout diagnostics must not be reclassified as a
    # provider/network failure.  Otherwise replan would incorrectly evict a
    # healthy pool when only the local process-group deadline fired.
    if CONTROLLER_TIMEOUT_RE.search(text):
        return "stall"
    if RESOURCE_RE.search(text):
        return "resource"
    if QUOTA_RE.search(text):
        return "quota"
    if LOCATION_RE.search(text):
        return "location_restricted"
    if CAPABILITY_RE.search(text):
        return "capability"
    if AUTH_RE.search(text):
        return "auth"
    if NETWORK_RE.search(text):
        return "network"
    return None


def current_attempt_text(text: str, marker: Any) -> str:
    """Limit error classification to the current attempt in an append-only log."""
    marker_text = str(marker or "")
    if not marker_text:
        return text
    position = text.rfind(marker_text)
    return text[position:] if position >= 0 else ""


def pid_from_path(path: pathlib.Path | None) -> int | None:
    if path is None:
        return None
    try:
        value = path.read_text(encoding="utf-8").strip().splitlines()[0]
        return int(value) if value.isdigit() else None
    except (FileNotFoundError, IsADirectoryError, PermissionError, IndexError):
        return None


def worker_paths(
    worker: dict[str, Any], root: pathlib.Path
) -> tuple[pathlib.Path | None, list[pathlib.Path], list[pathlib.Path]]:
    log_value = worker.get("log_path")
    log_path = resolve_path(str(log_value), root) if log_value else None
    required_values = list(worker.get("required_paths") or [])
    if worker.get("required_artifact"):
        required_values.append(worker["required_artifact"])
    progress_values = list(worker.get("progress_paths") or [])
    return (
        log_path,
        [resolve_path(str(value), root) for value in required_values],
        [resolve_path(str(value), root) for value in progress_values],
    )


def observe_worker(
    worker: dict[str, Any], root: pathlib.Path, previous: dict[str, Any] | None
) -> dict[str, Any]:
    try:
        log_path, required_paths, progress_paths = worker_paths(worker, root)
        pid_path_value = worker.get("pid_path")
        pid_path = resolve_path(str(pid_path_value), root) if pid_path_value else None
    except ValueError:
        return _path_security_observation(worker, "local monitor path rejected")
    log_fact = file_fact(log_path) if log_path else None
    artifact_facts = [file_fact(path) for path in required_paths]
    progress_facts = [file_fact(path) for path in progress_paths]
    artifact_ready = bool(artifact_facts) and all(
        fact["exists"] and fact["size"] > 0 for fact in artifact_facts
    )
    completion_verified, completion_reason = completion_evidence(worker)
    observed_pid = pid_from_path(pid_path) if pid_path else worker.get("pid")
    alive = pid_alive(observed_pid)
    tail = tail_text(log_path) if log_path else ""
    log_error_class = classify_error(current_attempt_text(tail, worker.get("log_attempt_marker")))
    controller_error_class = str(worker.get("error_class") or "").strip() or None
    error_class = log_error_class or controller_error_class
    fingerprint = {
        "log_size": log_fact["size"] if log_fact else 0,
        "artifact_sizes": [fact["size"] for fact in artifact_facts],
        "artifact_mtimes": [fact["mtime"] for fact in artifact_facts],
        "progress_sizes": [fact["size"] for fact in progress_facts],
        "progress_mtimes": [fact["mtime"] for fact in progress_facts],
    }
    progressed = previous is None or fingerprint != previous.get("fingerprint")
    durable_status = durable_controller_status(worker, completion_verified, artifact_ready)
    if durable_status:
        status = durable_status
    elif error_class:
        status = "failed"
    elif alive is False and artifact_ready:
        status = "artifact_ready_needs_validation"
    elif alive is False:
        status = "failed"
    elif artifact_ready:
        status = "artifact_ready"
    elif progressed:
        status = "healthy"
    else:
        status = "no_progress"
    return {
        "worker_id": worker.get("worker_id") or worker.get("job_id"),
        "job_id": worker.get("job_id"),
        "pool_id": worker.get("pool_id"),
        "provider": worker.get("provider"),
        "model": worker.get("model"),
        "variant": worker.get("variant"),
        "attempt_id": worker.get("attempt_id"),
        "controller_status": worker.get("controller_status"),
        "attempt_status": worker.get("attempt_status"),
        "observation_reason": worker.get("observation_reason"),
        "lane_id": worker.get("lane_id"),
        "lane_index": worker.get("lane_index"),
        "lane_count": worker.get("lane_count"),
        "lease": worker.get("lease"),
        "heartbeat": worker.get("heartbeat"),
        "runtime_state_path": worker.get("runtime_state_path"),
        "execution_host": worker.get("execution_host") or "local_mac",
        "workload_host": worker.get("workload_host") or worker.get("execution_host") or "local_mac",
        "pid": observed_pid,
        "pid_alive": alive,
        "status": status,
        "progressed": progressed,
        "error_class": error_class,
        "error_origin": (
            "worker_log" if log_error_class
            else "controller_state" if controller_error_class
            else None
        ),
        "log": log_fact,
        "required_artifacts": artifact_facts,
        "progress_files": progress_facts,
        "artifact_ready": artifact_ready,
        "completion_verified": completion_verified,
        "completion_reason": completion_reason,
        "fingerprint": fingerprint,
        "observed_at_utc": iso_now(),
    }


def observe_remote_worker(
    worker: dict[str, Any],
    host_id: str,
    host: dict[str, Any],
    previous: dict[str, Any] | None,
    timeout: float,
) -> dict[str, Any]:
    root = str(host.get("project_path") or ".")
    try:
        log_value = str(worker.get("log_path") or "")
        log_path = remote_path(log_value, root) if log_value else ""
        pid_path_value = str(worker.get("pid_path") or "")
        pid_path = remote_path(pid_path_value, root) if pid_path_value else ""
        required_values = list(worker.get("required_paths") or [])
        if worker.get("required_artifact"):
            required_values.append(worker["required_artifact"])
        artifact_paths = [remote_path(str(value), root) for value in required_values]
        progress_paths = [
            remote_path(str(value), root) for value in (worker.get("progress_paths") or [])
        ]
    except ValueError:
        return _path_security_observation(worker, "remote monitor path rejected")
    pid_value = str(worker.get("pid") or "")
    if pid_value and not pid_value.isdigit():
        pid_value = ""
    remote_args = [pid_value, pid_path, log_path, *artifact_paths, *progress_paths]
    remote_command = "sh -s -- " + " ".join(shlex.quote(value) for value in remote_args)
    try:
        completed = subprocess.run(
            ssh_argv(host, timeout) + [remote_command],
            input=REMOTE_OBSERVER,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=max(2.0, timeout),
            check=False,
        )
    except subprocess.TimeoutExpired:
        completed = None
    if completed is None or completed.returncode != 0:
        message = (
            f"remote observation timeout after {timeout}s"
            if completed is None
            else completed.stderr.strip()[-1000:] or f"ssh exit {completed.returncode}"
        )
        return {
            "worker_id": worker.get("worker_id") or worker.get("job_id"),
            "job_id": worker.get("job_id"),
            "pool_id": worker.get("pool_id"),
            "model": worker.get("model"),
            "variant": worker.get("variant"),
            "attempt_id": worker.get("attempt_id"),
            "controller_status": worker.get("controller_status"),
            "attempt_status": worker.get("attempt_status"),
            "observation_reason": worker.get("observation_reason"),
            "lane_id": worker.get("lane_id"),
            "lane_index": worker.get("lane_index"),
            "lane_count": worker.get("lane_count"),
            "lease": worker.get("lease"),
            "heartbeat": worker.get("heartbeat"),
            "execution_host": worker.get("execution_host") or host_id,
            "workload_host": worker.get("workload_host") or host_id,
            "pid_alive": None,
            "status": "failed",
            "progressed": False,
            "error_class": "host_unreachable",
            "error_origin": "compute_host",
            "error_message": message,
            "log": {"path": log_path, "exists": False, "size": 0, "mtime": None},
            "required_artifacts": [
                {"path": path, "exists": False, "size": 0, "mtime": None}
                for path in artifact_paths
            ],
            "progress_files": [
                {"path": path, "exists": False, "size": 0, "mtime": None}
                for path in progress_paths
            ],
            "artifact_ready": False,
            "fingerprint": {
                "log_size": 0, "artifact_sizes": [], "artifact_mtimes": [],
                "progress_sizes": [], "progress_mtimes": [],
            },
            "observed_at_utc": iso_now(),
        }
    facts_text, _, tail = completed.stdout.partition("TAIL_BEGIN\n")
    alive: bool | None = None
    observed_pid: int | None = None
    file_facts: dict[int, dict[str, Any]] = {}
    all_paths = [log_path, *artifact_paths, *progress_paths]
    for raw_line in facts_text.splitlines():
        parts = raw_line.split("|")
        if parts[0] == "PID" and len(parts) >= 2:
            alive = True if parts[1] == "1" else False if parts[1] == "0" else None
        elif parts[0] == "PID_VALUE" and len(parts) >= 2 and parts[1].isdigit():
            observed_pid = int(parts[1])
        elif parts[0] == "FILE" and len(parts) >= 5:
            try:
                index = int(parts[1])
                path_index = index + 1
                file_facts[index] = {
                    "path": all_paths[path_index],
                    "exists": parts[2] == "1",
                    "size": int(parts[3]),
                    "mtime": float(parts[4]) if parts[4] != "0" else None,
                }
            except (ValueError, IndexError):
                continue
    log_fact = file_facts.get(-1) if log_path else None
    artifact_facts = [
        file_facts.get(index, {"path": path, "exists": False, "size": 0, "mtime": None})
        for index, path in enumerate(artifact_paths)
    ]
    progress_facts = [
        file_facts.get(
            len(artifact_paths) + index,
            {"path": path, "exists": False, "size": 0, "mtime": None},
        )
        for index, path in enumerate(progress_paths)
    ]
    artifact_ready = bool(artifact_facts) and all(
        fact["exists"] and fact["size"] > 0 for fact in artifact_facts
    )
    completion_verified, completion_reason = completion_evidence(worker)
    log_error_class = classify_error(current_attempt_text(tail, worker.get("log_attempt_marker")))
    controller_error_class = str(worker.get("error_class") or "").strip() or None
    error_class = log_error_class or controller_error_class
    fingerprint = {
        "log_size": log_fact["size"] if log_fact else 0,
        "artifact_sizes": [fact["size"] for fact in artifact_facts],
        "artifact_mtimes": [fact["mtime"] for fact in artifact_facts],
        "progress_sizes": [fact["size"] for fact in progress_facts],
        "progress_mtimes": [fact["mtime"] for fact in progress_facts],
    }
    progressed = previous is None or fingerprint != previous.get("fingerprint")
    durable_status = durable_controller_status(worker, completion_verified, artifact_ready)
    if durable_status:
        status = durable_status
    elif error_class:
        status = "failed"
    elif alive is False and artifact_ready:
        status = "artifact_ready_needs_validation"
    elif alive is False:
        status = "failed"
    elif artifact_ready:
        status = "artifact_ready"
    elif progressed:
        status = "healthy"
    else:
        status = "no_progress"
    return {
        "worker_id": worker.get("worker_id") or worker.get("job_id"),
        "job_id": worker.get("job_id"),
        "pool_id": worker.get("pool_id"),
        "provider": worker.get("provider"),
        "model": worker.get("model"),
        "variant": worker.get("variant"),
        "attempt_id": worker.get("attempt_id"),
        "controller_status": worker.get("controller_status"),
        "attempt_status": worker.get("attempt_status"),
        "observation_reason": worker.get("observation_reason"),
        "lane_id": worker.get("lane_id"),
        "lane_index": worker.get("lane_index"),
        "lane_count": worker.get("lane_count"),
        "lease": worker.get("lease"),
        "heartbeat": worker.get("heartbeat"),
        "runtime_state_path": worker.get("runtime_state_path"),
        "execution_host": worker.get("execution_host") or host_id,
        "workload_host": worker.get("workload_host") or host_id,
        "pid": observed_pid,
        "pid_alive": alive,
        "status": status,
        "progressed": progressed,
        "error_class": error_class,
        "error_origin": (
            "worker_log" if log_error_class
            else "controller_state" if controller_error_class
            else None
        ),
        "log": log_fact,
        "required_artifacts": artifact_facts,
        "progress_files": progress_facts,
        "artifact_ready": artifact_ready,
        "completion_verified": completion_verified,
        "completion_reason": completion_reason,
        "fingerprint": fingerprint,
        "observed_at_utc": iso_now(),
    }


def _observe_on_host(
    worker: dict[str, Any],
    host_id: str,
    host: dict[str, Any],
    root: pathlib.Path,
    previous: dict[str, Any] | None,
    timeout: float,
    *,
    role: str,
) -> dict[str, Any]:
    """Observe one placement role without mixing agent and workload paths."""
    if role == "workload":
        # A split placement must declare workload telemetry explicitly. Do
        # not probe the agent's local PID/log as if they were remote compute.
        if not any(
            worker.get(key)
            for key in (
                "workload_pid", "workload_pid_path", "workload_log_path",
                "workload_required_paths", "workload_progress_paths",
            )
        ):
            return {
                "worker_id": worker.get("worker_id") or worker.get("job_id"),
                "job_id": worker.get("job_id"),
                "pool_id": worker.get("pool_id"),
                "model": worker.get("model"),
                "execution_host": worker.get("execution_host") or "local_mac",
                "workload_host": host_id,
                "status": "unknown",
                "progressed": False,
                "error_class": None,
                "error_origin": "workload_observation_unavailable",
                "error_message": "split placement has no workload PID/log/artifact telemetry",
                "pid_alive": None,
                "artifact_ready": False,
                "fingerprint": {},
                "observed_at_utc": iso_now(),
            }
        observed = dict(worker)
        for suffix in (
            "pid", "pid_path", "log_path", "required_paths", "required_artifact",
            "progress_paths", "log_attempt_marker",
        ):
            key = f"workload_{suffix}"
            if key in worker:
                observed[suffix] = worker[key]
        observed["execution_host"] = worker.get("execution_host") or "local_mac"
        observed["workload_host"] = host_id
    else:
        observed = dict(worker)
        observed["execution_host"] = host_id
    if host.get("transport") == "ssh":
        return observe_remote_worker(observed, host_id, host, previous, timeout)
    return observe_worker(observed, root, previous)


def observe_placement(
    worker: dict[str, Any],
    state: dict[str, Any],
    root: pathlib.Path,
    previous: dict[str, Any] | None,
    timeout: float,
) -> dict[str, Any]:
    """Observe agent execution and workload compute as separate placements."""
    execution_host = str(worker.get("execution_host") or "local_mac")
    workload_host = str(worker.get("workload_host") or execution_host)
    hosts = state.get("compute_hosts") or {}
    agent_previous = (
        previous.get("agent_observation") if isinstance(previous, dict) and previous.get("agent_observation") else previous
    )
    execution = _observe_on_host(
        worker, execution_host, hosts.get(execution_host) or {}, root, agent_previous, timeout, role="execution"
    )
    if workload_host == execution_host:
        execution["execution_host"] = execution_host
        execution["workload_host"] = workload_host
        return execution
    workload = _observe_on_host(
        worker,
        workload_host,
        hosts.get(workload_host) or {},
        root,
        previous.get("workload_observation") if isinstance(previous, dict) else None,
        timeout,
        role="workload",
    )
    agent_bad = execution.get("status") in {"failed", "stalled"}
    workload_bad = workload.get("status") in {"failed", "stalled"}
    if agent_bad:
        status = execution.get("status")
        error_class = execution.get("error_class")
        error_origin = execution.get("error_origin") or "provider"
        failed_host = execution_host
    elif workload_bad:
        status = workload.get("status")
        error_class = workload.get("error_class") or "host_unreachable"
        error_origin = "compute_host"
        failed_host = workload_host
    elif execution.get("status") == "unknown" or workload.get("status") == "unknown":
        status = "unknown"
        error_class = None
        error_origin = "workload_observation_unavailable"
        failed_host = None
    elif execution.get("status") == "completed" and workload.get("status") == "completed":
        status = "completed"
        error_class = None
        error_origin = None
        failed_host = None
    elif execution.get("status") == "artifact_ready_needs_validation" or workload.get("status") == "artifact_ready_needs_validation":
        status = "artifact_ready_needs_validation"
        error_class = None
        error_origin = "completion_evidence"
        failed_host = None
    elif execution.get("status") == "no_progress" or workload.get("status") == "no_progress":
        status = "no_progress"
        error_class = None
        error_origin = None
        failed_host = None
    else:
        status = "healthy"
        error_class = None
        error_origin = None
        failed_host = None
    return {
        "worker_id": worker.get("worker_id") or worker.get("job_id"),
        "job_id": worker.get("job_id"),
        "pool_id": worker.get("pool_id"),
        "provider": worker.get("provider"),
        "model": worker.get("model"),
        "variant": worker.get("variant"),
        "attempt_id": worker.get("attempt_id"),
        "runtime_state_path": worker.get("runtime_state_path"),
        "execution_host": execution_host,
        "workload_host": workload_host,
        "pid": execution.get("pid"),
        "pid_alive": execution.get("pid_alive"),
        "status": status,
        "progressed": bool(execution.get("progressed") or workload.get("progressed")),
        "error_class": error_class,
        "error_origin": error_origin,
        "failed_host": failed_host,
        "agent_observation": execution,
        "workload_observation": workload,
        "log": execution.get("log"),
        "required_artifacts": workload.get("required_artifacts") or execution.get("required_artifacts", []),
        "progress_files": workload.get("progress_files") or execution.get("progress_files", []),
        "artifact_ready": bool(workload.get("artifact_ready") or execution.get("artifact_ready")),
        "fingerprint": {
            "agent": execution.get("fingerprint"),
            "workload": workload.get("fingerprint"),
        },
        "observed_at_utc": iso_now(),
    }


def compute_snapshot(state: dict[str, Any], timeout: float) -> dict[str, Any]:
    hosts = [dict(host or {}, host_id=str(host_id)) for host_id, host in (state.get("compute_hosts") or {}).items()]
    if not hosts:
        return {"ok": False, "error": "no compute_hosts in state"}
    script = pathlib.Path(__file__).with_name("compute_resource_probe.py")
    try:
        result = subprocess.run(
            [sys.executable, str(script), "--inventory", "-", "--timeout", str(timeout)],
            input=json.dumps({"hosts": hosts}, ensure_ascii=False),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=max(5.0, timeout + 5.0),
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"compute probe timeout after {timeout}s"}
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"ok": False, "error": result.stderr[-2000:] or result.stdout[-2000:]}


def merge_compute_hosts(state: dict[str, Any], snapshot: dict[str, Any]) -> None:
    if not snapshot.get("ok"):
        return
    current_hosts = state.setdefault("compute_hosts", {})
    for host_id, probed in (snapshot.get("compute_hosts") or {}).items():
        current = current_hosts.setdefault(host_id, {})
        dynamic = {key: current.get(key) for key in ("inflight", "max_concurrency", "billing_stop") if key in current}
        current.update(probed)
        current.update(dynamic)


def compute_alerts(state: dict[str, Any]) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    active_hosts = {
        # Resource pressure belongs to the workload host. The provider CLI
        # may remain authenticated and running on a different execution host.
        str(worker.get("workload_host") or worker.get("execution_host") or "local_mac")
        for worker in state.get("workers", [])
        if worker.get("status") not in {"completed", "failed"}
    }
    for host_id, host in (state.get("compute_hosts") or {}).items():
        if not host.get("reachable") and host_id in active_hosts:
            alerts.append({"host_id": host_id, "severity": "stop", "reason": "active_host_unreachable"})
            continue
        disk_free = float(host.get("disk_free_gib") or 0)
        disk_total = float(host.get("disk_total_gib") or 0)
        if host.get("transport") == "local" and disk_free and disk_total and (
            disk_free < 20 or disk_free / disk_total < 0.10
        ):
            alerts.append({"host_id": host_id, "severity": "conserve", "reason": "local_disk_below_20_GiB_or_10_percent"})
        memory_free = float(host.get("memory_available_gib") or 0)
        memory_total = float(host.get("memory_total_gib") or 0)
        pressure_state = str(host.get("memory_pressure_state") or "unknown").lower()
        if host.get("transport") == "local" and pressure_state in {"critical", "conserve"}:
            alerts.append({
                "host_id": host_id,
                "severity": "stop" if pressure_state == "critical" else "reduce",
                "reason": f"local_memory_pressure_{pressure_state}",
            })
        if host.get("transport") == "local" and host.get("local_agent_launch_allowed") is False:
            alerts.append({"host_id": host_id, "severity": "stop", "reason": "local_agent_launch_blocked"})
        if memory_free and memory_total and memory_free / memory_total < 0.08:
            alerts.append({"host_id": host_id, "severity": "reduce", "reason": "available_memory_below_8_percent"})
        # A finite cgroup-v1/v2 boundary is the effective worker limit on
        # Linux containers; host-sized /proc memory can look healthy while a
        # worker is near its limit.  An explicitly observed unlimited v1
        # controller is usable host-boundary evidence, while unknown or
        # malformed evidence is intentionally not converted into health.
        cgroup_max = host.get("cgroup_memory_max_bytes")
        cgroup_current = host.get("cgroup_memory_current_bytes")
        try:
            cgroup_max_value = float(cgroup_max)
            cgroup_current_value = float(cgroup_current)
        except (TypeError, ValueError):
            cgroup_max_value = cgroup_current_value = 0.0
        if host.get("cgroup_required") and host.get("cgroup_memory_evidence_status") not in {
            "complete",
            "unbounded",
        }:
            alerts.append({"host_id": host_id, "severity": "stop", "reason": "cgroup_memory_evidence_unknown"})
        elif cgroup_max_value > 0 and cgroup_current_value >= cgroup_max_value * 0.90:
            alerts.append({"host_id": host_id, "severity": "stop", "reason": "cgroup_memory_current_at_or_above_90_percent"})
        elif cgroup_max_value > 0 and cgroup_current_value >= cgroup_max_value * 0.80:
            alerts.append({"host_id": host_id, "severity": "reduce", "reason": "cgroup_memory_current_at_or_above_80_percent"})
        try:
            cgroup_oom_kill = int(host.get("cgroup_memory_events_oom_kill") or 0)
        except (TypeError, ValueError):
            cgroup_oom_kill = 0
        try:
            cgroup_oom = int(host.get("cgroup_memory_events_oom") or 0)
        except (TypeError, ValueError):
            cgroup_oom = 0
        if cgroup_oom_kill > 0:
            alerts.append({"host_id": host_id, "severity": "stop", "reason": "cgroup_memory_oom_kill_observed"})
        elif cgroup_oom > 0:
            alerts.append({"host_id": host_id, "severity": "reduce", "reason": "cgroup_memory_oom_observed"})
        try:
            psi_some_avg10 = float(host.get("psi_some_avg10"))
        except (TypeError, ValueError):
            psi_some_avg10 = None
        if psi_some_avg10 is not None and psi_some_avg10 >= 20.0:
            alerts.append({"host_id": host_id, "severity": "stop", "reason": "psi_memory_some_avg10_at_or_above_20_percent"})
        elif psi_some_avg10 is not None and psi_some_avg10 >= 5.0:
            alerts.append({"host_id": host_id, "severity": "reduce", "reason": "psi_memory_some_avg10_at_or_above_5_percent"})
        for gpu in host.get("gpus") or []:
            if float(gpu.get("utilization_percent") or 0) >= 98:
                alerts.append({"host_id": host_id, "severity": "observe", "reason": "gpu_utilization_at_or_above_98_percent"})
    return alerts


def codex_usage_snapshot(timeout: float) -> dict[str, Any]:
    script = pathlib.Path(__file__).with_name("codex_usage_snapshot.py")
    result = subprocess.run(
        [sys.executable, str(script), "--timeout", str(timeout)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout + 5,
    )
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        payload = {
            "ok": False,
            "error": result.stderr[-2000:] or result.stdout[-2000:] or "invalid usage JSON",
        }
    return payload


def merge_codex_pools(state: dict[str, Any], usage: dict[str, Any]) -> None:
    if not usage.get("ok"):
        return
    pools = state.setdefault("pools", {})
    for pool_id, snapshot in (usage.get("pools") or {}).items():
        current = pools.setdefault(pool_id, {})
        current.update(
            {
                "health": snapshot.get("health"),
                "effective_remaining_percent": snapshot.get("effective_remaining_percent"),
                "reset_horizon": [
                    window.get("resets_at_utc")
                    for window in (snapshot.get("primary"), snapshot.get("secondary"))
                    if window
                ],
                "last_checked_at": usage.get("fetched_at_utc"),
            }
        )


def update_quota_rates(
    state: dict[str, Any], before: dict[str, Any], after: dict[str, Any], elapsed_minutes: float
) -> list[dict[str, Any]]:
    updates: list[dict[str, Any]] = []
    if elapsed_minutes <= 0 or not before.get("ok") or not after.get("ok"):
        return updates
    active_by_pool: dict[str, list[dict[str, Any]]] = {}
    for worker in state.get("workers", []):
        if worker.get("status") in {
            "running",
            "starting",
            "healthy",
            "artifact_ready",
            "stalled",
            "completed",
        }:
            active_by_pool.setdefault(str(worker.get("pool_id")), []).append(worker)
    pools = state.setdefault("pools", {})
    for pool_id, after_pool in (after.get("pools") or {}).items():
        before_pool = (before.get("pools") or {}).get(pool_id) or {}
        before_remaining = before_pool.get("effective_remaining_percent")
        after_remaining = after_pool.get("effective_remaining_percent")
        if not isinstance(before_remaining, (int, float)) or not isinstance(after_remaining, (int, float)):
            continue
        consumed = max(0.0, float(before_remaining) - float(after_remaining))
        observed_rate = consumed / elapsed_minutes
        current = pools.setdefault(pool_id, {})
        prior = current.get("quota_rate_percent_per_minute")
        workers = active_by_pool.get(pool_id, [])
        exclusive = bool(state.get("exclusive_pool_observation")) or (
            len(workers) == 1 and bool(workers[0].get("exclusive_pool_observation"))
        )
        if consumed == 0:
            upper_bound = 1.0 / elapsed_minutes
            if prior is not None:
                new_rate = min(float(prior), upper_bound * 0.5)
            else:
                new_rate = upper_bound * 0.5
            evidence = "zero displayed-percent change; rate is an upper-bound estimate"
        else:
            upper_bound = None
            new_rate = observed_rate if prior is None else float(prior) * 0.7 + observed_rate * 0.3
            evidence = "displayed quota delta divided by elapsed monitor time"
        current["observed_pool_burn_rate_percent_per_minute"] = round(
            observed_rate, 6
        )
        current["quota_rate_observed_at"] = iso_now()
        if exclusive:
            current["quota_rate_percent_per_minute"] = round(new_rate, 6)
        if exclusive and len(workers) == 1 and workers[0].get("model"):
            model_rates = current.setdefault("model_quota_rates", {})
            model_rates[str(workers[0]["model"])] = round(new_rate, 6)
        updates.append(
            {
                "pool_id": pool_id,
                "consumed_percent": consumed,
                "elapsed_minutes": round(elapsed_minutes, 3),
                "observed_rate_percent_per_minute": round(observed_rate, 6),
                "estimated_rate_percent_per_minute": (
                    round(new_rate, 6) if exclusive else prior
                ),
                "zero_delta_upper_bound": round(upper_bound, 6) if upper_bound else None,
                "evidence": evidence,
                "attribution": (
                    "exclusive_single_model"
                    if exclusive and len(workers) == 1
                    else "pool_level_or_externally_confounded"
                ),
            }
        )
    return updates


def apply_feedback(state: dict[str, Any], observation: dict[str, Any]) -> None:
    pools = state.setdefault("pools", {})
    models = state.setdefault("model_state", {})
    pool_id = observation.get("pool_id")
    model = observation.get("model")
    error_class = observation.get("error_class")
    if observation.get("error_origin") == "compute_host":
        host_id = observation.get("workload_host") or observation.get("failed_host") or observation.get("execution_host")
        if host_id:
            host = state.setdefault("compute_hosts", {}).setdefault(str(host_id), {})
            host["reachable"] = False
            host["probe_error"] = observation.get("error_message") or error_class
            host["last_probed_at_utc"] = observation.get("observed_at_utc")
        return
    if error_class == "quota" and pool_id:
        pool = pools.setdefault(pool_id, {})
        pool["health"] = "cooldown"
        pool.setdefault("recent_failures", []).append("explicit quota/rate failure")
    elif error_class in {"capability", "location_restricted"} and model:
        models.setdefault(model, {}).update(
            {
                "runtime_state": "rejected",
                "runtime_reason": (
                    "location restriction; configure a supported region or "
                    "GCP/enterprise project before retry"
                    if error_class == "location_restricted"
                    else "capability rejection observed in worker log"
                ),
                "last_checked_at": observation["observed_at_utc"],
            }
        )
        if error_class == "location_restricted":
            models[model].update(
                recovery_action="gcp_project_or_supported_region",
                retryable=False,
                route_change_required=True,
            )
    elif error_class in {"auth", "network"} and pool_id:
        pool = pools.setdefault(pool_id, {})
        pool["health"] = "degraded"
        pool.setdefault("recent_failures", []).append(f"{error_class} failure")
    elif error_class == "resource":
        # Resource admission is a placement/host condition, not evidence that
        # the Codex/model pool is unhealthy.  Keep the model pool intact and
        # make the next planner wave avoid local execution until refreshed.
        host_id = observation.get("execution_host") or observation.get("workload_host")
        if host_id:
            host = state.setdefault("compute_hosts", {}).setdefault(str(host_id), {})
            host["local_agent_launch_allowed"] = False
            host["probe_error"] = "local resource admission blocked before child creation"
            host["last_probed_at_utc"] = observation.get("observed_at_utc")

    # ``model_state`` is a monitor-report convenience view.  The durable
    # runtime overlay is the source consumed by the next preflight.  Persist
    # the exact provider/model/variant evidence when a worker carries an
    # explicit runtime-state path; capability failures remain model-scoped and
    # therefore cannot poison sibling models in a shared pool.
    runtime_path = observation.get("runtime_state_path") or state.get("runtime_state")
    if runtime_path and pool_id and error_class:
        try:
            script_dir = pathlib.Path(__file__).resolve().parent
            if str(script_dir) not in sys.path:
                sys.path.insert(0, str(script_dir))
            from continuity_controller import record_runtime_feedback

            provider = str(
                observation.get("provider")
                or (str(pool_id).split(".", 1)[0] if "." in str(pool_id) else "")
            )
            job = {
                "pool_id": str(pool_id),
                "provider": provider,
                "model": str(model or ""),
                "variant": observation.get("variant"),
                "runtime_state_path": str(runtime_path),
            }
            attempt = dict(job)
            attempt["attempt_id"] = observation.get("attempt_id") or observation.get("worker_id")
            output = str(
                observation.get("error_message")
                or observation.get("log_tail")
                or observation.get("error")
                or "monitor feedback"
            )
            record_runtime_feedback(
                {"runtime_state": str(runtime_path)},
                job,
                attempt,
                success=False,
                error_class=str(error_class),
                output=output,
            )
        except (ImportError, OSError, ValueError, TypeError):
            # A monitor report must remain useful even when its optional
            # runtime sidecar is unavailable.  The omission is explicit in
            # the report's model_state and can be retried on the next tick.
            state.setdefault("runtime_feedback_errors", []).append(
                {"pool_id": str(pool_id), "model": str(model or ""), "error_class": str(error_class)}
            )


def monitor(
    state: dict[str, Any],
    duration_seconds: float,
    interval_seconds: float,
    stall_seconds: float,
    refresh_codex: bool,
    usage_timeout: float,
    refresh_compute: bool,
    compute_timeout: float,
    stream: bool,
) -> dict[str, Any]:
    root = pathlib.Path(state.get("project_root") or os.getcwd()).expanduser().resolve()
    started = time.monotonic()
    usage_before = codex_usage_snapshot(usage_timeout) if refresh_codex else {"ok": False}
    merge_codex_pools(state, usage_before)
    compute_before = compute_snapshot(state, compute_timeout) if refresh_compute else {"ok": False}
    merge_compute_hosts(state, compute_before)
    history: list[dict[str, Any]] = []
    previous: dict[str, dict[str, Any]] = {}
    last_progress: dict[str, float] = {}
    while True:
        tick_time = time.monotonic()
        observations: list[dict[str, Any]] = []
        for worker in state.get("workers", []):
            worker_id = str(worker.get("worker_id") or worker.get("job_id"))
            observation = observe_placement(
                worker, state, root, previous.get(worker_id), compute_timeout
            )
            if observation["progressed"]:
                last_progress[worker_id] = tick_time
            no_progress_for = tick_time - last_progress.get(worker_id, started)
            observation["no_progress_seconds"] = round(no_progress_for, 1)
            if (
                observation["status"] == "no_progress"
                and no_progress_for >= stall_seconds
            ):
                observation["status"] = "stalled"
            previous[worker_id] = observation
            observations.append(observation)
            apply_feedback(state, observation)
            worker["status"] = observation["status"]
            worker["last_observed_at"] = observation["observed_at_utc"]
        tick = {"observed_at_utc": iso_now(), "workers": observations}
        history.append(tick)
        if stream:
            print(json.dumps({"event": "monitor_tick", **tick}, ensure_ascii=False), flush=True)
        elapsed = time.monotonic() - started
        if elapsed >= duration_seconds:
            break
        time.sleep(min(interval_seconds, max(0.0, duration_seconds - elapsed)))

    usage_after = codex_usage_snapshot(usage_timeout) if refresh_codex else {"ok": False}
    merge_codex_pools(state, usage_after)
    compute_after = compute_snapshot(state, compute_timeout) if refresh_compute else {"ok": False}
    merge_compute_hosts(state, compute_after)
    resource_alerts = compute_alerts(state)
    elapsed_minutes = max(0.001, (time.monotonic() - started) / 60.0)
    quota_rate_updates = update_quota_rates(state, usage_before, usage_after, elapsed_minutes)
    final_workers = history[-1]["workers"] if history else []
    completed_jobs = state.setdefault("completed_jobs", [])
    completed_ids = {
        item.get("job_id") if isinstance(item, dict) else str(item)
        for item in completed_jobs
    }
    failed_jobs = state.setdefault("failed_jobs", [])
    failed_ids = {
        item.get("job_id") if isinstance(item, dict) else str(item)
        for item in failed_jobs
    }
    for worker in final_workers:
        job_id = worker.get("job_id")
        if not job_id:
            continue
        if worker["status"] == "completed" and job_id not in completed_ids:
            completed_jobs.append(job_id)
            completed_ids.add(job_id)
        elif worker["status"] in {"failed", "stalled"} and job_id not in failed_ids:
            failed_jobs.append(
                {
                    "job_id": job_id,
                    "status": worker["status"],
                    "error_class": worker.get("error_class"),
                    "observed_at_utc": worker["observed_at_utc"],
                }
            )
            failed_ids.add(job_id)
    statuses = {worker["status"] for worker in final_workers}
    if any(alert["severity"] == "stop" for alert in resource_alerts):
        decision = "reroute_or_pause"
    elif "failed" in statuses or "stalled" in statuses:
        decision = "reroute_or_pause"
    elif "completed" in statuses:
        decision = "replan_unblocked_jobs"
    elif statuses & {"healthy", "artifact_ready", "no_progress"}:
        decision = "keep_and_monitor"
    else:
        decision = "replan"
    state["last_monitor_at"] = iso_now()
    state["last_rescore_reason"] = "minute_monitor_feedback"
    return {
        "ok": True,
        "monitor_started_at_utc": history[0]["observed_at_utc"] if history else iso_now(),
        "monitor_finished_at_utc": iso_now(),
        "duration_seconds": round((time.monotonic() - started), 2),
        "decision": decision,
        "final_workers": final_workers,
        "quota_rate_updates": quota_rate_updates,
        "compute_alerts": resource_alerts,
        "codex_usage_before": usage_before,
        "codex_usage_after": usage_after,
        "compute_snapshot_before": compute_before,
        "compute_snapshot_after": compute_after,
        "state": state,
        "next": "run dynamic_dispatch_planner.py again with the updated state",
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", required=True)
    parser.add_argument("--duration-seconds", type=float, default=180.0)
    parser.add_argument("--interval-seconds", type=float, default=30.0)
    parser.add_argument("--stall-seconds", type=float, default=120.0)
    parser.add_argument("--refresh-codex-usage", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--usage-timeout", type=float, default=15.0)
    parser.add_argument("--refresh-compute-hosts", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--compute-timeout", type=float, default=8.0)
    parser.add_argument("--stream", action="store_true")
    parser.add_argument("--state-out")
    parser.add_argument("--report")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        state = load_json(args.state)
        report = monitor(
            state,
            max(0.0, args.duration_seconds),
            max(0.1, args.interval_seconds),
            max(1.0, args.stall_seconds),
            args.refresh_codex_usage,
            max(2.0, args.usage_timeout),
            args.refresh_compute_hosts,
            max(2.0, args.compute_timeout),
            args.stream,
        )
        if args.state_out:
            atomic_write(args.state_out, report["state"])
        if args.report:
            atomic_write(args.report, report)
        else:
            print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False, indent=2))
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
