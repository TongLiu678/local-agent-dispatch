#!/usr/bin/env python3
"""Supervise one fixed, loopback-only reverse SSH forward.

This module is a transport lifecycle boundary, not a general SSH launcher.
The command builder emits only ``ssh -N -T -R`` with a loopback mapping.  The
supervisor records bounded metadata and restarts a dead tunnel a finite number
of times; it never accepts a shell command, provider prompt, environment, or
credential value.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import pathlib
import re
import signal
import subprocess
import threading
import time
from typing import Any, Callable, Sequence


SCHEMA_VERSION = 1
_TOKEN_RE = re.compile(r"[A-Za-z0-9_./+-]+\Z")
_TARGET_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")


class SupervisorError(ValueError):
    """Raised when a reverse tunnel configuration is unsafe."""


def _utc_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _safe_token(value: Any, field: str, *, pattern: re.Pattern[str] = _TOKEN_RE) -> str:
    if not isinstance(value, str) or not value or any(char in value for char in "\0\r\n"):
        raise SupervisorError(f"{field} is invalid")
    if not pattern.fullmatch(value):
        raise SupervisorError(f"{field} is invalid")
    return value


def _safe_path(value: Any, field: str) -> str:
    value = _safe_token(value, field)
    path = pathlib.Path(value)
    if not path.is_absolute() or path == pathlib.Path(path.anchor):
        raise SupervisorError(f"{field} must be a non-root absolute path")
    if any(part in {"", ".", ".."} for part in value.split("/")[1:]):
        raise SupervisorError(f"{field} contains an unsafe component")
    return value


def _safe_port(value: Any, field: str) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise SupervisorError(f"{field} is invalid") from exc
    if port < 1 or port > 65535:
        raise SupervisorError(f"{field} is outside 1..65535")
    return port


def build_ssh_argv(
    *,
    ssh_executable: str,
    ssh_config: str,
    identity_file: str,
    target: str,
    central_port: int,
    worker_port: int,
    connect_timeout: int = 10,
    server_alive_interval: int = 20,
    server_alive_count_max: int = 3,
) -> list[str]:
    """Build the only SSH command this supervisor is allowed to run."""

    executable = _safe_token(ssh_executable, "ssh_executable")
    config = _safe_path(ssh_config, "ssh_config")
    identity = _safe_path(identity_file, "identity_file")
    target = _safe_token(target, "target", pattern=_TARGET_RE)
    timeout = _safe_port(connect_timeout, "connect_timeout")
    alive_interval = _safe_port(server_alive_interval, "server_alive_interval")
    alive_count = _safe_port(server_alive_count_max, "server_alive_count_max")
    central = _safe_port(central_port, "central_port")
    worker = _safe_port(worker_port, "worker_port")
    return [
        executable,
        "-F",
        config,
        "-i",
        identity,
        "-N",
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "ExitOnForwardFailure=yes",
        "-o",
        f"ConnectTimeout={timeout}",
        "-o",
        f"ServerAliveInterval={alive_interval}",
        "-o",
        f"ServerAliveCountMax={alive_count}",
        "-R",
        f"127.0.0.1:{central}:127.0.0.1:{worker}",
        target,
    ]


def _command_digest(argv: Sequence[str]) -> str:
    return hashlib.sha256(
        json.dumps(list(argv), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _write_json_atomic(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, ensure_ascii=False, sort_keys=True, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


class ReverseTunnelSupervisor:
    """Run and boundedly restart one fixed SSH process."""

    def __init__(
        self,
        argv: Sequence[str],
        *,
        status_path: pathlib.Path | str,
        log_path: pathlib.Path | str,
        max_attempts: int = 3,
        restart_backoff_seconds: float = 5.0,
        max_runtime_seconds: float = 0.0,
        popen_factory: Callable[..., Any] = subprocess.Popen,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not argv or not all(isinstance(item, str) for item in argv):
            raise SupervisorError("argv must be a non-empty string sequence")
        if "-N" not in argv or "-T" not in argv or "-R" not in argv:
            raise SupervisorError("argv must be a non-interactive reverse tunnel")
        try:
            mapping = argv[list(argv).index("-R") + 1]
        except (ValueError, IndexError) as exc:
            raise SupervisorError("argv must contain one -R mapping") from exc
        if not isinstance(mapping, str) or not re.fullmatch(
            r"127\.0\.0\.1:[0-9]+:127\.0\.0\.1:[0-9]+\Z", mapping
        ):
            raise SupervisorError("reverse tunnel must bind both endpoints to loopback")
        self.argv = list(argv)
        self.status_path = pathlib.Path(status_path).expanduser().resolve()
        self.log_path = pathlib.Path(log_path).expanduser().resolve()
        if self.status_path == pathlib.Path(self.status_path.anchor) or self.log_path == pathlib.Path(self.log_path.anchor):
            raise SupervisorError("status_path and log_path may not be filesystem root")
        try:
            attempts = int(max_attempts)
        except (TypeError, ValueError) as exc:
            raise SupervisorError("max_attempts is invalid") from exc
        if attempts < 0 or attempts > 256:
            raise SupervisorError("max_attempts must be between 0 and 256")
        if restart_backoff_seconds < 0 or restart_backoff_seconds > 3600:
            raise SupervisorError("restart_backoff_seconds is invalid")
        if max_runtime_seconds < 0 or max_runtime_seconds > 7 * 24 * 3600:
            raise SupervisorError("max_runtime_seconds is invalid")
        self.max_attempts = attempts
        self.restart_backoff_seconds = float(restart_backoff_seconds)
        self.max_runtime_seconds = float(max_runtime_seconds)
        self.popen_factory = popen_factory
        self.monotonic = monotonic
        self.sleep = sleep
        self.stop_event = threading.Event()
        self._child: Any | None = None
        self._child_started_new_session = False
        self._command_digest = _command_digest(self.argv)

    def _status(
        self,
        state: str,
        *,
        attempts: int,
        child_pid: int | None = None,
        last_returncode: int | None = None,
        error: str | None = None,
    ) -> dict[str, Any]:
        result: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "kind": "reverse_tunnel_supervisor",
            "state": state,
            "supervisor_pid": os.getpid(),
            "child_pid": child_pid,
            "attempts": attempts,
            "last_returncode": last_returncode,
            "command_digest": self._command_digest,
            "observed_at_utc": _utc_now(),
        }
        if error is not None:
            result["error"] = error
        _write_json_atomic(self.status_path, result)
        return result

    def request_stop(self) -> None:
        self.stop_event.set()
        child = self._child
        if child is not None and child.poll() is None:
            try:
                child.terminate()
            except OSError:
                pass

    def _wait(self, child: Any, deadline: float | None) -> int | None:
        while True:
            returncode = child.poll()
            if returncode is not None:
                return int(returncode)
            if self.stop_event.is_set():
                self.request_stop()
                try:
                    return int(child.wait(timeout=10))
                except (subprocess.TimeoutExpired, OSError):
                    try:
                        child.kill()
                    except OSError:
                        pass
                    return -9
            if deadline is not None and self.monotonic() >= deadline:
                self.request_stop()
                try:
                    return int(child.wait(timeout=10))
                except (subprocess.TimeoutExpired, OSError):
                    try:
                        child.kill()
                    except OSError:
                        pass
                    return -9
            try:
                return int(child.wait(timeout=1))
            except subprocess.TimeoutExpired:
                continue

    def run(self) -> dict[str, Any]:
        started = self.monotonic()
        attempts = 0
        last_returncode: int | None = None
        deadline = started + self.max_runtime_seconds if self.max_runtime_seconds else None
        # Zero means no retry limit, but the caller still owns the process and
        # must use request_stop or max_runtime_seconds to end it.
        while not self.stop_event.is_set() and (self.max_attempts == 0 or attempts < self.max_attempts):
            attempts += 1
            self._status("starting", attempts=attempts)
            try:
                with self.log_path.open("a", encoding="utf-8") as log_handle:
                    child = self.popen_factory(
                        self.argv,
                        stdin=subprocess.DEVNULL,
                        stdout=log_handle,
                        stderr=log_handle,
                        start_new_session=True,
                        close_fds=True,
                    )
                    self._child = child
                    self._child_started_new_session = True
                    child_pid = int(getattr(child, "pid", 0) or 0) or None
                    self._status("running", attempts=attempts, child_pid=child_pid)
                    last_returncode = self._wait(child, deadline)
            except (OSError, TypeError, ValueError) as exc:
                self._child = None
                self._status("failed", attempts=attempts, error=type(exc).__name__)
                last_returncode = None
            finally:
                self._child = None
            if self.stop_event.is_set():
                return self._status(
                    "stopped", attempts=attempts, last_returncode=last_returncode
                )
            if deadline is not None and self.monotonic() >= deadline:
                return self._status(
                    "stopped", attempts=attempts, last_returncode=last_returncode
                )
            if self.max_attempts and attempts >= self.max_attempts:
                return self._status(
                    "failed", attempts=attempts, last_returncode=last_returncode
                )
            self._status("backoff", attempts=attempts, last_returncode=last_returncode)
            if self.restart_backoff_seconds:
                self.sleep(self.restart_backoff_seconds)
        return self._status("stopped", attempts=attempts, last_returncode=last_returncode)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ssh-executable", default="ssh")
    parser.add_argument("--ssh-config", required=True)
    parser.add_argument("--identity-file", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--central-port", required=True, type=int)
    parser.add_argument("--worker-port", required=True, type=int)
    parser.add_argument("--status-path", required=True)
    parser.add_argument("--log-path", required=True)
    parser.add_argument("--max-attempts", type=int, default=3)
    parser.add_argument("--restart-backoff-seconds", type=float, default=5.0)
    parser.add_argument("--max-runtime-seconds", type=float, default=0.0)
    args = parser.parse_args(argv)
    try:
        command = build_ssh_argv(
            ssh_executable=args.ssh_executable,
            ssh_config=args.ssh_config,
            identity_file=args.identity_file,
            target=args.target,
            central_port=args.central_port,
            worker_port=args.worker_port,
        )
        supervisor = ReverseTunnelSupervisor(
            command,
            status_path=args.status_path,
            log_path=args.log_path,
            max_attempts=args.max_attempts,
            restart_backoff_seconds=args.restart_backoff_seconds,
            max_runtime_seconds=args.max_runtime_seconds,
        )

        def stop(_signum: int, _frame: Any) -> None:
            supervisor.request_stop()

        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        result = supervisor.run()
    except (SupervisorError, OSError, ValueError) as exc:
        print(json.dumps({"schema_version": SCHEMA_VERSION, "state": "error", "error": type(exc).__name__}, sort_keys=True))
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result.get("state") in {"stopped", "running"} else 1


__all__ = ["ReverseTunnelSupervisor", "SupervisorError", "build_ssh_argv"]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
