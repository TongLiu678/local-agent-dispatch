"""Bounded process-group execution helper.

Starts a child process (and any grandchildren) in a dedicated process group
so the entire tree can be signalled on timeout.  On POSIX the child gets its
own session via ``os.setsid``; on Windows a new process group is created via
``CREATE_NEW_PROCESS_GROUP`` and cleanup falls back to ``taskkill /T /F``.
"""

from __future__ import annotations

import os
import pathlib
import signal
import subprocess
import sys
import importlib.util
from dataclasses import dataclass

try:
    from resource_admission import LocalLaunchAdmissionError, check_local_launch
except ImportError:  # pragma: no cover - direct package loading fallback
    _admission_path = pathlib.Path(__file__).with_name("resource_admission.py")
    _admission_spec = importlib.util.spec_from_file_location("resource_admission", _admission_path)
    if _admission_spec is not None and _admission_spec.loader is not None:
        _admission_module = importlib.util.module_from_spec(_admission_spec)
        sys.modules.setdefault("resource_admission", _admission_module)
        _admission_spec.loader.exec_module(_admission_module)
        LocalLaunchAdmissionError = _admission_module.LocalLaunchAdmissionError
        check_local_launch = _admission_module.check_local_launch
    else:  # pragma: no cover - missing bundled helper
        LocalLaunchAdmissionError = None  # type: ignore[assignment,misc]
        check_local_launch = None  # type: ignore[assignment]

_IS_WINDOWS = sys.platform == "win32"

_GRACE_PERIOD_SECONDS = 3
_TIMEOUT_RETURNCODE = 124


@dataclass(frozen=True, slots=True)
class ProcessGroupResult:
    """Result of a process-group execution.

    Attributes:
        stdout: Combined stdout and stderr of the child process.
        returncode: Exit code of the child, or 124 if the process timed out.
        timed_out: ``True`` when the process was killed due to timeout.
    """

    stdout: str
    returncode: int
    timed_out: bool


def _kill_process_group_posix(proc: subprocess.Popen[bytes]) -> None:
    """Send SIGTERM then SIGKILL to the child's process group (POSIX)."""
    pgid = proc.pid
    try:
        os.killpg(pgid, signal.SIGTERM)
    except OSError:
        # Process (group) already dead – nothing to do.
        return

    try:
        proc.wait(timeout=_GRACE_PERIOD_SECONDS)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(pgid, signal.SIGKILL)
        except OSError:
            pass


def _kill_process_group_windows(proc: subprocess.Popen[bytes]) -> None:
    """Best-effort recursive kill via ``taskkill`` (Windows)."""
    try:
        subprocess.run(
            ["taskkill", "/T", "/F", "/PID", str(proc.pid)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=_GRACE_PERIOD_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired):
        pass


def run_in_process_group(
    argv: list[str],
    *,
    cwd: str | None = None,
    stdin_data: str | None = None,
    timeout_seconds: int = 3600,
    pid_path: str | None = None,
    local_admission: bool = False,
    local_admission_label: str = "local_agent",
    local_admission_paths: tuple[str, ...] = (),
) -> ProcessGroupResult:
    """Run *argv* in a new process group with an optional timeout.

    Parameters:
        argv: Command and arguments to execute.
        cwd: Working directory for the child process.
        stdin_data: Optional string piped to the child's stdin.
        timeout_seconds: Maximum wall-clock seconds before the process group
            is terminated.  Defaults to one hour.
        pid_path: Optional controller-confined breadcrumb containing the live
            child PID.  It is removed when the process exits.

    Returns:
        A :class:`ProcessGroupResult` containing captured output, exit code,
        and whether the execution timed out.
    """
    if local_admission:
        if check_local_launch is None or LocalLaunchAdmissionError is None:  # pragma: no cover
            raise RuntimeError("local launch admission helper is unavailable")
        admission = check_local_launch(
            cwd,
            additional_paths=tuple(
                item for item in ((pid_path,) if pid_path else ()) + tuple(local_admission_paths)
                if item
            ),
            label=local_admission_label,
        )
        if not admission.get("allowed"):
            raise LocalLaunchAdmissionError(admission)

    popen_kwargs: dict[str, object] = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.STDOUT,
    }

    if cwd is not None:
        popen_kwargs["cwd"] = cwd

    if stdin_data is not None:
        popen_kwargs["stdin"] = subprocess.PIPE

    if _IS_WINDOWS:
        popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]
    else:
        # `start_new_session` is the thread-safe subprocess equivalent of
        # `setsid`; avoid `preexec_fn` because the controller may later gain
        # parallel lanes and Python warns against running arbitrary code after
        # fork in a multi-threaded process.
        popen_kwargs["start_new_session"] = True

    proc = subprocess.Popen(argv, **popen_kwargs)  # type: ignore[call-overload]
    pid_file = pathlib.Path(pid_path).expanduser() if pid_path else None
    try:
        if pid_file is not None:
            # The controller supplies this path only after workspace
            # confinement. Keep the runner generic but write just the child
            # PID; no argv or prompt content is persisted.
            pid_file.parent.mkdir(parents=True, exist_ok=True)
            pid_file.write_text(f"{proc.pid}\n", encoding="utf-8")
        encoded_input = stdin_data.encode() if stdin_data is not None else None
        raw_output, _ = proc.communicate(
            input=encoded_input,
            timeout=timeout_seconds,
        )
        return ProcessGroupResult(
            stdout=raw_output.decode(errors="replace"),
            returncode=proc.returncode,
            timed_out=False,
        )
    except subprocess.TimeoutExpired as exc:
        # Capture any partial output attached to the exception.
        partial = exc.stdout or b""

        # Kill the entire process group.
        if _IS_WINDOWS:
            _kill_process_group_windows(proc)
        else:
            _kill_process_group_posix(proc)

        # Drain whatever remains in the pipe after killing.
        try:
            remaining, _ = proc.communicate(timeout=_GRACE_PERIOD_SECONDS)
        except subprocess.TimeoutExpired:
            remaining = b""

        combined = partial + remaining
        return ProcessGroupResult(
            stdout=combined.decode(errors="replace"),
            returncode=_TIMEOUT_RETURNCODE,
            timed_out=True,
        )
    finally:
        if pid_file is not None:
            try:
                pid_file.unlink()
            except FileNotFoundError:
                pass
        # Belt-and-suspenders: make sure the child is truly gone.
        if proc.poll() is None:
            proc.kill()
            try:
                proc.wait(timeout=_GRACE_PERIOD_SECONDS)
            except subprocess.TimeoutExpired:
                pass
