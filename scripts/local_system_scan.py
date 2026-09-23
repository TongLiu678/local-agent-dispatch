#!/usr/bin/env python3
"""Emit a privacy-preserving, read-only inventory of the local dispatch host.

The scanner never queries provider catalogs, authentication state, quota APIs,
or model endpoints.  External commands are limited to local version, hardware,
and process-name probes.  Process arguments are deliberately never collected.
"""

from __future__ import annotations

import argparse
import ctypes
import datetime as dt
import json
import os
import pathlib
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from typing import Any


SCHEMA_VERSION = 1
DEFAULT_TIMEOUT_SECONDS = 4.0
MINIMUM_PYTHON = (3, 10)

CLI_VERSION_ARGS: dict[str, tuple[str, ...]] = {
    "codex": ("--version",),
    # Cursor Desktop and the standalone Cursor Agent are separate
    # capabilities.  Never invoke `cursor agent` as a discovery fallback: the
    # desktop wrapper may install software as a side effect.
    "cursor": ("--version",),
    "cursor-agent": ("--version",),
    "antigravity": ("--version",),
    "opencode": ("--version",),
    "ollama": ("--version",),
    "vllm": ("--version",),
    "llama-server": ("--version",),
    "docker": ("--version",),
    "ssh": ("-V",),
}

# `ollama --version` attempts to contact the local Ollama service.  Presence is
# still useful, but version discovery must remain static to keep this scanner
# free of even loopback network probes.
STATIC_ONLY_VERSION_CLIS = {"ollama"}

PROCESS_NAMES: dict[str, tuple[str, str]] = {
    "codex": ("codex", "agent"),
    "cursor-agent": ("cursor-agent", "agent"),
    "antigravity": ("antigravity", "agent"),
    "opencode": ("opencode", "agent"),
    "ollama": ("ollama", "model_runtime"),
    "vllm": ("vllm", "model_runtime"),
    "llama-server": ("llama-server", "model_runtime"),
    "llama_cpp_server": ("llama_cpp_server", "model_runtime"),
    "local-ai": ("local-ai", "model_runtime"),
    "localai": ("localai", "model_runtime"),
    "xinference": ("xinference", "model_runtime"),
    "text-generation-launcher": ("text-generation-launcher", "model_runtime"),
    "tritonserver": ("tritonserver", "model_runtime"),
}

ANSI_ESCAPE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")


def utc_now() -> str:
    return dt.datetime.now(tz=dt.timezone.utc).isoformat()


def _safe_environment() -> dict[str, str]:
    """Return a minimal environment without tokens or provider credentials."""
    allowed = (
        "PATH",
        "PATHEXT",
        "HOME",
        "USERPROFILE",
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "TMPDIR",
        "TMP",
        "TEMP",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TERM",
    )
    environment = {key: os.environ[key] for key in allowed if key in os.environ}
    # Cursor's shell launcher enables Node's compile cache by default.  A
    # version probe must not create or update that cache.
    environment["NODE_DISABLE_COMPILE_CACHE"] = "1"
    environment["NODE_COMPILE_CACHE"] = os.devnull
    return environment


def _run_command(argv: list[str], timeout: float) -> dict[str, Any]:
    """Run one bounded local-only probe and return sanitized control metadata."""
    try:
        completed = subprocess.run(
            argv,
            cwd=tempfile.gettempdir(),
            env=_safe_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=max(0.2, timeout),
            check=False,
        )
        return {
            "ok": completed.returncode == 0,
            "returncode": completed.returncode,
            "stdout": completed.stdout or "",
            "stderr": completed.stderr or "",
            "timed_out": False,
        }
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "returncode": 124,
            "stdout": "",
            "stderr": "",
            "timed_out": True,
        }
    except OSError:
        return {
            "ok": False,
            "returncode": 127,
            "stdout": "",
            "stderr": "",
            "timed_out": False,
        }


def _clean_single_line(value: str, limit: int = 300) -> str | None:
    clean = ANSI_ESCAPE.sub("", value or "")
    for line in clean.splitlines():
        line = " ".join(line.split())
        if line:
            return line[:limit]
    return None


def _display_path(value: pathlib.Path | str) -> str:
    """Make user-scoped paths useful without publishing the local username."""
    path = pathlib.Path(value).expanduser()
    try:
        home = pathlib.Path.home()
        relative = path.relative_to(home)
        return "~" if str(relative) == "." else str(pathlib.Path("~") / relative)
    except (OSError, ValueError):
        return str(path)


def _gib(value: int | None) -> float | None:
    return None if value is None else round(value / (1024**3), 3)


def python_runtime_evidence(
    version_info: tuple[int, ...] | None = None,
    executable: str | None = None,
) -> dict[str, Any]:
    """Describe whether this interpreter can safely run the dispatch package."""

    observed = tuple(version_info or tuple(sys.version_info[:3]))
    normalized = tuple(int(part) for part in observed[:3])
    while len(normalized) < 3:
        normalized += (0,)
    supported = normalized[:2] >= MINIMUM_PYTHON
    return {
        "version": ".".join(str(part) for part in normalized),
        "implementation": platform.python_implementation(),
        "executable": _display_path(executable or sys.executable),
        "minimum_version": ".".join(str(part) for part in MINIMUM_PYTHON),
        "supported": supported,
    }


def _int_or_none(value: Any) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _local_command(name: str) -> str | None:
    return shutil.which(name)


def static_version_from_executable(name: str, executable: str) -> str | None:
    """Extract versions embedded in local package-manager paths without running a CLI."""
    try:
        parts = pathlib.Path(executable).resolve(strict=True).parts
    except OSError:
        return None
    for marker in ("Cellar", "Caskroom"):
        try:
            index = parts.index(marker)
        except ValueError:
            continue
        if index + 2 >= len(parts):
            continue
        package = parts[index + 1].lower()
        candidate = parts[index + 2]
        if package == name.lower() and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,99}", candidate):
            return candidate
    return None


def _sysctl_value(name: str, timeout: float) -> str | None:
    executable = _local_command("sysctl")
    if not executable:
        return None
    result = _run_command([executable, "-n", name], timeout)
    if not result["ok"]:
        return None
    return _clean_single_line(result["stdout"], limit=500)


def parse_proc_cpuinfo(text: str) -> tuple[int | None, str | None]:
    """Return physical core count and model without exposing unrelated fields."""
    physical_cores: set[tuple[str, str]] = set()
    processor_count = 0
    model: str | None = None
    for block in re.split(r"\n\s*\n", text.strip()):
        values: dict[str, str] = {}
        for line in block.splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            values[key.strip().lower()] = value.strip()
        if "processor" in values:
            processor_count += 1
        if "physical id" in values and "core id" in values:
            physical_cores.add((values["physical id"], values["core id"]))
        if model is None:
            model = values.get("model name") or values.get("hardware") or values.get("processor")
    physical = len(physical_cores) or None
    if physical is None and processor_count == 1:
        physical = 1
    return physical, _clean_single_line(model or "", limit=300)


def scan_cpu(system_name: str, timeout: float) -> dict[str, Any]:
    logical = os.cpu_count()
    physical: int | None = None
    model = _clean_single_line(platform.processor(), limit=300)
    source = "python"

    if system_name == "Darwin":
        logical = _int_or_none(_sysctl_value("hw.logicalcpu", timeout)) or logical
        physical = _int_or_none(_sysctl_value("hw.physicalcpu", timeout))
        model = (
            _sysctl_value("machdep.cpu.brand_string", timeout)
            or _sysctl_value("hw.model", timeout)
            or model
        )
        source = "sysctl"
    elif system_name == "Linux":
        try:
            text = pathlib.Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        parsed_physical, parsed_model = parse_proc_cpuinfo(text)
        physical = parsed_physical
        model = parsed_model or model
        source = "procfs" if text else "python"
    elif system_name == "Windows":
        powershell = _local_command("powershell") or _local_command("pwsh")
        if powershell:
            command = (
                "$c=Get-CimInstance Win32_Processor; "
                "[pscustomobject]@{Physical=($c|Measure-Object NumberOfCores -Sum).Sum; "
                "Logical=($c|Measure-Object NumberOfLogicalProcessors -Sum).Sum; "
                "Model=($c|Select-Object -First 1 -ExpandProperty Name)}|ConvertTo-Json -Compress"
            )
            result = _run_command([powershell, "-NoProfile", "-NonInteractive", "-Command", command], timeout)
            try:
                payload = json.loads(result["stdout"]) if result["ok"] else {}
            except ValueError:
                payload = {}
            physical = _int_or_none(payload.get("Physical"))
            logical = _int_or_none(payload.get("Logical")) or logical
            model = _clean_single_line(str(payload.get("Model") or model or ""), limit=300)
            source = "windows_cim" if payload else "python"

    load_1m: float | None = None
    load_source: str | None = None
    # A logical-core count is a capacity ceiling, not the amount of CPU that
    # can safely be reserved for a new lane.  On POSIX systems the one-minute
    # load average is a cheap, read-only signal that lets the planner make a
    # conservative idle-capacity estimate.  Keep it explicitly unknown on
    # platforms where the signal is unavailable instead of fabricating zero.
    try:
        load_1m = float(os.getloadavg()[0])
        if load_1m >= 0:
            load_source = "os.getloadavg"
        else:
            load_1m = None
    except (AttributeError, OSError):
        load_1m = None

    return {
        "logical_cores": logical,
        "physical_cores": physical,
        "model": model,
        "source": source,
        "load_1m": load_1m,
        "load_source": load_source,
    }


def _parse_meminfo_values(text: str) -> dict[str, int]:
    values: dict[str, int] = {}
    for line in text.splitlines():
        match = re.match(r"^([A-Za-z_()]+):\s+(\d+)\s+kB\s*$", line)
        if match:
            values[match.group(1)] = int(match.group(2)) * 1024
    return values


def parse_meminfo_details(text: str) -> tuple[int | None, int | None, str]:
    """Return total/available memory plus the evidence source.

    ``MemAvailable`` was added after the old RHEL/CentOS 6 kernels that are
    still common on shared clusters.  Falling back to ``MemFree`` alone makes
    a healthy host look almost full because reclaimable page cache and buffers
    are omitted.  The legacy estimate keeps those buckets disjoint from used
    anonymous memory and is explicitly labelled so admission/reporting can
    distinguish it from the kernel-provided value.
    """

    values = _parse_meminfo_values(text)
    total = values.get("MemTotal")
    if "MemAvailable" in values:
        return total, values["MemAvailable"], "procfs"
    free = values.get("MemFree")
    if free is None:
        return total, None, "unknown"
    reclaimable = free + values.get("Buffers", 0) + values.get("Cached", 0)
    return total, reclaimable, "procfs_legacy_estimate"


def parse_meminfo(text: str) -> tuple[int | None, int | None]:
    """Return total/available memory with a safe old-kernel fallback."""

    total, available, _ = parse_meminfo_details(text)
    return total, available


def parse_psi_memory(text: str) -> float | None:
    """Return Linux PSI ``some`` pressure (avg10) without fabricating it."""

    match = re.search(r"(?:^|\n)some\s+avg10=([0-9]+(?:\.[0-9]+)?)", text)
    if not match:
        return None
    try:
        value = float(match.group(1))
    except (TypeError, ValueError):
        return None
    return value if 0.0 <= value <= 100.0 else None


def parse_cgroup_v2_memory(text: str) -> dict[str, Any]:
    """Parse cgroup-v2 memory counters and preserve unknown values.

    ``memory.max=max`` is deliberately represented as an unknown finite
    capacity.  Admission may only use this record when both current and a
    finite maximum are present; callers can still retain the event counters as
    diagnostic pressure evidence.
    """

    values: dict[str, Any] = {
        "cgroup_memory_max_bytes": None,
        "cgroup_memory_current_bytes": None,
        "cgroup_memory_available_bytes": None,
        "cgroup_memory_events_high": None,
        "cgroup_memory_events_oom": None,
        "cgroup_memory_events_oom_kill": None,
        "cgroup_memory_source": "cgroup_v2",
        "cgroup_memory_evidence_status": "unknown",
        "cgroup_memory_unbounded": False,
    }
    for line in text.splitlines():
        key, _, raw = line.strip().partition(" ")
        raw = raw.strip()
        if key == "memory.max":
            if raw != "max":
                values["cgroup_memory_max_bytes"] = _int_or_none(raw)
        elif key == "memory.current":
            values["cgroup_memory_current_bytes"] = _int_or_none(raw)
        elif key in {"high", "oom", "oom_kill"}:
            parsed = _int_or_none(raw)
            values[f"cgroup_memory_events_{key}"] = parsed
    maximum = values["cgroup_memory_max_bytes"]
    current = values["cgroup_memory_current_bytes"]
    if maximum is not None and maximum > 0 and current is not None and 0 <= current <= maximum:
        values["cgroup_memory_available_bytes"] = maximum - current
        values["cgroup_memory_evidence_status"] = "complete"
    return values


def parse_cgroup_v1_memory(text: str) -> dict[str, Any]:
    """Parse cgroup-v1 memory files without treating an unlimited cap as unknown.

    CentOS/RHEL 6 workers expose ``memory.limit_in_bytes`` and
    ``memory.usage_in_bytes`` rather than the cgroup-v2 files.  The kernel's
    ``LONG_MAX``-style limit is an explicit unlimited boundary, not a finite
    capacity; retain that distinction so callers can safely use the host
    ``MemAvailable`` estimate while still recording that the memory controller
    was observed.
    """

    values: dict[str, Any] = {
        "cgroup_memory_max_bytes": None,
        "cgroup_memory_current_bytes": None,
        "cgroup_memory_available_bytes": None,
        "cgroup_memory_events_high": None,
        "cgroup_memory_events_oom": None,
        "cgroup_memory_events_oom_kill": None,
        "cgroup_memory_source": "cgroup_v1",
        "cgroup_memory_evidence_status": "unknown",
        "cgroup_memory_unbounded": False,
    }
    for line in text.splitlines():
        key, _, raw = line.strip().partition(" ")
        raw = raw.strip()
        if key not in {"memory.limit_in_bytes", "memory.usage_in_bytes"}:
            continue
        parsed = _int_or_none(raw)
        if key == "memory.limit_in_bytes":
            # cgroup-v1 uses a signed-long-sized sentinel for no limit.  Keep
            # the threshold broad enough for 32/64-bit kernels while refusing
            # to turn an arbitrary malformed huge value into a finite cap.
            if parsed is not None and parsed >= 1 << 60:
                values["cgroup_memory_unbounded"] = True
            else:
                values["cgroup_memory_max_bytes"] = parsed
        else:
            values["cgroup_memory_current_bytes"] = parsed
    maximum = values["cgroup_memory_max_bytes"]
    current = values["cgroup_memory_current_bytes"]
    if values["cgroup_memory_unbounded"] and current is not None and current >= 0:
        values["cgroup_memory_evidence_status"] = "unbounded"
    elif maximum is not None and maximum > 0 and current is not None and 0 <= current <= maximum:
        values["cgroup_memory_available_bytes"] = maximum - current
        values["cgroup_memory_evidence_status"] = "complete"
    return values


def _read_cgroup_v2_memory() -> dict[str, Any]:
    """Read only this process' cgroup-v2 memory files, fail-closed on errors."""

    unknown = parse_cgroup_v2_memory("")
    try:
        rel = pathlib.Path("/proc/self/cgroup").read_text(
            encoding="utf-8", errors="replace"
        )
    except OSError:
        return unknown
    match = re.search(r"^0::(/[^\n]*)$", rel, flags=re.MULTILINE)
    if not match:
        return unknown
    relative = match.group(1).lstrip("/")
    base = pathlib.Path("/sys/fs/cgroup").resolve()
    root = (base / relative).resolve()
    try:
        root.relative_to(base)
    except ValueError:
        return unknown
    try:
        max_text = (root / "memory.max").read_text(encoding="utf-8", errors="replace")
        current_text = (root / "memory.current").read_text(encoding="utf-8", errors="replace")
        events_text = ""
        events_path = root / "memory.events"
        if events_path.is_file():
            events_text = events_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return unknown
    return parse_cgroup_v2_memory(
        f"memory.max {max_text.strip()}\n"
        f"memory.current {current_text.strip()}\n{events_text}"
    )


def _read_cgroup_v1_memory() -> dict[str, Any]:
    """Read this process' cgroup-v1 memory files, failing closed on errors."""

    unknown = parse_cgroup_v1_memory("")
    try:
        cgroup_text = pathlib.Path("/proc/self/cgroup").read_text(
            encoding="utf-8", errors="replace"
        )
        mounts_text = pathlib.Path("/proc/mounts").read_text(
            encoding="utf-8", errors="replace"
        )
    except OSError:
        return unknown
    relative: str | None = None
    for line in cgroup_text.splitlines():
        hierarchy, _, path = line.partition(":")
        if not hierarchy or ":" not in line:
            continue
        subsystems, _, path = path.partition(":")
        if "memory" in {item for item in subsystems.split(",") if item}:
            relative = path.lstrip("/")
            break
    if relative is None:
        return unknown
    mountpoint: pathlib.Path | None = None
    for line in mounts_text.splitlines():
        try:
            fields = shlex.split(line)
        except ValueError:
            continue
        if len(fields) < 4 or fields[2] != "cgroup":
            continue
        options = set(fields[3].split(","))
        if "memory" in options:
            mountpoint = pathlib.Path(fields[1])
            break
    if mountpoint is None:
        return unknown
    base = mountpoint.resolve()
    root = (base / relative).resolve()
    try:
        root.relative_to(base)
    except ValueError:
        return unknown
    try:
        limit_text = (root / "memory.limit_in_bytes").read_text(
            encoding="utf-8", errors="replace"
        )
        usage_text = (root / "memory.usage_in_bytes").read_text(
            encoding="utf-8", errors="replace"
        )
    except OSError:
        return unknown
    return parse_cgroup_v1_memory(
        f"memory.limit_in_bytes {limit_text.strip()}\n"
        f"memory.usage_in_bytes {usage_text.strip()}\n"
    )


def _read_cgroup_memory() -> dict[str, Any]:
    """Read the active Linux cgroup memory controller (v2, then v1)."""

    v2 = _read_cgroup_v2_memory()
    if v2.get("cgroup_memory_evidence_status") != "unknown":
        return v2
    return _read_cgroup_v1_memory()


def parse_vm_stat(text: str, page_size: int) -> int | None:
    """Estimate reclaimable macOS memory from non-sensitive vm_stat counters."""
    page_counts: dict[str, int] = {}
    for line in text.splitlines():
        match = re.match(
            r"^Pages (free|inactive|speculative|purgeable):\s+(\d+)\.?\s*$",
            line.strip(),
            flags=re.IGNORECASE,
        )
        if match:
            page_counts[match.group(1).lower()] = int(match.group(2))
    if not page_counts or page_size <= 0:
        return None
    return sum(page_counts.values()) * page_size


def parse_swapusage(text: str) -> dict[str, int | None]:
    """Parse macOS ``sysctl vm.swapusage`` without retaining raw output."""
    values: dict[str, int | None] = {
        "swap_total_bytes": None,
        "swap_used_bytes": None,
        "swap_free_bytes": None,
    }
    units = {"k": 1024, "m": 1024**2, "g": 1024**3, "t": 1024**4}
    for name, raw, unit in re.findall(
        r"\b(total|used|free)\s*=\s*([0-9]+(?:\.[0-9]+)?)\s*([KMGT])",
        text,
        flags=re.IGNORECASE,
    ):
        # The regex above is intentionally strict; a malformed or localized
        # line stays unknown instead of becoming a fabricated zero.
        match = re.search(
            rf"\b{name}\s*=\s*([0-9]+(?:\.[0-9]+)?)\s*([KMGT])",
            text,
            flags=re.IGNORECASE,
        )
        if not match:
            continue
        number, unit = match.groups()
        key = f"swap_{name.lower()}_bytes"
        values[key] = int(float(number) * units[unit.lower()])
    return values


def parse_memory_pressure(text: str) -> int | None:
    """Parse macOS ``memory_pressure -Q`` free percentage."""
    match = re.search(r"memory\s+free\s+percentage\s*:\s*([0-9]+(?:\.[0-9]+)?)%", text, re.I)
    if not match:
        return None
    try:
        value = float(match.group(1))
    except ValueError:
        return None
    return int(round(value)) if 0.0 <= value <= 100.0 else None


def parse_linux_swap(text: str) -> dict[str, int | None]:
    """Parse SwapTotal/SwapFree from Linux meminfo."""
    values: dict[str, int | None] = {
        "swap_total_bytes": None,
        "swap_used_bytes": None,
        "swap_free_bytes": None,
    }
    raw: dict[str, int] = {}
    for line in text.splitlines():
        match = re.match(r"^(SwapTotal|SwapFree):\s+(\d+)\s+kB\s*$", line)
        if match:
            raw[match.group(1)] = int(match.group(2)) * 1024
    total = raw.get("SwapTotal")
    free = raw.get("SwapFree")
    values["swap_total_bytes"] = total
    values["swap_free_bytes"] = free
    if total is not None and free is not None:
        values["swap_used_bytes"] = max(0, total - free)
    return values


def _memory_pressure_state(
    *,
    total_bytes: int | None,
    available_bytes: int | None,
    swap_total_bytes: int | None,
    swap_free_bytes: int | None,
    pressure_free_percent: int | None,
    psi_some_avg10: float | None = None,
    cgroup_memory_events_oom: int | None = None,
    cgroup_memory_events_oom_kill: int | None = None,
) -> str:
    """Classify pressure conservatively for admission, not user diagnostics."""
    available_percent = None
    if total_bytes and available_bytes is not None and total_bytes > 0:
        available_percent = 100.0 * available_bytes / total_bytes
    swap_exhausted = swap_total_bytes is not None and swap_total_bytes > 0 and swap_free_bytes == 0
    swap_used_percent = None
    if swap_total_bytes and swap_free_bytes is not None and swap_total_bytes > 0:
        swap_used_percent = 100.0 * max(0, swap_total_bytes - swap_free_bytes) / swap_total_bytes
    # macOS can report a healthy instantaneous ``memory_pressure`` percentage
    # while the compressor has already pushed most pages into swap.  That is a
    # delayed warning for an agent launcher: the next large context can still
    # force a global reclaim/pause.  Treat high swap occupancy as conserve
    # pressure, and reserve critical for a nearly full swap combined with low
    # headroom.  Unknown values remain unknown rather than being fabricated.
    swap_high = swap_used_percent is not None and swap_used_percent >= 85.0
    swap_critical = swap_used_percent is not None and swap_used_percent >= 95.0
    psi_critical = psi_some_avg10 is not None and psi_some_avg10 >= 20.0
    psi_high = psi_some_avg10 is not None and psi_some_avg10 >= 5.0
    cgroup_oom = (cgroup_memory_events_oom or 0) > 0
    cgroup_oom_kill = (cgroup_memory_events_oom_kill or 0) > 0
    if (swap_exhausted and available_percent is not None and available_percent < 25.0) or (
        swap_critical and available_percent is not None and available_percent < 35.0
    ) or (
        available_percent is not None and available_percent < 8.0
    ) or (pressure_free_percent is not None and pressure_free_percent < 10) or psi_critical or cgroup_oom_kill:
        return "critical"
    if swap_exhausted or swap_high or (available_percent is not None and available_percent < 20.0) or (
        pressure_free_percent is not None and pressure_free_percent < 20
    ) or psi_high or cgroup_oom:
        return "conserve"
    if available_percent is None:
        return "unknown"
    return "normal"


def _windows_memory() -> tuple[int | None, int | None]:
    class MEMORYSTATUSEX(ctypes.Structure):
        _fields_ = [
            ("dwLength", ctypes.c_ulong),
            ("dwMemoryLoad", ctypes.c_ulong),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]

    status = MEMORYSTATUSEX()
    status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
    try:
        ok = ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status))
    except (AttributeError, OSError):
        return None, None
    if not ok:
        return None, None
    return int(status.ullTotalPhys), int(status.ullAvailPhys)


def scan_ram(system_name: str, timeout: float) -> dict[str, Any]:
    total: int | None = None
    available: int | None = None
    source = "unknown"
    swap: dict[str, int | None] = {
        "swap_total_bytes": None,
        "swap_used_bytes": None,
        "swap_free_bytes": None,
    }
    pressure_free_percent: int | None = None
    pressure_source: str | None = None
    psi_some_avg10: float | None = None
    cgroup: dict[str, Any] = {}
    if system_name == "Linux":
        try:
            text = pathlib.Path("/proc/meminfo").read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        total, available, source = parse_meminfo_details(text)
        swap = parse_linux_swap(text)
        if total is None:
            source = "unknown"
        pressure_path = pathlib.Path("/proc/pressure/memory")
        try:
            pressure_text = pressure_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            pressure_text = ""
        psi_some_avg10 = parse_psi_memory(pressure_text)
        if psi_some_avg10 is not None:
            pressure_source = "procfs_psi_memory"
        # Linux workers can be constrained below the host's /proc/meminfo
        # capacity.  Keep this evidence separate and make it mandatory for
        # controller admission on Linux; an unreadable cgroup is unknown.
        cgroup = _read_cgroup_memory()
    elif system_name == "Darwin":
        total = _int_or_none(_sysctl_value("hw.memsize", timeout))
        page_size = _int_or_none(_sysctl_value("hw.pagesize", timeout))
        vm_stat = _local_command("vm_stat")
        if page_size and vm_stat:
            result = _run_command([vm_stat], timeout)
            if result["ok"]:
                available = parse_vm_stat(result["stdout"], page_size)
        if available is None:
            try:
                page_size = int(os.sysconf("SC_PAGE_SIZE"))
                available_pages = int(os.sysconf("SC_AVPHYS_PAGES"))
                available = page_size * available_pages
            except (AttributeError, OSError, TypeError, ValueError):
                available = None
        source = "sysctl+vm_stat" if available is not None else "sysctl"
        sysctl = _local_command("sysctl")
        if sysctl:
            result = _run_command([sysctl, "vm.swapusage"], timeout)
            if result["ok"]:
                swap = parse_swapusage(result["stdout"])
        memory_pressure = _local_command("memory_pressure")
        if memory_pressure:
            result = _run_command([memory_pressure, "-Q"], timeout)
            if result["ok"]:
                pressure_free_percent = parse_memory_pressure(result["stdout"])
                if pressure_free_percent is not None:
                    pressure_source = "memory_pressure"
    elif system_name == "Windows":
        total, available = _windows_memory()
        source = "win32"
    else:
        try:
            page_size = int(os.sysconf("SC_PAGE_SIZE"))
            total = page_size * int(os.sysconf("SC_PHYS_PAGES"))
            available = page_size * int(os.sysconf("SC_AVPHYS_PAGES"))
            source = "sysconf"
        except (AttributeError, OSError, TypeError, ValueError):
            pass
    pressure_state = _memory_pressure_state(
        total_bytes=total,
        available_bytes=available,
        swap_total_bytes=swap["swap_total_bytes"],
        swap_free_bytes=swap["swap_free_bytes"],
        pressure_free_percent=pressure_free_percent,
        psi_some_avg10=psi_some_avg10,
        cgroup_memory_events_oom=cgroup.get("cgroup_memory_events_oom"),
        cgroup_memory_events_oom_kill=cgroup.get("cgroup_memory_events_oom_kill"),
    )
    swap_total = swap["swap_total_bytes"]
    swap_free = swap["swap_free_bytes"]
    swap_free_percent = None
    if swap_total is not None and swap_free is not None and swap_total > 0:
        swap_free_percent = round(100.0 * swap_free / swap_total, 3)
    result = {
        "total_bytes": total,
        "available_bytes": available,
        "total_gib": _gib(total),
        "available_gib": _gib(available),
        "source": source,
        "swap_total_bytes": swap_total,
        "swap_used_bytes": swap["swap_used_bytes"],
        "swap_free_bytes": swap_free,
        "swap_free_percent": swap_free_percent,
        "pressure_free_percent": pressure_free_percent,
        "pressure_source": pressure_source,
        "psi_some_avg10": psi_some_avg10,
        "pressure_state": pressure_state,
    }
    if system_name == "Linux":
        result.update(cgroup)
        result["cgroup_required"] = True
        if cgroup.get("cgroup_memory_evidence_status") == "complete":
            cgroup_source = str(cgroup.get("cgroup_memory_source") or "cgroup")
            result.update(
                total_bytes=cgroup.get("cgroup_memory_max_bytes"),
                available_bytes=cgroup.get("cgroup_memory_available_bytes"),
                total_gib=_gib(cgroup.get("cgroup_memory_max_bytes")),
                available_gib=_gib(cgroup.get("cgroup_memory_available_bytes")),
                source=f"{cgroup_source}_current_max",
            )
            # Reclassify against the effective cgroup boundary.  Keeping the
            # procfs-derived pressure state here would let a host-sized
            # MemAvailable reading re-open local admission for a constrained
            # worker; PSI/swap/oom counters are retained in the same report.
            result["pressure_state"] = _memory_pressure_state(
                total_bytes=result.get("total_bytes"),
                available_bytes=result.get("available_bytes"),
                swap_total_bytes=result.get("swap_total_bytes"),
                swap_free_bytes=result.get("swap_free_bytes"),
                pressure_free_percent=pressure_free_percent,
                psi_some_avg10=psi_some_avg10,
                cgroup_memory_events_oom=cgroup.get("cgroup_memory_events_oom"),
                cgroup_memory_events_oom_kill=cgroup.get("cgroup_memory_events_oom_kill"),
            )
    return result


def _nearest_existing_path(path: pathlib.Path) -> pathlib.Path | None:
    current = path.expanduser().absolute()
    while not current.exists() and current != current.parent:
        current = current.parent
    return current if current.exists() else None


def scan_disk(path: pathlib.Path) -> dict[str, Any]:
    expanded = path.expanduser().absolute()
    probe_path = _nearest_existing_path(expanded)
    result: dict[str, Any] = {
        "path": _display_path(expanded),
        "exists": expanded.exists(),
        "probe_path": _display_path(probe_path) if probe_path else None,
        "writable": os.access(expanded if expanded.exists() else (probe_path or expanded), os.W_OK),
    }
    if probe_path is None:
        result.update(total_bytes=None, used_bytes=None, free_bytes=None, free_gib=None, free_percent=None)
        return result
    try:
        usage = shutil.disk_usage(probe_path)
    except OSError:
        result.update(total_bytes=None, used_bytes=None, free_bytes=None, free_gib=None, free_percent=None)
        return result
    result.update(
        total_bytes=usage.total,
        used_bytes=usage.used,
        free_bytes=usage.free,
        free_gib=_gib(usage.free),
        free_percent=round(100.0 * usage.free / usage.total, 3) if usage.total else None,
    )
    return result


def disk_capacity_gate(disks: dict[str, dict[str, Any]]) -> dict[str, Any]:
    minimum_free_bytes = 20 * 1024**3
    minimum_free_percent = 10.0
    pressured: list[str] = []
    unknown: list[str] = []
    for label, row in disks.items():
        free = row.get("free_bytes")
        free_percent = row.get("free_percent")
        if free is None or free_percent is None:
            unknown.append(label)
            continue
        if int(free) < minimum_free_bytes or float(free_percent) < minimum_free_percent:
            pressured.append(label)
    disk_pressure = bool(pressured)
    return {
        "disk_pressure": disk_pressure,
        "local_bulk_allowed": not disk_pressure and not unknown,
        "pressured_disks": pressured,
        "unknown_disks": unknown,
        "minimum_free_bytes": minimum_free_bytes,
        "minimum_free_percent": minimum_free_percent,
    }


def default_cache_dir(system_name: str) -> pathlib.Path:
    if system_name == "Windows":
        base = pathlib.Path(os.environ.get("LOCALAPPDATA") or pathlib.Path.home() / "AppData" / "Local")
        return base / "local-agent-dispatch" / "Cache"
    if system_name == "Darwin":
        return pathlib.Path.home() / "Library" / "Caches" / "local-agent-dispatch"
    base = pathlib.Path(os.environ.get("XDG_CACHE_HOME") or pathlib.Path.home() / ".cache")
    return base / "local-agent-dispatch"


def _vendor_from_text(text: str) -> str:
    lowered = text.lower()
    if "nvidia" in lowered:
        return "NVIDIA"
    if "advanced micro devices" in lowered or "amd" in lowered or " ati " in f" {lowered} ":
        return "AMD"
    if "intel" in lowered:
        return "Intel"
    if "apple" in lowered:
        return "Apple"
    return "Unknown"


def parse_nvidia_smi(text: str) -> list[dict[str, Any]]:
    accelerators: list[dict[str, Any]] = []
    for line in text.splitlines():
        fields = [field.strip() for field in line.split(",")]
        if len(fields) < 6:
            continue
        try:
            total_mib = float(fields[2])
            free_mib = float(fields[3])
            utilization = float(fields[4])
        except ValueError:
            continue
        accelerators.append(
            {
                "type": "gpu",
                "vendor": "NVIDIA",
                "index": _int_or_none(fields[0]),
                "name": _clean_single_line(fields[1], limit=300),
                "memory_total_bytes": int(total_mib * 1024**2),
                "memory_free_bytes": int(free_mib * 1024**2),
                "utilization_percent": utilization,
                "driver_version": _clean_single_line(fields[5], limit=100),
                "source": "nvidia-smi",
            }
        )
    return accelerators


def parse_lspci(text: str) -> list[dict[str, Any]]:
    accelerators: list[dict[str, Any]] = []
    for line in text.splitlines():
        try:
            fields = shlex.split(line)
        except ValueError:
            continue
        if len(fields) < 4:
            continue
        device_class = fields[1].lower()
        if not any(item in device_class for item in ("vga", "3d controller", "display controller")):
            continue
        vendor = _vendor_from_text(fields[2])
        if vendor == "Unknown":
            continue
        name = _clean_single_line(f"{fields[2]} {fields[3]}", limit=300)
        accelerators.append(
            {
                "type": "gpu",
                "vendor": vendor,
                "name": name,
                "pci_address": fields[0],
                "source": "lspci",
            }
        )
    return accelerators


def parse_system_profiler(text: str) -> list[dict[str, Any]]:
    try:
        payload = json.loads(text)
    except ValueError:
        return []
    rows = payload.get("SPDisplaysDataType") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        return []
    accelerators: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = row.get("sppci_model") or row.get("_name") or row.get("spdisplays_chipset_model")
        vendor_text = str(row.get("spdisplays_vendor") or row.get("sppci_vendor") or name or "")
        if not name:
            continue
        accelerator: dict[str, Any] = {
            "type": "gpu",
            "vendor": _vendor_from_text(vendor_text),
            "name": _clean_single_line(str(name), limit=300),
            "source": "system_profiler",
        }
        cores = _int_or_none(row.get("sppci_cores") or row.get("spdisplays_cores"))
        if cores is not None:
            accelerator["core_count"] = cores
        if accelerator["vendor"] == "Apple":
            accelerator["unified_memory"] = True
        accelerators.append(accelerator)
    return accelerators


def parse_windows_video_controllers(text: str) -> list[dict[str, Any]]:
    try:
        payload = json.loads(text)
    except ValueError:
        return []
    rows = payload if isinstance(payload, list) else [payload]
    accelerators: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict) or not row.get("Name"):
            continue
        memory = _int_or_none(row.get("AdapterRAM"))
        accelerators.append(
            {
                "type": "gpu",
                "vendor": _vendor_from_text(str(row["Name"])),
                "name": _clean_single_line(str(row["Name"]), limit=300),
                "memory_total_bytes": memory,
                "driver_version": _clean_single_line(str(row.get("DriverVersion") or ""), limit=100),
                "source": "windows_cim",
            }
        )
    return accelerators


def _deduplicate_accelerators(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for row in rows:
        key = (str(row.get("vendor") or "").lower(), str(row.get("name") or "").lower())
        if key in seen:
            continue
        if row.get("source") == "lspci" and row.get("vendor") == "NVIDIA" and any(
            item.get("vendor") == "NVIDIA" and item.get("source") == "nvidia-smi" for item in result
        ):
            continue
        seen.add(key)
        result.append(row)
    return result


def scan_accelerators(system_name: str, arch: str, timeout: float) -> tuple[list[dict[str, Any]], list[str]]:
    rows: list[dict[str, Any]] = []
    warnings: list[str] = []
    nvidia_smi = _local_command("nvidia-smi")
    if nvidia_smi:
        result = _run_command(
            [
                nvidia_smi,
                "--query-gpu=index,name,memory.total,memory.free,utilization.gpu,driver_version",
                "--format=csv,noheader,nounits",
            ],
            timeout,
        )
        if result["ok"]:
            rows.extend(parse_nvidia_smi(result["stdout"]))
        else:
            warnings.append("nvidia-smi probe failed")

    if system_name == "Darwin":
        profiler = _local_command("system_profiler")
        if profiler:
            result = _run_command([profiler, "SPDisplaysDataType", "-json"], max(timeout, 6.0))
            if result["ok"]:
                rows.extend(parse_system_profiler(result["stdout"]))
            else:
                warnings.append("system_profiler display probe failed")
        if arch.lower() in {"arm64", "aarch64"} and not any(row.get("vendor") == "Apple" for row in rows):
            chip = _sysctl_value("machdep.cpu.brand_string", timeout) or "Apple Silicon"
            rows.append(
                {
                    "type": "gpu",
                    "vendor": "Apple",
                    "name": chip,
                    "unified_memory": True,
                    "source": "apple_silicon_inference",
                }
            )
    elif system_name == "Linux":
        lspci = _local_command("lspci")
        if lspci:
            result = _run_command([lspci, "-mm", "-nn"], timeout)
            if result["ok"]:
                rows.extend(parse_lspci(result["stdout"]))
            else:
                warnings.append("lspci display probe failed")
    elif system_name == "Windows":
        powershell = _local_command("powershell") or _local_command("pwsh")
        if powershell:
            command = (
                "Get-CimInstance Win32_VideoController|"
                "Select-Object Name,AdapterRAM,DriverVersion|ConvertTo-Json -Compress"
            )
            result = _run_command([powershell, "-NoProfile", "-NonInteractive", "-Command", command], timeout)
            if result["ok"]:
                rows.extend(parse_windows_video_controllers(result["stdout"]))
            else:
                warnings.append("Windows display controller probe failed")
    return _deduplicate_accelerators(rows), warnings


def scan_clis(timeout: float) -> dict[str, dict[str, Any]]:
    clis: dict[str, dict[str, Any]] = {}
    for name, version_args in CLI_VERSION_ARGS.items():
        executable = _local_command(name)
        if not executable:
            clis[name] = {"present": False, "version": None, "version_ok": False}
            continue
        if name in STATIC_ONLY_VERSION_CLIS:
            version = static_version_from_executable(name, executable)
            clis[name] = {
                "present": True,
                "executable": _display_path(executable),
                "version": version,
                "version_ok": version is not None,
                "version_source": "installation_path" if version else None,
            }
            if version is None:
                clis[name]["version_error"] = "safe_static_version_unavailable"
            continue
        result = _run_command([executable, *version_args], timeout)
        version = _clean_single_line(result["stdout"] or result["stderr"]) if result["ok"] else None
        version_error: str | None = None
        if result["timed_out"]:
            version_error = "timeout"
        elif not result["ok"]:
            version_error = f"exit_{result['returncode']}"
        clis[name] = {
            "present": True,
            "executable": _display_path(executable),
            "version": version,
            "version_ok": bool(result["ok"] and version),
        }
        if version_error:
            clis[name]["version_error"] = version_error
    return clis


def classify_process_name(raw_name: str) -> tuple[str, str] | None:
    """Classify a process while returning only a canonical, argument-free name."""
    normalized = raw_name.strip().strip("[]").replace("\\", "/")
    basename = normalized.rsplit("/", 1)[-1].lower()
    if basename.endswith(".exe"):
        basename = basename[:-4]
    for candidate, classification in PROCESS_NAMES.items():
        if basename == candidate or basename.startswith(candidate + " "):
            return classification
    if basename.startswith("codex-"):
        return PROCESS_NAMES["codex"]
    return None


def parse_unix_processes(text: str, current_pid: int) -> list[dict[str, Any]]:
    processes: list[dict[str, Any]] = []
    seen: set[int] = set()
    for line in text.splitlines():
        fields = line.strip().split(None, 2)
        if len(fields) < 2 or not fields[0].isdigit():
            continue
        pid = int(fields[0])
        if pid == current_pid or pid in seen:
            continue
        rss_kib: int | None = None
        command_field = " ".join(fields[1:])
        if len(fields) == 3 and fields[1].isdigit():
            rss_kib = int(fields[1])
            command_field = fields[2]
        classification = classify_process_name(command_field)
        if classification is None:
            continue
        command_name, kind = classification
        row: dict[str, Any] = {"pid": pid, "command_name": command_name, "kind": kind}
        if rss_kib is not None:
            row["rss_kib"] = rss_kib
        processes.append(row)
        seen.add(pid)
    return sorted(processes, key=lambda row: row["pid"])


def parse_windows_processes(text: str, current_pid: int) -> list[dict[str, Any]]:
    try:
        payload = json.loads(text)
    except ValueError:
        return []
    rows = payload if isinstance(payload, list) else [payload]
    processes: list[dict[str, Any]] = []
    for source_row in rows:
        if not isinstance(source_row, dict):
            continue
        pid = _int_or_none(source_row.get("Id"))
        if pid is None or pid == current_pid:
            continue
        classification = classify_process_name(str(source_row.get("ProcessName") or ""))
        if classification is None:
            continue
        command_name, kind = classification
        row: dict[str, Any] = {"pid": pid, "command_name": command_name, "kind": kind}
        working_set = _int_or_none(source_row.get("WorkingSet64"))
        if working_set is not None:
            row["rss_bytes"] = working_set
        processes.append(row)
    return sorted(processes, key=lambda row: row["pid"])


def scan_processes(system_name: str, timeout: float) -> dict[str, Any]:
    if system_name == "Windows":
        powershell = _local_command("powershell") or _local_command("pwsh")
        if not powershell:
            return {"scan_ok": False, "arguments_collected": False, "processes": []}
        command = "Get-Process|Select-Object Id,ProcessName,WorkingSet64|ConvertTo-Json -Compress"
        result = _run_command([powershell, "-NoProfile", "-NonInteractive", "-Command", command], timeout)
        processes = parse_windows_processes(result["stdout"], os.getpid()) if result["ok"] else []
    else:
        ps = _local_command("ps")
        if not ps:
            return {"scan_ok": False, "arguments_collected": False, "processes": []}
        args = [ps, "-axo", "pid=,rss=,comm="] if system_name == "Darwin" else [ps, "-eo", "pid=,rss=,comm="]
        result = _run_command(args, timeout)
        processes = parse_unix_processes(result["stdout"], os.getpid()) if result["ok"] else []
    rss_bytes = 0
    rss_known = False
    for row in processes:
        if row.get("rss_kib") is not None:
            rss_bytes += int(row["rss_kib"]) * 1024
            rss_known = True
        elif row.get("rss_bytes") is not None:
            rss_bytes += int(row["rss_bytes"])
            rss_known = True
    return {
        "scan_ok": bool(result["ok"]),
        "arguments_collected": False,
        "processes": processes,
        "rss_bytes_total": rss_bytes if rss_known else None,
        "rss_source": "ps_rss" if system_name != "Windows" and rss_known else (
            "win32_working_set" if system_name == "Windows" and rss_known else None
        ),
    }


def build_snapshot(workspace: pathlib.Path, cache_dir: pathlib.Path, timeout: float) -> dict[str, Any]:
    system_name = platform.system() or "Unknown"
    arch = platform.machine() or "unknown"
    accelerators, accelerator_warnings = scan_accelerators(system_name, arch, timeout)
    disks = {
        "workspace": scan_disk(workspace),
        "cache": scan_disk(cache_dir),
    }
    capacity = disk_capacity_gate(disks)
    warnings = list(accelerator_warnings)
    ram = scan_ram(system_name, timeout)
    python_runtime = python_runtime_evidence()
    memory_pressure = str(ram.get("pressure_state") or "unknown")
    # A new local lane needs more than RAM: Python/Node startup, lock files,
    # SQLite WAL and temporary output all consume the same filesystem.  The
    # old gate only blocked bulk work, so a nearly-full disk could still fail
    # while creating a child-agent lock.  Keep diagnostics/resume read-only,
    # but fail closed before any new local agent launch when disk evidence is
    # pressured or unknown.
    capacity["local_agent_launch_allowed"] = (
        python_runtime["supported"]
        and memory_pressure not in {"critical", "conserve"}
        and not capacity["disk_pressure"]
        and not capacity["unknown_disks"]
    )
    capacity["python_runtime_supported"] = python_runtime["supported"]
    capacity["memory_pressure_state"] = memory_pressure
    if memory_pressure in {"critical", "conserve"}:
        warnings.append(
            "local memory pressure: new agent lanes are blocked; route compatible work to a remote host"
        )
    if not python_runtime["supported"]:
        warnings.append(
            "local Python runtime is below the required 3.10; new dispatch lanes "
            "are blocked until lad runs under a supported interpreter"
        )
    if capacity["disk_pressure"]:
        warnings.append(
            "local disk pressure: bulk local workloads are blocked for "
            + ", ".join(capacity["pressured_disks"])
        )
        warnings.append("local disk pressure: new agent launches are blocked before lock creation")
    elif capacity["unknown_disks"]:
        warnings.append("local disk capacity is unknown; bulk local workloads are blocked")
        warnings.append("local disk capacity is unknown; new agent launches are blocked")
    return {
        "ok": True,
        "schema_version": SCHEMA_VERSION,
        "scanned_at_utc": utc_now(),
        "scan_policy": {
            "read_only": True,
            "network_probes": False,
            "model_invocations": False,
            "credential_queries": False,
            "provider_auth_queries": False,
            "process_arguments_collected": False,
        },
        "os": {
            "name": system_name,
            "release": platform.release() or None,
            "version": _clean_single_line(platform.version(), limit=500),
        },
        "arch": arch,
        "kernel": {
            "name": system_name,
            "release": platform.release() or None,
            "version": _clean_single_line(platform.version(), limit=500),
        },
        "python": python_runtime,
        "cpu": scan_cpu(system_name, timeout),
        "ram": ram,
        "disks": disks,
        "capacity_gates": capacity,
        "accelerators": accelerators,
        "clis": scan_clis(timeout),
        "agent_model_processes": scan_processes(system_name, timeout),
        "warnings": warnings,
    }


def write_json(payload: dict[str, Any], output: str | None, compact: bool) -> None:
    text = json.dumps(
        payload,
        ensure_ascii=False,
        indent=None if compact else 2,
        separators=(",", ":") if compact else None,
        sort_keys=True,
    ) + "\n"
    if not output or output == "-":
        print(text, end="")
        return
    target = pathlib.Path(output).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(target.suffix + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    temporary.replace(target)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", default=str(pathlib.Path.cwd()), help="workspace disk to inspect")
    parser.add_argument("--cache-dir", help="dispatch cache disk to inspect without creating it")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--output", default="-", help="JSON output path, or - for stdout")
    parser.add_argument("--compact", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    timeout = max(0.2, min(float(args.timeout), 30.0))
    system_name = platform.system() or "Unknown"
    workspace = pathlib.Path(args.workspace).expanduser()
    cache_dir = pathlib.Path(args.cache_dir).expanduser() if args.cache_dir else default_cache_dir(system_name)
    try:
        payload = build_snapshot(workspace, cache_dir, timeout)
    except Exception as exc:
        payload = {
            "ok": False,
            "schema_version": SCHEMA_VERSION,
            "scanned_at_utc": utc_now(),
            "error": f"local scan failed: {type(exc).__name__}",
        }
    write_json(payload, args.output, args.compact)
    return 0 if payload.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
