#!/usr/bin/env python3
"""Probe local and SSH compute hosts into scheduler-ready JSON state."""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import hashlib
import json
import pathlib
import re
import shlex
import subprocess
import sys
import time
from typing import Any

# Keep remote process attribution on the same conservative classifier used by
# the local preflight.  The import is intentionally one-way: the preflight
# module does not import this probe, and the classifier only inspects the
# transient command string in memory.  No raw argv is returned by this module.
from dispatch_preflight_scan import pool_for_process


# Route verification is a short-lived admission input, not a permanent host
# capability. Keep the TTL in projected evidence so downstream split
# placement can reject stale preflight snapshots without retaining egress IPs.
RACKNERD_ROUTE_TTL_SECONDS = 900
# External connectivity is also a short-lived host capability.  The probe only
# checks public, unauthenticated control endpoints; it never sends a provider
# prompt, reads an auth store, or records DNS answers/egress identities.
EXTERNAL_NETWORK_EVIDENCE_TTL_SECONDS = 900
# Wall-clock timestamps are used by receipts and quota windows, while the
# durable run loop uses a monotonic deadline for elapsed time.  A host clock
# that differs materially from the controller can nevertheless make a future
# receipt look stale (or a planned end look already expired).  Keep this
# threshold explicit in the bounded probe so callers can opt into a
# fail-closed temporal gate without inferring it from a hostname or port.
MAX_CLOCK_SKEW_SECONDS = 60.0
EXTERNAL_NETWORK_TARGETS = ("github.com", "opencode.ai")
_RUNTIME_EXECUTABLE_RE = re.compile(r"[A-Za-z0-9._+@=:/-]+\Z")


REMOTE_PROBE = r'''
probe_path=$1
shift
verify_racknerd_route=0
verify_external_network=0
for requested in "$@"; do
  [ "$requested" = "__LAD_VERIFY_RACKNERD_ROUTE__" ] && verify_racknerd_route=1
  [ "$requested" = "__LAD_VERIFY_EXTERNAL_NETWORK__" ] && verify_external_network=1
done
declared_python=""
for requested in "$@"; do
  case "$requested" in
    __LAD_RUNTIME_PYTHON__=*) declared_python=${requested#*=} ;;
  esac
done
os_name=$(uname -s 2>/dev/null || printf unknown)
arch=$(uname -m 2>/dev/null || printf unknown)
host_name=$(hostname 2>/dev/null || printf unknown)
printf 'META|%s|%s|%s\n' "$host_name" "$os_name" "$arch"
# Kernel release is a compatibility fact, not a proxy for readiness.  Keep
# it as a separate bounded field so a runtime can require (for example) Linux
# >=5.1 while legacy CPU/PBS work remains compatible with older hosts.
kernel_release=$(uname -r 2>/dev/null || printf unknown)
case "$kernel_release" in
  ''|*[!A-Za-z0-9._+-]*) kernel_release=unknown ;;
esac
printf 'KERNEL|%s\n' "$kernel_release"
# ``date +%s`` is available on the legacy Linux nodes used by the central
# cluster and is sufficient for a bounded skew estimate.  A missing or
# malformed value remains explicit unknown; it never becomes a synthetic
# timestamp.
clock_epoch=$(date +%s 2>/dev/null || printf 0)
case "$clock_epoch" in
  ''|*[!0-9]* ) ;;
  * ) printf 'CLOCK|%s\n' "$clock_epoch" ;;
esac
# ``ntpstat`` is a bounded status summary on the legacy Linux nodes used by
# the central cluster.  Keep only its normalized synchronization state; do not
# retain the server name, polling text, or locale-dependent diagnostic body.
if command -v ntpstat >/dev/null 2>&1; then
  ntp_summary=$(LC_ALL=C ntpstat 2>/dev/null || true)
  case "$ntp_summary" in
    synchronised*|synchronized*) printf 'NTPSYNC|synchronised\n' ;;
    unsynchronised*|unsynchronized*) printf 'NTPSYNC|unsynchronised\n' ;;
    *) printf 'NTPSYNC|unknown\n' ;;
  esac
fi

if [ "$os_name" = Darwin ]; then
  logical=$(sysctl -n hw.logicalcpu 2>/dev/null || printf 0)
  physical=$(sysctl -n hw.physicalcpu 2>/dev/null || printf 0)
  total_bytes=$(sysctl -n hw.memsize 2>/dev/null || printf 0)
  page_size=$(sysctl -n hw.pagesize 2>/dev/null || printf 4096)
  vm_values=$(vm_stat 2>/dev/null | awk '
    /Pages free/ {gsub("\\.", "", $3); free=$3}
    /Pages inactive/ {gsub("\\.", "", $3); inactive=$3}
    /Pages speculative/ {gsub("\\.", "", $3); speculative=$3}
    /Pages purgeable/ {gsub("\\.", "", $3); purgeable=$3}
    END {printf "%d", free+inactive+speculative+purgeable}')
  available_bytes=$((vm_values * page_size))
  load1=$(sysctl -n vm.loadavg 2>/dev/null | awk '{print $2}')
  cpu_model=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || printf Apple)
else
  logical=$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || printf 0)
  physical=$(lscpu -p=core,socket 2>/dev/null | awk -F, '!/^#/ {seen[$1 FS $2]=1} END {print length(seen)}')
  [ -n "$physical" ] || physical=$logical
  total_kb=$(awk '/MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null)
  # RHEL6-era kernels do not expose MemAvailable.  Use the conservative
  # free+buffers+cached estimate in that case and carry the source label so
  # admission can distinguish a measured value from a legacy estimate.
  memory_pair=$(awk '
    $1 == "MemAvailable:" {available=$2; have_available=1}
    $1 == "MemFree:" {free=$2}
    $1 == "Buffers:" {buffers=$2}
    $1 == "Cached:" {cached=$2}
    END {
      if (have_available && available ~ /^[0-9]+$/) {
        printf "%s|procfs_memavailable", available
      } else if (free ~ /^[0-9]+$/ && buffers ~ /^[0-9]+$/ && cached ~ /^[0-9]+$/) {
        printf "%s|procfs_legacy_estimate", free + buffers + cached
      } else {
        printf "0|unknown"
      }
    }' /proc/meminfo 2>/dev/null)
  available_kb=${memory_pair%%|*}
  memory_source=${memory_pair#*|}
  total_bytes=$((${total_kb:-0} * 1024))
  available_bytes=$((${available_kb:-0} * 1024))
  load1=$(cut -d' ' -f1 /proc/loadavg 2>/dev/null || printf 0)
  cpu_model=$(lscpu 2>/dev/null | awk -F: '/Model name/ {sub(/^[ 	]+/, "", $2); print $2; exit}')
fi
printf 'CPU|%s|%s|%s|%s\n' "${logical:-0}" "${physical:-0}" "${load1:-0}" "${cpu_model:-unknown}"
printf 'MEM|%s|%s|%s\n' "${total_bytes:-0}" "${available_bytes:-0}" "${memory_source:-unknown}"

# Linux PSI is a scheduler pressure signal, not a provider/runtime probe.
# Emit only a finite memory ``some.avg10`` value; missing or malformed PSI
# remains unknown and therefore cannot satisfy the remote admission contract.
if [ "$os_name" = Linux ] && [ -r /proc/pressure/memory ]; then
  psi_avg10=$(awk '/^some / {for (i=1; i<=NF; i++) if ($i ~ /^avg10=/) {sub(/^avg10=/, "", $i); print $i; exit}}' /proc/pressure/memory 2>/dev/null)
  case "$psi_avg10" in
    ''|*[!0-9.]* ) ;;
    * ) printf 'PSI|%s\n' "$psi_avg10" ;;
  esac
fi

# A container can expose host-sized /proc/meminfo while the worker is actually
# fenced by cgroup v2.  Read the effective cgroup limit/current counters as a
# separate evidence line; the parser below will prefer a finite cgroup limit
# for admission while retaining the procfs values for discrepancy diagnosis.
if [ "$os_name" = Linux ] && [ -r /proc/self/cgroup ] && [ -d /sys/fs/cgroup ]; then
  cgroup_rel=$(awk -F: '$1 == "0" {print $3; exit}' /proc/self/cgroup 2>/dev/null)
  cgroup_root=/sys/fs/cgroup${cgroup_rel:-}
  cgroup_max_path=$cgroup_root/memory.max
  cgroup_current_path=$cgroup_root/memory.current
  cgroup_events_path=$cgroup_root/memory.events
  cgroup_stat_path=$cgroup_root/memory.stat
  if [ -r "$cgroup_max_path" ] && [ -r "$cgroup_current_path" ]; then
    cgroup_max=$(cat "$cgroup_max_path" 2>/dev/null)
    cgroup_current=$(cat "$cgroup_current_path" 2>/dev/null)
    if [ "$cgroup_max" = max ]; then cgroup_max=0; fi
    cgroup_high=0
    cgroup_oom=0
    cgroup_oom_kill=0
    if [ -r "$cgroup_events_path" ]; then
      cgroup_high=$(awk '$1 == "high" {print $2; found=1} END {if (!found) print 0}' "$cgroup_events_path" 2>/dev/null)
      cgroup_oom=$(awk '$1 == "oom" {print $2; found=1} END {if (!found) print 0}' "$cgroup_events_path" 2>/dev/null)
      cgroup_oom_kill=$(awk '$1 == "oom_kill" {print $2; found=1} END {if (!found) print 0}' "$cgroup_events_path" 2>/dev/null)
    fi
    case "$cgroup_max:$cgroup_current" in
      ''|*[!0-9:]* ) ;;
      * ) printf 'CGMEM|%s|%s|%s|%s|%s\n' "$cgroup_max" "$cgroup_current" "${cgroup_high:-0}" "${cgroup_oom:-0}" "${cgroup_oom_kill:-0}" ;;
    esac
  fi
  if [ -r "$cgroup_stat_path" ]; then
    cgroup_stat_line=$(awk '
      $1 == "anon" {anon=$2}
      $1 == "file" {file=$2}
      $1 == "active_file" {active_file=$2}
      $1 == "inactive_file" {inactive_file=$2}
      $1 == "slab" {slab=$2}
      END {
        if (anon ~ /^[0-9]+$/ && file ~ /^[0-9]+$/ &&
            active_file ~ /^[0-9]+$/ && inactive_file ~ /^[0-9]+$/ &&
            slab ~ /^[0-9]+$/) {
          printf "%s|%s|%s|%s|%s", anon, file, active_file, inactive_file, slab
        }
      }' "$cgroup_stat_path" 2>/dev/null)
    [ -z "$cgroup_stat_line" ] || printf 'CGMEMSTAT|%s\n' "$cgroup_stat_line"
  fi
fi

probe_disk() {
  candidate=$1
  [ -n "$candidate" ] || return 0
  if [ -d "$candidate" ]; then
    disk_line=$(df -Pk "$candidate" 2>/dev/null | tail -n 1)
    disk_total=$(printf '%s\n' "$disk_line" | awk '{print $2 * 1024}')
    disk_available=$(printf '%s\n' "$disk_line" | awk '{print $4 * 1024}')
    if [ -w "$candidate" ]; then writable=1; else writable=0; fi
    # The candidate directory is not necessarily the filesystem mount point
    # (for example /root/EXAMPLE_001 may be a subdirectory).  Keep both values
    # so admission can bind the workspace to the actual writable mount.
    mount_path=$(printf '%s\n' "$disk_line" | awk '{print $NF}')
    printf 'DISK|%s|1|%s|%s|%s|%s\n' "$candidate" "${disk_total:-0}" "${disk_available:-0}" "$writable" "${mount_path:-}"
  else
    printf 'DISK|%s|0|0|0|0\n' "$candidate"
  fi
}

# The declared project path remains the primary compatibility field.  Extra
# paths let a container use its real data/work volume rather than assuming
# that / (or /root) is the only capacity.  All checks are read-only df/test.
probe_disk "$probe_path"
for candidate in "$@"; do
  [ "$candidate" = "__LAD_DISCOVER_STORAGE__" ] && continue
  [ "$candidate" = "__LAD_VERIFY_RACKNERD_ROUTE__" ] && continue
  [ "$candidate" = "__LAD_VERIFY_EXTERNAL_NETWORK__" ] && continue
  case "$candidate" in
    __LAD_RUNTIME_PYTHON__=*) continue ;;
  esac
  [ "$candidate" = "$probe_path" ] && continue
  probe_disk "$candidate"
done
for candidate in /workspace /data /mnt /scratch /work; do
  discover=0
  for requested in "$@"; do
    [ "$requested" = "__LAD_DISCOVER_STORAGE__" ] && discover=1
  done
  [ "$discover" = 1 ] || break
  [ "$candidate" = "$probe_path" ] && continue
  probe_disk "$candidate"
done

# Container images often mount their useful project/data volumes under a
# vendor-specific prefix (for example /autodl-pub) rather than one of the
# conventional paths above.  Enumerate mount points from df itself so the
# planner never treats /root as the host's total storage.  Keep the filter
# deliberately narrow: skip kernel/temporary mounts and only retain paths that
# can be a declared project, data, cache, or work volume.  The operation is
# read-only; a slow/autofs mount remains bounded by the outer SSH timeout.
if [ "$discover" = 1 ]; then
  df -Pk 2>/dev/null | awk 'NR > 1 {
    path=$6
    if (substr(path, 1, 7) == "/autodl" ||
        substr(path, 1, 10) == "/workspace" ||
        substr(path, 1, 5) == "/data" ||
        substr(path, 1, 4) == "/mnt" ||
        substr(path, 1, 9) == "/scratch" ||
        substr(path, 1, 5) == "/work" ||
        substr(path, 1, 8) == "/project" ||
        substr(path, 1, 9) == "/projects" ||
        substr(path, 1, 5) == "/home" ||
        substr(path, 1, 5) == "/root") print path
  }' | sort -u | while IFS= read -r candidate; do
    [ -n "$candidate" ] || continue
    [ "$candidate" = "$probe_path" ] && continue
    case "$candidate" in
      /proc*|/sys*|/dev*|/run*|/tmp*) continue ;;
    esac
    probe_disk "$candidate"
  done
fi

# A route helper is not evidence merely because its binary is installed.  When
# an explicit live probe requests verification, call only its bounded
# credential-free ``verify`` operation and persist a boolean/status summary;
# never persist the helper output or its egress identity.  This is transport
# evidence for server workloads, not a provider-region or account-capability
# claim.
if [ "$verify_racknerd_route" = 1 ]; then
  route_bin=$(command -v codex-racknerd-route 2>/dev/null || true)
  if [ -z "$route_bin" ] && [ -x "$HOME/.local/bin/codex-racknerd-route" ]; then
    route_bin="$HOME/.local/bin/codex-racknerd-route"
  fi
  if [ -n "$route_bin" ] && [ -x "$route_bin" ]; then
    route_output=$("$route_bin" verify 2>/dev/null || true)
    route_has_identity=$(printf '%s\n' "$route_output" | awk '
      /[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*/ {found=1}
      END {print found+0}' 2>/dev/null)
    if [ "$route_has_identity" = 1 ]; then
      printf 'ROUTE|racknerd|workload|direct|1\n'
    else
      printf 'ROUTE|racknerd|workload|unknown|0\n'
    fi
  else
    printf 'ROUTE|racknerd|workload|missing|0\n'
  fi
fi

# Network reachability is deliberately separate from RackNerd route identity.
# A login node may have public egress while a PBS compute node is isolated.
# Emit only bounded boolean checks for two public control endpoints; no URL
# response, IP address, headers, or credentials enter the parsed snapshot.
if [ "$verify_external_network" = 1 ]; then
  probe_network_target() {
    network_target=$1
    dns_ok=0
    https_ok=0
    if command -v getent >/dev/null 2>&1 && getent hosts "$network_target" >/dev/null 2>&1; then
      dns_ok=1
    fi
    if command -v curl >/dev/null 2>&1 && curl -I -L --max-time 10 -sS "https://$network_target/" >/dev/null 2>&1; then
      https_ok=1
    fi
    printf 'NET|%s|%s|%s\n' "$network_target" "$dns_ok" "$https_ok"
  }
  probe_network_target github.com
  probe_network_target opencode.ai
fi

# A remote host may already be consuming a shared provider pool.  Collect only
# the short-lived ps stream needed for in-memory classification.  The parser
# below emits PID/pool/model/command_name records and never returns the raw
# command line, so prompts, tokens, and working paths cannot enter the saved
# compute-host snapshot.  A marker makes a missing ps binary fail closed.
if command -v ps >/dev/null 2>&1 && command -v awk >/dev/null 2>&1; then
  if [ "$os_name" = Darwin ]; then
    ps -axo pid=,ppid=,command= 2>/dev/null | awk '{pid=$1; ppid=$2; $1=""; $2=""; sub(/^[ \t]+/, ""); printf "PROC|%s|%s|%s\n", pid, ppid, $0}'
  else
    ps -eo pid=,ppid=,args= 2>/dev/null | awk '{pid=$1; ppid=$2; $1=""; $2=""; sub(/^[ \t]+/, ""); printf "PROC|%s|%s|%s\n", pid, ppid, $0}'
  fi
  printf 'PROCSCAN|1\n'
else
  printf 'PROCSCAN|0\n'
fi

if command -v nvidia-smi >/dev/null 2>&1; then
  nvidia-smi --query-gpu=index,name,memory.total,memory.free,utilization.gpu,driver_version \
    --format=csv,noheader,nounits 2>/dev/null | while IFS= read -r gpu_line; do
      printf 'GPU|%s\n' "$gpu_line"
    done
elif [ "$os_name" = Darwin ]; then
  system_profiler SPDisplaysDataType 2>/dev/null | awk -F': ' '
    /Chipset Model:/ {name=$2}
    /Total Number of Cores:/ {printf "APPLE_GPU|%s|%s\n", name, $2; exit}'
fi

probe_command() {
  command_name=$1
  shift
  command_path=$(command -v "$command_name" 2>/dev/null || true)
  if [ -z "$command_path" ] && [ -x "$HOME/.local/bin/$command_name" ]; then
    command_path="$HOME/.local/bin/$command_name"
  fi
  # Torque/PBS installations commonly keep client binaries outside PATH.  A
  # fixed allow-list makes discovery portable without executing a guessed
  # command or treating a filename as scheduler health evidence.
  if [ -z "$command_path" ]; then
    for candidate in "$@"; do
      if [ -x "$candidate" ]; then
        command_path="$candidate"
        break
      fi
    done
  fi
  [ -z "$command_path" ] || printf 'CMD|%s|%s\n' "$command_name" "$command_path"
}

probe_command python3
probe_command conda
probe_command docker
probe_command nvidia-smi
probe_command codex
probe_command agy
probe_command antigravity
probe_command opencode
probe_command codex-racknerd-route
probe_command codex-large-download
probe_command qstat \
  /opt/torque-2.5.2/bin/qstat /opt/torque/bin/qstat /opt/pbs/bin/qstat \
  /usr/local/bin/qstat /usr/bin/qstat
probe_command qsub \
  /opt/torque-2.5.2/bin/qsub /opt/torque/bin/qsub /opt/pbs/bin/qsub \
  /usr/local/bin/qsub /usr/bin/qsub
probe_command pbsnodes \
  /opt/torque-2.5.2/bin/pbsnodes /opt/torque/bin/pbsnodes /opt/pbs/bin/pbsnodes \
  /usr/local/bin/pbsnodes /usr/bin/pbsnodes
python_path=$(command -v python3 2>/dev/null || true)
if [ -n "$python_path" ]; then
  python_version=$(python3 -c 'import platform; print(platform.python_version())' 2>/dev/null || true)
  printf 'PYTHON|%s|%s\n' "$python_path" "$python_version"
fi
if [ -n "$declared_python" ]; then
  runtime_python="$declared_python"
  case "$runtime_python" in
    /*) ;;
    *) runtime_python=$(command -v "$declared_python" 2>/dev/null || true) ;;
  esac
  runtime_status=missing
  runtime_version=unknown
  if [ -n "$runtime_python" ] && [ -x "$runtime_python" ]; then
    runtime_version=$("$runtime_python" -c 'import platform; print(platform.python_version())' 2>/dev/null || true)
    if [ -n "$runtime_version" ]; then runtime_status=verified; else runtime_status=unverified; fi
  fi
  printf 'RUNTIME_PYTHON|%s|%s|%s\n' "$runtime_status" "$declared_python" "${runtime_version:-unknown}"
fi
'''


def load_json(path: str) -> Any:
    if path == "-":
        return json.load(sys.stdin)
    return json.loads(pathlib.Path(path).expanduser().read_text(encoding="utf-8"))


def atomic_write(path: str | None, payload: dict[str, Any]) -> None:
    text = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    if not path:
        print(text, end="")
        return
    target = pathlib.Path(path).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(target.suffix + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    temporary.replace(target)


def gib(value: str) -> float:
    try:
        return round(int(float(value)) / (1024**3), 3)
    except (TypeError, ValueError):
        return 0.0


def parse_gpu(line: str) -> dict[str, Any] | None:
    parts = [part.strip() for part in line.split(",")]
    if len(parts) < 6:
        return None
    try:
        total = round(float(parts[2]) / 1024, 3)
        free = round(float(parts[3]) / 1024, 3)
        utilization = float(parts[4])
    except ValueError:
        return None
    return {
        "index": int(parts[0]) if parts[0].isdigit() else parts[0],
        "name": parts[1],
        "vram_total_gib": total,
        "vram_free_gib": free,
        "utilization_percent": utilization,
        "driver_version": parts[5],
    }


def _parse_nonnegative_bytes(value: Any) -> int | None:
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


def _declared_runtime_python(host: dict[str, Any]) -> str | None:
    """Return one explicit interpreter declared by a host inventory.

    Legacy compute nodes often have no ``python3`` on PATH, while a copied
    desktop virtualenv can contain a broken absolute symlink.  Probe the
    inventory's explicit worker/runtime interpreter instead of silently
    treating PATH absence as proof that the host has no usable Python.
    """

    candidates: list[Any] = [
        host.get("runtime_python"),
        host.get("worker_python"),
        host.get("python_path"),
    ]
    for key in ("pbs", "runtime"):
        nested = host.get(key)
        if isinstance(nested, dict):
            candidates.extend((nested.get("python"), nested.get("worker_python")))
    for value in candidates:
        if value is None:
            continue
        if not isinstance(value, str) or not value or len(value) > 4096:
            raise ValueError("declared runtime interpreter is invalid")
        if not _RUNTIME_EXECUTABLE_RE.fullmatch(value):
            raise ValueError("declared runtime interpreter contains unsafe characters")
        if value.startswith("/"):
            pieces = value.split("/")
            if any(piece in {"", ".", ".."} for piece in pieces[1:]):
                raise ValueError("declared runtime interpreter contains an unsafe path")
        return value
    return None


def parse_remote_processes(lines: list[str]) -> dict[str, Any]:
    """Classify remote ``PROC`` lines without retaining raw argv.

    ``lines`` contains the probe's transient stdout only.  Each returned row
    is deliberately limited to a PID, canonical command name, and (when the
    existing allow-listed classifier can prove it) an exact provider/model.
    The ppid and complete command are used only for parsing and are dropped.
    """

    processes: list[dict[str, Any]] = []
    inflight: dict[str, int] = {}
    seen: set[int] = set()
    scan_seen = False
    scan_ok = False
    for raw in lines:
        parts = raw.split("|")
        if not parts:
            continue
        if parts[0] == "PROCSCAN" and len(parts) >= 2:
            scan_seen = True
            scan_ok = parts[1] == "1"
            continue
        if parts[0] != "PROC" or len(parts) < 4:
            continue
        try:
            pid = int(parts[1])
        except (TypeError, ValueError):
            continue
        if pid <= 0 or pid in seen:
            continue
        # The command can contain pipes; join it transiently for the shared
        # classifier and never include it in the returned object.
        command = "|".join(parts[3:])
        pool_id, model = pool_for_process(command)
        if not pool_id:
            continue
        row: dict[str, Any] = {
            "pid": pid,
            "pool_id": pool_id,
            "command_name": pool_id.split(".", 1)[0],
            "arguments_collected": False,
        }
        if model:
            row["model"] = model
        processes.append(row)
        inflight[pool_id] = inflight.get(pool_id, 0) + 1
        seen.add(pid)
    if not scan_seen:
        return {
            "scan_ok": False,
            "unknown": True,
            "processes": [],
            "inflight_by_pool": {},
            "exclusive_pool_observation": False,
            "attribution": "unknown_process_state_nonexclusive",
        }
    result = {
        "scan_ok": scan_ok,
        "processes": processes,
        "inflight_by_pool": inflight,
        "exclusive_pool_observation": False,
        "attribution": "pool_level_or_externally_confounded",
    }
    if not scan_ok:
        result["unknown"] = True
        result["attribution"] = "unknown_process_state_nonexclusive"
    return result


def scheduler_command_evidence(commands: dict[str, str]) -> dict[str, Any]:
    """Summarize fixed Torque/PBS client discovery without claiming health.

    Legacy central nodes keep ``qstat``/``qsub``/``pbsnodes`` under
    ``/opt/torque-2.5.2/bin`` and omit that directory from PATH.  The probe
    therefore records command discovery separately from scheduler reachability:
    callers still need a bounded ``qstat``/``qsub`` response before admitting a
    job.  Keeping this distinction prevents a present binary from becoming a
    false ready signal.
    """

    required = ["pbsnodes", "qstat", "qsub"]
    present = sorted(name for name in required if isinstance(commands.get(name), str) and commands[name])
    if not present:
        status = "missing"
    elif len(present) == len(required):
        status = "discovered"
    else:
        status = "partial"
    return {
        "status": status,
        "backend": "torque-pbs" if present else None,
        "present_commands": present,
        "required_commands": required,
        "source": "compute_resource_probe.command_discovery",
    }


def parse_output(text: str) -> dict[str, Any]:
    result: dict[str, Any] = {"gpus": [], "commands": {}, "disks": []}
    process_lines: list[str] = []
    network_checks: dict[str, dict[str, bool]] = {}
    for raw in text.splitlines():
        parts = raw.split("|")
        if not parts:
            continue
        tag = parts[0]
        if tag == "META" and len(parts) >= 4:
            # Keep the SSH connection hostname from the inventory. Container
            # hostnames are diagnostic facts and are usually not externally resolvable.
            result.update(reported_hostname=parts[1], os=parts[2], arch=parts[3])
        elif tag == "KERNEL" and len(parts) >= 2:
            kernel_release = parts[1].strip()
            if kernel_release and re.fullmatch(r"[A-Za-z0-9._+\-]+", kernel_release):
                result["kernel_release"] = kernel_release
        elif tag == "CLOCK" and len(parts) >= 2:
            try:
                epoch = int(parts[1])
            except (TypeError, ValueError):
                continue
            if epoch >= 0:
                result.update(clock_epoch_seconds=epoch, clock_source="date_epoch")
        elif tag == "NTPSYNC" and len(parts) >= 2:
            normalized = {
                "synchronised": "synchronized",
                "synchronized": "synchronized",
                "unsynchronised": "unsynchronized",
                "unsynchronized": "unsynchronized",
                "unknown": "unknown",
            }.get(parts[1].strip())
            if normalized:
                result["time_sync_evidence"] = {
                    "status": normalized,
                    "source": "ntpstat",
                }
        elif tag == "CPU" and len(parts) >= 5:
            try:
                logical = int(parts[1])
                physical = int(parts[2])
                load1 = float(parts[3] or 0)
            except ValueError:
                continue
            result.update(
                logical_cpu_cores=logical,
                physical_cpu_cores=physical,
                load1=load1,
                estimated_idle_cpu_cores=max(0, int(logical - load1)),
                cpu_model="|".join(parts[4:]),
            )
        elif tag == "MEM" and len(parts) >= 3:
            result.update(
                proc_memory_total_gib=gib(parts[1]),
                proc_memory_available_gib=gib(parts[2]),
                memory_total_gib=gib(parts[1]),
                memory_available_gib=gib(parts[2]),
                memory_source=(parts[3] if len(parts) >= 4 and parts[3] else "procfs"),
            )
        elif tag == "PSI" and len(parts) >= 2:
            try:
                psi_avg10 = float(parts[1])
            except ValueError:
                continue
            if 0 <= psi_avg10 <= 100:
                result["psi_some_avg10"] = psi_avg10
                result["psi_source"] = "proc_pressure_memory"
        elif tag == "CGMEM" and len(parts) >= 3:
            try:
                maximum = int(parts[1])
                current = int(parts[2])
            except (TypeError, ValueError):
                continue
            if maximum <= 0 or current < 0:
                continue
            available = max(0, maximum - current)
            result.update(
                cgroup_memory_max_bytes=maximum,
                cgroup_memory_current_bytes=current,
                cgroup_memory_available_bytes=available,
                cgroup_memory_max_gib=gib(str(maximum)),
                cgroup_memory_current_gib=gib(str(current)),
                cgroup_memory_available_gib=gib(str(available)),
                cgroup_memory_events_high=int(parts[3]) if len(parts) >= 4 and parts[3].isdigit() else 0,
                cgroup_memory_events_oom=int(parts[4]) if len(parts) >= 5 and parts[4].isdigit() else 0,
                cgroup_memory_events_oom_kill=int(parts[5]) if len(parts) >= 6 and parts[5].isdigit() else 0,
                memory_total_gib=gib(str(maximum)),
                memory_available_gib=gib(str(available)),
                memory_source="cgroup_v2_current_max",
                cgroup_required=True,
                cgroup_memory_evidence_status="complete",
            )
            proc_total = result.get("proc_memory_total_gib")
            proc_available = result.get("proc_memory_available_gib")
            if proc_total is not None and abs(float(proc_total) - float(result["memory_total_gib"])) > max(1.0, float(proc_total) * 0.05):
                result["memory_discrepancy"] = True
            if proc_available is not None and abs(float(proc_available) - float(result["memory_available_gib"])) > max(1.0, float(proc_available) * 0.05):
                result["memory_discrepancy"] = True
        elif tag == "CGMEMSTAT" and len(parts) >= 6:
            fields = ("anon", "file", "active_file", "inactive_file", "slab")
            parsed = {
                field: _parse_nonnegative_bytes(parts[index + 1])
                for index, field in enumerate(fields)
            }
            if all(value is not None for value in parsed.values()):
                result["cgroup_memory_stat"] = parsed
                result.update(
                    cgroup_memory_anon_bytes=parsed["anon"],
                    cgroup_memory_file_bytes=parsed["file"],
                    cgroup_memory_active_file_bytes=parsed["active_file"],
                    cgroup_memory_inactive_file_bytes=parsed["inactive_file"],
                    cgroup_memory_slab_bytes=parsed["slab"],
                    cgroup_memory_stat_source="cgroup_v2_memory.stat",
                    cgroup_memory_stat_evidence_status="complete",
                )
                current = _parse_nonnegative_bytes(result.get("cgroup_memory_current_bytes"))
                # active_file/inactive_file are subdivisions of file, not
                # additional memory.  Keep the accounting buckets disjoint.
                accounted = sum(int(parsed[field]) for field in ("anon", "file", "slab"))
                result["cgroup_memory_stat_accounted_bytes"] = accounted
                if current is not None:
                    result["cgroup_memory_stat_unaccounted_bytes"] = max(0, current - accounted)
        elif tag == "DISK" and len(parts) >= 6:
            path = parts[1]
            row = {
                "path": path,
                "exists": parts[2] == "1",
                "disk_total_gib": gib(parts[3]),
                "disk_free_gib": gib(parts[4]),
                "writable": parts[5] == "1",
            }
            if len(parts) >= 7 and parts[6]:
                row["mount_path"] = parts[6]
            result["disks"].append(row)
        elif tag == "GPU" and len(parts) >= 2:
            gpu = parse_gpu("|".join(parts[1:]))
            if gpu:
                result["gpus"].append(gpu)
        elif tag == "APPLE_GPU" and len(parts) >= 3:
            result["gpus"].append(
                {
                    "index": 0,
                    "name": parts[1],
                    "unified_memory": True,
                    "core_count": int(parts[2]) if parts[2].isdigit() else parts[2],
                }
            )
        elif tag == "CMD" and len(parts) >= 3:
            result["commands"][parts[1]] = "|".join(parts[2:])
        elif tag == "PYTHON" and len(parts) >= 3:
            result["python"] = {"path": parts[1], "version": parts[2]}
        elif tag == "RUNTIME_PYTHON" and len(parts) >= 4:
            status = parts[1]
            if status not in {"verified", "missing", "unverified"}:
                continue
            path = parts[2]
            if not path or "\x00" in path or "\n" in path or "\r" in path:
                continue
            result["runtime_python"] = {
                "status": status,
                "path": path,
                "version": parts[3] or "unknown",
                "source": "declared_inventory",
            }
        elif tag == "ROUTE" and len(parts) >= 5:
            provider, kind, status, verified = parts[1:5]
            # The route helper's output is intentionally not retained.  Only
            # the bounded verification result is carried forward; the host
            # identity is attached by ``probe_host`` after parsing.
            if provider == "racknerd" and kind in {"control", "execution", "workload", "artifact", "bulk_data"}:
                result["route_evidence"] = {
                    "provider": provider,
                    "kind": kind,
                    "status": status,
                    "verified": verified == "1",
                    "source": "codex-racknerd-route verify",
                }
        elif tag == "NET" and len(parts) >= 4:
            target = parts[1]
            if target not in EXTERNAL_NETWORK_TARGETS:
                continue
            network_checks[target] = {
                "dns_resolved": parts[2] == "1",
                "https_reachable": parts[3] == "1",
            }
        elif tag == "PROC" or tag == "PROCSCAN":
            # Keep process records out of the generic field parser until all
            # lines have been consumed; parse_remote_processes drops argv.
            process_lines.append(raw)
    if process_lines:
        result["external_consumers"] = parse_remote_processes(process_lines)
    result["scheduler_command_evidence"] = scheduler_command_evidence(result["commands"])
    if network_checks:
        missing_targets = [target for target in EXTERNAL_NETWORK_TARGETS if target not in network_checks]
        if missing_targets:
            status = "unknown"
        elif all(
            check.get("dns_resolved") and check.get("https_reachable")
            for check in network_checks.values()
        ):
            status = "verified"
        else:
            status = "blocked"
        result["external_network_evidence"] = {
            "status": status,
            "scope": "host_public_control_endpoints",
            "targets": dict(sorted(network_checks.items())),
            "source": "compute_resource_probe",
        }
    # Linux worker admission must use the cgroup boundary when available; a
    # missing/unreadable cgroup remains explicit unknown for fail-closed
    # callers, rather than inheriting host-sized procfs memory.
    if str(result.get("os") or "") == "Linux":
        result.setdefault("cgroup_required", True)
        result.setdefault("cgroup_memory_evidence_status", "unknown")
        result.setdefault("cgroup_memory_stat_evidence_status", "unknown")
    result["gpu_count"] = len(result["gpus"])
    # Preserve the first/project disk fields consumed by existing planners,
    # while exposing every declared/discovered mount for placement decisions.
    disks = [row for row in result["disks"] if row.get("exists")]
    if disks:
        primary = disks[0]
        result.update(
            project_path_exists=bool(primary.get("exists")),
            disk_total_gib=primary.get("disk_total_gib", 0.0),
            disk_free_gib=primary.get("disk_free_gib", 0.0),
            project_path_writable=bool(primary.get("writable")),
        )
        writable = [row for row in disks if row.get("writable")]
        best = max(disks, key=lambda row: float(row.get("disk_free_gib") or 0.0))
        result["best_storage_path"] = best.get("path")
        result["best_writable_storage_path"] = max(writable, key=lambda row: float(row.get("disk_free_gib") or 0.0)).get("path") if writable else None
    else:
        result.update(project_path_exists=False, disk_total_gib=0.0, disk_free_gib=0.0, project_path_writable=False)
        result["best_storage_path"] = None
        result["best_writable_storage_path"] = None
    return result


CAPACITY_RECEIPT_SCHEMA_VERSION = "0.1.0"
CAPACITY_RECEIPT_KIND = "server_capacity_receipt"
_CAPACITY_RECEIPT_FIELDS = (
    "schema_version", "kind", "host_identity_digest", "project_path_digest",
    "output_path_digest", "runtime_digest", "resource_request_digest",
    "available_disk_bytes", "required_disk_bytes", "available_memory_bytes",
    "required_memory_bytes", "gpu_inventory_digest", "writable_probe_digest",
    "observed_at", "maximum_age_seconds",
)


def _capacity_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def capacity_receipt_from_probe(
    probe: dict[str, Any], *, host_identity_digest: str, project_path_digest: str,
    output_path_digest: str, runtime_digest: str, resource_request_digest: str,
    required_disk_bytes: int, required_memory_bytes: int, observed_at: str,
    maximum_age_seconds: int = 300,
) -> dict[str, Any]:
    """Build a bounded capacity receipt from one parsed read-only probe.

    This helper deliberately emits counts, digests and timestamps only.  It
    does not copy SSH commands, prompts, environment variables or credentials.
    """
    if not isinstance(probe, dict):
        raise ValueError("capacity probe must be an object")
    disks = [row for row in probe.get("disks", []) if isinstance(row, dict) and row.get("exists")]
    writable = [row for row in disks if row.get("writable")]
    selected = max(writable or disks, key=lambda row: float(row.get("disk_free_gib") or 0.0), default={})
    available_disk_bytes = int(max(0.0, float(selected.get("disk_free_gib") or 0.0)) * (1024 ** 3))
    available_memory_bytes = probe.get("cgroup_memory_available_bytes")
    if not isinstance(available_memory_bytes, int) or available_memory_bytes < 0:
        available_memory_bytes = int(max(0.0, float(probe.get("memory_available_gib") or 0.0)) * (1024 ** 3))
    gpu_summary = [
        {key: gpu.get(key) for key in ("index", "name", "vram_total_gib", "vram_free_gib", "driver_version") if key in gpu}
        for gpu in probe.get("gpus", []) if isinstance(gpu, dict)
    ]
    body = {
        "schema_version": CAPACITY_RECEIPT_SCHEMA_VERSION,
        "kind": CAPACITY_RECEIPT_KIND,
        "host_identity_digest": host_identity_digest,
        "project_path_digest": project_path_digest,
        "output_path_digest": output_path_digest,
        "runtime_digest": runtime_digest,
        "resource_request_digest": resource_request_digest,
        "available_disk_bytes": available_disk_bytes,
        "required_disk_bytes": int(required_disk_bytes),
        "available_memory_bytes": int(available_memory_bytes),
        "required_memory_bytes": int(required_memory_bytes),
        "gpu_inventory_digest": _capacity_digest(gpu_summary),
        "writable_probe_digest": _capacity_digest({"path": selected.get("path"), "mount_path": selected.get("mount_path"), "writable": bool(selected.get("writable"))}),
        "observed_at": observed_at,
        "maximum_age_seconds": int(maximum_age_seconds),
    }
    return {**body, "receipt_digest": _capacity_digest(body)}


def ssh_argv(host: dict[str, Any], timeout: float) -> list[str]:
    hostname = str(host.get("hostname") or "")
    if not hostname or any(char in hostname for char in "\n\r\0"):
        raise ValueError("SSH host requires a safe hostname")
    user = str(host.get("user") or "")
    target = f"{user}@{hostname}" if user else hostname
    argv = [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", f"ConnectTimeout={max(1, int(timeout))}",
        "-o", "ServerAliveInterval=3",
        "-o", "ServerAliveCountMax=1",
    ]
    if host.get("ssh_legacy_rsa") is True:
        argv.extend([
            "-o", "HostKeyAlgorithms=+ssh-rsa",
            "-o", "PubkeyAcceptedAlgorithms=+ssh-rsa",
        ])
    if host.get("port"):
        argv.extend(["-p", str(int(host["port"]))])
    identity_file = host.get("identity_file")
    if identity_file:
        argv.extend(["-i", str(pathlib.Path(str(identity_file)).expanduser())])
    argv.append(target)
    return argv


def probe_host(
    host: dict[str, Any], timeout: float, *, verify_racknerd_route: bool = False,
    verify_external_network: bool = False,
) -> tuple[str, dict[str, Any]]:
    host_id = str(host.get("host_id") or "")
    if not host_id:
        raise ValueError("every host requires host_id")
    transport = str(host.get("transport") or ("ssh" if host.get("hostname") else "local"))
    project_path = str(host.get("project_path") or ".")
    if any(char in project_path for char in "\n\r\0|"):
        raise ValueError(f"unsafe project_path for {host_id}")
    raw_storage = host.get("storage_paths") or host.get("storage_candidates") or []
    if isinstance(raw_storage, (str, pathlib.Path)):
        raw_storage = [str(raw_storage)]
    if not isinstance(raw_storage, list):
        raise ValueError(f"storage_paths for {host_id} must be a list")
    storage_paths: list[str] = []
    for item in raw_storage:
        value = item.get("path") if isinstance(item, dict) else item
        if not isinstance(value, str) or not value.strip() or any(char in value for char in "\n\r\0|"):
            raise ValueError(f"unsafe storage path for {host_id}")
        if value not in storage_paths and value != project_path:
            storage_paths.append(value)
    declared_runtime_python = _declared_runtime_python(host)
    discover_storage = bool(host.get("discover_storage", transport == "ssh"))
    probe_args = [project_path, *storage_paths]
    if declared_runtime_python:
        probe_args.append("__LAD_RUNTIME_PYTHON__=" + declared_runtime_python)
    if discover_storage:
        probe_args.append("__LAD_DISCOVER_STORAGE__")
    if verify_racknerd_route:
        probe_args.append("__LAD_VERIFY_RACKNERD_ROUTE__")
    network_requested = verify_external_network or bool(host.get("verify_external_network"))
    if network_requested:
        probe_args.append("__LAD_VERIFY_EXTERNAL_NETWORK__")
    # Keep both clocks: monotonic bounds the probe latency, while the wall
    # clock provides a midpoint against which the remote epoch can be compared.
    started = time.monotonic()
    started_wall_epoch = time.time()
    if transport == "local":
        argv = ["sh", "-s", "--", *probe_args]
    elif transport == "ssh":
        argv = ssh_argv(host, timeout) + ["sh -s -- " + " ".join(shlex.quote(item) for item in probe_args)]
    else:
        raise ValueError(f"unsupported transport for {host_id}: {transport}")
    try:
        completed = subprocess.run(
            argv,
            input=REMOTE_PROBE,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=max(2.0, timeout),
            check=False,
        )
        reachable = completed.returncode == 0
        parsed = parse_output(completed.stdout) if reachable else {"gpus": [], "commands": {}, "disks": [], "gpu_count": 0}
        error = None if reachable else (completed.stderr.strip()[-1000:] or f"exit {completed.returncode}")
    except subprocess.TimeoutExpired:
        reachable = False
        parsed = {"gpus": [], "commands": {}, "disks": [], "gpu_count": 0}
        error = f"probe timeout after {timeout}s"
    finished_wall_epoch = time.time()
    result = dict(host)
    result.update(parsed)
    result.update(
        host_id=host_id,
        transport=transport,
        project_path=project_path,
        reachable=reachable,
        probe_latency_seconds=round(time.monotonic() - started, 3),
        last_probed_at_utc=dt.datetime.now(tz=dt.timezone.utc).isoformat(),
    )
    if declared_runtime_python and "runtime_python" not in parsed:
        result["runtime_python"] = {
            "status": "unknown",
            "path": declared_runtime_python,
            "version": "unknown",
            "source": "declared_inventory",
        }
    remote_epoch = parsed.get("clock_epoch_seconds")
    if isinstance(remote_epoch, int) and remote_epoch >= 0:
        midpoint = (started_wall_epoch + finished_wall_epoch) / 2.0
        offset = float(remote_epoch) - midpoint
        result["clock_evidence"] = {
            "status": "verified" if abs(offset) <= MAX_CLOCK_SKEW_SECONDS else "blocked",
            "remote_epoch_seconds": remote_epoch,
            "controller_midpoint_epoch_seconds": round(midpoint, 3),
            "offset_seconds": round(offset, 3),
            "max_allowed_seconds": MAX_CLOCK_SKEW_SECONDS,
            "source": "compute_resource_probe.date_epoch",
            "observed_at_utc": result["last_probed_at_utc"],
            "ttl_seconds": EXTERNAL_NETWORK_EVIDENCE_TTL_SECONDS,
        }
    else:
        result["clock_evidence"] = {
            "status": "unknown",
            "source": "compute_resource_probe.date_epoch",
            "observed_at_utc": result["last_probed_at_utc"],
            "ttl_seconds": EXTERNAL_NETWORK_EVIDENCE_TTL_SECONDS,
        }
    time_sync = parsed.get("time_sync_evidence")
    if isinstance(time_sync, dict):
        time_sync = dict(time_sync)
        time_sync.update(
            target_host_id=host_id,
            observed_at_utc=result["last_probed_at_utc"],
            ttl_seconds=EXTERNAL_NETWORK_EVIDENCE_TTL_SECONDS,
        )
        result["time_sync_evidence"] = time_sync
    result["storage_paths"] = parsed.get("disks", [])
    result["storage_discovery"] = {
        "declared_paths": storage_paths,
        "common_mounts_scanned": discover_storage,
        "mount_table_scanned": discover_storage,
        "vendor_mount_prefixes": [
            "/autodl", "/workspace", "/data", "/mnt", "/scratch",
            "/work", "/project", "/projects", "/home", "/root",
        ] if discover_storage else [],
    }
    route = parsed.get("route_evidence")
    if isinstance(route, dict):
        route = dict(route)
        route["target_host_id"] = host_id
        route["observed_at_utc"] = result["last_probed_at_utc"]
        route["ttl_seconds"] = RACKNERD_ROUTE_TTL_SECONDS
        result["route_evidence"] = route
    network = parsed.get("external_network_evidence")
    if isinstance(network, dict):
        network = dict(network)
        network["target_host_id"] = host_id
        network["observed_at_utc"] = result["last_probed_at_utc"]
        network["ttl_seconds"] = EXTERNAL_NETWORK_EVIDENCE_TTL_SECONDS
        result["external_network_evidence"] = network
    if error:
        result["probe_error"] = error
    if reachable:
        result["racknerd_route_helper"] = "codex-racknerd-route" in result.get("commands", {})
        result["large_download_helper"] = "codex-large-download" in result.get("commands", {})
    return host_id, result


def probe_inventory(
    payload: Any,
    timeout: float,
    workers: int,
    *,
    verify_racknerd_routes: bool = False,
    verify_external_network: bool = False,
) -> dict[str, Any]:
    # Private inventories historically used ``hosts`` as a list, while the
    # live dispatch inventory stores the same rows under ``compute_hosts``
    # keyed by host id.  Accept both shapes, preserving the mapping key when
    # the row itself does not repeat ``host_id``.  This is a schema adapter,
    # not a readiness override: every row still goes through probe_host and
    # retains the normal fail-closed result on probe/route/resource errors.
    if isinstance(payload, dict):
        hosts = payload.get("hosts")
        if hosts is None:
            hosts = payload.get("compute_hosts")
        if hosts is None:
            hosts = payload.get("compute_hosts_list")
        if isinstance(hosts, dict):
            normalized_hosts = []
            for key, row in hosts.items():
                if not isinstance(row, dict):
                    continue
                host = dict(row)
                host.setdefault("host_id", str(key))
                normalized_hosts.append(host)
            hosts = normalized_hosts
    else:
        hosts = payload
    if not isinstance(hosts, list) or not hosts:
        raise ValueError(
            "inventory must be a host list or an object with a non-empty hosts/compute_hosts list"
        )
    compute_hosts: dict[str, dict[str, Any]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(workers, len(hosts)))) as executor:
        futures = [
            executor.submit(
                probe_host,
                dict(host),
                timeout,
                **{
                    "verify_racknerd_route": verify_racknerd_routes or bool(host.get("verify_racknerd_route")),
                    **(
                        {"verify_external_network": True}
                        if verify_external_network or bool(host.get("verify_external_network"))
                        else {}
                    ),
                },
            )
            for host in hosts
        ]
        for future in concurrent.futures.as_completed(futures):
            host_id, result = future.result()
            compute_hosts[host_id] = result
    reachable = sum(1 for host in compute_hosts.values() if host.get("reachable"))
    return {
        "ok": True,
        "probed_at_utc": dt.datetime.now(tz=dt.timezone.utc).isoformat(),
        "reachable_hosts": reachable,
        "total_hosts": len(compute_hosts),
        "compute_hosts": dict(sorted(compute_hosts.items())),
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", required=True, help="JSON inventory path or - for stdin")
    # Some hosted containers expose large AutoFS mounts (for example a
    # read-only data volume) whose first ``df`` may take several seconds.  An
    # 8-second default made a reachable GPU host look unavailable.  Keep the
    # probe bounded, but give the read-only mount inventory enough budget to
    # finish before fail-closed timeout handling marks the host unknown.
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument(
        "--verify-racknerd-routes",
        action="store_true",
        help="Explicitly run each remote RackNerd helper's read-only verify operation.",
    )
    parser.add_argument(
        "--verify-external-network",
        action="store_true",
        help="Run bounded unauthenticated DNS/HTTPS checks for public control endpoints.",
    )
    parser.add_argument("--output")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        result = probe_inventory(
            load_json(args.inventory),
            max(2.0, args.timeout),
            max(1, args.workers),
            verify_racknerd_routes=args.verify_racknerd_routes,
            verify_external_network=args.verify_external_network,
        )
    except Exception as exc:
        result = {"ok": False, "error": str(exc)}
    atomic_write(args.output, result)
    return 0 if result.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
