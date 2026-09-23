"""Provider-free probe parsers and probe reports.

Nothing in this module executes a live probe.  It parses captured evidence
text (``/proc/self/mountinfo``, ``statvfs`` fields, ``nvidia-smi`` CSV, cgroup
v2 files) into schema-versioned domain records and tracks exactly which paths
were probed, so the placement gate can reject root-only evidence for paths on
other mounts.

The live probe plan (commands that a host-side scanner would run) is recorded
as declarative ``PROBE_COMMANDS`` metadata only; the parser surface accepts
fixture text captured from those commands.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Sequence, Tuple

from ..domain.world_state import (
    GpuProcess,
    GpuState,
    MountState,
    Observation,
    RamState,
    ResourceValues,
)

# Declarative record of the host-side commands whose output this module can
# parse.  Never executed here; used to describe evidence sources.
PROBE_COMMANDS: Mapping[str, str] = {
    "mountinfo": "read /proc/self/mountinfo",
    "statvfs": "os.statvfs() on each candidate directory",
    "nvidia_gpu": "nvidia-smi --query-gpu=index,name,memory.total,memory.free,"
    "memory.used --format=csv,noheader",
    "nvidia_apps": "nvidia-smi --query-compute-apps=pid,used_memory,name "
    "--format=csv,noheader",
    "cgroup_v2_memory": "read /sys/fs/cgroup/memory.max and memory.current",
}


def _octal_unescape(value: str) -> str:
    """Decode mountinfo ``\\040``-style escapes for paths with spaces."""

    def replace(match: "re.Match[str]") -> str:
        return chr(int(match.group(1), 8))

    return re.sub(r"\\([0-7]{3})", replace, value)


def _to_int(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    stripped = value.strip()
    if not stripped or stripped in ("-", "N/A", "nan"):
        return None
    return int(stripped)


def _to_float(value: Optional[str]) -> Optional[float]:
    if value is None:
        return None
    stripped = value.strip()
    if not stripped or stripped in ("-", "N/A", "nan"):
        return None
    return float(stripped)


def parse_mountinfo(text: str) -> Tuple[MountState, ...]:
    """Parse ``/proc/self/mountinfo`` lines into unprobed mount records.

    The mounts are *listed* only: ``probed_path`` stays ``None`` and no
    capacity field is fabricated.  Statvfs evidence must be attached
    separately via :func:`apply_statvfs` for a mount to be probeable.
    """
    mounts: list[MountState] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        separator = None
        for index, field in enumerate(fields):
            if field == "-":
                separator = index
                break
        if separator is None or separator < 6:
            continue
        mount_point = _octal_unescape(fields[4])
        fs_type = fields[separator + 1]
        source = fields[separator + 2] if separator + 2 < len(fields) else None
        options = tuple(fields[5].split(",")) if len(fields) > 5 else ()
        mounts.append(
            MountState(
                path=mount_point,
                device=_octal_unescape(source) if source else None,
                fs_type=fs_type,
                options=options,
                writable=None,
            )
        )
    return tuple(mounts)


def statvfs_evidence(
    path: str,
    f_frsize: int,
    f_blocks: int,
    f_bfree: int,
    f_bavail: int,
    f_files: int,
    f_ffree: int,
    f_favail: int,
    writable: Optional[bool],
    observed_at: str,
    source: str,
    ttl_seconds: Optional[float] = None,
    confidence: Optional[float] = None,
    evidence: Sequence[str] = (),
) -> MountState:
    """Build a probed mount record from ``statvfs``-style fields.

    ``free_bytes`` uses the unprivileged-available blocks (``f_bavail``) and
    ``free_inodes`` uses ``f_favail``; capacity uses ``f_blocks``.  These are
    the same units ``os.statvfs`` returns on Linux and macOS.
    """
    return MountState(
        path=path,
        probed_path=path,
        writable=writable,
        values=ResourceValues(
            units="bytes",
            capacity=f_blocks * f_frsize,
            available_now=f_bavail * f_frsize,
            used=(f_bfree - f_bavail) * f_frsize if f_bfree >= f_bavail else None,
        ),
        free_bytes=f_bavail * f_frsize,
        free_inodes=f_favail,
        observation=Observation(
            kind="mount",
            source=source,
            observed_at=observed_at,
            evidence=tuple(evidence),
            ttl_seconds=ttl_seconds,
            confidence=confidence,
        ),
    )


def apply_statvfs(
    mounts: Sequence[MountState],
    path: str,
    f_frsize: int,
    f_blocks: int,
    f_bfree: int,
    f_bavail: int,
    f_files: int,
    f_ffree: int,
    f_favail: int,
    writable: Optional[bool],
    observed_at: str,
    source: str,
    ttl_seconds: Optional[float] = None,
) -> Tuple[MountState, ...]:
    """Replace the listed mount at ``path`` with its probed statvfs evidence."""
    probe = statvfs_evidence(
        path,
        f_frsize,
        f_blocks,
        f_bfree,
        f_bavail,
        f_files,
        f_ffree,
        f_favail,
        writable,
        observed_at,
        source,
        ttl_seconds=ttl_seconds,
    )
    updated = [probe if mount.path == path else mount for mount in mounts]
    if not any(mount.path == path for mount in mounts):
        updated.append(probe)
    return tuple(updated)


def parse_nvidia_gpu_csv(text: str, observed_at: str, source: str = "nvidia-smi") -> Tuple[GpuState, ...]:
    """Parse ``--query-gpu=index,name,memory.total,memory.free,memory.used``
    CSV into VRAM states with unknown fields preserved as None."""
    gpus: list[GpuState] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        cells = [cell.strip() for cell in line.split(",")]
        if len(cells) < 5:
            continue
        index = cells[0]
        name = cells[1] or None
        total = _to_float(_strip_mi(cells[2]))
        free = _to_float(_strip_mi(cells[3]))
        used = _to_float(_strip_mi(cells[4]))
        gpus.append(
            GpuState(
                index=index,
                model=name,
                vram=ResourceValues(
                    units="MiB",
                    capacity=total,
                    available_now=free,
                    used=used,
                ),
                observation=Observation(
                    kind="vram",
                    source=source,
                    observed_at=observed_at,
                    evidence=(line,),
                ),
            )
        )
    return tuple(gpus)


def parse_nvidia_apps_csv(text: str) -> Tuple[GpuProcess, ...]:
    """Parse ``--query-compute-apps=pid,used_memory,name`` CSV rows."""
    processes: list[GpuProcess] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        cells = [cell.strip() for cell in line.split(",")]
        if len(cells) < 3:
            continue
        pid = _to_int(cells[0])
        if pid is None:
            continue
        processes.append(
            GpuProcess(
                pid=pid,
                name=cells[2] or "unknown",
                vram_mib=_to_int(_strip_mi(cells[1])),
            )
        )
    return tuple(processes)


def parse_cgroup_v2_memory(text: str) -> RamState:
    """Parse ``memory.max``/``memory.current`` lines from a cgroup v2 file."""
    max_bytes: Optional[int] = None
    current_bytes: Optional[int] = None
    for line in text.splitlines():
        key, _, value = line.strip().partition(" ")
        value = value.strip()
        if key == "memory.max":
            max_bytes = None if value == "max" else _to_int(value)
        elif key == "memory.current":
            current_bytes = _to_int(value)
    return RamState(
        values=ResourceValues(units="bytes", capacity=max_bytes),
        cgroup_limit_bytes=max_bytes,
        cgroup_current_bytes=current_bytes,
    )


def _strip_mi(value: str) -> str:
    return value.replace("MiB", "").strip()


@dataclass(frozen=True)
class MountProbeReport:
    """What the probe actually measured: listed mounts plus probed paths.

    ``probed_paths`` is the authoritative set of directories covered by
    statvfs evidence.  A path that resolves onto a listed mount whose exact
    directory was never probed must be rejected by the placement gate; listing
    a mount in ``mountinfo`` is not evidence of capacity.
    """

    mounts: Tuple[MountState, ...]
    probed_paths: Tuple[str, ...]
    sources: Tuple[str, ...] = ("mountinfo", "statvfs")

    def mount(self, path: str) -> Optional[MountState]:
        for mount in self.mounts:
            if mount.path.rstrip("/") == path.rstrip("/"):
                return mount
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "mounts": [m.to_dict() for m in self.mounts],
            "probed_paths": list(self.probed_paths),
            "sources": list(self.sources),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "MountProbeReport":
        return cls(
            mounts=tuple(
                MountState.from_dict(m) for m in data.get("mounts", ())
            ),
            probed_paths=tuple(str(p) for p in data.get("probed_paths", ())),
            sources=tuple(str(s) for s in data.get("sources", ())),
        )


__all__ = [
    "PROBE_COMMANDS",
    "MountProbeReport",
    "parse_mountinfo",
    "statvfs_evidence",
    "apply_statvfs",
    "parse_nvidia_gpu_csv",
    "parse_nvidia_apps_csv",
    "parse_cgroup_v2_memory",
]
