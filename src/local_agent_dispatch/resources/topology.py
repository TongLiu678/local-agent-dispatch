"""Storage and GPU placement gates over the world-state digital twin.

The central rule this module enforces: placement is decided against the exact
candidate path's own mount evidence.  A small root filesystem never rejects a
path on a large project mount, and evidence from another mount (including
root-only probing) is never substituted for the target mount.  Stale
observations are rejected through observation TTLs, so a path cannot be
accepted on the basis of outdated root capacity either.

Verdicts are ``safe``, ``unknown``, or ``reject``:

- ``safe`` requires verified writability, fresh evidence, known free bytes and
  inodes, and enough free space for the request plus P90 headroom;
- ``unknown`` is fail-closed: any essential value that could not be verified
  (free bytes, inodes, quota, writability, freshness) means no safe placement;
- ``reject`` is a verified hard violation (read-only, stale evidence, missing
  mount evidence, insufficient space/inodes).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePath, PurePosixPath, PureWindowsPath
from typing import Optional, Sequence, Tuple

from ..domain.world_state import (
    GpuState,
    Host,
    MountState,
    _min_known,
)

VERDICT_ORDER = {"safe": 0, "unknown": 1, "reject": 2}


@dataclass(frozen=True)
class PathRequirements:
    required_bytes: int
    required_inodes: Optional[int] = None
    p90_headroom_ratio: float = 0.1


@dataclass(frozen=True)
class MountResolution:
    mount: Optional[MountState]
    probed: bool
    covering_prefix: bool
    reason: Optional[str] = None
    evidence_unknown: bool = False


def _pure_absolute_path(path: str) -> tuple[Optional[PurePath], Optional[str], str]:
    """Parse an absolute path according to its lexical path shape.

    ``pathlib.Path`` follows the controller's operating system, which makes a
    Windows worker path look relative on a POSIX controller.  The scheduler
    instead needs host-independent lexical containment, so drive-qualified
    paths use :class:`PureWindowsPath` and slash-rooted paths use
    :class:`PurePosixPath`.

    UNC paths are deliberately not admitted yet.  They require share-level
    locality and capacity evidence, which the mount model does not currently
    encode.  Returning an explicit unknown reason keeps that gap fail-closed.
    """

    text = str(path).strip()
    if not text:
        return None, "path is empty; filesystem evidence is unknown", "unknown"
    if "\x00" in text:
        return None, "path contains a NUL byte; filesystem evidence is unknown", "unknown"

    windows = PureWindowsPath(text)
    if windows.drive.startswith("\\\\"):
        return (
            None,
            f"UNC path {path!r} is unsupported; share evidence is unknown",
            "unc",
        )
    if windows.drive:
        if not windows.is_absolute():
            return (
                None,
                f"drive-relative Windows path {path!r} is unsupported; filesystem evidence is unknown",
                "windows",
            )
        if ".." in windows.parts:
            return None, f"path {path!r} contains unresolved parent traversal", "windows"
        return windows, None, "windows"

    posix = PurePosixPath(text)
    if not posix.is_absolute():
        return (
            None,
            f"relative path {path!r} is unsupported; filesystem evidence is unknown",
            "unknown",
        )
    if ".." in posix.parts:
        return None, f"path {path!r} contains unresolved parent traversal", "posix"
    return posix, None, "posix"


def _covers(parent: PurePath, child: PurePath) -> bool:
    if type(parent) is not type(child):
        return False
    try:
        child.relative_to(parent)
    except ValueError:
        return False
    return True


def resolve_mount(path: str, mounts: Sequence[MountState]) -> MountResolution:
    """Find the mount covering ``path`` by exact match, then longest prefix.

    ``probed`` is False when the covering mount was listed but its own
    directory was never probed (for example when only ``/`` received statvfs
    evidence) — root-only evidence must not cover the path.
    """
    normalized, path_error, path_flavor = _pure_absolute_path(path)
    if normalized is None:
        return MountResolution(
            None,
            False,
            False,
            path_error or f"path shape for {path!r} is unsupported",
            True,
        )

    normalized_mounts: list[tuple[MountState, PurePath]] = []
    for mount in mounts:
        mount_path, _, mount_flavor = _pure_absolute_path(mount.path)
        if mount_path is None or mount_flavor != path_flavor:
            continue
        normalized_mounts.append((mount, mount_path))
        if mount_path == normalized:
            return MountResolution(mount, mount.is_probed(), False)
    best: Optional[MountState] = None
    best_depth = -1
    for mount, mount_path in normalized_mounts:
        # A root-only probe is intentionally exact-only.  If a separately
        # listed project mount disappeared, falling back to root would turn
        # that missing evidence into a false safe placement.
        if mount_path.parent == mount_path:
            continue
        if _covers(mount_path, normalized):
            depth = len(mount_path.parts)
            if depth > best_depth:
                best = mount
                best_depth = depth
    if best is None:
        return MountResolution(
            None,
            False,
            False,
            f"no mount evidence covers {path}",
        )
    if not best.is_probed():
        return MountResolution(
            best,
            False,
            True,
            f"mount {best.path} was listed but never probed; root-only "
            f"evidence cannot substitute for {path}",
        )
    return MountResolution(best, True, True, None)


@dataclass(frozen=True)
class PlacementDecision:
    path: str
    verdict: str
    mount: Optional[MountState]
    writable: Optional[bool]
    free_bytes: Optional[int]
    free_inodes: Optional[int]
    fs_type: Optional[str]
    p90_headroom_bytes: Optional[int]
    safe_to_place_bytes: Optional[int]
    stale: Optional[bool]
    reasons: Tuple[str, ...]


def _decide(
    path: str,
    verdict: str,
    reasons: Sequence[str],
    *,
    mount: Optional[MountState] = None,
    writable: Optional[bool] = None,
    free_bytes: Optional[int] = None,
    free_inodes: Optional[int] = None,
    fs_type: Optional[str] = None,
    p90_headroom_bytes: Optional[int] = None,
    safe_to_place_bytes: Optional[int] = None,
    stale: Optional[bool] = None,
) -> PlacementDecision:
    return PlacementDecision(
        path=path,
        verdict=verdict,
        mount=mount,
        writable=writable,
        free_bytes=free_bytes,
        free_inodes=free_inodes,
        fs_type=fs_type,
        p90_headroom_bytes=p90_headroom_bytes,
        safe_to_place_bytes=safe_to_place_bytes,
        stale=stale,
        reasons=tuple(reasons),
    )


def evaluate_placement(
    host: Host,
    path: str,
    requirements: PathRequirements,
    now: Optional[str] = None,
) -> PlacementDecision:
    """Gate one exact path on one host; never substitutes other mounts."""
    headroom = int(round(requirements.required_bytes * requirements.p90_headroom_ratio))
    headroom = max(headroom, 0)
    needed = requirements.required_bytes + headroom

    resolution = resolve_mount(path, host.mounts)
    mount = resolution.mount
    if mount is None or not resolution.probed:
        verdict = "unknown" if resolution.evidence_unknown else "reject"
        return _decide(
            path, verdict, [resolution.reason or "no probe evidence"],
            p90_headroom_bytes=headroom,
        )
    if mount.observation is None:
        return _decide(
            path,
            "reject",
            [f"mount {mount.path} has no observation"],
            p90_headroom_bytes=headroom,
        )
    stale = mount.observation.is_stale(now)
    if stale is True:
        return _decide(
            path,
            "reject",
            [f"mount {mount.path} observation is stale (TTL expired)"],
            p90_headroom_bytes=headroom,
        )
    if stale is None:
        return _decide(
            path,
            "unknown",
            [f"mount {mount.path} freshness unverifiable (no TTL)"],
            p90_headroom_bytes=headroom,
        )
    reasons: list[str] = []
    if mount.writable is None:
        return _decide(
            path,
            "unknown",
            [f"mount {mount.path} writability was not verified"],
            mount=mount,
            writable=None,
            free_bytes=mount.free_bytes,
            free_inodes=mount.free_inodes,
            fs_type=mount.fs_type,
            p90_headroom_bytes=headroom,
            stale=False,
        )
    if not mount.writable:
        return _decide(
            path,
            "reject",
            [f"mount {mount.path} is not writable"],
            mount=mount,
            writable=False,
            free_bytes=mount.free_bytes,
            free_inodes=mount.free_inodes,
            fs_type=mount.fs_type,
            p90_headroom_bytes=headroom,
            stale=False,
        )
    reasons.append(f"writable on {mount.fs_type or 'unknown fs'}")

    free_bytes = mount.free_bytes
    if free_bytes is None:
        return _decide(
            path,
            "unknown",
            [f"mount {mount.path} free bytes are unknown"],
            mount=mount,
            writable=mount.writable,
            free_bytes=None,
            free_inodes=mount.free_inodes,
            fs_type=mount.fs_type,
            p90_headroom_bytes=headroom,
            stale=False,
        )
    quota_free: Optional[int] = None
    if mount.quota is not None:
        if mount.quota.free is None:
            return _decide(
                path,
                "unknown",
                [f"mount {mount.path} quota exists but free quota is unknown"],
                mount=mount,
                writable=mount.writable,
                free_bytes=free_bytes,
                free_inodes=mount.free_inodes,
                fs_type=mount.fs_type,
                p90_headroom_bytes=headroom,
                stale=False,
            )
        quota_free = int(mount.quota.free)
        reasons.append(f"quota free {quota_free}")
    effective_free = free_bytes
    if quota_free is not None:
        effective_free = min(effective_free, quota_free)

    if requirements.required_inodes is not None:
        if mount.free_inodes is None:
            return _decide(
                path,
                "unknown",
                [f"mount {mount.path} free inodes are unknown"],
                mount=mount,
                writable=mount.writable,
                free_bytes=free_bytes,
                free_inodes=None,
                fs_type=mount.fs_type,
                p90_headroom_bytes=headroom,
                stale=False,
            )
        if mount.free_inodes < requirements.required_inodes:
            return _decide(
                path,
                "reject",
                [
                    f"mount {mount.path} inode exhaustion: "
                    f"{mount.free_inodes} free < {requirements.required_inodes} required"
                ],
                mount=mount,
                writable=mount.writable,
                free_bytes=free_bytes,
                free_inodes=mount.free_inodes,
                fs_type=mount.fs_type,
                p90_headroom_bytes=headroom,
                stale=False,
            )
        reasons.append(f"inodes {mount.free_inodes} free")

    if effective_free < needed:
        return _decide(
            path,
            "reject",
            [
                f"mount {mount.path} free {effective_free} bytes < "
                f"{needed} required with P90 headroom"
            ],
            mount=mount,
            writable=mount.writable,
            free_bytes=free_bytes,
            free_inodes=mount.free_inodes,
            fs_type=mount.fs_type,
            p90_headroom_bytes=headroom,
            stale=False,
        )
    reserved = mount.values.reserved if mount.values.reserved is not None else 0
    if mount.values.reserved is None:
        reasons.append("no reservation evidence; reserved treated as 0")
    else:
        reasons.append(f"reserved {int(mount.values.reserved)}")
        if effective_free - reserved < needed:
            return _decide(
                path,
                "reject",
                [
                    f"mount {mount.path} free {effective_free} minus reserved "
                    f"{int(mount.values.reserved)} < {needed} with P90 headroom"
                ],
                mount=mount,
                writable=mount.writable,
                free_bytes=free_bytes,
                free_inodes=mount.free_inodes,
                fs_type=mount.fs_type,
                p90_headroom_bytes=headroom,
                stale=False,
            )
    safe_to_place = effective_free - reserved - needed
    return _decide(
        path,
        "safe",
        tuple(reasons + [f"P90 headroom {headroom} bytes"]),
        mount=mount,
        writable=mount.writable,
        free_bytes=free_bytes,
        free_inodes=mount.free_inodes,
        fs_type=mount.fs_type,
        p90_headroom_bytes=headroom,
        safe_to_place_bytes=safe_to_place,
        stale=False,
    )


def rank_paths(
    host: Host,
    requirements: PathRequirements,
    declared_paths: Sequence[str],
    now: Optional[str] = None,
) -> Tuple[PlacementDecision, ...]:
    """Rank candidate paths by exact-path evidence: safe first, then by
    remaining safe-to-place capacity, then unknown, then rejected."""
    decisions = [
        evaluate_placement(host, path, requirements, now=now)
        for path in declared_paths
    ]

    def sort_key(decision: PlacementDecision) -> Tuple[int, int]:
        spare = decision.safe_to_place_bytes
        return (VERDICT_ORDER[decision.verdict], -(spare if spare is not None else -1))

    return tuple(sorted(decisions, key=sort_key))


@dataclass(frozen=True)
class GpuFit:
    gpu_index: str
    verdict: str
    required_mib: int
    available_now_mib: Optional[int]
    in_use_mib: Optional[int]
    reasons: Tuple[str, ...]


def gpu_available_now_mib(gpu: GpuState) -> Optional[int]:
    """Free VRAM now: min of observed available/allocatable/capacity minus
    VRAM held by observed GPU processes.  None when any part is unknown."""
    base = _min_known(
        (
            gpu.vram.available_now if gpu.vram else None,
            gpu.vram.allocatable if gpu.vram else None,
            gpu.vram.capacity if gpu.vram else None,
        )
    )
    in_use = gpu.in_use_vram_mib()
    if base is None or in_use is None:
        return None
    return int(base - in_use)


def evaluate_vram(
    gpu: GpuState,
    required_mib: int,
    p90_headroom_ratio: float = 0.1,
) -> GpuFit:
    """Gate one GPU by free VRAM minus observed process VRAM plus headroom."""
    available = gpu_available_now_mib(gpu)
    in_use = gpu.in_use_vram_mib()
    if available is None:
        return GpuFit(
            gpu.index,
            "unknown",
            required_mib,
            None,
            in_use,
            (f"GPU {gpu.index} free VRAM is unknown",),
        )
    headroom = int(round(required_mib * p90_headroom_ratio))
    needed = required_mib + headroom
    if available < needed:
        return GpuFit(
            gpu.index,
            "reject",
            required_mib,
            available,
            in_use,
            (
                f"GPU {gpu.index} free VRAM {available} MiB < {needed} MiB "
                f"required with P90 headroom (in use: {in_use} MiB)"
            ),
        )
    return GpuFit(
        gpu.index,
        "safe",
        required_mib,
        available,
        in_use,
        (f"GPU {gpu.index} free VRAM {available} MiB >= {needed} MiB",),
    )


def rank_gpus(
    gpus: Sequence[GpuState],
    required_mib: int,
    p90_headroom_ratio: float = 0.1,
) -> Tuple[GpuFit, ...]:
    fits = [evaluate_vram(gpu, required_mib, p90_headroom_ratio) for gpu in gpus]
    return tuple(
        sorted(
            fits,
            key=lambda fit: (
                VERDICT_ORDER[fit.verdict],
                -(fit.available_now_mib or -1),
            ),
        )
    )


__all__ = [
    "PathRequirements",
    "MountResolution",
    "PlacementDecision",
    "GpuFit",
    "resolve_mount",
    "evaluate_placement",
    "rank_paths",
    "gpu_available_now_mib",
    "evaluate_vram",
    "rank_gpus",
]
