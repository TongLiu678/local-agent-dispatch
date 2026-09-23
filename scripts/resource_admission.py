#!/usr/bin/env python3
"""Small, side-effect-free resource gates used immediately before a launch.

The planner and system scanner are intentionally advisory snapshots.  This
module is the last cheap check before a local child process is created.  It
does not create a lock, temporary file, subprocess, or process; it only reads
``statvfs`` for the working and temporary filesystems.  A remote SSH command
does not use this gate because its filesystem is not the controller's local
filesystem.
"""

from __future__ import annotations

import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any


SCHEMA_VERSION = 1
MIB = 1024**2
DEFAULT_MIN_FREE_BYTES = 256 * MIB
# This is deliberately a byte floor, not the scanner's 10% bulk-work gate.
# A large nearly-full volume may still have enough room for a bounded child;
# conversely 0.15 GiB on any volume is unsafe for Python/Node/SQLite startup.
DEFAULT_MIN_FREE_PERCENT = 0.0

# SQLite WAL requires a local filesystem.  This is intentionally a small
# deny-list of filesystems whose locking semantics are not a valid Controller
# durability boundary.  Unknown filesystems remain evidence-limited instead
# of being guessed as local.
_SHARED_FILESYSTEM_TYPES = frozenset(
    {
        "9p",
        "afs",
        "ceph",
        "cifs",
        "fuse.sshfs",
        "glusterfs",
        "gpfs",
        "lustre",
        "nfs",
        "nfs4",
        "smbfs",
        "smb3",
        "sshfs",
        "virtiofs",
    }
)
_LOCAL_FILESYSTEM_TYPES = frozenset(
    {
        "apfs",
        "aufs",
        "btrfs",
        "erofs",
        "exfat",
        "ext2",
        "ext3",
        "ext4",
        "f2fs",
        "hfs",
        "hfsplus",
        "jfs",
        "nilfs2",
        "ntfs",
        "ntfs3",
        "overlay",
        "refs",
        "reiserfs",
        "ufs",
        "vfat",
        "xfs",
        "zfs",
    }
)
_EPHEMERAL_FILESYSTEM_TYPES = frozenset({"devtmpfs", "ramfs", "tmpfs"})
_NONPERSISTENT_FILESYSTEM_TYPES = _EPHEMERAL_FILESYSTEM_TYPES | {"aufs", "overlay"}
_OCTAL_ESCAPE = re.compile(r"\\([0-7]{3})")
_DARWIN_MOUNT_RE = re.compile(r"^(?P<source>.+?) on (?P<path>.+?) \((?P<options>[^)]*)\)$")


def _normalize_path_platform(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip().lower()
    if text.startswith("linux"):
        return "linux"
    if text in {"darwin", "mac", "macos"}:
        return "darwin"
    if text in {"win32", "windows", "nt"}:
        return "win32"
    if text == "posix":
        return "posix"
    return None


def _host_path_platform() -> str:
    normalized = _normalize_path_platform(sys.platform)
    if normalized is not None:
        return normalized
    return "win32" if os.name == "nt" else "posix"


def _select_path_platform(
    *,
    platform: str | None,
    mountinfo_text: str | None,
    darwin_mount_text: str | None,
    windows_volume_info: dict[str, Any] | None,
) -> tuple[str | None, str | None, bool]:
    """Select path semantics from explicit evidence before consulting the host."""

    explicit = None
    if platform is not None:
        explicit = _normalize_path_platform(platform)
        if explicit is None:
            return None, "unsupported_platform", False
    evidence_platforms = {
        candidate
        for candidate, supplied in (
            ("linux", mountinfo_text is not None),
            ("darwin", darwin_mount_text is not None),
            ("win32", windows_volume_info is not None),
        )
        if supplied
    }
    if len(evidence_platforms) > 1:
        return explicit, "platform_evidence_conflict", True
    evidence_platform = next(iter(evidence_platforms), None)
    if explicit is not None and evidence_platform not in {None, explicit}:
        return explicit, "platform_evidence_conflict", True
    return explicit or evidence_platform or _host_path_platform(), None, bool(
        evidence_platforms
    )


def _posix_absolute_path(
    value: str | os.PathLike[str],
) -> tuple[pathlib.PurePosixPath | None, str | None]:
    """Return an absolute lexical POSIX path without using host path rules."""

    text = os.fspath(value).strip()
    if not text or "\x00" in text:
        return None, "invalid_path"
    path = pathlib.PurePosixPath(text)
    if not path.is_absolute() or ".." in path.parts:
        return None, "unsupported_posix_path_shape"
    return path, None


def _windows_absolute_path(
    value: str | os.PathLike[str],
) -> tuple[pathlib.PureWindowsPath | None, str | None]:
    """Return a safe lexical Windows path, independent of controller OS."""

    text = os.fspath(value).strip()
    if not text or "\x00" in text:
        return None, "invalid_path"
    path = pathlib.PureWindowsPath(text)
    if path.drive.startswith("\\\\"):
        # Share-level locality/capacity is not represented by the current
        # volume receipt, so treating a UNC share as a normal drive would
        # silently borrow unrelated evidence.
        return None, "unc_path_unsupported"
    if not path.drive or not path.is_absolute() or ".." in path.parts:
        return None, "unsupported_windows_path_shape"
    return path, None


def _pure_path_covers(parent: pathlib.PurePath, child: pathlib.PurePath) -> bool:
    if type(parent) is not type(child):
        return False
    try:
        child.relative_to(parent)
    except ValueError:
        return False
    return True


def _windows_volume_record(
    path: str | os.PathLike[str],
    *,
    windows_volume_info: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Return read-only Windows volume locality evidence.

    ``windows_volume_info`` keeps the platform-specific branch testable on
    non-Windows CI.  Live evidence comes from kernel32 only; no shell or
    PowerShell process is started.
    """

    if windows_volume_info is not None:
        return dict(windows_volume_info)
    if sys.platform != "win32":
        return None
    try:  # pragma: no cover - exercised on Windows CI when available
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        volume_path = ctypes.create_unicode_buffer(32768)
        if not kernel32.GetVolumePathNameW(
            wintypes.LPCWSTR(str(path)), volume_path, len(volume_path)
        ):
            return None
        filesystem = ctypes.create_unicode_buffer(256)
        volume_name = ctypes.create_unicode_buffer(256)
        serial = wintypes.DWORD()
        max_component = wintypes.DWORD()
        flags = wintypes.DWORD()
        if not kernel32.GetVolumeInformationW(
            wintypes.LPCWSTR(volume_path.value),
            volume_name,
            len(volume_name),
            ctypes.byref(serial),
            ctypes.byref(max_component),
            ctypes.byref(flags),
            filesystem,
            len(filesystem),
        ):
            return None
        drive_type = int(kernel32.GetDriveTypeW(wintypes.LPCWSTR(volume_path.value)))
        return {
            "mount_path": volume_path.value,
            "fs_type": filesystem.value.lower() or None,
            "source": volume_path.value,
            "drive_type": drive_type,
            "local_hint": drive_type in {2, 3, 6},
            "shared_hint": drive_type == 4,
            "ephemeral_hint": drive_type == 6,
            "format": "windows_volume",
        }
    except (AttributeError, OSError, ValueError):
        return None


def _decode_mountinfo_path(value: str) -> str:
    return _OCTAL_ESCAPE.sub(lambda match: chr(int(match.group(1), 8)), value)


def _mount_record(
    path: str | os.PathLike[str],
    *,
    mountinfo_text: str | None = None,
    darwin_mount_text: str | None = None,
    windows_volume_info: dict[str, Any] | None = None,
    platform: str | None = None,
) -> dict[str, Any]:
    """Return the most-specific platform mount/volume record for ``path``.

    Explicit evidence selects its own path semantics, so Linux, Darwin, and
    Windows fixtures remain provider-free and independent of the test host.
    When no evidence or platform override is supplied, the native host is
    probed and unknown locality remains unknown.
    """
    raw_path = os.fspath(path)
    probe: pathlib.Path | None = None
    path_error: str | None = None
    target_windows: pathlib.PureWindowsPath | None = None
    target_posix: pathlib.PurePosixPath | None = None
    target_platform, platform_error, injected_evidence = _select_path_platform(
        platform=platform,
        mountinfo_text=mountinfo_text,
        darwin_mount_text=darwin_mount_text,
        windows_volume_info=windows_volume_info,
    )
    if platform_error:
        path_error = platform_error
        target = raw_path
    elif target_platform == "win32":
        target_windows, path_error = _windows_absolute_path(raw_path)
        # Only touch the live filesystem when using native, non-injected
        # evidence.  Fixture paths remain lexical and reproducible everywhere.
        if (
            target_windows is not None
            and _host_path_platform() == "win32"
            and not injected_evidence
        ):  # pragma: no cover - Windows CI
            probe = _nearest_existing(pathlib.Path(str(target_windows)))
        target = str(target_windows) if target_windows is not None else raw_path
    else:
        native_platform = _host_path_platform()
        if injected_evidence or target_platform != native_platform:
            target_posix, path_error = _posix_absolute_path(raw_path)
            target = str(target_posix) if target_posix is not None else raw_path
        else:
            concrete = pathlib.Path(raw_path).expanduser().absolute()
            probe = _nearest_existing(concrete)
            # Keep the requested suffix even when the database file (or its project
            # directory) has not been created yet.  Using only ``probe`` would
            # reduce every not-yet-created path to its nearest existing parent and
            # could pick the wrong mount in live evidence.
            target = os.path.realpath(str(concrete))
            target_posix = pathlib.PurePosixPath(target)
    if (
        mountinfo_text is None
        and target_platform == "linux"
        and _host_path_platform() == "linux"
    ):
        try:
            mountinfo_text = pathlib.Path("/proc/self/mountinfo").read_text(
                encoding="utf-8", errors="replace"
            )
        except OSError:
            mountinfo_text = None
    if (
        darwin_mount_text is None
        and target_platform == "darwin"
        and _host_path_platform() == "darwin"
    ):
        try:
            completed = subprocess.run(
                ["/sbin/mount"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=2.0,
                check=False,
            )
            if completed.returncode == 0:
                darwin_mount_text = completed.stdout
        except (OSError, subprocess.TimeoutExpired):
            darwin_mount_text = None
    best: dict[str, Any] | None = None
    if target_platform == "win32" and target_windows is not None:
        best = _windows_volume_record(
            probe or target_windows, windows_volume_info=windows_volume_info
        )
        if best is not None:
            mount_windows, mount_error = _windows_absolute_path(
                str(best.get("mount_path") or "")
            )
            if mount_windows is None or not _pure_path_covers(
                mount_windows, target_windows
            ):
                best = None
                path_error = mount_error or "windows_volume_does_not_cover_target"
    if mountinfo_text:
        for raw_line in mountinfo_text.splitlines():
            fields = raw_line.split()
            try:
                separator = fields.index("-")
            except ValueError:
                continue
            if separator < 6 or separator + 2 >= len(fields):
                continue
            mount_path = _decode_mountinfo_path(fields[4])
            normalized_path = pathlib.PurePosixPath(mount_path)
            normalized = str(normalized_path)
            if target_posix is None or not _pure_path_covers(
                normalized_path, target_posix
            ):
                continue
            row = {
                "mount_path": normalized,
                "fs_type": fields[separator + 1].lower(),
                "source": _decode_mountinfo_path(fields[separator + 2]),
                "format": "linux_mountinfo",
            }
            if best is None or len(normalized_path.parts) > len(
                pathlib.PurePosixPath(str(best["mount_path"])).parts
            ):
                best = row
    if darwin_mount_text:
        for raw_line in darwin_mount_text.splitlines():
            match = _DARWIN_MOUNT_RE.match(raw_line.strip())
            if match is None:
                continue
            mount_path = _decode_mountinfo_path(match.group("path"))
            normalized_path = pathlib.PurePosixPath(mount_path)
            normalized = str(normalized_path)
            if target_posix is None or not _pure_path_covers(
                normalized_path, target_posix
            ):
                continue
            options = [item.strip().lower() for item in match.group("options").split(",")]
            if not options:
                continue
            row = {
                "mount_path": normalized,
                "fs_type": options[0],
                "source": _decode_mountinfo_path(match.group("source")),
                "local_hint": "local" in options,
                "format": "darwin_mount",
            }
            if best is None or len(normalized_path.parts) > len(
                pathlib.PurePosixPath(str(best["mount_path"])).parts
            ):
                best = row
    return {
        "probe_path": str(probe) if probe else None,
        "mount_path": best.get("mount_path") if best else None,
        "fs_type": best.get("fs_type") if best else None,
        "source": best.get("source") if best else None,
        "local_hint": best.get("local_hint") if best else None,
        "shared_hint": best.get("shared_hint") if best else None,
        "ephemeral_hint": best.get("ephemeral_hint") if best else None,
        "drive_type": best.get("drive_type") if best else None,
        "format": best.get("format") if best else None,
        "evidence": "complete" if best else "unknown",
        "path_error": path_error,
        "platform": target_platform,
    }


def check_sqlite_storage(
    path: str | os.PathLike[str],
    *,
    mountinfo_text: str | None = None,
    darwin_mount_text: str | None = None,
    windows_volume_info: dict[str, Any] | None = None,
    platform: str | None = None,
    require_local: bool = True,
) -> dict[str, Any]:
    """Admit a SQLite Controller database only on known-local storage.

    Linux mountinfo, the macOS mount table, and Windows volume APIs are
    read-only evidence. Explicit evidence (or ``platform``) selects path
    semantics independently of the caller's OS. Unknown locality fails closed
    when ``require_local`` is true; callers must opt into compatibility
    explicitly instead of opening a durable controller database on an
    unverified network filesystem.
    """
    raw = os.fspath(path)
    if raw in {":memory:", ""}:
        return {
            "schema_version": SCHEMA_VERSION,
            "read_only": True,
            "path": raw,
            "allowed": True,
            "decision": "admit",
            "locality": "memory",
            "evidence": "explicit",
            "reasons": [],
        }
    target_platform, platform_error, injected_evidence = _select_path_platform(
        platform=platform,
        mountinfo_text=mountinfo_text,
        darwin_mount_text=darwin_mount_text,
        windows_volume_info=windows_volume_info,
    )
    resolved_windows: pathlib.PureWindowsPath | None = None
    resolved_posix: pathlib.PurePosixPath | None = None
    if platform_error:
        resolved_text = raw
        mount_target: str | os.PathLike[str] = raw
    elif target_platform == "win32":
        resolved_windows, _ = _windows_absolute_path(raw)
        resolved_text = str(resolved_windows) if resolved_windows is not None else raw
        mount_target = raw
    elif injected_evidence or target_platform != _host_path_platform():
        resolved_posix, _ = _posix_absolute_path(raw)
        resolved_text = str(resolved_posix) if resolved_posix is not None else raw
        mount_target = raw
    else:
        resolved = pathlib.Path(raw).expanduser().absolute()
        resolved_text = str(resolved)
        mount_target = resolved
    mount = _mount_record(
        mount_target,
        mountinfo_text=mountinfo_text,
        darwin_mount_text=darwin_mount_text,
        windows_volume_info=windows_volume_info,
        platform=platform,
    )
    fs_type = mount.get("fs_type")
    reasons: list[str] = []
    path_error = mount.get("path_error")
    if path_error:
        locality = "unknown"
        if require_local:
            reasons.append(f"sqlite:{path_error}")
    elif mount.get("shared_hint") is True or fs_type in _SHARED_FILESYSTEM_TYPES:
        reasons.append(f"sqlite:shared_filesystem:{fs_type}")
        locality = "shared"
    elif mount.get("ephemeral_hint") is True or fs_type in _EPHEMERAL_FILESYSTEM_TYPES:
        locality = "ephemeral_local"
        if require_local:
            evidence_name = "windows_ramdisk" if mount.get("ephemeral_hint") else fs_type
            reasons.append(f"sqlite:ephemeral_filesystem:{evidence_name}")
    elif fs_type:
        mount_format = mount.get("format")
        if (
            mount_format in {"darwin_mount", "windows_volume"}
            and mount.get("local_hint") is True
        ):
            locality = "local_candidate"
        elif mount_format == "linux_mountinfo" and fs_type in _LOCAL_FILESYSTEM_TYPES:
            locality = "local_candidate"
        else:
            locality = "unknown"
            if require_local:
                reasons.append("sqlite:filesystem_locality_unknown")
    else:
        locality = "unknown"
        if require_local:
            reasons.append("sqlite:filesystem_locality_unknown")
    allowed = not reasons
    known_local = locality in {"local_candidate", "memory"} and allowed
    # Local locking evidence and persistence are distinct.  A database under
    # a conventional temporary root or on a container/ephemeral filesystem
    # may be safe for SQLite locking while still being unsuitable as the sole
    # continuity record across a reboot or environment replacement.
    if resolved_windows is not None:
        temporary_windows = [
            parsed
            for item in (tempfile.gettempdir(),)
            for parsed, error in (_windows_absolute_path(item),)
            if parsed is not None and error is None
        ]
        under_temporary_root = any(
            _pure_path_covers(root, resolved_windows) for root in temporary_windows
        )
    elif resolved_posix is not None:
        temporary_posix = [
            pathlib.PurePosixPath("/tmp"),
            pathlib.PurePosixPath("/var/tmp"),
        ]
        native_temporary, native_error = _posix_absolute_path(tempfile.gettempdir())
        if native_temporary is not None and native_error is None:
            temporary_posix.append(native_temporary)
        under_temporary_root = any(
            _pure_path_covers(root, resolved_posix) for root in temporary_posix
        )
    else:
        path_real = os.path.realpath(resolved_text)
        temporary_roots = {
            os.path.realpath(tempfile.gettempdir()),
            os.path.realpath(os.path.abspath(os.sep + "tmp")),
            os.path.realpath(os.path.abspath(os.sep + "var" + os.sep + "tmp")),
        }
        under_temporary_root = any(
            path_real == root or path_real.startswith(root.rstrip(os.sep) + os.sep)
            for root in temporary_roots
            if root
        )
    persistent = (
        known_local
        and locality == "local_candidate"
        and fs_type not in _NONPERSISTENT_FILESYSTEM_TYPES
        and not under_temporary_root
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "read_only": True,
        "path": resolved_text,
        "allowed": allowed,
        "decision": "admit" if allowed else "block",
        "locality": locality,
        "known_local": known_local,
        "persistent": persistent,
        "evidence": mount.get("evidence"),
        "mount": mount,
        "reasons": reasons,
        "next_action": "move_controller_db_to_local_filesystem" if not allowed else None,
    }


class SQLiteStorageAdmissionError(RuntimeError):
    """Raised before a Controller opens a database on unsafe storage."""

    def __init__(self, report: dict[str, Any]) -> None:
        self.report = report
        reasons = ", ".join(str(item) for item in report.get("reasons") or [])
        super().__init__(
            "SQLite Controller storage blocked before database open: "
            + (reasons or "unknown filesystem locality")
        )


def _nearest_existing(path: pathlib.Path) -> pathlib.Path | None:
    current = path.expanduser().absolute()
    while not current.exists() and current != current.parent:
        current = current.parent
    return current if current.exists() else None


def _filesystem(path: pathlib.Path) -> dict[str, Any]:
    probe = _nearest_existing(path)
    row: dict[str, Any] = {
        "path": str(path.expanduser().absolute()),
        "probe_path": str(probe) if probe else None,
        "evidence": "unknown",
        "source": None,
        "free_bytes": None,
        "total_bytes": None,
        "free_percent": None,
    }
    if probe is None:
        return row
    total: int | None = None
    free: int | None = None
    source: str | None = None
    statvfs = getattr(os, "statvfs", None)
    if callable(statvfs):
        try:
            stat = statvfs(probe)
            total = int(stat.f_blocks) * int(stat.f_frsize)
            free = int(stat.f_bavail) * int(stat.f_frsize)
            source = "statvfs"
        except (AttributeError, OSError, ValueError):
            total = None
            free = None
    if total is None or free is None:
        # ``os.statvfs`` does not exist on Windows.  ``shutil.disk_usage`` is
        # a read-only stdlib wrapper over the platform's local volume API and
        # supplies the byte evidence needed by this launch gate.  Any failure
        # remains unknown and therefore blocks the launch.
        try:
            usage = shutil.disk_usage(probe)
            total = int(usage.total)
            free = int(usage.free)
            source = "disk_usage"
        except (AttributeError, OSError, ValueError):
            return row
    if total <= 0 or free < 0 or free > total:
        return row
    row.update(
        evidence="complete",
        source=source,
        free_bytes=free,
        total_bytes=total,
        free_percent=100.0 * free / total,
    )
    return row


def check_local_launch(
    workspace: str | os.PathLike[str] | None,
    *,
    temporary_directory: str | os.PathLike[str] | None = None,
    additional_paths: list[str | os.PathLike[str]] | tuple[str | os.PathLike[str], ...] = (),
    minimum_free_bytes: int = DEFAULT_MIN_FREE_BYTES,
    minimum_free_percent: float = DEFAULT_MIN_FREE_PERCENT,
    label: str = "local_agent",
) -> dict[str, Any]:
    """Return a deterministic admission decision before a local launch.

    Both the work filesystem and the temporary filesystem are checked.  This
    catches the common case where the project disk has room but Python's
    ``tempfile``/SQLite lock path is on a full volume (or the inverse).
    """
    work = pathlib.Path(workspace or pathlib.Path.cwd()).expanduser().absolute()
    temp = pathlib.Path(temporary_directory or tempfile.gettempdir()).expanduser().absolute()
    candidates = [work, temp, *[pathlib.Path(item).expanduser().absolute() for item in additional_paths]]
    paths: list[dict[str, Any]] = []
    seen_probes: set[str] = set()
    for candidate in candidates:
        row = _filesystem(candidate)
        probe_key = str(row.get("probe_path") or row.get("path") or candidate)
        if probe_key in seen_probes:
            continue
        seen_probes.add(probe_key)
        paths.append(row)
    reasons: list[str] = []
    for row in paths:
        if row["evidence"] != "complete":
            reasons.append(f"{label}:filesystem_evidence_unknown:{row['path']}")
            continue
        free = int(row["free_bytes"])
        free_percent = float(row["free_percent"])
        if free < int(minimum_free_bytes):
            reasons.append(f"{label}:free_bytes_below_floor:{row['path']}")
        if free_percent < float(minimum_free_percent):
            reasons.append(f"{label}:free_percent_below_floor:{row['path']}")
    allowed = not reasons
    return {
        "schema_version": SCHEMA_VERSION,
        "read_only": True,
        "label": label,
        "allowed": allowed,
        "decision": "admit" if allowed else "block",
        "reasons": reasons,
        "minimum_free_bytes": int(minimum_free_bytes),
        "minimum_free_percent": float(minimum_free_percent),
        "filesystems": paths,
        "next_action": "run_remote_or_free_space_with_user_approval" if not allowed else None,
    }


class LocalLaunchAdmissionError(RuntimeError):
    """Raised before ``Popen`` when local filesystem admission is unsafe."""

    def __init__(self, report: dict[str, Any]) -> None:
        self.report = report
        reasons = ", ".join(str(item) for item in report.get("reasons") or [])
        super().__init__(f"local launch blocked before child creation: {reasons or 'unknown resource evidence'}")
