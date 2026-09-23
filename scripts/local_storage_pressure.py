#!/usr/bin/env python3
"""Bounded, read-only storage pressure report for the local control plane.

This is deliberately not a cleanup tool.  It explains recurring ENOSPC/lock
failures by separating filesystem headroom from bounded sizes of known runtime
roots.  Symlinks are not followed and the scan stops after a fixed number of
entries so a large session directory cannot itself exhaust the control plane.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pathlib
import shutil
import tempfile
from typing import Any, Iterable, Mapping


SCHEMA_VERSION = 1
DEFAULT_MAX_ENTRIES = 10_000
DEFAULT_MAX_DEPTH = 3
GIB = 1024**3


def _now() -> str:
    return dt.datetime.now(tz=dt.timezone.utc).isoformat()


def _safe_path(value: str | os.PathLike[str]) -> pathlib.Path:
    return pathlib.Path(value).expanduser().absolute()


def _walk_bounded(root: pathlib.Path, *, max_entries: int, max_depth: int) -> dict[str, Any]:
    files = 0
    directories = 0
    bytes_seen = 0
    entries_seen = 0
    truncated = False
    depth_limited_directories = 0
    largest: list[dict[str, Any]] = []

    def visit(directory: pathlib.Path, depth: int) -> None:
        nonlocal files, directories, bytes_seen, entries_seen, truncated
        nonlocal depth_limited_directories
        try:
            children = list(os.scandir(directory))
        except (OSError, PermissionError):
            return
        for entry in children:
            if entries_seen >= max_entries:
                truncated = True
                return
            entries_seen += 1
            try:
                stat = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            if entry.is_symlink():
                continue
            if entry.is_dir(follow_symlinks=False):
                directories += 1
                if depth < max_depth:
                    visit(pathlib.Path(entry.path), depth + 1)
                else:
                    # Do not recurse indefinitely through session/cache trees,
                    # but never present a shallow scan as a complete size
                    # measurement.  Callers can use this as a lower bound.
                    depth_limited_directories += 1
                continue
            if not entry.is_file(follow_symlinks=False):
                continue
            size = max(0, int(stat.st_size))
            files += 1
            bytes_seen += size
            largest.append({"path": str(pathlib.Path(entry.path)), "bytes": size})
            largest.sort(key=lambda row: (-int(row["bytes"]), str(row["path"])))
            del largest[10:]

    if root.is_dir():
        visit(root, 0)
    return {
        "path": str(root),
        "exists": root.exists(),
        "scan_complete": not (truncated or depth_limited_directories),
        "truncated": truncated,
        "depth_limited": bool(depth_limited_directories),
        "depth_limited_directories": depth_limited_directories,
        "bytes_seen_is_lower_bound": bool(truncated or depth_limited_directories),
        "entries_seen": entries_seen,
        "directories": directories,
        "files": files,
        "bytes_seen": bytes_seen,
        "gib_seen": round(bytes_seen / GIB, 6),
        "largest_files": largest,
    }


def _disk(path: pathlib.Path) -> dict[str, Any]:
    try:
        usage = shutil.disk_usage(path if path.exists() else path.parent)
    except OSError:
        return {"path": str(path), "evidence": "unknown"}
    free_percent = 100.0 * usage.free / usage.total if usage.total else None
    return {
        "path": str(path),
        "evidence": "complete",
        "total_bytes": int(usage.total),
        "free_bytes": int(usage.free),
        "free_gib": round(usage.free / GIB, 6),
        "free_percent": round(free_percent, 6) if free_percent is not None else None,
    }


def build_report(
    roots: Iterable[str | os.PathLike[str]],
    *,
    temporary_directory: str | os.PathLike[str] | None = None,
    max_entries: int = DEFAULT_MAX_ENTRIES,
    max_depth: int = DEFAULT_MAX_DEPTH,
    minimum_free_bytes: int = 20 * GIB,
    minimum_free_percent: float = 10.0,
    previous_report: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a privacy-safe pressure report without deleting or writing data."""
    normalized_roots: list[pathlib.Path] = []
    seen: set[str] = set()
    for value in roots:
        path = _safe_path(value)
        if str(path) not in seen:
            normalized_roots.append(path)
            seen.add(str(path))
    temp = _safe_path(temporary_directory or tempfile.gettempdir())
    if str(temp) not in seen:
        normalized_roots.append(temp)
        seen.add(str(temp))
    disks = [_disk(path) for path in normalized_roots]
    pressured_disks = [
        row["path"]
        for row in disks
        if row.get("evidence") != "complete"
        or int(row.get("free_bytes") or 0) < int(minimum_free_bytes)
        or float(row.get("free_percent") or 0.0) < float(minimum_free_percent)
    ]
    root_reports = [
        _walk_bounded(path, max_entries=max(1, int(max_entries)), max_depth=max(0, int(max_depth)))
        for path in normalized_roots
    ]
    comparison: dict[str, Any] | None = None
    if isinstance(previous_report, Mapping):
        previous_disks = {
            str(row.get("path")): row
            for row in previous_report.get("disks", [])
            if isinstance(row, Mapping) and row.get("path")
        }
        disk_deltas = []
        for row in disks:
            old = previous_disks.get(str(row.get("path")))
            if not isinstance(old, Mapping):
                continue
            if row.get("free_bytes") is None or old.get("free_bytes") is None:
                continue
            disk_deltas.append({
                "path": row["path"],
                "free_bytes_delta": int(row["free_bytes"]) - int(old["free_bytes"]),
                "free_bytes_direction": (
                    "freed" if int(row["free_bytes"]) > int(old["free_bytes"])
                    else "consumed" if int(row["free_bytes"]) < int(old["free_bytes"])
                    else "unchanged"
                ),
            })
        previous_roots = {
            str(row.get("path")): row
            for row in previous_report.get("roots", [])
            if isinstance(row, Mapping) and row.get("path")
        }
        root_deltas = []
        for row in root_reports:
            old = previous_roots.get(str(row.get("path")))
            if not isinstance(old, Mapping):
                continue
            if row.get("bytes_seen") is None or old.get("bytes_seen") is None:
                continue
            root_deltas.append({
                "path": row["path"],
                "bytes_seen_delta": int(row["bytes_seen"]) - int(old["bytes_seen"]),
                "lower_bound": bool(
                    row.get("bytes_seen_is_lower_bound")
                    or old.get("bytes_seen_is_lower_bound")
                ),
            })
        comparison = {
            "previous_observed_at_utc": previous_report.get("observed_at_utc"),
            "disk_deltas": disk_deltas,
            "root_observed_deltas": root_deltas,
            "interpretation": (
                "directional_only_lower_bound_for_roots"
                if any(row["lower_bound"] for row in root_deltas)
                else "directional_observed_delta"
            ),
        }
    return {
        "schema_version": SCHEMA_VERSION,
        "report_type": "local-agent-dispatch.local-storage-pressure",
        "observed_at_utc": _now(),
        "read_only": True,
        "provider_execution": False,
        "disk_pressure": bool(pressured_disks),
        "pressured_disks": pressured_disks,
        "roots": root_reports,
        "disks": disks,
        "comparison": comparison,
        "policy": {
            "minimum_free_bytes": int(minimum_free_bytes),
            "minimum_free_percent": float(minimum_free_percent),
            "new_local_launch_allowed": not bool(pressured_disks),
            "local_bulk_allowed": not bool(pressured_disks),
            "cleanup_required_by_user": bool(pressured_disks),
            "automatic_delete": False,
        },
        "next_action": (
            "route_heavy_work_remote_and_request_user_approved_archive_or_cleanup"
            if pressured_disks
            else "continue_with_resource_admission"
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", action="append", default=[], help="known runtime root to inspect")
    parser.add_argument("--temporary-directory")
    parser.add_argument("--max-entries", type=int, default=DEFAULT_MAX_ENTRIES)
    parser.add_argument("--max-depth", type=int, default=DEFAULT_MAX_DEPTH)
    parser.add_argument("--previous", help="read a prior JSON report for directional comparison")
    parser.add_argument("--output", default="-")
    args = parser.parse_args(argv)
    roots = args.root or [
        str(pathlib.Path.home() / ".codex" / "sessions"),
        str(pathlib.Path.home() / ".codex" / "local-agent-dispatch"),
    ]
    previous_report = None
    if args.previous:
        try:
            loaded = json.loads(_safe_path(args.previous).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            parser.error(f"--previous is not valid JSON: {exc}")
        if not isinstance(loaded, Mapping):
            parser.error("--previous must contain a JSON object")
        previous_report = loaded
    report = build_report(
        roots,
        temporary_directory=args.temporary_directory,
        max_entries=args.max_entries,
        max_depth=args.max_depth,
        previous_report=previous_report,
    )
    text = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output == "-":
        print(text, end="")
    else:
        target = _safe_path(args.output)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
