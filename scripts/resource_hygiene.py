#!/usr/bin/env python3
"""Compose a read-only local resource attribution and server-first queue report.

The report joins existing provider-free system and bounded storage evidence.  It
never deletes files, signals processes, starts an agent, or probes a remote
host.  Its purpose is to explain *why* local admission is blocked and to make
the next user-controlled cleanup/archive or verified-server placement decision
small and auditable.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import platform
import sys
from collections.abc import Mapping
from typing import Any

import local_storage_pressure
import local_system_scan


SCHEMA_VERSION = 1
DEFAULT_MAX_ENTRIES = 2_000
DEFAULT_MAX_DEPTH = 2


def _integer(value: Any) -> int | None:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return None


def _display_path(value: str | os.PathLike[str]) -> str:
    path = pathlib.Path(value).expanduser().absolute()
    try:
        relative = path.relative_to(pathlib.Path.home())
    except ValueError:
        return str(path)
    return "~" if str(relative) == "." else str(pathlib.Path("~") / relative)


def _rss_bytes(row: Mapping[str, Any]) -> int | None:
    direct = _integer(row.get("rss_bytes"))
    if direct is not None:
        return direct
    kib = _integer(row.get("rss_kib"))
    return None if kib is None else kib * 1024


def process_attribution(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    """Aggregate only argument-free Agent/runtime process RSS evidence."""
    process_section = snapshot.get("agent_model_processes")
    source_rows = (
        process_section.get("processes", [])
        if isinstance(process_section, Mapping)
        else []
    )
    rows: list[dict[str, Any]] = []
    by_command: dict[str, int] = {}
    by_kind: dict[str, int] = {}
    unknown_rss_count = 0
    for source in source_rows:
        if not isinstance(source, Mapping):
            continue
        pid = _integer(source.get("pid"))
        command = str(source.get("command_name") or "unknown")
        kind = str(source.get("kind") or "unknown")
        rss = _rss_bytes(source)
        if rss is None:
            unknown_rss_count += 1
        else:
            by_command[command] = by_command.get(command, 0) + rss
            by_kind[kind] = by_kind.get(kind, 0) + rss
        row = {"pid": pid, "command_name": command, "kind": kind, "rss_bytes": rss}
        rows.append(row)
    rows.sort(key=lambda row: (-(row["rss_bytes"] or 0), row["pid"] or 0))
    return {
        "scan_ok": bool(
            isinstance(process_section, Mapping) and process_section.get("scan_ok")
        ),
        "arguments_collected": False,
        "rss_evidence": "complete" if rows and unknown_rss_count == 0 else "partial",
        "rss_total_bytes": sum(by_command.values()),
        "by_command_bytes": dict(sorted(by_command.items())),
        "by_kind_bytes": dict(sorted(by_kind.items())),
        "unknown_rss_processes": unknown_rss_count,
        "top_processes": rows[:10],
    }


def cgroup_memory_attribution(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    """Separate cgroup anonymous memory, file cache, and slab evidence.

    ``memory.stat:anon`` is an aggregate anonymous-memory signal, not a
    per-model RSS measurement.  ``file`` (with active/inactive breakdown) and
    ``slab`` are deliberately reported in separate buckets and never added to
    ``agent_rss.rss_total_bytes``.
    """
    source: Mapping[str, Any] | None = None
    direct = snapshot.get("cgroup_memory_stat")
    if isinstance(direct, Mapping):
        source = direct
    elif isinstance(snapshot.get("ram"), Mapping) and isinstance(
        snapshot["ram"].get("cgroup_memory_stat"), Mapping
    ):
        source = snapshot["ram"]["cgroup_memory_stat"]
    fields = ("anon", "file", "active_file", "inactive_file", "slab")
    if source is None:
        flat_source = {
            field: snapshot.get(f"cgroup_memory_{field}_bytes")
            for field in fields
        }
        if isinstance(snapshot.get("ram"), Mapping):
            flat_source = {
                field: (
                    value
                    if value is not None
                    else snapshot["ram"].get(f"cgroup_memory_{field}_bytes")
                )
                for field, value in flat_source.items()
            }
        if any(value is not None for value in flat_source.values()):
            source = flat_source
    values = {
        field: _integer(source.get(field)) if source is not None else None
        for field in fields
    }
    known = [value for value in values.values() if value is not None]
    if not known:
        evidence = "unknown"
    elif len(known) == len(fields):
        evidence = "complete"
    else:
        evidence = "partial"
    current = _integer(snapshot.get("cgroup_memory_current_bytes"))
    if current is None and isinstance(snapshot.get("ram"), Mapping):
        current = _integer(snapshot["ram"].get("cgroup_memory_current_bytes"))
    # active_file and inactive_file are subdivisions of file; do not count
    # them a second time when estimating the disjoint cgroup buckets.
    accounted = sum(
        values[field] or 0 for field in ("anon", "file", "slab")
    )
    return {
        "evidence": evidence,
        "source": "cgroup_v2_memory.stat" if evidence != "unknown" else None,
        "anon_bytes": values["anon"],
        "file_bytes": values["file"],
        "active_file_bytes": values["active_file"],
        "inactive_file_bytes": values["inactive_file"],
        "slab_bytes": values["slab"],
        "anonymous_memory_bytes": values["anon"],
        "file_cache_bytes": values["file"],
        "kernel_slab_bytes": values["slab"],
        "accounted_bytes": accounted if known else 0,
        "current_bytes": current,
        "unaccounted_bytes": max(0, current - accounted) if current is not None else None,
        "agent_model_rss_bytes": None,
        "file_cache_excluded_from_agent_rss": True,
        "anonymous_memory_is_not_per_process_rss": True,
    }


def storage_attribution(
    storage_report: Mapping[str, Any], labels: Mapping[str, str]
) -> list[dict[str, Any]]:
    """Attach stable roles to bounded storage facts without exposing children."""
    normalized_labels = {
        str(pathlib.Path(path).expanduser().absolute()): str(label)
        for path, label in labels.items()
    }
    rows: list[dict[str, Any]] = []
    for source in storage_report.get("roots", []):
        if not isinstance(source, Mapping) or not source.get("path"):
            continue
        raw_path = str(pathlib.Path(str(source["path"])).expanduser().absolute())
        rows.append(
            {
                "role": normalized_labels.get(raw_path, "temporary_or_other"),
                "path": _display_path(raw_path),
                "exists": bool(source.get("exists")),
                "bytes_seen": _integer(source.get("bytes_seen")) or 0,
                "bytes_seen_is_lower_bound": bool(
                    source.get("bytes_seen_is_lower_bound")
                ),
                "scan_complete": bool(source.get("scan_complete")),
                "entries_seen": _integer(source.get("entries_seen")) or 0,
            }
        )
    rows.sort(key=lambda row: (-int(row["bytes_seen"]), str(row["role"])))
    return rows


def _queue_reasons(
    snapshot: Mapping[str, Any], storage_report: Mapping[str, Any]
) -> list[str]:
    gates = snapshot.get("capacity_gates")
    gates = gates if isinstance(gates, Mapping) else {}
    reasons: set[str] = set()
    if bool(gates.get("disk_pressure")) or bool(storage_report.get("disk_pressure")):
        reasons.add("local_disk_pressure")
    if gates.get("unknown_disks"):
        reasons.add("local_disk_evidence_unknown")
    memory_state = str(
        gates.get("memory_pressure_state")
        or (snapshot.get("ram") or {}).get("pressure_state")
        or "unknown"
    ).lower()
    if memory_state in {"conserve", "critical", "emergency"}:
        reasons.add(f"local_memory_pressure_{memory_state}")
    if gates.get("local_agent_launch_allowed") is False and not reasons:
        reasons.add("local_launch_admission_blocked")
    return sorted(reasons)


def build_report(
    snapshot: Mapping[str, Any],
    storage_report: Mapping[str, Any],
    *,
    storage_labels: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Return deterministic attribution and non-executing placement advice."""
    labels = dict(storage_labels or {})
    storage_rows = storage_attribution(storage_report, labels)
    processes = process_attribution(snapshot)
    cgroup_memory = cgroup_memory_attribution(snapshot)
    reasons = _queue_reasons(snapshot, storage_report)
    review_items = [
        {
            "role": row["role"],
            "observed_bytes": row["bytes_seen"],
            "measurement": (
                "lower_bound" if row["bytes_seen_is_lower_bound"] else "complete"
            ),
            "suggested_action": "review_archive_or_remove_manually",
        }
        for row in storage_rows
        if row["exists"] and row["bytes_seen"] > 0
    ]
    if processes["rss_total_bytes"]:
        review_items.append(
            {
                "role": "agent_process_rss",
                "observed_bytes": processes["rss_total_bytes"],
                "measurement": processes["rss_evidence"],
                "suggested_action": "review_owned_sessions_and_close_via_owning_app",
            }
        )
    gates = snapshot.get("capacity_gates")
    gates = gates if isinstance(gates, Mapping) else {}
    return {
        "schema_version": SCHEMA_VERSION,
        "report_type": "local-agent-dispatch.resource-hygiene",
        "observed_at_utc": snapshot.get("scanned_at_utc"),
        "evidence": {
            "system_snapshot_schema_version": snapshot.get("schema_version"),
            "storage_report_schema_version": storage_report.get("schema_version"),
            "storage_measurements_may_be_lower_bounds": any(
                row["bytes_seen_is_lower_bound"] for row in storage_rows
            ),
        },
        "attribution": {
            "storage": storage_rows,
            "agent_rss": processes,
            "cgroup_memory": cgroup_memory,
        },
        "placement": {
            "decision": (
                "queue_for_verified_remote" if reasons else "server_first_preferred"
            ),
            "queue_reason_codes": reasons,
            "new_local_agent_launch_allowed": bool(
                gates.get("local_agent_launch_allowed") and not reasons
            ),
            "heavy_execution_target": "verified_remote_server",
            "remote_preflight_required": True,
            "automatic_remote_start": False,
        },
        "review_items": review_items,
        "safety": {
            "read_only": True,
            "provider_execution": False,
            "network_probe": False,
            "automatic_delete": False,
            "automatic_kill": False,
            "automatic_signal": False,
            "automatic_agent_start": False,
            "process_arguments_collected": False,
        },
        "next_action": (
            "keep_local_control_plane_read_only_and_queue_preapproved_work_for_remote_preflight"
            if reasons
            else "continue_with_transactional_resource_admission_and_remote_preflight"
        ),
    }


def _default_roots(cache: pathlib.Path) -> dict[pathlib.Path, str]:
    codex_root = pathlib.Path.home() / ".codex"
    return {
        codex_root / "sessions": "codex_sessions",
        codex_root / "logs": "codex_logs",
        codex_root / "local-agent-dispatch": "dispatch_runtime",
        cache: "dispatch_cache",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", default=str(pathlib.Path.cwd()))
    parser.add_argument("--cache-dir")
    parser.add_argument("--max-entries", type=int, default=DEFAULT_MAX_ENTRIES)
    parser.add_argument("--max-depth", type=int, default=DEFAULT_MAX_DEPTH)
    parser.add_argument("--timeout", type=float, default=4.0)
    parser.add_argument("--compact", action="store_true")
    args = parser.parse_args(argv)

    workspace = pathlib.Path(args.workspace).expanduser()
    system_name = platform.system() or "Unknown"
    cache = pathlib.Path(args.cache_dir).expanduser() if args.cache_dir else (
        local_system_scan.default_cache_dir(system_name)
    )
    roots = _default_roots(cache)
    snapshot = local_system_scan.build_snapshot(
        workspace, cache, max(0.2, min(float(args.timeout), 30.0))
    )
    storage = local_storage_pressure.build_report(
        roots,
        max_entries=max(1, int(args.max_entries)),
        max_depth=max(0, int(args.max_depth)),
    )
    report = build_report(
        snapshot,
        storage,
        storage_labels={str(path): role for path, role in roots.items()},
    )
    print(
        json.dumps(
            report,
            ensure_ascii=False,
            indent=None if args.compact else 2,
            separators=(",", ":") if args.compact else None,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
