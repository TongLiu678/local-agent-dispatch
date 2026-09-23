#!/usr/bin/env python3
"""Turn live hardware/preflight facts into a local-vs-server fit report.

This command is intentionally read-only.  It does not probe hosts, install a
runtime, download a model, or send a provider prompt.  Host facts must come
from the system-first scan/preflight (or an equivalent user-supplied fixture).
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import sys
from typing import Any


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from dispatch_preflight_scan import local_system_host  # noqa: E402
from dynamic_dispatch_planner import host_fit, resource_estimate  # noqa: E402
from task_estimator import estimate_task as strict_task_estimate  # noqa: E402


SCHEMA_VERSION = 1


def load_json(path: str) -> Any:
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


def _number(value: Any, default: float = 0.0) -> float:
    try:
        return max(0.0, float(value))
    except (TypeError, ValueError):
        return default


def _host_summary(host_id: str, host: dict[str, Any]) -> dict[str, Any]:
    gpus = []
    for gpu in host.get("gpus") or []:
        if not isinstance(gpu, dict):
            continue
        gpus.append(
            {
                "name": gpu.get("name"),
                "vram_total_gib": gpu.get("vram_total_gib"),
                "vram_free_gib": gpu.get("vram_free_gib"),
                "unified_memory": bool(gpu.get("unified_memory", False)),
                "utilization_percent": gpu.get("utilization_percent"),
            }
        )
    storage_paths = []
    for row in host.get("storage_paths") or host.get("disks") or []:
        if not isinstance(row, dict) or not row.get("path"):
            continue
        storage_paths.append(
            {
                "path": row.get("path"),
                "exists": row.get("exists"),
                "writable": row.get("writable"),
                "disk_total_gib": row.get("disk_total_gib"),
                "disk_free_gib": row.get("disk_free_gib"),
            }
        )
    return {
        "host_id": host_id,
        "transport": host.get("transport", "local"),
        "reachable": bool(host.get("reachable", False)),
        "project_path": host.get("project_path"),
        "os": host.get("os"),
        "arch": host.get("arch"),
        "kernel_release": host.get("kernel_release") or host.get("kernel") or host.get("uname_kernel"),
        "logical_cpu_cores": host.get("logical_cpu_cores"),
        "estimated_idle_cpu_cores": host.get("estimated_idle_cpu_cores"),
        "load1": host.get("load1"),
        "load_source": host.get("load_source"),
        "capacity_evidence": host.get("capacity_evidence"),
        "memory_total_gib": host.get("memory_total_gib"),
        "memory_available_gib": host.get("memory_available_gib"),
        "disk_free_gib": host.get("disk_free_gib"),
        "project_path_writable": host.get("project_path_writable"),
        "best_storage_path": host.get("best_storage_path"),
        "best_writable_storage_path": host.get("best_writable_storage_path"),
        "storage_paths": storage_paths,
        "storage_discovery": host.get("storage_discovery"),
        "external_network_evidence": host.get("external_network_evidence"),
        "gpus": gpus,
        "commands": sorted((host.get("commands") or {}).keys()),
        "resource_source": host.get("resource_source"),
    }


def required_server_config(
    estimate: dict[str, Any], job: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Return explicit minimum server facts needed by a workload."""
    return {
        "min_cpu_cores": estimate["cpu_cores"],
        "min_available_ram_gib": estimate["required_available_ram_gib"],
        "min_free_disk_gib": estimate["required_free_disk_gib"],
        "gpu_count": estimate["gpu_count"],
        "min_free_vram_gib_per_gpu": estimate["vram_gib"],
        "required_commands": list(estimate.get("required_commands") or []),
        "min_linux_kernel": estimate.get("min_linux_kernel"),
        "python_version": estimate.get("python_version"),
        "compute_minutes": estimate["compute_minutes"],
        "new_disk_gib": estimate["new_disk_gib"],
        "server_first": estimate["server_first"],
        "server_first_reasons": list(estimate["server_first_reasons"]),
        "confidence": estimate["confidence"],
        "unknowns": list(estimate["unknowns"]),
        "pilot_required": estimate["pilot_required"],
        "requires_external_network": bool((job or {}).get("requires_external_network") is True),
    }


def _candidate(
    job: dict[str, Any], estimate: dict[str, Any], host_id: str, host: dict[str, Any]
) -> dict[str, Any]:
    fit, score, reasons, route, errors = host_fit(job, estimate, host_id, host)
    return {
        "host_id": host_id,
        "fit": fit,
        "score": round(score, 3),
        "transport": host.get("transport", "local"),
        "route": route,
        "reasons": reasons,
        "rejected": errors,
        "host": _host_summary(host_id, host),
    }


def _consistent_estimate(job: dict[str, Any]) -> dict[str, Any]:
    """Apply the strict task-estimator gate to the hardware-fit estimator.

    ``lad fit`` and ``lad dispatch`` must not disagree merely because the
    former uses the planner's legacy convenience defaults.  The detailed
    planner estimate remains useful for host arithmetic, while unknown
    runtime/footprint evidence from the strict estimator is promoted to a
    pilot gate and server-first decision.
    """
    estimate = resource_estimate(job)
    strict = strict_task_estimate(job)
    resources = job.get("resources") if isinstance(job.get("resources"), dict) else {}
    # Preserve the established fit contract when a caller already supplied
    # the workload footprint/runtime hints consumed by the legacy planner.
    # The strict estimator should add a pilot gate for genuinely underspecified
    # jobs, not turn a fully specified server-first request into pilot_first
    # merely because token/network telemetry is absent.  Local-only jobs are
    # likewise governed by their explicit GUI/USB/private-data capability.
    has_footprint_or_runtime_hint = any(
        key in resources
        for key in (
            "input_gib", "download_gib", "environment_gib", "temporary_gib",
            "cache_gib", "output_gib", "compute_minutes", "runtime_minutes",
        )
    )
    local_only = bool(
        job.get("requires_local_gui")
        or job.get("requires_usb")
        or job.get("private_local_only")
    )
    if (
        strict.get("pilot_required")
        and not job.get("pilot")
        and not has_footprint_or_runtime_hint
        and not local_only
    ):
        estimate["pilot_required"] = True
        estimate["unknowns"] = list(strict.get("unknowns") or [])
        estimate["confidence"] = strict.get("confidence", "unknown")
        estimate["server_first"] = strict.get("server_first")
        estimate["server_first_reasons"] = list(strict.get("server_first_reasons") or [])
    return estimate


def _decision(
    job: dict[str, Any],
    estimate: dict[str, Any],
    candidates: list[dict[str, Any]],
) -> dict[str, Any]:
    local = [row for row in candidates if row["transport"] == "local"]
    remote = [row for row in candidates if row["transport"] == "ssh"]
    local_fit = next((row for row in local if row["fit"]), None)
    remote_fit = sorted((row for row in remote if row["fit"]), key=lambda row: -row["score"])
    local_only = bool(job.get("requires_local_gui") or job.get("requires_usb") or job.get("private_local_only"))
    if local_only:
        if local_fit:
            return {
                "action": "run_local",
                "reason": "task_requires_local_capability",
                "selected_host": local_fit["host_id"],
                "server_eligible": False,
            }
        return {
            "action": "blocked",
            "reason": "required_local_capability_does_not_fit",
            "selected_host": None,
            "server_eligible": False,
        }
    if estimate["pilot_required"] and not job.get("pilot"):
        return {
            "action": "pilot_first",
            "reason": "resource_metadata_or_peak_requirement_unknown",
            "selected_host": None,
            "server_eligible": bool(remote_fit),
        }
    if estimate["server_first"]:
        if remote_fit:
            return {
                "action": "run_server",
                "reason": "server_first_gate",
                "selected_host": remote_fit[0]["host_id"],
                "server_eligible": True,
            }
        return {
            "action": "blocked",
            "reason": "server_first_but_no_remote_host_fits",
            "selected_host": None,
            "server_eligible": False,
        }
    if local_fit:
        return {
            "action": "run_local",
            "reason": "local_host_fits_and_workload_is_not_server_first",
            "selected_host": local_fit["host_id"],
            "server_eligible": bool(remote_fit),
        }
    if remote_fit:
        return {
            "action": "run_server",
            "reason": "local_host_does_not_fit_remote_host_available",
            "selected_host": remote_fit[0]["host_id"],
            "server_eligible": True,
        }
    return {
        "action": "blocked",
        "reason": "no_live_host_fits",
        "selected_host": None,
        "server_eligible": False,
    }


def build_report(preflight: dict[str, Any], jobs: list[dict[str, Any]], workspace: pathlib.Path) -> dict[str, Any]:
    local_snapshot = preflight.get("local_system") or {}
    hosts = preflight.get("compute_hosts") or {}
    if not isinstance(hosts, dict):
        hosts = {}
    local_host = local_system_host(local_snapshot, workspace)
    if local_host:
        local_id = next(
            (host_id for host_id, host in hosts.items() if str((host or {}).get("transport", "local")) == "local"),
            "local_system",
        )
        merged = dict(hosts.get(local_id) or {})
        merged.update(local_host)
        hosts = dict(hosts)
        hosts[local_id] = merged

    normalized_hosts = {str(host_id): dict(host or {}) for host_id, host in hosts.items()}
    job_reports: list[dict[str, Any]] = []
    for job in jobs:
        job_id = str(job.get("job_id") or "")
        if not job_id:
            raise ValueError("every job must contain job_id")
        estimate = _consistent_estimate(job)
        candidates = [
            _candidate(job, estimate, host_id, host)
            for host_id, host in sorted(normalized_hosts.items())
        ]
        decision = _decision(job, estimate, candidates)
        job_reports.append(
            {
                "job_id": job_id,
                "task_type": job.get("task_type"),
                "difficulty": job.get("difficulty"),
                "estimate": estimate,
                "required_server_config": required_server_config(estimate, job),
                "decision": decision,
                "candidates": candidates,
            }
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": dt.datetime.now(tz=dt.timezone.utc).isoformat(),
        "read_only": True,
        "source": {
            "preflight_scanned_at_utc": preflight.get("scanned_at_utc"),
            "workspace": str(workspace),
            "hardware_source": "preflight.local_system + preflight.compute_hosts",
        },
        "local_hardware": _host_summary(
            "local_system", local_host or normalized_hosts.get("local_system") or {}
        ),
        "hosts": {
            host_id: _host_summary(host_id, host)
            for host_id, host in sorted(normalized_hosts.items())
        },
        "jobs": job_reports,
        "summary": {
            "job_count": len(job_reports),
            "server_first_jobs": sum(1 for row in job_reports if row["estimate"]["server_first"]),
            "server_eligible_jobs": sum(1 for row in job_reports if row["decision"]["server_eligible"]),
            "blocked_jobs": sum(1 for row in job_reports if row["decision"]["action"] == "blocked"),
            "pilot_jobs": sum(1 for row in job_reports if row["decision"]["action"] == "pilot_first"),
        },
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preflight", required=True, help="system-first preflight JSON")
    parser.add_argument("--jobs", required=True, help="JSON list or {jobs: [...]} workload descriptions")
    parser.add_argument("--workspace", default=".")
    parser.add_argument("--output")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        preflight = load_json(args.preflight)
        raw_jobs = load_json(args.jobs)
        jobs = raw_jobs.get("jobs") if isinstance(raw_jobs, dict) else raw_jobs
        if not isinstance(preflight, dict) or not isinstance(jobs, list):
            raise ValueError("preflight must be an object and jobs must be a list or {jobs: [...]}")
        report = build_report(preflight, jobs, pathlib.Path(args.workspace).expanduser().resolve())
        atomic_write(args.output, report)
        return 0
    except Exception as exc:
        atomic_write(args.output, {"schema_version": SCHEMA_VERSION, "ok": False, "error": f"{type(exc).__name__}: {exc}"})
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
