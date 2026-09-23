#!/usr/bin/env python3
"""Run the provider-free, system-first dispatch planning workflow.

The workflow is deliberately a *preflight* boundary.  It can read a saved
preflight snapshot (the default, fully offline mode), or an explicitly opted
in live preflight can discover provider/SSH state.  Neither mode launches a
model, sends a prompt, starts a runtime, mutates a worktree, or enqueues a
job.  The output is a versioned report that can be reviewed before the
separate packet/controller commands are used.

The stage order is intentionally visible in the report::

    local system scan -> preflight snapshot -> task estimate -> hardware fit
    -> rolling-horizon planner

``run_workflow`` and ``build_report`` are pure orchestration surfaces used by
the fake-only tests and by the thin ``lad dispatch`` CLI wrapper.
"""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import json
import os
import pathlib
import subprocess
import sys
import tempfile
from collections.abc import Callable, Mapping, Sequence
from typing import Any


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import dispatch_preflight_scan as preflight_scan  # noqa: E402
import dynamic_dispatch_planner as planner  # noqa: E402
import hardware_fit_planner as hardware_fit  # noqa: E402
import task_estimator  # noqa: E402


REPORT_SCHEMA_VERSION = 1
REPORT_TYPE = "local-agent-dispatch.workflow"
STAGES = ("system_scan", "preflight", "task_estimate", "hardware_fit", "planner")

CODEX_LUNA_MAX_POLICY = {
    "name": "codex-luna-max",
    "provider": "codex",
    "pool_id": "codex.luna",
    "model": "gpt-5.6-luna",
    "variant": "max",
    "excluded_pools": [
        "codex.spark",
        "cursor.composer_grok",
        "cursor.other",
        "antigravity.gemini",
        "antigravity.claude_gpt",
        "opencode.go",
    ],
}

CODEX_SOL_MAX_POLICY = {
    "name": "codex-sol-max",
    "provider": "codex",
    # The Codex account pool is shared across GPT-5.6 tiers; the model is
    # nevertheless exact here so the planner cannot silently fall back to
    # Luna, Terra, Spark, or another provider.
    "pool_id": "codex.luna",
    "model": "gpt-5.6-sol",
    "variant": "max",
    "excluded_pools": [
        "codex.spark",
        "cursor.composer_grok",
        "cursor.other",
        "antigravity.gemini",
        "antigravity.claude_gpt",
        "opencode.go",
    ],
}

SPARK_ANTIGRAVITY_GEMINI_POLICY = {
    "name": "codex-spark-antigravity-gemini",
    "routes": {
        "codex.spark": {
            "provider": "codex",
            "model": "gpt-5.3-codex-spark",
            "variant": "xhigh",
        },
        "antigravity.gemini": {
            "provider": "antigravity",
            "model": "gemini-3.6-flash-high",
            "variant": None,
            "approval": "task_exact_model",
            "catalog_gate": "fresh_exact_slug_required",
            "fallback": "none_without_new_exact_approval",
        },
    },
    "excluded_pools": [
        "codex.luna",
        "cursor.composer_grok",
        "cursor.other",
        "antigravity.claude_gpt",
        "opencode.go",
    ],
}


def _apply_model_policy(
    jobs: Sequence[Mapping[str, Any]], model_policy: str | None
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    """Apply an explicit task-local model route without contacting a provider.

    Named policies are task-local allow-lists, not global quota or readiness
    claims.  Existing task requests that name another pool/model are rejected
    instead of silently overwritten.  In particular, the Gemini route is an
    exact approval for ``gemini-3.6-flash-high`` only; the planner must still
    find that slug in fresh catalog evidence and pass the pool health/quota
    gates.  There is no implicit fallback to another catalog member.
    """

    policy_name = str(model_policy or "auto").strip().lower()
    if policy_name in {"", "auto"}:
        return [dict(job) for job in jobs], None
    if policy_name not in {
        "codex-luna-max",
        "codex-sol-max",
        "codex-spark-antigravity-gemini",
    }:
        raise ValueError(
            "unsupported model policy "
            f"{model_policy!r}; expected 'auto', 'codex-luna-max', or "
            "'codex-sol-max', or 'codex-spark-antigravity-gemini'"
        )

    if policy_name in {"codex-luna-max", "codex-sol-max"}:
        policy = (
            CODEX_LUNA_MAX_POLICY
            if policy_name == "codex-luna-max"
            else CODEX_SOL_MAX_POLICY
        )
        route_specs = {
            "codex.luna": {
                "model": policy["model"],
                "variant": policy["variant"],
            }
        }
        route_policy = policy
    else:
        route_specs = SPARK_ANTIGRAVITY_GEMINI_POLICY["routes"]
        route_policy = SPARK_ANTIGRAVITY_GEMINI_POLICY

    result: list[dict[str, Any]] = []
    conflicts: list[str] = []

    def model_ids(value: Any) -> set[str]:
        if isinstance(value, str):
            return {value} if value.strip() else set()
        if isinstance(value, Mapping):
            for key in ("model", "exact_model"):
                if value.get(key):
                    return model_ids(value.get(key))
            found: set[str] = set()
            for item in value.values():
                found.update(model_ids(item))
            return found
        if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
            found: set[str] = set()
            for item in value:
                found.update(model_ids(item))
            return found
        return set()

    for raw_job in jobs:
        job = dict(raw_job)
        job_id = str(job.get("job_id") or job.get("task_id") or "<unknown>")
        existing_pools = {str(item) for item in (job.get("allowed_pools") or []) if item}
        allowed_route_pools = set(route_specs)
        if existing_pools and not existing_pools.issubset(allowed_route_pools):
            conflicts.append(f"{job_id}: allowed_pools={sorted(existing_pools)!r}")
        selected_pools = (
            existing_pools & allowed_route_pools
            if existing_pools
            else allowed_route_pools
        )

        overrides = job.get("model_by_pool")
        if isinstance(overrides, Mapping):
            for pool_id, value in overrides.items():
                pool_name = str(pool_id)
                if pool_name not in selected_pools:
                    conflicts.append(f"{job_id}: model_by_pool contains {pool_id!r}")
                    continue
                requested = value.get("model") if isinstance(value, Mapping) else value
                expected_model = route_specs[pool_name]["model"]
                if requested and str(requested) != expected_model:
                    conflicts.append(f"{job_id}: requested model={requested!r}")
                if isinstance(value, Mapping) and value.get("variant") not in {
                    None,
                    "",
                    route_specs[pool_name].get("variant"),
                }:
                    conflicts.append(f"{job_id}: requested variant={value.get('variant')!r}")

        explicit_model_sources = [job.get("allowed_models"), job.get("approved_models")]
        task_policy = job.get("__dispatch_policy") or job.get("policy")
        if isinstance(task_policy, Mapping):
            explicit_model_sources.extend(
                [task_policy.get("allowed_models"), task_policy.get("approved_models")]
            )
        requested_models = {
            model for source in explicit_model_sources for model in model_ids(source)
        }
        route_models = {str(route_specs[pool]["model"]) for pool in selected_pools}
        unsupported_models = requested_models - route_models
        if unsupported_models:
            conflicts.append(f"{job_id}: allowed models={sorted(unsupported_models)!r}")

        # Keep the exact contract in the normalized job so both the planner
        # and the independent post-planner policy gate see the same route.
        job["allowed_pools"] = sorted(selected_pools)
        job["allowed_models"] = {
            pool_id: [str(route_specs[pool_id]["model"])]
            for pool_id in sorted(selected_pools)
        }
        job["model_by_pool"] = {
            pool_id: {
                "model": str(route_specs[pool_id]["model"]),
                "variant": route_specs[pool_id].get("variant"),
            }
            for pool_id in sorted(selected_pools)
        }
        result.append(job)

    if conflicts:
        raise ValueError(
            f"{policy_name} conflicts with explicit task model policy: "
            + "; ".join(conflicts)
        )
    return result, copy.deepcopy(route_policy)


def now_utc() -> str:
    return dt.datetime.now(tz=dt.timezone.utc).isoformat()


def load_json(path: pathlib.Path) -> Any:
    return json.loads(path.expanduser().read_text(encoding="utf-8"))


def write_json(path: pathlib.Path | None, payload: Mapping[str, Any]) -> None:
    text = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if path is None:
        print(text, end="")
        return
    target = path.expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(target.suffix + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    temporary.replace(target)


def _json_command(
    argv: Sequence[str],
    *,
    cwd: pathlib.Path,
    timeout: float,
    preserve_environment: bool = False,
) -> dict[str, Any]:
    """Run a discovery helper and parse its JSON output.

    This helper is only used for system/preflight discovery.  The workflow
    never passes model prompts or execution commands to it.  The default
    environment is deliberately scrubbed; live provider credentials are
    preserved only when the caller explicitly enables ``--live-probes``.
    """

    env = os.environ.copy() if preserve_environment else {
        key: value
        for key, value in os.environ.items()
        if not key.upper().endswith("_KEY")
        and not any(token in key.upper() for token in ("TOKEN", "PASSWORD", "SECRET"))
    }
    env["PYTHONIOENCODING"] = "utf-8"
    env["NODE_DISABLE_COMPILE_CACHE"] = "1"
    try:
        completed = subprocess.run(
            list(argv),
            cwd=str(cwd),
            env=env,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=max(1.0, float(timeout)),
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "ok": False,
            "returncode": 124,
            "error": "discovery command timed out",
            "stderr": str(exc),
            "stdout": "",
        }
    except OSError as exc:
        return {
            "ok": False,
            "returncode": 127,
            "error": f"discovery command unavailable: {exc}",
            "stderr": str(exc),
            "stdout": "",
        }
    stdout = completed.stdout.strip()
    try:
        value = json.loads(stdout) if stdout else {}
    except json.JSONDecodeError as exc:
        return {
            "ok": False,
            "returncode": completed.returncode,
            "error": f"discovery output is not JSON: {exc}",
            "stderr": completed.stderr.strip(),
            "stdout": stdout[-2000:],
        }
    payload = value if isinstance(value, dict) else {"value": value}
    payload.setdefault("ok", completed.returncode == 0)
    payload.setdefault("returncode", completed.returncode)
    if completed.stderr.strip():
        payload.setdefault("stderr", completed.stderr.strip()[-2000:])
    return payload


def _local_scan(
    workspace: pathlib.Path,
    *,
    timeout: float,
    snapshot: Mapping[str, Any] | None,
    runner: Callable[..., dict[str, Any]] | None,
) -> dict[str, Any]:
    if snapshot is not None:
        return dict(snapshot)
    command = [
        sys.executable,
        str(SCRIPT_DIR / "local_system_scan.py"),
        "--workspace",
        str(workspace),
        "--timeout",
        str(min(max(float(timeout), 1.0), 30.0)),
        "--output",
        "-",
    ]
    invoke = runner or _json_command
    return dict(invoke(command, cwd=workspace, timeout=max(10.0, timeout + 10.0)))


def _live_preflight(
    workspace: pathlib.Path,
    inventory: pathlib.Path,
    *,
    timeout: float,
    verify_racknerd_routes: bool,
    verify_external_network: bool,
    model_state: pathlib.Path | None,
    runtime_state: pathlib.Path | None,
    skip_antigravity_usage: bool,
    opencode_go_usage_endpoint: str | None,
    skip_opencode_go_usage: bool,
    runner: Callable[..., dict[str, Any]] | None,
) -> dict[str, Any]:
    """Discover provider/SSH state only when the caller explicitly opts in."""

    # SSH and route verification are multi-hop discovery operations.  A
    # caller may use a small planner timeout for local work, but passing that
    # value straight through makes the unified workflow silently lose remote
    # hosts before planning.  Keep the provider-free probe bounded while
    # giving each remote helper a deterministic minimum window.
    probe_timeout = max(60.0, float(timeout))
    command = [
        sys.executable,
        str(SCRIPT_DIR / "dispatch_preflight_scan.py"),
        "--cwd",
        str(workspace),
        "--inventory",
        str(inventory),
        "--timeout",
        str(probe_timeout),
    ]
    if verify_racknerd_routes:
        command.append("--verify-racknerd-routes")
    if verify_external_network:
        command.append("--verify-external-network")
    if model_state is not None:
        command.extend(("--model-state", str(model_state)))
    if runtime_state is not None:
        command.extend(("--runtime-state", str(runtime_state)))
    if skip_antigravity_usage:
        command.append("--skip-antigravity-usage")
    if opencode_go_usage_endpoint is not None:
        command.extend(("--opencode-go-usage-endpoint", str(opencode_go_usage_endpoint)))
    if skip_opencode_go_usage:
        command.append("--skip-opencode-go-usage")

    invoke = runner or _json_command
    return dict(
        invoke(
            command,
            cwd=workspace,
            timeout=max(120.0, probe_timeout * 6.0 + 30.0),
            preserve_environment=True,
        )
    )


def _merge_local_snapshot(
    preflight: Mapping[str, Any], local_system: Mapping[str, Any], workspace: pathlib.Path
) -> dict[str, Any]:
    """Make the system-first snapshot authoritative inside saved preflight."""

    merged = copy.deepcopy(dict(preflight))
    merged["local_system"] = copy.deepcopy(dict(local_system))
    pools = merged.get("pools")
    if isinstance(pools, dict):
        # Older Antigravity snapshots called the fresh catalog
        # ``schedulable_models``.  Normalize that legacy shape before the
        # planner sees it so an exact route cannot pass on an empty catalog.
        for pool in pools.values():
            if not isinstance(pool, dict) or "catalog_models" in pool:
                continue
            raw_catalog = pool.get("schedulable_models")
            if isinstance(raw_catalog, str):
                catalog_values = [raw_catalog]
            elif isinstance(raw_catalog, Sequence) and not isinstance(
                raw_catalog, (bytes, bytearray)
            ):
                catalog_values = raw_catalog
            else:
                continue
            rejected = {
                str(item)
                for item in (pool.get("rejected_models") or [])
                if item
            }
            pool["catalog_models"] = sorted(
                {str(item) for item in catalog_values if item} - rejected
            )
        provider_catalogs = merged.get("provider_catalogs")
        codex_catalogs = (
            provider_catalogs.get("codex")
            if isinstance(provider_catalogs, Mapping)
            else None
        )
        if isinstance(codex_catalogs, Mapping):
            for pool_id, keys in {
                "codex.luna": ("luna", "sol"),
                "codex.spark": ("spark",),
            }.items():
                pool = pools.get(pool_id)
                if not isinstance(pool, dict) or "catalog_models" in pool:
                    continue
                models: set[str] = set()
                variants: dict[str, set[str]] = {}
                for key in keys:
                    capability = codex_catalogs.get(key)
                    if not isinstance(capability, Mapping) or capability.get("ok") is not True:
                        continue
                    model = str(capability.get("model") or "")
                    effort = str(capability.get("effort") or "")
                    if not model or not effort:
                        continue
                    models.add(model)
                    variants.setdefault(model, set()).add(effort)
                # Preserve exact capability evidence from a saved snapshot;
                # a failed result becomes an empty catalog, never an
                # optimistic default-model allowance.
                pool["catalog_models"] = sorted(models)
                if models:
                    pool["available_model_variants"] = {
                        model: sorted(values)
                        for model, values in sorted(variants.items())
                    }
    compute_hosts = merged.get("compute_hosts") or merged.get("hosts") or {}
    if not isinstance(compute_hosts, dict):
        compute_hosts = {}
    merged["compute_hosts"] = preflight_scan.merge_local_system_compute_host(
        compute_hosts, local_system, workspace
    )
    return merged


def _jobs_payload(value: Any) -> list[dict[str, Any]]:
    jobs = None
    capture_policy: Mapping[str, Any] | None = None
    if isinstance(value, Mapping):
        jobs = value.get("jobs")
        if jobs is None and value.get("capture") == "bounded-task-capture":
            jobs = value.get("planner_jobs")
            raw_policy = value.get("policy")
            if isinstance(raw_policy, Mapping):
                capture_policy = raw_policy
    else:
        jobs = value
    if not isinstance(jobs, list):
        raise ValueError("jobs input must be a list or an object with a jobs list")
    result: list[dict[str, Any]] = []
    for index, raw in enumerate(jobs):
        if not isinstance(raw, Mapping):
            raise ValueError(f"job {index} must be an object")
        job = dict(raw)
        job_id = str(job.get("job_id") or job.get("task_id") or "")
        if not job_id:
            raise ValueError(f"job {index} requires job_id")
        job["job_id"] = job_id
        # Preserve only the allow-listed capture policy as an internal
        # planning hint.  It is not an execution credential and is never
        # copied into a provider argv or packet by this read-only workflow.
        if capture_policy and "__dispatch_policy" not in job:
            job["__dispatch_policy"] = copy.deepcopy(dict(capture_policy))
        result.append(job)
    return result


def _planner_resources(estimate: Mapping[str, Any]) -> dict[str, Any]:
    """Translate estimator P50 facts into planner resource hints.

    Unknown values are intentionally omitted.  Unknown/pilot handling happens
    before planning, so this translation cannot accidentally turn ``None``
    into an optimistic zero.
    """

    metrics = estimate.get("metrics") or {}
    mapping = {
        "input_gib": "input_gib",
        "download_gib": "download_gib",
        "environment_gib": "environment_gib",
        "temporary_gib": "temporary_gib",
        "cache_gib": "cache_gib",
        "output_gib": "output_gib",
        "cpu_cores": "cpu_cores",
        "ram_gib": "ram_gib",
        "gpu_count": "gpu_count",
        "vram_gib": "vram_gib",
        "runtime_minutes": "compute_minutes",
        "cpu_utilization_percent": "expected_cpu_utilization_percent",
        "gpu_utilization_percent": "expected_gpu_utilization_percent",
        # Token bounds are kept as planner hints for model-specific cost
        # scoring.  They are not used as a quota balance and remain omitted
        # when the estimator has no evidence.
        "input_tokens": "estimated_input_tokens",
        "output_tokens": "estimated_output_tokens",
    }
    resources: dict[str, Any] = {}
    for metric_name, planner_name in mapping.items():
        record = metrics.get(metric_name) or {}
        value = record.get("p50") if isinstance(record, Mapping) else None
        if value is not None:
            resources[planner_name] = value
    return resources


def _model_policy(job: Mapping[str, Any]) -> tuple[set[str], dict[str, set[str]]]:
    """Return global and pool-specific exact model allowlists for one job."""

    policy = job.get("__dispatch_policy") or job.get("policy")
    source: Any = job.get("allowed_models")
    if source is None and isinstance(policy, Mapping):
        source = policy.get("allowed_models")
    global_models: set[str] = set()
    pool_models: dict[str, set[str]] = {}
    if isinstance(source, Mapping):
        for pool_id, values in source.items():
            if isinstance(values, str):
                values = [values]
            if isinstance(values, Sequence) and not isinstance(values, (bytes, bytearray)):
                pool_models[str(pool_id)] = {str(item) for item in values if str(item)}
    elif isinstance(source, str):
        global_models.add(source)
    elif isinstance(source, Sequence) and not isinstance(source, (bytes, bytearray)):
        global_models = {str(item) for item in source if str(item)}
    return global_models, pool_models


def _enforce_model_policy(
    plan: Mapping[str, Any], jobs: Sequence[Mapping[str, Any]]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Fail closed when a planner assignment violates a task allowlist.

    The planner remains responsible for pool/model capability selection.  This
    second gate is deliberately independent so a stale pool snapshot cannot
    turn an explicit capture policy into an unbounded model choice.
    """

    updated = copy.deepcopy(dict(plan))
    by_job = {str(job.get("job_id")): job for job in jobs}
    kept: list[dict[str, Any]] = []
    violations: list[dict[str, Any]] = []
    for assignment in list(updated.get("assignments") or []):
        job_id = str(assignment.get("job_id") or "")
        global_models, pool_models = _model_policy(by_job.get(job_id, {}))
        if not global_models and not pool_models:
            kept.append(assignment)
            continue
        pool_id = str(assignment.get("pool_id") or "")
        allowed = pool_models.get(pool_id, global_models)
        model = str(assignment.get("model") or "")
        if model in allowed:
            kept.append(assignment)
            continue
        violations.append(
            {
                "job_id": job_id,
                "pool_id": pool_id,
                "selected_model": model,
                "allowed_models": sorted(allowed),
                "reason": "model_policy_violation",
            }
        )
    if violations:
        deferred = list(updated.get("deferred") or [])
        deferred.extend(violations)
        updated["deferred"] = deferred
        updated["assignments"] = kept
        updated["ok"] = False
        updated["decision"] = "pause"
        updated["model_policy_violations"] = violations
    else:
        updated["assignments"] = kept
        updated.setdefault("model_policy_violations", [])
    return updated, violations


def _task_estimates(
    jobs: Sequence[Mapping[str, Any]],
    *,
    manifest: Mapping[str, Any] | None,
    history: Any,
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    reports: dict[str, dict[str, Any]] = {}
    planner_jobs: list[dict[str, Any]] = []
    gated: list[dict[str, Any]] = []
    for raw_job in jobs:
        job = dict(raw_job)
        report = task_estimator.build_report(job, manifest=manifest, history=history)
        estimate = report["estimate"]
        job_id = str(job["job_id"])
        reports[job_id] = report
        requires_pilot = bool(estimate.get("pilot_required")) and not bool(job.get("pilot"))
        if requires_pilot:
            gated.append(
                {
                    "job_id": job_id,
                    "gate": "task_estimate_pilot_required",
                    "server_first": estimate.get("server_first"),
                    "unknowns": list(estimate.get("unknowns") or []),
                    "pilot_reasons": list(estimate.get("pilot_reasons") or []),
                }
            )
            continue
        planner_job = copy.deepcopy(job)
        # Captured estimates are observations, not durable overrides.  Rebuild
        # them from the current estimator so a new unknown cannot inherit an
        # optimistic P50 from an older capture.  Explicit non-capture jobs may
        # still provide resource_estimate as a user-authored hint.
        if planner_job.get("capture_source"):
            merged_resources = dict(
                planner_job.get("resource_hints")
                or planner_job.get("resources")
                or {}
            )
        else:
            merged_resources = dict(planner_job.get("resource_estimate") or {})
        merged_resources.update(_planner_resources(estimate))
        if merged_resources:
            planner_job["resource_estimate"] = merged_resources
        else:
            planner_job.pop("resource_estimate", None)
        planner_jobs.append(planner_job)
    return reports, planner_jobs, gated


def _host_summary(host_id: str, host: Mapping[str, Any]) -> dict[str, Any]:
    gpus: list[dict[str, Any]] = []
    for raw_gpu in host.get("gpus") or []:
        if not isinstance(raw_gpu, Mapping):
            continue
        gpus.append(
            {
                "name": raw_gpu.get("name"),
                "vram_total_gib": raw_gpu.get("vram_total_gib"),
                "vram_free_gib": raw_gpu.get("vram_free_gib"),
                "unified_memory": bool(raw_gpu.get("unified_memory", False)),
                "utilization_percent": raw_gpu.get("utilization_percent"),
            }
        )
    return {
        "host_id": host_id,
        "transport": host.get("transport", "local"),
        "reachable": bool(host.get("reachable", False)),
        "project_path": host.get("project_path"),
        "os": host.get("os"),
        "arch": host.get("arch"),
        "logical_cpu_cores": host.get("logical_cpu_cores"),
        "estimated_idle_cpu_cores": host.get("estimated_idle_cpu_cores"),
        "load1": host.get("load1"),
        "load_source": host.get("load_source"),
        "capacity_evidence": host.get("capacity_evidence"),
        "memory_total_gib": host.get("memory_total_gib"),
        "memory_available_gib": host.get("memory_available_gib"),
        "disk_total_gib": host.get("disk_total_gib"),
        "disk_free_gib": host.get("disk_free_gib"),
        "project_path_exists": host.get("project_path_exists"),
        "project_path_writable": host.get("project_path_writable"),
        "best_storage_path": host.get("best_storage_path"),
        "best_writable_storage_path": host.get("best_writable_storage_path"),
        "gpu_count": host.get("gpu_count"),
        "gpus": gpus,
        "commands": sorted((host.get("commands") or {}).keys()),
        "resource_source": host.get("resource_source"),
    }


def _pool_reset_at(pool: Mapping[str, Any]) -> str | None:
    """Carry only the selected quota reset time into the public report."""
    sources: list[Mapping[str, Any]] = [pool]
    for bucket_name in ("primary", "secondary"):
        bucket = pool.get(bucket_name)
        if isinstance(bucket, Mapping):
            sources.append(bucket)
    for source in sources:
        for key in ("reset_at_utc", "resets_at_utc", "quota_reset_at_utc"):
            value = source.get(key)
            if isinstance(value, str) and value.strip():
                return " ".join(value.split())[:80]
    return None


def _pool_summary(pool_id: str, pool: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "pool_id": pool_id,
        "provider": pool.get("provider"),
        "provider_id": pool.get("provider_id"),
        "health": pool.get("health", "unknown"),
        "default_model": pool.get("default_model"),
        "default_variant": pool.get("default_variant"),
        "catalog_models": sorted(str(item) for item in (pool.get("catalog_models") or []) if item),
        "shared_members": sorted(str(item) for item in (pool.get("shared_members") or []) if item),
        "role_models": copy.deepcopy(pool.get("role_models") or {}),
        "role_model_candidates": copy.deepcopy(pool.get("role_model_candidates") or {}),
        "model_variants": copy.deepcopy(pool.get("model_variants") or {}),
        "available_model_variants": copy.deepcopy(pool.get("available_model_variants") or {}),
        "model_usage_multipliers": copy.deepcopy(pool.get("model_usage_multipliers") or {}),
        # Keep the public report's price field free of credential-shaped
        # names; the unit is documented as USD per million input/output
        # tokens, while the schema secret scan rejects generic ``token`` keys.
        "model_costs_per_million": copy.deepcopy(pool.get("model_costs_per_million_tokens") or {}),
        "model_approval_required": bool(pool.get("model_approval_required", False)),
        "model_approval_policy": pool.get("model_approval_policy"),
        "policy_excluded_models": sorted(str(item) for item in (pool.get("policy_excluded_models") or []) if item),
        "rejected_models": sorted(str(item) for item in (pool.get("rejected_models") or []) if item),
        "rejected_model_variants": copy.deepcopy(pool.get("rejected_model_variants") or {}),
        "effective_remaining_percent": pool.get("effective_remaining_percent"),
        "reset_at_utc": _pool_reset_at(pool),
        "unknown_quota_policy": pool.get("unknown_quota_policy"),
        "unknown_quota_pilot_percent": pool.get("unknown_quota_pilot_percent"),
        "max_concurrency": pool.get("max_concurrency"),
        "inflight": pool.get("inflight"),
        "blocked_reason": pool.get("blocked_reason"),
    }


def build_report(
    local_system: Mapping[str, Any],
    preflight: Mapping[str, Any],
    jobs: Sequence[Mapping[str, Any]],
    workspace: pathlib.Path,
    max_lanes: int = 4,
    horizon: int = 8,
    manifest: Mapping[str, Any] | None = None,
    history: Any = None,
    model_policy: str | None = None,
) -> dict[str, Any]:
    """Build the complete read-only report from already-observed facts."""

    normalized_jobs, route_policy = _apply_model_policy(
        _jobs_payload(list(jobs)), model_policy
    )
    merged_preflight = _merge_local_snapshot(preflight, local_system, workspace)
    estimates, planner_jobs, task_gates = _task_estimates(
        normalized_jobs, manifest=manifest, history=history
    )

    # Fit is intentionally run for every input job so a user can see why a
    # gated task would fit (or not fit) once its unknowns are resolved.
    fit_report = hardware_fit.build_report(
        merged_preflight, normalized_jobs, workspace.expanduser().resolve()
    )
    fit_rows = {str(row.get("job_id")): row for row in fit_report.get("jobs") or []}
    for job_id, task_report in estimates.items():
        row = fit_rows.get(job_id)
        if row is None:
            continue
        estimate = task_report.get("estimate") or {}
        row["task_estimate"] = estimate
        if any(item.get("job_id") == job_id for item in task_gates):
            row["task_gate"] = "pilot_first"
            row["decision"] = {
                "action": "pilot_first",
                "reason": "task_estimate_has_critical_unknowns",
                "selected_host": None,
                "server_eligible": bool(row.get("decision", {}).get("server_eligible")),
            }

    planner_state = dict(merged_preflight)
    planner_state["compute_hosts"] = merged_preflight.get("compute_hosts") or {}
    planner_state["pools"] = merged_preflight.get("pools") or {}
    try:
        plan = planner.plan(
            planner_state,
            {"jobs": planner_jobs},
            max(1, int(max_lanes)),
            max(1, int(horizon)),
        )
    except Exception as exc:  # pragma: no cover - exercised by malformed live probes
        plan = {
            "ok": False,
            "decision": "pause",
            "assignments": [],
            "deferred": [],
            "error": f"{type(exc).__name__}: {exc}",
            "max_lanes": max(1, int(max_lanes)),
        }

    # Preserve the pre-planner unknown gate in the same deferred stream as
    # capacity/quota decisions.  No gated task can be accidentally dispatched
    # merely because the legacy planner has heuristic defaults.
    deferred = list(plan.get("deferred") or [])
    deferred.extend(task_gates)
    plan["deferred"] = deferred
    plan, model_policy_violations = _enforce_model_policy(plan, planner_jobs)
    assignments = list(plan.get("assignments") or [])
    model_approval = plan.get("model_approval")
    if not isinstance(model_approval, Mapping):
        # Keep the report shape deterministic even when a malformed/older
        # planner snapshot is supplied.
        model_approval = {"state": "not_required", "blocked": []}
    else:
        model_approval = {
            "state": str(model_approval.get("state") or "not_required"),
            "blocked": copy.deepcopy(model_approval.get("blocked") or []),
        }

    hosts = merged_preflight.get("compute_hosts") or {}
    if not isinstance(hosts, Mapping):
        hosts = {}
    pools = merged_preflight.get("pools") or {}
    if not isinstance(pools, Mapping):
        pools = {}
    pool_rows = {
        str(pool_id): _pool_summary(str(pool_id), pool)
        for pool_id, pool in sorted(pools.items())
        if isinstance(pool, Mapping)
    }
    host_rows = {
        str(host_id): _host_summary(str(host_id), host)
        for host_id, host in sorted(hosts.items())
        if isinstance(host, Mapping)
    }
    unknown_pools = [
        pool_id
        for pool_id, row in pool_rows.items()
        if row.get("health") in {"unknown", "degraded"}
        or row.get("effective_remaining_percent") is None
    ]
    blocked_pools = [
        pool_id
        for pool_id, row in pool_rows.items()
        if row.get("health") in {"blocked", "cooldown", "quota_exhausted", "unavailable"}
    ]
    lane_rows = [
        {
            "lane": index + 1,
            "job_id": assignment.get("job_id"),
            "pool_id": assignment.get("pool_id"),
            "model": assignment.get("model"),
            "variant": assignment.get("variant"),
            "execution_host": assignment.get("execution_host"),
            "workload_host": assignment.get("workload_host"),
        }
        for index, assignment in enumerate(assignments)
    ]
    system_ok = bool(local_system.get("ok"))
    preflight_ok = bool(merged_preflight.get("ok", True))
    report: dict[str, Any] = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "report_type": REPORT_TYPE,
        "generated_at_utc": now_utc(),
        "ok": bool(
            system_ok
            and preflight_ok
            and plan.get("ok", False)
            and not model_policy_violations
        ),
        "read_only": True,
        "provider_execution": False,
        "model_prompts_sent": False,
        "project_executed": False,
        "side_effects": [],
        "policy": {
            "mode": "saved-preflight" if not merged_preflight.get("live_probe") else "live-preflight-no-prompt",
            "unknown_quota": "reported_and_bounded_by_snapshot",
            "unknown_resource": "pilot_first_unless_job.pilot=true",
            "system_first": True,
            "model_route": route_policy or {"name": "auto"},
        },
        "sequence": [
            {
                "stage": "system_scan",
                "status": "ready" if system_ok else "failed",
                "provider_contact": False,
                "model_prompt_sent": False,
            },
            {
                "stage": "preflight",
                "status": "ready" if preflight_ok else "failed",
                "source": "saved_snapshot" if not merged_preflight.get("live_probe") else "live_discovery",
                "model_prompt_sent": False,
            },
            {
                "stage": "task_estimate",
                "status": "ready",
                "job_count": len(normalized_jobs),
                "pilot_gate_count": len(task_gates),
                "provider_prompts_sent": False,
            },
            {
                "stage": "hardware_fit",
                "status": "ready",
                "host_count": len(host_rows),
                "server_first_job_count": sum(
                    1
                    for row in estimates.values()
                    if (row.get("estimate") or {}).get("server_first") is True
                ),
            },
            {
                "stage": "planner",
                "status": "ready" if plan.get("ok") else "failed",
                "max_lanes": max(1, int(max_lanes)),
                "planned_assignments": len(assignments),
                "provider_execution": False,
            },
        ],
        "workspace": str(workspace.expanduser().resolve()),
        "local_system": dict(local_system),
        "preflight": {
            "scanned_at_utc": merged_preflight.get("scanned_at_utc"),
            "readiness": merged_preflight.get("readiness") or {},
            "diagnostic_failures": merged_preflight.get("diagnostic_failures") or {},
        },
        "hosts": host_rows,
        "pools": pool_rows,
        "model_approval": copy.deepcopy(model_approval),
        "task_estimates": estimates,
        "hardware_fit": fit_report,
        "planner": plan,
        "assignments": assignments,
        "multi_lane": {
            "requested_max_lanes": max(1, int(max_lanes)),
            "planned_lane_count": len(lane_rows),
            "parallel_wave": len(lane_rows) > 1,
            "lanes": lane_rows,
        },
        "gates": {
            "task_pilot": task_gates,
            "model_policy": model_policy_violations,
            "model_approval": copy.deepcopy(model_approval),
            "unknown_quota_pools": sorted(unknown_pools),
            "blocked_pools": sorted(blocked_pools),
            "planner_quota_uncertainty": plan.get("quota_uncertainty") or {},
            "server_first_jobs": [
                job_id
                for job_id, row in estimates.items()
                if (row.get("estimate") or {}).get("server_first") is True
            ],
            "server_first_unknown_jobs": [
                job_id
                for job_id, row in estimates.items()
                if (row.get("estimate") or {}).get("server_first") == "unknown"
            ],
        },
        "evidence": {
            "system_scan_schema_version": local_system.get("schema_version"),
            "preflight_schema_version": merged_preflight.get("schema_version"),
            "planner_method": plan.get("planning_method"),
            "no_paid_model_prompt": True,
        },
    }
    return report


def run_workflow(
    *,
    workspace: pathlib.Path,
    jobs: Sequence[Mapping[str, Any]],
    preflight: Mapping[str, Any] | None = None,
    preflight_path: pathlib.Path | None = None,
    inventory: pathlib.Path | None = None,
    model_state: pathlib.Path | None = None,
    runtime_state: pathlib.Path | None = None,
    live_probes: bool = False,
    verify_racknerd_routes: bool = False,
    verify_external_network: bool = False,
    skip_antigravity_usage: bool = False,
    opencode_go_usage_endpoint: str | None = None,
    skip_opencode_go_usage: bool = False,
    timeout: float = 30.0,
    max_lanes: int = 4,
    horizon: int = 8,
    manifest: Mapping[str, Any] | None = None,
    history: Any = None,
    model_policy: str | None = None,
    system_snapshot: Mapping[str, Any] | None = None,
    runner: Callable[..., dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Execute discovery and planning stages without executing a provider."""

    workspace = workspace.expanduser().resolve()
    if not workspace.is_dir():
        raise NotADirectoryError(f"workspace does not exist: {workspace}")
    local_system = _local_scan(
        workspace, timeout=timeout, snapshot=system_snapshot, runner=runner
    )

    snapshot = dict(preflight) if preflight is not None else None
    if snapshot is None and preflight_path is not None:
        snapshot = load_json(preflight_path)
    if snapshot is None:
        if not live_probes:
            raise ValueError(
                "provider-free dispatch requires --preflight saved JSON; "
                "use --live-probes only for explicit no-prompt discovery"
            )
        if inventory is None or not inventory.expanduser().is_file():
            raise FileNotFoundError("--inventory is required for --live-probes")
        snapshot = _live_preflight(
            workspace,
            inventory.expanduser().resolve(),
            timeout=timeout,
            verify_racknerd_routes=verify_racknerd_routes,
            verify_external_network=verify_external_network,
            model_state=model_state,
            runtime_state=runtime_state,
            skip_antigravity_usage=skip_antigravity_usage,
            opencode_go_usage_endpoint=opencode_go_usage_endpoint,
            skip_opencode_go_usage=skip_opencode_go_usage,
            runner=runner,
        )
        snapshot["live_probe"] = True
    if not isinstance(snapshot, Mapping):
        raise ValueError("preflight snapshot must be a JSON object")

    return build_report(
        local_system=local_system,
        preflight=snapshot,
        jobs=jobs,
        workspace=workspace,
        max_lanes=max_lanes,
        horizon=horizon,
        manifest=manifest,
        history=history,
        model_policy=model_policy,
    )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", default=".")
    parser.add_argument("--jobs", required=True, help="JSON list or {jobs: [...]} file")
    parser.add_argument("--preflight", help="saved provider-free preflight JSON")
    parser.add_argument("--inventory", help="private host inventory for --live-probes")
    parser.add_argument("--model-state")
    parser.add_argument("--runtime-state")
    parser.add_argument("--live-probes", action="store_true", help="opt in to no-prompt CLI/SSH discovery")
    parser.add_argument(
        "--verify-racknerd-routes",
        action="store_true",
        help="when live probes are enabled, verify configured server-local RackNerd routes",
    )
    parser.add_argument(
        "--verify-external-network",
        action="store_true",
        help="when live probes are enabled, verify public DNS/HTTPS reachability on compute hosts",
    )
    parser.add_argument("--skip-antigravity-usage", action="store_true")
    parser.add_argument(
        "--opencode-go-usage-endpoint",
        default=None,
        help="verified HTTPS OpenCode Go usage endpoint; defaults in the preflight script",
    )
    parser.add_argument(
        "--skip-opencode-go-usage",
        action="store_true",
        help="skip the authenticated read-only OpenCode Go usage request",
    )
    parser.add_argument("--manifest", help="bounded task manifest JSON")
    parser.add_argument("--history", help="historical task observations JSON")
    parser.add_argument(
        "--model-policy",
        choices=(
            "auto",
            "codex-luna-max",
            "codex-sol-max",
            "codex-spark-antigravity-gemini",
        ),
        default="auto",
        help=(
            "task-local model route; named routes are exact allow-lists and do not "
            "promote catalogued models to runtime-ready"
        ),
    )
    parser.add_argument("--max-lanes", type=int, default=4)
    parser.add_argument("--horizon", type=int, default=8)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--output", help="versioned report output path")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    output = pathlib.Path(args.output).expanduser().resolve() if args.output else None
    try:
        jobs = _jobs_payload(load_json(pathlib.Path(args.jobs)))
        manifest = load_json(pathlib.Path(args.manifest)) if args.manifest else None
        history = load_json(pathlib.Path(args.history)) if args.history else None
        report = run_workflow(
            workspace=pathlib.Path(args.workspace),
            jobs=jobs,
            preflight_path=pathlib.Path(args.preflight) if args.preflight else None,
            inventory=pathlib.Path(args.inventory) if args.inventory else None,
            model_state=pathlib.Path(args.model_state) if args.model_state else None,
            runtime_state=pathlib.Path(args.runtime_state) if args.runtime_state else None,
            live_probes=bool(args.live_probes),
            verify_racknerd_routes=bool(args.verify_racknerd_routes),
            verify_external_network=bool(args.verify_external_network),
            skip_antigravity_usage=bool(args.skip_antigravity_usage),
            opencode_go_usage_endpoint=args.opencode_go_usage_endpoint,
            skip_opencode_go_usage=bool(args.skip_opencode_go_usage),
            timeout=args.timeout,
            max_lanes=args.max_lanes,
            horizon=args.horizon,
            manifest=manifest if isinstance(manifest, Mapping) else None,
            history=history,
            model_policy=args.model_policy,
        )
    except Exception as exc:
        report = {
            "schema_version": REPORT_SCHEMA_VERSION,
            "report_type": REPORT_TYPE,
            "generated_at_utc": now_utc(),
            "ok": False,
            "read_only": True,
            "provider_execution": False,
            "model_prompts_sent": False,
            "project_executed": False,
            "side_effects": [],
            "sequence": [
                {
                    "stage": stage,
                    "status": "failed" if index == 0 else "not_run",
                    "provider_contact": False,
                    "model_prompt_sent": False,
                }
                for index, stage in enumerate(STAGES)
            ],
            "hosts": {},
            "pools": {},
            "task_estimates": {},
            "assignments": [],
            "multi_lane": {
                "requested_max_lanes": max(1, int(args.max_lanes)),
                "planned_lane_count": 0,
                "parallel_wave": False,
                "lanes": [],
            },
            "gates": {},
            "error": f"{type(exc).__name__}: {exc}",
        }
        write_json(output, report)
        return 2
    write_json(output, report)
    return 0 if report.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
