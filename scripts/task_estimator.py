#!/usr/bin/env python3
"""Bounded, provider-free task resource estimation.

The estimator is deliberately a small boundary between a task description and
the scheduler.  It reads JSON and (optionally) file metadata from a repository
root; it never starts a provider, imports a model client, downloads data, or
executes the project.  A value is only reported when it is present in an
explicit hint, a measured observation, or a bounded file manifest.  Missing
values stay ``None`` and are surfaced as unknowns instead of being replaced by
optimistic defaults.

The public pure functions are useful to the planner without coupling it to
this command's CLI:

``build_light_manifest``
    bounded file metadata inventory (no file contents are read);
``estimate_task``
    deterministic metric estimates and server-first/pilot gates;
``build_report``
    stable JSON envelope suitable for a preflight artifact.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import os
import pathlib
import sys
from typing import Any, Iterable, Mapping, Sequence


SCHEMA_VERSION = 1
ESTIMATOR_NAME = "bounded-task-estimator"
BYTES_PER_GIB = 1024**3

# The manifest is intentionally conservative.  These directories commonly
# contain generated/bulk data and are not needed to understand a task's source
# footprint.
IGNORED_DIR_NAMES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "dist",
        "build",
    }
)

# Metric names are stable API.  Keep storage and compute separate so a caller
# can make its own placement decision later.
METRIC_SPECS: dict[str, str] = {
    "input_gib": "GiB",
    "download_gib": "GiB",
    "environment_gib": "GiB",
    "temporary_gib": "GiB",
    "cache_gib": "GiB",
    "output_gib": "GiB",
    "cpu_cores": "cores",
    "ram_gib": "GiB",
    "gpu_count": "devices",
    "vram_gib": "GiB/device",
    "cpu_utilization_percent": "%",
    "gpu_utilization_percent": "%",
    "network_mbps": "Mbit/s",
    "network_gib": "GiB",
    "runtime_minutes": "minutes",
    "input_tokens": "tokens",
    "output_tokens": "tokens",
}

RESOURCE_ALIASES: dict[str, tuple[str, ...]] = {
    "input_gib": ("input_gib", "input_size_gib", "dataset_gib", "input_size"),
    "download_gib": ("download_gib", "download_size_gib", "download_size"),
    "environment_gib": ("environment_gib", "env_gib", "environment_size_gib"),
    "temporary_gib": ("temporary_gib", "temp_gib", "scratch_gib", "temporary_size_gib"),
    "cache_gib": ("cache_gib", "cache_size_gib"),
    "output_gib": ("output_gib", "output_size_gib"),
    "cpu_cores": ("cpu_cores", "required_cpu_cores", "cores"),
    "ram_gib": ("ram_gib", "memory_gib", "required_ram_gib"),
    "gpu_count": ("gpu_count", "required_gpu_count"),
    "vram_gib": ("vram_gib", "required_vram_gib", "vram_gib_per_gpu"),
    "cpu_utilization_percent": ("cpu_utilization_percent", "expected_cpu_utilization_percent"),
    "gpu_utilization_percent": ("gpu_utilization_percent", "expected_gpu_utilization_percent"),
    "network_mbps": ("network_mbps", "network_bandwidth_mbps"),
    "network_gib": ("network_gib", "transfer_gib", "network_transfer_gib"),
    "runtime_minutes": ("runtime_minutes", "compute_minutes", "estimated_minutes", "duration_minutes"),
    "input_tokens": (
        "input_tokens", "prompt_tokens", "estimated_input_tokens", "context_tokens",
    ),
    "output_tokens": (
        "output_tokens", "completion_tokens", "estimated_output_tokens", "response_tokens",
    ),
}


def _finite_number(value: Any) -> float | None:
    """Return a non-negative finite number, preserving unknown as ``None``."""

    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(number) or number < 0:
        return None
    return number


def _number(value: Any) -> int | float | None:
    number = _finite_number(value)
    if number is None:
        return None
    return int(number) if number.is_integer() else number


def _mapping_value(mapping: Mapping[str, Any], aliases: Iterable[str]) -> tuple[Any, str | None]:
    for key in aliases:
        if key in mapping and mapping[key] is not None:
            return mapping[key], key
    return None, None


def _resource_hints(task: Mapping[str, Any]) -> tuple[Mapping[str, Any], str]:
    for key in ("resource_hints", "resources", "resource_estimate"):
        value = task.get(key)
        if isinstance(value, Mapping):
            return value, f"task.{key}"
    return task, "task"


def _quantile(values: Sequence[float], probability: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def _history_values(history: Any, metric: str) -> list[float]:
    """Extract finite observations from either a mapping or observation rows."""

    values: list[Any] = []
    if isinstance(history, Mapping):
        candidate = history.get(metric)
        if isinstance(candidate, Sequence) and not isinstance(candidate, (str, bytes)):
            values.extend(candidate)
        elif candidate is not None:
            values.append(candidate)
    elif isinstance(history, Sequence) and not isinstance(history, (str, bytes)):
        for row in history:
            if isinstance(row, Mapping) and metric in row:
                values.append(row[metric])
    return [number for item in values if (number := _finite_number(item)) is not None]


def _metric(
    metric: str,
    hints: Mapping[str, Any],
    source_name: str,
    history: Any,
    *,
    derived: float | None = None,
    derived_evidence: str | None = None,
) -> dict[str, Any]:
    """Create a P50/P90 record while retaining evidence and uncertainty."""

    observations = _history_values(history, metric)
    if observations:
        p50 = _quantile(observations, 0.50)
        p90 = _quantile(observations, 0.90)
        evidence = [f"history.{metric} ({len(observations)} observation(s))"]
        confidence = "high" if len(observations) >= 5 else "medium"
        source = "measured_history"
    else:
        raw, key = _mapping_value(hints, RESOURCE_ALIASES.get(metric, (metric,)))
        p50_raw, p50_key = _mapping_value(
            hints, tuple(f"{alias}_p50" for alias in RESOURCE_ALIASES.get(metric, (metric,)))
        )
        p90_raw, p90_key = _mapping_value(
            hints, tuple(f"{alias}_p90" for alias in RESOURCE_ALIASES.get(metric, (metric,)))
        )
        if isinstance(raw, Mapping):
            p50_raw = raw.get("p50", p50_raw)
            p90_raw = raw.get("p90", p90_raw)
            p50_key = f"{key}.p50" if raw.get("p50") is not None else p50_key
            p90_key = f"{key}.p90" if raw.get("p90") is not None else p90_key
        p50_explicit = _finite_number(p50_raw)
        p90_explicit = _finite_number(p90_raw)
        explicit = _finite_number(raw)
        if p50_explicit is not None or p90_explicit is not None:
            p50 = p50_explicit if p50_explicit is not None else p90_explicit
            p90 = p90_explicit if p90_explicit is not None else p50_explicit
            evidence = [f"{source_name}.{p50_key or p90_key} (explicit percentile hint)"]
            confidence = "medium"
            source = "explicit_percentile_hint"
        elif explicit is not None:
            p50 = explicit
            p90 = explicit
            evidence = [f"{source_name}.{key} (single-point hint)"]
            confidence = "low"
            source = "explicit_hint"
        elif derived is not None:
            p50 = derived
            p90 = derived
            evidence = [derived_evidence or "bounded_derivation"]
            confidence = "medium"
            source = "bounded_manifest"
        else:
            p50 = None
            p90 = None
            evidence = [f"{metric} not provided"]
            confidence = "unknown"
            source = "unknown"
    return {
        "p50": _number(p50),
        "p90": _number(p90),
        "unit": METRIC_SPECS[metric],
        "confidence": confidence,
        "source": source,
        "evidence": evidence,
        "observation_count": len(observations),
    }


def _manifest_total_gib(manifest: Mapping[str, Any] | None) -> float | None:
    if not isinstance(manifest, Mapping):
        return None
    role = str(manifest.get("role") or "source").lower()
    # A truncated manifest is not a lower bound that can safely be used for a
    # placement estimate.  Keep the value unknown until the caller supplies a
    # complete bounded manifest or an explicit input hint.
    if bool(manifest.get("truncated", False)):
        return None
    if role not in {"source", "input", "dataset", "artifact"}:
        return None
    total = _finite_number(manifest.get("total_bytes"))
    if total is None:
        return None
    return total / BYTES_PER_GIB


def _combine_known(values: Iterable[float | int | None]) -> float | None:
    nums = [float(value) for value in values if _finite_number(value) is not None]
    if not nums:
        return None
    return sum(nums)


def _confidence_rank(value: str) -> int:
    return {"unknown": 0, "low": 1, "medium": 2, "high": 3}.get(value, 0)


def build_light_manifest(
    root: str | os.PathLike[str],
    *,
    max_files: int = 2000,
    max_depth: int = 4,
    max_total_bytes: int = 8 * 1024 * 1024,
) -> dict[str, Any]:
    """Inventory bounded file metadata without opening files or following links.

    This function deliberately returns a ``truncated`` flag.  A partial
    manifest must never be mistaken for a complete repository size.
    """

    if max_files < 1 or max_depth < 0 or max_total_bytes < 0:
        raise ValueError("manifest limits must be non-negative (max_files >= 1)")
    base = pathlib.Path(root).expanduser().resolve()
    if not base.is_dir():
        raise NotADirectoryError(f"repository root is not a directory: {base}")
    rows: list[dict[str, Any]] = []
    total = 0
    truncated = False

    def visit(directory: pathlib.Path, depth: int) -> None:
        nonlocal total, truncated
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name)
        except OSError:
            truncated = True
            return
        for entry in entries:
            if entry.name in IGNORED_DIR_NAMES:
                continue
            try:
                if entry.is_symlink():
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if depth < max_depth:
                        visit(pathlib.Path(entry.path), depth + 1)
                    else:
                        truncated = True
                    continue
                if not entry.is_file(follow_symlinks=False):
                    continue
                stat = entry.stat(follow_symlinks=False)
                size = max(0, int(stat.st_size))
            except OSError:
                truncated = True
                continue
            if len(rows) >= max_files or total + size > max_total_bytes:
                truncated = True
                return
            rows.append(
                {
                    "path": pathlib.Path(entry.path).relative_to(base).as_posix(),
                    "size_bytes": size,
                }
            )
            total += size

    visit(base, 0)
    return {
        "schema_version": SCHEMA_VERSION,
        "root": str(base),
        "role": "source",
        "files": rows,
        "file_count": len(rows),
        "total_bytes": total,
        "total_gib": round(total / BYTES_PER_GIB, 9),
        "truncated": truncated,
        "limits": {
            "max_files": max_files,
            "max_depth": max_depth,
            "max_total_bytes": max_total_bytes,
        },
        "evidence": ["filesystem.stat metadata only", "file contents not read"],
    }


def _critical_unknowns(metrics: Mapping[str, Mapping[str, Any]], task: Mapping[str, Any]) -> list[str]:
    # Without at least one bounded runtime or compute signal, a local run is a
    # pilot even if the source tree is small.  Unknown storage/network fields
    # are reported, but only fields relevant to placement drive this gate.
    keys = ["runtime_minutes", "cpu_cores", "ram_gib"]
    unknowns = [key for key in keys if metrics[key]["p50"] is None]
    if bool(task.get("requires_gpu")) and metrics["gpu_count"]["p50"] is None:
        unknowns.append("gpu_count")
    return unknowns


def estimate_task(
    task: Mapping[str, Any],
    *,
    manifest: Mapping[str, Any] | None = None,
    history: Mapping[str, Any] | Sequence[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Estimate one task from explicit hints, history, and optional manifest."""

    if not isinstance(task, Mapping):
        raise TypeError("task must be a mapping")
    hints, source_name = _resource_hints(task)
    task_history = history if history is not None else task.get("history") or task.get("observations")
    metrics: dict[str, dict[str, Any]] = {}
    # Token hints are intentionally separate from storage/compute hints.  A
    # caller may provide ``resources`` for placement and ``tokens`` for cost
    # planning; neither should silently overwrite the other.  Unknown token
    # counts remain unknown and never become zero.
    token_hints: dict[str, Any] = {}
    for source in (task.get("token_estimate"), task.get("tokens"), task):
        if isinstance(source, Mapping):
            token_hints.update(source)
    token_history = task_history
    for metric in METRIC_SPECS:
        derived = None
        derived_evidence = None
        if metric == "input_gib":
            derived = _manifest_total_gib(manifest)
            if derived is not None:
                derived_evidence = "bounded repository manifest total_bytes (role=input/dataset/artifact)"
        metric_hints = token_hints if metric in {"input_tokens", "output_tokens"} else hints
        metrics[metric] = _metric(
            metric,
            metric_hints,
            source_name,
            token_history,
            derived=derived,
            derived_evidence=derived_evidence,
        )

    # Storage total is only known when every component is known.  Summing a
    # partial list would understate the footprint and violate the unknown rule.
    storage_keys = ("input_gib", "download_gib", "environment_gib", "temporary_gib", "cache_gib", "output_gib")
    storage_unknowns = [key for key in storage_keys if metrics[key]["p50"] is None]
    total_p50 = None if storage_unknowns else _combine_known(metrics[key]["p50"] for key in storage_keys)
    total_p90 = None if storage_unknowns else _combine_known(metrics[key]["p90"] for key in storage_keys)
    token_total_p50 = _combine_known(
        (metrics["input_tokens"].get("p50"), metrics["output_tokens"].get("p50"))
    ) if all(metrics[key].get("p50") is not None for key in ("input_tokens", "output_tokens")) else None
    token_total_p90 = _combine_known(
        (metrics["input_tokens"].get("p90"), metrics["output_tokens"].get("p90"))
    ) if all(metrics[key].get("p90") is not None for key in ("input_tokens", "output_tokens")) else None

    reasons: list[str] = []

    def exceeds(metric: str, threshold: float, label: str) -> None:
        value = metrics[metric]["p50"]
        if value is not None and float(value) > threshold:
            reasons.append(label)

    exceeds("runtime_minutes", 10.0, "runtime_p50_over_10_minutes")
    exceeds("gpu_count", 0.0, "gpu_is_useful")
    exceeds("vram_gib", 0.0, "vram_requirement_present")
    if total_p50 is not None and total_p50 > 1.0:
        reasons.append("known_storage_footprint_over_1_gib")
    if metrics["download_gib"]["p50"] is not None and float(metrics["download_gib"]["p50"]) > 1.0:
        reasons.append("download_over_1_gib")
    for flag, label in (
        ("full_dataset", "full_dataset_requested"),
        ("full_model", "full_model_requested"),
        ("parallel_sweep", "parallel_sweep_requested"),
        ("requires_server", "server_required_by_task"),
    ):
        if bool(task.get(flag)):
            reasons.append(label)

    unknowns = [key for key, value in metrics.items() if value["p50"] is None]
    critical_unknowns = _critical_unknowns(metrics, task)
    # A complete storage decomposition is required to prove a local fit.  A
    # missing optional network/utilization signal does not by itself block
    # placement, while unknown footprint/GPU/runtime signals do.
    gate_unknowns = list(dict.fromkeys(critical_unknowns + storage_unknowns))
    server_first: bool | str = True if reasons else ("unknown" if gate_unknowns else False)
    # Explicit local-only tasks override the generic server-first suggestion;
    # they still carry the estimate and unknowns for a caller to inspect.
    if any(bool(task.get(flag)) for flag in ("requires_local_gui", "requires_usb", "private_local_only")):
        server_first = False
        reasons = ["task_requires_local_capability"]
    pilot_required = bool(task.get("pilot", False)) is False and bool(gate_unknowns)
    confidence_values = [value["confidence"] for value in metrics.values()]
    known_confidence_values = [value for value in confidence_values if value != "unknown"]
    overall = min(known_confidence_values, key=_confidence_rank) if known_confidence_values else "unknown"

    return {
        "schema_version": SCHEMA_VERSION,
        "task_id": str(task.get("job_id") or task.get("task_id") or ""),
        "metrics": metrics,
        # Stable human-facing groupings mirror the task vocabulary while the
        # canonical machine interface remains ``metrics``.  Each alias points
        # to the same P50/P90 record and therefore preserves unknowns exactly.
        "resources": {
            "storage": {
                "input": metrics["input_gib"],
                "download": metrics["download_gib"],
                "environment": metrics["environment_gib"],
                "temporary": metrics["temporary_gib"],
                "cache": metrics["cache_gib"],
                "output": metrics["output_gib"],
            },
            "compute": {
                "cpu": metrics["cpu_cores"],
                "ram": metrics["ram_gib"],
                "gpu": metrics["gpu_count"],
                "vram": metrics["vram_gib"],
                "cpu_utilization": metrics["cpu_utilization_percent"],
                "gpu_utilization": metrics["gpu_utilization_percent"],
                "network": metrics["network_mbps"],
                "network_transfer": metrics["network_gib"],
                "runtime": metrics["runtime_minutes"],
            },
            "tokens": {
                "input": metrics["input_tokens"],
                "output": metrics["output_tokens"],
                "total": {
                    "p50": _number(token_total_p50),
                    "p90": _number(token_total_p90),
                    "unit": "tokens",
                    "confidence": (
                        "unknown"
                        if token_total_p50 is None
                        else min(
                            (metrics["input_tokens"]["confidence"], metrics["output_tokens"]["confidence"]),
                            key=_confidence_rank,
                        )
                    ),
                    "source": "sum_of_input_and_output_token_bounds" if token_total_p50 is not None else "unknown",
                    "evidence": ["input_tokens + output_tokens"] if token_total_p50 is not None else ["token total not provided"],
                },
            },
        },
        "storage": {
            "new_footprint_gib": {"p50": _number(total_p50), "p90": _number(total_p90), "unit": "GiB"},
            "unknown_components": storage_unknowns,
        },
        "server_first": server_first,
        "server_first_reasons": reasons,
        "pilot_required": pilot_required,
        "pilot_reasons": [f"unknown_{key}" for key in gate_unknowns],
        "unknowns": unknowns,
        "confidence": overall,
        "evidence": sorted({item for metric in metrics.values() for item in metric["evidence"]}),
        "bounds": {
            "p50": "50th percentile of supplied observations; single hints are reported as single-point bounds",
            "p90": "90th percentile of supplied observations; unknown when no evidence exists",
            "provider_prompts_sent": False,
            "project_executed": False,
        },
    }


def _description_hash(description: Any) -> str | None:
    if not isinstance(description, str) or not description.strip():
        return None
    return hashlib.sha256(description.encode("utf-8")).hexdigest()


def build_report(
    task: Mapping[str, Any],
    *,
    manifest: Mapping[str, Any] | None = None,
    history: Mapping[str, Any] | Sequence[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Return a JSON-safe report envelope with no provider/runtime side effects."""

    estimate = estimate_task(task, manifest=manifest, history=history)
    return {
        "schema_version": SCHEMA_VERSION,
        "estimator": ESTIMATOR_NAME,
        "generated_at_utc": dt.datetime.now(tz=dt.timezone.utc).isoformat(),
        "read_only": True,
        "provider_prompts_sent": False,
        "project_executed": False,
        "task": {
            "task_id": estimate["task_id"],
            "description_present": bool(_description_hash(task.get("description"))),
            "description_sha256": _description_hash(task.get("description")),
        },
        "manifest": dict(manifest) if isinstance(manifest, Mapping) else None,
        "estimate": estimate,
    }


def _load_json(path: str) -> Any:
    return json.loads(pathlib.Path(path).expanduser().read_text(encoding="utf-8"))


def _task_from_arg(value: str) -> Mapping[str, Any]:
    path = pathlib.Path(value).expanduser()
    if path.is_file():
        payload = _load_json(str(path))
        if isinstance(payload, Mapping) and isinstance(payload.get("task"), Mapping):
            return payload["task"]
        if isinstance(payload, Mapping):
            return payload
        raise ValueError("--task JSON must be an object")
    return {"task_id": "cli-task", "description": value}


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--task", required=True, help="JSON task file, or a literal task description")
    parser.add_argument("--manifest", help="bounded manifest JSON (read-only)")
    parser.add_argument("--repo-root", help="repository root for a bounded metadata-only manifest")
    parser.add_argument("--history", help="JSON mapping/list of previous measurements")
    parser.add_argument("--max-files", type=int, default=2000)
    parser.add_argument("--max-depth", type=int, default=4)
    parser.add_argument("--max-total-bytes", type=int, default=8 * 1024 * 1024)
    parser.add_argument("--output")
    return parser.parse_args(list(argv))


def _write(path: str | None, payload: Mapping[str, Any]) -> None:
    text = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    if not path:
        print(text, end="")
        return
    target = pathlib.Path(path).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(target.suffix + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    temporary.replace(target)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        task = _task_from_arg(args.task)
        manifest: Mapping[str, Any] | None = None
        if args.manifest:
            loaded = _load_json(args.manifest)
            if not isinstance(loaded, Mapping):
                raise ValueError("--manifest JSON must be an object")
            manifest = loaded
        elif args.repo_root:
            manifest = build_light_manifest(
                args.repo_root,
                max_files=args.max_files,
                max_depth=args.max_depth,
                max_total_bytes=args.max_total_bytes,
            )
        history: Any = None
        if args.history:
            history = _load_json(args.history)
        report = build_report(task, manifest=manifest, history=history)
        _write(args.output, report)
        return 0
    except Exception as exc:
        _write(args.output, {"schema_version": SCHEMA_VERSION, "ok": False, "error": f"{type(exc).__name__}: {exc}"})
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
