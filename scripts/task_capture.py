#!/usr/bin/env python3
"""Provider-free task capture, DAG normalization, and history calibration.

This module is deliberately a boundary around :mod:`task_estimator` rather
than a second planner.  It turns a user description and optional, read-only
repository metadata into a reviewable ``TaskPacket``.  It never invokes a
provider, runs a project command, or assumes a missing resource is zero.

The public functions are intentionally pure (apart from the bounded metadata
walk requested by ``capture_task``):

``build_dag``
    Validate explicit step/dependency input and emit deterministic topological
    order plus parallel waves.  A missing dependency or cycle makes the DAG
    invalid; it is not silently flattened.
``calibrate_history``
    Filter measured observations by task family/model/host and calculate
    P50/P90, EWMA, and an optional measured/estimated bias factor.  Empty or
    insufficient buckets stay ``unknown``/``pilot``.
``capture_task``
    Build a packet containing the request provenance, bounded repository
    summary, DAG, per-node estimates, and an optional calibration report.

The JSON schema is intentionally additive and can be consumed by the existing
``task_estimator.py`` and planner without changing their contracts.
"""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import json
import math
import pathlib
import re
import sys
from collections.abc import Mapping, Sequence
from typing import Any

try:  # The script is also shipped as a standalone data file.
    from task_estimator import METRIC_SPECS, build_light_manifest, estimate_task
    from dispatch_schema import validate as validate_schema
except ImportError:  # pragma: no cover - only used by unusual direct imports
    from .task_estimator import METRIC_SPECS, build_light_manifest, estimate_task
    from .dispatch_schema import validate as validate_schema


SCHEMA_VERSION = 1
CAPTURE_NAME = "bounded-task-capture"
CALIBRATOR_NAME = "bounded-history-calibration"
MAX_DESCRIPTION_CHARS = 16_384
MAX_ID_CHARS = 96

_FAMILY_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("test", ("test", "pytest", "unittest", "测试", "回归")),
    ("build", ("build", "compile", "编译", "构建")),
    ("training", ("train", "training", "finetune", "fine-tune", "训练", "微调")),
    ("data_transfer", ("download", "upload", "dataset", "model", "下载", "数据集", "模型")),
    ("deployment", ("deploy", "serve", "endpoint", "部署", "服务")),
    ("research", ("literature", "paper", "research", "文献", "论文", "研究")),
    ("analysis", ("analyze", "analyse", "inspect", "audit", "分析", "检查", "审计")),
)

_POLICY_KEYS = frozenset(
    {
        "allow_server",
        "server_first",
        "private_local_only",
        "requires_external_network",
        "requires_local_gui",
        "requires_usb",
        "write_scope",
        "allowed_hosts",
        "allowed_models",
        "max_lanes",
        "stop_conditions",
    }
)

_GIT_KEYS = frozenset(
    {
        "branch",
        "base_commit",
        "head_commit",
        "changed_files",
        "diff_stat",
        "dirty",
    }
)


def _finite_number(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(number) or number < 0:
        return None
    return number


def _number(value: float | int | None) -> int | float | None:
    if value is None:
        return None
    return int(value) if float(value).is_integer() else value


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


def _clean_text(value: Any, *, limit: int = MAX_DESCRIPTION_CHARS) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    return text[:limit]


def _hash_text(value: str) -> str | None:
    if not value:
        return None
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _safe_id(value: Any, fallback: str, used: set[str]) -> str:
    raw = _clean_text(value, limit=MAX_ID_CHARS).lower()
    raw = re.sub(r"[^a-z0-9._-]+", "-", raw).strip("-._") or fallback
    raw = raw[:MAX_ID_CHARS]
    candidate = raw
    suffix = 2
    while candidate in used:
        candidate = f"{raw}-{suffix}"
        suffix += 1
    used.add(candidate)
    return candidate


def infer_task_family(description: str, explicit: Any = None) -> str:
    """Return a stable, low-cardinality family label.

    Explicit labels are preferred but normalized to avoid unbounded history
    buckets.  If no rule matches, ``general`` is intentionally used rather
    than pretending that a model-specific family was inferred.
    """

    if isinstance(explicit, str) and explicit.strip():
        normalized = re.sub(r"[^a-z0-9._-]+", "_", explicit.strip().lower()).strip("._-")
        return normalized[:64] or "general"
    haystack = description.casefold()
    for family, keywords in _FAMILY_RULES:
        if any(keyword.casefold() in haystack for keyword in keywords):
            return family
    return "general"


def _resource_hints(value: Mapping[str, Any]) -> dict[str, Any]:
    for key in ("resources", "resource_hints", "resource_estimate"):
        candidate = value.get(key)
        if isinstance(candidate, Mapping):
            return dict(candidate)
    return {}


def _normalise_dependencies(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        values = list(value)
    else:
        return []
    result: list[str] = []
    for item in values:
        text = _clean_text(item, limit=MAX_ID_CHARS).lower()
        if text and text not in result:
            result.append(text)
    return result


def _inferred_nodes(description: str) -> tuple[list[Any], str]:
    """Conservatively split obvious serial/segment requests into nodes.

    Natural-language decomposition is intentionally narrow: only explicit
    sequencing words or line/semicolon boundaries are used.  Ambiguous prose
    remains one node, so a heuristic cannot invent a dependency that changes
    the user's task.
    """

    text = _clean_text(description)
    serial_parts = [
        part.strip()
        for part in re.split(r"(?:\s+then\s+|\s+after(?:wards)?\s+|随后|然后|之后|接着)", text, flags=re.IGNORECASE)
        if part.strip()
    ]
    if len(serial_parts) > 1:
        return [
            {
                "id": f"step-{index + 1}",
                "description": part,
                "depends_on": [f"step-{index}"] if index else [],
            }
            for index, part in enumerate(serial_parts)
        ], "inferred_sequence"
    segment_parts = [part.strip() for part in re.split(r"(?:\r?\n|;|；)", text) if part.strip()]
    if len(segment_parts) > 1:
        return segment_parts, "inferred_segments"
    return [], "implicit_single_node"


def _raw_nodes(steps: Any, dag: Any, description: str = "") -> tuple[list[Any], str]:
    if isinstance(dag, Mapping):
        for key in ("nodes", "steps", "tasks"):
            if isinstance(dag.get(key), Sequence) and not isinstance(dag.get(key), (str, bytes)):
                return list(dag[key]), f"task.dag.{key}"
    if isinstance(steps, Sequence) and not isinstance(steps, (str, bytes)):
        return list(steps), "task.steps"
    return _inferred_nodes(description)


def build_dag(
    steps: Any = None,
    dag: Any = None,
    *,
    description: str = "",
) -> dict[str, Any]:
    """Normalize and validate an explicit or implicit task DAG.

    Nodes with no dependency are deliberately left disconnected, which gives
    the planner a truthful opportunity to run them in parallel.  Every
    dependency is checked against the normalized node IDs before an order is
    emitted.  The returned ``valid`` flag is the gate callers should consult.
    """

    raw_nodes, source = _raw_nodes(steps, dag, description)
    used: set[str] = set()
    nodes: list[dict[str, Any]] = []
    for index, raw in enumerate(raw_nodes):
        if isinstance(raw, Mapping):
            raw_map = raw
            node_id = _safe_id(raw_map.get("id") or raw_map.get("step_id"), f"step-{index + 1}", used)
            text = _clean_text(raw_map.get("description") or raw_map.get("title") or raw_map.get("task"))
            deps = _normalise_dependencies(
                raw_map.get("depends_on", raw_map.get("dependencies", raw_map.get("after")))
            )
            parallel_group = _clean_text(raw_map.get("parallel_group"), limit=64) or None
            hints = _resource_hints(raw_map)
            node = {
                "id": node_id,
                "description": text,
                "depends_on": deps,
                "parallel_group": parallel_group,
                "resource_hints": hints,
            }
            if isinstance(raw_map.get("policy"), Mapping):
                node["policy"] = {str(k): v for k, v in raw_map["policy"].items() if str(k) in _POLICY_KEYS}
        elif isinstance(raw, str):
            node_id = _safe_id(None, f"step-{index + 1}", used)
            node = {
                "id": node_id,
                "description": _clean_text(raw),
                "depends_on": [],
                "parallel_group": None,
                "resource_hints": {},
            }
        else:
            node_id = _safe_id(None, f"step-{index + 1}", used)
            node = {
                "id": node_id,
                "description": "",
                "depends_on": [],
                "parallel_group": None,
                "resource_hints": {},
            }
        nodes.append(node)

    if not nodes:
        nodes = [
            {
                "id": "task",
                "description": _clean_text(description) or "captured task",
                "depends_on": [],
                "parallel_group": None,
                "resource_hints": {},
            }
        ]
        source = "implicit_single_node"

    known = {node["id"] for node in nodes}
    unknown_dependencies: list[dict[str, str]] = []
    edges: list[dict[str, str]] = []
    incoming: dict[str, set[str]] = {node["id"]: set() for node in nodes}
    outgoing: dict[str, set[str]] = {node["id"]: set() for node in nodes}
    for node in nodes:
        valid_deps: list[str] = []
        for dependency in node["depends_on"]:
            # Dependencies refer to normalized IDs.  This strict behavior is
            # safer than guessing that a typo names another step.
            if dependency not in known:
                unknown_dependencies.append({"node": node["id"], "dependency": dependency})
                continue
            if dependency == node["id"]:
                unknown_dependencies.append({"node": node["id"], "dependency": dependency, "reason": "self_dependency"})
                continue
            valid_deps.append(dependency)
            incoming[node["id"]].add(dependency)
            outgoing[dependency].add(node["id"])
            edges.append({"from": dependency, "to": node["id"]})
        node["depends_on"] = valid_deps

    # Kahn's algorithm with lexical ordering yields stable output and waves.
    remaining = {node_id: set(deps) for node_id, deps in incoming.items()}
    ready = sorted(node_id for node_id, deps in remaining.items() if not deps)
    order: list[str] = []
    waves: list[list[str]] = []
    while ready:
        wave = sorted(ready)
        waves.append(wave)
        ready = []
        for node_id in wave:
            order.append(node_id)
            for child in sorted(outgoing[node_id]):
                remaining[child].discard(node_id)
                if not remaining[child]:
                    ready.append(child)
    cycle_nodes = sorted(node_id for node_id, deps in remaining.items() if deps)
    valid = not unknown_dependencies and not cycle_nodes
    return {
        "schema_version": SCHEMA_VERSION,
        "source": source,
        "nodes": nodes,
        "edges": sorted(edges, key=lambda edge: (edge["from"], edge["to"])),
        "topological_order": order,
        "parallel_waves": waves,
        "unknown_dependencies": unknown_dependencies,
        "cycle_nodes": cycle_nodes,
        "valid": valid,
        "gate": "ready" if valid else "dag_invalid",
    }


def _bucket_value(row: Mapping[str, Any], key: str) -> Any:
    for candidate in (row, row.get("task") if isinstance(row.get("task"), Mapping) else None, row.get("metadata") if isinstance(row.get("metadata"), Mapping) else None):
        if isinstance(candidate, Mapping) and candidate.get(key) is not None:
            return candidate.get(key)
    return None


def _history_rows(history: Any) -> list[Mapping[str, Any]]:
    if isinstance(history, Mapping):
        for key in ("observations", "history", "rows", "measurements"):
            candidate = history.get(key)
            if isinstance(candidate, Sequence) and not isinstance(candidate, (str, bytes)):
                return [row for row in candidate if isinstance(row, Mapping)]
        # A mapping of metric arrays is accepted as one legacy bucket.  This
        # preserves compatibility with task_estimator's --history format.
        if any(metric in history for metric in METRIC_SPECS):
            lengths = [
                len(value)
                for value in history.values()
                if isinstance(value, Sequence) and not isinstance(value, (str, bytes))
            ]
            count = max(lengths, default=0)
            rows: list[Mapping[str, Any]] = []
            for index in range(count):
                rows.append(
                    {
                        metric: values[index]
                        for metric, values in history.items()
                        if metric in METRIC_SPECS
                        and isinstance(values, Sequence)
                        and not isinstance(values, (str, bytes))
                        and index < len(values)
                    }
                )
            return rows
    if isinstance(history, Sequence) and not isinstance(history, (str, bytes)):
        return [row for row in history if isinstance(row, Mapping)]
    return []


def _nested_metric(row: Mapping[str, Any], container_name: str, metric: str) -> Any:
    container = row.get(container_name)
    if not isinstance(container, Mapping):
        return None
    value = container.get(metric)
    if isinstance(value, Mapping):
        for key in ("actual", "measured", "observed", "value"):
            if value.get(key) is not None:
                return value[key]
        # Percentile-only hints are not measurements and must not be used as
        # calibration observations.
        return None
    return value


def _actual_value(row: Mapping[str, Any], metric: str) -> float | None:
    for container_name in ("actual", "measured", "observed", "measurement", "metrics", "resources"):
        value = _nested_metric(row, container_name, metric)
        number = _finite_number(value)
        if number is not None:
            return number
    for key in (metric, f"actual_{metric}", f"measured_{metric}", f"observed_{metric}"):
        value = row.get(key)
        if isinstance(value, Mapping):
            value = value.get("actual", value.get("value"))
        number = _finite_number(value)
        if number is not None:
            return number
    return None


def _estimated_value(row: Mapping[str, Any], metric: str) -> float | None:
    for container_name in ("estimated", "estimate", "prediction", "predicted"):
        value = _nested_metric(row, container_name, metric)
        number = _finite_number(value)
        if number is not None:
            return number
    for key in (f"estimated_{metric}", f"predicted_{metric}"):
        value = row.get(key)
        if isinstance(value, Mapping):
            value = value.get("p50", value.get("value"))
        number = _finite_number(value)
        if number is not None:
            return number
    return None


def _confidence(observation_count: int) -> str:
    if observation_count <= 0:
        return "unknown"
    if observation_count == 1:
        return "low"
    if observation_count < 5:
        return "medium"
    return "high"


def calibrate_history(
    history: Any,
    *,
    task_family: str | None = None,
    model: str | None = None,
    host: str | None = None,
    alpha: float = 0.3,
    min_observations: int = 3,
) -> dict[str, Any]:
    """Calculate bounded historical calibration for one exact bucket.

    ``history`` may contain direct metric rows, ``actual``/``estimated``
    containers, or the legacy metric-array mapping.  Requested bucket keys are
    matched exactly; rows with a missing key do not leak into a narrower
    bucket.  Unknown metrics stay ``None`` and no factor of 1.0 is fabricated.
    """

    if not (0.0 < float(alpha) <= 1.0):
        raise ValueError("alpha must be in (0, 1]")
    if int(min_observations) < 1:
        raise ValueError("min_observations must be >= 1")
    bucket = {
        key: value
        for key, value in (("task_family", task_family), ("model", model), ("host", host))
        if isinstance(value, str) and value.strip()
    }
    rows = _history_rows(history)
    matched: list[Mapping[str, Any]] = []
    rejected_bucket = 0
    for row in rows:
        if any(_bucket_value(row, key) != expected for key, expected in bucket.items()):
            rejected_bucket += 1
            continue
        matched.append(row)

    metrics: dict[str, dict[str, Any]] = {}
    unknown_metrics: list[str] = []
    total_invalid = 0
    for metric, unit in METRIC_SPECS.items():
        values: list[float] = []
        ratios: list[float] = []
        invalid = 0
        for row in matched:
            actual = _actual_value(row, metric)
            if actual is None:
                invalid += 1
                continue
            values.append(actual)
            estimated = _estimated_value(row, metric)
            if estimated is not None and estimated > 0:
                ratios.append(actual / estimated)
        total_invalid += invalid
        if not values:
            unknown_metrics.append(metric)
            metrics[metric] = {
                "p50": None,
                "p90": None,
                "ewma": None,
                "bias_factor": None,
                "unit": unit,
                "confidence": "unknown",
                "source": "unknown",
                "observation_count": 0,
                "bias_observation_count": 0,
                "invalid_observation_count": invalid,
                "evidence": [f"history.{metric} not observed in selected bucket"],
            }
            continue
        ewma = values[0]
        for value in values[1:]:
            ewma = float(alpha) * value + (1.0 - float(alpha)) * ewma
        bias_factor = None
        if ratios:
            bias_factor = ratios[0]
            for ratio in ratios[1:]:
                bias_factor = float(alpha) * ratio + (1.0 - float(alpha)) * bias_factor
        metrics[metric] = {
            "p50": _number(_quantile(values, 0.50)),
            "p90": _number(_quantile(values, 0.90)),
            "ewma": _number(ewma),
            "bias_factor": _number(bias_factor),
            "unit": unit,
            "confidence": _confidence(len(values)),
            "source": "measured_history",
            "observation_count": len(values),
            "bias_observation_count": len(ratios),
            "invalid_observation_count": invalid,
            "evidence": [f"history.{metric} ({len(values)} measured observation(s))"],
        }
    observed_count = sum(row_count["observation_count"] for row_count in metrics.values())
    status = "unknown"
    if observed_count > 0:
        status = "calibrated" if any(
            row_count["observation_count"] >= int(min_observations) for row_count in metrics.values()
        ) else "pilot"
    return {
        "schema_version": SCHEMA_VERSION,
        "calibrator": CALIBRATOR_NAME,
        "bucket": bucket,
        "alpha": float(alpha),
        "min_observations": int(min_observations),
        "row_count": len(rows),
        "matched_row_count": len(matched),
        "rejected_bucket_count": rejected_bucket,
        "invalid_observation_count": total_invalid,
        "status": status,
        "metrics": metrics,
        "unknown_metrics": unknown_metrics,
        "evidence": [
            "provider-free measured history",
            "exact task_family/model/host bucket matching" if bucket else "unbucketed history",
            "unknown values are omitted, never treated as zero",
        ],
    }


def apply_history_calibration(
    estimate: Mapping[str, Any], calibration: Mapping[str, Any]
) -> dict[str, Any]:
    """Return a copy of an estimator report adjusted by measured bias factors.

    A metric changes only when both its estimate bounds and a measured
    ``bias_factor`` exist.  This function does not turn a pilot into a fully
    trusted estimate; it records the calibration provenance and leaves all
    unknown metrics untouched.
    """

    result = copy.deepcopy(dict(estimate))
    metrics = result.get("metrics")
    calibration_metrics = calibration.get("metrics") if isinstance(calibration, Mapping) else None
    if not isinstance(metrics, Mapping) or not isinstance(calibration_metrics, Mapping):
        result["calibration"] = {"status": "unknown", "applied_metrics": []}
        return result
    applied: list[str] = []
    for metric, row in metrics.items():
        calibration_row = calibration_metrics.get(metric)
        if not isinstance(row, dict) or not isinstance(calibration_row, Mapping):
            continue
        factor = _finite_number(calibration_row.get("bias_factor"))
        p50 = _finite_number(row.get("p50"))
        p90 = _finite_number(row.get("p90"))
        if factor is None or p50 is None or p90 is None:
            continue
        row["p50"] = _number(p50 * factor)
        row["p90"] = _number(max(p50 * factor, p90 * factor))
        row["source"] = "history_calibration"
        row["calibration_bias_factor"] = _number(factor)
        row.setdefault("evidence", []).append(
            f"{CALIBRATOR_NAME} bias_factor={_number(factor)}"
        )
        applied.append(str(metric))
    result["calibration"] = {
        "status": calibration.get("status", "unknown"),
        "bucket": dict(calibration.get("bucket", {})) if isinstance(calibration.get("bucket"), Mapping) else {},
        "applied_metrics": applied,
    }
    return result


def _safe_policy(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    return {str(key): value[key] for key in value if str(key) in _POLICY_KEYS}


def _safe_git(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    return {str(key): value[key] for key in value if str(key) in _GIT_KEYS}


def _manifest_summary(manifest: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(manifest, Mapping):
        return None
    return {
        key: manifest.get(key)
        for key in ("schema_version", "root", "role", "file_count", "total_bytes", "total_gib", "truncated", "limits", "evidence")
        if key in manifest
    }


_PLANNER_METRIC_MAP = {
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
    "input_tokens": "estimated_input_tokens",
    "output_tokens": "estimated_output_tokens",
}


def _planner_resources(estimate: Mapping[str, Any]) -> dict[str, Any]:
    """Project only known P50 facts into the planner job contract."""
    metrics = estimate.get("metrics") or {}
    result: dict[str, Any] = {}
    for metric, planner_name in _PLANNER_METRIC_MAP.items():
        row = metrics.get(metric) or {}
        if isinstance(row, Mapping) and row.get("p50") is not None:
            result[planner_name] = row["p50"]
    return result


def capture_task(
    task: Mapping[str, Any] | str,
    *,
    repo_root: str | pathlib.Path | None = None,
    manifest: Mapping[str, Any] | None = None,
    git_metadata: Mapping[str, Any] | None = None,
    policy: Mapping[str, Any] | None = None,
    history: Any = None,
    model: str | None = None,
    host: str | None = None,
    max_files: int = 2000,
    max_depth: int = 4,
    max_total_bytes: int = 8 * 1024 * 1024,
) -> dict[str, Any]:
    """Capture one task into a reviewable packet without execution.

    ``repo_root`` invokes only ``build_light_manifest`` (``stat`` metadata,
    bounded depth/bytes, no file content).  Git and policy information is
    caller-supplied and allow-listed; this keeps the function deterministic and
    avoids accidentally recording credentials or arbitrary environment data.
    """

    if isinstance(task, str):
        raw: dict[str, Any] = {"description": task}
    elif isinstance(task, Mapping):
        raw = dict(task)
    else:
        raise TypeError("task must be a mapping or description string")
    description = _clean_text(raw.get("description") or raw.get("request") or raw.get("prompt"))
    supplied_task_id = _clean_text(raw.get("job_id") or raw.get("task_id"), limit=MAX_ID_CHARS)
    task_id = _safe_id(supplied_task_id, "capture-task", set())
    if not supplied_task_id:
        digest = _hash_text(description) or "unknown"
        task_id = f"capture-{digest[:12]}"
    family = infer_task_family(description, raw.get("task_family"))

    if manifest is None and repo_root is not None:
        manifest = build_light_manifest(
            repo_root,
            max_files=max_files,
            max_depth=max_depth,
            max_total_bytes=max_total_bytes,
        )
    dag = build_dag(raw.get("steps"), raw.get("dag"), description=description)
    root_estimate = estimate_task(raw, manifest=manifest, history=history)
    node_job_ids: dict[str, str] = {}
    used_job_ids: set[str] = set()
    for node in dag["nodes"]:
        node_job_ids[node["id"]] = _safe_id(
            f"{task_id}-{node['id']}", f"{task_id}-node", used_job_ids
        )
    for node in dag["nodes"]:
        node_task = {
            "job_id": node_job_ids[node["id"]],
            "description": node.get("description") or description,
            "resources": node.get("resource_hints") or {},
        }
        if isinstance(raw.get("tokens"), Mapping):
            node_task["tokens"] = dict(raw["tokens"])
        node["task_family"] = infer_task_family(node_task["description"], raw.get("task_family"))
        node["estimate"] = estimate_task(node_task, history=history)

    calibration = None
    if history is not None:
        calibration = calibrate_history(
            history,
            task_family=family,
            model=model,
            host=host,
        )
        root_estimate = apply_history_calibration(root_estimate, calibration)

    planner_jobs = []
    for node in dag["nodes"]:
        node_estimate = node.get("estimate") or {}
        planner_job = {
            "job_id": node_job_ids[node["id"]],
            "description": node.get("description") or description,
            "task_type": infer_task_family(node.get("description") or description),
            "depends_on": [
                node_job_ids[dependency]
                for dependency in (node.get("depends_on") or [])
            ],
            "resource_estimate": _planner_resources(node_estimate),
            "pilot": bool(node_estimate.get("pilot_required") is False),
            "capture_source": task_id,
        }
        node_policy = node.get("policy")
        if not isinstance(node_policy, Mapping):
            node_policy = raw.get("policy")
        if isinstance(node_policy, Mapping) and node_policy.get("requires_external_network") is True:
            planner_job["requires_external_network"] = True
        elif raw.get("requires_external_network") is True:
            planner_job["requires_external_network"] = True
        planner_jobs.append(planner_job)

    evidence = ["user-supplied request text", "provider prompts not sent", "project commands not executed"]
    if manifest is not None:
        evidence.append("bounded filesystem metadata manifest")
    if git_metadata:
        evidence.append("caller-supplied git metadata (not executed by capture)")
    if policy:
        evidence.append("allow-listed user policy")
    packet = {
        "schema_version": SCHEMA_VERSION,
        "capture": CAPTURE_NAME,
        "captured_at_utc": dt.datetime.now(tz=dt.timezone.utc).isoformat(),
        "read_only": True,
        "provider_prompts_sent": False,
        "project_executed": False,
        "task_id": task_id,
        **({"task_id_source": supplied_task_id} if supplied_task_id and supplied_task_id != task_id else {}),
        "task_family": family,
        "description": description,
        "description_sha256": _hash_text(description),
        "policy": _safe_policy(policy if policy is not None else raw.get("policy")),
        "git": _safe_git(git_metadata if git_metadata is not None else raw.get("git")),
        "repository": _manifest_summary(manifest),
        "dag": dag,
        "planner_jobs": planner_jobs,
        "estimate": root_estimate,
        "calibration": calibration,
        "gate": "ready" if dag["valid"] else "dag_invalid",
        "evidence": evidence,
        "unknown_semantics": {
            "missing_resource": "unknown",
            "missing_history": "unknown",
            "invalid_dag": "blocked_until_review",
            "missing_model_or_host_bucket": "unbucketed_history_only",
        },
    }
    return packet


def _load_json(path: str) -> Any:
    return json.loads(pathlib.Path(path).expanduser().read_text(encoding="utf-8"))


def _task_arg(value: str) -> Mapping[str, Any] | str:
    path = pathlib.Path(value).expanduser()
    if not path.is_file():
        return value
    payload = _load_json(str(path))
    if isinstance(payload, Mapping) and isinstance(payload.get("task"), Mapping):
        return payload["task"]
    if isinstance(payload, Mapping):
        return payload
    raise ValueError("--task JSON must be an object")


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--task", required=True, help="JSON task file or literal description")
    parser.add_argument("--repo-root", help="bounded metadata-only repository root")
    parser.add_argument("--manifest", help="precomputed bounded manifest JSON")
    parser.add_argument("--git-metadata", help="caller-supplied git metadata JSON")
    parser.add_argument("--policy", help="allow-listed user policy JSON")
    parser.add_argument("--history", help="historical observation JSON")
    parser.add_argument("--model")
    parser.add_argument("--host")
    parser.add_argument("--output")
    parser.add_argument("--max-files", type=int, default=2000)
    parser.add_argument("--max-depth", type=int, default=4)
    parser.add_argument("--max-total-bytes", type=int, default=8 * 1024 * 1024)
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
        manifest = _load_json(args.manifest) if args.manifest else None
        if manifest is not None and not isinstance(manifest, Mapping):
            raise ValueError("--manifest JSON must be an object")
        git_metadata = _load_json(args.git_metadata) if args.git_metadata else None
        policy = _load_json(args.policy) if args.policy else None
        history = _load_json(args.history) if args.history else None
        packet = capture_task(
            _task_arg(args.task),
            repo_root=args.repo_root,
            manifest=manifest,
            git_metadata=git_metadata,
            policy=policy,
            history=history,
            model=args.model,
            host=args.host,
            max_files=args.max_files,
            max_depth=args.max_depth,
            max_total_bytes=args.max_total_bytes,
        )
        validate_schema("task_capture", packet)
        _write(args.output, packet)
        return 0
    except Exception as exc:
        _write(args.output, {"schema_version": SCHEMA_VERSION, "ok": False, "error": f"{type(exc).__name__}: {exc}"})
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
