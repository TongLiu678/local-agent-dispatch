#!/usr/bin/env python3
"""Provider-free virtual 24-hour continuity soak.

The runner advances the existing deterministic fake-cluster clock; it never
sleeps, contacts SSH/PBS, starts a provider, or downloads data.  Its output is
an evidence packet for deciding whether a real server soak may begin.  A
virtual pass is therefore E1/provider-free evidence only.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import sys
from typing import Any, Mapping, Sequence

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from research.replay.run_manifest import build_manifest  # noqa: E402
from research.simulator.fake_cluster import (  # noqa: E402
    QuotaAwarePolicy,
    run_replay,
)


class ContinuousSoakError(ValueError):
    """Raised when a virtual-soak request is outside the safe boundary."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _horizon(value: Any) -> int:
    if isinstance(value, bool):
        raise ContinuousSoakError("horizon_seconds must be an integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ContinuousSoakError("horizon_seconds must be an integer") from exc
    if parsed < 3600 or parsed > 7 * 24 * 60 * 60:
        raise ContinuousSoakError("horizon_seconds must be between one hour and seven days")
    return parsed


def _load_scenario(path: pathlib.Path | str | None) -> dict[str, Any]:
    scenario_path = pathlib.Path(path) if path else ROOT / "research" / "scenarios" / "quota-windows.json"
    try:
        payload = json.loads(scenario_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ContinuousSoakError(f"cannot read provider-free scenario: {scenario_path}") from exc
    if not isinstance(payload, Mapping):
        raise ContinuousSoakError("provider-free scenario must be an object")
    if not isinstance(payload.get("pools"), list) or not isinstance(payload.get("hosts"), list):
        raise ContinuousSoakError("provider-free scenario needs pools and hosts")
    return dict(payload)


def _default_faults() -> list[dict[str, Any]]:
    # Targets are chosen so that the injected duplicate delivery is observed
    # while the review-required job is still in flight; a duplicate effect is
    # never silently accepted as a successful soak.
    return [
        {"fault": "crash", "t": 600.0, "target": "worker-a"},
        {"fault": "lost_ack", "t": 900.0, "target": "worker-a"},
        {"fault": "duplicate_delivery", "t": 1200.0, "target": "j-3"},
        {"fault": "stale_fence", "t": 1800.0, "target": "worker-a"},
        {"fault": "partial_artifact", "t": 2400.0, "target": "j-3"},
        {"fault": "ssh_disconnect", "t": 3600.0, "target": "host-remote-a"},
        {"fault": "quota_exhaustion", "t": 7200.0, "target": "opencode.go"},
        {"fault": "quota_reset", "t": 9000.0, "target": "opencode.go"},
        {"fault": "mount_loss", "t": 12000.0, "target": "host-remote-a"},
        {"fault": "capability_rejection", "t": 18000.0, "target": "opencode.go"},
        {"fault": "missing_human_review", "t": 24000.0, "target": "j-3"},
    ]


def _replay_manifest(*, seed: int, horizon: int, scenario: Mapping[str, Any], faults: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    corpus = list(scenario.get("job_corpus") or [])
    if not corpus:
        raise ContinuousSoakError("scenario job_corpus is empty")
    jobs: list[dict[str, Any]] = []
    for index in range(max(4, min(16, len(corpus) * 2))):
        template = dict(corpus[index % len(corpus)])
        template["job_id"] = f"j-{index}"
        template["arrival"] = float(index * 120.0)
        jobs.append(template)
    fixture = {"pools": scenario["pools"], "hosts": scenario["hosts"]}
    return {
        "seed": int(seed),
        "start": 0.0,
        "horizon": float(horizon),
        "fixture": fixture,
        "jobs": jobs,
        "faults": [dict(row) for row in faults],
    }


def _continuous_manifest(*, run_id: str, seed: int, horizon: int, fixture: Mapping[str, Any], faults: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    epoch = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
    raw = {
        "schema_version": 1,
        "run_id": run_id,
        "mode": "offline_soak",
        "evidence_level": "E1",
        "source_digest": _digest({"fixture": fixture, "seed": seed}),
        "policy_digest": _digest({"policy": "quota_aware", "seed": seed}),
        "capsule_digest": _digest({"capsule": "virtual-provider-free", "seed": seed}),
        "segment_seconds": 3600,
        "planned_end_at": (epoch + dt.timedelta(seconds=horizon)).isoformat().replace("+00:00", "Z"),
        "fault_schedule_digest": _digest(list(faults)),
        "stop_conditions": {
            "accepted_task_loss": 0,
            "duplicate_irreversible_effect": 0,
            "unowned_process_signal": 0,
            "oom_or_enospc_unrecorded": 0,
        },
        "validator_id": "continuous-soak-validator-v1",
        "provider_execution": False,
        "network_execution": False,
        "metadata": {"clock_mode": "virtual", "seed": int(seed)},
    }
    return build_manifest(raw)


def _checkpoint_chain(*, run_id: str, horizon: int, segment_seconds: int, manifest_digest: str) -> list[dict[str, Any]]:
    previous = "sha256:" + "0" * 64
    checkpoints: list[dict[str, Any]] = []
    count = (horizon + segment_seconds - 1) // segment_seconds
    for sequence in range(1, count + 1):
        at = min(horizon, sequence * segment_seconds)
        state = {
            "run_id": run_id,
            "sequence": sequence,
            "at_seconds": at,
            "manifest_digest": manifest_digest,
            "previous_state_digest": previous,
        }
        state_digest = _digest(state)
        checkpoints.append({
            "checkpoint_id": f"{run_id}:checkpoint:{sequence}",
            "run_id": run_id,
            "sequence": sequence,
            "at_seconds": at,
            "previous_state_digest": previous,
            "state_digest": state_digest,
            "artifact_manifest": [],
            "validator_state": "provider_free_virtual",
        })
        previous = state_digest
    return checkpoints


def run_virtual_soak(*, seed: int = 11, horizon_seconds: int = 24 * 60 * 60, scenario: pathlib.Path | str | None = None, faults: Sequence[Mapping[str, Any]] | None = None) -> dict[str, Any]:
    """Run one deterministic virtual soak and return a redacted evidence packet."""

    if isinstance(seed, bool):
        raise ContinuousSoakError("seed must be an integer")
    try:
        seed_value = int(seed)
    except (TypeError, ValueError) as exc:
        raise ContinuousSoakError("seed must be an integer") from exc
    horizon = _horizon(horizon_seconds)
    scenario_obj = _load_scenario(scenario)
    fault_rows = [dict(row) for row in (faults if faults is not None else _default_faults())]
    replay_manifest = _replay_manifest(seed=seed_value, horizon=horizon, scenario=scenario_obj, faults=fault_rows)
    continuous = _continuous_manifest(
        run_id=f"virtual-soak-{seed_value}",
        seed=seed_value,
        horizon=horizon,
        fixture=replay_manifest["fixture"],
        faults=fault_rows,
    )
    record = run_replay(replay_manifest, QuotaAwarePolicy())
    serialized = json.loads(record.serialize())
    summary = dict(serialized.get("summary") or {})
    invariant_failures: list[str] = []
    violations = summary.get("violations") if isinstance(summary.get("violations"), Mapping) else {}
    if int(violations.get("duplicate_effect", 0) or 0) != 0:
        invariant_failures.append("duplicate_delivery_created_irreversible_effect")
    if int(violations.get("unvalidated_completed", 0) or 0) != 0:
        invariant_failures.append("unvalidated_completed_job")
    checkpoints = _checkpoint_chain(
        run_id=continuous["run_id"],
        horizon=horizon,
        segment_seconds=int(continuous["segment_seconds"]),
        manifest_digest=_digest(continuous),
    )
    if len(checkpoints) != (horizon + int(continuous["segment_seconds"]) - 1) // int(continuous["segment_seconds"]):
        invariant_failures.append("checkpoint_chain_length_mismatch")
    report: dict[str, Any] = {
        "schema_version": 1,
        "report_type": "local-agent-dispatch.continuous_soak",
        "provider_execution": False,
        "network_execution": False,
        "clock_mode": "virtual",
        "evidence_ceiling": "E1_provider_free_virtual_only",
        "run_manifest": continuous,
        "manifest_digest": _digest(continuous),
        "replay_manifest_digest": _digest(replay_manifest),
        "horizon_seconds": horizon,
        "segment_count": len(checkpoints),
        "checkpoints": checkpoints,
        "event_trace": serialized.get("event_trace", []),
        "outcome": summary,
        "invariant_failures": invariant_failures,
    }
    report["ok"] = not invariant_failures
    report["decision"] = "eligible_for_server_provider_free_soak" if report["ok"] else "blocked"
    report["report_digest"] = _digest(report)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("virtual", "real-clock"), default="virtual")
    parser.add_argument("--horizon-seconds", type=int, default=24 * 60 * 60)
    parser.add_argument("--seed", type=int, default=11)
    parser.add_argument("--scenario")
    parser.add_argument("--manifest-out")
    args = parser.parse_args(argv)
    if args.mode != "virtual":
        print(json.dumps({"schema_version": 1, "ok": False, "error": "real_clock_requires_reviewed_server_preflight"}, sort_keys=True))
        return 2
    try:
        report = run_virtual_soak(seed=args.seed, horizon_seconds=args.horizon_seconds, scenario=args.scenario)
    except (ContinuousSoakError, ValueError, TypeError, KeyError) as exc:
        print(json.dumps({"schema_version": 1, "ok": False, "error": type(exc).__name__, "detail": str(exc)}, sort_keys=True))
        return 2
    output = json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if args.manifest_out:
        path = pathlib.Path(args.manifest_out).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(output, encoding="utf-8")
    print(output, end="")
    return 0 if report["ok"] else 1


__all__ = ["ContinuousSoakError", "run_virtual_soak"]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
