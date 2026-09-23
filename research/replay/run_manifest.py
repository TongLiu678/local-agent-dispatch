"""Provider-free run-manifest validator for the research program (WP0).

Every research result must carry a machine-readable run manifest that pins
policy digest, seed, source/fixture digest, start commit or source digest,
evidence level, validator identity, and result digest.  This module is
stdlib-only and never contacts a provider, the network, or a shell.

Fail-closed contract
--------------------
`validate_run_manifest` rejects any manifest that is missing, malformed, or
that names an unknown schema version, evidence level, or validator.  A result
without a manifest, without a validator identity, or without an evidence
level is never accepted.  `verify_fixture` / `verify_result` recompute the
declared digests over canonical JSON; a mismatch fails closed.  Unknown or
missing values are never fabricated.
"""

from __future__ import annotations

import hashlib
import json
import re
import datetime as dt
from typing import Any, Mapping

MANIFEST_SCHEMA_VERSION = 1

EVIDENCE_LEVELS = ("E0", "E1", "E2", "E3", "E4")

# Provider-free evidence ceiling: replay/simulator artifacts may only carry
# E0 (schema/design review) or E1 (fixture/replay) evidence.
PROVIDER_FREE_CEILING = "E1"

DIGEST_ALGORITHM = "sha256"

_DIGEST_HEX = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_HEX = re.compile(r"^[0-9a-f]{7,64}$")
_VALIDATOR_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_CONTINUOUS_ID = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
_CONTINUOUS_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")

CONTINUOUS_RUN_MODES = ("offline_soak", "shadow", "canary", "soak")
_CONTINUOUS_STOP_FIELDS = (
    "accepted_task_loss",
    "duplicate_irreversible_effect",
    "unowned_process_signal",
    "oom_or_enospc_unrecorded",
)

_REQUIRED_FIELDS = (
    "schema_version",
    "policy_digest",
    "seed",
    "fixture_digest",
    "evidence_level",
    "validator_id",
    "result_digest",
)

_MISSING_CODES = {
    "schema_version": "missing_schema_version",
    "policy_digest": "missing_policy_digest",
    "seed": "missing_seed",
    "fixture_digest": "missing_fixture_digest",
    "evidence_level": "missing_evidence_level",
    "validator_id": "missing_validator_id",
    "result_digest": "missing_result_digest",
}


def _canonical(payload: Any) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def digest(payload: Any) -> str:
    """Deterministic sha256 over canonical JSON of ``payload``."""
    return hashlib.sha256(_canonical(payload)).hexdigest()


def _continuous_timestamp(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be an ISO-8601 timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include a timezone")
    return value


def _continuous_digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _CONTINUOUS_DIGEST.fullmatch(value):
        raise ValueError(f"{field} must be a sha256:<64 lowercase hex> digest")
    return value


def build_manifest(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and canonicalize a continuous-run manifest.

    The existing ``seal_run_manifest`` contract is intentionally unchanged:
    it describes a replay result and requires seed/fixture/result digests.  A
    continuous-run manifest describes an active 24-hour execution window, so
    it has a separate, explicit contract and never infers missing fields from
    the replay manifest.
    """

    if not isinstance(payload, Mapping):
        raise ValueError("continuous manifest must be an object")
    required = (
        "schema_version",
        "run_id",
        "mode",
        "evidence_level",
        "source_digest",
        "policy_digest",
        "capsule_digest",
        "planned_end_at",
        "stop_conditions",
        "validator_id",
    )
    missing = [field for field in required if field not in payload]
    if missing:
        raise ValueError("continuous manifest missing: " + ",".join(missing))
    if payload.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise ValueError("continuous manifest schema_version is unsupported")
    run_id = payload.get("run_id")
    if not isinstance(run_id, str) or not _CONTINUOUS_ID.fullmatch(run_id):
        raise ValueError("run_id is invalid")
    mode = payload.get("mode")
    if mode not in CONTINUOUS_RUN_MODES:
        raise ValueError(f"continuous manifest mode is invalid: {mode!r}")
    evidence_level = payload.get("evidence_level")
    if evidence_level not in EVIDENCE_LEVELS:
        raise ValueError(f"continuous manifest evidence level is invalid: {evidence_level!r}")
    if mode == "offline_soak" and evidence_level not in {"E0", "E1"}:
        raise ValueError("offline_soak may only carry E0 or E1 evidence")
    if payload.get("provider_execution") is True and evidence_level in {"E0", "E1"}:
        raise ValueError("provider execution cannot be declared with provider-free evidence")
    if payload.get("network_execution") is True and mode == "offline_soak":
        raise ValueError("offline_soak cannot declare network execution")

    normalized: dict[str, Any] = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "run_id": run_id,
        "mode": mode,
        "evidence_level": evidence_level,
        "source_digest": _continuous_digest(payload.get("source_digest"), "source_digest"),
        "policy_digest": _continuous_digest(payload.get("policy_digest"), "policy_digest"),
        "capsule_digest": _continuous_digest(payload.get("capsule_digest"), "capsule_digest"),
        "planned_end_at": _continuous_timestamp(payload.get("planned_end_at"), "planned_end_at"),
        "validator_id": payload.get("validator_id"),
    }
    validator_id = normalized["validator_id"]
    if not isinstance(validator_id, str) or not _VALIDATOR_ID.fullmatch(validator_id):
        raise ValueError("validator_id is invalid")

    if "start_at" in payload:
        normalized["start_at"] = _continuous_timestamp(payload.get("start_at"), "start_at")
    if "mission_id" in payload:
        mission_id = payload.get("mission_id")
        if not isinstance(mission_id, str) or not _CONTINUOUS_ID.fullmatch(mission_id):
            raise ValueError("mission_id is invalid")
        normalized["mission_id"] = mission_id
    segment_seconds = payload.get("segment_seconds", 3600)
    if isinstance(segment_seconds, bool) or not isinstance(segment_seconds, int):
        raise ValueError("segment_seconds must be an integer")
    if segment_seconds < 60 or segment_seconds > 24 * 60 * 60:
        raise ValueError("segment_seconds must be between 60 and 86400")
    normalized["segment_seconds"] = segment_seconds
    if "scheduler_max_wall_seconds" in payload:
        scheduler_max = payload.get("scheduler_max_wall_seconds")
        if isinstance(scheduler_max, bool) or not isinstance(scheduler_max, int) or scheduler_max < 60:
            raise ValueError("scheduler_max_wall_seconds is invalid")
        if segment_seconds > scheduler_max:
            raise ValueError("segment_seconds exceeds scheduler walltime evidence")
        normalized["scheduler_max_wall_seconds"] = scheduler_max
    if "fault_schedule_digest" in payload:
        normalized["fault_schedule_digest"] = _continuous_digest(
            payload.get("fault_schedule_digest"), "fault_schedule_digest"
        )

    stop_conditions = payload.get("stop_conditions")
    if not isinstance(stop_conditions, Mapping):
        raise ValueError("stop_conditions must be an object")
    if set(stop_conditions) != set(_CONTINUOUS_STOP_FIELDS):
        raise ValueError("stop_conditions must contain the exact safety fields")
    normalized_stop: dict[str, int] = {}
    for field in _CONTINUOUS_STOP_FIELDS:
        value = stop_conditions.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"stop_conditions.{field} must be a non-negative integer")
        normalized_stop[field] = value
    normalized["stop_conditions"] = normalized_stop

    for field in ("provider_execution", "network_execution"):
        if field in payload:
            value = payload.get(field)
            if not isinstance(value, bool):
                raise ValueError(f"{field} must be boolean")
            normalized[field] = value
    for field in ("scheduler", "host_fingerprint", "metadata"):
        if field in payload:
            value = payload.get(field)
            if not isinstance(value, Mapping):
                raise ValueError(f"{field} must be an object")
            normalized[field] = dict(value)
    return normalized


def _digest_field_error(field: str, value: Any) -> str | None:
    if field in ("start_commit",):
        return None
    if not isinstance(value, str):
        return f"malformed_{field}"
    if not _DIGEST_HEX.fullmatch(value):
        return f"malformed_{field}"
    return None


def _start_source_error(manifest: Mapping[str, Any]) -> str | None:
    has_start = isinstance(manifest.get("start_commit"), str)
    has_source = isinstance(manifest.get("source_digest"), str)
    if not has_start and not has_source:
        return "missing_start_source"
    if has_start and not _COMMIT_HEX.fullmatch(manifest["start_commit"]):
        return "malformed_start_commit"
    if has_source and not _DIGEST_HEX.fullmatch(manifest["source_digest"]):
        return "malformed_source_digest"
    return None


def validate_run_manifest(manifest: Any) -> dict[str, Any]:
    """Validate a run manifest and return a report.

    Fail-closed: the report is ``valid`` only when every required field is
    present, well-formed, and carries a known schema version, evidence level,
    and validator identity.
    """
    errors: list[str] = []
    fields: dict[str, Any] = {}

    if not isinstance(manifest, Mapping):
        return {
            "schema_version": MANIFEST_SCHEMA_VERSION,
            "valid": False,
            "errors": ["missing_manifest"],
            "warnings": [],
            "fields": {},
        }

    for field, code in _MISSING_CODES.items():
        if field not in manifest:
            errors.append(code)
        else:
            fields[field] = manifest[field]

    if "schema_version" in manifest:
        if manifest["schema_version"] != MANIFEST_SCHEMA_VERSION:
            errors.append("unsupported_schema_version")
            fields["schema_version"] = manifest["schema_version"]

    if "seed" in manifest:
        if isinstance(manifest["seed"], bool) or not isinstance(manifest["seed"], int):
            errors.append("invalid_seed")
        else:
            fields["seed"] = manifest["seed"]

    for field in ("policy_digest", "fixture_digest", "result_digest", "source_digest"):
        if field in manifest:
            code = _digest_field_error(field, manifest[field])
            if code:
                errors.append(code)

    if "evidence_level" in manifest:
        if manifest["evidence_level"] not in EVIDENCE_LEVELS:
            errors.append("unknown_evidence_level")
        else:
            fields["evidence_level"] = manifest["evidence_level"]

    if "validator_id" in manifest:
        if not isinstance(manifest["validator_id"], str) or not _VALIDATOR_ID.fullmatch(
            manifest["validator_id"]
        ):
            errors.append("malformed_validator_id")

    start_error = _start_source_error(manifest)
    if start_error:
        errors.append(start_error)

    valid = not errors
    fields["digest_algorithm"] = DIGEST_ALGORITHM
    fields["evidence_ceiling"] = PROVIDER_FREE_CEILING
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "valid": valid,
        "errors": sorted(set(errors)),
        "warnings": [],
        "fields": fields,
    }


def verify_fixture(manifest: Mapping[str, Any], fixture_payload: Any) -> bool:
    """Recompute the declared fixture digest over ``fixture_payload``.

    A missing manifest or a digest mismatch fails closed (returns False).
    """
    if not isinstance(manifest, Mapping):
        return False
    declared = manifest.get("fixture_digest")
    if not isinstance(declared, str):
        return False
    return digest(fixture_payload) == declared


def verify_result(manifest: Mapping[str, Any], result_payload: Any) -> bool:
    """Recompute the declared result digest over ``result_payload``.

    A missing manifest or a digest mismatch fails closed (returns False).
    """
    if not isinstance(manifest, Mapping):
        return False
    declared = manifest.get("result_digest")
    if not isinstance(declared, str):
        return False
    return digest(result_payload) == declared


def seal_run_manifest(
    *,
    policy_payload: Any,
    fixture_payload: Any,
    result_payload: Any,
    seed: int,
    evidence_level: str,
    validator_id: str,
    start_commit: str | None = None,
    source_digest: str | None = None,
    policy_digest: str | None = None,
    max_evidence_level: str = PROVIDER_FREE_CEILING,
) -> dict[str, Any]:
    """Build a self-consistent, byte-stable run manifest.

    Digests are computed over canonical JSON of the payloads, so the same
    inputs produce the identical manifest.  ``evidence_level`` above the
    configured ceiling (default: provider-free E1) raises ValueError; missing
    start provenance fails closed.
    """
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ValueError("seed must be an int")
    if evidence_level not in EVIDENCE_LEVELS:
        raise ValueError(f"unknown evidence level: {evidence_level!r}")
    max_index = EVIDENCE_LEVELS.index(max_evidence_level)
    if EVIDENCE_LEVELS.index(evidence_level) > max_index:
        raise ValueError(
            f"evidence level {evidence_level} exceeds ceiling {max_evidence_level}"
        )
    if not isinstance(validator_id, str) or not _VALIDATOR_ID.fullmatch(validator_id):
        raise ValueError(f"invalid validator id: {validator_id!r}")
    if start_commit is None and source_digest is None:
        raise ValueError("start_commit or source_digest is required")
    if start_commit is not None and not _COMMIT_HEX.fullmatch(start_commit):
        raise ValueError(f"invalid start commit: {start_commit!r}")
    if source_digest is not None and not _DIGEST_HEX.fullmatch(source_digest):
        raise ValueError(f"invalid source digest: {source_digest!r}")

    manifest: dict[str, Any] = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "policy_digest": policy_digest or digest(policy_payload),
        "seed": seed,
        "fixture_digest": digest(fixture_payload),
        "evidence_level": evidence_level,
        "validator_id": validator_id,
        "result_digest": digest(result_payload),
    }
    if start_commit is not None:
        manifest["start_commit"] = start_commit
    if source_digest is not None:
        manifest["source_digest"] = source_digest
    return manifest
