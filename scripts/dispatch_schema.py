import json
import pathlib
import re
from typing import Any

SCHEMA_DIR = pathlib.Path(__file__).resolve().parents[1] / "schemas"

class SchemaValidationError(Exception):
    """Raised when a document violates structural invariants or schema requirements."""
    pass

def load_schema(name: str) -> dict[str, Any]:
    """Load a base JSON schema by name."""
    path = SCHEMA_DIR / f"{name}.schema.json"
    if not path.exists():
        raise SchemaValidationError(f"Schema {name} not found")
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)

def validate(name: str, payload: dict[str, Any]) -> None:
    """
    Validate the payload against minimum structural invariants,
    bypassing a heavy jsonschema dependency for performance and deterministic behavior.
    """
    if not isinstance(payload, dict):
        raise SchemaValidationError("Payload must be a dictionary")

    version = payload.get("schema_version")
    if version is None:
        raise SchemaValidationError("Missing schema_version")

    # Foundry packets are a separately versioned, strict JSON boundary.  They
    # must not be silently coerced into the legacy integer-version packet
    # contract: the caller-owned binding and self-digest are the authority
    # passed between repositories.
    if name == "task_packet" and version == "lad_task_packet/2.0.0":
        _validate_foundry_task_packet_contract(payload)
        _check_secrets(payload)
        return
    
    if version != 1:
        raise SchemaValidationError(f"Unsupported schema_version: {version}")

    _validate_common_fields(payload)
    if name == "task_packet":
        _validate_task_packet_contract(payload)
    elif name == "dispatch_workflow_report":
        _validate_dispatch_workflow_report_contract(payload)
    elif name == "task_capture":
        _validate_task_capture_contract(payload)
    elif name == "reservation":
        _validate_reservation_contract(payload)
    _check_secrets(payload)

def _validate_common_fields(payload: dict[str, Any]) -> None:
    # Validate commonly structured fields if they are present
    for field in ("job", "attempt", "pool"):
        val = payload.get(field)
        if val is not None and not isinstance(val, dict):
            raise SchemaValidationError(f"malformed {field} field: must be a dict")

    # Pools usually contain mapping of pool_id -> dict
    pools = payload.get("pools")
    if pools is not None:
        if not isinstance(pools, dict):
            raise SchemaValidationError("malformed pools field: must be a dict")
        for k, v in pools.items():
            if not isinstance(v, dict):
                raise SchemaValidationError(f"malformed pool entry for {k}: must be a dict")


def _validate_task_packet_contract(payload: dict[str, Any]) -> None:
    """Validate the modern packet shape while retaining explicit migration."""
    modern = "packet_id" in payload or "attempts" in payload
    if not modern:
        return
    if payload.get("legacy_compatibility") is True:
        return
    for field in ("packet_id", "job_id", "write_scope"):
        if not isinstance(payload.get(field), str) or not payload.get(field):
            raise SchemaValidationError(f"task_packet requires non-empty {field}")
    if payload.get("validation_required") is not True:
        raise SchemaValidationError("task_packet requires validation_required=true")
    artifacts = payload.get("required_artifacts")
    if not isinstance(artifacts, list) or not artifacts or not all(isinstance(item, str) and item for item in artifacts):
        raise SchemaValidationError("task_packet requires non-empty required_artifacts")
    attempts = payload.get("attempts")
    if not isinstance(attempts, list) or not attempts:
        raise SchemaValidationError("task_packet requires non-empty attempts")
    for index, attempt in enumerate(attempts):
        if not isinstance(attempt, dict):
            raise SchemaValidationError(f"malformed task_packet attempt {index}")
        for field in ("attempt_id", "adapter", "transport", "model"):
            if not isinstance(attempt.get(field), str) or not attempt.get(field):
                raise SchemaValidationError(f"task_packet attempt {index} requires {field}")


_FOUNDRY_PACKET_FIELDS = frozenset({
    "schema_version", "kind", "job_id", "exact_model", "exact_effort",
    "execution_host_digest", "workload_host_digest", "resource_request",
    "quota_snapshot", "write_scope", "validation_command", "artifact_path",
    "result_path", "plan_digest", "assignment_digest", "foundry_binding",
    "packet_digest",
})
_FOUNDRY_BINDING_FIELDS = frozenset({
    "schema_version", "kind", "task_profile_digest", "agent_instance_digest",
    "cps_recipe_digest", "route_manifest_digest", "lane_profile_digest",
    "resource_request_digest", "quota_snapshot_digest",
    "builder_backend_evidence_digest", "worktree_lease_digest", "worktree_fence",
    "plan_digest", "assignment_digest", "adapter_digest", "binding_digest",
})
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")


def _foundry_digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise SchemaValidationError(f"Foundry packet {label} must be a sha256 digest")
    return value


def _foundry_content_digest(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    import hashlib
    return "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _validate_foundry_task_packet_contract(payload: dict[str, Any]) -> None:
    if set(payload) != _FOUNDRY_PACKET_FIELDS:
        missing = sorted(_FOUNDRY_PACKET_FIELDS - set(payload))
        extra = sorted(set(payload) - _FOUNDRY_PACKET_FIELDS)
        raise SchemaValidationError(
            f"Foundry task packet fields differ from schema: missing={missing}, extra={extra}"
        )
    if payload.get("kind") != "foundry_task_packet":
        raise SchemaValidationError("Foundry task packet kind is invalid")
    for field in (
        "job_id", "exact_model", "execution_host_digest", "workload_host_digest",
        "plan_digest", "assignment_digest",
    ):
        if not isinstance(payload.get(field), str) or not payload[field]:
            raise SchemaValidationError(f"Foundry task packet requires non-empty {field}")
    if payload.get("exact_effort") is not None and not isinstance(payload.get("exact_effort"), str):
        raise SchemaValidationError("Foundry task packet exact_effort must be a string or null")
    for field in ("execution_host_digest", "workload_host_digest", "plan_digest", "assignment_digest", "packet_digest"):
        _foundry_digest(payload[field], field)
    write_scope = payload.get("write_scope")
    if (
        not isinstance(write_scope, list)
        or not write_scope
        or not all(isinstance(item, str) and item and not item.startswith("/") for item in write_scope)
        or any(".." in item.replace("\\", "/").split("/") for item in write_scope)
    ):
        raise SchemaValidationError("Foundry task packet write_scope must be safe relative paths")
    command = payload.get("validation_command")
    if not isinstance(command, list) or not command or not all(isinstance(item, str) and item for item in command):
        raise SchemaValidationError("Foundry task packet validation_command must be a non-empty argv")
    executable = command[0].rsplit("/", 1)[-1].lower()
    if executable in {"sh", "bash", "zsh", "fish", "cmd", "powershell", "pwsh"} and any(
        item in {"-c", "/c", "-command"} for item in command[1:]
    ):
        raise SchemaValidationError("Foundry task packet validation_command may not invoke a shell")
    for field in ("artifact_path", "result_path"):
        value = payload.get(field)
        if not isinstance(value, str) or not value or ".." in value.replace("\\", "/").split("/"):
            raise SchemaValidationError(f"Foundry task packet {field} is unsafe")
    for field in ("resource_request", "quota_snapshot", "foundry_binding"):
        if not isinstance(payload.get(field), dict):
            raise SchemaValidationError(f"Foundry task packet requires object {field}")
    binding = payload["foundry_binding"]
    if set(binding) != _FOUNDRY_BINDING_FIELDS:
        missing = sorted(_FOUNDRY_BINDING_FIELDS - set(binding))
        extra = sorted(set(binding) - _FOUNDRY_BINDING_FIELDS)
        raise SchemaValidationError(f"Foundry binding fields differ from schema: missing={missing}, extra={extra}")
    if binding.get("schema_version") != "cpslab_lad_binding/0.1.0" or binding.get("kind") != "lad_packet_binding":
        raise SchemaValidationError("Foundry binding schema or kind is invalid")
    for field in _FOUNDRY_BINDING_FIELDS - {"schema_version", "kind", "worktree_fence", "binding_digest"}:
        _foundry_digest(binding[field], f"foundry_binding.{field}")
    if isinstance(binding.get("worktree_fence"), bool) or not isinstance(binding.get("worktree_fence"), int) or binding["worktree_fence"] < 1:
        raise SchemaValidationError("Foundry binding worktree_fence must be positive")
    binding_body = {key: value for key, value in binding.items() if key != "binding_digest"}
    _foundry_digest(binding["binding_digest"], "foundry_binding.binding_digest")
    if binding["binding_digest"] != _foundry_content_digest(binding_body):
        raise SchemaValidationError("Foundry binding self-digest mismatch")
    packet_body = {key: value for key, value in payload.items() if key != "packet_digest"}
    if payload["packet_digest"] != _foundry_content_digest(packet_body):
        raise SchemaValidationError("Foundry task packet self-digest mismatch")
    resource_request = payload["resource_request"]
    quota_snapshot = payload["quota_snapshot"]
    request_digest = resource_request.get("request_digest")
    if not isinstance(request_digest, str) or request_digest != _foundry_content_digest(
        {key: value for key, value in resource_request.items() if key != "request_digest"}
    ):
        raise SchemaValidationError("Foundry resource request self-digest mismatch")
    snapshot_digest = quota_snapshot.get("snapshot_digest")
    if not isinstance(snapshot_digest, str) or snapshot_digest != _foundry_content_digest(
        {key: value for key, value in quota_snapshot.items() if key != "snapshot_digest"}
    ):
        raise SchemaValidationError("Foundry quota snapshot self-digest mismatch")
    if binding.get("resource_request_digest") != request_digest:
        raise SchemaValidationError("Foundry resource request digest binding mismatch")
    if binding.get("quota_snapshot_digest") != snapshot_digest:
        raise SchemaValidationError("Foundry quota snapshot digest binding mismatch")
    if quota_snapshot.get("exact_model") != payload.get("exact_model"):
        raise SchemaValidationError("Foundry quota snapshot model binding mismatch")
    if binding.get("plan_digest") != payload.get("plan_digest") or binding.get("assignment_digest") != payload.get("assignment_digest"):
        raise SchemaValidationError("Foundry packet plan/assignment binding mismatch")


def _validate_dispatch_workflow_report_contract(payload: dict[str, Any]) -> None:
    """Validate the stable read-only dispatch preflight envelope."""

    if payload.get("report_type") != "local-agent-dispatch.workflow":
        raise SchemaValidationError("dispatch_workflow_report requires report_type")
    for field, expected in (
        ("read_only", True),
        ("provider_execution", False),
        ("model_prompts_sent", False),
    ):
        if payload.get(field) is not expected:
            raise SchemaValidationError(
                f"dispatch_workflow_report requires {field}={str(expected).lower()}"
            )
    sequence = payload.get("sequence")
    if not isinstance(sequence, list) or len(sequence) < 5:
        raise SchemaValidationError("dispatch_workflow_report requires five ordered stages")
    stages = [row.get("stage") for row in sequence if isinstance(row, dict)]
    if stages[:5] != ["system_scan", "preflight", "task_estimate", "hardware_fit", "planner"]:
        raise SchemaValidationError("dispatch_workflow_report stage order is invalid")
    for field in ("hosts", "pools", "task_estimates", "multi_lane", "gates"):
        if not isinstance(payload.get(field), dict):
            raise SchemaValidationError(f"dispatch_workflow_report requires object field {field}")
    if not isinstance(payload.get("assignments"), list):
        raise SchemaValidationError("dispatch_workflow_report requires assignments list")


def _validate_task_capture_contract(payload: dict[str, Any]) -> None:
    """Validate the provider-free capture envelope before it feeds planning."""
    if payload.get("capture") != "bounded-task-capture":
        raise SchemaValidationError("task_capture requires capture=bounded-task-capture")
    for field, expected in (
        ("read_only", True),
        ("provider_prompts_sent", False),
        ("project_executed", False),
    ):
        if payload.get(field) is not expected:
            raise SchemaValidationError(
                f"task_capture requires {field}={str(expected).lower()}"
            )
    for field in ("task_id", "task_family"):
        if not isinstance(payload.get(field), str) or not payload[field]:
            raise SchemaValidationError(f"task_capture requires non-empty {field}")
    if not isinstance(payload.get("dag"), dict):
        raise SchemaValidationError("task_capture requires dag object")
    if not isinstance(payload.get("planner_jobs"), list):
        raise SchemaValidationError("task_capture requires planner_jobs list")
    if not isinstance(payload.get("estimate"), dict):
        raise SchemaValidationError("task_capture requires estimate object")
    if not isinstance(payload.get("unknown_semantics"), dict):
        raise SchemaValidationError("task_capture requires unknown_semantics object")


def _validate_reservation_contract(payload: dict[str, Any]) -> None:
    """Validate the SQLite migration-v3 reservation object (schema v1).

    ``schema_version`` here describes the serialized reservation object; it is
    deliberately independent from the SQLite migration number.  Fence values
    are ownership metadata, not credentials, so they are checked as positive
    integers while the recursive secret scanner remains active for all other
    token-like keys.
    """

    required = (
        "reservation_id", "job_id", "scope", "status", "owner_id",
        "fence_token", "created_at_utc", "updated_at_utc",
        "lease_expires_at_utc", "resource_request", "admission",
    )
    for field in required:
        if field not in payload:
            raise SchemaValidationError(f"reservation requires {field}")
    for field in (
        "reservation_id", "job_id", "scope", "status", "owner_id",
        "created_at_utc", "updated_at_utc", "lease_expires_at_utc",
    ):
        if not isinstance(payload.get(field), str) or not payload[field]:
            raise SchemaValidationError(f"reservation requires non-empty {field}")
    if payload.get("status") not in {"active", "released", "expired"}:
        raise SchemaValidationError("reservation status is invalid")
    fence = payload.get("fence_token")
    if isinstance(fence, bool) or not isinstance(fence, int) or fence < 1:
        raise SchemaValidationError("reservation fence_token must be a positive integer")
    for field in ("resource_request", "admission"):
        if not isinstance(payload.get(field), dict):
            raise SchemaValidationError(f"reservation {field} must be a dict")

def _check_secrets(payload: Any) -> None:
    """Recursively search for keys that look like secrets/credentials."""
    # Numeric workload-cost metrics contain the word ``token`` but are not
    # credentials.  Keep the default deny rule for arbitrary token-like keys,
    # while allowing this small, schema-owned metric vocabulary.
    safe_numeric_token_keys = {
        "tokens", "input_tokens", "output_tokens", "total_tokens",
        "estimated_input_tokens", "estimated_output_tokens",
        "fence_token", "reservation_token", "lease_token", "claim_fence",
    }
    if isinstance(payload, dict):
        for k, v in payload.items():
            k_lower = str(k).lower()
            token_metric = k_lower in safe_numeric_token_keys
            if (
                any(s in k_lower for s in ("secret", "token", "password", "api_key", "credential"))
                and not token_metric
            ):
                raise SchemaValidationError(f"Secret-like field detected in public snapshot: {k}")
            _check_secrets(v)
    elif isinstance(payload, list):
        for item in payload:
            _check_secrets(item)
