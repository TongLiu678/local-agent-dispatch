# Dispatch Schema Contract

This document outlines the schema validation strategy for durable objects in local-agent-dispatch (`task_packet`, `dispatch_plan`, `runtime_state`, `reservation`, and two explicitly different event envelopes).

`schemas/event.schema.json` is the legacy dispatch envelope used by the
lightweight `scripts/dispatch_schema.py` validator and remains at
`schema_version=1` for compatibility. The normative causal ledger is
`schemas/provenance_event.schema.json`; it is EventV2 and uses
`schema_version=2`, with runtime validation in
`src/local_agent_dispatch/domain/events.py`. A v1 dispatch event must not be
treated as an EventV2 ledger event, and an EventV2 record must not be downgraded
to v1 merely to satisfy the legacy validator.

## Versioning and Unknown Values

All durable objects MUST contain a `schema_version` integer. Dispatch envelopes
currently use version 1; the causal ledger uses version 2 as stated above.
Modern
planner packets additionally require `packet_id`, `job_id`, `write_scope`,
`validation_required=true`, non-empty `required_artifacts`, and a non-empty
`attempts` list with exact `attempt_id`/`adapter`/`transport`/`model` fields.
Unknown extension fields remain allowed, but malformed known fields fail closed.
Older hand-written queues may be read only when the packet explicitly sets
`legacy_compatibility=true`; the controller records that evidence level rather
than silently upgrading it to a modern packet.

Resource reservations use object `schema_version=1` and are validated by the
lightweight `reservation` contract in `scripts/dispatch_schema.py`. This object
version is independent of the SQLite migration number (currently migration 3
for the reservation table). A reservation requires a positive `fence_token`,
an explicit lifecycle status, numeric resource-request metadata, and an
admission object. Fence values are ownership metadata, not credentials; all
other secret-like keys remain rejected.

Model-policy exceptions are task-scoped extension fields. For example,
`allow_policy_excluded_models` may name one exact model that the user has
explicitly authorized, together with `model_by_pool`; the planner still checks
that the model is visible in the current catalog and charges the existing
shared pool. An exception never changes quota accounting or bypasses
validation, write-scope, or host gates.

## Evidence Fields

Evidence fields are explicitly captured and structured (e.g. `pools` inside a `runtime_state`, or nested `attempt` maps) because the dispatch planner relies on their shapes to match capabilities against requirements. By explicitly validating that these fields are valid dictionaries if present, we protect the planner from type errors without demanding a rigid schema for the rest of the payload.

Secret-like fields (such as `token`, `password`, `api_key`) are globally banned
in public snapshots and task packets. The focused validator scans keys across
the entire structure to prevent accidental credential leakage in telemetry,
queue state, or open snapshots.

## Future Migrations

When migrating to a new schema version (e.g. `schema_version = 2`):

1. **Bump Version:** The objects written by the prototype will emit `schema_version: 2`.
2. **Backwards Compatibility:** The schema validator `scripts/dispatch_schema.py` should be updated to accept `schema_version: 1` and `2`. It must apply structural rules depending on the version. 
3. **Rollout Strategy:** Update consumers (planner/controller) to handle version 1 and 2 gracefully, or transparently upgrade version 1 objects to version 2 in memory before applying logic.
4. **Deprecation:** Once no version 1 objects exist in the system (e.g. active jobs complete), the support for version 1 can be phased out.
