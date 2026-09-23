# WP1 Ledger Contract (slice v2)

This document is the short normative contract for the first WP1 slice:
a provider-free, stdlib-only causal provenance ledger.

## Scope

- `schemas/provenance_event.schema.json` — normative JSON Schema (draft-07).
- `src/local_agent_dispatch/domain/events.py` — stable IDs, event factory,
  runtime validation.
- `src/local_agent_dispatch/ledger/store.py` — append-only causal store,
  idempotency, liveness reconciler.
- `src/local_agent_dispatch/ledger/projections.py` — redaction and public
  projections.
- `research/replay/import_legacy_runs.py` — legacy JSON importer.
- `research/replay/materialize_observations.py` — estimator observation gate.

## Invariants

1. **Stable IDs** (`stable_id(kind, *parts)`, deterministic UUID5): `mission`,
   `task`, `plan_revision`, `assignment`, `reservation`, `attempt`, `event`,
   `observation`, `artifact`, `human_decision`, `policy_version`.
2. **Every event carries** `schema_version=2`, `event_id`, `event_type`,
   RFC 3339 `timestamp`, `causal_parent` (or explicit `null`), `source`,
   `confidence` (0..1), `privacy_class`, `idempotency_key`. The default
   `event_id` is derived from the idempotency key, so retries are recognised.
3. **Attempt lifecycle events**: `attempt.queued`, `attempt.reserved`,
   `attempt.claimed`, `attempt.started`, `attempt.heartbeat`,
   `artifact.observed`, `attempt.validation`, `attempt.completed`,
   `attempt.failed`, `attempt.abandoned`, `attempt.review`.
4. **References only**: provider/pool/model/variant, CPS digest, source and
   worktree digests, execution/workload host, mount, route, validator are
   strings or `sha256:`/`sha512:` digests. Prompt bodies and credentials are
   refused by the store (`SecretLeakError`) and removed by public projections;
   `pid` is redacted from public projections.
5. **Idempotent duplicates**: same `event_id` + identical payload is a no-op;
   conflicting payload fails closed with `DuplicateConflictError`.
6. **Causal ordering**: an event whose `causal_parent` is not yet present is
   rejected (`OrphanEventError`); roots use explicit `null`.
7. **Legacy imports**: every imported record becomes one root
   `attempt.queued` event with `evidence_quality=legacy_incomplete`; only
   values present in the source are copied; model/quota/resource/terminal
   state are never invented; a legacy `status` survives only as
   `legacy_evidence.legacy_status`. Re-import is idempotent.
8. **Liveness reconciler**: stale attempts (no terminal event, older than the
   staleness horizon) are closed with `attempt.abandoned` when the pid is
   confirmed dead, or `attempt.review` when liveness cannot be confirmed.
   Original evidence is never mutated (`preserves_evidence=true`).  The
   metadata-only SQLite importer applies the same distinction to an imported
   legacy `running`/`retry` row when its caller supplies a liveness probe:
   confirmed `dead` becomes an abandoned child of the imported
   `attempt.queued`; `alive` or `unknown` becomes an escalated review child.
   A legacy `queued` row never receives an abandoned event because a queued
   status does not prove that a provider process was claimed.  Missing probe
   evidence remains `unknown` and does not create a synthetic reconciliation
   event.  No branch fabricates completion, validation, artifacts, or a
   successful execution.
9. **Projections are deterministic** and preserve missing values as the string
   `"unknown"`. They are not causal model-quality evidence: historical data is
   replay/closure evidence only.

## Attribution rule

Estimator observations are materialized only when an attempt is completed,
has an exact `model_id`/`provider`/`pool_id`, has at least one observed
artifact digest, is validated (passing `attempt.validation`), and is not
`legacy_incomplete`. Everything else is excluded with a listed reason.
