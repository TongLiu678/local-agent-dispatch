# Architecture

`local-agent-dispatch` is a local control plane with explicit provider and
compute boundaries. The packaged `lad` command is intentionally thin; the
provider-free path can be run on a machine with no credentials or network.

Development and promotion are deliberately separate:

- `offline_implementation` builds and verifies contracts, schemas, transaction
  logic, fake adapters, and deterministic replay without claiming that a live
  host or provider is ready.
- `live_promotion` binds one exact environment fingerprint, scheduler/sandbox,
  ProjectCapsule generation, writable mount, route, quota/auth state, and
  canary/soak receipt before execution capability is promoted.

The two version domains are also separate:

```text
sqlite_database_schema = 7
resource_packet_schema = 3
```

Neither offline fixtures nor a resource packet format version can substitute
for current live admission evidence.

```text
system/provider/compute discovery
              |
              v
versioned evidence + task/resource estimate
              |
              v
policy gates -> rolling-horizon planner
              |
              v
plan packet bridge (dry-run, exact model/variant)
              |
              v
auto backend (SQLite WAL for new queues; JSON migration path for existing
             state.json runs) or explicit JSON controller
              |
              v
provider/runtime adapter -> validator -> artifact manifest
              |
              v
review -> ClaimContract promotion -> monitor -> reviewable replan constraints
              -> next planning wave
```

Discovery is an explicit subsystem, not a collection of provider-specific
guesses. The Evidence Discovery and Compatibility Resolver searches official
documentation/source and local versioned capabilities first, ranks evidence,
then performs only bounded, authorized probes. It records catalog, auth, quota,
runtime, transport, resource, and policy evidence separately with source,
version, TTL, confidence, and discrepancy fields. A catalog hit never implies
that a request is accepted or that a numeric balance is available. See
`docs/research/evidence-discovery-subsystem.md`.

The planner has two placement fields: `execution_host` is where an
authenticated desktop CLI or server adapter runs, while `workload_host` is
where data/compute is consumed. A split placement requires an explicit
workload wrapper and telemetry; otherwise the bridge or monitor fails closed.

Provider pools represent shared quota, not individual model IDs. Model
catalog visibility, authentication, runtime acceptance, and numeric quota are
separate evidence fields. Unknown quota is blocked unless a preflight policy
explicitly grants a bounded pilot.

The provenance ledger distinguishes execution completion, validation, review,
and claim promotion. `claim.promoted` is not a cosmetic label: the append
boundary requires a passing validation, an approved review, and the review as
the causal parent. This keeps a successful process exit from being mistaken
for a publishable or scientific claim.

## Plugin boundary

`src/local_agent_dispatch/plugins/` is the package-level Phase 2 seam. It
defines five explicit stdlib-only protocols—`SystemProbe`, `ProviderAdapter`,
`RuntimeAdapter`, `TransportAdapter`, and `Validator`—plus typed request/result
objects, an API-versioned descriptor, and an explicit `PluginRegistry`.
Registration and conformance are metadata-only: no provider prompt, network
connection, SSH session, subprocess, or model runtime starts merely because a
plugin is present. Provider discovery is split into catalog, auth, quota, and
runtime evidence so one failed probe cannot fabricate another status. A
controller may invoke a registered operation only after its normal lease,
policy, path, and quota gates; a crashing plugin is isolated to an invocation
failure result. Existing standalone scripts remain compatible while their
provider/host calls are migrated behind this seam in a later Phase 2 step.

The `auto` backend is SQLite-first for new queues. It provides WAL
transactions, lease fencing, atomic claim/complete, idempotent events, and
stale-job recovery. Transient retryable failures are persisted with a
`retry_at_utc` gate and bounded exponential backoff, so a durable worker does
not hot-loop against a rate-limited provider or unhealthy host. An explicit,
approved replan may still fencedly requeue a terminal job immediately. If a
supplied run directory already contains
`state.json` (and no SQLite database), `auto` preserves that JSON controller
for migration; `--backend json` remains an explicit escape hatch for older
prepared runs.

The SQLite Controller opens its WAL database only after the local-storage
admission gate resolves the host mount.  Known shared filesystems and unknown
Linux mount locality are blocked before schema creation, lock creation, or
child launch.  Large workload data can still live on a verified server data
mount; the Controller database stays on a known-local path.

For resource-bearing packets, the controller uses a single-store
`reserve_and_claim_job` transaction: capacity/admission is checked, the
reservation is inserted, and the job/attempt claim plus lifecycle events are
committed together. A rejected lane therefore leaves no half-created promise;
the legacy reservation-only API remains available to migration diagnostics.

When the live inventory exposes Torque/PBS, `scripts/pbs_worker_wrapper.py`
provides a deliberately provider-free persistence seam. `submit` sends only a
fixed `run` invocation without inheriting the caller environment; `run` invokes
the existing `remote_worker.py fake-service` contract and atomically records
PBS/job/host/status plus SHA-256 artifact rows. The completed canary is evidence
for scheduler reachability, lease recovery, and receipt durability only; it is
not OpenCode, Antigravity, Cursor, quota, network, or real-provider evidence.

`scripts/pbs_controller_bridge.py` joins that seam to the SQLite transport
outbox. It accepts only an already accepted `execute.prepared` envelope, uses a
deterministic per-job run root, records the PBS job/submission digest under the
controller fence, and later promotes only a validated `completed`/`failed`
worker receipt. Replaying submit or reconcile is idempotent; a disconnected
controller leaves the accepted row durable for the next poll. The bridge is
still provider-free and does not make a PBS receipt evidence of model,
OpenCode, quota, or network availability.
