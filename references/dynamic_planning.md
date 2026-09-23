# Dynamic Planning and Feedback Loop

## Contents

1. Usage signals
2. Cost-aware planning
3. Rolling-horizon procedure
4. State and job schemas
5. Monitoring decisions

## Usage signals

Start with `lad scan`. Provider discovery is conditional on its
installed-CLI inventory, and compute planning must use its observed local
CPU/RAM/disk/GPU facts rather than a synthetic fallback host. This stage is
local-only and does not query authentication, catalogs, quota, or models.

```bash
lad scan --workspace "<trusted-workspace>"
```

Use `codex /usage` for a human-readable account token-activity view when the
installed release provides it. Treat lifetime/recent token activity as
historical usage, not remaining scheduling capacity.

For scheduling, collect the machine-readable account evidence as part of one
private preflight snapshot:

```bash
lad preflight --workspace "<trusted-workspace>" \
  --inventory "<private-hosts.json>" \
  --output "<private-preflight.json>"
```

The Codex portion reads `account/rateLimits/read` and `account/usage/read`
through Codex's local app-server without sending a model prompt. Treat
rate-limit windows as capacity and token activity as trend evidence only.

Map live rate-limit buckets by returned identity:

- `codex` -> `codex.luna` for the approved Luna/max lane.
- `codex_bengalfox` or a live limit name containing Spark -> `codex.spark`.
- Preserve unknown limit IDs as separate pools rather than guessing.

Refresh Cursor catalog/runtime evidence and Antigravity `/usage` using the
existing skill rules. Do not paid-probe a model merely to refresh health.

For OpenCode Go, use the OpenCode evidence in `lad preflight`. Treat all exact
`opencode-go/*` members as one `opencode.go` subscription pool. Its local
`stats` output is historical usage, not remaining allowance; keep five-hour,
weekly, monthly, and overage-fallback state unknown when the CLI returns no
machine-readable balance. Catalog/auth evidence creates a candidate, while the
first authorized task supplies runtime acceptance or exact rejection evidence.

The same preflight snapshot also
discovers server-local APIs and overlays exact runtime rejections on live
catalog visibility before the planner builds candidates.

## Cost-aware planning

Optimize useful work per quota unit, not remaining percentage alone:

```text
utility =
  priority_value
  + task_and_difficulty_fit
  + quality_value
  + latency_value
  + user_primary_model_bonus
  + estimated_work_per_quota_unit
  - failure_and_stall_penalties
  - reserve_violation_penalty
```

Estimate quota cost as:

```text
estimated_quota_percent =
  estimated_minutes
  * measured_quota_percent_per_minute
  * difficulty_multiplier
```

Prefer an explicit per-job/per-pool estimate when supplied. Otherwise use the
latest observed pool/model rate. Fall back to a prior only when no observation
exists.

Within a multi-model pool, an attributable exact-model rate takes precedence
over a pool-wide rate. Otherwise apply only a live advertised usage multiplier
to the pool prior. Preserve OpenCode's per-million-token catalog costs as price
metadata, but do not pretend they are a measured remaining-quota percentage.
When a task also contains explicit or measured `input_tokens` and
`output_tokens` P50 bounds, the planner emits `estimated_usd_cost` and
`cost_evidence=model_price_and_token_hints` on the assignment. Missing price or
token evidence remains `unknown`; it is never represented as zero cost.

Treat planner-default quota rates as versioned, low-confidence priors, not
provider prices or current account evidence. Keep site/user observations in
private state or configuration, including their sample duration, attribution,
and timestamp. A zero displayed delta creates only an upper bound when the
UI/API reports integer percentages; keep the prior when an observation is too
short or confounded to improve it.

Do not infer a model-specific rate when multiple or unknown external consumers
may use the same pool. Record that sample as pool-level/confounded. Update a
model rate only when the state or sole worker explicitly marks the observation
`exclusive_pool_observation=true`. Use an EWMA for positive deltas so one burst
does not dominate future plans.

## Rolling-horizon procedure

Use model-predictive control: plan a small horizon, execute only the first wave,
observe, then solve again from the new state.

1. Capture the request into a bounded TaskPacket.  This normalizes an explicit
   or conservative inferred DAG, records parallel waves, and optionally
   calibrates an exact task-family/model/host history bucket:

   ```bash
   lad capture \
     --task task.json --repo-root . --history observations.json \
     --model codex.spark --host remote-a > task-packet.json
   ```

   The capture boundary reads file metadata only; it does not execute a
   project command or send a provider prompt.  Missing observations remain
   `unknown`; invalid dependencies and cycles produce `dag_invalid`.
2. Run the local system scan, then build the dependency graph and bounded job records.
3. Refresh only installed providers plus runtime-health and compute-host signals.
4. Estimate resource requests/headroom and run the joint pool/host planner over
   the next 6-10 ready jobs.
5. Dispatch only the selected first wave with disjoint write scopes.
6. Monitor for 180 seconds by default, polling every 30 seconds.
7. Feed progress, artifacts, failures, quota deltas, and host pressure back into state.
8. Replan immediately on completion, failure, stall, quota change, model
   rejection, host/data-route pressure, or user scope change; otherwise replan
   after the monitor window.

Planning command:

```bash
lad plan --state planner-state.json --jobs jobs.json --max-lanes 4 --horizon 8 \
  > plan.json
```

For a SQLite-backed run, derive monitor input from the durable controller; do
not pass planner state directly to the monitor:

```bash
lad monitor-state --db dispatch.sqlite3 > monitor-state.json
lad monitor --state monitor-state.json \
  --duration-seconds 180 --interval-seconds 30 \
  --stall-seconds 120 > monitor-report.json
lad replan --monitor-report monitor-report.json --jobs jobs.json \
  --state planner-state.json --run-planner > replan.json
```

`monitor-state` is read-only and marks running attempts without explicit PID/log
breadcrumbs as `unknown`. The monitor report contains the observed worker state
needed by the replan step. The monitor does not kill or reroute processes
automatically; it emits `keep_and_monitor`,
`replan_unblocked_jobs`, `reroute_or_pause`, or `replan` for the supervising
agent to apply safely.

For a deliberate legacy/direct-worker run, use a separate worker-state file
that explicitly contains a nonempty `workers` list. Never reuse planner state
as monitor state merely because both are JSON objects.

For a launcher that exits after starting a durable service, monitor the service
PID file rather than the launcher PID. Set `pid_path` to the service PID file.
For an append-only log reused across retries, set `log_attempt_marker` to the
unique marker written at the beginning of the current attempt. Error
classification then ignores stale failures from earlier attempts.

## State and job schemas

Minimum pool state:

```json
{
  "pools": {
    "codex.luna": {
      "health": "balanced",
      "effective_remaining_percent": 28,
      "quota_rate_percent_per_minute": null,
      "quota_rate_evidence": "unknown",
      "reserve_percent": 20,
      "max_concurrency": 1,
      "inflight": 0,
      "recent_failures": []
    }
  },
  "workers": [],
  "completed_jobs": [],
  "failed_jobs": [],
  "monitor_seconds": 180,
  "poll_interval_seconds": 30
}
```

Minimum job record:

```json
{
  "job_id": "J1",
  "task_type": "audit",
  "difficulty": 4,
  "priority": "high",
  "latency_priority": "normal",
  "estimated_minutes": 40,
  "depends_on": [],
  "write_scope": "worker_J1/",
  "required_artifact": "worker_J1/status.md"
}
```

Optional job overrides include `allowed_pools`, `excluded_pools`,
`preferred_pools`, `avoid_providers`, `estimated_quota_cost`,
`quota_cost_by_pool`, `allow_reserve`, `allow_server_local`,
`allow_unreviewed_server_local`, and `high_stakes`. A server-local pool is bound
to the host that serves its model and is not eligible for high-stakes/audit work
unless explicitly allowed; medium/hard outputs require later provider review.
When a server-local agentic smoke publishes `max_difficulty` and
`requires_provider_review`, those calibrated values are hard scheduler gates;
catalog/API visibility alone never makes the pool ready.

An `opencode.go` pool also carries `catalog_models`, `role_model_candidates`,
`available_model_variants`, `rejected_models`,
`rejected_model_variants`, `model_usage_multipliers`, and
`overage_fallback_state`. These fields choose an exact model within one shared
capacity counter; they never create per-model quota.

## Monitoring decisions

- Growing logs or artifacts -> keep the worker and preserve its route.
- Completed required artifact plus exited process -> mark complete and unlock
  dependencies before replanning.
- No progress past the stall window -> inspect once, then reroute or pause.
- Explicit quota/rate failure -> cool the shared pool.
- Capability/model rejection -> reject only the exact model/variant tuple.
- Quota/auth/network failures -> update the shared pool; do not create a
  permanent exact-model rejection.
- Provider auth/network failure -> degrade the provider pool and prefer an
  independent healthy backend.
- Quota delta with one attributable model -> update that model's cost-rate EWMA.
- Quota delta with concurrent consumers -> update only pool-level cost evidence.
