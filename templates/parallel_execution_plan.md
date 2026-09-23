# Dynamic Local-Agent Execution Plan

Use this template before dispatching two or more workers from Codex CLI,
Cursor Agent, or Antigravity. It records shared quota pools so changing model
names cannot accidentally bypass pool-level backpressure.

```markdown
# Execution Plan: <task/project>

## Metadata

- project_root:
- run_id:
- created:
- execution_mode: serial | parallel-shards | parallel-council | pipeline | monitor-only
- max_total_lanes:
- quota_notes:
- compute_policy: filter-score-reserve-reconcile
- data_route_notes:

## Pool State

| Pool | Health | Weekly | Five hour | Effective remaining | Quota %/min | Reserve | Inflight | Recent failure | Last checked |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| codex.luna |  |  |  |  | measured/estimated | 20% default |  |  |  |
| codex.spark |  |  |  |  | measured/estimated | 10% default |  |  |  |
| cursor.composer_grok |  |  |  | shared pool | measured/unknown | 10% default |  |  |  |
| cursor.other |  |  |  | shared pool | measured/unknown | 10% default |  |  |  |
| antigravity.gemini |  |  |  | min(weekly, five-hour) | measured/estimated | 15% default |  |  |  |
| antigravity.claude_gpt |  |  |  | min(weekly, five-hour) | measured/estimated | 20% default |  |  |  |

## Preflight Evidence

| Check | State | Evidence |
| --- | --- | --- |
| real project root and write scopes |  |  |
| Codex live model/effort pairs |  | models_cache.json + preflight helper |
| Codex rate-limit buckets |  | codex_usage_snapshot.py; Luna and Spark separate |
| Codex token activity |  | historical trend only; not remaining quota |
| Cursor auth/subscription |  | status/about |
| Cursor candidate catalog |  | cursor-agent --list-models; visibility only |
| Cursor runtime eligibility |  | latest real request outcome; do not paid-probe |
| Antigravity model quota |  | interactive /usage helper |
| Antigravity canonical models |  | antigravity models |
| compute hosts |  | compute_resource_probe.py; live facts only |
| server-local runtimes/models |  | server_local_model_scan.py; loopback APIs only |
| continuity controller |  | durable PID/run dir/state/events/logs, or not armed |
| server-first and bulk route |  | size/runtime/GPU gate; remote-origin transfers |

## Compute Host State

| Host | Reachable | CPU idle/total | RAM available/total | GPU/free VRAM/util | Disk free | Runtime/path | Paid/stop path | Last checked |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| local_mac |  |  |  |  |  |  | no |  |
| direct_remote |  |  |  |  |  |  |  |  |

## Cursor Model Eligibility

| Exact model | Pool | Catalog state | Runtime state | Runtime reason | Last runtime success | Last checked |
| --- | --- | --- | --- | --- | --- | --- |
|  |  | visible / absent / unknown | accepted / rejected / unknown |  |  |  |

Catalog visibility is candidate-discovery evidence, not proof of execution.
The request endpoint wins for runtime eligibility. Carry the newest same-day
runtime rejection into continuations; refreshing the catalog does not clear it.

## Dependency Graph

```text
J0 preflight
J1 plan -> J2a shard A
        -> J2b shard B
J2a,J2b -> J3 audit
J3 -> J4 merge/final
```

## Jobs and Resource Requests

| job_id | pool/model | execution host | agent/compute min | CPU/RAM | GPU/VRAM | data+env/temp/cache/output GiB | data route | depends_on | output/stop |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| J0 | local checks | local_mac |  |  |  |  | none |  | state.json / preflight complete |
| J1 | planner | planner |  |  |  |  | planner | J0 | task_packet.md / plan accepted |
| J2 | selected | selected |  |  |  |  | direct remote if bulk | J1 | artifact / complete |

## Candidate Registry

| Pool | Typical models | Role | Selection note |
| --- | --- | --- | --- |
| codex.luna | gpt-5.6-luna/max | primary general, hard reasoning, audit | low-cost prior; calibrate from usage deltas |
| codex.spark | gpt-5.3-codex-spark | primary tiny bounded code loop |  |
| cursor.composer_grok | composer-2.5*, cursor-grok-4.5* | throughput and alternate reasoning; shared capacity |  |
| cursor.other | GPT/Codex/Gemini/Claude/Kimi/GLM IDs from live list | task-fit alternate; shared capacity |  |
| antigravity.gemini | Gemini Flash / Gemini Pro exact live slugs | throughput / hard independent critique; shared capacity |  |
| antigravity.claude_gpt | Claude Opus / Claude Sonnet / GPT-OSS exact live slugs | premium audit / strong routine / diversity; shared capacity |  |
| server_local.<host> | exact loaded model from live `/v1/models` or Ollama tags | quota-independent queued work; host-affine | requires later review by difficulty |

## Quota-Continuity State

| Field | Value |
| --- | --- |
| durable run directory |  |
| controller PID/log |  |
| task packet directory |  |
| fallback chain | local provider CLI -> server tool-capable agent |
| state/events | `state.json` / `events.jsonl` |
| resume artifact | `resume.json` |
| server-local readiness | runtime + loaded model + agentic smoke validation |

## Dynamic Re-score Events

- a job completes or fails;
- a shared pool reports a rate/quota error;
- measured quota cost changes after a monitor window;
- `/usage` or another quota signal changes;
- a process stalls or produces no required artifact;
- task scope or latency priority changes.
- a host becomes unreachable or CPU/RAM/disk/GPU capacity changes;
- an OOM, VRAM pressure, bulk-route, environment, or billing gate changes.

Plan only the first rolling-horizon wave. Monitor it for 180 seconds by default
at 30-second intervals, feed progress and quota deltas back into state, then run
the planner again. A lower remaining percentage does not automatically lose to
a larger pool when the selected model delivers more useful work per quota unit.

When one member of a Cursor or Antigravity pool reports explicit quota pressure,
cool down that entire shared pool. Do not switch to another member of the same
pool as a quota workaround. A capability error such as `Cannot use this model`
rejects only the exact model and does not prove shared-pool exhaustion. For
Antigravity, use the lower of weekly and five-hour available percentages as the
effective scheduling budget.

## Merge and Audit Rules

- No two workers edit the same durable file.
- Each worker writes to a unique scoped output path.
- A launched process is not proof of completion.
- Every background worker needs visible logs or heartbeat plus a required artifact.
- Unsupported claims are removed or marked as gaps.
- Conflicts are resolved from evidence, not model confidence.

## State Update

```json
{
  "run_id": "",
  "execution_mode": "",
  "planning": {"method": "filter_score_reserve_reconcile", "horizon": 8, "max_lanes": 4},
  "monitor": {"duration_seconds": 180, "interval_seconds": 30, "stall_seconds": 120},
  "pools": {},
  "compute_hosts": {},
  "model_state": {},
  "workers": [],
  "completed_jobs": [],
  "failed_jobs": [],
  "last_rescore_reason": "",
  "next_action": ""
}
```
```
