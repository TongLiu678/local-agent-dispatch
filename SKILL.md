---
name: local-agent-dispatch
description: "Plan or run evidence-gated work across multiple local agent CLIs and verified remote workers. Use when a request needs multi-provider routing, quota-aware scheduling, durable/background execution, or dispatch continuity; also use when the user explicitly asks this control plane to dispatch or review a bounded packet through a supported local provider CLI such as Cursor/Grok. Do not use for ordinary single-agent work performed directly, generic hardware questions, or standalone SSH/data-transfer tasks."
---

# Local Agent Dispatch

Use this skill as a thin control-plane entry point. It turns an explicitly
multi-agent, continuity-oriented, or local-provider-dispatch request into a
reviewable plan, then crosses separate authorization boundaries for live
discovery, enqueue, and execution.

Do not use it merely because a request mentions a model, GPU, quota, download,
or SSH host. Handle ordinary single-agent work directly.

## Choose a mode

| User intent | Mode | Provider prompt? | Mutates queue? |
| --- | --- | --- | --- |
| Check installation or local capacity | offline inspect | no | no |
| Capture work or plan from saved evidence | provider-free plan | no | no |
| Refresh catalogs, auth, quota, or SSH reachability | live discovery | no model prompt | no |
| Convert an approved plan to packets | bridge dry-run | no | no |
| Queue approved packets | enqueue | no | yes |
| Start workers | run | yes, through declared adapters | yes |

Default to the least powerful mode that answers the request. Live discovery,
enqueue, and run are distinct boundaries; permission for one does not imply the
next.

Prefer the installed `lad` command. In a source checkout where it is not
installed, use a Python 3.10+ interpreter and run from the repository root:

```bash
PYTHONPATH=src python -m local_agent_dispatch.cli
```

Do not assume that a platform's bare `python3` meets the package requirement.

## Core invariants

Preserve all of these rules:

1. **System first.** Inspect the local machine before selecting provider or
   remote probes. Missing optional CLIs disable only their own lanes.
2. **Evidence stays separate.** Catalog visibility, authentication, runtime
   acceptance, quota, host reachability, and artifact validation are different
   facts. Never infer one from another.
3. **Unknown fails closed.** Unknown quota or capacity is not zero or full.
   Use a bounded pilot only when the saved pool policy explicitly permits it.
4. **Pools are shared.** Models under one subscription pool share capacity.
   Switching sibling model IDs is not a quota workaround.
5. **Exact routes only.** Select only model IDs and variants returned by the
   current catalog/capability scan. Never manufacture a slug from a display
   name or dated documentation.
6. **Placement is two-dimensional.** `execution_host` is where the agent CLI
   runs; `workload_host` is where the workload runs. A local desktop-authenticated
   CLI may coordinate an approved SSH workload without moving its credentials.
7. **Planning is not execution.** A planner result is data. The bridge is dry-run
   by default. Enqueue and run require explicit commands and reviewed adapters.
8. **Every write is bounded.** Packets require one writer per write scope,
   confined paths, an expected artifact, a validator, and freshness checks.
9. **Gate the real filesystems before process launch.** Immediately before
   `Popen` of any local controller, worker, or validator, probe both the trusted
   workspace filesystem and the process's actual temporary filesystem. Unknown
   or sub-floor evidence fails closed before a lock, WAL file, or child process
   is created.
10. **A fallback must not become a second writer.** After an unclassified
    execution error or suspected partial write, first stop or fence the original
    writer and inspect and reconcile its declared write scope. Only then may an
    explicitly declared fallback acquire that scope.
11. **Leases are authoritative.** Transactionally durable SQLite execution uses
   atomic claims, WAL transactions, fencing, heartbeat evidence, and restart
   reconciliation. For continuity across a reboot or environment replacement,
   the database also needs a known-local, non-temporary storage receipt with
   `persistent=true`.
12. **A PID is not success.** Completion requires a fresh nonempty artifact and
    a passing validator. Preserve the exact failure class before rerouting.

## Scope and model policy

- Do not add standalone Claude Code/`claude` or standalone DeepSeek backends.
- Models exposed inside Cursor or Antigravity remain members of those providers'
  shared pools; their brand names do not create new backends.
- OpenCode Go DeepSeek members may remain visible for accounting but are
  excluded from dispatch unless the user explicitly approves an exact member
  for the current task.
- The default Codex policy permits only the release's approved exact routes.
  A user may explicitly select another supported task-local route; never silently
  substitute a different model or effort.
- An explicit user model choice overrides default ranking but not capability,
  quota, path, resource, or validation gates.

Read [provider routing](references/provider_routing.md) when selecting a
provider, interpreting a provider failure, or configuring an adapter. Do not
load it for offline inspection alone.

## Workflow

### 1. Establish the boundary

Confirm the trusted workspace, requested outputs, allowed write scopes,
dependencies, and whether the user asked only for a plan or for execution.
Separate independent jobs from serial dependencies. Never let two workers own
the same write scope.

For natural-language work, capture a provider-free task packet:

```bash
lad capture --task "<task-or-task.json>" --repo-root "<trusted-workspace>"
```

The capture path reads bounded metadata, not arbitrary repository contents,
and does not contact a provider.

### 2. Inspect locally

Run safe offline checks first:

```bash
lad doctor --offline
lad scan --workspace "<trusted-workspace>"
```

Local process discovery may identify agent/model processes only by normalized
canonical name, process kind, and PID; bounded numeric RSS counters may support
capacity checks. It must never persist any process `argv` or command line, even
when the arguments appear harmless. Do not store private runtime state in the
repository: this includes host inventories and addresses, SSH or model
endpoints, provider/account/auth/quota snapshots, prompts and task packets,
adapter registries, queue databases and WAL/lock/lease files, PID metadata,
controller/worker/validator logs, attempt receipts, local paths, results, and
artifacts. Runtime state belongs under the configured
`LOCAL_AGENT_DISPATCH_HOME`; private host inventories stay outside source.

If capacity, downloads, data locality, accelerators, or a remote workload
matters, read [compute routing](references/compute_routing.md). That reference
owns server-first thresholds, host probing, storage placement, and data-route
rules; do not duplicate them here.

### 3. Build evidence

Use saved evidence for an offline plan. Refresh live provider/SSH evidence only
when the user asked for current routing or execution readiness:

```bash
lad preflight \
  --workspace "<trusted-workspace>" \
  --inventory "<private-hosts.json>" \
  --output "<private-preflight.json>"
```

Preflight may read configured auth stores and contact read-only catalog, quota,
or host endpoints. It sends no model prompt. Keep each probe's failure local to
its provider or host; one missing integration must not invalidate good evidence
from another.

For a locked macOS keychain or another Cursor authentication-context failure,
follow [provider routing](references/provider_routing.md); never unlock or copy
credentials on the user's behalf or infer readiness from a cached catalog.

### 4. Plan one wave

Create jobs with explicit resource estimates, allowed pools, dependencies,
write scopes, required artifacts, and validators. Then plan only the next
bounded horizon:

```bash
lad dispatch \
  --workspace "<trusted-workspace>" \
  --jobs "<jobs.json>" \
  --preflight "<private-preflight.json>" \
  --output "<dispatch-plan.json>"
```

Or use the deterministic planner directly:

```bash
lad plan --state "<planner-state.json>" --jobs "<jobs.json>" \
  --max-lanes 2 --horizon 2
```

Read [dynamic planning](references/dynamic_planning.md) when scoring several
pools, estimating quota cost, calibrating history, or running a rolling-horizon
loop. Keep explicit user choices exact; otherwise favor task fit, current
evidence, independent-provider diversity, and measured cost rather than a
static model list.

### 5. Review the execution boundary

Convert the plan without enqueueing it:

```bash
lad bridge \
  --plan "<dispatch-plan.json>" \
  --jobs "<jobs.json>" \
  --state "<private-preflight.json>" \
  --adapters "<adapter-registry.json>"
```

Review exact model/variant, execution and workload hosts, adapter, prompt and
result paths, write scope, validation command, required artifact, and fallback
attempts. Reject path traversal, missing adapters, unverified remote wrappers,
and any attempt that broadens the user's requested scope.

### 6. Enqueue and run only when requested

Enqueue changes durable state but does not call a provider:

```bash
lad bridge \
  --plan "<dispatch-plan.json>" \
  --jobs "<jobs.json>" \
  --state "<private-preflight.json>" \
  --adapters "<adapter-registry.json>" \
  --enqueue --db "<dispatch.sqlite3>"
```

Starting the controller is the provider-execution boundary:

```bash
lad run --backend sqlite --db "<dispatch.sqlite3>" \
  --workspace "<trusted-workspace>" --max-lanes 2 --detach
```

Use JSON mode only to continue an existing legacy JSON run deliberately. For a
queue that must survive the chat, read
[quota continuity](references/quota_continuity.md) before launch. A detached
controller may continue already-authorized packets; it cannot infer new user
intent.

### 7. Observe, validate, and replan

```bash
lad status --backend sqlite --db "<dispatch.sqlite3>"
lad monitor-state --db "<dispatch.sqlite3>" > "<monitor-state.json>"
lad monitor --state "<monitor-state.json>" --duration-seconds 180 \
  > "<monitor-report.json>"
lad replan --monitor-report "<monitor-report.json>" \
  --jobs "<jobs.json>" --state "<planner-state.json>" --run-planner
```

By default monitoring is read-only; provider quota refresh and SSH refresh are
separate opt-ins. Replan after completion, failure, quota reset, material host
change, or a new user request. Validate artifacts before calling work complete.

Classify failures precisely:

- capability rejection: reject the exact model/variant;
- explicit quota/rate failure: cool down the shared pool;
- authentication or network failure: block the affected provider route;
- resource/path failure: move only to a predeclared compatible attempt;
- missing/stale artifact or failed validator: mark the attempt failed, even if
  the process exited successfully.

## Report status

```text
active: <workers, exact models, execution/workload hosts>
pools: <ready/degraded/cooldown/blocked/unknown with evidence age>
progress: <done/pending/failed and latest validated artifact>
decision: keep / reroute / drain / pause / escalate
next: <next authorized scheduler action>
```

Do not report `unknown` as ready, and do not claim success from catalog
visibility, an accepted enqueue, or a live PID.

## Verify changes

From the repository root, run the provider-free checks used by CI:

```bash
PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s tests -p 'test_*.py'
python -m compileall -q src scripts
for script in scripts/*.sh; do bash -n "$script"; done
PYTHONPATH=src python -m local_agent_dispatch.cli --version
PYTHONPATH=src python -m local_agent_dispatch.cli doctor --offline
PYTHONPATH=src python -m local_agent_dispatch.cli demo --offline
```

Also run the skill validator available in the current Codex installation. Paid
or networked smoke tests require explicit authorization and never belong in the
provider-free suite.
