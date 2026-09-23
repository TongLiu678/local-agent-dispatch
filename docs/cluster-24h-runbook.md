# Cluster 24-hour runbook (provider-free first)

This runbook describes the safe path for a long run.  A 24-hour window is a
sequence of bounded scheduler segments, not one unkillable process.  Every
segment has a manifest/capsule binding, a durable submission intent, a
checkpoint boundary, a terminal receipt, and a controller fence.

## Placement contract

- Keep the controller SQLite WAL on a controller-local filesystem.  Never put
  it on `/data`, NFS, or another shared mount.
- Keep source, datasets, models, caches, logs, and bulk artifacts on the
  project-owned server paths under `/srv/<project>/lt_work` and
  `/data/<project>/lt_work` after live capacity and writeability checks.
- Use a node-local `TMPDIR` for PBS scratch.  Do not use the Mac as a data or
  model relay, and do not reverse-forward the Mac proxy to a server route.
- For PBS, bind that scratch explicitly as `pbs.tmp_root` in the inventory;
  the wrapper creates a job-specific child on the execution node while keeping
  receipts and the controller database on durable paths.  A durable `/data`
  run root must not silently become the scratch directory.
- Pin the worker interpreter in the live inventory (`worker_python` or
  `pbs.python`) when a legacy compute node has no `python3` on `PATH`.  Never
  copy a desktop `.venv` into the server project: an absolute macOS symlink
  can look present while being unusable on Linux.  The preflight must record
  `runtime_python` evidence for the selected interpreter before claim.
- Treat wall-clock timestamps as source-attributed evidence.  When the
  controller, Torque server, and execution node are not clock-synchronized,
  enforce the run horizon with the controller's monotonic deadline plus PBS
  `walltime`; do not use a cross-node `planned_end_at` as the sole safety
  cutoff.  Record the observed clock sources and any skew in the receipt.
- A desktop-authenticated provider CLI remains on the host where it is
  authenticated.  A server workload is a separate placement decision.

## Start sequence

1. Re-probe the exact host, PBS queue/walltime, home/data capacity, Python
   runtime, node-local temporary space, and the current route evidence.
2. Freeze the approved Mission/TaskGraph/CPS and write a
   `continuous-run.json` plus a project Capsule.  Unknown quota, mount,
   route, or process identity is `blocked`, not a guessed default.
3. Open the controller-local SQLite database and acquire its lease.  Begin one
   segment with the manifest and Capsule digests.
4. Persist the PBS submission intent before calling `qsub`.  If the response
   is lost, reconcile that intent/status; never submit the same segment again
   merely because the caller timed out.
5. Start with provider-free execution.  Only after replay and soak gates pass
   may a single exact pool/model/host bounded canary be approved.

## Segment tick

Each monitor tick performs the following in order:

`lease heartbeat → PBS/outbox reconcile → Governor admission → claim only
approved work → worker heartbeat → bounded event/receipt write`.

When the segment reaches its rollover guard, the supervisor stops new claims,
flushes checkpoints, finishes the old segment, and then opens the next one.
At the planned end it writes the final checkpoint/receipt and does not create
an unfinishable segment.

## Recovery rules

- `submission.intent.json` with no terminal receipt means `reconcile before
  retry`; it is not permission to issue another `qsub`.
- An expired lease is not proof that a remote process died.  Unknown remote
  liveness remains `blocked` until a stronger receipt or human decision exists.
- A partial checkpoint, stale fence, missing artifact hash, quota failure,
  mount loss, or memory/disk emergency stops new admission and preserves the
  event ledger.  Automatic kill is not enabled without a complete owned
  `(pid, start_time, process_group, run_id, fence)` identity.
- Before reclaiming an expired remote lease, the adapter must submit a fresh
  `process-identity` witness bound to that lease.  `recover`/`resume` in strict
  mode accepts only `exited` or `not_found`; otherwise it records
  `recovery_review` and waits for an operator decision.  Lease expiry alone is
  never treated as proof that a process died.
- When the chat/control plane disappears, the server may continue only the
  already compiled, approved, and persisted envelopes.  It must not infer a
  new task from a log or a model response.

## Central transport recovery gate

The central PBS cluster and its control path are separate pieces of evidence.
A successful provider-free run proves only that the cluster was reachable at
that observation time; it does not keep the SSH route alive.  Record each
transport layer independently:

1. the configured direct SSH endpoint;
2. the configured Tailscale, jump-host, or reverse-tunnel endpoint;
3. any server-local RackNerd egress (public internet only, never a presumed
   private-cluster route); and
4. the scheduler and node liveness observed after SSH is established.

The central route is 'blocked' until one configured path returns an SSH banner,
the expected host identity, a current clock/capacity snapshot, and a writable
project path.  A TCP CONNECT accepted by a proxy without an SSH banner is
not a usable route.  A Tailscale daemon being alive locally is not evidence
that the center peer or its backend is online.  If a path has previously
passed and later fails, retain both observations as a transport-flap record
and apply the shorter evidence TTL; do not promote the old success.

While this gate is blocked, the controller may continue already approved work
on a verified alternate host and may write a pending handoff/receipt to the
shared control store.  It must not submit or resubmit central scheduler jobs,
reclaim old leases, or infer central PBS state from stale PID/status files.
After transport recovery, reconcile existing submission intents and leases
before creating any new segment.  Keep private endpoint values in the
inventory and receipts, not in this runbook.

### Route classification when a tailnet peer forwards the cluster port

An SSH banner obtained through a Tailscale peer is not automatically a
server-to-server route.  If the verified peer is a desktop/macOS host that
forwards the cluster TCP port, record `mac_peer_in_path=true`,
`server_to_server_direct=false`, and `bulk_transfer_allowed=false`.  Such a
path is valid for bounded control-plane probes and receipt reconciliation
only.  Dataset, model, checkpoint, and archive bytes must use a verified
server-side object-store/direct-server route, with the route identity and
byte/hash receipt recorded separately.  A watcher must expose this
classification rather than reporting a generic `route_ready` state.

## Evidence gates

The minimum promotion chain is:

`deterministic replay → virtual fault matrix → server provider-free soak →
single-pool bounded canary → 2h → 8h → three independent 24h windows`.

Provider-free evidence proves continuity of the tested controller/worker
path; it does not prove model quality, scientific validity, quota remaining, or
production readiness.  Each window records accepted-task loss, duplicate
irreversible effects, unowned process signals, OOM/ENOSPC, recovery time,
resource P90 coverage, receipts, and the exact host/Capsule/manifest digests.

## Safe command shape

Use an explicit compatible interpreter and a durable scheduler script on the
server.  The exact paths must come from the current preflight; this example is
illustrative and intentionally has no provider command.  If the source tree
contains a copied or broken `.venv`, ignore it and use the inventory-bound
interpreter instead:

```text
/srv/<project>/.../python3.11 scripts/durable_controller.py start \
  --manifest /data/<project>/lt_work/runs/<run>/continuous-run.json \
  --capsule /data/<project>/lt_work/runs/<run>/project-capsule.json \
  --run-root /data/<project>/lt_work/runs/<run>
```

The packaged CLI is a dry-run boundary until a reviewed SQLite/PBS adapter is
injected.  Do not treat a PID, an old smoke log, a catalog entry, or a model
history chart as a successful 24-hour receipt.

## Reviewed long-lived runner (after remote sync)

`scripts/durable_run_loop.py` is the reviewed control-plane loop.  It keeps
the SQLite lease heartbeat outside the supervisor, restores active segments
from SQLite, appends one fsync'd monitor record per tick, and turns repeated
errors or an unflushable checkpoint into an explicit `blocked` result.  It
does not create new tasks or start a provider.  The command remains dry-run
unless `--execute` is explicitly approved:

```text
<python3.11> scripts/durable_run_loop.py \
  --db <controller-local>/dispatch.sqlite3 \
  --manifest <run-root>/continuous-run.json \
  --capsule <run-root>/project-capsule.json \
  --inventory <private-inventory> \
  --run-root <run-root> \
  --poll-seconds 30 \
  --max-runtime-seconds 86400 \
  --max-record-bytes 131072
```

Before using `--execute`, the cluster preflight must provide a current PBS
queue/walltime, writable run path, worker Python, host identity, payload
digest, and route evidence.  A successful 24-hour virtual replay or a
provider-free runner does not promote provider/model quality claims.

For a provider-free closed-loop replay, saved quota observations can be passed
to the wave boundary.  The watcher is evaluated before the read-only next
plan; a blocked pool is excluded without rotating to another model in that
pool, and a future reset is only a bounded wake hint:

```text
<python3.11> scripts/dispatch_closed_loop.py \
  --approved-packets <run-root>/planner/approved.json \
  --mode fake-execute --db <controller-local>/dispatch.sqlite3 \
  --workspace <run-root>/workspace \
  --jobs <run-root>/planner/jobs.json --state <run-root>/planner/state.json \
  --quota-snapshot <run-root>/quota/codex.json \
  --quota-snapshot <run-root>/quota/antigravity.json \
  --quota-now-utc <observed-time> \
  --output <run-root>/monitor/closed-loop.json
```

This command remains provider-free: it does not refresh a provider, enqueue a
new packet, or contact SSH.  A real runner must still keep lease heartbeats,
resource admission, and mount/route checks active while using the resulting
`quota_replan_schedule`.

The monitor JSONL is deliberately bounded per record.  If a reconciliation
report is larger than `--max-record-bytes`, the runner writes only stable
identity, a compact status projection, and a digest; full receipts remain in
the controller-local SQLite database.  This prevents a long run from turning
verbose transport state into an unbounded disk-growth failure.

Each monitor record also distinguishes the two time bases: the runner's
`loop_elapsed_seconds`/`loop_remaining_seconds` use its monotonic budget, while
the supervisor's legacy `remaining_seconds` is mirrored as
`segment_remaining_seconds` and describes only the current bounded segment.
This prevents a segment rollover from being mistaken for completion of the
whole 8/24-hour loop, especially when an execution node's wall clock is skewed.

## Server-side Git integration

Workers must write only in their project capsule's isolated worktree and
produce a candidate commit.  The server project branch has one writer:
`scripts/server_git_integrator.py`.  Its proposal spool and OS lock live
outside the Git worktree, and a proposal stores only project identity, commit
IDs, SHA-256 bindings, and receipt digests.  Prompts, argv, credentials,
environment variables, and raw private paths are never copied into the
proposal.

The transition is deliberately split:

1. `propose(...)` verifies the bound capsule, passing validation receipt,
   passing public scrub receipt, candidate/base ancestry, and an unchanged
   target head.  It does not alter the checkout.
2. `apply_local(proposal_id)` requires an explicit review decision of
   `approved`, a clean target worktree, the same base commit, and a
   fast-forward candidate.  Repeating the call after success is idempotent.
3. `push(proposal_id, approved=True)` is a separate human approval boundary;
   `approved=False` is report-only and never contacts the remote.

If the target branch moves, the worktree is dirty, a receipt is incomplete, or
the candidate is not descended from the recorded base, the integrator fails
closed.  It never force-resets, copies Mac credentials, pushes, merges, tags,
or releases implicitly.

## Reviewed remote model canary

After the provider-free server soak, create a fresh placement contract and a
short-lived authorization receipt on the server.  The reviewed adapter is
`scripts/remote_cli_execution.py`; it accepts the exact Spark route
`codex.spark/gpt-5.3-codex-spark/xhigh` or the exact Antigravity route
`antigravity.gemini/gemini-3.6-flash-high`.  A catalog entry, old usage chart,
or a successful dry-run is not execution evidence.

The default command is planning-only:

```text
<python3.11> scripts/remote_cli_execution.py \
  --contract <run-root>/placement/remote-cli-contract.json \
  --prompt-file <remote-workspace>/TASK.md \
  --result-source <remote-workspace>/src/canary-result.txt
```

Only after the user-approved bounded canary packet contains current quota,
capacity, authentication and RackNerd route receipts may the server invoke
the same command with `--authorization <run-root>/placement/authorization.json
--execute`.  The adapter keeps prompts out of argv, refuses stale route/auth
evidence and existing results, and writes a terminal receipt below
`remote_workspace/.lad/receipts`.  It does not fall back to another model or
reuse a stale authorization record.

## Replan wake hints

After a monitor report and a read-only planner result are available, run the
replan controller with the original plan.  Its `replan_schedule` field is the
only supported wake hint for a quota-reset wait:

```text
<python3.11> scripts/replan_controller.py \
  --monitor-report <run-root>/monitor/report.json \
  --plan <run-root>/planner/plan.json \
  --generated-at-utc <planner-observed-time> \
  --schedule-max-wait-seconds 300 \
  --output <run-root>/replan/decision.json
```

The caller may wait for `sleep_seconds`, then re-probe and replan.  The wait is
bounded (five minutes by default, one hour maximum), and it never replaces the
durable runner's lease heartbeat, Governor admission, or mount/network checks.
Missing, naive, or malformed `replan_at_utc` is a fail-closed `due_now` result;
it cannot postpone a safety observation.  The artifact is advisory and does
not enqueue work or contact a provider.

For a long-lived SQLite worker, pass the saved planner or closed-loop report to
the controller.  The file is re-read on every empty-queue tick and while a
provider lane is active, so a monitor can publish a new reset/health decision
without restarting the worker or waiting for a long task to finish:

```text
<python3.11> scripts/sqlite_controller.py run \
  --db <run-root>/state/dispatch.sqlite3 \
  --workspace <run-root>/workspace \
  --replan-feedback <run-root>/replan/decision.json \
  --poll-seconds 1 --idle-backoff-seconds 30 \
  --max-idle-rounds 0
```

`replan_at_utc` only changes the next bounded observation interval.  A due
feedback emits one idempotent `replan_due` event per feedback digest, including
the trigger source and any active job/attempt IDs; it does not enqueue work,
rotate models, or invoke a provider.  The controller keeps its lease heartbeat
and resource admission checks between wakes.  If the file is missing or
malformed, it fails closed to a short health poll rather than sleeping
indefinitely.

## Quota window watcher

`scripts/quota_window_watcher.py` is the provider-free observation boundary
used before a long-lived controller waits for a reset. It accepts one or more
saved Codex, Antigravity, or OpenCode-style JSON snapshots and produces a
shared-pool projection plus `replan_feedback`; it never contacts a provider or
sleeps:

```text
<python3.11> scripts/quota_window_watcher.py \
  --snapshot <run-root>/quota/codex.json \
  --snapshot <run-root>/quota/antigravity.json \
  --now-utc <observed-time> \
  --output <run-root>/quota/watch.json
```

`replan_controller.py` can consume the same snapshots in one read-only cycle;
it attaches `quota_window_watch`, excludes blocked pools from the next planner
inputs, and emits a separate `quota_replan_schedule` so an existing plan
feedback schedule is not silently overwritten:

```text
<python3.11> scripts/replan_controller.py \
  --monitor-report <run-root>/monitor/report.json \
  --quota-snapshot <run-root>/quota/codex.json \
  --quota-snapshot <run-root>/quota/antigravity.json \
  --generated-at-utc <observed-time> \
  --output <run-root>/replan/decision.json
```

The watcher keeps model quota separate from execution readiness. For example,
an Antigravity `/usage` balance can remain known while a raw TUI `not signed
in` diagnostic yields `needs_reauth`; the separate G1 `Out of credits` wallet
is not treated as model quota exhaustion. A fresh zero quota with a future
reset yields `cooldown_until_reset` and a wake hint; stale, malformed, unknown,
or authentication-conflicted evidence yields a bounded health recheck instead.
`--unknown-quota-policy pilot` is an explicit small-pilot exception only when
catalog visibility and configured authentication are also present. The caller
must keep lease heartbeats, Governor sampling and safety checks active during
any wait.

The L0 Cockpit can consume the resulting replan artifact without exposing raw
prompts or argv. It projects one health level, the first blocker, a safe next
action, the latest receipt metadata, and a compact quota summary:

```text
<python3.11> scripts/mission_cockpit.py \
  --snapshot <run-root>/controller/snapshot.json \
  --mission <run-root>/mission/mission.json \
  --governor <run-root>/monitor/governor.json \
  --replan <run-root>/replan/decision.json \
  --monitor <run-root>/monitor/continuous-loop.jsonl \
  --output <run-root>/cockpit/l0.json
```

The Cockpit is a read-only projection. A `keep_new_local_lanes_blocked` or
`bounded_wait_then_reprobe_quota` action is advisory evidence for the
Controller; it never kills a process, rotates a model, or enqueues work.
The optional `--monitor` input accepts either one JSON object or the
append-only `continuous-loop.jsonl` stream and projects only stable identity
and progress metadata.  New records keep the monotonic whole-loop clock
(`loop_elapsed_seconds`/`loop_remaining_seconds`) separate from the legacy
segment clock (`remaining_seconds`, exposed as `segment_remaining_seconds`);
missing clocks remain `null`/`unknown` rather than being inferred.

## External process supervision

The public template
`templates/durable-run-loop.service.example` is an optional controller-host
unit.  Replace its example paths only after the current capsule/mount probe;
do not copy an inventory or credentials into the repository.  It uses bounded
`Restart=on-failure` with `RestartPreventExitStatus=1`: startup/lease failures
(exit 2) can be retried while an old lease expires, while a deliberate
`blocked`/`paused` exit stays visible for review instead of being resubmitted
indefinitely.  The controller cgroup is bounded separately from PBS/remote
workload resources.  If the cluster uses a different supervisor, preserve
the same semantics: retry only bounded launcher/lease failures, cap restart
bursts, retain the run root, and never issue a new task after a blocked
checkpoint or unknown remote identity.
