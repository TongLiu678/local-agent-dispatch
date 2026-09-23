# Provider-free durable worker contract

`scripts/remote_worker.py` is the small, local spool contract used to test the
continuity boundary without a provider, SSH session, network request, shell
command, or model prompt. It is deliberately a fake executor seam, not a
remote-service implementation.

## Lifecycle

The durable lifecycle is:

1. `prepare` validates a task packet and writes a redacted manifest plus a
   prepare-time artifact/hash baseline.
2. `claim_job` creates a fenced owner/token lease. `heartbeat` renews that
   lease; owner, token, and expiry are checked on every mutating operation.
3. A running adapter records a fenced process witness with
   `process-identity`. The witness contains only `(pid, start_time,
   process_group, run_id, fence)` plus bounded liveness metadata; the lease
   token is supplied as an authenticated command argument rather than copied
   into stdin.
4. Strict `recover`/`resume` requires a fresh `exited` or `not_found` witness
   before marking an expired lease `recoverable`. Missing, stale, alive, or
   mismatched evidence moves the job to `recovery_review` and prevents a new
   claim. The lease-only recovery path remains available only as an explicit
   compatibility override for an operator.
5. An executor records final artifact hashes and calls `complete_job`. Success
   requires every declared artifact to be a non-empty regular file and to be
   new or hash-changed from the prepare baseline. Otherwise completion fails
   closed with a deterministic error code.
6. `resume_handoff` emits a bounded, prompt/argv-safe report containing packet
   identity, placement/write scope, artifact evidence, lease state, and an
   allow-listed event tail. A later controller can use `next_action` to decide
   whether to wait, recover/claim, or review a terminal result.

`recover_and_handoff` (CLI: `resume`/`recover-handoff`) combines lease
reconciliation and handoff generation under one spool lock. This is the
reconnect boundary for a controller returning after Codex quota loss or a
short-lived SSH/chat disconnect. In strict mode (the SSH client's default),
the handoff records whether process liveness was `verified` or
`unverified`, and an unverified job exposes only `review_process_liveness` as
its next action. The caller gets a single claim/review action without a race
between separate `recover` and `handoff` calls.

The manifest and event log are written atomically under a spool lock. Owner
hashes are exposed instead of owner IDs, lease tokens are never returned by a
handoff, and raw packet prompt/argv fields are never copied into events or the
handoff artifact.

## CI/fake execution seam

`fake-execute` (alias `fake-run`) is intentionally bounded: it writes only the
declared artifact paths with a small fixture string, records SHA-256 hashes,
and finalizes through the same lease and freshness gate. It does not interpret
`attempts`, invoke a subprocess, contact a provider, or open SSH. This makes it
safe for unit tests and recovery demonstrations while preserving the contract
that a future server worker must satisfy.

```bash
python3 scripts/remote_worker.py prepare \
  --packet packet.json --project-root /trusted/project --spool /tmp/lad-spool
python3 scripts/remote_worker.py fake-execute \
  --spool /tmp/lad-spool --job-id example-job --owner ci-fake
python3 scripts/remote_worker.py handoff \
  --spool /tmp/lad-spool --job-id example-job --output handoff.json

# A server adapter records the child identity while it owns the lease.  The
# identity JSON must not contain the lease token; the worker binds it to the
# current fence from --lease-token.
python3 scripts/remote_worker.py process-identity \
  --spool /tmp/lad-spool --job-id example-job \
  --owner server-worker --lease-token <lease-token> --identity identity.json

# On reconnect, reconcile an expired lease and emit the handoff atomically.
# Strict mode is the default for the SSH client; the local worker CLI opts in
# with --require-process-identity.
python3 scripts/remote_worker.py resume \
  --spool /tmp/lad-spool --job-id example-job \
  --require-process-identity --output handoff.json
```

The output is evidence for the local control-plane tests only. It must not be
reported as proof that a provider, remote host, GPU runtime, or bulk data route
is available. Real remote execution remains behind explicit server-first
capacity/route checks and an authorized adapter.

### PBS persistence seam

`scripts/pbs_worker_wrapper.py` is the bounded PBS persistence seam used after
the site has been observed to expose a working `qsub`/queue.  It has two
explicit modes:

```bash
python3 scripts/pbs_worker_wrapper.py submit \
  --python /trusted/python \
  --worker-script /trusted/project/scripts/remote_worker.py \
  --spool /data/lad/spool --job-id approved-fixture --owner lad-service \
  --run-root /data/lad/runs/approved-fixture \
  --qsub /opt/torque-2.5.2/bin/qsub --queue workq --nodes 1 --ppn 1

python3 scripts/pbs_worker_wrapper.py run \
  --python /trusted/python \
  --worker-script /trusted/project/scripts/remote_worker.py \
  --spool /data/lad/spool --job-id approved-fixture --owner lad-service \
  --run-root /data/lad/runs/approved-fixture
```

`submit` sends only a fixed `run` invocation to PBS, does not inherit the
caller's environment, and writes an atomic submission intent plus
`submission.json`.  A leftover intent without a receipt blocks blind
re-submission after a controller crash; it must be reconciled by an operator
or site-specific queue adapter.  `run` invokes
only `remote_worker.py fake-service`, captures bounded JSON/stderr files, and
writes an atomic `receipt.json` containing the PBS job, host, provider/network
flags, status, owner digest, and SHA-256 artifact rows.  Unsafe paths, IDs,
queue names, arbitrary commands, `--execute`, and provider names are rejected
or never accepted.  A `completed` receipt means only that the provider-free
fixture passed its lease and artifact gate; it is not evidence of OpenCode,
Antigravity, Cursor, a model, quota, or network availability.  A real adapter
must be added behind a separate review and capability receipt.

### SQLite/PBS controller bridge

After `remote_prepare_orchestrator.py` has recorded an accepted worker
envelope, `scripts/pbs_controller_bridge.py` may submit the fixed wrapper and
reconcile it under the local SQLite controller lease:

```bash
python3 scripts/pbs_controller_bridge.py --db dispatch.sqlite3 --inventory hosts.json
python3 scripts/pbs_controller_bridge.py --db dispatch.sqlite3 --inventory hosts.json --execute
python3 scripts/pbs_controller_bridge.py --db dispatch.sqlite3 --inventory hosts.json --reconcile --execute
```

For a real submission, the controller can require a fresh, host-bound
scheduler-health receipt before it opens the SQLite lease or invokes `qsub`:

```bash
python3 scripts/pbs_controller_bridge.py --db dispatch.sqlite3 \
  --inventory hosts.json --execute --require-scheduler-health \
  --scheduler-health /var/lib/local-agent-dispatch/receipts/pbs-health.json \
  --scheduler-health-queue workq --scheduler-health-node compute-01
```

The receipt is accepted only when its bounded report is `verified`, transport
and physical-memory admission are both true, the queue/node identity matches,
and `observed_at` is within the 15-minute default TTL.  A degraded report such
as Torque `availmem` including swap blocks before any database mutation or PBS
side effect; there is no implicit waiver.  Reconcile/status operations do not
need a fresh queue-health receipt because they read an already accepted remote
identity rather than create a new scheduler job.

The inventory must explicitly declare a `pbs` object for the target host with
absolute `wrapper`, `python`, `qsub`, and `run_root` paths plus a bounded queue,
node, and `ppn` request. The bridge records `executor=pbs`, `pbs_job_id`,
`run_root`, and submission/worker receipt digests as allow-listed SQLite
metadata. It never submits a pending/unprepared envelope, accepts arbitrary
commands, or promotes a status response without a matching request, payload
digest, PBS job id, and terminal result/error evidence.

Transport completion and parent-job completion are separate gates. If a
controller has already claimed an SQLite attempt, it must first bind the
outbox row with `SQLiteStore.bind_transport_attempt(...)`. A validator that has
fresh artifact evidence may then call
`SQLiteStore.record_transport_receipt_and_complete(...)`; that method records
the terminal receipt, attempt result/manifest/validation, reservation release,
job transition, and lifecycle events in one fenced transaction. It requires
`validation={"ok": true}` plus an artifact manifest for successful promotion.
The ordinary `record_transport_receipt(...)` and the CLI bridge remain
transport-only, so a completed PBS receipt for an unbound or merely queued job
cannot be mistaken for an end-to-end completed task.

### Independent fake-service smoke

`fake-service` is a process-level continuation smoke for service managers and
chat-loss recovery tests. It accepts one explicit `job_id`, waits for that
prepared/recoverable manifest, reconciles an expired lease, and invokes only
the deterministic `fake-execute` fixture before returning a safe handoff:

```bash
python3 scripts/remote_worker.py fake-service \
  --spool /var/lib/local-agent-dispatch/spool \
  --job-id approved-fixture --owner lad-service \
  --poll-seconds 1 --max-idle-rounds 0
```

This command is intentionally provider-free and is not a model fallback. A
production service must replace it with a separately reviewed adapter while
preserving the same lease, artifact-freshness, validation, and handoff gates.
The SSH client exposes the same operation as an explicit, dry-run-by-default
transport for fake-SSH CI; use a service manager or a durable remote supervisor
for real detached execution rather than assuming an interactive SSH session
survives chat termination.

## SSH transport seam

`scripts/remote_worker_client.py` is the bounded transport adapter for an
already-verified private inventory. It accepts only `transport=ssh` hosts with
an explicit port, user, worker script, project path, and spool path. Remote
paths are absolute and use a conservative shell-safe character set. Hosts may
also declare `worker_python` when a compute node does not expose `python3` on
its default PATH; this is either an absolute, validated interpreter path or a
simple executable name, and defaults to `python3`. The client builds an argv
list with `shell=False`; it never concatenates a remote shell command or
accepts arbitrary SSH options. A legacy gateway that offers only `ssh-rsa` may
set the explicit boolean `ssh_legacy_rsa: true`; that flag expands only to the
fixed `HostKeyAlgorithms=+ssh-rsa` and `PubkeyAcceptedAlgorithms=+ssh-rsa`
options and is otherwise absent by default.

Before the first worker operation, run the explicit `bootstrap` operation when
the remote host does not already have a verified worker bundle. Bootstrap sends
only `remote_worker.py`, `remote_envelope.py`, `dispatch_schema.py`, and the
repository's JSON schemas over the existing SSH stdin stream. The transfer is
bounded, records a per-file SHA-256 manifest and bundle digest, refuses unsafe
paths/symlinks, and uses remote atomic replace. It never sends a task packet,
prompt, provider output, credential, or model request. The inventory's worker
path must be `<worker-root>/scripts/remote_worker.py`; its schema directory is
the corresponding `<worker-root>/schemas`.

```bash
python3 scripts/remote_worker_client.py bootstrap \
  --inventory "$HOME/.codex/local-agent-dispatch/hosts.json" \
  --host-id remote-a --source-root . --execute
```

The bootstrap receipt is a deployment prerequisite, not runtime readiness: a
successful bundle install does not prove SSH reachability beyond that command,
OpenCode authentication, quota, model capability, or available resources.

All client operations are dry-run by default. `--execute` is an explicit gate
for `prepare`, `status`, `recover`, `handoff`, `resume`, or `fake-execute`.
`prepare`
passes the redacted packet to `remote_worker.py prepare --packet -` through SSH
stdin. The other operations use an empty stdin stream and retrieve only the
worker's JSON result. Stderr is represented by a byte count and SHA-256 digest,
not copied into local logs. Prompt text, raw provider argv, and credentials are
not returned in client reports.

The client exposes `process-identity` for a server adapter's bounded
PID/process-group witness. Its JSON is allow-listed and sent on stdin without
the lease token; the token remains only in the validated SSH argument. The
client's `recover` and `resume` calls default to
`--require-process-identity`. Use the explicit `--no-require-process-identity`
compatibility switch only for a reviewed operator recovery of legacy manifests.

The client maps known local absolute packet paths (workspace, artifact,
prompt/result and runtime paths) into the selected host's declared
`project_path`; absolute paths outside the captured local workspace are
rejected. This keeps a Mac `/Users/...` path from entering a server manifest
and avoids treating a remote path as a local file. The client preserves
`execution_host` and `workload_host` in its placement evidence. A split
placement must carry a declared workload wrapper; this seam records that
declaration but never executes it. A fake SSH binary can therefore exercise
`prepare -> fake-execute -> resume` in CI without a network, provider,
download, or remote shell.

The shared private inventory may also contain the local controller as an
explicit `transport=local` entry. The SSH client ignores that controller entry
while validating all selected remote entries; unknown transports and an
inventory with no SSH host still fail closed. This lets the same inventory feed
both placement planning and the bounded remote transport without making a
remote operation fail before its requested SSH host is selected.

## Controller SSH runtime boundary

The SQLite controller also supports an explicitly prepared `server_openai`
attempt over SSH when the inventory host exposes a loopback OpenAI-compatible
runtime. The prompt is read from the controller workspace, the short request
script is sent over the authenticated SSH stdin, and the remote runtime writes
the declared result artifact under `remote_workspace`. Artifact observation and
validation both use the SSH host; a local absolute validator path is rejected
by the packet bridge. This is an authorized, bounded runtime path, not a
generic shell or public endpoint, and completion still requires a fresh,
hashable artifact plus a successful remote validator.

## Server-side OpenCode Go boundary

`remote_opencode_client.py` is the explicit transport for a child agent that
must run on the server rather than on the local Mac. Its inventory entry names
the remote project root, `opencode_remote_run.py`, and the already-installed
OpenCode binary. The client never transfers `auth.json`; the operator must run
`opencode auth login` once on the server and verify the provider there. For
parallel lanes, the inventory may additionally declare a unique
`runtime_root` plus an `opencode_auth_root` pointing to the server-local,
read-only OpenCode data directory containing the configured account. The
client then prefixes the remote runner with an explicit `env` containing
lane-local `HOME`, `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_STATE_HOME`, and
`XDG_CACHE_HOME`. When `opencode_auth_root` is supplied, `XDG_DATA_HOME` still
points at the lane's own mutable data root; the wrapper creates only a
read-only symlink from that root to the existing server-side
`opencode/auth.json`. Credentials are never copied or returned. This isolates
OpenCode's SQLite database, locks, logs, and
cache; sharing one OpenCode home across lanes is unsupported because it causes
false failures from database/lock contention. A request is dry-run by default.
The discovery scanner must not rely on `PATH`: an inventory may declare
`opencode_bin`, and the scanner records the bounded absolute candidate and its
runtime context separately from Go authentication or quota evidence. A binary
being present is therefore not a readiness claim.
The corresponding snapshot command accepts `--auth-data-root` for this same
split: it pins mutable lane state under `--runtime-root` while reading only
allow-listed provider state from the existing server-local XDG data root. If a
remote checkout rejects that flag, its source revision is stale and must be
updated and hash-verified before scheduling.
For a complete account diagnostic, pass the account XDG data directory again
as `--history-data-root`; this makes the history database explicit instead of
silently reporting the newly-created empty lane database. History is still
spend evidence, not remaining quota, and is not attributed to one worker.
With `--execute`, the prompt bytes are written to the SSH stdin stream, while
model, variant, cwd, result path, and timeout remain fixed argv fields. The
wrapper returns only a redacted JSON status and result SHA-256/size. This keeps
model context, child-process memory, and full output on the server while the
local controller retains leases, quota policy, and human approval.
