# local-agent-dispatch

> Alpha: a provider-free, evidence-gated control plane for placing agent work
> across a local machine and verified remote workers.

This is an experimental Apache-2.0 release. It is designed to keep the heavy
execution plane on a server when a workload is server-compatible, while the
local machine retains a small control plane, manifests, and human review.
Provider execution, live quota values, and remote runtime readiness are never
inferred from a model catalog alone.

This package adds a small, installable entry point named `lad` for the existing
`local_agent_dispatch` repository surface.

Architecture, evidence-level, and threat-boundary notes live in
[`docs/architecture.md`](docs/architecture.md),
[`docs/evidence-model.md`](docs/evidence-model.md), and
[`docs/threat-model.md`](docs/threat-model.md).
The public implementation boundary is tracked in
[`docs/status.md`](docs/status.md), and clean-checkout checks are in
[`docs/reproducibility.md`](docs/reproducibility.md). The publication procedure
is documented in [`docs/public-release.md`](docs/public-release.md), while the
research questions and evidence principles are summarized in
[`docs/research-program.md`](docs/research-program.md).

## Install

From the repository root:

```bash
python -m pip install -e .
```

For a non-editable install, `python -m pip install .` also bundles the
read-only scan, fit, schema, and helper scripts under the package data
directory. Set `LAD_REPO_ROOT` only when deliberately using a separate source
checkout.

The console entry point is:

```bash
lad --version
```

## Offline commands

- `lad doctor --offline`  
  Runs `scripts/local_system_scan.py` and reports only local, read-only evidence.
  It must not contact providers or send prompts.
- `python scripts/resource_governor.py --requested-lanes N`
  Reports live memory/swap/RSS pressure and a non-destructive local-lane
  admission decision. It never kills unowned processes; see
  `docs/research/resource-governor-v1.md` for the controller integration gate.
- `lad demo --offline`  
  Runs the same local evidence path and prints a concise offline demonstration payload.
- `lad scan --workspace PATH`  
  Runs a workspace-targeted local scan through the bundled script path resolution,
  regardless of current working directory.
- `lad preflight --workspace PATH --inventory PATH [--output PATH]`  
  Runs the local hardware scan first, then explicitly probes configured provider
  CLIs and SSH compute. It never sends a model prompt; the snapshot is private
  runtime evidence and should not be committed.
- `lad scheduler resolve --input POLICY.json` and `lad scheduler decide --input DECISION.json`
  Resolve organization/project/task policy layers or evaluate one saved,
  replayable resource decision. Both commands are offline: stale, conflicting,
  missing, or quota-unknown evidence fails closed instead of creating capacity.
- `lad package resolve --catalog DIR --requirements REQUIREMENTS.json --output lad.lock.json`
  Deterministically resolves a local extension catalog to exact versions and a
  catalog-bound lock. `lad package verify-lock` reproduces that resolution and
  can hash an existing local store; `install`, `activate`, `rollback`, and
  `uninstall` remain separate explicit operations. No package command imports
  or invokes an entrypoint.
- `lad skill search|compose|analyze ...`
  Uses a fresh, body-free index for eligible-skill recall, exact 3/5/10
  complementary portfolios, or bounded latent similarity/redundancy/coverage
  analysis. Output never includes embeddings or instruction bodies.
- `lad skill create --spec SPEC.json --destination NEW_DIR`
  Atomically creates an inert `kind=skill` source containing `SKILL.md` and a
  digest-bound `lad-package.json`. Creation does not install, activate, index,
  enable, or execute the skill; those are independent gates.
- `lad fit --preflight PATH --jobs PATH`  
  Reads a saved preflight and workload descriptions, then reports local hardware,
  server-first gates, required CPU/RAM/GPU/VRAM/disk/runtime configuration, and
  eligible remote hosts. This is read-only and does not probe or send prompts.
- `lad capture --task TASK [--repo-root PATH] [--history PATH]`  
  Builds a provider-free `TaskPacket`: bounded repository metadata, a validated
  DAG with parallel waves, per-node estimates, and optional exact
  task-family/model/host history calibration. It reads no file contents,
  executes no project command, and sends no provider prompt. Missing resource
  or history evidence remains `unknown`; an invalid dependency or cycle is
  `dag_invalid` and must be reviewed before dispatch.
  The emitted `planner_jobs` field is accepted directly by `lad dispatch
  --jobs` for a provider-free planning pass; it still lacks execution
  credentials, write approval, and validator-bound packet fields.
- `lad evidence --provider NAME --capability NAME [--version VERSION]`
  Builds an offline, search-first compatibility plan from official docs/source,
  release notes, and issue/PR queries. An optional redacted `--sources` JSON is
  ranked without making network calls, probes, or model calls.
- `lad dispatch --workspace PATH --jobs PATH --preflight PATH [--max-lanes N]`  
  Runs the complete provider-free planning boundary in one call: system-first
  local scan, saved preflight merge, P50/P90 task estimates, local/remote
  hardware fit, and rolling-horizon planning. It emits a versioned report with
  exact host/model/pool assignments, server-first reasons, unknown/pilot gates,
  quota uncertainty, and lane placement. It never executes a provider or sends
  a model prompt. Add `--model-policy codex-luna-max` to hard-route this
  planning request to the exact `gpt-5.6-luna/max` Codex pair and exclude every
  other subscription pool; `--live-probes --inventory PATH` is an explicit
  opt-in for no-prompt catalog/quota/SSH discovery.
- `lad bridge --plan PATH --jobs PATH --state PATH --adapters PATH`  
  Converts a dispatch plan into reviewable, validation-bound packets without
  executing a provider. It defaults to `dry-run`; only explicit
  `--enqueue --db PATH` (or the `--execute` alias) mutates a local SQLite
  queue, and that flag still does not execute a provider. `lad dispatch` has
  the same auditable `--enqueue/--execute --adapters PATH --db PATH` boundary
  after its read-only planning report.
- `lad plan --state PATH --jobs PATH`  
  Runs the rolling-horizon planner against saved evidence. It does not launch a
  provider or perform a network probe.
- `lad run --workspace PATH [--once]` and `lad resume/status --workspace PATH`  
  Drive the durable controller and return its status/lease metadata. The
  default `--backend auto` uses a workspace-local SQLite WAL database for new
  queues; an existing `run-dir/state.json` is detected as a legacy JSON run.
  Queries against an uninitialized auto workspace return
  `status=not_initialized` without creating a database. Use
  `--backend json --run-dir PATH` to force the migration controller.
- `lad enqueue/status/run/resume --backend sqlite ...`  
  Explicitly select the SQLite WAL controller (or let `auto` select it). Queue
  claim, lease fencing, attempt transition, and events are transactional.
  Add `lad run --backend sqlite --db PATH --detach` to start a
  chat-independent worker; it records a private PID metadata file and log
  path. `--max-idle-rounds 0` keeps that worker alive for later authorized
  enqueue operations.
- `lad monitor --state PATH`  
  Runs the observation loop. Provider quota and SSH compute refreshes are off
  by default and must be explicitly enabled with the corresponding flags.
- `lad monitor-state --db PATH` (or `--snapshot PATH`)  
  Projects a SQLite controller snapshot into the monitor's worker schema. It
  is read-only and prompt/argv-safe; a running job without an explicit PID or
  log breadcrumb is reported as `unknown`, never inferred healthy.
- Provider-free durable worker seam: `scripts/remote_worker.py` implements the
  local `prepare → claim → heartbeat → recover → complete → resume-handoff`
  contract and a bounded `fake-execute` executor for CI/recovery tests. It does
  not call providers, SSH, shells, or networks; see
  [`docs/remote-worker-contract.md`](docs/remote-worker-contract.md).
- `scripts/remote_worker_client.py` adds a dry-run-by-default, fake-SSH-tested
  transport for an already verified inventory. Packets travel over SSH stdin
  after redaction; remote paths, ports, placement, stderr, and explicit
  `--execute` are independently gated. It is not a generic shell runner.
  Legacy PBS nodes may declare an absolute `worker_python` (or nested
  `pbs.python`) in that inventory.  The resource probe verifies that exact
  interpreter and emits bounded `runtime_python` evidence; it never treats a
  copied desktop `.venv` or a missing `python3` PATH entry as a usable runtime.
- `scripts/remote_envelope.py` provides the provider-free cross-host
  outbox/inbox boundary: versioned metadata-only envelopes, atomic receipts,
  request-id idempotency, conflict rejection, and pending recovery after a
  dropped connection. It never executes a provider or shell; see
  [`docs/remote-envelope-contract.md`](docs/remote-envelope-contract.md).
- `scripts/reverse_envelope_service.py` exposes those fixed envelope
  operations on a loopback-only JSON socket for a worker that is reached via a
  reverse tunnel. `scripts/reverse_tunnel_supervisor.py` owns the fixed
  loopback `ssh -N -T -R` child, records a redacted lifecycle status, and
  performs bounded restarts. These are transport canaries, not provider
  execution or a claim of 24-hour durability until installed under a reviewed
  supervisor and connected to the SQLite outbox.
- `scripts/remote_opencode_client.py` plus
  `scripts/opencode_remote_run.py` provide the server-side OpenCode Go seam.
  The controller sends only a prompt file over SSH stdin; the remote wrapper
  starts an already-authenticated `opencode-go/<model-id>` CLI and returns a
  result hash/size summary. It is dry-run by default, never copies auth files,
  and requires a separate server-side `opencode auth login` before paid work.
  This is an **experimental server canary boundary** in Alpha: it does not
  claim that every OpenCode model is executable or that remaining Go quota is
  machine-readable. The server-side wrapper is the intended place for
  OpenCode Go execution; do not run a full model workload through the Mac.
  Remote discovery does not depend on `PATH` alone: a private host entry may
  declare `opencode_bin`, an isolated `runtime_root`, and (when the server
  already has an account) a read-only `opencode_auth_root`. The bounded server
  scanner records absolute installation paths and allow-listed `auth list`
  provider names separately from catalog, runtime, and quota evidence. A
  discovered binary or configured account is not by itself a model-readiness or
  remaining-quota claim.
- `lad replan --monitor-report PATH [--jobs PATH] [--plan PATH]`  
  Converts observations into copy-on-write pool/model/host constraints. It is
  provider-free and read-only; a human or a higher-level controller must review
  the decision before invoking the planner again.
- `lad closed-loop --approved-packets PATH` (alias `lad loop`)  
  Consumes only an explicitly approved `enqueue-ready` packet bundle. It is
  dry-run by default and does not create SQLite state or call a provider. The
  explicit `--fake-execute --db PATH` mode is a provider-free CI/demo lane for
  local Python fake commands; it runs the real SQLite wave, monitor, and
  read-only replan boundary without enqueueing the next plan.

Planner output is deliberately not executable by itself. Use
`scripts/plan_packet_bridge.py` with an explicit adapter registry to create a
reviewable, validation-bound task packet; it defaults to dry-run and rejects
desktop-CLI/remote-workload split placement without a declared wrapper.

The persistent controller uses a run-level lease and heartbeat. `enqueue`,
`resume`, and `init` acquire the same lease, so a live run rejects concurrent
full-state mutations instead of silently losing queued jobs. Completion can
require an explicit validator and SHA-256/fresh artifact manifest.

Modern packets accepted by either controller backend must carry a `packet_id`,
exact `attempts`, a write scope, non-empty artifacts, and an independent
validator. The JSON controller can ingest an older hand-written queue only
when `legacy_compatibility: true` is explicit. Unknown provider quota is
blocked by default; a preflight provider may opt into a bounded pilot and that
policy is recorded in the planning evidence.

Within a shared Cursor Composer/Grok or Antigravity pool, the planner may pick
an efficient or hard-role member from the fresh catalog. That changes model
eligibility, not quota accounting: the pool remains one shared budget.

When a task supplies input/output-token P50/P90 bounds and the catalog supplies
per-million-token prices, assignments include an estimated USD cost and its
evidence. Missing token or price data stays `unknown`; it is never treated as
free.

OpenCode Go DeepSeek members are excluded by default. An exact user-authorized
task can opt in with `allow_policy_excluded_models` and `model_by_pool`; the
model must be visible in the current catalog and remains charged to the shared
`opencode.go` pool.

Antigravity execution is an optional adapter. The open-source core does not
ship or assume a guarded TUI runner; set `ANTIGRAVITY_GUARDED_RUN` to an
audited local adapter before enqueueing an Antigravity packet, otherwise the
controller fails closed.

## System-first scan

The offline scanner collects local system facts first (OS, resources, disk gates,
CLI presence). Provider/catalog/rate checks and model prompts are not performed.

`--version` remains a deterministic local-only command.

## Evidence levels

- `offline`: no provider network contact, no model prompt.
- `local-only`: evidence derived from system signals and command existence checks.
- `runtime`: richer inventory or execution evidence built from explicit
  provider/runtime commands; it is never implied by the offline scan.

## Runtime state location

Runtime state is expected to remain under `LOCAL_AGENT_DISPATCH_HOME` (default
`$HOME/.codex/local-agent-dispatch`) and not in the package outputs.
The CLI scaffold does not persist secrets, accounts, or prompts.

## Server-first / bulk transfer boundary

This command surface is lightweight and intentionally not for heavy model
execution or dataset/model transfer on the Mac. Any server-compatible workload
should stay on a verified server per project policy; this layer is the local
control-plane entry point. The remote OpenCode seam is opt-in and experimental,
with task envelopes, hashes, and receipts kept separate from provider
credentials.
The `fit` report is a placement decision from current evidence, not proof that a
remote runtime is installed or that a model will fit until the server-side smoke
gate succeeds.

## Scope note

The skill remains a thin launcher, but the packaged CLI now exposes the
provider-free planner/monitor/replan boundaries and a SQLite-first `auto`
execution backend with an explicit JSON migration path. Provider execution is
still explicit, adapter-bound, and outside the offline discovery path.
