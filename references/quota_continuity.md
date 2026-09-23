# Chat-Quota Continuity and Server-Local Agents

## Contents

1. What survives a chat-quota interruption
2. Control-plane architecture
3. Preflight scan
4. Persistent queue and fallback chains
5. Server-local runtime adapters
6. Quality and safety gates
7. Start, monitor, and resume
8. Deployment gate

## What survives a chat-quota interruption

A skill is instruction text loaded by an active agent. It cannot execute after
the Codex chat itself is no longer able to take turns. Continuity therefore
requires a separate operating-system process started before the interruption.

That process can finish only work already represented as durable task packets.
It cannot know new user intent while the chat is unavailable. Persist every
job's prompt, dependencies, allowed write scope, attempts, timeout, required
artifacts, and validation command before launching it.

## Control-plane architecture

Use four layers:

```text
Codex chat while available
  -> preflight snapshot + rolling-horizon plan
  -> persistent continuity controller
       -> local OpenCode Go, Cursor, or Antigravity adapter
       -> SSH server agent adapter
            -> vLLM | Ollama | llama.cpp loopback model API
            -> Aider | OpenCode | another approved tool-capable agent
  -> state.json + events.jsonl + attempt logs + artifacts
  -> Codex resume and audit when quota returns
```

The controller must not depend on the current Codex process, conversation, or
rate-limit bucket. Store its run directory outside a temporary workspace. Keep
one run directory per project/run and record its process ID and controller log.
Run it on the desktop host when the fallback chain needs local OpenCode Go,
Cursor, or Antigravity. For
the strongest server-only continuity, copy the small controller, task packets,
source/worktree, and a server-local inventory to the selected server and launch
it there; `transport=local` then means that server, so it survives a Mac-side
Codex interruption or disconnect.

## Preflight scan

Run the unified scan before important dispatches:

```bash
lad preflight --workspace "<trusted-workspace>" \
  --inventory "<private-hosts.json>" \
  --output "<private-preflight.json>"
```

It performs no paid prompt. It refreshes:

- local OS/architecture, CPU, available RAM, disk capacity gates, accelerators,
  installed CLIs, and argument-free agent/runtime process names first;
- Codex Luna/Spark availability and rate-limit buckets;
- OpenCode Go provider/catalog/history as one shared `opencode.go` pool, while
  leaving remaining quota and runtime acceptance unknown without evidence;
- Cursor authentication, catalog visibility, and persisted runtime rejections;
- Antigravity canonical models and interactive `/usage` groups;
- local and SSH compute capacity;
- installed vLLM/Ollama/llama.cpp-style runtimes, loopback APIs, loaded model
  identifiers, model directories, and tool-capable agent executables.

Catalog visibility is not runtime acceptance. A persisted execution rejection
continues to block the exact model until a later real success supersedes it.
For OpenCode, a capability failure may block only one advertised variant; quota
or auth failure applies to the shared Go pool instead.

## Persistent queue and fallback chains

Enqueue reviewed JSON job packets into a durable SQLite run:

```bash
lad enqueue --backend sqlite --db "<dispatch.sqlite3>" \
  --job-file "<job.json>"
```

SQLite locality admission protects locking and WAL semantics. If this queue
must also survive a reboot or environment replacement, place the database on a
known-local, non-temporary path and require its storage receipt to report
`persistent=true`; `/tmp` and container-overlay paths are not that boundary.

Example packet:

This is a contract template, not a model allowlist. Replace every angle-bracket
value with an exact route returned by the current preflight/plan and a real
shell-free project validator before enqueueing.

```json
{
  "schema_version": 1,
  "packet_id": "packet-J2",
  "job_id": "J2",
  "depends_on": ["J1"],
  "prompt_file": "task-packets/J2.md",
  "write_scope": "worker-J2/",
  "output_path": "worker-J2/status.md",
  "required_artifacts": ["worker-J2/status.md"],
  "validation_required": true,
  "validation_argv": ["<project-validator>", "worker-J2/status.md"],
  "attempts": [
    {
      "attempt_id": "opencode-go-live-route",
      "adapter": "opencode",
      "transport": "local",
      "provider": "opencode",
      "pool_id": "opencode.go",
      "model": "<exact-live-opencode-go-model>",
      "prompt_file": "task-packets/J2.md",
      "result_source_path": "worker-J2/opencode-final.md",
      "output_path": "worker-J2/status.md",
      "timeout_seconds": 1800,
      "fallback_on": ["quota", "auth", "network", "capability"]
    },
    {
      "attempt_id": "cursor-live-route",
      "adapter": "cursor",
      "transport": "local",
      "provider": "cursor",
      "pool_id": "cursor.composer_grok",
      "model": "<exact-live-cursor-model>",
      "prompt_file": "task-packets/J2.md",
      "output_path": "worker-J2/status.md",
      "cursor_prompt_argv_authorized": true,
      "timeout_seconds": 1800,
      "fallback_on": ["quota", "auth", "network", "capability"]
    },
    {
      "attempt_id": "server-agent",
      "adapter": "command",
      "transport": "ssh",
      "host_id": "<verified-remote-host-id>",
      "model": "<exact-live-server-model>",
      "workspace": "<remote-project-root>/project-worker-J2",
      "argv": ["<explicit-server-agent-argv>", "--model", "<exact-local-model>", "--yes-always", "--no-auto-commits", "--message-file", "task-packets/J2.md"],
      "timeout_seconds": 3600
    }
  ]
}
```

Attempt order is part of the plan. Fall through only for named pre-execution or
provider failures by default: quota, authentication, network, or capability.
Do not automatically run a second writer after an unclassified execution error
because the first agent may have partially modified its worktree.

The local OpenCode adapter requires an exact model selected by the persisted
plan and a prompt file. Its guarded runner sends the packet on stdin, keeps the
body out of process argv, defaults to `--pure`, does not use attachments, and
never enables `--auto` without the explicit `auto_approve` field. The
`opencode.go` route is hosted subscription inference; do not mislabel it as a
quota-free server-local model.

## Server-local runtime adapters

Use loopback-only APIs and reach them through SSH. Never expose an unauthenticated
model endpoint on `0.0.0.0` merely to simplify routing.

- vLLM: preferred on a currently verified compatible GPU host when a supported
  model fits its measured free VRAM. It provides an OpenAI-compatible API,
  batching, metrics, and strong GPU throughput.
- Ollama: convenient model lifecycle and a simple API. Prefer it for smaller or
  quantized models when ease of operation matters more than peak throughput.
- llama.cpp: preferred for GGUF quantization, CPU/GPU split, or models that need
  tighter memory control. `llama-server` also exposes an OpenAI-compatible API.

The `server_openai` controller adapter calls `/v1/chat/completions` either on
the controller host's loopback or through SSH and writes the returned text to
an explicit output path. It is suitable for
drafts, decomposition, extraction, and review packets. It is not by itself a
coding agent because the model has no file or shell tools.

For code changes, use an approved tool-capable agent such as Aider or OpenCode
on the server. Give it a dedicated worktree/output directory, bounded task
packet, exact validation command, timeout, log, and required artifact. The
continuity controller invokes the approved argv; it does not execute shell text
invented by model output.

## Quality and safety gates

Server-local models may continue:

- deterministic indexing, extraction, refactors, tests, and documentation;
- bounded implementation in an isolated worktree;
- experiment setup, monitoring, and non-authoritative summaries;
- drafts that will later receive independent review.

Require a stronger provider or human/Codex review before accepting:

- destructive operations, credential or permission changes;
- final scientific claims, legal/medical/financial decisions, or publication;
- security-sensitive changes and production deployment;
- difficult cross-repository changes beyond the local model's calibrated level.

Mark medium/hard local-model results `requires_provider_review=true`. Completion
means required artifacts are newly created or changed and validation passed; a
stale pre-existing file, model response, or live PID is not completion evidence.
Set `accept_existing_artifacts=true` only for an explicit validation-only job.

## Start, monitor, and resume

Start the controller before quota loss through the packaged detached boundary:

```bash
lad run --backend sqlite --db "<dispatch.sqlite3>" \
  --workspace "<trusted-workspace>" --max-lanes 2 --detach
```

Record the returned PID metadata and log paths. The controller atomically
updates durable state and writes one log per attempt. It keeps an empty queue
alive when `--max-idle-rounds 0` (the default). Only packets already reviewed
and enqueued before the chat interruption are eligible; no new intent is
created by the worker.

Existing JSON `state.json` runs remain a deliberate legacy mode. Continue one
with `lad run --backend json --run-dir "<durable-run-dir>" --detach`; do not
silently migrate or mix the two state formats.

When Codex capacity returns:

```bash
lad resume --backend sqlite --db "<dispatch.sqlite3>" > resume.json
```

The resume command re-observes durable artifacts for interrupted/failed jobs.
Artifacts discovered after an SSH disconnect become
`artifact_ready_needs_review`, never automatic success. Read `resume.json`,
verify every required artifact and validation result, import completed jobs into
scheduler state, inspect failed/blocked attempts, then replan only unfinished
dependencies. Never rerun completed jobs by default.

## Deployment gate

Never infer deployment readiness from a dated host description. Read the
current preflight's loopback API, loaded model, and agentic-smoke evidence.
Before installing a missing runtime/model, estimate runtime/environment/model
download, cache, VRAM, RAM, disk, and startup time. A model download over 1 GiB
is a bulk transfer: download directly on the selected server, verify live egress
according to the bulk-network policy, and record final bytes and checksum when
available. Do not relay model weights through the Mac.

Choose the model only after checking license, context length, tool-use support,
quantization, and measured fit against the selected host's current free VRAM.
Run a bounded agentic smoke task and artifact validation before marking the
server-local pool ready.

For a host with roughly 32 GiB of free VRAM, the managed bootstrap
`scripts/deploy_server_local_qwen25_awq.sh` is an example deployment recipe.
It downloads the approximately 9.3 GiB Qwen2.5-Coder-14B-Instruct-AWQ
repository directly from the server, validates exact bytes and repository
SHA-256 values, creates an isolated vLLM environment, and binds the
OpenAI-compatible endpoint to loopback only. Treat it as a recipe, not
readiness evidence: the API smoke and isolated agentic coding smoke must still
pass on the live host.
