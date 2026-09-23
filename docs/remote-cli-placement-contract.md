# Remote CLI placement contract

`scripts/remote_cli_placement.py` is a provider-free sidecar for describing a
CLI that is installed and authenticated on a remote SSH host. It addresses a
specific ambiguity in the planner: `execution_host` is the machine where the
model CLI runs, while `workload_host` is the machine that owns the data and
compute. A large remote workload does not, by itself, move a desktop-authenticated
CLI to that server.

The compiler is dry-run only. It never opens SSH, starts `codex` or `agy`,
contacts a provider, installs software, reads credential values, or creates a
receipt. A successful report is a placement contract and not proof that a
model request would succeed.

## Exact routes

The contract has three explicit route tuples. The tuple is an allow-list,
not a family pattern, and there is no implicit fallback. The current user
execution policy is the first row; the other rows remain explicit opt-in
routes and are not selected by fallback:

| Pool/provider | Remote CLI | Exact model | Exact variant |
| --- | --- | --- | --- |
| `codex.luna` / `codex` | `codex` | `gpt-5.6-sol` | `max` |
| `codex.spark` / `codex` | `codex` | `gpt-5.3-codex-spark` | `xhigh` |
| `antigravity.gemini` / `antigravity` | `agy` | `gemini-3.6-flash-high` | JSON `null` (the effort is encoded in the slug) |

The `variant` key is mandatory even when its exact value is `null`. A model
catalog entry or an installed binary with a different name is not enough to
pass this contract.

The Gemini route is task-local and deliberately exact.  The current catalog
exposes `gemini-3.6-flash-high`; an older `gemini-3.1-pro-high` runtime
observation was location-restricted, so this route avoids silently retrying
that rejected tuple.  Catalog visibility still does not promote the route to
execution-ready: fresh authentication, quota, host, route, and a bounded real
request remain separate evidence gates.

## Required evidence

The planner-side assignment, remote host row, and route observation must
provide all of the following:

- `execution_host` equal to the SSH host's stable `host_id` and
  `execution_transport=ssh`;
- an absolute, confined `project_path` and `remote_workspace`;
- an installed CLI with an absolute path and version;
- authentication evidence with `state=authenticated`,
  `scope=remote_host`, host binding, timestamp, TTL, and a source; local Mac
  desktop authentication is rejected even when the host row says `ssh`;
- route evidence with `provider=racknerd`, `status=verified`, `verified=true`,
  the exact target host, an egress IP, timestamp, TTL, and source;
- an explicit dry-run wrapper identity (`name`, `version`, SHA-256, and
  `mode=dry-run`);
- a relative `write_scope` below the remote workspace; and
- a durable receipt path below `remote_workspace/.lad/receipts/`.

All timestamps are checked against the supplied `--now-utc` (or the current
UTC clock), and stale or future evidence fails closed. Inputs containing
credential-shaped keys are rejected before projection. The output is an
allow-listed, redacted contract with a `contract_digest`; no raw command,
prompt, token, or credential is copied.

## Planner and packet shape

The planner may carry the fields below in an assignment. The sidecar compiles
them into `remote_cli_placement` and can attach that object to a packet:

```json
{
  "job_id": "spark-job",
  "attempt_id": "spark-attempt",
  "pool_id": "codex.spark",
  "provider": "codex",
  "model": "gpt-5.3-codex-spark",
  "variant": "xhigh",
  "execution_host": "westd",
  "execution_transport": "ssh",
  "workload_host": "westd",
  "workload_transport": "ssh",
  "remote_workspace": "/srv/lad/spark-job",
  "write_scope": "src/spark",
  "receipt_path": "/srv/lad/spark-job/.lad/receipts/spark-attempt.json",
  "remote_cli_wrapper": {
    "name": "codex-remote-cli-wrapper",
    "version": "0.1.0",
    "sha256": "<64 lowercase hex characters>",
    "mode": "dry-run"
  }
}
```

The packet extension marks the future adapter as `adapter=remote_cli`, binds
the exact model/variant, host, project path, write scope, wrapper, route
observation, and pending receipt. It also carries
`provider_execution=false`, `model_prompts_sent=false`, and
`ssh_prompt_sent=false`. Those flags are invariants for this provider-free
slice. A production adapter must be reviewed separately before this marker is
allowed to execute.

When `workload_host` differs from `execution_host`, a second explicit
`workload_wrapper` with the same dry-run identity fields is required. This
prevents a remote CLI placement from silently becoming an unwrapped split
placement.

## Commands and boundaries

Compile a contract without contacting a provider:

```bash
python3 scripts/remote_cli_placement.py build \
  --assignment assignment.json \
  --host remote-host.json \
  --route racknerd-route.json \
  --now-utc 2026-08-15T08:00:00+00:00
```

Attach an admitted contract to an already prepared packet. Output is stdout
unless `--output` is explicitly supplied:

```bash
python3 scripts/remote_cli_placement.py attach \
  --packet packet.json \
  --contract remote-cli-contract.json
```

The sidecar does not replace `plan_packet_bridge`, SQLite admission, resource
reservation, or a real adapter. It supplies the missing, reviewable placement
evidence so those later stages can distinguish a genuine server-local CLI
from a local desktop CLI whose workload merely happens to be remote.

## Reviewed execution adapter

`scripts/remote_cli_execution.py` is the separately reviewed server execution
boundary for the two exact routes currently selected by the task-local policy:
`codex.spark/gpt-5.3-codex-spark/xhigh` and
`antigravity.gemini/gemini-3.6-flash-high`.  The placement contract remains
dry-run-only; execution requires a distinct, short-lived authorization record
whose contract digest, model/variant, attempt, quota snapshot digest and
capacity receipt digest all match the contract.

The adapter is also dry-run by default.  Only `--execute` together with
`decision=allow_provider_execution` and `approved=true` can open the remote
CLI.  It rechecks fresh remote authentication and verified RackNerd egress,
confines prompt/result/receipt paths to the remote workspace and write scope,
keeps prompts out of argv, refuses to overwrite an existing result, and emits
only a bounded terminal receipt.  It never logs in, downloads a model, copies
Mac credentials, chooses a fallback, or uses the Mac proxy.  Provider-free
tests use fake executable CLIs and do not contact either provider.
