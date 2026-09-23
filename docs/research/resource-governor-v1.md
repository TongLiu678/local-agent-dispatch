# Resource Governor v1

## Why this is a separate subsystem

The scheduler answers whether a task fits a host in a plan. It cannot by itself
protect a live desktop: provider CLIs, MCP servers, renderers, compilers, and
model runtimes can grow after admission, while macOS compression and swap make
the instantaneous free-memory number lag behind the real failure point. A
separate governor therefore owns the live admission and degradation decision.

```text
observe -> attribute -> reserve headroom -> admit/throttle/pause -> replan
```

The governor does not replace the planner and does not kill arbitrary desktop
processes. It may identify only controller-owned PIDs as future pause/resume
candidates; unowned Codex, IDE, MCP, and system processes remain advisory.

## Signals

- physical total and available memory;
- swap total/used/free and, where available, compressor or PSI pressure;
- RSS, virtual size, and CPU for canonical process names only (never argv);
- controller ownership, lease, lane, model pool, and workload host;
- declared P50/P90 per-lane peak and a fixed reserve for the desktop.

RSS is an attribution signal, not a sum to compare blindly with physical RAM:
shared pages and virtual mappings can be counted more than once. Admission uses
available memory, swap pressure, and a reserve; RSS is used to explain and rank
contributors.

## Tiers and actions

| Tier | Admission | Controller action |
| --- | --- | --- |
| normal | bounded by reserve and per-lane peak | admit or throttle |
| conserve | no new local lanes | route compatible work to a verified server; shorten next wave |
| critical | no new lanes | pause only owned lanes after lease/fence check; replan |
| emergency | no new lanes | pause owned lanes, surface a human stop; never kill unowned processes |

The transition thresholds have hysteresis in the monitor integration (the
current pure report is deliberately stateless). A recovery requires two
consecutive healthy samples, so a single transient free-memory spike cannot
cause a new fan-out.

## Required controller integration

1. Reserve memory and pool slots in the same SQLite transaction as the attempt
   claim; a planner-only reservation is not sufficient.
2. Attach `owner_id`, `lease_token`, `pid`, `model`, `pool_id`,
   `execution_host`, and `workload_host` to every launched lane.
3. On conserve, stop admission and submit a copy-on-write replan constraint;
   do not kill an active attempt automatically.
4. On critical/emergency, send a bounded pause/cancel to owned process groups,
   record the signal and evidence, and preserve a resume handoff. An absent or
   expired lease means “do not signal”.
5. Poll at 30 seconds by default, persist every decision, and sample at 5–10
   seconds during emergency recovery. Quota and server resource observations
   remain separate from local agent pressure.

## Current implementation boundary

`scripts/resource_governor.py` remains a provider-free, non-destructive report:
it parses canonical process names, computes pressure tiers, applies a persisted
JSON-safe hysteresis state (`update_hysteresis`), estimates bounded lane
capacity, and emits actions. Worsening pressure is immediate by default;
recovery requires two consecutive healthy samples. It explicitly reports
`automatic_kill=false`. Schema-v3 SQLite reservations now provide the fenced
claim/heartbeat/release ledger for packets that carry `resource_request`; the
strict CLI controller invokes the governor before claiming those packets.
The provider-free `scripts/owned_process_control.py` seam now proves that a
fake pause/resume reaches its backend only with an explicitly owned process,
the complete identity `(pid,start_time,process_group,run_id,fence)`, and a
matching active lease; its receipt is redacted and records no OS signal. The
remaining gates are live identity registration, durable monitor/controller
wiring, and OS-native PSI/macOS pressure integration; no automatic signal is
enabled yet.
