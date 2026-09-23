# Adaptive scheduling policy

`local_agent_dispatch.scheduler.policy` is a provider-free policy engine. It
does not read configuration files, probe a host, call a provider, launch a
worker, or persist controller state. A controller supplies already-validated
policy values and fresh observations, receives a deterministic decision, and
owns any subsequent state transition.

## Three policy layers

The layers have distinct authority:

1. `SafetyInvariants` is deployment-owned and immutable. It fixes the absolute
   concurrency ceiling, minimum RAM and disk reserves, minimum quota reserve,
   and maximum acceptable error rate. Fresh telemetry is mandatory and unknown
   evidence always maps to concurrency zero.
2. `OrganizationPolicy` is a revisioned, hot-reloadable value. It supplies the
   normal concurrency range, operational reserve thresholds, latency target,
   AIMD parameters, scale-up hysteresis, and cooldown. A caller validates a new
   value and atomically replaces the old bundle with
   `SchedulingPolicyBundle.with_organization`; the module performs no file
   watching itself.
3. `TaskPreferences` contains optional task-local preferences. A task can ask
   to lower the normal concurrency minimum, lower the concurrency maximum, or
   apply stricter reserve/error thresholds, and can choose a latency target. A
   task cannot raise the organization's minimum (and thereby compel more
   work), raise an inherited ceiling, or lower an inherited safety/resource
   floor.

`resolve_policy` applies the layers in that order. Floors use `max`, ceilings
use `min`, and fields are visited in a fixed order so diagnostics are stable.
An attempted weakening is ignored and returned as a warning. In particular,
`preferred_min_concurrency` is resolved with `min`: it may reduce an
organization's operational floor but never increase it. An organization
minimum above the safety-bounded maximum is an impossible policy: resolution
returns `valid=false`, and adaptive scheduling returns concurrency zero. A
task-level minimum above its effective maximum is only a preference conflict;
it is clipped and diagnosed.

The wire representation is versioned as
`local-agent-dispatch.scheduling-policy.v1`. Its closed JSON Schema is
`schemas/scheduling_policy.schema.json`. Unknown keys, duplicate JSON keys,
non-finite numbers, Boolean-as-integer values, and unknown versions are
rejected by the Python model.

## Adaptive concurrency

`adapt_concurrency` consumes:

- immutable `AdaptiveConcurrencyState` from the previous evaluation;
- a valid resolved policy;
- a `ResourceSnapshot` and its correlated `WorkerHeartbeat`;
- revisioned `ProviderSignals` for maximum concurrency, remaining quota,
  observed error rate, latency, and an explicit three-valued timeout signal;
  and
- `TaskResourceEstimate` for CPU, RAM, swap, per-device GPU memory, disk,
  inodes, and owned-process RSS per additional slot plus the exact mount used
  by the task.

Every per-slot dimension must be explicit. `None` means unknown and blocks
admission; zero means the caller has positively declared that the task does
not consume that dimension. CPU must be positive when known. This distinction
prevents an omitted GPU, swap, inode, or RSS estimate from silently becoming
zero demand.

Every observation must be fresh, positively confident, and sequence-monotonic.
The heartbeat must match the snapshot's host, worker, fence, and resource
sequence. Missing TTL, stale or future-dated evidence, incomplete provider
signals (including an unknown timeout flag), a sequence rollback, unknown
reservation reconciliation, or a missing exact writable mount fails closed to
concurrency zero. Relevant CPU availability, cgroup ceilings, swap, every
GPU's available memory, exact-mount free inodes, and owned-process RSS must be
known. The controller never turns unknown capacity into zero usage or guessed
headroom. Mount evidence is canonicalized before exact comparison: slash style,
drive-letter case, and Windows path case cannot create a false missing-mount
result, while POSIX comparison remains case-sensitive.

The hard cap for a healthy evaluation is the minimum of:

- resolved policy maximum;
- provider-reported maximum; and
- the multidimensional resource cap after reserves and the per-slot estimate.

The resource cap takes the minimum safe slot count across CPU, RAM, swap,
disk, inodes, owned-process RSS, and—when requested—GPU memory. GPU slots are
counted per device before summing, so fragmented memory on several devices is
not treated as one fictitious large GPU. Owned-process RSS is correlated with
the heartbeat's actual usage; incomplete or conflicting evidence blocks
admission.

Quota at or below the resolved reserve closes admission. A lower provider or
resource cap takes effect immediately. Ordinary error, latency, or
actual-usage pressure uses multiplicative decrease. A complete error window
(`error_rate == 1`) or an explicit provider timeout opens the circuit and
sets concurrency to zero even when the organization minimum is nonzero. An
unknown timeout signal also fails closed. There is no implicit one-lane probe:
a controller that wants probes must model and authorize them separately, while
the scheduler remains closed by default. Healthy evidence uses additive
increase only after the configured number of distinct healthy observation
windows and after the cooldown has elapsed. Re-evaluating identical sequence
numbers does not advance hysteresis. A busy worker may hold its safe limit but
cannot trigger an increase; draining, stopped, or unknown workers close
admission.

This is bounded AIMD, not a fixed lane count. No default such as “twelve
workers” is embedded in the algorithm: every ceiling comes from safety policy,
organization/task policy, current resources, or provider evidence.

## Controller integration

The packaged CLI exposes the same pure functions without crossing the evidence
boundary:

```console
lad scheduler resolve --input policy-bundle.json
lad scheduler decide --input scheduler-decision-input.json
```

`resolve` accepts exactly one `SchedulingPolicyBundle` object. `decide` accepts
the versioned envelope defined by
`schemas/scheduler_decision_input.schema.json`: policy bundle, previous state,
resource snapshot, correlated heartbeat, provider signals, task estimates, and
an explicit RFC 3339 `now`. Both commands accept `--input -` for stdin, reject
duplicate keys and unknown fields at every modeled layer, and emit
machine-readable JSON. A valid blocked decision exits successfully with
`target_concurrency: 0`; malformed or ambiguous input exits with code 2.

These commands only replay caller-supplied evidence. They do not run a system
probe, inspect live memory, contact a provider, send a prompt, open a network
connection, launch a worker, or mutate controller state. Their output includes
an `evidence_boundary` receipt stating those negative facts. Supplying `now`
is mandatory so freshness decisions are deterministic rather than dependent
on the CLI host's wall clock.

A controller embedding the library can call the same pure evaluator directly
and should keep the policy bundle and adaptive state in its own transaction
boundary:

```python
from local_agent_dispatch.scheduler.policy import adapt_concurrency

decision = adapt_concurrency(
    state=previous_state,
    policy=resolved_policy,
    resource_snapshot=resource_snapshot,
    heartbeat=worker_heartbeat,
    provider=provider_signals,
    task_resources=task_estimate,
    now=controller_time,
)
```

Persist or publish `decision.next_state` only if the surrounding controller
accepts the decision under its own fence. Reducing a concurrency limit prevents
new admissions; it is not authorization to kill running work. Provider calls,
probing, file watching, durable storage, and worker lifecycle actions remain
outside this module and retain their separate authorization boundaries.
