# Reference harness adapters

`local_agent_dispatch.adapters.harness` is a provider-free reference layer for
the public `AgentHarness` lifecycle. It separates lifecycle policy from the
code that actually starts or controls an agent process:

```text
persisted evidence + lifecycle request
                 -> pure command planner
                 -> injected runner boundary
                 -> sanitized lifecycle result + durable handle
```

Importing, constructing, checking conformance, registering, and reading
capabilities do not start a subprocess or contact a provider. The package does
not import `subprocess`. An application must explicitly inject a runner and
invoke `submit`, `observe`, `heartbeat`, `cancel`, `collect`, or `resume` before
the execution boundary can be crossed. `prepare` only validates and hashes an
ephemeral plan.

## Generic injected-runner lifecycle

`InjectedRunnerHarness` takes three inert dependencies:

- a `CapabilityResult` snapshot collected before adapter construction;
- a pure `CommandPlanner` that returns a `CommandPlan`;
- a callable `HarnessRunner` that accepts `RunnerInvocation` and returns a
  sanitized `RunnerOutcome`.

`CommandPlan.argv` is excluded from `repr` because some CLIs carry the prompt
there. Logs and receipts must use `redacted_argv` or `summary`. Plans are kept
ephemeral; lifecycle results contain only a redacted summary, handle identity,
declared artifact references, and runner-supplied sanitized data.

The reference lifecycle provides:

| Property | Reference behavior |
| --- | --- |
| Submit idempotency | The same operation and idempotency key returns its first receipt without calling the runner again. Reuse with a different request is a conflict. |
| Fencing | Integer generations advance monotonically; older generations are rejected before the runner. An opaque token must remain identical because the adapter cannot prove ordering. |
| Durable identity | Submit handle IDs are deterministic from plugin/job/attempt/idempotency identity and contain no prompt. A reconstructed adapter can pass the persisted handle to the same durable runner. |
| Cancellation and collection | Both are explicit runner calls. Collection rejects any artifact reference not declared by the request. |
| Failure isolation | Runner or planner exceptions become classified plugin failures; their exception text is not copied into receipts. |

The in-process receipt and fence maps make retries safe inside one adapter
instance. A production runner and receipt store must also atomically persist
external submission idempotency and fence generations. The adapter deliberately
does not claim that process memory alone is crash-durable.

## Cursor Agent reference adapter

`CursorAgentHarness` consumes previously collected `Evidence` objects. It
never runs auth or catalog discovery itself. Ready auth evidence must contain
one explicit authenticated fact: `authenticated: true`,
`isAuthenticated: true`, or `auth_state: authenticated`. Ready catalog
evidence must contain a `models` sequence of exact, non-empty IDs. Unknown,
blocked, unavailable, malformed, or empty evidence fails closed.

Every prepare/submit request supplies these options:

```python
{
    "model": "exact-id-from-injected-catalog",
    "prompt": "bounded task text",
    "cursor_prompt_argv_authorized": True,
    "cursor_sandbox": "enabled",
    "workspace": "/absolute/containing/workspace",
    "write_scope": "relative/bounded-root",
    # Optional read-only Cursor modes: "plan" or "ask".
    "cursor_mode": "plan",
}
```

The planner uses the resolved `write_scope`, not the broader containing
workspace, for both the process working directory and Cursor's `--workspace`
argument. The scope must remain inside the declared workspace and cannot be a
filesystem root. The emitted shape is:

```text
cursor-agent --print --workspace <write-scope> --model <exact-id>
  --sandbox enabled [--mode plan|ask] -- <prompt>
```

Cursor's current print interface places prompt text in local process argv and
has access to write and shell tools. The adapter therefore requires the
literal `cursor_prompt_argv_authorized=True`; authorization for a provider or
workspace does not imply authorization to expose prompt text in argv. Keep
credentials and other secrets out of such prompts.

The reference planner never emits `--trust`, `--force`, `-f`, or `--yolo` and
rejects requests for the corresponding privilege options. Sandbox disablement,
catalog aliases, fuzzy model matches, implicit workspaces, and escaping write
scopes are unsupported. The executable may be the literal `cursor-agent`
command or an absolute path whose basename is exactly `cursor-agent`.

## Minimal provider-free wiring

```python
from local_agent_dispatch.adapters.harness import CursorAgentHarness
from local_agent_dispatch.plugins import Evidence

harness = CursorAgentHarness(
    runner=my_explicit_runner,
    auth_evidence=Evidence("ready", {"authenticated": True}),
    catalog_evidence=Evidence("ready", {"models": ["exact-model-id"]}),
)
```

Construction above only stores values and builds a pure planner. The injected
runner is responsible for implementing the actual Cursor session/process
lifecycle, durable external receipts, bounded environment, timeouts, and safe
termination. Registration is not permission to submit; controllers must still
hold their lease and apply quota, resource, path, and artifact-validation
gates.
