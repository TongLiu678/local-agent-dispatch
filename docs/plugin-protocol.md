# Plugin protocol boundary

`src/local_agent_dispatch/plugins/` is the stdlib-only public seam between the
LAD control plane and optional integrations. It contains data contracts,
structural protocols, and explicit registration only. Importing the package or
registering a plugin does not contact a provider, open SSH, start a subprocess,
or read an artifact.

The package-level `PLUGIN_API_VERSION` remains `"1"`. Existing v1 plugins keep
their original method sets; the scheduling lifecycle below is an additive v1
extension. Lifecycle request, result, handle, and artifact objects carry the
independent wire-shape version `lad.plugin.lifecycle/1.0`.

## Plugin kinds

The original five kinds remain unchanged:

| Kind | Required operations | Role |
| --- | --- | --- |
| `system_probe` | `probe(request)` | Read local OS, hardware, and installed-runtime evidence |
| `provider` | `discover_catalog`, `discover_auth_state`, `discover_quota`, `probe_runtime`, `execute` | Provider catalog, account, quota, acceptance, and legacy execution boundary |
| `runtime` | `probe`, `execute` | Local/server inference runtime such as vLLM, Ollama, or llama.cpp |
| `transport` | `prepare`, `execute` | Bounded local/SSH workspace or artifact transport |
| `validator` | `validate(request)` | Independent artifact freshness and quality validation |

Three additive kinds separate agent orchestration from model providers,
inference runtimes, and transports:

| Kind | Required operations | Role |
| --- | --- | --- |
| `agent_harness` | full scheduling lifecycle | Agent CLI/session boundary such as Codex, Cursor, or OpenCode |
| `batch_scheduler` | full scheduling lifecycle | Queue/runtime boundary such as local, PBS, Slurm, or Kubernetes |
| `artifact_store` | `capabilities`, `prepare`, `collect` | Validate/reserve and later materialize declared artifact references |

The full scheduling lifecycle is:

```text
capabilities -> prepare -> submit(handle)
                         -> observe / heartbeat
                         -> cancel
                         -> collect(artifact references)
                         -> resume (reattach persisted handle)
```

`provider`, `agent_harness`, `runtime`, `transport`, and `batch_scheduler` are
different boundaries even when one product happens to implement several of
them. A model name, CLI name, SSH route, and scheduler job ID must not be
collapsed into one untyped adapter string.

## Lifecycle data contracts

The public types are immutable dataclasses and perform no I/O:

| Contract | Required durable information |
| --- | --- |
| `CapabilityRequest` / `CapabilityResult` | Dynamic, host-scoped capabilities and classified unavailable/unknown evidence |
| `PrepareRequest` / `PrepareResult` | Job/attempt identity, idempotency key, fence token, declared artifact references, optional preparation ID |
| `SubmitRequest` / `SubmitResult` | Prepared attempt plus a durable `ExecutionHandle` for every accepted/running submission |
| `ObserveRequest` / `ObserveResult` | Persisted handle and current state without inferring completion from a PID |
| `HeartbeatRequest` / `HeartbeatResult` | Ownership renewal under the current fence token |
| `CancelRequest` / `CancelResult` | Idempotent cancellation request and classified outcome |
| `CollectRequest` / `CollectResult` | Only declared `ArtifactReference` values, never an implicit directory crawl |
| `ResumeRequest` / `ResumeResult` | Reattach to a persisted handle, optionally with a declared checkpoint reference |

`ReattachRequest` and `ReattachResult` are public spelling aliases for the
resume wire shape. The protocol operation is named `resume`.

### Idempotency and fencing

Every stateful lifecycle request requires a non-empty `idempotency_key` and a
non-negative integer or non-empty opaque-string `fence_token`.

- Retrying the same logical operation with the same idempotency key must not
  create another external job, session, transfer, or artifact.
- `submit` returns an `ExecutionHandle` containing the submit idempotency key
  and fence token; controllers persist the handle before relying on it.
- A stale owner must be rejected with `status="blocked"` or `status="error"`
  and `error_class="fenced"`. A plugin must not silently accept an older fence.
- `observe`, `heartbeat`, `cancel`, `collect`, and `resume` bind the request's
  job/attempt identity to the persisted handle.

These dataclasses validate shape only. Comparing fence generations and
persisting idempotency receipts remain atomic responsibilities of the
controller and concrete plugin.

### Errors and artifacts

Lifecycle results always carry an explicit `error_class`. Successful states
(`ready`, `accepted`, `pending`, `running`, `succeeded`) require `none`.
Failure states require a classification such as `authentication`, `quota`,
`rate_limit`, `resource`, `transport`, `timeout`, `cancelled`, `validation`,
`conflict`, `fenced`, `not_found`, `plugin`, or `unknown`.

Artifacts cross the protocol as `ArtifactReference` values. A reference has an
opaque URI/path, role, optional digest, media type, size, and safe metadata.
Constructing it never opens the URI. A plugin may return an undigested staging
reference, but LAD's existing promotion policy may still require a fresh
digest and independent validator before declaring success.

## Registration and conformance

Each plugin exposes a static `PluginDescriptor` named `descriptor`.
`PluginRegistry.register()` and `conformance_report()` use static inspection:
they do not bind descriptors, evaluate properties, call operation methods,
scan Python entry points, or import optional integrations. A computed
`descriptor` property is therefore non-conforming; metadata must be inert.

Static conformance checks:

- stable plugin ID, known kind, and API version;
- non-empty plugin version and unique capability labels;
- the complete callable surface for the declared kind, including the eight
  lifecycle methods for harnesses and batch schedulers.

`register_many()` returns one report per plugin and isolates malformed
plugins. Only an explicit later `registry.invoke(...)` call can execute an
operation. Invocation remains subject to controller lease, path, quota,
resource, and authorization gates; plugin exceptions are returned as redacted
local failures.

## Provider-free example

```python
from local_agent_dispatch.plugins import (
    CapabilityRequest,
    CapabilityResult,
    PluginDescriptor,
)

class OfflineHarnessSkeleton:
    descriptor = PluginDescriptor(
        "offline-skeleton",
        "agent_harness",
        capabilities=("submit", "resume"),
    )

    def capabilities(self, request: CapabilityRequest) -> CapabilityResult:
        return CapabilityResult(
            status="unknown",
            error_class="unknown",
            reason="fixture has no live harness",
        )

    # prepare, submit, observe, heartbeat, cancel, collect, and resume must
    # also be present before this skeleton can be registered.
```

The conformance tests use only in-memory fakes. They introduce no provider
SDK, subprocess, filesystem mutation, or network request.

## Security boundary

The registry is structural isolation, not a sandbox or trust boundary. A real
plugin still needs an allowlist, least-privilege credentials, timeouts, path
confinement, secret filtering, and ideally an out-of-process plugin host.
Capability labels are declarations, not permissions. Registration never makes
a route ready, and a successful process or scheduler state never replaces
artifact validation.
