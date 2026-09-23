# Provider routing and failure semantics

Read this reference only when selecting a provider/model, interpreting live
provider evidence, or configuring an execution adapter. The main skill owns
the authorization workflow; this file does not grant permission to probe or
execute anything.

## Evidence ladder

Keep these facts independent and timestamped:

1. **Installed:** the CLI executable exists in the local system scan.
2. **Catalog-visible:** the exact model/variant appears in a fresh provider
   response or verified local capability cache.
3. **Authenticated:** the current execution context can use the account.
4. **Runtime-accepted:** an authorized real invocation accepted the exact
   model/variant.
5. **Quota-available:** provider evidence shows usable capacity, or an explicit
   bounded-pilot policy permits an unknown balance.
6. **Artifact-valid:** the invocation produced a fresh expected artifact and
   its validator passed.

Higher steps do not rewrite lower ones. Catalog visibility is not runtime
acceptance; authentication is not quota; process exit is not artifact success.
A newer exact invocation outcome outranks an older catalog snapshot for runtime
eligibility.

## Shared pools

| Pool | Shared capacity semantics |
| --- | --- |
| `codex.luna` | approved Luna route and its observed Codex rate-limit bucket |
| `codex.spark` | approved Spark route and its distinct observed bucket |
| `cursor.composer_grok` | all eligible Composer and Cursor Grok members |
| `cursor.other` | all other policy-eligible Cursor members |
| `antigravity.gemini` | Gemini Flash/Pro members shown in the same usage group |
| `antigravity.claude_gpt` | Claude/GPT-OSS members shown in the same usage group |
| `opencode.go` | every OpenCode Go member, including policy-excluded members |

Never split one shared provider allowance into fictional per-model budgets.
Exact model rejections are model-scoped; explicit shared rate/quota failures
are pool-scoped.

## Codex CLI

Use the release's task-local model policies or exact model/effort evidence from
preflight. The approved default lanes are versioned in code and tests, not in a
dated documentation snapshot. If the user explicitly requests a supported
non-default Codex route, pin that exact route and do not silently fall back.

The capability preflight reads the local model cache and sends no prompt. The
usage snapshot reads machine-facing rate-limit evidence. Keep capability and
quota separate, and preserve unknown bucket IDs rather than merging them into a
known pool.

For execution, use a declared Codex adapter with the trusted workspace,
workspace-write sandbox, exact model and effort, and a final-result path. Keep
combined event output in the attempt log; publish only a fresh nonempty final
result as the artifact.

## Cursor Agent and Grok

Cursor supplies a live catalog and authentication state but no dependable
numeric remaining-quota value. An authenticated exact catalog member can be a
bounded-pilot candidate only when the pool declares that policy. The first
authorized real job may establish runtime acceptance; do not spend a separate
prompt merely to turn `runtime_state=unknown` into accepted.

For `cursor.composer_grok`, rank only exact live IDs:

- efficient/code roles prefer the newest Composer family, then eligible Grok;
- hard/audit roles prefer the newest Grok family and strongest advertised
  effort, then Composer;
- blocked IDs are removed before ranking;
- never keep a hard-coded historical Grok version ahead of a newer live one.

Treat these outcomes differently:

- `Cannot use this model`, unsupported, or not-entitled without a rate signal:
  reject the exact model/variant only;
- explicit Composer or Grok usage/rate failure: cool down the whole
  `cursor.composer_grok` pool;
- explicit shared failure for another member: cool down `cursor.other`;
- blank alternatives after a request rejection: preserve the blank response,
  but do not erase a previously successful fresh catalog globally.

### macOS keychain and remote shells

A desktop-authenticated Cursor session may not be usable over SSH. If a
no-prompt status/catalog call reports a locked login keychain or disallowed user
interaction:

1. record `auth_state=unavailable` and
   `auth_error_class=keychain_locked` for that execution context;
2. mark Cursor pools blocked there even if catalog IDs are cached;
3. do not unlock the keychain, read credential values, automate the UI, or copy
   authentication files;
4. ask the user to unlock the keychain on that Mac or execute from its logged-in
   local session, then refresh evidence.

Cursor's print-mode interface places prompt text in process arguments. Keep
secrets out of Cursor prompts. Process identity persists only the normalized
command name, process kind, and PID (plus bounded numeric RSS counters), never
any `argv`; private attempt records may separately
retain sanitized command identity, model, logs, and result metadata. Prefer
adapters that constrain the workspace and output path. The adapter must not add
trust or command-execution flags unless the packet explicitly authorizes them.

The ordinary Cursor editor executable is not proof that `cursor-agent` is
installed. Verify the agent CLI itself and its current auth context. Do not use
the desktop wrapper as an offline fallback because it may install the agent.

A reviewed adapter entry can opt into only the capabilities it needs:

```json
{
  "cursor.composer_grok": {
    "provider": "cursor",
    "adapter": "cursor",
    "transport": "local",
    "cursor_prompt_argv_authorized": true,
    "cursor_sandbox": "enabled",
    "cursor_mode": "plan",
    "cursor_trust_workspace": false,
    "cursor_force_commands": false
  }
}
```

Omit `cursor_mode` for an explicitly approved editing task. Enabling
`cursor_force_commands` or disabling the sandbox is a separate high-trust
choice; neither follows from permission to expose a prompt in local argv.

## OpenCode Go

OpenCode Go is a hosted subscription accessed through an authenticated
OpenCode CLI. Exact members use the `opencode-go/` namespace and all consume the
single `opencode.go` pool.

The read-only snapshot may inspect installed version, configured auth state,
exact catalog, local history, and—when not opted out—the verified account usage
endpoint. Credential values stay in memory and must not enter snapshots.
Local `stats` and database history are historical spend evidence, never a
remaining-balance substitute. Histories from isolated runtime roots must be
collected explicitly and de-duplicated by database identity.

Role preferences are live candidates, not a static allowlist. Preserve exact
model cost, usage multiplier, and advertised variants from the current
catalog. A misspelled or unadvertised variant fails closed.

DeepSeek members stay in shared-pool accounting but are excluded by default. A
bounded task may use one only when it carries both an exact `model_by_pool`
override and an explicit policy-exclusion override. This never creates a new
quota pool.

The bundled guarded runner sends the prompt on stdin and does not enable
dangerous auto-approval implicitly. Server-side OpenCode requires separate
authentication on the verified host; never copy a local auth file into source,
a task packet, or an SSH payload.

## Antigravity

Antigravity `/usage` is the model-quota surface. `/credits` is a separate
wallet and must not be used as evidence that model quota is empty. The bounded
TUI snapshot waits for authenticated readiness, uses a capable terminal, and
may retry the slash command once. A transient login screen or parse failure
leaves quota unknown, not zero.

Use only exact slugs from the current `antigravity models` response. Within
each displayed usage group, the effective availability is the lower of the
weekly and five-hour windows. A model capability/location rejection disables
only that exact member; an explicit group quota failure affects the whole
shared pool. Provider-wide auth, TLS, or zero-progress failure affects both
Antigravity pools.

The guarded Antigravity runner is optional and is not bundled. Configure an
audited path through `ANTIGRAVITY_GUARDED_RUN`; if it is absent, the adapter
must fail closed. Never depend on another skill's private installation path.

## Provider and compute placement

Desktop-authenticated Codex, Cursor, and Antigravity processes normally keep
`execution_host` on the local desktop. OpenCode may use a separately
authenticated, explicitly wrapped remote route. A compute-heavy workload may
use a different verified `workload_host` without moving provider credentials.

A remote host must have a declared project root, compatible commands and
resources, confined prompt/result/artifact paths, and a reviewed transport
adapter. The bundled remote worker seam is not a generic shell runner and does
not imply permission to install software, download data, or invoke providers.

Any server-local model API, including a `server_openai` route, must bind to and
resolve as loopback only. Reach a remote host's loopback endpoint through the
declared SSH transport or an audited loopback-to-loopback tunnel; never expose
the model API directly on `0.0.0.0`, a LAN/Tailscale address, or a public
interface for dispatch convenience.

## Failure decision table

| Evidence | State change | Retry behavior |
| --- | --- | --- |
| exact model/variant rejected | reject that tuple | next eligible tuple in same pool |
| explicit shared quota/rate limit | cooldown or exhaust pool | wait for verified reset or use another pool |
| auth failure | block provider route | refresh only after auth context changes |
| locked macOS keychain | block Cursor in that context | user unlock/local session required |
| TLS/network failure | degrade/block affected route | bounded retry, then alternate provider |
| local disk/RAM/CPU gate | resource failure | approved remote workload attempt only |
| missing/stale result | attempt failed | inspect adapter/log; never infer success |
| validator failure | attempt failed | repair or rerun within declared scope |

Record the latest exact reason, evidence timestamp, cooldown/reset if known,
and the pool/model/host to which it applies. A catalog refresh alone must not
erase a runtime rejection or active cooldown.
