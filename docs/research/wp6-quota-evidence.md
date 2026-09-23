# WP6 — OpenCode Go quota evidence and conservative scheduling

Status: design + provider-free implementation (E1 evidence only).
Scope: the shared `opencode.go` pool only. No Mission, resource, scheduler,
provider-adapter, or CPS files are touched.

## Problem

The OpenCode Go catalog exposes `opencode-go/deepseek-v4-flash` (and other
members), but the machine-readable OpenCode CLI snapshot does not expose the
current remaining five-hour/weekly/monthly balance. The CLI snapshot must
therefore report `unknown`; fabricating a balance (zero or full) is forbidden.

OpenCode Go is one shared subscription pool. A quota or rate-limit failure
from any member (including DeepSeek V4 Flash) cools or blocks the whole
`opencode.go` pool. Model-specific price/usage multiplier metadata is
accounting inside the pool; it is not a separate remaining-quota signal and
never rescues an exhausted pool.

## Evidence classes

| Evidence | Source | Meaning | Does not prove |
| --- | --- | --- | --- |
| `catalog_state=visible` | `opencode models opencode-go --verbose` | exact ID listed | runtime acceptance or remaining quota |
| `auth_state=configured` | `opencode providers list` | credential exists | validity for a model or remaining balance |
| `history` / `receipt` | `opencode stats`, before/after receipts | historical spend | remaining balance |
| `api` | explicitly verified operator-supplied HTTPS endpoint | account-level rolling/weekly/monthly usage and reset evidence | deployment, per-model attribution, or Zen wallet amount |
| `console` | explicit user-supplied read-only export | account remaining/reset values | exclusive consumption attribution |
| `runtime_error` | 429 / reset hints / quota text | observed pool-level backpressure | a model-family-specific balance |
| `manual` | operator statement | reviewed value | anything newer than its TTL |

## Record

Versioned record (`schemas/quota_evidence.schema.json`, `schema_version=1`):

- `source` ∈ `console|api|receipt|history|runtime_error|manual`
- `observed_at_utc`, `scope_hash` (SHA-256 of canonical pool scope)
- `window` ∈ `five_hour|weekly|monthly` (nullable for unclassified events)
- `remaining_percent`, `remaining_amount`, `cap_amount` (all nullable)
- `reset_at_utc` (nullable), `confidence`, `ttl_seconds`, `discrepancy`
- `attribution` ∈ `exclusive|confounded|unknown` (concurrent-pool labeling)
- `exact_balance` (numeric value is provider-supplied, not derived)
- `overage_fallback_state` ∈ `unknown|enabled|disabled`

Unknown values remain `None`; `remaining_percent=0` or `=100` require exact
evidence.

## Console import

`parse_console_snapshot` imports an explicit read-only export:

- Refuses (fails closed, exit 3) any credential-like key anywhere in the file;
  only key names are reported, never values.
- Preserves `overage_fallback_state`; a Zen balance is recorded separately
  with `is_free_quota=false` and never merged into remaining quota.
- Normalizes timestamps, flags discrepancies: reset in the past, percent
  outside [0,100], percent/amount/cap disagreement, and reset-ordering
  contradictions (`five_hour <= weekly <= monthly`).
- Windows absent from the snapshot remain `unknown`, never zero/full.

## Optional user-verified usage endpoint

The public Go documentation currently exposes plan limits and the console, not
a guaranteed CLI balance API. Search results and feature requests are treated
as discovery hints only. `opencode_go_quota_snapshot.py --usage-api` therefore
requires both an explicit `--usage-endpoint https://...` and an explicit
credential source; normal preflight never calls it. If an operator verifies a
compatible endpoint for the current account, the helper holds the key in
memory, records endpoint/probe evidence, and normalizes its `percent` field
from *used* to remaining. `rolling` is normalized to `five_hour`; all models
still consume the one shared `opencode.go` pool. If the endpoint fails or its
shape is incompatible, the planner retains `unknown` and uses the explicit
pilot/block policy.

## Historical spend

Local stats and before/after receipts are spend evidence only
(`spend_bounds`, `kind=historical_spend_evidence`). When the window cap is
unknown, remaining-percent bounds are withheld (`None`). When caps are known
and spend is fully known, a conservative interval `[100·(1−max/cap),
100·(1−min/cap)]` is produced and labeled as a bound, not a balance.
Attribution: `exclusive` only when every receipt declares exclusivity and no
temporal overlap exists; otherwise `confounded` or `unknown`.

## Runtime classification

`classify_runtime_failure` maps 429 / rate-limit / quota / auth text (and
`Retry-After`, `resets in N h|m`, `resets at ISO` hints) to pool-level
events on `opencode.go`, retaining the exact model and variant in the event.
Estimated resets are flagged `reset_estimated`. Capability rejections
(`Cannot use this model`, `not entitled`, ...) affect only that exact model
tuple and never cool the pool. Unclassified failures do not claim pool level.

## Multipliers and pilot

- `effective_multiplier`: exact model > longest family/provider prefix >
  pool default. Missing multipliers are not fabricated.
- `pilot_decision`: with a known balance, pilot is allowed above 0% and
  `ready_claim` requires effective percent above the reserve. With an unknown
  balance, a pilot is allowed only under an explicit
  `unknown_quota_policy=pilot` with catalog visibility and configured auth;
  per-lane cost/token caps and a reserve are mandatory, and
  `ready_claim=false` — catalog visibility alone never sets ready.

## Security boundaries

No model prompt is sent and no credential value is emitted. Authenticated API
usage is opt-in and limited to an operator-verified HTTPS endpoint; the key is
read only when the operator selects an environment variable or auth-store
source.
Without `--usage-api`, the helper uses only the documented CLI commands
(`--version`, `providers list`, `models opencode-go --verbose`, `stats --days N
--models`) plus explicit console import.

## Files

- `schemas/quota_evidence.schema.json`
- `src/local_agent_dispatch/quota/evidence.py`
- `scripts/opencode_go_quota_snapshot.py`
- `tests/test_opencode_go_quota.py`
- `research/fixtures/quota_console.json` (sanitized)

## Limitations

- The CLI catalog alone has no numeric balance. Balance becomes `known` after a
  successful operator-verified usage response, console import, or equivalent
  manual evidence. A catalog or issue search is never sufficient.
- Console values are account-level; concurrent consumers are not
  attributable, so `attribution=unknown`.
- Reset hints in failure text are estimates and flagged as such.
- This is provider-free E1 evidence; no real OpenCode Go spend was made.

## Source provenance

- [OpenCode Go documentation](https://opencode.ai/docs/go) is authoritative for
  plan windows, pricing, and the console, not for a local machine's current
  balance.
- [Issue #31084](https://github.com/anomalyco/opencode/issues/31084) is a feature
  request describing a possible usage route; its text is discovery evidence,
  not proof that the endpoint is deployed. This distinction is intentional.
