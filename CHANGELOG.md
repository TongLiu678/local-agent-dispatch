# Changelog

All notable user-visible changes to local-agent-dispatch are recorded here.
The project follows the spirit of [Keep a Changelog](https://keepachangelog.com/)
and uses semantic versioning for package releases.

## [Unreleased]

## [0.1.0-alpha.6] - 2026-09-23

### Security

- Added a deterministic public-snapshot exporter with a closed, count-bound
  redaction policy, exact Git-ref binding, redacted manifests, and fail-closed
  handling for repository paths, Git object access, and private policy files.
- Hardened the release path against ambient Git configuration, replacement
  objects, lazy-fetch/network side effects, unsafe cross-platform paths, and
  accidental export of the private redaction policy itself.
- Closed receipt-redaction metadata overrides, execution-handle rebinding,
  non-finite manifest metadata, and cross-platform package/scaffold path
  ambiguities.

### Fixed

- Made the public-export contract tests portable to Windows while retaining
  POSIX executable-mode assertions where the filesystem exposes them.
- Removed the hard-coded public egress expectation from the provider canary;
  live egress must now be supplied explicitly and missing evidence blocks the
  run.
- Bound evolution outcomes to exact composition plans and independent evidence
  receipts; enforced lineage cardinality and strictly newer revisions.
- Made large-vector cosine scoring overflow-safe, exact package constraints
  build-metadata-aware, and skill cost admission decimal-exact. Composition
  now fails closed at explicit computation bounds.
- Preserved scheduler sequence watermarks on regressed evidence, accounted for
  reserved CPU threads, and canonicalized Windows mount evidence.

## [0.1.0-alpha.5] - 2026-09-23

### Changed

- The skill entry point is now a compact mode router with provider details in
  progressive-disclosure references; dated catalog/readiness snapshots no
  longer influence routing guidance.
- Cursor execution now requires explicit acknowledgement of argv prompt
  exposure. Workspace trust and forced command execution are independent,
  opt-in adapter capabilities; controller diagnostics redact even short Cursor
  prompts by position.
- SQLite controller storage now verifies macOS and Windows volume locality and
  blocks SMB, NFS, ephemeral, or unknown filesystems in strict mode before
  opening the database. Temporary and container-overlay paths are no longer
  reported as persistent continuity storage.

### Fixed

- Cursor Composer/Grok role selection now ranks exact live model IDs by family,
  version, and role instead of falling back to lexicographic or unrelated
  catalog entries. A Grok-only authenticated catalog is schedulable, and the
  same case-insensitive classifier now partitions catalogs without duplicates.
  Process occupancy recognizes both current `--print` and legacy `-p` Cursor
  invocations, preserving shared-pool concurrency limits.
- Locked macOS keychains and unavailable SSH signing agents are classified
  separately from network refusal, including when partial probe diagnostics
  arrive at timeout.
- Local launch admission now blocks Python versions below the package's 3.10
  minimum, and system inventory reports Cursor Desktop separately from the
  standalone `cursor-agent` CLI.

### Added

- Open-source contribution and security guidance.
- A strict adaptive scheduler API and offline CLI with layered policy
  resolution, filter-score-reserve-reconcile fencing, resource/quota gates,
  and AIMD concurrency decisions from saved evidence.
- Portable worker registration, capability/resource heartbeat, execution, and
  harness contracts, including an explicit Cursor lifecycle adapter and
  Windows/POSIX file locking for controller and remote spool state.
- A Homebrew/pip-shaped local package ecosystem with strict manifests,
  deterministic dependency resolution and lockfiles, verified atomic installs,
  exact activation generations, rollback, and safe uninstall. `kind=skill`
  packages are inert and require a digest-bound root `SKILL.md`.
- Body-free skill search and exact 3/5/10 composition, latent-space
  similarity/redundancy/coverage analysis, outcome/lineage-based evolution
  proposals, and atomic `lad skill create` scaffolding. Creation, installation,
  indexing, enablement, and execution remain distinct authorization boundaries.
- Provider-free GitHub CI checks for the CLI, schemas, scanner, planner,
  controller, and shell helpers.
- `lad plan`, `lad run`, `lad monitor`, `lad replan`, `lad resume`, `lad
  enqueue`, and `lad status` control-plane commands.
- Explicit `lad preflight` command that performs the local hardware stage before
  provider and SSH discovery without sending a model prompt.
- Opt-in SQLite WAL controller with lease fencing, atomic claims/completions,
  restart recovery, and fake-provider execution coverage.
- Modern controller/SQLite enqueue now validates packet shape, artifacts,
  validator, exact attempt fields, and secret-like keys; legacy queues require
  an explicit `legacy_compatibility` marker.
- Unknown quota is fail-closed by default. Provider preflight may explicitly
  opt into a bounded pilot cap (5% default for Cursor/Antigravity/OpenCode Go)
  rather than fabricating a remaining-balance percentage.
- OpenCode Go policy-excluded DeepSeek models remain off by default but can be
  selected only through an exact, user-authored task-level opt-in.
- Monitor placement now keeps `execution_host` separate from `workload_host`
  and reports missing split-workload telemetry as `unknown` instead of treating
  a local provider process as evidence that remote compute is healthy.
- Cursor Composer/Grok and Antigravity shared pools now expose role candidates
  to the planner, so hard jobs can prefer the stronger visible member without
  creating a second quota counter. Unknown CPU/RAM/disk capacity is also
  fail-closed unless a job explicitly opts into unknown capacity.
- Non-editable wheel installs now discover bundled scripts under both standard
  `sysconfig` data roots and `pip --target` layouts; CI smoke-tests that path.
- Task estimation now carries explicit P50/P90 input/output-token bounds into
  model-price-aware USD estimates without treating missing evidence as zero.
- Local/remote fit consumes discovered writable non-root storage mounts and
  adds hard local load/disk-pressure gates; unknown-quota pools are capped to
  one pilot lane.
- `lad monitor-state` and `controller_monitor_adapter.py` project SQLite
  snapshots into prompt/argv-safe monitor workers; SQLite launches can publish
  a confined live PID breadcrumb, while absent telemetry remains `unknown`.
- Controller-owned timeout messages are classified as stalls rather than
  provider/network failures, and capability feedback persists exact
  model/variant runtime evidence for the next preflight.
- New queues now use a SQLite-first `--backend auto` path; read-only status and
  resume report `not_initialized` without creating a database, while existing
  JSON runs remain compatible.
- Added provider-free task capture with bounded repository metadata, DAG
  parallel waves, per-node P50/P90 estimates, and task-family/model/host
  history calibration with EWMA and bias evidence.
- Added a durable remote-worker contract with fenced leases, artifact hash
  freshness completion, bounded fake execution, and prompt/argv-safe resume
  handoff reports. It is not evidence of a live provider or SSH runtime.
- Capture packets now expose versioned, planner-compatible `planner_jobs` so a
  reviewed provider-free capture can be passed directly to `lad dispatch`.
- Capture planner IDs are now safe for remote spool paths; explicit model
  allowlists are enforced after planning, and stale captured resource hints are
  cleared when current evidence becomes unknown.
- Added a provider-free SSH worker transport with strict host/path validation,
  redacted stdin packet delivery, dry-run-by-default execution gates, and
  placement-aware fake-SSH tests. Artifact observations are read-only unless a
  current worker lease fence is supplied.
- SSH `server_openai` attempts now write and validate artifacts on the remote
  workload host instead of inspecting a local path; remote traversal/symlink
  escape is rejected and the bridge refuses local absolute validator paths.
- SQLite multi-lane execution now contains heartbeat/adapter exceptions per
  lane, records a fenced controller failure, and preserves sibling results
  instead of allowing one future to tear down the whole batch.
- SSH compute probing now gives read-only AutoFS/non-root mount discovery a
  bounded 20-second default and passes the same budget from preflight, avoiding
  false host-unreachable results on slow data mounts while remaining fail-closed.
- SSH preflight failures now preserve bounded transport classes for timeout,
  connection refusal, DNS failure, and authentication failure without storing
  raw stderr or weakening fail-closed admission.
- Durable SQLite lease and retry timestamps now normalize RFC 3339 `Z` suffixes
  on Python 3.10, keeping legacy server scheduling behavior consistent with
  newer runtimes.

## [0.1.0-alpha.4]

This public Alpha snapshot aligns the installable package with the published
`v0.1.0-alpha.4` repository ref. It includes the provider-free control-plane
contracts, SQLite/resource admission boundaries, privacy scrub, and the
server-side OpenCode Go bounded-canary seam. It does not claim a persistent
remote service, a 24-hour soak, or unrestricted provider concurrency.

## [0.1.0-alpha.1]

This is the first public Apache-2.0 Alpha snapshot. It includes the SQLite
controller, resource-governor reports, Mission/CPS capture, legacy-history
import boundaries, remote-worker contracts, and an experimental server-side
OpenCode Go canary seam. Provider/server evidence is opt-in and is not part of
the provider-free CI claim.

- Preflight no longer probes a guessed OpenCode Go balance URL. The optional
  usage helper requires an explicitly verified HTTPS endpoint; otherwise the
  shared pool remains quota-unknown and uses the configured pilot/block policy.

## [0.1.0]

### Added

- Installable `lad` entry point with offline `doctor`, `demo`, `scan`, `fit`,
  and planner-to-controller `bridge` commands.
- Read-only local hardware discovery and server-fit reporting with explicit
  CPU, memory, GPU/VRAM, disk, runtime, and placement evidence.
- Schema validation for task packets, dispatch plans, runtime state, and
  events, including public-snapshot secret checks.
- Dynamic planning, shared-pool accounting, and quota-continuity references
  for Codex, OpenCode Go, Cursor, Antigravity, and server-local runtimes.
- A durable controller foundation with run leases, heartbeat state, validation,
  path confinement, process-group timeouts, and fresh SHA-256 artifact checks.
- Fake-provider and offline tests covering the planner/bridge/controller path.

This first release is an experimental productization scaffold. It does not
claim provider availability, quota availability, remote runtime readiness, or
distributed-controller consistency from catalog or saved-preflight evidence
alone.
