# Public implementation status

This page is the public source of truth for the current implementation boundary
of local-agent-dispatch. It describes repository capabilities, not the state of
any developer machine, provider account, private worker, or cluster.

The package is an experimental alpha. Its default claims are provider-free:
catalog visibility, a configured adapter, or a discovered host does not prove
that a live execution lane is ready.

## Version domains

The durable database and resource packet evolve independently:

```text
sqlite_database_schema = 7
resource_packet_schema = 3
```

## Implementation tracks

- `offline_implementation` covers schemas, deterministic resolution, package
  lifecycle planning, skill indexing and composition, replay, fake-adapter
  conformance, and read-only decision surfaces.
- `live_promotion` covers fresh resource evidence, authenticated provider or
  harness execution, writable placement, leases, canaries, and soak evidence.
  Missing, stale, or conflicting evidence blocks this track.

An offline pass never promotes a live lane. Unknown quota, memory, disk,
runtime, transport, or process identity remains unknown rather than being
converted into available capacity.

## Capability matrix

| Area | Public alpha state | Claim boundary |
| --- | --- | --- |
| Adaptive scheduling | Implemented with layered policies, replayable decisions, freshness checks, and fail-closed resource admission | A decision is planning evidence, not proof that a provider or worker executed it |
| Harness and worker contracts | Portable contracts and bounded adapters are implemented and covered by provider-free tests | Each real harness and host still requires current capability and identity evidence |
| Package lifecycle | Deterministic resolve, verify, install, activate, rollback, and uninstall boundaries are implemented | Package installation never implicitly enables or executes an entry point |
| Skill intelligence | Search, exact-size composition, bounded latent similarity analysis, outcome recording, and inert scaffolding are implemented | Generated or proposed skills require separate review, installation, activation, and execution gates |
| Durable control plane | SQLite leases, fencing, receipts, replay, and recovery primitives are implemented | Remote side effects require explicit transport, ownership, and validator evidence |
| Cross-platform support | Core Python contracts and bounded compatibility paths target Linux, macOS, and Windows | Platform-specific services, shells, schedulers, and provider CLIs are not claimed to be interchangeable |

## Current public priorities

1. Keep provider, harness, scheduler, and host policy configurable rather than
   binding the control plane to one machine or service.
2. Make package installation reproducible and separate it from activation and
   execution.
3. Improve skill retrieval, complementary portfolio selection, latent-space
   diagnostics, and evidence-backed evolution proposals.
4. Expand clean-clone and cross-platform verification without importing private
   runtime evidence into the repository.

Reproduction commands and evidence rules are in
[`reproducibility.md`](reproducibility.md). The release sanitization procedure
is in [`public-release.md`](public-release.md), and the research questions are
summarized in [`research-program.md`](research-program.md).
