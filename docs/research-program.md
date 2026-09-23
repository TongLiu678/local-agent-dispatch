# Research program

local-agent-dispatch studies how an evidence-gated control plane can select,
compose, install, and improve agent capabilities across heterogeneous local and
remote execution environments.

The research target is the complete loop:

```text
Observe -> Compile -> Plan -> Reserve -> Execute
        -> Validate -> Review -> Learn -> Replan
```

## Research questions

1. How should a scheduler balance capability fit, uncertainty, quota, latency,
   cost, memory, disk, locality, and failure risk without inventing missing
   evidence?
2. How can skills be retrieved from different semantic and procedural angles,
   then composed into complementary portfolios of three, five, ten, or another
   requested size without selecting redundant instructions?
3. Which latent representations expose skill similarity, coverage gaps,
   conflicts, and reusable clusters while keeping instruction bodies and
   embeddings out of routine dispatch output?
4. How should observed outcomes produce reviewable skill-evolution proposals
   without silently rewriting, installing, activating, or executing a skill?
5. How can package-manager semantics make agents, harness adapters, worker
   plugins, policies, and skills portable while preserving provenance,
   rollback, and explicit activation?

## Experimental principles

- Keep `offline_implementation` separate from `live_promotion`.
- Bind every result to an immutable input, policy, implementation, and
  validator identity.
- Compare against deterministic and bounded baselines before using live
  providers or remote workers.
- Record censored, failed, blocked, and interrupted outcomes rather than
  treating missing results as success.
- Keep training/evaluation boundaries explicit and protect holdout labels from
  the execution agent.
- Publish only aggregate, sanitized evidence; operational paths, endpoints,
  credentials, prompts, and private artifacts remain outside the repository.

## Public protocol documents

- [`research/protocol-v1.md`](research/protocol-v1.md) defines lifecycle,
  evidence, and experiment gates.
- [`research/benchmark-taxonomy-v1.md`](research/benchmark-taxonomy-v1.md)
  defines task strata and verification styles.
- [`research/data-governance-v1.md`](research/data-governance-v1.md) defines
  data classes and publication boundaries.
- [`skill-composition.md`](skill-composition.md) describes public skill search,
  complementary composition, latent analysis, and evolution contracts.

The current product boundary is summarized in [`status.md`](status.md), while
clean-checkout commands live in [`reproducibility.md`](reproducibility.md).
