# Benchmark Taxonomy v1 (WP0)

Frozen task/benchmark taxonomy for the local-agent-dispatch research program.
The public research questions and evidence principles are summarized in
[`docs/research-program.md`](../research-program.md).

## 1. Task strata

Four strata are required before any real-provider comparison:

| Stratum | Examples | Verification |
| --- | --- | --- |
| S0 deterministic | system scan, schema transform, log classification | exact output/schema |
| S1 bounded code | one-file bug, parser, unit-test addition | compile and tests |
| S2 integration | multi-file refactor, adapter contract, worktree merge | integration tests and artifact manifest |
| S3 research/high-risk | architecture review, source synthesis, claim-bounded research plan | evidence rubric, claim contract, independent review |

Seeded corpus: `research/corpus/missions.jsonl` (missions) and
`research/corpus/task-labels.jsonl` (labels). Missing labels remain `unknown`;
they are never inferred for ranking.

## 2. Task label fields

Every labeled task includes:

```text
reasoning_complexity
domain_specialization
context_size
tool_complexity
verifiability
reversibility
blast_radius
claim_risk
dag_width / dag_depth / critical_path
cpu / ram / gpu / vram / storage / network class
data_classification / data_location
deadline / human_review_requirement
```

## 3. Environment scenarios

The simulator must cover (seeded fixtures in `research/scenarios/`):

- **Quota** (`quota-windows.json`): healthy, near five-hour limit, weekly
  exhausted, imminent reset, unknown remaining balance.
- **Resources** (`resource-topologies.json`): healthy host, RAM pressure,
  VRAM pressure, root filesystem small but project mount large, mount
  disappearance, inode exhaustion, cgroup restriction.
- **Network:** normal, high latency, low throughput, short disconnect,
  server-server direct path, proxy/relay ambiguity, failed route
  verification.
- **Provider:** catalog-visible/runtime-rejected model, auth failure, rate
  limit, zero-progress stall, partial artifact.
- **Human:** online, fixed review window, extended absence.

## 4. Longitudinal cases

1. **Provider-free software case:** compile a mission, create a DAG, execute
   fake workers, validate artifacts, inject failures, recover, replan.
2. **Bounded real coding canary:** small reversible worktree with exact model,
   quota snapshots, tests, and no publication/deployment permission.
3. **Server continuity case:** execute one already-approved bounded task through
   envelope, checkpoint, disconnect, recovery, validator and receipt without
   inferring a new objective.
4. **Claim-bounded research case:** compile a source-backed synthesis into
   MissionSpec, DAG, CPS, evidence requirements and an independent review gate.

## 5. Baselines

| Family | Baselines |
| --- | --- |
| Routing | user manual; strongest for every task; cheapest/local for every task; round-robin / remaining-percent proportional; current static heuristic; task-label-only router; state-aware non-learning router; state-aware calibrated router; hindsight oracle (unattainable upper bound) |
| Scheduling | serial; fixed concurrency N; provider-limit-only concurrency; hardware-only concurrency; HEFT static placement; separate model then compute; joint temporal scheduler; hindsight oracle |
| CPS | raw user prompt; full repository/history context; generic agent system prompt; current Skill injection; human-authored CPS; compiled CPS; compiled CPS plus independent reviewer |
| Human control | approval at every step; fixed interval reporting; final-only approval; raw logs/current JSON reports; event-triggered gates with progressive disclosure |

## 6. Required ablations

Remove one mechanism at a time: quota reset calendar, outcome history,
verifiability and claim risk, model diversity and strong-model reserve,
rolling horizon, reservation fencing, communication cost, mount/path
selection, write-scope lock, P90 safety headroom, CPS output schema / stop
condition / claim envelope / provenance, human-event trigger / confidence
display / scheduling explanation.

## 7. Frozen margins and promotion mapping

- Non-inferiority margins and success gates are frozen in
  [`protocol-v1.md`](protocol-v1.md) Section 4 (e.g. success-rate margin
  -3 points, failure margin +2 points, RQ4 quota reduction >=20%).
- Evidence tiers for each baseline family follow
  [`promotion-checklist-v1.md`](promotion-checklist-v1.md).
- Replay comparisons use one preregistered primary outcome per question,
  paired summaries, median/IQR, cluster bootstrap 95% intervals, censored
  survival handling, and Holm-corrected secondaries
  (`research/analysis/paired_report.py`).

## 8. Boundaries

- Simulator numbers are mechanism evidence under modeled inputs only; they
  are never presented as physics, provider billing, or real latency/cost.
- Historical observational data is replay/closure evidence only, never
  causal model-quality evidence.
- Unknown quota/resource values stay `unknown`; no fabricated numbers.
