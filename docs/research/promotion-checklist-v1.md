# Promotion Checklist v1 (WP9)

Checklist for moving a scheduler/continuity policy between evidence tiers.
The tiers are strictly ordered and each has its own evidence ceiling:

The `WP*`/`G*` labels below are retained for compatibility with the original
research notes. The v3 canonical names are `WS0–WS10` and `AG-M0–AG-M6`:
legacy `WP0/G9` means the replay/baseline gate in `AG-M0`; `WP1` maps to the
Event/Provenance slice of `AG-M1`; `WP2` to Mission/CPS work in `AG-M2`; and
`WP9/WP10` to replay/shadow promotion in `AG-M6`. No legacy label creates a
separate acceptance gate.

| Tier | What it is | What it may claim | What it may never claim |
| --- | --- | --- | --- |
| **Provider-free replay** | Deterministic simulator runs (`research/simulator/*`), compressed time, injected faults | Mechanisms, relative ordering under the model, determinism, fault-handling logic | Any numeric rate, latency, cost, or quality value as a real-world fact; physics; provider billing |
| **Shadow** | Candidate policy replays next to current/manual decisions; alternatives are never executed | No-violation behavior on real inputs, decision comparability, route/resource sanity | Any counterfactual it did not execute; causation |
| **Canary** | Bounded, reversible, automatically validated, low-quota tasks only | Engineering reliability on real bounded work | Population-level statistical claims |
| **Scientific evidence** | Preregistered study with live-calibrated inputs, validated outcomes, independent review | Effect sizes and intervals within the study's claim envelope | Beyond-envelope generalization |

## Rules

1. **Replay → Shadow** — all of:
   - [ ] Legacy Gate G9 (v3 alias: `AG-M0` replay determinism): repeated replay with the same manifest is deterministic
     (byte-stable `ReplayRecord.serialize()`).
   - [ ] Fault matrix v1 covers every promotion-blocking failure class and each
     fault class was injected at least once in the corpus.
   - [ ] Statistical protocol followed: one preregistered primary outcome per
     question; paired summaries; median/IQR; cluster bootstrap 95% intervals;
     censored survival handling; Holm-corrected secondaries.
   - [ ] Simulator output labeled `evidence_ceiling: provider_free_replay_only`
     in every report artifact.
   - [ ] No value from replay presented as physics or provider behavior.

2. **Shadow → Canary** — all of:
   - [ ] Shadow plans had zero resource, quota, permission, privacy, route, or
     claim-boundary violations.
   - [ ] Only reversible, automatically validated, low-quota tasks admitted.
   - [ ] Randomization within task family and quota window; start commit,
     inputs, validator, retry limit, authority and time budget held constant.
   - [ ] Injections: controller/worker crash, stale PID, SSH disconnect, rate
     limit, quota exhaustion/reset, mount disappearance, partial artifact,
     truncated event, absent human review.

3. **Canary → Scientific evidence** — all of:
   - [ ] Lower gates pass; three 24-hour trials with no lost accepted task and
     no duplicate irreversible effect.
   - [ ] Evidence report distinguishes engineering reliability from scientific
     validity.
   - [ ] Inputs (cost/latency/quality/quota-reset behavior) calibrated from
     live measurements; simulator values replaced, not blended.
   - [ ] Sample size set from provider-free pilot variance and minimum effect
     size, not an arbitrary run count.
   - [ ] Long-soak success reported as bounded engineering evidence only.

## Standing prohibitions

- [ ] Never present simulator output as physics (WP9 stop condition).
- [ ] Never convert unknown quota/cost into a fabricated number; report
  `unknown` (paired report `data_quality`).
- [ ] Never treat observational history as causal model-ranking data.
- [ ] Never let replay alone promote a claim; mechanisms must also pass
  shadow/canary evidence where promotion requires it.
- [ ] Never run a paid smoke prompt without explicit user authorization.
