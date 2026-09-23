# Fault Injection Matrix v1 (WP9)

Provider-free replay laboratory. This document keeps the legacy WP9/WP10
labels for compatibility; in the v3 charter it is part of WS10/AG-M6. Every
fault class below must be injectable in
the deterministic simulator (`research/simulator/fake_cluster.py`) and every
one is a promotion-blocking failure class for the scheduler/continuity
policies. "Promotion" here means moving a policy from provider-free replay to
shadow mode (WP10), never a claim that real physics/providers behave this way.

## Matrix

| # | Fault kind | Event kinds in trace | Promotion-blocking because | Injection point | Expected policy behavior |
| --- | --- | --- | --- | --- | --- |
| F1 | `crash` | `worker_crashed`, `job_failed(censored)` | A dead worker with a live-looking lease lets the controller claim success from a PID alone | worker dies mid-run | Reconcile lease on resume; never infer completion from liveness; censored survival handling |
| F2 | `lost_ack` | `ack_lost` | Missing ack must not trigger a blind re-run of an irreversible action | delivery ack dropped | Idempotency key + receipt; retry only reads, never re-executes without fence |
| F3 | `duplicate_delivery` | `duplicate_delivery`, `duplicate_delivery_suppressed`, `job_duplicate_effect` | Redelivery of an already-completed job could duplicate an irreversible side effect | packet redelivered | A terminal receipt suppresses the replay and records `duplicate_delivery_suppressed`; `job_duplicate_effect` remains a promotion-blocking violation marker |
| F4 | `stale_fence` | `lease_fence_rejected` | An expired lease token must not claim the job | stale lease presented | Reject claim; require fresh transactional claim under the current lease |
| F5 | `partial_artifact` | `artifact_partial` | A truncated artifact must fail validation, not pass | artifact truncated mid-write | Validator fails closed on missing/truncated files; never infer from presence |
| F6 | `ssh_disconnect` | `route_lost` | Route loss mid-run must not orphan or double-run work | route dropped | Resume/recover-handoff reconciles the expired lease; un-fenced reads only |
| F7 | `quota_exhaustion` | `quota_exhausted` | Exhausted shared pool must cool down as a whole; model rotation is not a workaround | pool hits zero | Block pool; do not switch model IDs inside the same pool to escape the limit |
| F8 | `quota_reset` | `quota_restored` | Window refresh must actually restore capacity, not be guessed | window boundary crossed | Recompute health from real remaining; preserve until fresh evidence |
| F9 | `mount_loss` | `mount_lost` | A disappeared mount must fail writes closed, not silently write elsewhere | mount removed | Fail closed; no fallback path rewriting |
| F10 | `capability_rejection` | `model_capability_rejected` | Rejection is per exact model/variant; siblings and pool capacity survive | exact model tuple rejected | Reject only that tuple; try next eligible candidate; do not cool the shared pool |
| F11 | `missing_human_review` | `human_review_missed` | Absent review must not be inferred as approval | review window elapses | Mark review-pending; completion must never be inferred |

## Coverage rules

1. Every manifest used for a promotion decision must inject each fault class at
   least once across its corpus (replay-accelerated, compressed time).
2. A fault instance is a `{"fault": <kind>, "t": <instant>, "target": <id>}`
   entry; the full schedule is part of the manifest, so the corpus digest and
   event trace pin exactly which faults ran.
3. Determinism: same manifest (seed + policy digest + fixture digest) yields a
   byte-identical event trace (`ReplayRecord.serialize()`).
4. Faults are not physics: the matrix asserts which *mechanism* is exercised,
   not failure rates. Rates must be calibrated from shadow/canary evidence
   (see promotion checklist) before any quantitative claim leaves replay.

## Falsification targets

- A policy that treats worker liveness as completion fails F1.
- A policy that retries un-acked work without a fence fails F3/F4.
- A policy that rotates model IDs inside an exhausted shared pool fails F7.
- A policy that infers approval from an elapsed review window fails F11.
- A controller that validates by file presence alone fails F5.

See `research/scenarios/quota-windows.json` for the machine-readable matrix and
`tests/test_research_replay.py` for per-fault injection tests.
