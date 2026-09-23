# Approved-wave closed loop

`scripts/dispatch_closed_loop.py` and `lad closed-loop` close the provider-free
control-plane gap between the reviewed packet bridge and the monitor/replan
boundary.

The boundary is intentionally narrow:

```text
approved enqueue-ready packet bundle
        |
        v
strict packet validation + disjoint write scopes
        |
        +-- dry-run (default): preview only, no SQLite mutation
        |
        +-- fake-execute (explicit): fake/local/Python commands only
                    |
                    v
             SQLite enqueue + one wave
                    |
                    v
             durable snapshot -> monitor -> replan
                    |
                    v
             optional next plan (read-only, never enqueued)
```

The loop never captures free-form intent, infers another job from a prompt,
refreshes provider quota, opens SSH, or calls a real provider. A packet bundle
must either contain `approved: true` (or `approval.approved: true`) or be
passed with the explicit `--approved` attestation. A bridge report must have
`mode=enqueue-ready` and `ok=true`; a dry-run bridge report is rejected.

Preview a reviewed bundle:

```bash
lad closed-loop --approved-packets approved-bundle.json \
  --workspace /trusted/workspace
```

The command emits `provider_invocations=[]`, `model_prompts_sent=false`,
`enqueue_performed=false`, and a prompt/argv-free packet summary. It does not
create the requested database path.

The only execution mode shipped in the provider-free core is a bounded fake
lane suitable for CI and local control-plane demos:

```bash
lad loop --approved-packets approved-bundle.json --approved \
  --fake-execute --db /trusted/run/dispatch.sqlite3 \
  --workspace /trusted/workspace
```

Every attempt must use `provider=fake`, `adapter=command`,
`transport=local`, and an allow-listed Python executable. The real SQLite
controller still performs leases, claims, artifact freshness, and validation;
the monitor and replan stages consume its durable snapshot. If planner `--jobs`
and `--state` are supplied, the loop emits a next-wave plan for those explicit
jobs only. It never enqueues or executes that next plan automatically.

Real provider execution remains the separate reviewed packet/controller path.
This closed-loop entry point is therefore safe to run in CI and while
debugging quota-continuity behavior without spending provider quota.
