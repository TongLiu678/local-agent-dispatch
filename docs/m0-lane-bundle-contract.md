# M0 lane bundle contract

`scripts/m0_lane_bundle.py` is the small, provider-free planning seam for the
M0 source-truth work. It consumes an already captured M0 plan, an exact model
and optional variant, and a host inventory. The default output has ten lane
records. It does not select a model, invoke a CLI, open SSH, create a
worktree, or write a run directory.

Each lane receives a relative scope such as
`.lad/m0/source-truth/lane-01`. Scopes are checked by path segment, so a
prefix collision is rejected even when the strings differ. A lane is
`admitted` only when both the shared-pool quota budget and one host's declared
capacity/writable path admit it. Unknown quota, unknown writable paths, and
unknown required capacity are deferred with explicit reasons; they are never
treated as zero-cost or unlimited.

Minimal invocation:

```bash
python3 scripts/m0_lane_bundle.py \
  --plan m0-plan.json \
  --hosts host-inventory.json \
  --model opencode-go/deepseek-v4-flash \
  --variant max
```

The command prints JSON to stdout. `--output` is an explicit opt-in for a
small report file; no default runtime path is touched. The report marks
`provider_execution=false`, `ssh_execution=false`, and
`real_run_directory_written=false` and contains SHA-256 digests for the input
plan, inventory, every lane, and the complete bundle. Digests use canonical
sorted JSON (`sha256-json-c14n-v1`) and contain no wall-clock timestamp.

The exact model pin is strict: a model declared inside the plan must match the
caller argument, and a conflicting variant is rejected. This helper is not a
replacement for the dynamic planner or controller transaction gate; its
purpose is to make a safe, reviewable ten-lane M0 plan before execution.
