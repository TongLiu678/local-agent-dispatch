# Compute-Aware Routing

Use this reference when a dispatched job downloads data, creates an environment,
runs longer than a small local check, or may benefit from CPU/GPU servers.

## Contents

- Industry scheduling pattern
- Resource estimate schema
- Host inventory and probe
- Server and data gates
- Plan and monitor

## Industry Scheduling Pattern

Use a `filter -> score -> reserve -> reconcile` loop:

1. Express CPU, RAM, GPU/VRAM, ephemeral disk, data, environment, output, and
   runtime as resource requests plus safety headroom.
2. Filter unreachable or incompatible hosts before scoring. Treat path,
   runtime, GPU type/VRAM, data locality, privacy, and billing as hard gates.
3. Score feasible hosts with requested-to-capacity ratios. Bin-pack remote paid
   capacity, keep interactive local headroom, and spare GPU hosts for GPU work.
4. Reserve pool quota, host concurrency, CPU, RAM, disk, and GPUs atomically in
   the first rolling-horizon wave.
5. Order by priority; allow short backfill only when it cannot delay a higher
   priority reservation. Accurate workload time estimates improve backfill.
6. Treat multi-GPU/distributed bundles as gang requests: all required resources
   fit together or the job remains queued.
7. Reconcile live worker demand, artifacts, quotas, host health, utilization,
   and constraints every monitor window. Do not mutate cloud state during the
   scoring simulation.

This maps to Kubernetes resource requests/limits and NodeResourcesFit,
Slurm priority/backfill and GRES, Ray bin packing/placement groups, and Kueue
quota/fair-sharing patterns. Keep the local implementation small; do not deploy
a cluster control plane solely for this skill.

## Resource Estimate Schema

Put explicit facts under each job's `resources` object:

```json
{
  "download_gib": 12,
  "input_gib": 0,
  "environment_gib": 5,
  "temporary_gib": 15,
  "cache_gib": 4,
  "output_gib": 8,
  "ram_gib": 24,
  "cpu_cores": 8,
  "gpu_count": 1,
  "vram_gib": 16,
  "compute_minutes": 90,
  "gpu_useful": true,
  "full_dataset": true,
  "parallel_sweep": false,
  "required_commands": ["python3", "nvidia-smi"],
  "python_version": "3.11"
}
```

Keep `estimated_minutes` for agent/model time and `compute_minutes` for workload
runtime. If a full dataset/model or peak VRAM size is unknown, plan a bounded
pilot or pause for metadata; do not invent a precise full-run estimate.

## Host Inventory and Probe

Always inventory the current machine first:

```bash
lad scan --workspace "<trusted-workspace>"
```

The output is the authoritative local host record for OS/architecture, CPU,
available RAM, workspace/cache disk, accelerators, and installed CLIs. Process
inventory contains only canonical command names and PIDs. When this scan fails
or no compute host is observed, planning pauses; it must not invent CPU, RAM,
disk, GPU, reachability, or writability.

To make the local-vs-server decision explicit before dispatch, render a
read-only hardware fit report from the unified preflight:

```bash
lad fit \
  --preflight "<private-preflight.json>" \
  --jobs "<jobs.json>" \
  --workspace "<trusted-workspace>"
```

The report carries the local hardware profile, per-job minimum server
configuration (CPU, available RAM, free disk, GPU count, free VRAM, commands,
Python version), server-first reasons, eligible hosts, and exact rejection
reasons. It is a placement gate from saved evidence, not proof that a remote
runtime or model is installed.

Store only host connection metadata, candidate project path, billing label, and
tags in an inventory. Never store credentials in the skill or repository.
Keep the private runtime inventory under the configured
`LOCAL_AGENT_DISPATCH_HOME`, not in a project repository.

```bash
lad preflight --workspace "<trusted-workspace>" \
  --inventory "<private-hosts.json>" \
  --output "<private-preflight.json>"
```

The probe checks reachability, exact hostname/OS/architecture, CPU/load, total
and available RAM, project-path disk and writability, Python, NVIDIA or Apple
GPU facts, and bulk-download helpers. It is read-only and uses bounded parallel
SSH probes. Verify the exact project path again for the concrete task.

The unified preflight runs the local scan synchronously before launching these
remote probes, then merges the local facts into `compute_hosts`. Optional
provider absence is local to that provider; missing compute capacity remains a
hard planning gate.

## Server and Data Gates

Require a remote host when workload data exceeds 1 GiB, compute exceeds 10
minutes, GPU is useful, a full dataset/model is involved, or the job is a
parallel batch. Local-only GUI, USB, Apple-only, or untransferable private data
may override this with an explicit reason.

Do not start a new local bulk workload when local free space is below 20 GiB or
10 percent. For transfers over 1 GiB, download directly on the remote server;
never relay through the Mac. Verify live egress first and use the configured
RackNerd/large-download helpers when present. Before any smaller private-data
copy, verify authorization, license/privacy, counts/bytes, and SHA-256.

`scripts/codex_large_download_guard.sh` is the managed server-side guard. Its
route helper and verified egress identity are injected by the server
environment. A direct route is allowed only with an explicit
`--route direct --expected-egress <live-ip>` pair. Run every bulk object once
in plan mode, then repeat with `--execute`; the guard verifies the route before
and after transfer, exact byte count, and SHA-256 when provided. Install it
under the server user's configured `$HOME/.local/bin/` only after preserving
the previous helper. Record the route, observed egress, PID, log, destination,
final bytes, and checksum in deployment state.

For paid hosts, record the billing assumption and provider-side stop path.
Guest shutdown alone is not proof that billing stopped.

## Plan and Monitor

Run `lad plan` with model pools plus `compute_hosts`. Each
assignment reports the model, execution host, request/headroom, expected CPU/GPU
utilization, data route, and gates.

Run `lad monitor` for the first 180 seconds at 30-second intervals. It
observes local or SSH PIDs, logs, artifacts, Codex quota, host reachability,
RAM/disk/GPU pressure, then emits state for replanning. Replan immediately on a
failed host, OOM/VRAM/disk pressure, data-route failure, completion, stall,
quota change, model rejection, or user scope change.
