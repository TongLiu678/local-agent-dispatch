# WP4 — Resource Digital Twin and Route Evidence Contract

Short contract for the world-state resource layer (WP4). Provider-free;
nothing here probes a live host.

## Records and schema

`schema_version` is `1` and is const on every snapshot
(`schemas/world_state.schema.json`). `WorldStateSnapshot` is a versioned
projection of hosts, routes, and observations; every record serializes with
`to_dict`/`from_dict` and unknown values stay `None` — they are never
fabricated into numbers.

- Host: OS/arch plus distinct `execution_host` and `workload_host` roles.
- CPU: sockets/cores/threads, model, NUMA nodes and distance matrix.
- RAM: capacity/allocatable/available/reserved plus optional cgroup v2
  `memory.max`/`memory.current` limits.
- GPU: model, CUDA compatibility, VRAM values, and observed GPU process/VRAM
  list (`GpuProcess`).
- Mount: path, device, filesystem, options, writability, the exact
  `probed_path` directory, capacity values, free bytes, free inodes, optional
  quota evidence, and an observation with TTL.
- Runtime, Cache, DatasetLocation: version/compatibility, declared sizes and
  mount binding.
- Route: `kind` (`control`/`artifact`/`bulk_data`/`execution`/`workload`),
  `status` (`direct`/`bastion`/`proxy`/`relay`/`unknown`), verification time,
  evidence, peer, RTT/throughput, SSH config.
- Observation: kind, source, `observed_at`, evidence strings, TTL seconds,
  confidence. `is_stale()` returns True/False with a TTL, and None (unverifiable)
  without one.

## Value kinds

`capacity`, `allocatable`, `available_now`, `reserved`, and `safe_to_place`
are distinct. Safe-to-place is derived by the placement gate as
`min(available_now, allocatable, capacity) − reserved − P90 headroom`; it is
never stored as a raw observation.

## Placement gate (`resources/topology.py`)

`evaluate_placement(host, path, requirements, now)` decides on the exact
candidate path's own mount evidence:

- mount missing → `reject` (mount disappearance);
- covering mount listed but never probed → `reject` (root-only probing is
  never accepted as evidence for another mount);
- observation missing → `reject`; expired TTL → `reject` (stale root capacity
  is never accepted); TTL unknown → `unknown`;
- writability unverified → `unknown`; not writable → `reject` (read-only
  shared mounts);
- free bytes/quota-free/inodes unknown → `unknown` (fail closed);
- inode exhaustion → `reject`;
- free < required + P90 headroom (or minus reserved) → `reject`.

Only a fully verified path is `safe`. `rank_paths` orders declared
project/cache/temp/output paths safe-first, then by remaining headroom.

`evaluate_vram` applies the same gate to GPU free VRAM minus observed GPU
process VRAM.

## Routes

Control, artifact, and bulk-data routes are separate records; a missing route
reports `unknown` and is never inferred from another route or from host
reachability.

## Fixtures

`research/scenarios/resource-topologies.json` freezes: healthy host,
small-root/large-project-mount, read-only shared mount, inode exhaustion
(+ unknown inodes, unknown quota free), mount disappearance, root-only probe,
stale root evidence, VRAM pressure, and unknown-route scenarios.

## Live-probe limitation

No live probing is performed by this layer or its tests. Probe *parsers*
(`resources/probes.py`) accept captured text (mountinfo, statvfs fields,
nvidia-smi CSV, cgroup v2) and record the exact probed paths so the gate can
reject root-only evidence. A host-side scanner (WP0/`local_system_scan`) must
feed real evidence into the same records before any real placement; safe
verdicts remain evidence-gated.
