"""Deterministic fake cluster for falsifying scheduler/continuity policies.

This is a provider-free micro-simulation.  It never executes a real workload,
never contacts a provider, and never sleeps: time only moves through
`FakeClock.advance()`.  Its purpose is to falsify scheduler and continuity
policies (quota windows, pool sharing, fencing, retry) inside a controlled
world before any shadow or canary run.

Replay contract
---------------
`run_replay(manifest)` is a pure function of the manifest:

- every random draw comes from `random.Random(seed)`;
- all state transitions are driven by the same code path;
- the output `ReplayRecord.serialize()` is byte-stable: the same manifest
  JSON produces the identical UTF-8 JSON document.

The manifest pins `seed`, `policy` (digest), `fixture` (corpus digest),
`start`, fault schedule, job list and horizon.  Simulator output must never be
presented as physics; use the promotion checklist for evidence ceilings.
"""

from __future__ import annotations

import hashlib
import json
import math
import random
from typing import Any

from research.simulator.fake_clock import (
    FakeClock,
    QuotaWindow,
    WindowSpec,
)

SCHEMA_VERSION = 1

EVENT_VOCABULARY = frozenset(
    {
        "clock_tick",
        "quota_window_reset",
        "pool_health_change",
        "quota_exhausted",
        "quota_restored",
        "rate_limited",
        "model_capability_rejected",
        "job_created",
        "job_planned",
        "packet_sent",
        "ack_lost",
        "duplicate_delivery",
        "duplicate_delivery_suppressed",
        "worker_started",
        "worker_heartbeat",
        "worker_crashed",
        "lease_claimed",
        "lease_fence_rejected",
        "lease_expired",
        "route_lost",
        "route_restored",
        "mount_lost",
        "mount_restored",
        "vram_pressure",
        "vram_released",
        "artifact_written",
        "artifact_partial",
        "artifact_validated",
        "artifact_invalid",
        "human_review_opened",
        "human_review_completed",
        "human_review_missed",
        "job_completed",
        "job_failed",
        "job_duplicate_effect",
        "replay_ended",
    }
)

POOL_HEALTH_LEVELS = ("ready", "degraded", "cooldown", "blocked", "unknown")

FAULT_KINDS = frozenset(
    {
        "crash",
        "lost_ack",
        "duplicate_delivery",
        "stale_fence",
        "partial_artifact",
        "ssh_disconnect",
        "quota_exhaustion",
        "quota_reset",
        "mount_loss",
        "capability_rejection",
        "missing_human_review",
    }
)


def _canonical(payload: Any) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def digest(payload: Any) -> str:
    return hashlib.sha256(_canonical(payload)).hexdigest()


def policy_digest(policy: "DispatchPolicy") -> str:
    return policy.digest()


# --------------------------------------------------------------------------
# World state
# --------------------------------------------------------------------------


class ModelProfile:
    def __init__(self, model_id: str, pool_id: str, **kwargs: Any) -> None:
        self.model_id = model_id
        self.pool_id = pool_id
        self.cost_per_k = float(kwargs.get("cost_per_k", 0.001))
        self.base_latency = float(kwargs.get("base_latency", 10.0))
        self.quality = float(kwargs.get("quality", 0.9))
        self.role = str(kwargs.get("role", "bounded"))
        self.rejected = bool(kwargs.get("rejected", False))
        self.vram_mb = float(kwargs.get("vram_mb", 0.0))

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_id": self.model_id,
            "pool_id": self.pool_id,
            "cost_per_k": self.cost_per_k,
            "base_latency": self.base_latency,
            "quality": self.quality,
            "role": self.role,
            "rejected": self.rejected,
        }


class Pool:
    def __init__(self, pool_id: str, spec: dict[str, Any]) -> None:
        self.pool_id = pool_id
        self.health = str(spec.get("health", "ready"))
        self.models: dict[str, ModelProfile] = {}
        self.windows: dict[str, QuotaWindow] = {}
        self.recent_failures = 0
        self.last_success: float | None = None
        self.last_checked_at: float | None = None
        self.cooldown_until: float | None = None
        self.quota_display_known = bool(spec.get("quota_display_known", True))
        self.attribution_noise = float(spec.get("attribution_noise", 0.0))
        for raw in spec.get("models", []):
            model = ModelProfile(raw["model_id"], pool_id, **raw.get("params", {}))
            self.models[model.model_id] = model

    def effective_percent(self, now: float) -> float:
        """Minimum remaining percent across declared windows; unknown is NaN."""
        if not self.quota_display_known:
            return math.nan
        values = [w.remaining(now) / w.cap for w in self.windows.values()]
        if not values:
            return 1.0
        return min(values)

    def remaining(self, now: float) -> float:
        if not self.quota_display_known:
            return math.nan
        return min((w.remaining(now) for w in self.windows.values()), default=1.0)

    def to_dict(self, now: float) -> dict[str, Any]:
        return {
            "pool_id": self.pool_id,
            "health": self.health,
            "models": sorted(
                m.to_dict() for m in self.models.values()
            ),
            "windows": {
                name: w.snapshot(now) for name, w in self.windows.items()
            },
            "effective_percent": self.effective_percent(now),
            "recent_failures": self.recent_failures,
            "cooldown_until": self.cooldown_until,
            "quota_display_known": self.quota_display_known,
            "attribution_noise": self.attribution_noise,
        }


class Host:
    def __init__(self, host_id: str, spec: dict[str, Any]) -> None:
        self.host_id = host_id
        self.online = bool(spec.get("online", True))
        self.mounts: dict[str, bool] = dict(spec.get("mounts", {}))
        self.vram_total = float(spec.get("vram_total_mb", 0.0))
        self.vram_used = float(spec.get("vram_used_mb", 0.0))
        self.route_ok = bool(spec.get("route_ok", True))
        self.reservations: list[dict[str, Any]] = []
        self.workers: dict[str, "Worker"] = {}
        self.vram_ratio = 0.0 if self.vram_total <= 0 else self.vram_used / self.vram_total

    def vram_pressure(self) -> bool:
        return self.vram_total > 0 and self.vram_used / self.vram_total >= 0.9

    def to_dict(self) -> dict[str, Any]:
        return {
            "host_id": self.host_id,
            "online": self.online,
            "route_ok": self.route_ok,
            "mounts": dict(sorted(self.mounts.items())),
            "vram_ratio": self.vram_ratio,
            "vram_pressure": self.vram_pressure(),
        }


class Worker:
    def __init__(self, worker_id: str, host_id: str) -> None:
        self.worker_id = worker_id
        self.host_id = host_id
        self.alive = True
        self.busy: Job | None = None
        self.lease: Lease | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "worker_id": self.worker_id,
            "host_id": self.host_id,
            "alive": self.alive,
            "busy": self.busy.job_id if self.busy else None,
            "lease": self.lease.to_dict() if self.lease else None,
        }


class Lease:
    def __init__(self, owner: str, job_id: str, expires_at: float, token: str) -> None:
        self.owner = owner
        self.job_id = job_id
        self.expires_at = expires_at
        self.token = token

    def to_dict(self) -> dict[str, Any]:
        return {
            "owner": self.owner,
            "job_id": self.job_id,
            "expires_at": self.expires_at,
            "token": self.token,
        }


class Job:
    """A simulated task with a state machine, artifact and review lifecycle."""

    def __init__(self, job_id: str, spec: dict[str, Any]) -> None:
        self.job_id = job_id
        self.family = str(spec.get("family", "general"))
        self.difficulty = str(spec.get("difficulty", "L2"))
        self.requires_review = bool(spec.get("requires_review", True))
        self.arrival = float(spec.get("arrival", 0.0))
        self.state = "created"
        self.planned_pool: str | None = None
        self.planned_model: str | None = None
        self.host_id: str | None = None
        self.worker_id: str | None = None
        self.created_at: float | None = None
        self.validated_at: float | None = None
        self.completed_at: float | None = None
        self.acked = False
        self.artifacts_written = 0
        self.artifact_validated = False
        self.review_opened: float | None = None
        self.review_done = False
        self.review_missed = False
        self.failure: str | None = None
        self.duplicate_effect = False
        self.duplicate_delivery_count = 0
        self.duplicate_delivery_suppressed = 0
        self.last_progress: float | None = None
        self.cost_consumed = 0.0
        self.force_review_missed = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "family": self.family,
            "difficulty": self.difficulty,
            "requires_review": self.requires_review,
            "state": self.state,
            "planned_pool": self.planned_pool,
            "planned_model": self.planned_model,
            "host_id": self.host_id,
            "worker_id": self.worker_id,
            "validated_at": self.validated_at,
            "completed_at": self.completed_at,
            "failure": self.failure,
            "duplicate_effect": self.duplicate_effect,
            "duplicate_delivery_count": self.duplicate_delivery_count,
            "duplicate_delivery_suppressed": self.duplicate_delivery_suppressed,
        }


class World:
    """Snapshot-able cluster state; only the replay engine mutates it."""

    def __init__(self) -> None:
        self.pools: dict[str, Pool] = {}
        self.hosts: dict[str, Host] = {}
        self.jobs: dict[str, Job] = {}
        self.attribution_unknown = False

    def to_dict(self, now: float) -> dict[str, Any]:
        return {
            "pools": {pid: p.to_dict(now) for pid, p in self.pools.items()},
            "hosts": {hid: h.to_dict() for hid, h in self.hosts.items()},
        }


# --------------------------------------------------------------------------
# Policies under test
# --------------------------------------------------------------------------


class DispatchPolicy:
    """Policy interface. `choose` returns (pool_id, model_id) or raises
    `NoRouteError`; `should_retry` decides on failed attempts."""

    name = "base"
    description = ""

    def digest(self) -> str:
        return digest({"name": self.name, "description": self.description})

    def choose(
        self,
        world: World,
        job: Job,
        now: float,
        rng: random.Random,
    ) -> tuple[str, str]:
        raise NotImplementedError

    def should_retry(
        self, world: World, job: Job, now: float, attempt: int, rng: random.Random
    ) -> bool:
        return attempt < 2


class GreedyPolicy(DispatchPolicy):
    """Cheapest eligible model first. Ignores quota headroom, which makes it
    vulnerable to pool exhaustion and cooldowns."""

    name = "greedy"
    description = "cheapest eligible model, ignores quota headroom"

    def choose(
        self,
        world: World,
        job: Job,
        now: float,
        rng: random.Random,
    ) -> tuple[str, str]:
        candidates: list[tuple[float, str, str]] = []
        for pool in world.pools.values():
            if pool.health in ("blocked", "cooldown"):
                continue
            for model in pool.models.values():
                if model.rejected:
                    continue
                candidates.append((model.cost_per_k, pool.pool_id, model.model_id))
        if not candidates:
            raise NoRouteError("no eligible model in greedy policy")
        candidates.sort(key=lambda row: row[0])
        return candidates[0][1], candidates[0][2]


class QuotaAwarePolicy(DispatchPolicy):
    """Prefers the pool with the most remaining quota, then cheapest model,
    and cools down only pools that reported real failures."""

    name = "quota_aware"
    description = "max remaining quota percent, then cost, honors cooldowns"

    def choose(
        self,
        world: World,
        job: Job,
        now: float,
        rng: random.Random,
    ) -> tuple[str, str]:
        best: tuple[float, float, str, str] | None = None
        for pool in world.pools.values():
            if pool.health in ("blocked", "cooldown"):
                continue
            remaining = pool.remaining(now)
            if math.isnan(remaining):
                # Unknown quota is a hard planning block by default; a pilot
                # policy would choose a bounded pool instead.
                continue
            for model in pool.models.values():
                if model.rejected:
                    continue
                key = (remaining, model.cost_per_k, pool.pool_id, model.model_id)
                if best is None or key > best:
                    best = key
        if best is None:
            raise NoRouteError("no eligible route in quota_aware policy")
        return best[2], best[3]


class NoRouteError(RuntimeError):
    pass


# --------------------------------------------------------------------------
# Replay engine
# --------------------------------------------------------------------------


class ReplayError(ValueError):
    pass


def _validate_manifest(manifest: dict[str, Any]) -> None:
    if not isinstance(manifest.get("seed"), int):
        raise ReplayError("manifest.seed must be an integer")
    if not isinstance(manifest.get("fixture"), dict):
        raise ReplayError("manifest.fixture must be an object")
    faults = manifest.get("faults", [])
    if not isinstance(faults, list):
        raise ReplayError("manifest.faults must be a list")
    for fault in faults:
        if fault.get("fault") not in FAULT_KINDS:
            raise ReplayError(f"unknown fault kind: {fault.get('fault')}")
    for job in manifest.get("jobs", []):
        if not job.get("job_id"):
            raise ReplayError("every manifest job needs job_id")


class FaultScheduler:
    """Maps fault kinds to world mutators. Each fault is deterministic and
    leaves observable events in the trace."""

    def __init__(self, world: World, clock: FakeClock, events: list[dict[str, Any]]):
        self.world = world
        self.clock = clock
        self.events = events

    def inject(self, fault: dict[str, Any], now: float) -> None:
        kind = fault["fault"]
        target = fault.get("target")
        handler = getattr(self, f"fault_{kind}", None)
        if handler is None:
            raise ReplayError(f"unhandled fault kind: {kind}")
        handler(fault, now, target)

    def fault_crash(self, fault: dict[str, Any], now: float, target: str | None) -> None:
        for host in self.world.hosts.values():
            for worker in host.workers.values():
                if target is not None and worker.worker_id != target:
                    continue
                if worker.alive:
                    worker.alive = False
                    if worker.busy is not None:
                        worker.busy.failure = "crash"
                        self.events.append(
                            self.clock.emit(
                                "worker_crashed",
                                worker_id=worker.worker_id,
                                host_id=worker.host_id,
                                job_id=worker.busy.job_id,
                            )
                        )

    def fault_lost_ack(self, fault: dict[str, Any], now: float, target: str | None) -> None:
        self.events.append(self.clock.emit("ack_lost", target=target))

    def fault_duplicate_delivery(
        self, fault: dict[str, Any], now: float, target: str | None
    ) -> None:
        job = self.world.jobs.get(target or "")
        if job is not None:
            job.duplicate_delivery_count += 1
            self.events.append(
                self.clock.emit("duplicate_delivery", job_id=job.job_id, t=now)
            )
            # A terminal receipt is the idempotency boundary: redelivery may
            # be observed, but it must not create a second irreversible effect.
            # Keep the old ``job_duplicate_effect`` event in the vocabulary as
            # a reserved violation marker for future unsafe adapters; this
            # replay path models the safe receipt-backed behavior instead.
            if job.state == "done":
                job.duplicate_delivery_suppressed += 1
                self.events.append(
                    self.clock.emit(
                        "duplicate_delivery_suppressed",
                        job_id=job.job_id,
                        t=now,
                        receipt_state="terminal",
                    )
                )

    def fault_stale_fence(self, fault: dict[str, Any], now: float, target: str | None) -> None:
        self.events.append(self.clock.emit("lease_fence_rejected", target=target))

    def fault_partial_artifact(
        self, fault: dict[str, Any], now: float, target: str | None
    ) -> None:
        job = self.world.jobs.get(target or "")
        if job is not None:
            job.artifacts_written += 1
            self.events.append(
                self.clock.emit("artifact_partial", job_id=job.job_id)
            )

    def fault_ssh_disconnect(
        self, fault: dict[str, Any], now: float, target: str | None
    ) -> None:
        host = self.world.hosts.get(target or "")
        if host is not None and host.route_ok:
            host.route_ok = False
            self.events.append(
                self.clock.emit("route_lost", host_id=host.host_id)
            )

    def fault_quota_exhaustion(
        self, fault: dict[str, Any], now: float, target: str | None
    ) -> None:
        pool = self.world.pools.get(target or "")
        if pool is not None:
            self.events.append(
                self.clock.emit("quota_exhausted", pool_id=pool.pool_id)
            )
            pool.health = "blocked"

    def fault_quota_reset(
        self, fault: dict[str, Any], now: float, target: str | None
    ) -> None:
        pool = self.world.pools.get(target or "")
        if pool is not None:
            for window in pool.windows.values():
                window.reset()
            if pool.health in ("blocked", "cooldown"):
                pool.health = "ready"
            pool.recent_failures = 0
            self.events.append(
                self.clock.emit("quota_restored", pool_id=pool.pool_id)
            )

    def fault_mount_loss(
        self, fault: dict[str, Any], now: float, target: str | None
    ) -> None:
        host = self.world.hosts.get(target or "")
        if host is not None:
            for mount in host.mounts:
                if host.mounts[mount]:
                    host.mounts[mount] = False
                    self.events.append(
                        self.clock.emit("mount_lost", host_id=host.host_id, mount=mount)
                    )

    def fault_capability_rejection(
        self, fault: dict[str, Any], now: float, target: str | None
    ) -> None:
        for pool in self.world.pools.values():
            if target is not None and pool.pool_id != target:
                continue
            for model in pool.models.values():
                if not model.rejected:
                    model.rejected = True
                    self.events.append(
                        self.clock.emit(
                            "model_capability_rejected",
                            pool_id=pool.pool_id,
                            model_id=model.model_id,
                        )
                    )

    def fault_missing_human_review(
        self, fault: dict[str, Any], now: float, target: str | None
    ) -> None:
        job = self.world.jobs.get(target or "")
        if job is not None and not job.review_done:
            # Deterministic regardless of when the review window opens: the
            # human never arrives for this job in this replay.
            job.force_review_missed = True
            self.events.append(
                self.clock.emit("human_review_missed", job_id=job.job_id, t=now)
            )


def _load_fixture(fixture: dict[str, Any], clock: FakeClock, world: World) -> None:
    for pool_spec in fixture.get("pools", []):
        pool = Pool(pool_spec["pool_id"], pool_spec)
        for window_spec in pool_spec.get("windows", []):
            spec = WindowSpec(
                kind=window_spec["kind"],
                duration_seconds=window_spec.get("duration_seconds"),
                calendar_granularity=window_spec.get("calendar_granularity"),
            )
            pool.windows[window_spec.get("name", spec.to_dict()["kind"])] = clock.add_window(
                spec, float(window_spec["cap"])
            )
        world.pools[pool.pool_id] = pool
    for host_spec in fixture.get("hosts", []):
        host = Host(host_spec["host_id"], host_spec)
        for worker_id in host_spec.get("workers", []):
            host.workers[worker_id] = Worker(worker_id, host.host_id)
        world.hosts[host.host_id] = host


def run_replay(manifest: dict[str, Any], policy: DispatchPolicy) -> "ReplayRecord":
    _validate_manifest(manifest)
    seed = int(manifest["seed"])
    start = float(manifest.get("start", 0.0))
    horizon = float(manifest.get("horizon", 604800.0))
    clock = FakeClock(seed=seed, start=start)
    world = World()
    _load_fixture(manifest["fixture"], clock, world)

    faults = list(manifest.get("faults", []))
    faults.sort(key=lambda f: float(f.get("t", 0.0)))
    fault_index = 0
    jobs: list[Job] = [
        Job(str(job.get("job_id")), job) for job in manifest.get("jobs", [])
    ]
    jobs.sort(key=lambda j: j.arrival)
    for job in jobs:
        world.jobs[job.job_id] = job

    rng = clock.rng()
    horizon_seconds = max(0.0, horizon - start)
    now = clock.now()
    while now < horizon:
        # Arrivals this tick.
        due_jobs = [j for j in jobs if j.arrival <= now and j.state == "created"]
        for job in due_jobs:
            job.created_at = now
            clock.emit(
                "job_created",
                job_id=job.job_id,
                family=job.family,
                difficulty=job.difficulty,
                arrival=job.arrival,
            )
            _plan_job(clock, world, job, policy, rng, now)
        # Fault injection at exact instants.
        while fault_index < len(faults) and float(faults[fault_index]["t"]) <= now:
            FaultScheduler(world, clock, clock.events()).inject(faults[fault_index], now)
            fault_index += 1
        _run_one_tick(clock, world, rng)
        now = clock.now()
        if now >= horizon:
            break
        # Deterministic step: never exceed one small tick per loop.
        clock.advance(60.0)

    # Censor anything still in flight at horizon.  Jobs that never arrived
    # (arrival beyond the horizon) are recorded as not_arrived, not censored.
    for job in jobs:
        if job.arrival > horizon:
            clock.emit("job_failed", job_id=job.job_id, reason="not_arrived")
            job.state = "failed"
            job.failure = "not_arrived"
        elif job.state in ("created", "planned", "review"):
            if job.validated_at is None and job.failure is None:
                job.failure = "censored_at_horizon"
            clock.emit("job_failed", job_id=job.job_id, censored=True)
    clock.emit("replay_ended", seed=seed, policy=policy.name)

    return ReplayRecord(manifest=manifest, policy=policy, world=world, clock=clock)


def _plan_job(
    clock: FakeClock,
    world: World,
    job: Job,
    policy: DispatchPolicy,
    rng: random.Random,
    now: float,
) -> None:
    attempt = 0
    while True:
        try:
            pool_id, model_id = policy.choose(world, job, now, rng)
        except NoRouteError:
            clock.emit("job_failed", job_id=job.job_id, reason="no_route")
            job.state = "failed"
            job.failure = "no_route"
            return
        pool = world.pools[pool_id]
        model = pool.models[model_id]
        # Capability rejection is per exact model tuple: siblings stay usable.
        if model.rejected:
            clock.emit(
                "model_capability_rejected",
                pool_id=pool_id,
                model_id=model_id,
            )
            model.rejected = True
            attempt += 1
            if not policy.should_retry(world, job, now, attempt, rng):
                clock.emit("job_failed", job_id=job.job_id, reason="capability")
                job.state = "failed"
                job.failure = "capability"
                return
            continue
        remaining = pool.remaining(now)
        if remaining is not None and math.isnan(remaining):
            pool.quota_display_known = False
            pool.health = "unknown"
            clock.emit("pool_health_change", pool_id=pool_id, health="unknown")
            attempt += 1
            if not policy.should_retry(world, job, now, attempt, rng):
                clock.emit("job_failed", job_id=job.job_id, reason="quota_unknown")
                job.state = "failed"
                job.failure = "quota_unknown"
                return
            continue
        if pool.health == "blocked":
            clock.emit("quota_exhausted", pool_id=pool_id)
            attempt += 1
            if not policy.should_retry(world, job, now, attempt, rng):
                clock.emit("job_failed", job_id=job.job_id, reason="quota_exhausted")
                job.state = "failed"
                job.failure = "quota_exhausted"
                return
            continue
        # Rate limit: simulated from pool pressure.
        limit_prob = 0.0 if pool.recent_failures == 0 else 0.15 * pool.recent_failures
        if rng.random() < min(limit_prob, 0.5):
            clock.emit("rate_limited", pool_id=pool_id, model_id=model_id)
            pool.health = "cooldown"
            pool.cooldown_until = now + 300.0
            attempt += 1
            if not policy.should_retry(world, job, now, attempt, rng):
                clock.emit("job_failed", job_id=job.job_id, reason="rate_limited")
                job.state = "failed"
                job.failure = "rate_limited"
                return
            continue
        host = _pick_host(world, rng)
        if host is None or not host.route_ok or not host.online:
            clock.emit("route_lost", host_id=host.host_id if host else None)
            attempt += 1
            if not policy.should_retry(world, job, now, attempt, rng):
                clock.emit("job_failed", job_id=job.job_id, reason="route_lost")
                job.state = "failed"
                job.failure = "route_lost"
                return
            continue
        worker = _pick_worker(host, rng)
        lease = Lease(owner=policy.name, job_id=job.job_id, expires_at=now + 3600.0, token=rng.randint(0, 2**31))
        worker.lease = lease
        worker.busy = job
        job.state = "planned"
        job.planned_pool = pool_id
        job.planned_model = model_id
        job.host_id = host.host_id
        job.worker_id = worker.worker_id
        clock.emit(
            "job_planned",
            job_id=job.job_id,
            pool_id=pool_id,
            model_id=model_id,
            host_id=host.host_id,
            worker_id=worker.worker_id,
            lease_token=lease.token,
        )
        clock.emit(
            "packet_sent",
            job_id=job.job_id,
            worker_id=worker.worker_id,
            cost_per_k=model.cost_per_k,
        )
        return


def _pick_host(world: World, rng: random.Random) -> Host | None:
    hosts = [h for h in world.hosts.values() if h.online]
    if not hosts:
        return None
    return hosts[rng.randrange(len(hosts))]


def _pick_worker(host: Host, rng: random.Random) -> Worker:
    workers = list(host.workers.values())
    return workers[rng.randrange(len(workers))]


def _run_one_tick(clock: FakeClock, world: World, rng: random.Random) -> None:
    now = clock.now()
    # Cooldowns expire.
    for pool in world.pools.values():
        if pool.cooldown_until is not None and pool.cooldown_until <= now:
            pool.cooldown_until = None
            if pool.health == "cooldown":
                pool.health = "ready"
                clock.emit("pool_health_change", pool_id=pool.pool_id, health="ready")
        if pool.health == "blocked" and not pool.windows:
            pool.health = "ready"
    # Expire leases; stale fence protection rejects claims by other owners.
    for host in world.hosts.values():
        for worker in host.workers.values():
            if worker.lease and worker.lease.expires_at <= now:
                worker.lease = None
                clock.emit("lease_expired", worker_id=worker.worker_id)
    # Run planned jobs to completion with deterministic latencies and noise.
    for job in list(world.jobs.values()):
        if job.state != "planned":
            continue
        worker = None
        for host in world.hosts.values():
            for candidate in host.workers.values():
                if candidate.busy is job:
                    worker = candidate
        if worker is None or not worker.alive or worker.lease is None:
            # Interrupted run: no valid artifact can appear, the run stays
            # censored until the horizon rather than being discarded.
            if worker is not None and not worker.alive:
                job.failure = "worker_lost"
                clock.emit(
                    "worker_crashed",
                    worker_id=worker.worker_id,
                    job_id=job.job_id,
                    interrupted=True,
                )
            elif worker is not None and worker.lease is None:
                job.failure = "lease_expired"
                clock.emit(
                    "lease_expired", worker_id=worker.worker_id, job_id=job.job_id
                )
            continue
        if not worker.lease.expires_at > now:
            job.failure = "lease_expired"
            clock.emit("lease_expired", worker_id=worker.worker_id, job_id=job.job_id)
            continue
        pool = world.pools.get(job.planned_pool or "")
        model = pool.models[job.planned_model] if pool else None
        if pool is None or model is None:
            continue
        # Host route / mount / VRAM pressure check.
        host = world.hosts.get(job.host_id or "")
        if host is None:
            continue
        if not host.route_ok:
            clock.emit("route_lost", host_id=host.host_id, job_id=job.job_id)
            _fail_job(clock, job, "route_lost", pool, now)
            continue
        if not host.mounts or not any(host.mounts.values()):
            clock.emit("mount_lost", host_id=host.host_id, job_id=job.job_id)
            _fail_job(clock, job, "mount_lost", pool, now)
            continue
        if host.vram_pressure():
            clock.emit("vram_pressure", host_id=host.host_id, job_id=job.job_id)
            _fail_job(clock, job, "vram_pressure", pool, now)
            continue
        # Consume quota on the shared pool (model pool cost, not tokens).
        cost = model.cost_per_k * (0.5 + rng.random())
        window_names = list(pool.windows)
        if window_names:
            window = pool.windows[window_names[0]]
            if window.exhausted(now):
                clock.emit("quota_exhausted", pool_id=pool.pool_id, job_id=job.job_id)
                pool.health = "blocked"
                _fail_job(clock, job, "quota_exhausted", pool, now)
                continue
            window.consume(cost, now)
        job.cost_consumed += cost
        if rng.random() < pool.attribution_noise:
            world.attribution_unknown = True
            clock.emit(
                "rate_limited" if pool.recent_failures else "pool_health_change",
                pool_id=pool.pool_id,
                attribution_state="unknown",
            )
        latency = model.base_latency * (0.5 + rng.random())
        clock.advance(latency)
        now = clock.now()
        # Ack may be lost (redelivery then re-runs).
        if rng.random() < 0.02:
            clock.emit("ack_lost", job_id=job.job_id, worker_id=worker.worker_id)
            job.acked = False
        else:
            job.acked = True
        # Worker crash during run.
        if not worker.alive:
            clock.emit("worker_crashed", worker_id=worker.worker_id, job_id=job.job_id)
            _fail_job(clock, job, "crash", pool, now)
            continue
        # Artifact write, possibly partial.
        job.artifacts_written += 1
        clock.emit("artifact_written", job_id=job.job_id, bytes_written=1024)
        quality_roll = rng.random()
        if quality_roll <= model.quality:
            job.artifact_validated = True
            job.validated_at = now
            clock.emit("artifact_validated", job_id=job.job_id, t=now)
        else:
            clock.emit("artifact_invalid", job_id=job.job_id)
            _fail_job(clock, job, "artifact_invalid", pool, now)
            continue
        if job.requires_review:
            job.state = "review"
            job.review_opened = now
            clock.emit("human_review_opened", job_id=job.job_id, t=now)
            _run_review(clock, world, job, rng, now)
        if job.state == "review" and job.review_done:
            job.state = "done"
            job.completed_at = now
            clock.emit("job_completed", job_id=job.job_id, t=now)
        elif job.state == "review" and job.review_missed:
            _fail_job(clock, job, "human_review_missed", pool, now)
        elif not job.requires_review and job.state != "done":
            job.state = "done"
            job.completed_at = now
            clock.emit("job_completed", job_id=job.job_id, t=now)


def _run_review(
    clock: FakeClock, world: World, job: Job, rng: random.Random, now: float
) -> None:
    # Human availability is a scheduler input: deterministic window.
    review_horizon = 1800.0
    if job.force_review_missed or rng.random() < 0.1:
        # Human never arrives within the window in this replay.
        job.review_missed = True
        clock.emit("human_review_missed", job_id=job.job_id, t=now)
        return
    clock.advance(60.0 + rng.random() * (review_horizon - 60.0))
    job.review_done = True
    clock.emit("human_review_completed", job_id=job.job_id, t=clock.now())


def _fail_job(
    clock: FakeClock, job: Job, reason: str, pool: Pool | None, now: float
) -> None:
    job.state = "failed"
    job.failure = reason
    if pool is not None:
        pool.recent_failures += 1
        pool.last_success = None
    clock.emit("job_failed", job_id=job.job_id, reason=reason)


# --------------------------------------------------------------------------
# Replay record
# --------------------------------------------------------------------------


class ReplayRecord:
    """Stores seed, policy digest, fixture digest, corpus digest and the full
    event trace. `serialize()` is byte-stable for a given manifest."""

    def __init__(
        self, manifest: dict[str, Any], policy: DispatchPolicy, world: World, clock: FakeClock
    ) -> None:
        self.manifest = manifest
        self.policy = policy
        self.world = world
        self.clock = clock
        self.seed = int(manifest["seed"])
        self.policy_digest = policy_digest(policy)
        self.fixture_digest = digest(manifest["fixture"])
        self.corpus_digest = digest(
            {
                "seed": self.seed,
                "policy": self.policy_digest,
                "fixture": self.fixture_digest,
                "start": manifest.get("start", 0.0),
                "horizon": manifest.get("horizon", 604800.0),
            }
        )

    def summary(self) -> dict[str, Any]:
        jobs = self.world.jobs
        validated = [j for j in jobs.values() if j.artifact_validated]
        censored = [j for j in jobs.values() if j.failure == "censored_at_horizon"]
        quota_unknown = sum(
            1 for p in self.world.pools.values() if not p.quota_display_known
        )
        cost_attribution_unknown = self.world.attribution_unknown or quota_unknown > 0
        return {
            "seed": self.seed,
            "policy_digest": self.policy_digest,
            "fixture_digest": self.fixture_digest,
            "corpus_digest": self.corpus_digest,
            "jobs_total": len(jobs),
            "jobs_validated": len(validated),
            "jobs_failed": len([j for j in jobs.values() if j.state == "failed"]),
            "jobs_censored": len(censored),
            "validation_rate": len(validated) / len(jobs) if jobs else math.nan,
            "cost_total": sum(j.cost_consumed for j in jobs.values()),
            "violations": {
                "duplicate_effect": sum(1 for j in jobs.values() if j.duplicate_effect),
                "duplicate_delivery_suppressed": sum(
                    j.duplicate_delivery_suppressed for j in jobs.values()
                ),
                "unvalidated_completed": sum(
                    1 for j in jobs.values() if j.state == "done" and not j.artifact_validated
                ),
                "review_missed": sum(1 for j in jobs.values() if j.review_missed),
            },
            "data_quality": {
                "quota_display_known": not quota_unknown,
                "cost_attribution_unknown": cost_attribution_unknown,
                "unknown_fields": ["quota_remaining", "cost_total"]
                if cost_attribution_unknown
                else [],
            },
            "events": len(self.clock.events()),
        }

    def serialize(self) -> str:
        payload = {
            "schema_version": SCHEMA_VERSION,
            "seed": self.seed,
            "policy": {"name": self.policy.name, "digest": self.policy_digest},
            "fixture_digest": self.fixture_digest,
            "corpus_digest": self.corpus_digest,
            "event_trace": self.clock.events(),
            "jobs": [j.to_dict() for j in sorted(self.world.jobs.values(), key=lambda j: j.job_id)],
            "summary": self.summary(),
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def default_policy() -> DispatchPolicy:
    return QuotaAwarePolicy()
