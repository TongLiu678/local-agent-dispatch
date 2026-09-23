"""Paired statistical summaries for deterministic replay experiments.

This module implements the WP9 statistical protocol from the research plan:

- paired comparisons from the same manifest corpus (matched on seed and
  fixture digest);
- median/IQR for heavy-tailed time and cost metrics;
- cluster bootstrap 95% intervals (runs are the resampled clusters);
- binary validation success with Wilson intervals;
- survival-style time-to-valid-artifact with right-censored runs (crashed,
  failed-without-artifact and horizon-censored jobs are censored, not
  discarded);
- one preregistered primary outcome per comparison plus Holm-corrected
  secondary comparisons;
- explicit `unknown` markers instead of fabricated precision when quota or
  cost attribution was not known during the replay.

All randomness is seeded, so reports are reproducible.  Simulator output is
synthetic; it must never be promoted as physics or provider billing facts
(see docs/research/promotion-checklist-v1.md).
"""

from __future__ import annotations

import math
import random
import statistics
from typing import Any, Callable, Sequence

from research.simulator.fake_cluster import ReplayRecord

PRIMARY_OUTCOME_DEFAULT = "time_to_valid_artifact"
SECONDARY_OUTCOMES = ("validation_success", "cost_per_validated", "fairness_gini")

MIN_EVIDENCE = 3


# --------------------------------------------------------------------------
# Descriptive statistics
# --------------------------------------------------------------------------


def median_iqr(values: Sequence[float]) -> dict[str, Any]:
    """Median and IQR with an explicit precision guard for tiny samples."""
    vals = sorted(float(v) for v in values)
    n = len(vals)
    if n == 0:
        return {"n": 0, "median": None, "q1": None, "q3": None, "precision": "no_data"}
    if n < MIN_EVIDENCE:
        return {
            "n": n,
            "median": statistics.median(vals),
            "q1": None,
            "q3": None,
            "precision": "insufficient_evidence",
        }
    q1 = _percentile(vals, 25)
    q3 = _percentile(vals, 75)
    return {
        "n": n,
        "median": statistics.median(vals),
        "q1": q1,
        "q3": q3,
        "iqr": q3 - q1,
        "precision": "median_iqr",
    }


def _percentile(sorted_values: list[float], pct: float) -> float:
    if not sorted_values:
        return math.nan
    rank = (pct / 100.0) * (len(sorted_values) - 1)
    low = math.floor(rank)
    high = math.ceil(rank)
    if low == high:
        return sorted_values[low]
    return sorted_values[low] + (sorted_values[high] - sorted_values[low]) * (
        rank - low
    )


def wilson_ci(success: int, total: int, z: float = 1.96) -> dict[str, Any]:
    """Wilson score interval for a binary proportion; no fake precision for
    tiny totals."""
    if total == 0:
        return {
            "success": 0,
            "total": 0,
            "rate": None,
            "ci": None,
            "precision": "no_data",
        }
    if total < MIN_EVIDENCE:
        return {
            "success": success,
            "total": total,
            "rate": success / total,
            "ci": None,
            "precision": "insufficient_evidence",
        }
    p = success / total
    denom = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denom
    half = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denom
    return {
        "success": success,
        "total": total,
        "rate": p,
        "ci": [max(0.0, centre - half), min(1.0, centre + half)],
        "precision": "wilson_95",
    }


# --------------------------------------------------------------------------
# Cluster bootstrap
# --------------------------------------------------------------------------


def cluster_bootstrap(
    clusters: Sequence[Sequence[Any]],
    stat: Callable[[list[Any]], float | None],
    n_boot: int = 2000,
    seed: int = 0,
) -> dict[str, Any]:
    """Bootstrap by resampling whole clusters (runs) with replacement.

    `stat` receives the flattened bootstrap sample and returns None when the
    statistic is not estimable (e.g. survival median not reached); such draws
    are counted as `unestimable` and excluded from the interval.
    """
    rng = random.Random(int(seed))
    cluster_list = [list(c) for c in clusters]
    if not cluster_list:
        return {"n_boot": 0, "ci": None, "unestimable": 0, "precision": "no_data"}
    estimates: list[float] = []
    unestimable = 0
    for _ in range(int(n_boot)):
        sample: list[Any] = []
        for _cluster in range(len(cluster_list)):
            sample.extend(cluster_list[rng.randrange(len(cluster_list))])
        value = stat(sample)
        if value is None:
            unestimable += 1
            continue
        estimates.append(float(value))
    if not estimates:
        return {
            "n_boot": n_boot,
            "ci": None,
            "unestimable": unestimable,
            "precision": "unestimable",
        }
    estimates.sort()
    return {
        "n_boot": n_boot,
        "ci": [_percentile(estimates, 2.5), _percentile(estimates, 97.5)],
        "unestimable": unestimable,
        "precision": "cluster_bootstrap_95",
    }


# --------------------------------------------------------------------------
# Survival-style time-to-valid-artifact
# --------------------------------------------------------------------------


def _km_survival(
    times: Sequence[float], censored: Sequence[bool]
) -> list[tuple[float, float]]:
    """Kaplan-Meier estimator over sorted event/censor pairs."""
    order = sorted(range(len(times)), key=lambda i: (times[i], int(bool(censored[i]))))
    at_risk = float(len(order))
    survival = 1.0
    steps: list[tuple[float, float]] = [(0.0, 1.0)]
    i = 0
    while i < len(order):
        t = times[order[i]]
        events = 0
        censored_at = 0
        j = i
        while j < len(order) and times[order[j]] == t:
            if censored[order[j]]:
                censored_at += 1
            else:
                events += 1
            j += 1
        if events:
            survival *= 1.0 - events / at_risk
            steps.append((t, survival))
        at_risk -= events + censored_at
        i = j
    return steps


def km_median(times: Sequence[float], censored: Sequence[bool]) -> float | None:
    """Smallest t with S(t) <= 0.5; None when the median is not reached."""
    steps = _km_survival(times, censored)
    for _t, s in steps:
        if s <= 0.5:
            return _t
    return None


def survival_summary(
    times: Sequence[float], censored: Sequence[bool]
) -> dict[str, Any]:
    """Median, event/censor counts and precision guard for survival data."""
    times = [float(t) for t in times]
    censored = [bool(c) for c in censored]
    n = len(times)
    n_events = sum(0 if c else 1 for c in censored)
    if n == 0:
        return {
            "n": 0,
            "events": 0,
            "censored": 0,
            "median": None,
            "precision": "no_data",
        }
    if n_events < MIN_EVIDENCE:
        return {
            "n": n,
            "events": n_events,
            "censored": n - n_events,
            "median": None,
            "precision": "insufficient_evidence",
        }
    return {
        "n": n,
        "events": n_events,
        "censored": n - n_events,
        "median": km_median(times, censored),
        "precision": "km_median",
    }


# --------------------------------------------------------------------------
# Fairness
# --------------------------------------------------------------------------


def gini(groups: dict[str, int]) -> float | None:
    """Gini coefficient over group counts (e.g. validated jobs per family)."""
    values = sorted(float(v) for v in groups.values())
    if len(values) < 2 or sum(values) <= 0:
        return None
    n = len(values)
    cumulative = 0.0
    total = sum(values)
    for i, value in enumerate(values, start=1):
        cumulative += i * value
    return (2 * cumulative) / (n * total) - (n + 1) / n


# --------------------------------------------------------------------------
# Holm correction for predeclared secondary comparisons
# --------------------------------------------------------------------------


def holm_correct(p_values: Sequence[float]) -> list[float]:
    """Holm-Bonferroni adjusted p-values, preserving input order."""
    p = [float(v) for v in p_values]
    n = len(p)
    order = sorted(range(n), key=lambda i: p[i])
    adjusted = [0.0] * n
    running = 0.0
    for rank, idx in enumerate(order, start=1):
        running = max(running, p[idx] * (n - rank + 1))
        adjusted[idx] = min(1.0, running)
    return adjusted


# --------------------------------------------------------------------------
# Per-run outcomes
# --------------------------------------------------------------------------


def _job_outcomes(record: ReplayRecord) -> list[dict[str, Any]]:
    outcomes = []
    horizon = float(record.manifest.get("horizon", 604800.0))
    for job in record.world.jobs.values():
        if job.created_at is None:
            start = float(job.arrival)
        else:
            start = job.created_at
        ttv: float | None = None
        censored = True
        if job.validated_at is not None:
            ttv = job.validated_at - start
            censored = False
        elif job.completed_at is not None:
            ttv = job.completed_at - start
        elif job.failure == "not_arrived":
            ttv = None
        else:
            ttv = max(0.0, horizon - start)
        outcomes.append(
            {
                "job_id": job.job_id,
                "family": job.family,
                "run_seed": record.seed,
                "validated": job.artifact_validated,
                "censored": censored,
                "ttv": ttv,
            }
        )
    return [o for o in outcomes if o["ttv"] is not None]


def _run_stats(record: ReplayRecord) -> dict[str, Any]:
    outcomes = _job_outcomes(record)
    ttv = [o["ttv"] for o in outcomes]
    cens = [o["censored"] for o in outcomes]
    families: dict[str, int] = {}
    for o in outcomes:
        families[o["family"]] = families.get(o["family"], 0) + 1
    validated = sum(1 for o in outcomes if o["validated"])
    return {
        "n": len(outcomes),
        "median_ttv": statistics.median(ttv) if ttv else None,
        "validated": validated,
        "validation_rate": validated / len(outcomes) if outcomes else None,
        "gini": gini(families),
        "censored": sum(1 for c in cens if c),
    }


# --------------------------------------------------------------------------
# Paired report
# --------------------------------------------------------------------------


def _permutation_p_value(
    paired_diffs: Sequence[float], n_perm: int, seed: int
) -> float:
    """Two-sided sign-flip permutation test on paired differences."""
    diffs = [float(d) for d in paired_diffs]
    if not diffs:
        return 1.0
    rng = random.Random(int(seed))
    observed = abs(statistics.mean(diffs))
    count = 0
    for _ in range(int(n_perm)):
        flipped = [d if rng.random() < 0.5 else -d for d in diffs]
        if abs(statistics.mean(flipped)) >= observed:
            count += 1
    return count / n_perm


def paired_report(
    records_a: Sequence[ReplayRecord],
    records_b: Sequence[ReplayRecord],
    *,
    primary: str = PRIMARY_OUTCOME_DEFAULT,
    bootstrap_seed: int | None = None,
    n_boot: int = 2000,
) -> dict[str, Any]:
    """Paired comparison of two policies over matched replay runs.

    Runs are matched on (seed, fixture_digest).  Unmatched runs are reported
    as `unmatched` and excluded from paired statistics but kept in per-arm
    totals.  The primary outcome is time-to-valid-artifact (survival median);
    secondaries are Holm-corrected.
    """
    if primary != PRIMARY_OUTCOME_DEFAULT:
        raise ValueError(f"unknown primary outcome: {primary}")
    b_seed = (
        int(bootstrap_seed)
        if bootstrap_seed is not None
        else (records_a[0].seed if records_a else 0)
    )
    a_by_key = {(r.seed, r.fixture_digest): r for r in records_a}
    b_by_key = {(r.seed, r.fixture_digest): r for r in records_b}
    pairs: list[tuple[ReplayRecord, ReplayRecord]] = []
    unmatched_a = sum(1 for key in a_by_key if key not in b_by_key)
    unmatched_b = sum(1 for key in b_by_key if key not in a_by_key)
    for key, record in sorted(a_by_key.items()):
        if key in b_by_key:
            pairs.append((record, b_by_key[key]))

    def _arm_stats(records: Sequence[ReplayRecord]) -> dict[str, Any]:
        all_times: list[float] = []
        all_censored: list[bool] = []
        clusters: dict[int, list[tuple[float, bool]]] = {}
        family_validated: dict[str, int] = {}
        family_total: dict[str, int] = {}
        validated_total = 0
        total = 0
        censored_total = 0
        cost_total = 0.0
        cost_known = True
        quota_known = True
        violations: dict[str, int] = {}
        for record in records:
            clusters.setdefault(record.seed, [])
            summary = record.summary()
            for outcome in _job_outcomes(record):
                all_times.append(outcome["ttv"])
                all_censored.append(outcome["censored"])
                clusters[record.seed].append((outcome["ttv"], outcome["censored"]))
                total += 1
                family_total[outcome["family"]] = (
                    family_total.get(outcome["family"], 0) + 1
                )
                if outcome["validated"]:
                    validated_total += 1
                    family_validated[outcome["family"]] = (
                        family_validated.get(outcome["family"], 0) + 1
                    )
                if outcome["censored"]:
                    censored_total += 1
            if summary["data_quality"]["cost_attribution_unknown"]:
                cost_known = False
            else:
                cost_total += summary["cost_total"]
            if not summary["data_quality"]["quota_display_known"]:
                quota_known = False
            for key, value in summary["violations"].items():
                violations[key] = violations.get(key, 0) + value
        survival = survival_summary(all_times, all_censored)
        ci = cluster_bootstrap(
            list(clusters.values()),
            stat=lambda sample: km_median(
                [x[0] for x in sample], [x[1] for x in sample]
            ),
            seed=b_seed,
            n_boot=n_boot,
        )
        return {
            "runs": len(records),
            "jobs": total,
            "ttv_median_iqr": median_iqr(all_times),
            "survival": {**survival, "median_ci": ci if ci["precision"] != "no_data" else None},
            "validation_success": wilson_ci(validated_total, total),
            "censored_jobs": censored_total,
            "fairness_gini": gini(family_validated),
            "family_counts": {
                fam: {"validated": family_validated.get(fam, 0), "total": n}
                for fam, n in family_total.items()
            },
            "cost": {
                "known": cost_known,
                "total": cost_total if cost_known else None,
                "precision": "known" if cost_known else "attribution_unknown",
            },
            "quota_display_known": quota_known,
            "violations": violations,
        }

    arm_a = _arm_stats(records_a)
    arm_b = _arm_stats(records_b)

    # Paired per-run diffs for the secondary permutation tests.
    diff_validation: list[float] = []
    diff_gini: list[float] = []
    diff_cost: list[float] = []
    for rec_a, rec_b in pairs:
        sa, sb = _run_stats(rec_a), _run_stats(rec_b)
        if sa["validation_rate"] is not None and sb["validation_rate"] is not None:
            diff_validation.append(sb["validation_rate"] - sa["validation_rate"])
        if sa["gini"] is not None and sb["gini"] is not None:
            diff_gini.append(sb["gini"] - sa["gini"])
        sum_a, sum_b = rec_a.summary(), rec_b.summary()
        if (
            not sum_a["data_quality"]["cost_attribution_unknown"]
            and not sum_b["data_quality"]["cost_attribution_unknown"]
        ):
            diff_cost.append(sum_b["cost_total"] - sum_a["cost_total"])

    p_validation = _permutation_p_value(diff_validation, n_perm=2000, seed=b_seed)
    p_gini = _permutation_p_value(diff_gini, n_perm=2000, seed=b_seed + 1)
    p_cost = _permutation_p_value(diff_cost, n_perm=2000, seed=b_seed + 2)
    p_values = [p_validation, p_cost, p_gini]
    adjusted = holm_correct(p_values)
    secondaries = {
        "validation_success": {
            "paired_diff_b_minus_a": (
                statistics.mean(diff_validation) if diff_validation else None
            ),
            "p_value": p_validation,
            "holm_adjusted": adjusted[0],
            "precision": "permutation_2000",
        },
        "cost_per_validated": {
            "a": (
                arm_a["cost"]["total"] / arm_a["validation_success"]["total"]
                if arm_a["cost"]["known"] and arm_a["validation_success"]["total"]
                else None
            ),
            "b": (
                arm_b["cost"]["total"] / arm_b["validation_success"]["total"]
                if arm_b["cost"]["known"] and arm_b["validation_success"]["total"]
                else None
            ),
            "paired_diff_b_minus_a": (
                statistics.mean(diff_cost) if diff_cost else None
            ),
            "p_value": p_cost,
            "holm_adjusted": adjusted[1],
            "precision": "permutation_2000",
        },
        "fairness_gini": {
            "paired_diff_b_minus_a": (
                statistics.mean(diff_gini) if diff_gini else None
            ),
            "p_value": p_gini,
            "holm_adjusted": adjusted[2],
            "precision": "permutation_2000",
        },
    }

    # Primary: paired cluster bootstrap of the survival-median difference.
    primary_ci = None
    if pairs:
        a_clusters = [
            [(o["ttv"], o["censored"]) for o in _job_outcomes(a)] for a, _b in pairs
        ]
        b_clusters = [
            [(o["ttv"], o["censored"]) for o in _job_outcomes(b)] for _a, b in pairs
        ]
        rng = random.Random(int(b_seed + 3))
        diffs: list[float] = []
        unestimable = 0
        for _ in range(n_boot):
            a_sample: list[tuple[float, bool]] = []
            b_sample: list[tuple[float, bool]] = []
            for _pair in range(len(pairs)):
                idx = rng.randrange(len(pairs))
                a_sample.extend(a_clusters[idx])
                b_sample.extend(b_clusters[idx])
            ma = km_median([x[0] for x in a_sample], [x[1] for x in a_sample])
            mb = km_median([x[0] for x in b_sample], [x[1] for x in b_sample])
            if ma is None or mb is None:
                unestimable += 1
                continue
            diffs.append(mb - ma)
        if diffs:
            diffs.sort()
            primary_ci = {
                "ci": [_percentile(diffs, 2.5), _percentile(diffs, 97.5)],
                "n_boot": n_boot,
                "unestimable": unestimable,
                "precision": "paired_cluster_bootstrap_95",
            }
    primary_diff = None
    if (
        arm_a["survival"]["median"] is not None
        and arm_b["survival"]["median"] is not None
    ):
        primary_diff = arm_b["survival"]["median"] - arm_a["survival"]["median"]

    return {
        "schema_version": 1,
        "primary_outcome": primary,
        "policy_a": {
            "name": records_a[0].policy.name if records_a else None,
            "digest": records_a[0].policy_digest if records_a else None,
        },
        "policy_b": {
            "name": records_b[0].policy.name if records_b else None,
            "digest": records_b[0].policy_digest if records_b else None,
        },
        "pairs": len(pairs),
        "unmatched": {"a": unmatched_a, "b": unmatched_b},
        "arms": {"a": arm_a, "b": arm_b},
        "primary": {
            "metric": primary,
            "median_a": arm_a["survival"]["median"],
            "median_b": arm_b["survival"]["median"],
            "diff_b_minus_a": primary_diff,
            "paired_cluster_bootstrap_95": primary_ci,
            "censored": {"a": arm_a["censored_jobs"], "b": arm_b["censored_jobs"]},
            "precision": (
                "insufficient_pairs"
                if len(pairs) < 3
                else (
                    "km_median"
                    if (
                        arm_a["survival"]["precision"] == "km_median"
                        and arm_b["survival"]["precision"] == "km_median"
                    )
                    else "insufficient_evidence"
                )
            ),
        },
        "secondaries": secondaries,
        "data_quality": {
            "quota_display_known": {
                "a": arm_a["quota_display_known"],
                "b": arm_b["quota_display_known"],
            },
            "cost_attribution_known": {
                "a": arm_a["cost"]["known"],
                "b": arm_b["cost"]["known"],
            },
            "note": (
                "Unknown quota or cost attribution is reported as unknown; "
                "no fabricated precision is added."
            ),
        },
        "deterministic": True,
        "evidence_ceiling": "provider_free_replay_only",
    }
