#!/usr/bin/env python3
"""Aggregate the provider-free M0 evidence gates into one report.

This is an orchestration-only, read-only boundary.  It invokes the existing
source-truth, public-scrub, holdout, and deterministic-baseline tools through
argv lists (never a shell), stores no child stdout/stderr, and never contacts a
provider or mutates the repository.  The report is suitable for a private
dated evidence directory; it does not promote provisional labels or provider
readiness.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any, Sequence


SCHEMA_VERSION = 1
REPORT_TYPE = "local-agent-dispatch.m0_gate_snapshot"
DEFAULT_TIMEOUT_SECONDS = 900.0
DEFAULT_PUBLIC_REF = "refs/tags/public-v0.1.0-alpha.6"
DEFAULT_CORPUS = "research/corpus/generic-mission-benchmark-v1.json"
DEFAULT_MANIFEST = "research/corpus/generic-mission-benchmark-v1-holdout.json"
DEFAULT_BASELINE_COMMAND = (
    "python3",
    "-m",
    "unittest",
    "discover",
    "-s",
    "tests",
    "-p",
    "test_*.py",
)


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _current_head(root: pathlib.Path) -> str | None:
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def _safe_relative(root: pathlib.Path, raw: str) -> str:
    path = pathlib.Path(raw).expanduser()
    if path.is_absolute():
        try:
            path = path.resolve().relative_to(root)
        except ValueError as exc:
            raise ValueError(f"path escapes repository: {raw!r}") from exc
    else:
        path = pathlib.PurePosixPath(str(path).replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ValueError(f"unsafe repository path: {raw!r}")
    return path.as_posix()


def _clean_environment() -> dict[str, str]:
    env: dict[str, str] = {}
    for key, value in os.environ.items():
        upper = key.upper()
        if any(token in upper for token in ("API_KEY", "TOKEN", "SECRET", "PASSWORD")):
            continue
        env[key] = value
    env.update({"CI": "1", "NO_COLOR": "1", "PYTHONDONTWRITEBYTECODE": "1"})
    return env


def _step_gate(name: str, report: dict[str, Any]) -> str:
    if name == "source_truth":
        return (
            "pass"
            if report.get("canonical_state") in {"aligned", "ancestry_reconciled"}
            and report.get("working_tree_dirty") is False
            and not report.get("denied_candidates")
            else "blocked"
        )
    if name == "public_scrub":
        return "pass" if report.get("gate") == "pass" else "blocked"
    if name == "holdout":
        return "pass" if report.get("valid") is True else "blocked"
    if name == "baseline":
        return "pass" if report.get("gate") == "pass" else "blocked"
    return "blocked"


def _run_step(
    root: pathlib.Path,
    name: str,
    argv: Sequence[str],
    timeout_seconds: float,
) -> dict[str, Any]:
    command = [str(item) for item in argv]
    try:
        completed = subprocess.run(
            command,
            cwd=root,
            env=_clean_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "name": name,
            "status": "error",
            "exit_code": None,
            "timed_out": True,
            "stdout_sha256": _sha256(exc.stdout or b""),
            "stderr_sha256": _sha256(exc.stderr or b""),
            "report": None,
            "gate": "blocked",
        }
    stdout = completed.stdout or b""
    stderr = completed.stderr or b""
    try:
        report = json.loads(stdout.decode("utf-8"))
        if not isinstance(report, dict):
            raise ValueError("child report is not an object")
        status = "ok" if completed.returncode == 0 else "reported_failure"
        gate = _step_gate(name, report)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        report = None
        status = "invalid_output"
        gate = "blocked"
    return {
        "name": name,
        "status": status,
        "exit_code": completed.returncode,
        "timed_out": False,
        "stdout_sha256": _sha256(stdout),
        "stderr_sha256": _sha256(stderr),
        "report_sha256": _sha256(_canonical(report)) if report is not None else None,
        "report": report,
        "gate": gate,
        "provider_execution": False,
        "network_execution": False,
        "read_only": True,
    }


def build_report(
    repo: pathlib.Path | str,
    *,
    public_ref: str = DEFAULT_PUBLIC_REF,
    corpus: str = DEFAULT_CORPUS,
    manifest: str = DEFAULT_MANIFEST,
    baseline_command: Sequence[str] = DEFAULT_BASELINE_COMMAND,
    include_baseline: bool = True,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    require_current_source_head: bool = False,
) -> dict[str, Any]:
    root = pathlib.Path(repo).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"repository does not exist: {root}")
    if timeout_seconds <= 0 or timeout_seconds > 3600:
        raise ValueError("timeout_seconds must be in (0, 3600]")
    corpus_rel = _safe_relative(root, corpus)
    manifest_rel = _safe_relative(root, manifest)
    script = root / "scripts"
    steps: list[dict[str, Any]] = []
    steps.append(
        _run_step(
            root,
            "source_truth",
            [
                sys.executable,
                str(script / "source_truth_audit.py"),
                "--repo",
                ".",
                "--public-ref",
                public_ref,
                "--require-public-ref",
                "--require-reconciled",
            ],
            timeout_seconds,
        )
    )
    steps.append(
        _run_step(
            root,
            "public_scrub",
            [
                sys.executable,
                str(script / "public_scrub.py"),
                "--repo",
                ".",
                "--ref",
                public_ref,
                "--allow-path",
                "tests/fixtures/redaction",
            ],
            timeout_seconds,
        )
    )
    steps.append(
        _run_step(
            root,
            "holdout",
            [
                sys.executable,
                str(script / "benchmark_holdout.py"),
                "--corpus",
                corpus_rel,
                "--manifest",
                manifest_rel,
            ],
            timeout_seconds,
        )
    )
    if include_baseline:
        steps.append(
            _run_step(
                root,
                "baseline",
                [
                    sys.executable,
                    str(script / "m0_baseline_runner.py"),
                    "--repo",
                    ".",
                    "--command-json",
                    json.dumps(list(baseline_command), separators=(",", ":")),
                    "--fixture",
                    corpus_rel,
                    "--require-clean",
                ],
                timeout_seconds,
            )
        )
    current_head = _current_head(root)
    source_truth_step = next(
        (step for step in steps if step.get("name") == "source_truth"), None
    )
    source_report = (
        source_truth_step.get("report")
        if isinstance(source_truth_step, dict)
        else None
    )
    source_head = (
        source_report.get("local_head")
        if isinstance(source_report, dict)
        else None
    )
    source_head_is_current = (
        isinstance(source_head, str)
        and isinstance(current_head, str)
        and source_head == current_head
    )
    if require_current_source_head and not source_head_is_current:
        if isinstance(source_truth_step, dict):
            source_truth_step["gate"] = "blocked"
            source_truth_step[
                "blocking_reason"
            ] = "source_truth_head_not_current_head"
    gates = {step["name"]: step["gate"] for step in steps}
    passed = all(value == "pass" for value in gates.values())
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "report_type": REPORT_TYPE,
        "observed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "repository": ".",
        "public_ref": public_ref,
        "corpus": corpus_rel,
        "manifest": manifest_rel,
        "current_head": current_head,
        "source_head": source_head,
        "source_head_is_current": source_head_is_current,
        "require_current_source_head": require_current_source_head,
        "source_head_policy": (
            "exact_current_head" if require_current_source_head else "reported"
        ),
        "steps": steps,
        "gates": gates,
        "gate": "pass" if passed else "blocked",
        "provider_execution": False,
        "network_execution": False,
        "read_only": True,
        "evidence_ceiling": "provider_free_m0_gate_aggregation",
    }
    report["report_sha256"] = _sha256(_canonical(report))
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=".")
    parser.add_argument("--public-ref", default=DEFAULT_PUBLIC_REF)
    parser.add_argument("--corpus", default=DEFAULT_CORPUS)
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    parser.add_argument("--skip-baseline", action="store_true")
    parser.add_argument(
        "--require-current-source-head",
        action="store_true",
        help="block unless the source-truth report head equals current HEAD exactly",
    )
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--output", default="-")
    args = parser.parse_args(argv)
    try:
        report = build_report(
            args.repo,
            public_ref=args.public_ref,
            corpus=args.corpus,
            manifest=args.manifest,
            include_baseline=not args.skip_baseline,
            timeout_seconds=args.timeout,
            require_current_source_head=args.require_current_source_head,
        )
    except (OSError, subprocess.CalledProcessError, TypeError, ValueError) as exc:
        parser.error(str(exc))
    text = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output == "-":
        print(text, end="")
    else:
        output = pathlib.Path(args.output).expanduser()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
    return 0 if report["gate"] == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
