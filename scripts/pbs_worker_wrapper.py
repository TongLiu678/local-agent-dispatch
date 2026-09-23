#!/usr/bin/env python3
"""Submit and run the provider-free worker through an existing PBS queue.

This module is deliberately a narrow scheduler seam.  It does not interpret a
task packet, invoke a provider, copy credentials, or accept an arbitrary shell
command.  ``submit`` only submits a fixed ``run`` invocation and ``run`` only
executes the deterministic ``remote_worker.py fake-service`` contract.  A
future real adapter must be reviewed separately while retaining the receipt,
lease, artifact, and claim gates.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import shlex
import shutil
import subprocess
import sys
import time
from typing import Any, Mapping


SCHEMA_VERSION = "1.0"
_SAFE_COMPONENT = re.compile(r"^[A-Za-z0-9._+:@=-]+$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_SAFE_JOB_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_PBS_ID = re.compile(r"^[A-Za-z0-9._:-]{1,256}$")
_MAX_WORKER_OUTPUT = 2 * 1024 * 1024


class PBSWorkerError(RuntimeError):
    """Raised when the bounded PBS worker contract cannot be satisfied."""


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _digest_text(value: str) -> str:
    return _digest_bytes(value.encode("utf-8"))


def _digest_file(path: pathlib.Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            digest.update(chunk)
    return size, digest.hexdigest()


def _safe_path(value: str | pathlib.Path, *, label: str, must_exist: bool = False) -> pathlib.Path:
    raw = str(value)
    if not raw or "\x00" in raw or not raw.startswith("/"):
        raise PBSWorkerError(f"{label} must be an absolute path")
    path = pathlib.Path(raw)
    if any(part in {".", ".."} or not _SAFE_COMPONENT.fullmatch(part) for part in path.parts if part != "/"):
        raise PBSWorkerError(f"{label} contains an unsafe path component")
    try:
        resolved = path.resolve(strict=must_exist)
    except OSError as exc:
        raise PBSWorkerError(f"{label} could not be resolved") from exc
    if must_exist and not resolved.exists():
        raise PBSWorkerError(f"{label} does not exist")
    return resolved


def _ensure_directory(value: str | pathlib.Path, *, label: str) -> pathlib.Path:
    path = _safe_path(value, label=label)
    try:
        path.mkdir(parents=True, exist_ok=True)
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise PBSWorkerError(f"{label} is not writable") from exc
    if not resolved.is_dir():
        raise PBSWorkerError(f"{label} is not a directory")
    return resolved


def _safe_id(value: str, *, label: str, pattern: re.Pattern[str] = _SAFE_ID) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise PBSWorkerError(f"{label} is invalid")
    return value


def _safe_digest(value: str | None, *, label: str, required: bool = False) -> str | None:
    """Validate an optional lowercase SHA-256 binding carried by a receipt."""
    if value is None and not required:
        return None
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise PBSWorkerError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _executable(value: str | pathlib.Path, *, label: str) -> pathlib.Path:
    raw = str(value)
    candidate: pathlib.Path
    if raw.startswith("/"):
        candidate = _safe_path(raw, label=label, must_exist=True)
    else:
        resolved = shutil.which(raw)
        if not resolved:
            raise PBSWorkerError(f"{label} was not found")
        candidate = _safe_path(resolved, label=label, must_exist=True)
    if not candidate.is_file() or not os.access(candidate, os.X_OK):
        raise PBSWorkerError(f"{label} is not executable")
    return candidate


def _positive_int(value: str, *, label: str, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise PBSWorkerError(f"{label} must be an integer") from exc
    if parsed < 1 or parsed > maximum:
        raise PBSWorkerError(f"{label} must be between 1 and {maximum}")
    return parsed


def _nonnegative_int(value: str, *, label: str, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise PBSWorkerError(f"{label} must be an integer") from exc
    if parsed < 0 or parsed > maximum:
        raise PBSWorkerError(f"{label} must be between 0 and {maximum}")
    return parsed


def _poll_seconds(value: str) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise PBSWorkerError("poll-seconds must be a number") from exc
    if parsed < 0.01 or parsed > 3600:
        raise PBSWorkerError("poll-seconds must be between 0.01 and 3600")
    return parsed


def _atomic_json(path: pathlib.Path, payload: Mapping[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.partial")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def _artifact_row(path: pathlib.Path) -> dict[str, Any]:
    try:
        size, digest = _digest_file(path)
    except OSError as exc:
        return {"path": str(path), "exists": False, "error": type(exc).__name__}
    return {"path": str(path), "exists": True, "bytes": size, "sha256": digest}


def _bounded_json(path: pathlib.Path) -> dict[str, Any] | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if len(data) > _MAX_WORKER_OUTPUT:
        return None
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return dict(value) if isinstance(value, Mapping) else None


def _safe_worker_result(result: Mapping[str, Any] | None) -> dict[str, Any]:
    if not result:
        return {}
    allowed = (
        "schema_version",
        "service",
        "provider_execution",
        "job_id",
        "status",
        "resume_required",
        "resume_allowed",
        "next_action",
        "idle_rounds",
        "error",
    )
    return {key: result[key] for key in allowed if key in result}


def _safe_artifact_relative(value: Any) -> str:
    """Validate a POSIX-relative artifact path from a worker handoff."""
    if not isinstance(value, str) or not value or len(value) > 1024:
        raise PBSWorkerError("artifact path is invalid")
    if "\x00" in value or "\\" in value or value.startswith("/"):
        raise PBSWorkerError("artifact path is invalid")
    parts = value.split("/")
    if any(
        not part or part in {".", ".."} or not _SAFE_COMPONENT.fullmatch(part)
        for part in parts
    ):
        raise PBSWorkerError("artifact path is invalid")
    return "/".join(parts)


def _safe_artifact_rows(value: Any) -> list[dict[str, Any]]:
    """Reduce a worker-reported artifact manifest to hash-bearing rows."""
    if not isinstance(value, list) or len(value) > 256:
        raise PBSWorkerError("artifact manifest is invalid")
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, Mapping):
            raise PBSWorkerError("artifact manifest row is invalid")
        path = _safe_artifact_relative(item.get("path"))
        if path in seen:
            raise PBSWorkerError("artifact manifest contains duplicate paths")
        seen.add(path)
        if item.get("status") != "present":
            raise PBSWorkerError("artifact manifest contains a non-present artifact")
        size = item.get("size")
        if isinstance(size, bool) or not isinstance(size, int) or size < 1 or size > (1 << 50):
            raise PBSWorkerError("artifact manifest size is invalid")
        digest = _safe_digest(item.get("sha256"), label="artifact sha256", required=True)
        rows.append({"path": path, "status": "present", "size": size, "sha256": digest})
    return rows


def _artifact_failure(reason: str, *, manifest: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Build a bounded validation result without exposing worker payloads."""
    return {
        "artifact_manifest": list(manifest or []),
        "validation": {
            "ok": False,
            "validator": "pbs_worker_wrapper.artifact_rehash_v1",
            "artifact_freshness_verified": False,
            "reason": reason,
        },
    }


def _validated_artifact_evidence(
    worker_payload: Mapping[str, Any] | None,
    *,
    expected_job_id: str,
) -> dict[str, Any]:
    """Independently rehash the declared PBS artifacts.

    The worker result is only a hint.  This function obtains the project root
    and declaration from the bounded manifest/handoff, resolves every path
    beneath that root, hashes the current files, and compares them with the
    worker's own manifest.  It never returns the raw worker payload.
    """
    if not isinstance(worker_payload, Mapping):
        return _artifact_failure("worker_result_unreadable")
    if worker_payload.get("job_id") not in {None, expected_job_id}:
        return _artifact_failure("worker_job_id_mismatch")
    sources: list[Mapping[str, Any]] = [worker_payload]
    for key in ("manifest", "handoff"):
        value = worker_payload.get(key)
        if isinstance(value, Mapping):
            sources.append(value)

    project_root: Any = None
    required_raw: Any = None
    expected_raw: Any = None
    freshness: Any = None
    source_job_ids: set[str] = set()
    for source in sources:
        source_job = source.get("job_id")
        if source_job is not None:
            source_job_ids.add(str(source_job))
        if project_root is None and source.get("project_root") is not None:
            project_root = source.get("project_root")
        if required_raw is None and isinstance(source.get("required_artifacts"), list):
            required_raw = source.get("required_artifacts")
        if expected_raw is None and isinstance(source.get("artifact_manifest"), list):
            expected_raw = source.get("artifact_manifest")
        if freshness is None and source.get("artifact_freshness_verified") is not None:
            freshness = source.get("artifact_freshness_verified")
    if source_job_ids and source_job_ids != {expected_job_id}:
        return _artifact_failure("worker_job_id_mismatch")
    if not isinstance(required_raw, list):
        return _artifact_failure("required_artifacts_missing")
    if not isinstance(freshness, bool):
        return _artifact_failure("artifact_freshness_missing")
    try:
        root = _safe_path(project_root, label="artifact-project-root", must_exist=True)
        if not root.is_dir():
            return _artifact_failure("artifact-project-root-not-directory")
        required: list[str] = []
        for raw in required_raw:
            path = _safe_artifact_relative(raw)
            if path in required:
                raise PBSWorkerError("required_artifacts contains duplicate paths")
            required.append(path)
        observed: list[dict[str, Any]] = []
        for relative in required:
            candidate = root.joinpath(*relative.split("/"))
            if candidate.is_symlink():
                return _artifact_failure("artifact_symlink_rejected")
            resolved = candidate.resolve(strict=True)
            try:
                resolved.relative_to(root)
            except ValueError:
                return _artifact_failure("artifact_path_escape")
            if not resolved.is_file():
                return _artifact_failure("artifact_not_regular_file")
            before_stat = resolved.stat()
            size, digest = _digest_file(resolved)
            after_stat = resolved.stat()
            if (
                before_stat.st_dev != after_stat.st_dev
                or before_stat.st_ino != after_stat.st_ino
                or before_stat.st_size != after_stat.st_size
                or before_stat.st_mtime_ns != after_stat.st_mtime_ns
            ):
                return _artifact_failure("artifact_changed_during_validation")
            if size < 1:
                return _artifact_failure("artifact_empty")
            observed.append({"path": relative, "status": "present", "size": size, "sha256": digest})
        if expected_raw is not None:
            expected = _safe_artifact_rows(expected_raw)
            if expected != observed:
                return _artifact_failure("artifact_manifest_mismatch", manifest=observed)
        manifest_digest = _digest_text(
            json.dumps(observed, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        )
        validation: dict[str, Any] = {
            "ok": bool(freshness),
            "validator": "pbs_worker_wrapper.artifact_rehash_v1",
            "artifact_freshness_verified": bool(freshness),
            "artifact_manifest_digest": manifest_digest,
        }
        if not freshness:
            validation["reason"] = "artifact_freshness_not_verified"
        return {"artifact_manifest": observed, "validation": validation}
    except (OSError, PBSWorkerError, TypeError, ValueError):
        return _artifact_failure("artifact_validation_error")


def _worker_command(args: argparse.Namespace) -> list[str]:
    return [
        str(args.python),
        "-B",
        str(args.worker_script),
        "fake-service",
        "--spool",
        str(args.spool),
        "--job-id",
        args.job_id,
        "--owner",
        args.owner,
        "--poll-seconds",
        str(args.poll_seconds),
        "--max-idle-rounds",
        str(args.max_idle_rounds),
        "--lease-seconds",
        str(args.lease_seconds),
    ]


def run_worker(args: argparse.Namespace) -> int:
    args.python = _executable(args.python, label="python")
    args.worker_script = _safe_path(args.worker_script, label="worker-script", must_exist=True)
    if not args.worker_script.is_file():
        raise PBSWorkerError("worker-script is not a file")
    args.spool = _safe_path(args.spool, label="spool")
    args.run_root = _ensure_directory(args.run_root, label="run-root")
    _safe_id(args.job_id, label="job-id", pattern=_SAFE_JOB_ID)
    _safe_id(args.owner, label="owner")
    request_id = _safe_id(args.request_id, label="request-id") if args.request_id else None
    idempotency_key = _safe_id(args.idempotency_key, label="idempotency-key") if args.idempotency_key else None
    payload_digest = _safe_digest(args.payload_digest, label="payload-digest")
    args.poll_seconds = _poll_seconds(str(args.poll_seconds))
    args.max_idle_rounds = _nonnegative_int(str(args.max_idle_rounds), label="max-idle-rounds", maximum=10_000_000)
    args.lease_seconds = _positive_int(str(args.lease_seconds), label="lease-seconds", maximum=86_400)
    args.spool.mkdir(parents=True, exist_ok=True)
    if args.tmp_root:
        # ``run_root`` is durable and may be on NFS/shared storage, while
        # scratch must be local to the PBS execution node.  Keep one
        # job-specific child so simultaneous jobs cannot share locks/cache.
        tmp_root = _safe_path(args.tmp_root, label="tmp-root")
        temporary_dir = _ensure_directory(tmp_root / args.job_id, label="tmp-root.job")
    else:
        # Backward-compatible fallback for older manifests.  New central
        # cluster inventories should always declare ``tmp_root`` explicitly.
        temporary_dir = _ensure_directory(args.run_root / "tmp", label="run-root.tmp")
    stdout_path = args.run_root / "worker.json"
    stderr_path = args.run_root / "worker.stderr"
    receipt_path = args.run_root / "receipt.json"
    started_at = _utc_now()
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["TMPDIR"] = str(temporary_dir)
    worker_rc = 127
    spawn_error: str | None = None
    try:
        with stdout_path.open("wb") as stdout_handle, stderr_path.open("wb") as stderr_handle:
            completed = subprocess.run(
                _worker_command(args),
                cwd=str(args.worker_script.parent.parent),
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=stdout_handle,
                stderr=stderr_handle,
                check=False,
            )
        worker_rc = int(completed.returncode)
    except OSError as exc:
        spawn_error = type(exc).__name__
        stderr_path.write_text(spawn_error + "\n", encoding="utf-8")

    result = _bounded_json(stdout_path)
    worker_result = _safe_worker_result(result)
    status = str(worker_result.get("status") or ("failed" if worker_rc else "unknown"))
    receipt = {
        "schema_version": SCHEMA_VERSION,
        "receipt_type": "local-agent-dispatch.pbs-worker",
        "service": "provider_free_fixture",
        "provider_execution": False,
        "network_execution": False,
        "pbs_job_id": os.environ.get("PBS_JOBID") or os.environ.get("PBS_JOB_ID"),
        "host": os.uname().nodename,
        "job_id": args.job_id,
        "request_id": request_id,
        "idempotency_key": idempotency_key,
        "payload_digest": payload_digest,
        "owner_digest": _digest_text(args.owner),
        "worker_script": str(args.worker_script),
        "spool": str(args.spool),
        "run_root": str(args.run_root),
        "tmp_root": str(temporary_dir),
        "started_at": started_at,
        "completed_at": _utc_now(),
        "worker_exit_code": worker_rc,
        "status": status,
        "ok": worker_rc == 0 and status == "completed",
        "worker_result": worker_result,
        "worker_result_sha256": _digest_file(stdout_path)[1] if stdout_path.exists() else None,
        "spawn_error": spawn_error,
        "artifacts": [_artifact_row(stdout_path), _artifact_row(stderr_path)],
    }
    _atomic_json(receipt_path, receipt)
    return worker_rc


def _pbs_script(args: argparse.Namespace, wrapper: pathlib.Path) -> str:
    command = [
        # Do not rely on the batch node's shebang PATH.  Cluster login and
        # execution nodes often expose different Python runtimes (for
        # example, ``python3`` may be absent on an older Torque node), while
        # ``args.python`` has already passed the explicit executable gate.
        str(args.python),
        "-B",
        str(wrapper),
        "run",
        "--python",
        str(args.python),
        "--worker-script",
        str(args.worker_script),
        "--spool",
        str(args.spool),
        "--job-id",
        args.job_id,
        "--owner",
        args.owner,
        "--run-root",
        str(args.run_root),
        "--poll-seconds",
        str(args.poll_seconds),
        "--max-idle-rounds",
        str(args.max_idle_rounds),
        "--lease-seconds",
        str(args.lease_seconds),
    ]
    if args.request_id:
        command.extend(["--request-id", args.request_id])
    if args.payload_digest:
        command.extend(["--payload-digest", args.payload_digest])
    if args.idempotency_key:
        command.extend(["--idempotency-key", args.idempotency_key])
    if args.tmp_root:
        command.extend(["--tmp-root", str(args.tmp_root)])
    return "#!/bin/sh\nset -eu\nexec " + " ".join(shlex.quote(part) for part in command) + "\n"


def submit_worker(args: argparse.Namespace) -> int:
    args.python = _executable(args.python, label="python")
    args.worker_script = _safe_path(args.worker_script, label="worker-script", must_exist=True)
    args.spool = _safe_path(args.spool, label="spool")
    args.run_root = _ensure_directory(args.run_root, label="run-root")
    if args.tmp_root:
        # Do not create scratch on the login/controller node.  Only validate
        # its shape here; the batch node creates its job child in run_worker.
        args.tmp_root = _safe_path(args.tmp_root, label="tmp-root")
    args.qsub = _executable(args.qsub, label="qsub")
    wrapper = _safe_path(args.wrapper, label="wrapper", must_exist=True)
    if not wrapper.is_file():
        raise PBSWorkerError("wrapper is not a file")
    _safe_id(args.job_id, label="job-id", pattern=_SAFE_JOB_ID)
    _safe_id(args.owner, label="owner")
    request_id = _safe_id(args.request_id, label="request-id") if args.request_id else None
    payload_digest = _safe_digest(args.payload_digest, label="payload-digest")
    idempotency_key = _safe_id(args.idempotency_key, label="idempotency-key") if args.idempotency_key else None
    _safe_id(args.queue, label="queue")
    nodes = _positive_int(str(args.nodes), label="nodes", maximum=1024)
    ppn = _positive_int(str(args.ppn), label="ppn", maximum=4096)
    args.poll_seconds = _poll_seconds(str(args.poll_seconds))
    args.max_idle_rounds = _nonnegative_int(str(args.max_idle_rounds), label="max-idle-rounds", maximum=10_000_000)
    args.lease_seconds = _positive_int(str(args.lease_seconds), label="lease-seconds", maximum=86_400)
    script = _pbs_script(args, wrapper)
    submission_path = args.run_root / "submission.json"
    intent_path = args.run_root / "submission.intent.json"
    # The run root is deterministic for a controller request.  If an SSH
    # response was lost after qsub accepted the job, returning the original
    # immutable submission receipt avoids a second PBS side effect.
    existing = _bounded_json(submission_path)
    if existing is not None:
        expected = {
            "job_id": args.job_id,
            "owner_digest": _digest_text(args.owner),
            "run_root": str(args.run_root),
        }
        if any(existing.get(key) != value for key, value in expected.items()):
            raise PBSWorkerError("run-root already contains a different submission")
        if request_id is not None and existing.get("request_id") != request_id:
            raise PBSWorkerError("run-root submission request-id conflicts")
        if payload_digest is not None and existing.get("payload_digest") != payload_digest:
            raise PBSWorkerError("run-root submission payload-digest conflicts")
        if idempotency_key is not None and existing.get("idempotency_key") != idempotency_key:
            raise PBSWorkerError("run-root submission idempotency-key conflicts")
        existing = dict(existing)
        existing["idempotent"] = True
        print(json.dumps(existing, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    intent = {
        "schema_version": SCHEMA_VERSION,
        "receipt_type": "local-agent-dispatch.pbs-submission-intent",
        "status": "submitting",
        "provider_execution": False,
        "network_execution": False,
        "job_id": args.job_id,
        "request_id": request_id,
        "idempotency_key": idempotency_key,
        "payload_digest": payload_digest,
        "owner_digest": _digest_text(args.owner),
        "run_root": str(args.run_root),
        "script_sha256": _digest_text(script),
        "created_at": _utc_now(),
    }
    existing_intent = _bounded_json(intent_path)
    if existing_intent is not None:
        expected_intent = {
            "job_id": args.job_id,
            "owner_digest": _digest_text(args.owner),
            "run_root": str(args.run_root),
            "script_sha256": _digest_text(script),
        }
        if any(existing_intent.get(key) != value for key, value in expected_intent.items()):
            raise PBSWorkerError("run-root contains a conflicting submission intent")
        if existing_intent.get("status") != "submitted":
            raise PBSWorkerError("submission intent exists without a durable PBS receipt")
    qsub_argv = [
        str(args.qsub),
        "-q",
        args.queue,
        "-N",
        f"lad-{args.job_id}",
        "-l",
        f"nodes={nodes}:ppn={ppn}",
        "-o",
        str(args.run_root / "stdout"),
        "-e",
        str(args.run_root / "stderr"),
    ]
    if existing_intent is None:
        _atomic_json(intent_path, intent)
    try:
        completed = subprocess.run(
            qsub_argv,
            input=script.encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise PBSWorkerError(f"qsub could not start: {type(exc).__name__}") from exc
    except OSError as exc:
        # Leave the intent in place: an external supervisor can distinguish a
        # potentially submitted job from a clean retry and will not issue a
        # second qsub blindly.
        raise PBSWorkerError(f"qsub could not start: {type(exc).__name__}") from exc
    if completed.returncode != 0:
        intent_path.unlink(missing_ok=True)
        raise PBSWorkerError(
            "qsub rejected the bounded worker "
            + json.dumps(
                {
                    "returncode": int(completed.returncode),
                    "stderr_bytes": len(completed.stderr),
                    "stderr_sha256": _digest_bytes(completed.stderr),
                },
                sort_keys=True,
            )
        )
    lines = [line.strip() for line in completed.stdout.decode("utf-8", errors="replace").splitlines() if line.strip()]
    pbs_job_id = lines[-1] if lines else ""
    if not _PBS_ID.fullmatch(pbs_job_id):
        raise PBSWorkerError("qsub returned an invalid job id")
    submission = {
        "schema_version": SCHEMA_VERSION,
        "receipt_type": "local-agent-dispatch.pbs-submission",
        # Keep the transport stage explicit so a controller can distinguish a
        # durable PBS acceptance from a terminal worker receipt.  Older
        # submission files may omit this field; the controller bridge accepts
        # those only when their receipt_type is the fixed submission type.
        "status": "accepted",
        "provider_execution": False,
        "network_execution": False,
        "pbs_job_id": pbs_job_id,
        "queue": args.queue,
        "nodes": nodes,
        "ppn": ppn,
        "job_id": args.job_id,
        "request_id": request_id,
        "idempotency_key": idempotency_key,
        "payload_digest": payload_digest,
        "owner_digest": _digest_text(args.owner),
        "run_root": str(args.run_root),
        "stdout_path": str(args.run_root / "stdout"),
        "stderr_path": str(args.run_root / "stderr"),
        "script_sha256": _digest_text(script),
        "qsub_argv_sha256": _digest_text(json.dumps(qsub_argv, separators=(",", ":"), sort_keys=True)),
        "submitted_at": _utc_now(),
    }
    _atomic_json(submission_path, submission)
    _atomic_json(intent_path, {**intent, "status": "submitted", "pbs_job_id": pbs_job_id, "submitted_at": submission["submitted_at"]})
    print(json.dumps(submission, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def status_worker(args: argparse.Namespace) -> int:
    """Read the fixed PBS submission/worker receipts without mutating them."""
    args.run_root = _safe_path(args.run_root, label="run-root", must_exist=True)
    _safe_id(args.job_id, label="job-id", pattern=_SAFE_JOB_ID)
    _safe_id(args.owner, label="owner")
    request_id = _safe_id(args.request_id, label="request-id") if args.request_id else None
    idempotency_key = _safe_id(args.idempotency_key, label="idempotency-key") if args.idempotency_key else None
    payload_digest = _safe_digest(args.payload_digest, label="payload-digest")
    submission = _bounded_json(args.run_root / "submission.json")
    intent = _bounded_json(args.run_root / "submission.intent.json")
    receipt = _bounded_json(args.run_root / "receipt.json")
    if submission is None and receipt is None and intent is not None:
        if intent.get("job_id") != args.job_id or intent.get("owner_digest") != _digest_text(args.owner):
            raise PBSWorkerError("submission intent identity does not match status request")
        payload = {
            "schema_version": SCHEMA_VERSION,
            "status": "submitted_unknown",
            "provider_execution": False,
            "network_execution": False,
            "job_id": args.job_id,
            "request_id": intent.get("request_id"),
            "idempotency_key": intent.get("idempotency_key"),
            "payload_digest": intent.get("payload_digest"),
            "run_root": intent.get("run_root"),
            "submission_intent_digest": _digest_file(args.run_root / "submission.intent.json")[1],
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if submission is None and receipt is None:
        payload = {
            "schema_version": SCHEMA_VERSION,
            "status": "pending",
            "provider_execution": False,
            "network_execution": False,
            "job_id": args.job_id,
            "request_id": request_id,
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if submission is not None:
        if submission.get("job_id") != args.job_id or submission.get("owner_digest") != _digest_text(args.owner):
            raise PBSWorkerError("submission identity does not match status request")
        if request_id is not None and submission.get("request_id") != request_id:
            raise PBSWorkerError("submission request-id does not match status request")
        if payload_digest is not None and submission.get("payload_digest") != payload_digest:
            raise PBSWorkerError("submission payload-digest does not match status request")
        if idempotency_key is not None and submission.get("idempotency_key") != idempotency_key:
            raise PBSWorkerError("submission idempotency-key does not match status request")
    if receipt is not None:
        if receipt.get("job_id") != args.job_id or receipt.get("owner_digest") != _digest_text(args.owner):
            raise PBSWorkerError("worker receipt identity does not match status request")
        if request_id is not None and receipt.get("request_id") != request_id:
            raise PBSWorkerError("worker receipt request-id does not match status request")
        if payload_digest is not None and receipt.get("payload_digest") != payload_digest:
            raise PBSWorkerError("worker receipt payload-digest does not match status request")
        if idempotency_key is not None and receipt.get("idempotency_key") != idempotency_key:
            raise PBSWorkerError("worker receipt idempotency-key does not match status request")
        status = receipt.get("status")
        if status not in {"completed", "failed"}:
            raise PBSWorkerError("worker receipt status is invalid")
        result_digest = receipt.get("worker_result_sha256")
        payload = {
            "schema_version": SCHEMA_VERSION,
            "status": status,
            "provider_execution": False,
            "network_execution": False,
            "job_id": args.job_id,
            "request_id": receipt.get("request_id"),
            "idempotency_key": receipt.get("idempotency_key"),
            "payload_digest": receipt.get("payload_digest"),
            "pbs_job_id": receipt.get("pbs_job_id"),
            "run_root": receipt.get("run_root"),
            "result_digest": result_digest if status == "completed" else None,
            "error_code": "pbs_worker_failed" if status == "failed" else None,
            "worker_receipt_digest": _digest_file(args.run_root / "receipt.json")[1],
        }
        # ``worker.json`` is an untrusted execution report.  When present,
        # expose only an independently rehashed artifact manifest and its
        # bounded validation result.  Missing legacy worker output remains
        # transport-only; a present but malformed report is explicit evidence
        # of a blocked promotion rather than a reason to trust the receipt.
        worker_path = args.run_root / "worker.json"
        if worker_path.exists():
            evidence = (
                _artifact_failure("worker_result_symlink_rejected")
                if worker_path.is_symlink()
                else _validated_artifact_evidence(
                    _bounded_json(worker_path), expected_job_id=args.job_id
                )
            )
            payload.update(evidence)
    else:
        payload = {
            "schema_version": SCHEMA_VERSION,
            "status": "accepted",
            "provider_execution": False,
            "network_execution": False,
            "job_id": args.job_id,
            "request_id": submission.get("request_id"),
            "idempotency_key": submission.get("idempotency_key"),
            "payload_digest": submission.get("payload_digest"),
            "pbs_job_id": submission.get("pbs_job_id"),
            "run_root": submission.get("run_root"),
            "submission_digest": _digest_file(args.run_root / "submission.json")[1],
        }
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--worker-script", required=True)
    parser.add_argument("--spool", required=True)
    parser.add_argument("--job-id", required=True)
    parser.add_argument("--owner", required=True)
    parser.add_argument("--run-root", required=True)
    parser.add_argument(
        "--tmp-root",
        help="node-local scratch root; a job-specific child is created at run time",
    )
    parser.add_argument("--poll-seconds", type=float, default=1.0)
    parser.add_argument("--max-idle-rounds", type=int, default=0)
    parser.add_argument("--lease-seconds", type=int, default=90)
    parser.add_argument("--request-id")
    parser.add_argument("--idempotency-key")
    parser.add_argument("--payload-digest")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="bounded provider-free PBS worker")
    sub = parser.add_subparsers(dest="mode", required=True)
    run = sub.add_parser("run", help="run only remote_worker.py fake-service")
    _common(run)
    submit = sub.add_parser("submit", help="submit the fixed provider-free run invocation to PBS")
    _common(submit)
    submit.add_argument("--qsub", default=os.environ.get("LAD_PBS_QSUB", "qsub"))
    submit.add_argument("--queue", default="workq")
    submit.add_argument("--nodes", type=int, default=1)
    submit.add_argument("--ppn", type=int, default=1)
    submit.add_argument("--wrapper", default=str(pathlib.Path(__file__).resolve()))
    status = sub.add_parser("status", help="read fixed PBS submission/worker receipts")
    status.add_argument("--job-id", required=True)
    status.add_argument("--owner", required=True)
    status.add_argument("--run-root", required=True)
    status.add_argument("--request-id")
    status.add_argument("--idempotency-key")
    status.add_argument("--payload-digest")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.mode == "run":
            return run_worker(args)
        if args.mode == "submit":
            return submit_worker(args)
        return status_worker(args)
    except (OSError, PBSWorkerError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
