#!/usr/bin/env python3
"""Join the SQLite transport outbox to the bounded PBS worker wrapper.

The existing remote envelope is an acknowledgement that a prepared packet
reached a worker spool.  It is intentionally not an execution receipt.  This
module adds the next, provider-free stage without sharing SQLite over NFS:

``accepted envelope -> fixed PBS submission -> status/reconcile -> terminal``

The controller owns the local SQLite lease/fence.  A remote client is injected
in tests and the production ``PBSWorkerClient`` uses only a validated private
SSH inventory and a fixed ``pbs_worker_wrapper.py`` command.  No prompt,
provider credential, arbitrary shell, or model request crosses this seam.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import posixpath
import re
import subprocess
import sys
import uuid
from typing import Any, Callable, Mapping

SCRIPT_ROOT = pathlib.Path(__file__).resolve().parent
if str(SCRIPT_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPT_ROOT))

from remote_worker_client import (  # noqa: E402
    ClientError,
    RemoteWorkerClient,
    _stderr_evidence,
)
from pbs_scheduler_health import validate_scheduler_health_receipt  # noqa: E402
from sqlite_store import SQLiteStore, StoreError  # noqa: E402


class PBSBridgeError(RuntimeError):
    """Raised when the bounded PBS/controller contract cannot be joined."""


_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_REMOTE_SEGMENT_RE = re.compile(r"[A-Za-z0-9_+@=,:.-]+\Z")
_ARTIFACT_SEGMENT_RE = re.compile(r"[A-Za-z0-9._+:@=-]+\Z")
_QUEUE_RE = re.compile(r"[A-Za-z0-9_.:-]{1,64}\Z")
_SAFE_REMOTE_KEYS = {
    "schema_version",
    "receipt_type",
    "status",
    "provider_execution",
    "network_execution",
    "job_id",
    "request_id",
    "idempotency_key",
    "payload_digest",
    "pbs_job_id",
    "run_root",
    "result_digest",
    "error_code",
    "submission_digest",
    "worker_receipt_digest",
    "run_id",
    "segment_id",
    "sequence",
    "manifest_digest",
    "capsule_digest",
    "idempotent",
    "artifact_manifest",
    "validation",
}


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()


def _id(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise PBSBridgeError(f"{field} is invalid")
    return value


def _digest_value(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise PBSBridgeError(f"{field} is invalid")
    return value


def _absolute_remote_path(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.startswith("/") or value == "/":
        raise PBSBridgeError(f"{field} must be a non-root absolute path")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts[1:]):
        raise PBSBridgeError(f"{field} contains an unsafe path component")
    if any(not _REMOTE_SEGMENT_RE.fullmatch(part) for part in parts[1:]):
        raise PBSBridgeError(f"{field} contains an unsafe path component")
    return value


def _bounded_int(value: Any, field: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool):
        raise PBSBridgeError(f"{field} is invalid")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise PBSBridgeError(f"{field} is invalid") from exc
    if parsed < minimum or parsed > maximum:
        raise PBSBridgeError(f"{field} is outside {minimum}..{maximum}")
    return parsed


def _safe_remote_payload(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise PBSBridgeError("PBS client returned a non-object JSON value")
    return {
        str(key): value[key]
        for key in value
        if str(key) in _SAFE_REMOTE_KEYS
    }


def _safe_artifact_path(value: Any) -> str:
    """Validate a POSIX-relative artifact path carried by a PBS receipt."""
    if not isinstance(value, str) or not value or len(value) > 1024:
        raise PBSBridgeError("artifact path is invalid")
    if "\x00" in value or "\\" in value or value.startswith("/"):
        raise PBSBridgeError("artifact path is invalid")
    parts = value.split("/")
    if any(
        not part or part in {".", ".."} or not _ARTIFACT_SEGMENT_RE.fullmatch(part)
        for part in parts
    ):
        raise PBSBridgeError("artifact path is invalid")
    return "/".join(parts)


def _safe_artifact_manifest(value: Any) -> list[dict[str, Any]]:
    """Reduce remote artifact evidence to bounded hash-bearing rows."""
    if not isinstance(value, list) or len(value) > 256:
        raise PBSBridgeError("artifact_manifest is invalid")
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, Mapping):
            raise PBSBridgeError("artifact_manifest row is invalid")
        path = _safe_artifact_path(item.get("path"))
        if path in seen:
            raise PBSBridgeError("artifact_manifest contains duplicate paths")
        seen.add(path)
        if item.get("status") != "present":
            raise PBSBridgeError("artifact_manifest contains a non-present row")
        size = item.get("size")
        if isinstance(size, bool) or not isinstance(size, int) or size < 1 or size > (1 << 50):
            raise PBSBridgeError("artifact_manifest size is invalid")
        digest = item.get("sha256")
        if not isinstance(digest, str) or not _DIGEST_RE.fullmatch(digest):
            raise PBSBridgeError("artifact_manifest sha256 is invalid")
        rows.append({"path": path, "status": "present", "size": size, "sha256": digest})
    return rows


def _safe_validation(value: Any) -> dict[str, Any]:
    """Validate the bounded validator result used for lifecycle promotion."""
    if not isinstance(value, Mapping) or not isinstance(value.get("ok"), bool):
        raise PBSBridgeError("validation is invalid")
    validator = value.get("validator")
    if not isinstance(validator, str) or not _ID_RE.fullmatch(validator):
        raise PBSBridgeError("validation.validator is invalid")
    freshness = value.get("artifact_freshness_verified")
    if not isinstance(freshness, bool):
        raise PBSBridgeError("validation.artifact_freshness_verified is invalid")
    safe: dict[str, Any] = {
        "ok": bool(value["ok"]),
        "validator": validator,
        "artifact_freshness_verified": freshness,
    }
    digest = value.get("artifact_manifest_digest")
    if digest is not None:
        if not isinstance(digest, str) or not _DIGEST_RE.fullmatch(digest):
            raise PBSBridgeError("validation.artifact_manifest_digest is invalid")
        safe["artifact_manifest_digest"] = digest
    reason = value.get("reason")
    if reason is not None:
        if not isinstance(reason, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,160}\Z", reason):
            raise PBSBridgeError("validation.reason is invalid")
        safe["reason"] = reason
    if safe["ok"] and (safe["artifact_freshness_verified"] is not True or "artifact_manifest_digest" not in safe):
        raise PBSBridgeError("passing validation lacks artifact freshness evidence")
    return safe


def _load_inventory(value: pathlib.Path | str | Mapping[str, Any]) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    try:
        payload = json.loads(pathlib.Path(value).expanduser().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PBSBridgeError("PBS inventory is not valid JSON") from exc
    if not isinstance(payload, Mapping):
        raise PBSBridgeError("PBS inventory must be an object")
    return payload


def _raw_host_rows(inventory: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    raw = inventory.get("hosts", inventory)
    if isinstance(raw, list):
        rows = raw
        result: dict[str, Mapping[str, Any]] = {}
        for row in rows:
            if not isinstance(row, Mapping):
                raise PBSBridgeError("inventory host rows must be objects")
            host_id = _id(row.get("host_id"), "host_id")
            if host_id in result:
                raise PBSBridgeError(f"duplicate host_id: {host_id}")
            result[host_id] = row
        return result
    if isinstance(raw, Mapping):
        result = {}
        for key, row in raw.items():
            if not isinstance(row, Mapping):
                raise PBSBridgeError("inventory host rows must be objects")
            host_id = _id(row.get("host_id") or key, "host_id")
            if host_id != str(key) and row.get("host_id") is not None:
                raise PBSBridgeError("inventory host identity mismatch")
            if host_id in result:
                raise PBSBridgeError(f"duplicate host_id: {host_id}")
            result[host_id] = row
        return result
    raise PBSBridgeError("inventory must contain hosts list or object")


def _pbs_config(inventory: Mapping[str, Any], host_id: str, row: Mapping[str, Any]) -> dict[str, Any]:
    raw: Any = row.get("pbs")
    if raw is None:
        root_config = inventory.get("pbs")
        if isinstance(root_config, Mapping) and host_id in root_config and isinstance(root_config[host_id], Mapping):
            raw = root_config[host_id]
        elif isinstance(root_config, Mapping):
            raw = root_config
    if not isinstance(raw, Mapping):
        raise PBSBridgeError(f"host {host_id} has no explicit pbs configuration")
    config = {
        "wrapper": _absolute_remote_path(raw.get("wrapper"), f"host {host_id} pbs.wrapper"),
        "python": _absolute_remote_path(raw.get("python") or "/usr/bin/python3", f"host {host_id} pbs.python"),
        "qsub": _absolute_remote_path(raw.get("qsub"), f"host {host_id} pbs.qsub"),
        "run_root": _absolute_remote_path(raw.get("run_root"), f"host {host_id} pbs.run_root"),
        "queue": str(raw.get("queue") or "workq"),
        "nodes": _bounded_int(raw.get("nodes", 1), f"host {host_id} pbs.nodes", minimum=1, maximum=1024),
        "ppn": _bounded_int(raw.get("ppn", 1), f"host {host_id} pbs.ppn", minimum=1, maximum=4096),
    }
    if raw.get("tmp_root") is not None:
        config["tmp_root"] = _absolute_remote_path(raw.get("tmp_root"), f"host {host_id} pbs.tmp_root")
    if not _QUEUE_RE.fullmatch(config["queue"]):
        raise PBSBridgeError(f"host {host_id} pbs.queue is invalid")
    return config


class PBSWorkerClient:
    """Fixed-command PBS transport for an explicit SSH inventory."""

    def __init__(
        self,
        inventory: pathlib.Path | str | Mapping[str, Any],
        *,
        ssh_executable: str = "ssh",
        timeout: float = 30.0,
        runner: Callable[..., subprocess.CompletedProcess[bytes]] | None = None,
    ) -> None:
        if timeout < 1 or timeout > 900:
            raise PBSBridgeError("timeout must be between 1 and 900 seconds")
        self.inventory = _load_inventory(inventory)
        self.raw_hosts = _raw_host_rows(self.inventory)
        try:
            self.worker_client = RemoteWorkerClient(
                self.inventory,
                ssh_executable=ssh_executable,
                timeout=timeout,
                runner=runner,
            )
        except ClientError as exc:
            raise PBSBridgeError(str(exc)) from exc
        self.ssh_executable = ssh_executable
        self.timeout = float(timeout)
        self.runner = runner or subprocess.run

    def _host_config(self, host_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
        host_id = _id(host_id, "host_id")
        try:
            host = dict(self.worker_client.hosts[host_id])
            raw = self.raw_hosts[host_id]
        except KeyError as exc:
            raise PBSBridgeError("host_id is not present in the private inventory") from exc
        return host, _pbs_config(self.inventory, host_id, raw)

    @staticmethod
    def _run_root(config: Mapping[str, Any], job_id: str) -> str:
        root = posixpath.join(str(config["run_root"]), job_id)
        return _absolute_remote_path(root, "pbs.run_root.job")

    def _ssh_command(self, host: Mapping[str, Any], command: list[str]) -> list[str]:
        argv = [
            "-o", "BatchMode=yes",
            "-o", f"ConnectTimeout={max(1, int(self.timeout))}",
            "-o", "ServerAliveInterval=3",
            "-o", "ServerAliveCountMax=1",
        ]
        if host.get("ssh_legacy_rsa") is True:
            argv.extend([
                "-o", "HostKeyAlgorithms=+ssh-rsa",
                "-o", "PubkeyAcceptedAlgorithms=+ssh-rsa",
            ])
        if host.get("identity_file"):
            argv.extend(["-i", str(host["identity_file"])])
        argv.extend(["-p", str(host["port"]), f"{host['user']}@{host['hostname']}"])
        return [self.ssh_executable, *argv, *command]

    def _call(self, host: Mapping[str, Any], command: list[str], *, execute: bool) -> dict[str, Any]:
        report: dict[str, Any] = {
            "schema_version": 1,
            "client": "pbs_worker_client",
            "dry_run": not execute,
            "executed": bool(execute),
            "provider_execution": False,
            # ``execute=True`` means this client opened the controller->PBS
            # SSH leg.  The nested provider-free worker receipt may still
            # correctly report network_execution=False for its own stage.
            "network_execution": bool(execute),
        }
        if not execute:
            report["command_digest"] = _digest(command)
            return report
        try:
            completed = self.runner(
                self._ssh_command(host, command),
                input=b"",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.timeout,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise PBSBridgeError("PBS transport timed out") from exc
        except (OSError, ValueError) as exc:
            raise PBSBridgeError("PBS transport could not start") from exc
        stdout = completed.stdout if isinstance(completed.stdout, bytes) else str(completed.stdout or "").encode()
        stderr = completed.stderr if isinstance(completed.stderr, bytes) else str(completed.stderr or "").encode()
        if completed.returncode != 0:
            raise PBSBridgeError(
                "PBS wrapper command failed "
                + json.dumps({"returncode": int(completed.returncode), "stderr": _stderr_evidence(stderr)}, sort_keys=True)
            )
        try:
            payload = json.loads(stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PBSBridgeError("PBS wrapper returned invalid JSON") from exc
        report["remote"] = _safe_remote_payload(payload)
        if stderr:
            report["stderr"] = _stderr_evidence(stderr)
        return report

    def submit(
        self,
        *,
        host_id: str,
        job_id: str,
        owner: str,
        request_id: str,
        idempotency_key: str,
        payload_digest: str,
        execute: bool = False,
    ) -> dict[str, Any]:
        host, config = self._host_config(host_id)
        job_id = _id(job_id, "job_id")
        owner = _id(owner, "owner")
        request_id = _id(request_id, "request_id")
        idempotency_key = _id(idempotency_key, "idempotency_key")
        payload_digest = _digest_value(payload_digest, "payload_digest")
        run_root = self._run_root(config, job_id)
        command = [
            str(config["python"]), str(config["wrapper"]), "submit",
            "--python", str(config["python"]),
            "--worker-script", str(host["worker_script"]),
            "--spool", str(host["spool_path"]),
            "--job-id", job_id, "--owner", owner,
            "--run-root", run_root,
            "--qsub", str(config["qsub"]), "--queue", str(config["queue"]),
            "--nodes", str(config["nodes"]), "--ppn", str(config["ppn"]),
            "--wrapper", str(config["wrapper"]),
            "--request-id", request_id,
            "--idempotency-key", idempotency_key,
            "--payload-digest", payload_digest,
        ]
        if config.get("tmp_root"):
            command.extend(["--tmp-root", str(config["tmp_root"])])
        report = self._call(host, command, execute=execute)
        report.update({"host_id": host_id, "job_id": job_id, "request_id": request_id, "run_root": run_root})
        return report

    def status(
        self,
        *,
        host_id: str,
        job_id: str,
        owner: str,
        request_id: str,
        idempotency_key: str,
        payload_digest: str,
        execute: bool = False,
    ) -> dict[str, Any]:
        host, config = self._host_config(host_id)
        job_id = _id(job_id, "job_id")
        owner = _id(owner, "owner")
        request_id = _id(request_id, "request_id")
        idempotency_key = _id(idempotency_key, "idempotency_key")
        payload_digest = _digest_value(payload_digest, "payload_digest")
        run_root = self._run_root(config, job_id)
        command = [
            str(config["python"]), str(config["wrapper"]), "status",
            "--job-id", job_id, "--owner", owner,
            "--run-root", run_root,
            "--request-id", request_id,
            "--idempotency-key", idempotency_key,
            "--payload-digest", payload_digest,
        ]
        report = self._call(host, command, execute=execute)
        report.update({"host_id": host_id, "job_id": job_id, "request_id": request_id, "run_root": run_root})
        return report


def _remote_report(report: Mapping[str, Any]) -> Mapping[str, Any]:
    remote = report.get("remote")
    if not isinstance(remote, Mapping):
        raise PBSBridgeError("PBS client response has no remote payload")
    return remote


def _row_identity(row: Mapping[str, Any]) -> tuple[str, Mapping[str, Any], Mapping[str, Any]]:
    request_id = str(row.get("request_id") or "")
    envelope = row.get("envelope")
    if not request_id or not isinstance(envelope, Mapping):
        raise PBSBridgeError("malformed transport outbox row")
    if str(envelope.get("request_id") or request_id) != request_id:
        raise PBSBridgeError("transport request_id mismatch")
    if envelope.get("operation") != "execute.prepared":
        raise PBSBridgeError("PBS bridge accepts only execute.prepared envelopes")
    summary = envelope.get("payload_summary")
    if not isinstance(summary, Mapping):
        raise PBSBridgeError("transport envelope payload_summary is missing")
    job_id = str(row.get("job_id") or summary.get("job_id") or "")
    if not job_id or job_id != str(summary.get("job_id") or ""):
        raise PBSBridgeError("transport row/envelope job_id mismatch")
    return request_id, envelope, summary


def _segment_context(
    envelope: Mapping[str, Any],
    *,
    remote: Mapping[str, Any] | None = None,
    previous: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate optional bounded-run identity carried by a PBS receipt."""

    summary = envelope.get("payload_summary")
    summary = summary if isinstance(summary, Mapping) else {}
    remote = remote if isinstance(remote, Mapping) else {}
    previous = previous if isinstance(previous, Mapping) else {}
    keys = ("run_id", "segment_id", "sequence", "manifest_digest", "capsule_digest")
    values: dict[str, Any] = {}
    for key in keys:
        expected = summary.get(key)
        carried = remote.get(key, previous.get(key))
        if expected is not None and carried is not None and expected != carried:
            raise PBSBridgeError(f"PBS segment {key} mismatch")
        value = expected if expected is not None else carried
        if value is not None:
            values[key] = value
    if not values:
        return {}
    for key in ("run_id", "segment_id"):
        _id(values.get(key), f"segment {key}")
    sequence = values.get("sequence")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
        raise PBSBridgeError("segment sequence is invalid")
    for key in ("manifest_digest", "capsule_digest"):
        if key not in values:
            if key == "manifest_digest":
                raise PBSBridgeError("segment manifest_digest is required")
            continue
        digest = values[key]
        if not isinstance(digest, str) or not (
            _DIGEST_RE.fullmatch(digest)
            or (len(digest) == 71 and digest.startswith("sha256:") and _DIGEST_RE.fullmatch(digest[7:]))
        ):
            raise PBSBridgeError(f"segment {key} is invalid")
    return values


def _submission_receipt(
    remote: Mapping[str, Any],
    *,
    request_id: str,
    envelope: Mapping[str, Any],
    network_execution: bool = False,
    pbs_owner_id: str | None = None,
) -> dict[str, Any]:
    status = remote.get("status")
    # Releases before the explicit submission-stage status field wrote a
    # durable ``local-agent-dispatch.pbs-submission`` receipt without
    # ``status``.  Accept that legacy shape only when the receipt type and PBS
    # identity below still prove this is a submission response; never accept
    # an arbitrary status-less object.
    if status not in {"accepted", "pending", None}:
        raise PBSBridgeError("PBS submit did not return accepted")
    if status is None and remote.get("receipt_type") != "local-agent-dispatch.pbs-submission":
        raise PBSBridgeError("PBS submit returned a status-less non-submission receipt")
    pbs_job_id = remote.get("pbs_job_id")
    if not isinstance(pbs_job_id, str) or not pbs_job_id or not _ID_RE.fullmatch(pbs_job_id):
        raise PBSBridgeError("PBS submission did not return a valid pbs_job_id")
    if remote.get("job_id") not in {None, envelope.get("payload_summary", {}).get("job_id")}:
        raise PBSBridgeError("PBS submission job_id mismatch")
    if remote.get("request_id") not in {None, request_id}:
        raise PBSBridgeError("PBS submission request_id mismatch")
    if remote.get("payload_digest") not in {None, envelope.get("payload_digest")}:
        raise PBSBridgeError("PBS submission payload_digest mismatch")
    context = _segment_context(envelope, remote=remote)
    receipt = {
        "schema_version": 1,
        "receipt_version": 1,
        "request_id": request_id,
        "idempotency_key": envelope.get("idempotency_key"),
        "payload_digest": envelope.get("payload_digest"),
        "status": "accepted",
        "effect_count": 0,
        "receipt_digest": _digest({"request_id": request_id, "pbs_job_id": pbs_job_id, "status": "accepted"}),
        "observed_at": remote.get("observed_at"),
        "executor": "pbs",
        "executor_stage": "submission",
        # The PBS wrapper authenticates status reads against the owner that
        # submitted the job.  Persist that bounded controller identity so a
        # later reconciler can use a fresh lease without losing the remote
        # receipt identity.  This is an opaque owner id, never a credential.
        "pbs_owner_id": _id(pbs_owner_id, "pbs_owner_id") if pbs_owner_id is not None else None,
        "provider_execution": bool(remote.get("provider_execution", False)),
        "network_execution": bool(network_execution or remote.get("network_execution", False)),
        "pbs_job_id": pbs_job_id,
        "run_root": remote.get("run_root"),
        "submission_digest": remote.get("submission_digest"),
        **context,
    }
    return {key: value for key, value in receipt.items() if value is not None}


def _terminal_receipt(
    remote: Mapping[str, Any],
    *,
    request_id: str,
    envelope: Mapping[str, Any],
    previous: Mapping[str, Any],
    network_execution: bool = False,
) -> dict[str, Any] | None:
    status = remote.get("status")
    if status in {"pending", "accepted"}:
        return None
    if status not in {"completed", "failed"}:
        raise PBSBridgeError("PBS status returned an invalid terminal state")
    pbs_job_id = remote.get("pbs_job_id") or previous.get("pbs_job_id")
    if not isinstance(pbs_job_id, str) or not _ID_RE.fullmatch(pbs_job_id):
        raise PBSBridgeError("PBS terminal status has no valid pbs_job_id")
    if remote.get("request_id") not in {None, request_id}:
        raise PBSBridgeError("PBS terminal request_id mismatch")
    if remote.get("payload_digest") not in {None, envelope.get("payload_digest")}:
        raise PBSBridgeError("PBS terminal payload_digest mismatch")
    result_digest = remote.get("result_digest")
    error_code = remote.get("error_code")
    if status == "completed":
        result_digest = _digest_value(result_digest, "PBS result_digest")
        error_code = None
    else:
        if not isinstance(error_code, str) or not re.fullmatch(r"[a-z0-9_.-]{1,80}\Z", error_code):
            raise PBSBridgeError("PBS terminal error_code is invalid")
        result_digest = None
    artifact_manifest = None
    validation = None
    if "artifact_manifest" in remote:
        artifact_manifest = _safe_artifact_manifest(remote.get("artifact_manifest"))
    if "validation" in remote:
        validation = _safe_validation(remote.get("validation"))
    if (
        validation is not None
        and validation.get("ok") is True
        and artifact_manifest is not None
        and validation.get("artifact_manifest_digest") != _digest(artifact_manifest)
    ):
        raise PBSBridgeError("validation artifact_manifest_digest does not match manifest")
    pbs_owner_id = previous.get("pbs_owner_id")
    if pbs_owner_id is not None:
        pbs_owner_id = _id(pbs_owner_id, "pbs_owner_id")
    context = _segment_context(envelope, remote=remote, previous=previous)
    receipt_digest = _digest(
        {
            "request_id": request_id,
            "pbs_job_id": pbs_job_id,
            "pbs_owner_id": pbs_owner_id,
            "status": status,
            "result_digest": result_digest,
            "error_code": error_code,
            "artifact_manifest": artifact_manifest,
            "validation": validation,
        }
    )
    receipt = {
        "schema_version": 1,
        "receipt_version": 1,
        "request_id": request_id,
        "idempotency_key": envelope.get("idempotency_key"),
        "payload_digest": envelope.get("payload_digest"),
        "status": status,
        "effect_count": 1 if status == "completed" else 0,
        "result_digest": result_digest,
        "error_code": error_code,
        "receipt_digest": receipt_digest,
        "observed_at": remote.get("observed_at"),
        "executor": "pbs",
        "executor_stage": "terminal",
        "pbs_owner_id": pbs_owner_id,
        "provider_execution": bool(remote.get("provider_execution", False)),
        "network_execution": bool(network_execution or remote.get("network_execution", False)),
        "pbs_job_id": pbs_job_id,
        "run_root": remote.get("run_root") or previous.get("run_root"),
        "submission_digest": remote.get("submission_digest") or previous.get("submission_digest"),
        "worker_receipt_digest": remote.get("worker_receipt_digest"),
        "artifact_manifest": artifact_manifest,
        "validation": validation,
        **context,
    }
    return {key: value for key, value in receipt.items() if value is not None}


def _limit(value: Any) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise PBSBridgeError("max_items must be an integer") from exc
    if parsed < 1 or parsed > 128:
        raise PBSBridgeError("max_items must be between 1 and 128")
    return parsed


def _load_scheduler_health_receipt(
    value: pathlib.Path | str | Mapping[str, Any] | None,
) -> Mapping[str, Any] | None:
    """Load a bounded, already-redacted scheduler-health receipt."""

    if value is None or isinstance(value, Mapping):
        return value
    path = pathlib.Path(value).expanduser()
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise PBSBridgeError("scheduler health receipt could not be read") from exc
    if len(raw) > 2 * 1024 * 1024:
        raise PBSBridgeError("scheduler health receipt is too large")
    try:
        loaded = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PBSBridgeError("scheduler health receipt is not valid JSON") from exc
    if not isinstance(loaded, Mapping):
        raise PBSBridgeError("scheduler health receipt must be an object")
    return loaded


def submit_once(
    db_path: pathlib.Path | str,
    *,
    inventory: pathlib.Path | str | Mapping[str, Any] | None = None,
    execute: bool = False,
    max_items: int = 32,
    owner_id: str | None = None,
    lease_ttl_seconds: int = 90,
    client: Any | None = None,
    client_factory: Callable[[Any], Any] | None = None,
    scheduler_health: pathlib.Path | str | Mapping[str, Any] | None = None,
    require_scheduler_health: bool = False,
    scheduler_health_max_age_seconds: int = 900,
    scheduler_health_queue: str = "workq",
    scheduler_health_node: str = "compute-01",
    scheduler_health_host: str | None = None,
) -> dict[str, Any]:
    """Submit PBS for worker-accepted envelopes and persist submission receipts."""
    limit = _limit(max_items)
    path = pathlib.Path(db_path).expanduser().resolve()
    # A production execution has an explicit private inventory.  Make the
    # scheduler-health gate mandatory on that path even if a caller omitted
    # the convenience flag; injected fake clients without an inventory remain
    # usable for provider-free tests.
    require_scheduler_health = bool(require_scheduler_health or (execute and inventory is not None))
    health_gate: dict[str, Any] | None = None
    if require_scheduler_health:
        receipt = _load_scheduler_health_receipt(scheduler_health)
        health_gate = validate_scheduler_health_receipt(
            receipt,
            max_age_seconds=scheduler_health_max_age_seconds,
            expected_queue=scheduler_health_queue,
            expected_node=scheduler_health_node,
            expected_host=scheduler_health_host,
        )
        if not health_gate.get("valid"):
            raise PBSBridgeError(
                "PBS scheduler health admission blocked "
                + json.dumps(
                    {
                        "decision": health_gate.get("decision"),
                        "reason": health_gate.get("reason"),
                        "reasons": health_gate.get("reasons") or [],
                        "evidence_digest": health_gate.get("evidence_digest"),
                    },
                    sort_keys=True,
                )
            )
    if execute and inventory is None and client is None and client_factory is None:
        raise PBSBridgeError("execute requires a private SSH inventory or PBS client")
    if client is None:
        client = client_factory(inventory) if client_factory is not None else PBSWorkerClient(inventory)  # type: ignore[arg-type]
    owner = owner_id or f"pbs-submit-{uuid.uuid4().hex[:12]}"
    owner = _id(owner, "owner_id")
    results: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    with SQLiteStore(path) as store:
        with store.controller_lease(owner, ttl_seconds=max(30, int(lease_ttl_seconds))) as lease:
            fence = int(lease["fence_token"])
            rows = store.list_transport_outbox(statuses=("accepted",))[:limit]
            for row in rows:
                try:
                    request_id, envelope, summary = _row_identity(row)
                    previous = row.get("receipt") if isinstance(row.get("receipt"), Mapping) else {}
                    if previous.get("executor") == "pbs" and previous.get("pbs_job_id"):
                        results.append({"request_id": request_id, "status_before": row.get("status"), "status_after": row.get("status"), "idempotent": True, "provider_execution": False})
                        continue
                    target_id = str(envelope.get("target_id") or "")
                    job_id = str(summary.get("job_id") or "")
                    idempotency_key = str(envelope.get("idempotency_key") or request_id)
                    report = client.submit(
                        host_id=target_id,
                        job_id=job_id,
                        owner=owner,
                        request_id=request_id,
                        idempotency_key=idempotency_key,
                        payload_digest=str(envelope.get("payload_digest") or ""),
                        execute=execute,
                    )
                    remote = _remote_report(report)
                    if not execute:
                        results.append({"request_id": request_id, "target_id": target_id, "status_before": row.get("status"), "dry_run": True, "provider_execution": False, "command_digest": report.get("command_digest"), "run_root": report.get("run_root")})
                        continue
                    receipt = _submission_receipt(
                        remote,
                        request_id=request_id,
                        envelope=envelope,
                        network_execution=bool(report.get("network_execution")),
                        pbs_owner_id=owner,
                    )
                    stored = store.record_transport_receipt(request_id, receipt, owner_id=owner, fence_token=fence)
                    results.append({"request_id": request_id, "target_id": target_id, "status_before": row.get("status"), "status_after": stored.get("status"), "pbs_job_id": receipt.get("pbs_job_id"), "run_root": receipt.get("run_root"), "provider_execution": bool(receipt.get("provider_execution")), "network_execution": bool(receipt.get("network_execution"))})
                except (PBSBridgeError, StoreError, ClientError, OSError, RuntimeError, ValueError, TypeError) as exc:
                    errors.append({"request_id": str(row.get("request_id") or ""), "status_before": row.get("status"), "error": type(exc).__name__, "provider_execution": False})
    return {"schema_version": 1, "backend": "sqlite", "db_path": str(path), "execute_requested": bool(execute), "provider_execution": False, "network_execution": bool(execute), "controller_owner": owner, "attempted": len(results) + len(errors), "submitted": sum(1 for row in results if row.get("status_after") == "accepted" and not row.get("idempotent")), "planned": len(results) if not execute else 0, "results": results, "errors": errors, "scheduler_health": health_gate, "ok": not errors}


def reconcile_once(
    db_path: pathlib.Path | str,
    *,
    inventory: pathlib.Path | str | Mapping[str, Any] | None = None,
    execute: bool = False,
    max_items: int = 32,
    owner_id: str | None = None,
    lease_ttl_seconds: int = 90,
    client: Any | None = None,
    client_factory: Callable[[Any], Any] | None = None,
) -> dict[str, Any]:
    """Reconcile PBS submission receipts into terminal SQLite receipts."""
    limit = _limit(max_items)
    path = pathlib.Path(db_path).expanduser().resolve()
    if execute and inventory is None and client is None and client_factory is None:
        raise PBSBridgeError("execute requires a private SSH inventory or PBS client")
    if client is None:
        client = client_factory(inventory) if client_factory is not None else PBSWorkerClient(inventory)  # type: ignore[arg-type]
    owner = owner_id or f"pbs-reconcile-{uuid.uuid4().hex[:12]}"
    owner = _id(owner, "owner_id")
    results: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    with SQLiteStore(path) as store:
        with store.controller_lease(owner, ttl_seconds=max(30, int(lease_ttl_seconds))) as lease:
            fence = int(lease["fence_token"])
            rows = store.list_transport_outbox(statuses=("accepted",))[:limit]
            for row in rows:
                try:
                    request_id, envelope, summary = _row_identity(row)
                    previous = row.get("receipt") if isinstance(row.get("receipt"), Mapping) else {}
                    if previous.get("executor") != "pbs" or not previous.get("pbs_job_id"):
                        results.append({"request_id": request_id, "status_before": row.get("status"), "awaiting_submission": True, "provider_execution": False})
                        continue
                    target_id = str(envelope.get("target_id") or "")
                    job_id = str(summary.get("job_id") or "")
                    # Submission/status receipts are tied to the owner that
                    # created the remote PBS submission.  Reconciliation is
                    # intentionally allowed to use a fresh local lease, but
                    # must retain the persisted remote identity when one is
                    # available.  Legacy receipts lack this field; falling
                    # back to the current owner preserves their old behavior
                    # while new submissions are self-contained.
                    status_owner = previous.get("pbs_owner_id") or owner
                    status_owner = _id(status_owner, "pbs_owner_id")
                    report = client.status(
                        host_id=target_id,
                        job_id=job_id,
                        owner=status_owner,
                        request_id=request_id,
                        idempotency_key=str(envelope.get("idempotency_key") or request_id),
                        payload_digest=str(envelope.get("payload_digest") or ""),
                        execute=execute,
                    )
                    remote = _remote_report(report)
                    if not execute:
                        results.append({"request_id": request_id, "status_before": row.get("status"), "remote_status": remote.get("status"), "dry_run": True, "provider_execution": False, "command_digest": report.get("command_digest")})
                        continue
                    terminal = _terminal_receipt(
                        remote,
                        request_id=request_id,
                        envelope=envelope,
                        previous=previous,
                        network_execution=bool(report.get("network_execution")),
                    )
                    if terminal is None:
                        results.append({"request_id": request_id, "status_before": row.get("status"), "remote_status": remote.get("status"), "provider_execution": False})
                        continue
                    # A terminal PBS receipt promotes the parent lifecycle only
                    # when the controller had explicitly bound this outbox row
                    # to its currently running attempt.  Successful work also
                    # needs the wrapper's independent artifact/validator
                    # evidence.  Legacy or unbound rows remain transport-only.
                    bound = bool(row.get("attempt_id"))
                    can_promote = bound and (
                        terminal.get("status") == "failed"
                        or (
                            terminal.get("status") == "completed"
                            and isinstance(terminal.get("validation"), Mapping)
                            and terminal["validation"].get("ok") is True
                            and terminal.get("artifact_manifest") is not None
                        )
                    )
                    lifecycle_promoted = False
                    idempotent = False
                    lifecycle_blocked = None
                    if can_promote:
                        promotion = store.record_transport_receipt_and_complete(
                            request_id,
                            terminal,
                            owner_id=owner,
                            fence_token=fence,
                            validation=terminal.get("validation"),
                            artifact_manifest=terminal.get("artifact_manifest"),
                            result=terminal,
                            error_class=(
                                str(terminal.get("error_code") or "remote_transport_failed")
                                if terminal.get("status") == "failed"
                                else None
                            ),
                            error=(
                                {
                                    "error_code": terminal.get("error_code"),
                                    "transport_request_id": request_id,
                                }
                                if terminal.get("status") == "failed"
                                else None
                            ),
                        )
                        stored = promotion.get("transport") or {}
                        lifecycle_promoted = bool(promotion.get("lifecycle_promoted"))
                        idempotent = bool(promotion.get("idempotent"))
                    else:
                        stored = store.record_transport_receipt(request_id, terminal, owner_id=owner, fence_token=fence)
                        if bound and terminal.get("status") == "completed":
                            lifecycle_blocked = "validation_evidence_required"
                    result_row = {
                        "request_id": request_id,
                        "status_before": row.get("status"),
                        "status_after": stored.get("status"),
                        "remote_status": remote.get("status"),
                        "pbs_job_id": terminal.get("pbs_job_id"),
                        "provider_execution": bool(terminal.get("provider_execution")),
                        "network_execution": bool(terminal.get("network_execution")),
                        "lifecycle_promoted": lifecycle_promoted,
                        "idempotent": idempotent,
                    }
                    if lifecycle_blocked is not None:
                        result_row["lifecycle_blocked"] = lifecycle_blocked
                    results.append(result_row)
                except (PBSBridgeError, StoreError, ClientError, OSError, RuntimeError, ValueError, TypeError) as exc:
                    errors.append({"request_id": str(row.get("request_id") or ""), "status_before": row.get("status"), "error": type(exc).__name__, "provider_execution": False})
    return {"schema_version": 1, "backend": "sqlite", "db_path": str(path), "execute_requested": bool(execute), "provider_execution": False, "network_execution": bool(execute), "controller_owner": owner, "attempted": len(results) + len(errors), "reconciled": sum(1 for row in results if row.get("status_after") in {"completed", "failed"}), "planned": len(results) if not execute else 0, "results": results, "errors": errors, "ok": not errors}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True)
    parser.add_argument("--inventory")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--reconcile", action="store_true")
    parser.add_argument("--max-items", type=int, default=32)
    parser.add_argument("--owner-id")
    parser.add_argument("--scheduler-health", help="bounded scheduler-health receipt for the submit gate")
    parser.add_argument("--require-scheduler-health", action="store_true", help="fail closed unless a fresh verified scheduler-health receipt is supplied")
    parser.add_argument("--scheduler-health-max-age", type=int, default=900)
    parser.add_argument("--scheduler-health-queue", default="workq")
    parser.add_argument("--scheduler-health-node", default="compute-01")
    parser.add_argument("--scheduler-health-host")
    args = parser.parse_args(argv)
    try:
        if args.reconcile:
            report = reconcile_once(args.db, inventory=args.inventory, execute=args.execute, max_items=args.max_items, owner_id=args.owner_id)
        else:
            report = submit_once(
                args.db,
                inventory=args.inventory,
                execute=args.execute,
                max_items=args.max_items,
                owner_id=args.owner_id,
                scheduler_health=args.scheduler_health,
                require_scheduler_health=args.require_scheduler_health,
                scheduler_health_max_age_seconds=args.scheduler_health_max_age,
                scheduler_health_queue=args.scheduler_health_queue,
                scheduler_health_node=args.scheduler_health_node,
                scheduler_health_host=args.scheduler_health_host,
            )
    except (PBSBridgeError, ClientError, StoreError, OSError, ValueError) as exc:
        print(json.dumps({"schema_version": 1, "ok": False, "error": type(exc).__name__}, sort_keys=True))
        return 2
    print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = ["PBSBridgeError", "PBSWorkerClient", "reconcile_once", "submit_once"]
