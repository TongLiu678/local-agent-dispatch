#!/usr/bin/env python3
"""Provider-free fake pause/resume control for controller-owned lanes.

This module closes the safety seam between the resource governor's proposed
``pause_owned_lanes`` action and a future OS-specific controller.  It is
deliberately a fake backend: it never invokes an operating-system process
control API, never touches a real process, and never starts a provider.  A
real signal adapter must be reviewed separately after the identity, lease,
and fault-injection contracts are proven.

Every action requires two independent witnesses:

* the observed process must be explicitly marked ``owned_by_dispatch``;
* the observed identity, expected lane identity, and active lease must match
  on PID, start time, process group, run ID, and fence.

The returned receipt contains only bounded status/reason/digest fields.  Raw
lease fences, argv, prompts, credentials, and process command lines are never
copied into it.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
from typing import Any, Mapping

try:  # direct script/test import
    from resource_governor import normalize_pause_identity, validate_pause_identity
except ModuleNotFoundError:  # pragma: no cover - package-style fallback
    from .resource_governor import normalize_pause_identity, validate_pause_identity


SCHEMA_VERSION = 1
RECEIPT_TYPE = "local-agent-dispatch.owned-process-control"
IDENTITY_FIELDS = ("pid", "start_time", "process_group", "run_id", "fence")
_MAX_OWNER_LENGTH = 256
_ACTIVE_LEASE_STATUS = "active"


def _utc_now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def _parse_utc(value: Any) -> _dt.datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = _dt.datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(_dt.timezone.utc)


def _safe_owner(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    owner = value.strip()
    if not owner or len(owner) > _MAX_OWNER_LENGTH:
        return None
    return owner


def _canonical_digest(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        dict(value), ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _lease_fence(lease: Mapping[str, Any]) -> str | None:
    """Return the explicit lease fence without accepting an absent value."""

    value = lease.get("fence")
    if value in (None, ""):
        value = lease.get("fence_token")
    if value in (None, ""):
        value = lease.get("lease_token")
    if value in (None, ""):
        return None
    text = str(value).strip()
    return text if text and len(text) <= 256 else None


def _lease_expiry(lease: Mapping[str, Any]) -> _dt.datetime | None:
    for key in ("lease_expires_at_utc", "expires_at_utc", "expires_at"):
        if key in lease:
            return _parse_utc(lease.get(key))
    return None


def validate_control_context(
    *,
    observed: Mapping[str, Any] | None,
    expected: Mapping[str, Any] | None,
    lease: Mapping[str, Any] | None,
    owner_id: str | None,
    now: _dt.datetime | None = None,
) -> dict[str, Any]:
    """Validate ownership, all identity fields, and the live lease.

    The result is safe to expose in a receipt: it contains only fixed reason
    codes and a boolean, never raw process or lease input.
    """

    normalized_observed = normalize_pause_identity(observed)
    normalized_expected = normalize_pause_identity(expected)
    identity_check = validate_pause_identity(observed, expected)
    reasons = list(identity_check["reasons"])
    if not isinstance(observed, Mapping) or observed.get("owned_by_dispatch") is not True:
        reasons.append("ownership_not_proven")

    normalized_lease = dict(lease) if isinstance(lease, Mapping) else {}
    expected_owner = _safe_owner(owner_id)
    lease_owner = _safe_owner(normalized_lease.get("owner_id"))
    if expected_owner is None:
        reasons.append("owner_id_invalid")
    if lease_owner is None:
        reasons.append("lease_owner_missing")
    elif expected_owner is not None and lease_owner != expected_owner:
        reasons.append("lease_owner_mismatch")

    if str(normalized_lease.get("status") or "").strip().lower() != _ACTIVE_LEASE_STATUS:
        reasons.append("lease_not_active")
    expiry = _lease_expiry(normalized_lease)
    if expiry is None:
        reasons.append("lease_expiry_invalid")
    elif expiry <= (now or _utc_now()).astimezone(_dt.timezone.utc):
        reasons.append("lease_expired")

    lease_identity: dict[str, Any] = {}
    if normalized_lease:
        # A fake control lease is intentionally bound to the full lane
        # identity.  A generic controller lease is insufficient evidence for
        # a process-group action.
        for field in IDENTITY_FIELDS:
            if field == "fence":
                value = _lease_fence(normalized_lease)
            else:
                value = normalized_lease.get(field)
            if value not in (None, ""):
                lease_identity[field] = value
        normalized_lease_identity = normalize_pause_identity(lease_identity)
        if normalized_lease_identity is None:
            reasons.append("lease_identity_incomplete")
        elif normalized_expected is not None:
            for field in IDENTITY_FIELDS:
                if normalized_lease_identity[field] != normalized_expected[field]:
                    reasons.append(f"lease_identity_{field}_mismatch")

    # De-duplicate while retaining a stable order for deterministic receipts.
    reasons = list(dict.fromkeys(reasons))
    return {
        "valid": not reasons,
        "reasons": reasons,
        "identity": normalized_expected if not reasons else None,
        "identity_digest": _canonical_digest(normalized_expected) if normalized_expected else None,
    }


class FakeProcessControl:
    """In-memory backend used by provider-free tests and replay fixtures.

    ``calls`` is intentionally public so tests can prove that rejected or
    stale actions never reach the backend.  No operating-system API is used.
    """

    def __init__(self) -> None:
        self.calls: list[dict[str, str]] = []
        self._paused: set[str] = set()

    @property
    def paused_identity_digests(self) -> tuple[str, ...]:
        return tuple(sorted(self._paused))

    def pause_group(self, identity: Mapping[str, Any]) -> None:
        digest = _canonical_digest(identity)
        self.calls.append({"action": "pause", "identity_digest": digest})
        self._paused.add(digest)

    def resume_group(self, identity: Mapping[str, Any]) -> None:
        digest = _canonical_digest(identity)
        self.calls.append({"action": "resume", "identity_digest": digest})
        self._paused.discard(digest)

    def is_paused(self, identity: Mapping[str, Any]) -> bool:
        return _canonical_digest(identity) in self._paused


def _receipt(
    *,
    action: str,
    status: str,
    validation: Mapping[str, Any],
    reason: str | None = None,
) -> dict[str, Any]:
    identity = validation.get("identity")
    receipt: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "receipt_type": RECEIPT_TYPE,
        "action": action,
        "status": status,
        "provider_execution": False,
        "backend": "fake",
        "os_signal_sent": False,
        "automatic_signal": False,
        "identity_fields": list(IDENTITY_FIELDS),
        "identity_digest": validation.get("identity_digest"),
        "run_id": identity.get("run_id") if isinstance(identity, Mapping) else None,
        "reasons": list(validation.get("reasons") or []),
    }
    if reason is not None:
        receipt["reason"] = reason
    return receipt


def pause_owned(
    *,
    observed: Mapping[str, Any] | None,
    expected: Mapping[str, Any] | None,
    lease: Mapping[str, Any] | None,
    owner_id: str | None,
    backend: FakeProcessControl,
    now: _dt.datetime | None = None,
) -> dict[str, Any]:
    """Pause one owned lane in the fake backend after all gates pass."""

    validation = validate_control_context(
        observed=observed,
        expected=expected,
        lease=lease,
        owner_id=owner_id,
        now=now,
    )
    if not validation["valid"]:
        return _receipt(
            action="pause",
            status="blocked",
            validation=validation,
            reason="identity_or_lease_gate",
        )
    identity = validation["identity"]
    assert isinstance(identity, Mapping)  # guarded by validation["valid"]
    backend.pause_group(identity)
    return _receipt(action="pause", status="paused", validation=validation)


def resume_owned(
    *,
    observed: Mapping[str, Any] | None,
    expected: Mapping[str, Any] | None,
    lease: Mapping[str, Any] | None,
    owner_id: str | None,
    backend: FakeProcessControl,
    now: _dt.datetime | None = None,
) -> dict[str, Any]:
    """Resume a previously fake-paused lane under the same live fence."""

    validation = validate_control_context(
        observed=observed,
        expected=expected,
        lease=lease,
        owner_id=owner_id,
        now=now,
    )
    if not validation["valid"]:
        return _receipt(
            action="resume",
            status="blocked",
            validation=validation,
            reason="identity_or_lease_gate",
        )
    identity = validation["identity"]
    assert isinstance(identity, Mapping)  # guarded by validation["valid"]
    if not backend.is_paused(identity):
        validation = {
            **validation,
            "reasons": ["lane_not_paused"],
        }
        return _receipt(
            action="resume",
            status="blocked",
            validation=validation,
            reason="resume_state_missing",
        )
    backend.resume_group(identity)
    return _receipt(action="resume", status="resumed", validation=validation)


__all__ = [
    "FakeProcessControl",
    "IDENTITY_FIELDS",
    "RECEIPT_TYPE",
    "SCHEMA_VERSION",
    "pause_owned",
    "resume_owned",
    "validate_control_context",
]
