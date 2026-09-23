"""Strict, stdlib-only validation helpers for controller/worker contracts.

The helpers intentionally reject unknown object keys, duplicate JSON keys,
booleans supplied as integers, naive timestamps, and non-finite numbers.  The
wire contracts use ``None``/JSON ``null`` for unknown scalar observations;
validation never replaces an unknown with zero or another guessed value.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from typing import Any


class ContractValidationError(ValueError):
    """Raised when a v1 controller/worker payload violates its contract."""


def strict_object(
    data: Mapping[str, Any],
    *,
    required: set[str],
    optional: set[str] | None = None,
    name: str,
) -> None:
    if not isinstance(data, Mapping):
        raise ContractValidationError(f"{name} must be a JSON object")
    non_string_keys = [key for key in data if not isinstance(key, str)]
    if non_string_keys:
        raise ContractValidationError(f"{name} field names must be strings")
    allowed = required | (optional or set())
    missing = sorted(required - set(data))
    if missing:
        raise ContractValidationError(
            f"{name} is missing required field(s): {', '.join(missing)}"
        )
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise ContractValidationError(
            f"{name} contains unknown field(s): {', '.join(unknown)}"
        )


def nonempty_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ContractValidationError(f"{field} must be a non-empty string")
    return value


def optional_string(value: Any, field: str) -> str | None:
    if value is None:
        return None
    return nonempty_string(value, field)


def integer(value: Any, field: str, *, minimum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ContractValidationError(f"{field} must be an integer")
    if minimum is not None and value < minimum:
        raise ContractValidationError(f"{field} must be >= {minimum}")
    return value


def optional_integer(
    value: Any, field: str, *, minimum: int | None = None
) -> int | None:
    if value is None:
        return None
    return integer(value, field, minimum=minimum)


def number(
    value: Any, field: str, *, minimum: float | None = None
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ContractValidationError(f"{field} must be a number")
    result = float(value)
    if not math.isfinite(result):
        raise ContractValidationError(f"{field} must be finite")
    if minimum is not None and result < minimum:
        raise ContractValidationError(f"{field} must be >= {minimum}")
    return result


def optional_number(
    value: Any, field: str, *, minimum: float | None = None
) -> float | None:
    if value is None:
        return None
    return number(value, field, minimum=minimum)


def boolean_or_none(value: Any, field: str) -> bool | None:
    if value is None:
        return None
    if not isinstance(value, bool):
        raise ContractValidationError(f"{field} must be a boolean or null")
    return value


def string_tuple(value: Any, field: str) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ContractValidationError(f"{field} must be an array of strings")
    result = tuple(nonempty_string(item, f"{field}[]") for item in value)
    if len(set(result)) != len(result):
        raise ContractValidationError(f"{field} must not contain duplicates")
    return result


def timestamp(value: Any, field: str) -> str:
    text = nonempty_string(value, field)
    normalized = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ContractValidationError(f"{field} must be an RFC 3339 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ContractValidationError(f"{field} must include a timezone offset")
    return text


def parse_timestamp(value: str) -> datetime:
    normalized = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
    return datetime.fromisoformat(normalized).astimezone(timezone.utc)


def freshness(
    *, observed_at: str, ttl_seconds: int | None, now: str | datetime | None
) -> str:
    """Return ``fresh``, ``stale``, or ``unknown`` without guessing TTLs."""

    timestamp(observed_at, "observed_at")
    if ttl_seconds is None:
        return "unknown"
    integer(ttl_seconds, "ttl_seconds", minimum=1)
    if now is None:
        current = datetime.now(timezone.utc)
    elif isinstance(now, datetime):
        if now.tzinfo is None or now.utcoffset() is None:
            raise ContractValidationError("now must include timezone information")
        current = now.astimezone(timezone.utc)
    else:
        timestamp(now, "now")
        current = parse_timestamp(now)
    age_seconds = (current - parse_timestamp(observed_at)).total_seconds()
    # A future-dated observation is not accepted as fresh.  Clock skew must be
    # reconciled explicitly instead of extending evidence lifetime silently.
    if age_seconds < 0:
        return "unknown"
    return "fresh" if age_seconds <= ttl_seconds else "stale"


def validate_version(schema_version: Any, api_version: Any, expected_api: str) -> None:
    if (
        isinstance(schema_version, bool)
        or not isinstance(schema_version, int)
        or schema_version != 1
    ):
        raise ContractValidationError(
            f"unsupported schema_version: {schema_version!r}; expected 1"
        )
    if not isinstance(api_version, str) or api_version != expected_api:
        raise ContractValidationError(
            f"unsupported api_version: {api_version!r}; expected {expected_api!r}"
        )


def load_json_object(text: str) -> dict[str, Any]:
    if not isinstance(text, str):
        raise ContractValidationError("JSON input must be text")

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ContractValidationError(f"duplicate JSON key: {key!r}")
            result[key] = value
        return result

    try:
        loaded = json.loads(text, object_pairs_hook=reject_duplicates)
    except ContractValidationError:
        raise
    except (json.JSONDecodeError, TypeError) as exc:
        raise ContractValidationError("invalid JSON document") from exc
    if not isinstance(loaded, dict):
        raise ContractValidationError("contract JSON must contain one object")
    return loaded


def dump_json_object(data: Mapping[str, Any]) -> str:
    return json.dumps(
        dict(data),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


class JsonContract:
    """Mixin providing canonical JSON encoding for strict dataclasses."""

    def to_dict(self) -> dict[str, Any]:  # pragma: no cover - interface only
        raise NotImplementedError

    def to_json(self) -> str:
        return dump_json_object(self.to_dict())

    @classmethod
    def from_json(cls, text: str):
        return cls.from_dict(load_json_object(text))
