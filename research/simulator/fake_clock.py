"""Deterministic fake clock for provider-free replay research.

The clock advances by explicit `advance()` calls and never sleeps.  It owns
quota-window bookkeeping so five-hour, weekly and monthly reset windows can be
compressed into a short replay without waiting for real time.

Determinism contract
--------------------
Given the same seed and the same sequence of `advance` calls, the clock
produces the same event sequence and the same `now()` values.  No wall clock,
time-of-day or locale-dependent formatting is used.  Calendar month boundaries
use the Gregorian calendar via `calendar.monthrange`, which is deterministic
for a fixed epoch.
"""

from __future__ import annotations

import calendar
import dataclasses
import math
import random
from typing import Any

# Window kinds understood by the replay layer.
FIVE_HOUR_SECONDS = 5 * 3600
WEEK_SECONDS = 7 * 24 * 3600
DAY_SECONDS = 24 * 3600
MONTH = "month"
WEEK = "week"
FIVE_HOUR = "five_hour"
DAY = "day"


@dataclasses.dataclass(frozen=True)
class WindowSpec:
    """A quota window definition.

    - `kind="rolling"` plus `duration_seconds` describes a sliding window
      (five-hour limit, weekly allowance): usage expires as entries age out.
    - `kind="calendar"` plus `calendar_granularity` describes a fixed-boundary
      window ("week" resets on Monday 00:00, "month" resets on the 1st 00:00).
    """

    kind: str
    duration_seconds: float | None = None
    calendar_granularity: str | None = None

    @classmethod
    def five_hour(cls) -> "WindowSpec":
        return cls(kind="rolling", duration_seconds=FIVE_HOUR_SECONDS)

    @classmethod
    def week(cls) -> "WindowSpec":
        return cls(kind="calendar", calendar_granularity="week")

    @classmethod
    def month(cls) -> "WindowSpec":
        return cls(kind="calendar", calendar_granularity="month")

    @classmethod
    def day(cls) -> "WindowSpec":
        return cls(kind="calendar", calendar_granularity="day")

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "duration_seconds": self.duration_seconds,
            "calendar_granularity": self.calendar_granularity,
        }


def _month_boundary(t: float) -> float:
    """Return seconds since epoch at the first day of the month containing `t`."""
    day = math.floor(t / DAY_SECONDS)
    days_from_epoch = calendar.timegm(
        (1970, 1, 1, 0, 0, 0)
    ) // DAY_SECONDS
    ref = day - days_from_epoch
    y, m, _d = _ymd_from_day(ref)
    first_ref = _day_from_ymd(y, m, 1)
    return float(first_ref * DAY_SECONDS)


def _week_boundary(t: float) -> float:
    """Return seconds since epoch at the most recent Monday 00:00 at or before t.

    Weeks start on Monday (ISO 8601).  Deterministic: 1970-01-01 was a Thursday.
    """
    day = math.floor(t / DAY_SECONDS)
    days_from_epoch = calendar.timegm(
        (1970, 1, 1, 0, 0, 0)
    ) // DAY_SECONDS
    ref = day - days_from_epoch
    # 1970-01-01 = Thursday; weekday()==3, so offset = (ref_weekday) % 7.
    offset = (ref + 3) % 7
    monday_ref = ref - offset
    return float(monday_ref * DAY_SECONDS)


def _day_boundary(t: float) -> float:
    return float(math.floor(t / DAY_SECONDS) * DAY_SECONDS)


def _ymd_from_day(ref_day: int) -> tuple[int, int, int]:
    year = 1970
    while True:
        days_in_year = 366 if calendar.isleap(year) else 365
        if ref_day < days_in_year:
            break
        ref_day -= days_in_year
        year += 1
    for month in range(1, 13):
        days_in_month = calendar.monthrange(year, month)[1]
        if ref_day < days_in_month:
            return year, month, ref_day + 1
        ref_day -= days_in_month
    raise AssertionError("unreachable month boundary")


def _day_from_ymd(year: int, month: int, day: int) -> int:
    ref_day = 0
    for y in range(1970, year):
        ref_day += 366 if calendar.isleap(y) else 365
    for m in range(1, month):
        ref_day += calendar.monthrange(year, m)[1]
    return ref_day + day - 1


class QuotaWindow:
    """Tracks usage inside one window and reports remaining capacity.

    Rolling windows expire usage by age; calendar windows clear at fixed
    boundaries (the clock emits a `quota_window_reset` event on the crossing).
    """

    def __init__(self, spec: WindowSpec, cap: float) -> None:
        self.spec = spec
        self.cap = cap
        self._entries: list[tuple[float, float]] = []  # (time, amount)

    def _active_entries(self, now: float) -> list[tuple[float, float]]:
        if self.spec.kind == "rolling":
            cutoff = now - (self.spec.duration_seconds or 0.0)
            return [e for e in self._entries if e[0] > cutoff]
        return list(self._entries)

    def consume(self, amount: float, now: float, event: str = "usage") -> None:
        if amount < 0:
            raise ValueError("usage amount must be non-negative")
        self._entries.append((now, amount))

    def usage(self, now: float) -> float:
        return sum(amount for _t, amount in self._active_entries(now))

    def remaining(self, now: float) -> float:
        return max(0.0, self.cap - self.usage(now))

    def exhausted(self, now: float) -> bool:
        return self.usage(now) >= self.cap

    def reset_instant(self, now: float) -> float | None:
        """Earliest instant at which usage starts to expire (rolling) or the
        next fixed boundary that clears the window (calendar)."""
        if self.spec.kind == "rolling":
            cutoff = now - (self.spec.duration_seconds or 0.0)
            future = [t for t, _a in self._entries if t > cutoff]
            return min(future) + (self.spec.duration_seconds or 0.0) if future else None
        return self.next_boundary(now)

    def next_boundary(self, now: float) -> float:
        if self.spec.kind == "calendar":
            if self.spec.calendar_granularity == "week":
                return _week_boundary(now) + WEEK_SECONDS
            if self.spec.calendar_granularity == "month":
                y, m, _d = _ymd_from_day(int(_month_boundary(now) // DAY_SECONDS))
                next_month = 1 if m == 12 else m + 1
                next_year = y + 1 if m == 12 else y
                return float(_day_from_ymd(next_year, next_month, 1) * DAY_SECONDS)
            if self.spec.calendar_granularity == "day":
                return _day_boundary(now) + DAY_SECONDS
            raise ValueError(
                f"unknown calendar granularity: {self.spec.calendar_granularity}"
            )
        return now + (self.spec.duration_seconds or 0.0)

    def reset(self) -> None:
        """Clear all usage (called by the clock at a calendar boundary)."""
        self._entries = []

    def snapshot(self, now: float) -> dict[str, Any]:
        return {
            "spec": self.spec.to_dict(),
            "cap": self.cap,
            "usage": round(self.usage(now), 6),
            "remaining": round(self.remaining(now), 6),
            "exhausted": self.exhausted(now),
            "next_boundary": self.next_boundary(now),
        }


class FakeClock:
    """Deterministic wall clock plus quota-window reset scheduling.

    `advance(seconds)` moves time forward in whole ticks and fires calendar
    window resets at their exact boundary instants.  A fresh clock with the
    same seed produces the same random draws, so replay is byte-stable.
    """

    def __init__(self, seed: int, start: float = 0.0) -> None:
        self._seed = int(seed)
        self._now = float(start)
        self._rng = random.Random(self._seed)
        self._windows: list[QuotaWindow] = []
        self._events: list[dict[str, Any]] = []

    def now(self) -> float:
        return self._now

    def rng(self) -> random.Random:
        return self._rng

    def add_window(self, spec: WindowSpec, cap: float) -> QuotaWindow:
        window = QuotaWindow(spec, cap)
        self._windows.append(window)
        return window

    def emit(self, kind: str, **detail: Any) -> dict[str, Any]:
        event = {"t": self._now, "kind": kind}
        event.update(detail)
        self._events.append(event)
        return event

    def events(self) -> list[dict[str, Any]]:
        return list(self._events)

    def advance(self, seconds: float) -> None:
        if seconds < 0:
            raise ValueError("advance must be non-negative")
        if seconds == 0:
            return
        target = self._now + float(seconds)
        while True:
            # Find the earliest calendar boundary strictly after now.
            pending = [
                w.next_boundary(self._now)
                for w in self._windows
                if w.spec.kind == "calendar"
            ]
            pending = [b for b in pending if self._now < b <= target]
            if not pending:
                break
            boundary = min(pending)
            self._now = boundary
            # Every calendar window whose next boundary falls exactly on this
            # instant (epoch-aligned day multiples) resets here.
            reset_specs = []
            for window in self._windows:
                if (
                    window.spec.kind == "calendar"
                    and window.next_boundary(self._now - 0.5) == self._now
                ):
                    window.reset()
                    reset_specs.append(window.spec.to_dict())
            self.emit("quota_window_reset", window_specs=reset_specs)
        self._now = target
        self.emit("clock_tick", seconds=float(seconds), now=self._now)

    def advance_to(self, instant: float) -> None:
        if instant < self._now:
            raise ValueError(f"cannot rewind clock to {instant} < {self._now}")
        self.advance(instant - self._now)
