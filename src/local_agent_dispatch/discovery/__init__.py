"""Provider-neutral evidence discovery and compatibility resolution."""

from .resolver import (
    build_probe_plan,
    build_search_plan,
    resolve_capability,
    resolve_gate,
)

__all__ = [
    "build_probe_plan",
    "build_search_plan",
    "resolve_capability",
    "resolve_gate",
]
