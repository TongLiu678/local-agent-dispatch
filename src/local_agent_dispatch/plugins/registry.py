"""Explicit plugin registration and provider-failure isolation.

The registry intentionally has no entry-point discovery and no implicit
imports.  Callers construct a plugin (usually from a local adapter module),
run conformance, and explicitly register it.  This keeps preflight provider-
free by default and makes the enabled integration set auditable in a packet or
runtime snapshot.
"""

from __future__ import annotations

import inspect
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from .protocols import (
    PLUGIN_API_VERSION,
    PLUGIN_KINDS,
    PROTOCOL_METHODS,
    PluginDescriptor,
)


_PLUGIN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_MAX_ERROR_CHARS = 512


class PluginRegistryError(ValueError):
    """Raised when a plugin cannot be safely admitted to the registry."""


@dataclass(frozen=True)
class ConformanceIssue:
    """One deterministic, provider-free conformance finding."""

    code: str
    message: str


@dataclass(frozen=True)
class ConformanceReport:
    """Result of checking a plugin's static contract."""

    ok: bool
    plugin_id: str | None
    kind: str | None
    api_version: str | None
    methods: tuple[str, ...]
    issues: tuple[ConformanceIssue, ...] = ()

    def raise_for_error(self) -> "ConformanceReport":
        if not self.ok:
            details = "; ".join(f"{item.code}: {item.message}" for item in self.issues)
            raise PluginRegistryError(details or "plugin failed conformance")
        return self


@dataclass(frozen=True)
class InvocationResult:
    """Redacted result wrapper used to isolate a crashing plugin."""

    ok: bool
    plugin_id: str
    kind: str
    operation: str
    value: Any = None
    error: str | None = None


def _safe_error(exc: BaseException) -> str:
    text = str(exc).replace("\r", " ").replace("\n", " ").strip()
    if not text:
        text = exc.__class__.__name__
    # Provider SDKs sometimes echo request headers or query parameters in an
    # exception.  Keep this boundary safe for event/log persistence while
    # retaining the exception class and a useful diagnostic fragment.
    text = re.sub(
        r"(?i)(api[_-]?key|token|password|secret|authorization|bearer)\s*[:=]\s*(?:bearer\s+)?[^\s,;]+",
        r"\1=<redacted>",
        text,
    )
    return f"{exc.__class__.__name__}: {text[:_MAX_ERROR_CHARS]}"


def _descriptor(plugin: Any) -> PluginDescriptor | None:
    """Read static metadata without invoking plugin descriptors or hooks."""

    try:
        value = inspect.getattr_static(plugin, "descriptor")
    except AttributeError:
        return None
    return value if isinstance(value, PluginDescriptor) else None


def _has_static_callable(plugin: Any, name: str) -> bool:
    """Return whether ``name`` is statically callable without binding it.

    ``inspect.getattr_static`` avoids invoking ``__getattr__``, properties, or
    custom descriptors during provider-free conformance.  Normal instance
    methods are plain function objects here; explicit static/class methods are
    unwrapped only for the callability check and are still never called.
    """

    try:
        value = inspect.getattr_static(plugin, name)
    except AttributeError:
        return False
    if isinstance(value, (staticmethod, classmethod)):
        value = value.__func__
    return callable(value)


def conformance_report(
    plugin: Any,
    *,
    expected_kind: str | None = None,
    api_version: str = PLUGIN_API_VERSION,
) -> ConformanceReport:
    """Check a plugin's metadata and required callable surface.

    This function never binds or calls plugin descriptors or operation
    methods.  It is safe to run during a no-network preflight and against fake
    provider fixtures.  Plugins must therefore expose ``descriptor`` as static
    data rather than a computed property.
    """

    issues: list[ConformanceIssue] = []
    descriptor = _descriptor(plugin)
    if descriptor is None:
        issues.append(
            ConformanceIssue("missing_descriptor", "plugin must expose a PluginDescriptor named descriptor")
        )
        return ConformanceReport(False, None, None, None, (), tuple(issues))

    plugin_id = descriptor.plugin_id if isinstance(descriptor.plugin_id, str) else None
    kind = descriptor.kind if isinstance(descriptor.kind, str) else None
    version = descriptor.api_version if isinstance(descriptor.api_version, str) else None

    if not plugin_id or not _PLUGIN_ID_RE.fullmatch(plugin_id):
        issues.append(ConformanceIssue("invalid_plugin_id", "plugin_id must be a simple stable identifier"))
    if kind not in PLUGIN_KINDS:
        issues.append(ConformanceIssue("invalid_kind", f"kind must be one of {PLUGIN_KINDS}"))
    if expected_kind is not None and kind != expected_kind:
        issues.append(ConformanceIssue("kind_mismatch", f"expected kind {expected_kind!r}, got {kind!r}"))
    if version != api_version:
        issues.append(ConformanceIssue("api_version_mismatch", f"expected api_version {api_version!r}, got {version!r}"))
    if not isinstance(descriptor.version, str) or not descriptor.version.strip():
        issues.append(ConformanceIssue("invalid_version", "plugin version must be a non-empty string"))
    if not isinstance(descriptor.capabilities, tuple) or any(
        not isinstance(item, str) or not item.strip() for item in descriptor.capabilities
    ):
        issues.append(ConformanceIssue("invalid_capabilities", "capabilities must be a tuple of non-empty strings"))
    elif len(set(descriptor.capabilities)) != len(descriptor.capabilities):
        issues.append(ConformanceIssue("duplicate_capabilities", "capabilities must not contain duplicates"))

    required = PROTOCOL_METHODS.get(kind, ())
    present: list[str] = []
    for name in required:
        if not _has_static_callable(plugin, name):
            issues.append(ConformanceIssue("missing_method", f"plugin must expose callable {name}()"))
        else:
            present.append(name)

    return ConformanceReport(
        ok=not issues,
        plugin_id=plugin_id,
        kind=kind,
        api_version=version,
        methods=tuple(present),
        issues=tuple(issues),
    )


class PluginRegistry:
    """Explicit, in-process registry keyed by ``(kind, plugin_id)``."""

    def __init__(self, *, api_version: str = PLUGIN_API_VERSION) -> None:
        self.api_version = api_version
        self._plugins: dict[tuple[str, str], Any] = {}

    def register(self, plugin: Any, *, replace: bool = False) -> PluginDescriptor:
        """Conform and register one plugin without invoking it."""

        report = conformance_report(plugin, api_version=self.api_version)
        report.raise_for_error()
        assert report.plugin_id is not None and report.kind is not None  # narrowed by conformance
        key = (report.kind, report.plugin_id)
        if key in self._plugins and not replace:
            raise PluginRegistryError(f"plugin already registered: {report.kind}.{report.plugin_id}")
        self._plugins[key] = plugin
        descriptor = _descriptor(plugin)
        assert descriptor is not None
        return descriptor

    def register_many(self, plugins: Iterable[Any], *, replace: bool = False) -> tuple[ConformanceReport, ...]:
        """Register independently and return all reports, isolating failures."""

        reports: list[ConformanceReport] = []
        for plugin in plugins:
            report = conformance_report(plugin, api_version=self.api_version)
            if report.ok:
                try:
                    self.register(plugin, replace=replace)
                except PluginRegistryError as exc:
                    report = ConformanceReport(
                        False,
                        report.plugin_id,
                        report.kind,
                        report.api_version,
                        report.methods,
                        report.issues + (ConformanceIssue("registration_failed", str(exc)),),
                    )
            reports.append(report)
        return tuple(reports)

    def unregister(self, kind: str, plugin_id: str) -> Any | None:
        """Remove a plugin explicitly; return the removed object if present."""

        return self._plugins.pop((str(kind), str(plugin_id)), None)

    def get(self, kind: str, plugin_id: str) -> Any:
        try:
            return self._plugins[(str(kind), str(plugin_id))]
        except KeyError as exc:
            raise PluginRegistryError(f"plugin not registered: {kind}.{plugin_id}") from exc

    def descriptors(self, *, kind: str | None = None) -> tuple[PluginDescriptor, ...]:
        """Return deterministic metadata only; no plugin operation is called."""

        rows = []
        for (plugin_kind, _), plugin in self._plugins.items():
            if kind is not None and plugin_kind != kind:
                continue
            descriptor = _descriptor(plugin)
            if descriptor is not None:
                rows.append(descriptor)
        return tuple(sorted(rows, key=lambda row: (row.kind, row.plugin_id)))

    def invoke(self, kind: str, plugin_id: str, operation: str, request: Any) -> InvocationResult:
        """Invoke one operation while converting plugin crashes to local errors.

        This helper is intentionally explicit: registration and discovery do
        not call operations.  A controller may opt into it after its lease and
        policy gates are held; a crashing provider is isolated to this result.
        """

        plugin = self.get(kind, plugin_id)
        if operation.startswith("_"):
            raise PluginRegistryError("private plugin operations cannot be invoked")
        if operation not in PROTOCOL_METHODS.get(str(kind), ()):
            raise PluginRegistryError(f"operation is outside the {kind} plugin contract: {operation}")
        method = getattr(plugin, operation, None)
        if not callable(method):
            raise PluginRegistryError(f"plugin {kind}.{plugin_id} has no operation {operation}")
        try:
            value = method(request)
        except Exception as exc:  # provider failure must not tear down sibling plugins
            return InvocationResult(False, str(plugin_id), str(kind), operation, error=_safe_error(exc))
        return InvocationResult(True, str(plugin_id), str(kind), operation, value=value)


__all__ = [
    "PluginRegistryError",
    "ConformanceIssue",
    "ConformanceReport",
    "InvocationResult",
    "conformance_report",
    "PluginRegistry",
]
