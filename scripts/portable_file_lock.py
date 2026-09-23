#!/usr/bin/env python3
"""Small fail-closed cross-platform exclusive file lock.

The dispatch scripts are also copied to execution-only Windows workers, where
``fcntl`` does not exist.  Discovery and import must therefore remain portable,
while the mutation boundary still needs an operating-system owned lock that is
released when the process exits.
"""

from __future__ import annotations

import contextlib
import errno
import os
from pathlib import Path
from typing import BinaryIO, Iterator

try:  # POSIX
    import fcntl as _fcntl
except ImportError:  # pragma: no cover - exercised on Windows
    _fcntl = None

try:  # Windows
    import msvcrt as _msvcrt
except ImportError:  # pragma: no cover - exercised on POSIX
    _msvcrt = None


class PortableFileLockError(RuntimeError):
    """Raised when this host cannot prove an exclusive file lock."""


class PortableFileLockContended(PortableFileLockError):
    """Raised when another owner demonstrably holds the requested lock."""


def _windows_error_is_contention(exc: OSError) -> bool:
    """Recognize the CRT/Win32 errors used for an overlapping byte lock."""

    return exc.errno in {errno.EACCES, errno.EAGAIN, errno.EDEADLK} or getattr(
        exc, "winerror", None
    ) in {32, 33, 36, 158}


def _prepare_windows_lock_byte(handle: BinaryIO) -> None:
    """Ensure byte zero exists without reading a possibly locked byte.

    Windows denies reads of a byte range locked through another handle.  An
    ``a+`` implementation that probes byte zero with ``read(1)`` therefore
    fails before it can wait for (or report) lock contention.  File length is
    metadata and remains observable while the byte is locked, so initialize an
    empty append-only lock file from EOF and never read the protected range.

    Two first-time creators may both observe an empty file and append a byte.
    That is harmless: all contenders still lock byte zero, and this file is a
    permanent lock sentinel rather than application data.
    """

    handle.seek(0, os.SEEK_END)
    if handle.tell() == 0:
        handle.write(b"\0")
        handle.flush()
        os.fsync(handle.fileno())
    handle.seek(0)


def _lock_windows(handle: BinaryIO, *, blocking: bool) -> None:
    assert _msvcrt is not None
    _prepare_windows_lock_byte(handle)
    # LK_LOCK is bounded by the CRT (ten one-second retries).  If contention
    # cannot be resolved, it raises instead of allowing an unlocked mutation.
    mode = _msvcrt.LK_LOCK if blocking else _msvcrt.LK_NBLCK
    _msvcrt.locking(handle.fileno(), mode, 1)


def _unlock_windows(handle: BinaryIO) -> None:
    assert _msvcrt is not None
    handle.seek(0)
    _msvcrt.locking(handle.fileno(), _msvcrt.LK_UNLCK, 1)


@contextlib.contextmanager
def exclusive_file_lock(
    path: str | os.PathLike[str], *, blocking: bool = True
) -> Iterator[None]:
    """Hold one OS-owned exclusive lock or fail without yielding.

    ``blocking=False`` performs one non-blocking acquisition, which is useful
    for controller leases.  The Windows blocking path retains the CRT's
    bounded retry behavior rather than waiting forever.  In every mode, an
    unknown backend, open error, acquire error, or release error fails closed.
    """

    lock_path = Path(path)
    try:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        handle = lock_path.open("a+b")
    except OSError as exc:
        raise PortableFileLockError(f"could not open lock file: {lock_path}") from exc

    with handle:
        if _fcntl is not None:
            operation = _fcntl.LOCK_EX | (0 if blocking else _fcntl.LOCK_NB)
            try:
                _fcntl.flock(handle.fileno(), operation)
            except BlockingIOError as exc:
                raise PortableFileLockContended(
                    f"exclusive lock is already held: {lock_path}"
                ) from exc
            except OSError as exc:
                raise PortableFileLockError(
                    f"could not acquire exclusive lock: {lock_path}"
                ) from exc
            try:
                yield
            finally:
                try:
                    _fcntl.flock(handle.fileno(), _fcntl.LOCK_UN)
                except OSError as exc:
                    raise PortableFileLockError(
                        f"could not release exclusive lock: {lock_path}"
                    ) from exc
            return
        if _msvcrt is not None:
            try:
                _lock_windows(handle, blocking=blocking)
            except OSError as exc:
                error_type = (
                    PortableFileLockContended
                    if _windows_error_is_contention(exc)
                    else PortableFileLockError
                )
                raise error_type(f"could not acquire exclusive lock: {lock_path}") from exc
            try:
                yield
            finally:
                try:
                    _unlock_windows(handle)
                except OSError as exc:
                    raise PortableFileLockError(
                        f"could not release exclusive lock: {lock_path}"
                    ) from exc
            return
        raise PortableFileLockError(
            "this platform has no supported process-scoped file-lock backend"
        )


__all__ = [
    "PortableFileLockContended",
    "PortableFileLockError",
    "exclusive_file_lock",
]
