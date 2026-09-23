from __future__ import annotations

import importlib.util
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = pathlib.Path(__file__).resolve().parents[1]


def load_lock_module():
    spec = importlib.util.spec_from_file_location(
        "portable_file_lock_under_test", ROOT / "scripts" / "portable_file_lock.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


locks = load_lock_module()


class _LockedByteProbe:
    """Minimal binary handle whose protected byte must never be read."""

    def __init__(self, size: int = 1):
        self.size = size
        self.position = 0
        self.writes: list[bytes] = []

    def seek(self, offset: int, whence: int = 0) -> int:
        if whence == 2:
            self.position = self.size + offset
        else:
            self.position = offset
        return self.position

    def tell(self) -> int:
        return self.position

    def write(self, value: bytes) -> int:
        self.writes.append(value)
        self.size += len(value)
        self.position = self.size
        return len(value)

    def flush(self) -> None:
        return None

    def fileno(self) -> int:
        return 7

    def read(self, _size: int = -1) -> bytes:  # pragma: no cover - must not run
        raise PermissionError("the existing Windows byte range is locked")


class PortableFileLockTests(unittest.TestCase):
    def test_nonblocking_contention_fails_then_release_allows_reacquire(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "dispatch.lock"
            with locks.exclusive_file_lock(path):
                with self.assertRaises(locks.PortableFileLockContended):
                    with locks.exclusive_file_lock(path, blocking=False):
                        self.fail("a contending owner must never enter the mutation scope")
            with locks.exclusive_file_lock(path, blocking=False):
                self.assertGreaterEqual(path.stat().st_size, 0)

    def test_lock_releases_when_protected_body_raises(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "dispatch.lock"
            with self.assertRaisesRegex(RuntimeError, "body failed"):
                with locks.exclusive_file_lock(path):
                    raise RuntimeError("body failed")
            with locks.exclusive_file_lock(path, blocking=False):
                pass

    def test_windows_existing_sentinel_is_never_read_or_rewritten(self):
        handle = _LockedByteProbe(size=1)
        locks._prepare_windows_lock_byte(handle)
        self.assertEqual([], handle.writes)
        self.assertEqual(0, handle.position)

    def test_windows_empty_sentinel_is_initialized_from_eof(self):
        handle = _LockedByteProbe(size=0)
        with patch.object(locks.os, "fsync") as fsync:
            locks._prepare_windows_lock_byte(handle)
        self.assertEqual([b"\0"], handle.writes)
        self.assertEqual(0, handle.position)
        fsync.assert_called_once_with(7)

    def test_unknown_lock_backend_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "dispatch.lock"
            with patch.object(locks, "_fcntl", None), patch.object(locks, "_msvcrt", None):
                with self.assertRaises(locks.PortableFileLockError):
                    with locks.exclusive_file_lock(path):
                        self.fail("unknown backends must not enter the mutation scope")


if __name__ == "__main__":
    unittest.main()
