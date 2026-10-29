"""Tests for LocalTreeWalker — ctime/atime propagation from os.stat()."""

import os
import threading
from unittest.mock import patch

from snaffler.discovery.local_tree_walker import LocalTreeWalker


def collect_callback():
    collected = []

    def on_file(path, size, mtime, ctime=0.0, atime=0.0):
        collected.append((path, size, mtime, ctime, atime))

    return on_file, collected


def test_local_walker_forwards_ctime_atime(tmp_path):
    """LocalTreeWalker reads st_ctime/st_atime and forwards them to on_file."""
    f = tmp_path / "data.txt"
    f.write_bytes(b"hello")

    walker = LocalTreeWalker()
    on_file, collected = collect_callback()
    walker.walk_directory(str(tmp_path), on_file=on_file)

    assert len(collected) == 1
    path, size, mtime, ctime, atime = collected[0]
    assert path == str(f)
    assert size == 5

    stat = os.stat(str(f))
    assert mtime == stat.st_mtime
    assert ctime == stat.st_ctime
    assert atime == stat.st_atime


def test_cancel_returns_empty(tmp_path):
    (tmp_path / "file.txt").write_bytes(b"data")
    cancel = threading.Event()
    cancel.set()

    walker = LocalTreeWalker()
    result = walker.walk_directory(str(tmp_path), cancel=cancel)
    assert result == []


def test_scandir_permission_error(tmp_path):
    walker = LocalTreeWalker()
    with patch("os.scandir", side_effect=PermissionError("denied")):
        result = walker.walk_directory(str(tmp_path))
    assert result == []


def test_dangling_symlink_skipped(tmp_path):
    (tmp_path / "real.txt").write_bytes(b"real")
    os.symlink(str(tmp_path / "nonexistent"), str(tmp_path / "broken_link"))

    walker = LocalTreeWalker()
    on_file, collected = collect_callback()
    dirs_collected = []
    walker.walk_directory(str(tmp_path), on_file=on_file, on_dir=lambda d: dirs_collected.append(d))

    paths = [c[0] for c in collected]
    assert str(tmp_path / "real.txt") in paths
    assert str(tmp_path / "broken_link") not in paths
    assert str(tmp_path / "broken_link") not in dirs_collected


def test_stat_oserror_fallback(tmp_path):
    f = tmp_path / "file.txt"
    f.write_bytes(b"data")

    walker = LocalTreeWalker()
    on_file, collected = collect_callback()

    real_scandir = os.scandir

    class BrokenStatEntry:
        """Wraps a real DirEntry but raises OSError on stat()."""
        def __init__(self, real_entry):
            self._real = real_entry
        def __getattr__(self, name):
            return getattr(self._real, name)
        def stat(self, *args, **kwargs):
            raise OSError("stat failed")

    def patched_scandir(path):
        with real_scandir(path) as ctx:
            entries = [BrokenStatEntry(e) for e in ctx]
        class Ctx:
            def __enter__(s):
                return s
            def __exit__(s, *a):
                pass
            def __iter__(s):
                return iter(entries)
        return Ctx()

    with patch("os.scandir", patched_scandir):
        walker.walk_directory(str(tmp_path), on_file=on_file)

    assert len(collected) == 1
    _, size, mtime, ctime, atime = collected[0]
    assert size == 0
    assert mtime == 0.0
    assert ctime == 0.0
    assert atime == 0.0
