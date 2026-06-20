"""Tests for LocalTreeWalker — ctime/atime propagation from os.stat()."""

import os

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
