"""Tests for snaffler.analysis.model.file_context.FileContext.

Covers created/accessed timestamp propagation from epoch values.
"""

from datetime import datetime

from snaffler.analysis.model.file_context import FileContext


def test_from_path_basic_fields():
    ctx = FileContext.from_path("//HOST/SHARE/dir/file.TXT", 100, 1700000000.0)

    assert ctx.unc_path == "//HOST/SHARE/dir/file.TXT"
    assert ctx.name == "file.TXT"
    assert ctx.ext == ".TXT"
    assert ctx.size == 100


def test_from_path_populates_created_and_accessed():
    """ctime_epoch / atime_epoch are converted to datetime."""
    mtime = 1700000000.0
    ctime = 1690000000.0
    atime = 1695000000.0

    ctx = FileContext.from_path("//HOST/SHARE/f.txt", 10, mtime, ctime, atime)

    assert ctx.modified == datetime.fromtimestamp(mtime)
    assert ctx.created == datetime.fromtimestamp(ctime)
    assert ctx.accessed == datetime.fromtimestamp(atime)


def test_from_path_created_accessed_default_to_none():
    """When ctime/atime are omitted they default to 0.0 → None."""
    ctx = FileContext.from_path("//HOST/SHARE/f.txt", 10, 1700000000.0)

    assert ctx.created is None
    assert ctx.accessed is None


def test_from_path_zero_epoch_is_none():
    """0.0 epoch for ctime/atime → None (mirrors 'no timestamp available')."""
    ctx = FileContext.from_path("//HOST/SHARE/f.txt", 10, 1700000000.0, 0.0, 0.0)

    assert ctx.created is None
    assert ctx.accessed is None


def test_from_path_none_epoch_is_none():
    """None epoch for ctime/atime → None."""
    ctx = FileContext.from_path("//HOST/SHARE/f.txt", 10, 1700000000.0, None, None)

    assert ctx.created is None
    assert ctx.accessed is None


def test_context_is_frozen():
    ctx = FileContext.from_path("//HOST/SHARE/f.txt", 10, 1700000000.0)
    try:
        ctx.created = datetime.now()  # type: ignore[misc]
    except Exception as e:
        assert e.__class__.__name__ in ("FrozenInstanceError", "AttributeError")
    else:
        raise AssertionError("FileContext should be frozen")
