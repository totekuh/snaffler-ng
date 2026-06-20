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


def test_from_path_modified_zero_epoch_is_none():
    """0.0 epoch for mtime → None (unified with ctime/atime, was 1970 before)."""
    ctx = FileContext.from_path("//HOST/SHARE/f.txt", 10, 0.0, 0.0, 0.0)

    assert ctx.modified is None
    assert ctx.created is None
    assert ctx.accessed is None


def test_from_path_modified_none_epoch_is_none():
    """None epoch for mtime → None."""
    ctx = FileContext.from_path("//HOST/SHARE/f.txt", 10, None)

    assert ctx.modified is None


def test_from_path_huge_epoch_degrades_to_none():
    """An out-of-range (huge) epoch degrades to None instead of raising."""
    ctx = FileContext.from_path("//HOST/SHARE/f.txt", 10, 1700000000.0, 1e20, 0.0)

    assert ctx.modified == datetime.fromtimestamp(1700000000.0)
    assert ctx.created is None
    assert ctx.accessed is None


def test_from_path_negative_epoch_degrades_to_none():
    """A very negative epoch degrades to None instead of raising."""
    ctx = FileContext.from_path("//HOST/SHARE/f.txt", 10, 1700000000.0, 0.0, -1e12)

    assert ctx.created is None
    assert ctx.accessed is None


def test_from_path_bad_mtime_degrades_to_none_keeps_other_fields():
    """A bad mtime alone must not abort the context; other fields survive."""
    ctx = FileContext.from_path("//HOST/SHARE/f.txt", 10, 1e20, 1690000000.0, 0.0)

    assert ctx.modified is None
    assert ctx.name == "f.txt"
    assert ctx.created == datetime.fromtimestamp(1690000000.0)


def test_context_is_frozen():
    ctx = FileContext.from_path("//HOST/SHARE/f.txt", 10, 1700000000.0)
    try:
        ctx.created = datetime.now()  # type: ignore[misc]
    except Exception as e:
        assert e.__class__.__name__ in ("FrozenInstanceError", "AttributeError")
    else:
        raise AssertionError("FileContext should be frozen")
