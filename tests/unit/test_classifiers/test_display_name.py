"""Tests for display_name plumbing through FileContext and FileScanner."""

from snaffler.analysis.model.file_context import FileContext


class TestFileContextDisplayName:
    def test_display_name_overrides_basename(self):
        ctx = FileContext.from_path(
            "/FileLib/ab12/ab12cd34ef56", size=100, mtime_epoch=1000.0,
            display_name="deploy-script.ps1",
        )
        assert ctx.name == "deploy-script.ps1"
        assert ctx.ext == ".ps1"
        assert ctx.unc_path == "/FileLib/ab12/ab12cd34ef56"

    def test_display_name_stored(self):
        ctx = FileContext.from_path(
            "/FileLib/ab12/ab12cd34ef56", size=100, mtime_epoch=1000.0,
            display_name="secret.txt",
        )
        assert ctx.display_name == "secret.txt"

    def test_no_display_name_uses_basename(self):
        ctx = FileContext.from_path(
            "//server/share/path/config.ini", size=100, mtime_epoch=1000.0,
        )
        assert ctx.name == "config.ini"
        assert ctx.ext == ".ini"
        assert ctx.display_name is None

    def test_display_name_ext_extraction(self):
        ctx = FileContext.from_path(
            "/FileLib/dead/deadbeef", size=50, mtime_epoch=0.0,
            display_name="backup.tar.gz",
        )
        assert ctx.name == "backup.tar.gz"
        assert ctx.ext == ".gz"

    def test_display_name_no_ext(self):
        ctx = FileContext.from_path(
            "/FileLib/ab12/ab12cd34", size=50, mtime_epoch=0.0,
            display_name="Makefile",
        )
        assert ctx.name == "Makefile"
        assert ctx.ext == ""
