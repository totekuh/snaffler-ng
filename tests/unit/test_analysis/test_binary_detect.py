import os
from pathlib import Path

from snaffler.analysis.binary_detect import read_magic

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "binaries"


# ── Positive matches ──

def test_elf_real():
    data = (DATA_DIR / "hello.elf").read_bytes()
    assert read_magic(data) == "ELF"


def test_elf_synthetic():
    assert read_magic(b"\x7fELF" + b"\x00" * 12) == "ELF"


def test_pe():
    data = (DATA_DIR / "tiny.exe").read_bytes()
    assert read_magic(data) == "PE"


def test_pe_minimal():
    assert read_magic(b"MZ\x90\x00") == "PE"


def test_macho_64_le():
    data = (DATA_DIR / "fake.macho").read_bytes()
    assert read_magic(data) == "Mach-O 64-bit (reversed)"


def test_macho_32_be():
    assert read_magic(b"\xfe\xed\xfa\xce" + b"\x00" * 4) == "Mach-O 32-bit"


def test_macho_64_be():
    assert read_magic(b"\xfe\xed\xfa\xcf" + b"\x00" * 4) == "Mach-O 64-bit"


def test_macho_32_le():
    assert read_magic(b"\xce\xfa\xed\xfe" + b"\x00" * 4) == "Mach-O 32-bit (reversed)"


def test_elf_with_txt_extension():
    data = (DATA_DIR / "secret_in_elf_ext.txt").read_bytes()
    assert read_magic(data) == "ELF"


# ── Negative matches (should NOT be detected as binary) ──

def test_plain_text():
    assert read_magic(b"hello world this is text") is None


def test_text_file_fixture():
    data = (DATA_DIR / "not_binary.txt").read_bytes()
    assert read_magic(data) is None


def test_empty():
    assert read_magic(b"") is None


def test_single_byte():
    assert read_magic(b"\x7f") is None


def test_png_not_binary():
    assert read_magic(b"\x89PNG\r\n\x1a\n" + b"\x00" * 16) is None


def test_jpeg_not_binary():
    assert read_magic(b"\xff\xd8\xff\xe0") is None


def test_gif_not_binary():
    assert read_magic(b"GIF89a" + b"\x00" * 10) is None


def test_pdf_not_binary():
    assert read_magic(b"%PDF-1.4 ") is None


def test_zip_not_binary():
    assert read_magic(b"PK\x03\x04" + b"\x00" * 26) is None


def test_rar_not_binary():
    assert read_magic(b"Rar!\x1a\x07\x01\x00") is None


def test_java_class_not_binary():
    assert read_magic(b"\xca\xfe\xba\xbe\x00\x00\x00\x34") is None


def test_python_pyc_not_binary():
    assert read_magic(b"\x61\x0d\r\n\x00\x00\x00\x00") is None


def test_wasm_not_binary():
    assert read_magic(b"\x00asm\x01\x00\x00\x00") is None
