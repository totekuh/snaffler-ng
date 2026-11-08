#!/usr/bin/env python3
"""Generate minimal binary test fixtures."""
import struct
from pathlib import Path

HERE = Path(__file__).parent


def write(name: str, data: bytes):
    (HERE / name).write_bytes(data)


# PE/MZ — minimal DOS header
dos_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 64)  # e_lfanew = 64
pe_sig = b"PE\x00\x00"
# COFF header: x86, 0 sections, timestamps, no symbols, optional header size 0
coff = struct.pack("<HHIIIHH", 0x14C, 0, 0, 0, 0, 0, 0)
write("tiny.exe", dos_header + pe_sig + coff)

# Mach-O 64-bit little-endian
write("fake.macho", b"\xcf\xfa\xed\xfe" + b"\x00" * 28)

# Plain text with a password (should NOT be skipped)
write("not_binary.txt", b"DB_PASSWORD=hunter2\nAPI_KEY=sk-1234567890\n")

# ELF binary with misleading .txt extension
elf_header = b"\x7fELF" + b"\x02\x01\x01" + b"\x00" * 9  # 64-bit, little-endian, Linux
write("secret_in_elf_ext.txt", elf_header + b"\x00" * 48)


if __name__ == "__main__":
    print("Generated binary fixtures in", HERE)
