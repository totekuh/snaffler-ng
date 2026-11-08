"""Detect native compiled binaries by magic bytes."""

BINARY_SIGNATURES = (
    (b"\x7fELF", "ELF"),
    (b"\xfe\xed\xfa\xce", "Mach-O 32-bit"),
    (b"\xfe\xed\xfa\xcf", "Mach-O 64-bit"),
    (b"\xce\xfa\xed\xfe", "Mach-O 32-bit (reversed)"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64-bit (reversed)"),
    (b"MZ", "PE"),
)


def read_magic(data: bytes) -> str | None:
    if len(data) < 2:
        return None
    for magic, name in BINARY_SIGNATURES:
        if data[:len(magic)] == magic:
            return name
    return None
