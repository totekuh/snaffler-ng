# snaffler/accessors/file_accessor.py

import logging
from abc import ABC, abstractmethod
from pathlib import Path

logger = logging.getLogger("snaffler")


class FileAccessor(ABC):
    @abstractmethod
    def read(self, file_path: str, max_bytes: int | None = None) -> bytes | None: ...

    @abstractmethod
    def copy_to_local(self, file_path: str, dest_root: str) -> None: ...

    def close(self) -> None:
        """Release resources. Override in subclasses with connections to clean up."""
        pass

    def _safe_local_write(self, dest_root: str, relative_parts: list[str], data: bytes) -> bool:
        """Write data under dest_root with path traversal protection. Returns True on success."""
        local = Path(dest_root).joinpath(*relative_parts).resolve()
        root = Path(dest_root).resolve()
        if not local.is_relative_to(root):
            logger.warning(f"Path traversal blocked: {'/'.join(relative_parts)}")
            return False
        local.parent.mkdir(parents=True, exist_ok=True)
        local.write_bytes(data)
        return True
