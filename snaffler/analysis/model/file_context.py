import os
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass(frozen=True)
class FileContext:
    unc_path: str
    name: str
    ext: str
    size: int
    modified: Optional[datetime]
    created: Optional[datetime] = None
    accessed: Optional[datetime] = None

    @classmethod
    def from_path(
        cls,
        file_path: str,
        size: int,
        mtime_epoch: float,
        ctime_epoch: float = 0.0,
        atime_epoch: float = 0.0,
    ) -> "FileContext":
        """Create a :class:`FileContext` from a file path and metadata.

        Extracts basename and extension via :func:`os.path.basename` /
        :func:`os.path.splitext`, and converts *mtime_epoch* / *ctime_epoch*
        / *atime_epoch* to :class:`datetime` values. Each timestamp is
        ``None`` when the corresponding epoch is ``None`` or ``0.0``
        (mirroring the *modified* handling).
        """
        file_name = os.path.basename(file_path)
        file_ext = os.path.splitext(file_name)[1]
        modified = datetime.fromtimestamp(mtime_epoch) if mtime_epoch is not None else None
        created = datetime.fromtimestamp(ctime_epoch) if ctime_epoch else None
        accessed = datetime.fromtimestamp(atime_epoch) if atime_epoch else None
        return cls(
            unc_path=file_path,
            name=file_name,
            ext=file_ext,
            size=size,
            modified=modified,
            created=created,
            accessed=accessed,
        )
