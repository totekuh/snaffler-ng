import logging
import os
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

logger = logging.getLogger("snaffler")


def _epoch_to_datetime(epoch: Optional[float]) -> Optional[datetime]:
    """Convert an epoch timestamp to a :class:`datetime`, degrading to ``None``.

    Returns ``None`` when *epoch* is ``None`` or ``0.0`` (both treated as
    "unknown" in this domain — ``0.0``/1970 is the walkers' default for an
    unavailable timestamp). A malformed or out-of-range epoch (huge or very
    negative) that would otherwise raise ``OSError``/``OverflowError``/
    ``ValueError`` is also degraded to ``None`` so a single bad timestamp
    never aborts an otherwise-valid file's scan.
    """
    if not epoch:
        return None
    try:
        return datetime.fromtimestamp(epoch)
    except (OSError, OverflowError, ValueError) as e:
        logger.debug(f"Ignoring out-of-range epoch {epoch!r}: {e}")
        return None


@dataclass(frozen=True)
class FileContext:
    unc_path: str
    name: str
    ext: str
    size: int
    modified: Optional[datetime]
    created: Optional[datetime] = None
    accessed: Optional[datetime] = None
    display_name: Optional[str] = None

    @classmethod
    def from_path(
        cls,
        file_path: str,
        size: int,
        mtime_epoch: float,
        ctime_epoch: float = 0.0,
        atime_epoch: float = 0.0,
        display_name: Optional[str] = None,
    ) -> "FileContext":
        """Create a :class:`FileContext` from a file path and metadata.

        When *display_name* is set (e.g. SCCM ContentLib original filename),
        it overrides basename/extension derivation for rule matching while
        *unc_path* stays as the real path for content reading.
        """
        file_name = display_name if display_name else os.path.basename(file_path)
        file_ext = os.path.splitext(file_name)[1]
        modified = _epoch_to_datetime(mtime_epoch)
        created = _epoch_to_datetime(ctime_epoch)
        accessed = _epoch_to_datetime(atime_epoch)
        return cls(
            unc_path=file_path,
            name=file_name,
            ext=file_ext,
            size=size,
            modified=modified,
            created=created,
            accessed=accessed,
            display_name=display_name,
        )
