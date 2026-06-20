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
        / *atime_epoch* to :class:`datetime` values via
        :func:`_epoch_to_datetime`. Each timestamp is ``None`` when the
        corresponding epoch is ``None``, ``0.0`` (both meaning "unknown"),
        or out of range — applied uniformly to all three fields so a single
        bad timestamp never aborts the file's scan.
        """
        file_name = os.path.basename(file_path)
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
        )
