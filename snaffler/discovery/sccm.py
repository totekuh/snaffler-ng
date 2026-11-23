"""SCCM ContentLib deep scan — resolve DataLib INI pointers to FileLib blobs."""

import logging
import re
from typing import Any

logger = logging.getLogger("snaffler")

_HASH_RE = re.compile(r"^Hash\s*=\s*([0-9a-fA-F]+)", re.MULTILINE)

_CONTENTLIB_NAMES = {"sccmcontentlib", "sccmcontentlib$"}


def is_contentlib_dir(dir_name: str) -> bool:
    return dir_name.lower() in _CONTENTLIB_NAMES


def parse_ini_hash(content: str) -> str | None:
    m = _HASH_RE.search(content)
    return m.group(1) if m else None


def resolve_filelib_path(base_path: str, file_hash: str) -> str:
    prefix = file_hash[:4]
    return f"{base_path}/FileLib/{prefix}/{file_hash}"


def walk_contentlib(smb: Any, server: str, share: str, base_path: str, on_file: Any) -> None:
    datalib_path = f"{base_path}/DataLib/"
    try:
        entries = smb.listPath(share, datalib_path + "*")
    except Exception as exc:
        logger.debug(f"Cannot list DataLib at //{server}/{share}{datalib_path}: {exc}")
        return

    for entry in entries:
        name = entry.get_longname()
        if name in (".", "..") or entry.is_directory():
            continue
        if not name.lower().endswith(".ini"):
            continue

        ini_path = datalib_path + name
        try:
            from io import BytesIO

            buf = BytesIO()
            smb.getFile(share, ini_path, buf.write)
            content = buf.getvalue().decode("utf-8", errors="replace")
        except Exception as exc:
            logger.debug(f"Cannot read INI {ini_path}: {exc}")
            continue

        file_hash = parse_ini_hash(content)
        if not file_hash:
            logger.debug(f"No hash in {ini_path}")
            continue

        original_name = name[:-4]  # strip .INI
        filelib_rel = resolve_filelib_path(base_path, file_hash)
        filelib_unc = f"//{server}/{share}{filelib_rel}"

        try:
            blob_entries = smb.listPath(share, filelib_rel)
            blob_entry = next((e for e in blob_entries if e.get_longname() == file_hash), None)
            if not blob_entry:
                logger.debug(f"FileLib blob missing for {original_name}: {filelib_rel}")
                continue
            size = blob_entry.get_filesize()
            try:
                mtime = blob_entry.get_mtime_epoch()
            except Exception:
                mtime = 0.0
            try:
                ctime = blob_entry.get_ctime_epoch()
            except Exception:
                ctime = 0.0
            try:
                atime = blob_entry.get_atime_epoch()
            except Exception:
                atime = 0.0
        except Exception as exc:
            logger.debug(f"Cannot stat FileLib blob {filelib_rel}: {exc}")
            continue

        logger.debug(f"SCCM ContentLib: {original_name} -> {filelib_unc}")
        if on_file:
            on_file(filelib_unc, size, mtime, ctime, atime, original_name)
