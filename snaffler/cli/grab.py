"""Bulk download mode: read file paths from stdin, download each."""

import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import typer

from snaffler.config.configuration import SnafflerConfiguration

logger = logging.getLogger("snaffler")


def run_grab(cfg: SnafflerConfiguration):
    dest = cfg.scanning.snaffle_path
    Path(dest).mkdir(parents=True, exist_ok=True)

    raw = sys.stdin.read()
    paths = [line.strip() for line in raw.splitlines() if line.strip()]
    if not paths:
        typer.echo("No file paths received on stdin.", err=True)
        raise typer.Exit(code=1)

    typer.echo(f"Grabbing {len(paths)} files to {dest}")

    smb_paths = []
    ftp_paths = []
    local_paths = []
    for p in paths:
        if p.startswith("ftp://"):
            ftp_paths.append(p)
        elif p.startswith("//"):
            smb_paths.append(p)
        else:
            local_paths.append(p)

    accessors = {}
    if smb_paths:
        from snaffler.accessors.smb_file_accessor import SMBFileAccessor
        accessors["smb"] = SMBFileAccessor(cfg)
    if ftp_paths:
        from snaffler.accessors.ftp_file_accessor import FTPFileAccessor
        accessors["ftp"] = FTPFileAccessor(cfg)
    if local_paths:
        from snaffler.accessors.local_file_accessor import LocalFileAccessor
        accessors["local"] = LocalFileAccessor()

    ok = 0
    fail = 0

    def _resolve_local_path(file_path: str) -> Path:
        import os
        if file_path.startswith("ftp://"):
            from snaffler.discovery.ftp_tree_walker import parse_ftp_url
            parsed = parse_ftp_url(file_path)
            if parsed:
                host, _port, remote = parsed
                return (Path(dest) / host / remote.lstrip("/")).resolve()
        elif file_path.startswith("//"):
            from snaffler.utils.path_utils import parse_unc_path
            parsed = parse_unc_path(file_path)
            if parsed:
                server, share, smb_path, _name, _ext = parsed
                clean = smb_path.lstrip("\\/").replace("\\", "/")
                return (Path(dest) / server / share / clean).resolve()
        else:
            rel = os.path.relpath(file_path, "/")
            return (Path(dest) / rel).resolve()
        return None

    def _grab_one(file_path: str) -> bool:
        if file_path.startswith("ftp://"):
            accessor = accessors["ftp"]
        elif file_path.startswith("//"):
            accessor = accessors["smb"]
        else:
            accessor = accessors["local"]
        accessor.copy_to_local(file_path, dest)
        local = _resolve_local_path(file_path)
        return local is not None and local.exists()

    workers = max(1, cfg.advanced.file_threads)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        future_to_path = {pool.submit(_grab_one, p): p for p in paths}
        for future in as_completed(future_to_path):
            p = future_to_path[future]
            try:
                if future.result():
                    ok += 1
                    logger.info(f"[OK] {p}")
                else:
                    fail += 1
                    logger.warning(f"[FAIL] {p}")
            except Exception as e:
                fail += 1
                logger.warning(f"[FAIL] {p}: {e}")

    typer.echo(f"\nDone: {ok} downloaded, {fail} failed ({len(paths)} total)")
