"""Build SnafflerConfiguration from CLI parameters."""

import logging
from pathlib import Path
from typing import Optional, List

import typer

from snaffler.config.configuration import SnafflerConfiguration

logger = logging.getLogger("snaffler")


def _is_explicit(ctx: typer.Context, param: str) -> bool:
    src = ctx.get_parameter_source(param)
    return src is not None and src.name not in ("DEFAULT", "DEFAULT_MAP")


def build_config(
    ctx: typer.Context,
    *,
    config_file, username, password, nthash, domain, dc_host, smb_timeout,
    kerberos, use_kcache,
    unc_targets, local, ftp, ftp_file, ftp_tls,
    computer, computer_file, shares_only, no_check_writable, check_writable,
    rescan_unreadable, domain_users, user_match, user_min_len,
    grab, include_disabled, stdin_mode,
    share, exclude_share, exclude_unc, exclusions_file, max_hosts,
    min_interest, max_read_bytes, max_file_bytes, context, max_depth,
    fast, match_filter, snaffle_path,
    max_threads, dns_threads, max_threads_per_share,
    stealth, rule_dir,
    output_file, log_level, log_type, no_color,
    state, fresh,
    web, web_port,
    default_log_type: str = "plain",
) -> SnafflerConfiguration:

    def _explicit(param: str) -> bool:
        return _is_explicit(ctx, param)

    cfg = SnafflerConfiguration()

    if config_file:
        cfg.load_from_toml(str(config_file))

    # ---------- AUTH ----------
    if _explicit("username"):     cfg.auth.username = username
    if _explicit("password"):     cfg.auth.password = password
    if _explicit("nthash"):       cfg.auth.nthash = nthash
    if _explicit("domain"):       cfg.auth.domain = domain
    if _explicit("dc_host"):      cfg.auth.dc_host = dc_host
    if _explicit("smb_timeout"):  cfg.auth.smb_timeout = smb_timeout
    if _explicit("kerberos"):     cfg.auth.kerberos = kerberos
    if _explicit("use_kcache"):   cfg.auth.use_kcache = use_kcache

    # ---------- TARGETING ----------
    if _explicit("unc_targets"):      cfg.targets.unc_targets = unc_targets or []
    if _explicit("local"):            cfg.targets.local_targets = local or []
    if _explicit("shares_only"):      cfg.targets.shares_only = shares_only
    if _explicit("no_check_writable"): cfg.targets.check_writable = not no_check_writable
    if _explicit("check_writable"):    cfg.targets.check_writable = check_writable
    if _explicit("include_disabled"): cfg.targets.skip_disabled_computers = not include_disabled
    if _explicit("rescan_unreadable"): cfg.targets.rescan_unreadable = rescan_unreadable
    if _explicit("domain_users"):     cfg.targets.domain_users = domain_users
    if _explicit("user_match"):       cfg.targets.user_match_strings = user_match or []
    if _explicit("user_min_len"):     cfg.targets.user_min_len = user_min_len
    if _explicit("share"):            cfg.targets.share_filter = share or []
    if _explicit("exclude_share"):    cfg.targets.exclude_share = exclude_share or []
    if _explicit("exclude_unc"):      cfg.targets.exclude_unc = exclude_unc or []

    if computer and computer_file:
        raise typer.BadParameter("Use either --computer or --computer-file, not both")

    if computer:
        from snaffler.utils.target_parser import expand_targets
        cfg.targets.computer_targets = expand_targets([h.upper() for h in computer])

    if computer_file:
        from snaffler.utils.target_parser import expand_targets
        raw = [l.strip().upper() for l in computer_file.read_text().splitlines() if l.strip()]
        cfg.targets.computer_targets = expand_targets(raw)

    if exclusions_file:
        cfg.targets.exclusions = [
            l.strip().upper() for l in exclusions_file.read_text().splitlines() if l.strip()
        ]

    if _explicit("max_hosts"):
        cfg.targets.max_hosts = max_hosts

    # ---------- GRAB MODE VALIDATION ----------
    if grab:
        if not snaffle_path:
            raise typer.BadParameter("--grab requires -m/--snaffle-path")
        if (cfg.targets.unc_targets or cfg.targets.computer_targets
                or cfg.targets.local_targets or cfg.auth.domain
                or cfg.targets.ftp_targets or stdin_mode
                or cfg.targets.rescan_unreadable):
            raise typer.BadParameter(
                "--grab is mutually exclusive with all other targeting modes"
            )

    # ---------- LOCAL TARGET VALIDATION ----------
    if cfg.targets.local_targets:
        if cfg.targets.unc_targets or cfg.targets.computer_targets or cfg.auth.domain or stdin_mode:
            raise typer.BadParameter(
                "--local-fs is mutually exclusive with --unc, --computer, --computer-file, --domain, and --stdin"
            )
        for lp in cfg.targets.local_targets:
            p = Path(lp)
            if not p.exists():
                raise typer.BadParameter(f"--local-fs path does not exist: {lp}")
            if not p.is_dir():
                raise typer.BadParameter(f"--local-fs path is not a directory: {lp}")

    # ---------- FTP TARGETS ----------
    if ftp and ftp_file:
        raise typer.BadParameter("Use either --ftp or --ftp-file, not both")

    def _normalize_ftp(raw_url: str) -> str:
        url = raw_url.strip()
        if not url.startswith("ftp://"):
            url = f"ftp://{url}"
        url = url.rstrip("/") or url
        from urllib.parse import urlparse
        parsed = urlparse(url)
        if not parsed.hostname:
            raise typer.BadParameter(f"Invalid FTP URL (no host): {raw_url}")
        return url

    if ftp:
        cfg.targets.ftp_targets = [_normalize_ftp(r) for r in ftp]
    if ftp_file:
        lines = [l.strip() for l in ftp_file.read_text().splitlines() if l.strip() and not l.strip().startswith("#")]
        cfg.targets.ftp_targets = [_normalize_ftp(r) for r in lines]
    if _explicit("ftp_tls"):
        cfg.targets.ftp_tls = ftp_tls

    if cfg.targets.ftp_targets:
        if cfg.targets.unc_targets or cfg.targets.computer_targets or cfg.targets.local_targets or cfg.auth.domain or stdin_mode:
            raise typer.BadParameter(
                "--ftp is mutually exclusive with --unc, --computer, --computer-file, --local-fs, --domain, and --stdin"
            )

    # ---------- STDIN (NXC) ----------
    if stdin_mode:
        if cfg.targets.unc_targets or cfg.targets.computer_targets or cfg.targets.local_targets or cfg.auth.domain:
            raise typer.BadParameter(
                "--stdin is mutually exclusive with --unc, --computer, --computer-file, --local-fs, and --domain"
            )
        import sys
        from snaffler.utils.nxc_parser import parse_nxc_shares

        raw = sys.stdin.read()
        parsed = parse_nxc_shares(raw)
        if not parsed:
            raise typer.BadParameter(
                "No shares found in stdin (expected NXC SMB --shares output)"
            )
        cfg.targets.unc_targets = parsed

    # ---------- TARGET MODE VALIDATION ----------
    has_unc = bool(cfg.targets.unc_targets)
    has_local = bool(cfg.targets.local_targets)
    has_computers = bool(cfg.targets.computer_targets)
    has_domain = bool(cfg.auth.domain)
    has_ftp = bool(cfg.targets.ftp_targets)

    if cfg.targets.rescan_unreadable and (has_local or has_ftp):
        raise typer.BadParameter(
            "--rescan-unreadable is mutually exclusive with --local-fs and --ftp"
        )

    if not grab and not (has_unc or has_local or has_computers or has_domain or has_ftp
            or cfg.targets.rescan_unreadable):
        raise typer.BadParameter(
            "No targets specified. Use one of: "
            "--unc, --local-fs, --ftp, --computer/--computer-file, --stdin, --domain, "
            "--grab, or --rescan-unreadable"
        )

    # ---------- SCANNING ----------
    if _explicit("min_interest"):   cfg.scanning.min_interest = min_interest
    if _explicit("max_read_bytes"): cfg.scanning.max_read_bytes = max_read_bytes
    if _explicit("max_file_bytes"): cfg.scanning.max_file_bytes = max_file_bytes
    if _explicit("context"):        cfg.scanning.match_context_bytes = context
    if _explicit("max_depth"):      cfg.scanning.max_depth = max_depth

    if match_filter:
        import re
        try:
            re.compile(match_filter)
        except re.error as exc:
            raise typer.BadParameter(f"Invalid --match regex: {exc}")
        cfg.scanning.match_filter = match_filter

    if snaffle_path:
        cfg.scanning.snaffle = True
        cfg.scanning.snaffle_path = str(snaffle_path)

    # ---------- ADVANCED ----------
    if _explicit("max_threads"):  cfg.advanced.max_threads = max_threads
    if _explicit("dns_threads"):  cfg.advanced.dns_threads = dns_threads
    if _explicit("stealth"):      cfg.advanced.stealth = stealth

    per_bucket = max(1, cfg.advanced.max_threads // 3)
    cfg.advanced.share_threads = per_bucket
    cfg.advanced.tree_threads = per_bucket
    cfg.advanced.file_threads = per_bucket

    if _explicit("max_threads_per_share"):
        cfg.advanced.max_tree_threads_per_share = max_threads_per_share

    # ---------- --fast mode ----------
    if fast:
        from snaffler.config.configuration import FAST_MODE_EXCLUSIONS
        cfg.targets.exclude_unc = list(FAST_MODE_EXCLUSIONS) + cfg.targets.exclude_unc
        if not _explicit("max_threads_per_share"):
            cfg.advanced.max_tree_threads_per_share = max(2, per_bucket // 4)

    if _explicit("rule_dir"):
        cfg.rules.rule_dir = f"{rule_dir}"

    # ---------- OUTPUT ----------
    cfg.output.to_file = output_file is not None
    cfg.output.output_file = str(output_file) if output_file else None
    cfg.output.log_level = log_level
    if log_type is None and output_file:
        ext = output_file.suffix.lower()
        if ext == ".json":
            log_type = "json"
        elif ext == ".tsv":
            log_type = "tsv"
    cfg.output.log_type = log_type or default_log_type

    if no_color:
        from snaffler.utils import logger as _logger_mod
        _logger_mod.NO_COLOR = True

    # ---------- STATE ----------
    state_path = Path(state) if state else Path("snaffler.db")
    if state_path.parent and not state_path.parent.exists():
        state_path.parent.mkdir(parents=True, exist_ok=True)
    if fresh and state_path.exists():
        state_path.unlink()
    cfg.state.state_db = str(state_path)

    # ---------- WEB DASHBOARD ----------
    if _explicit("web"):        cfg.web.enabled = web
    if _explicit("web_port"):   cfg.web.port = web_port
    if _explicit("web_port") and not cfg.web.enabled:
        typer.echo("Warning: --web-port has no effect without --web", err=True)

    # ---------- validate ----------
    try:
        cfg.validate()
    except ValueError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1)

    return cfg
