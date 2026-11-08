#!/usr/bin/env python3
import logging
from importlib.metadata import version as pkg_version
from pathlib import Path
from typing import Optional, List

import click
import typer

from snaffler.classifiers.loader import RuleLoader
from snaffler.config.configuration import SnafflerConfiguration
from snaffler.engine.runner import SnafflerRunner
from snaffler.utils.logger import setup_logging
from snaffler.cli.results import results_app
from snaffler.cli.config_builder import build_config
from snaffler.cli.grab import run_grab
from snaffler.cli.run_scan import run_scan

logger = logging.getLogger("snaffler")


def _get_version() -> str:
    try:
        return pkg_version("snaffler-ng")
    except Exception:
        return "1.5.11"  # fallback for PyInstaller/frozen builds — update on release


def _version_callback(value: bool):
    if value:
        typer.echo(f"snaffler-ng {_get_version()}")
        raise typer.Exit()


app = typer.Typer(
    add_completion=False,
    help="Snaffler Linux – Find credentials and sensitive data on Windows SMB shares",
)
app.add_typer(results_app, name="results")

# ---------------- DEFAULTS ----------------

MB = 1024 * 1024

# Scanning
DEFAULT_MIN_INTEREST = 0
DEFAULT_MAX_READ_BYTES = 2 * MB  # 2 MB
DEFAULT_MAX_FILE_BYTES = 10 * MB  # 10 MB
DEFAULT_MATCH_CONTEXT = 200  # bytes

# Network
DEFAULT_TIMEOUT_SECONDS = 5

# Threads
DEFAULT_MAX_THREADS = 60

# Output
DEFAULT_LOG_LEVEL = "info"
DEFAULT_LOG_TYPE = "plain"


def banner():
    typer.echo(r"""
   _____ _   _          ______ ______ _      ______ _____
  / ____| \ | |   /\   |  ____|  ____| |    |  ____|  __ \
 | (___ |  \| |  /  \  | |__  | |__  | |    | |__  | |__) |
  \___ \| . ` | / /\ \ |  __| |  __| | |    |  __| |  _  /
  ____) | |\  |/ ____ \| |    | |    | |____| |____| | \ \
 |_____/|_| \_/_/    \_\_|    |_|    |______|______|_|  \_\
                                                  Impacket Port
    """)


@app.callback(invoke_without_command=True)
def main(
        ctx: typer.Context,
        version: bool = typer.Option(
            False, "-V", "--version",
            help="Show version and exit",
            callback=_version_callback,
            is_eager=True,
        ),

        # ---------------- AUTH ----------------
        username: str = typer.Option(
            None, "-u", "--username",
            help="Username for authentication",
            rich_help_panel="Authentication",
        ),
        password: Optional[str] = typer.Option(
            None, "-p", "--password",
            help="Password for authentication (NTLM)",
            rich_help_panel="Authentication",
        ),
        nthash: Optional[str] = typer.Option(
            None, "--hash",
            help="NT hash for Pass-the-Hash authentication",
            rich_help_panel="Authentication",
        ),
        domain: Optional[str] = typer.Option(
            None, "-d", "--domain",
            help="AD domain for LDAP discovery, or Kerberos realm (e.g. CORP.LOCAL)",
            rich_help_panel="Targeting",
        ),
        kerberos: bool = typer.Option(
            False, "-k", "--kerberos",
            help="Use Kerberos authentication (requires -d and hostnames as targets)",
            rich_help_panel="Authentication",
        ),
        use_kcache: bool = typer.Option(
            False, "--use-kcache",
            help="Use Kerberos credentials from ccache (KRB5CCNAME)",
            rich_help_panel="Authentication",
        ),

        # ---------------- TARGETING ----------------
        unc_targets: Optional[List[str]] = typer.Option(
            None, "--unc",
            help="Direct UNC path(s) to scan (disables computer/share discovery)",
            rich_help_panel="Targeting",
        ),
        local: Optional[List[str]] = typer.Option(
            None, "--local-fs",
            help="Local directory path(s) to scan (no SMB, scans local filesystem)",
            rich_help_panel="Targeting",
        ),
        ftp: Optional[List[str]] = typer.Option(
            None, "--ftp",
            help="FTP target URL(s) to scan (e.g. ftp://10.0.0.5/data or bare 10.0.0.5)",
            rich_help_panel="Targeting",
        ),
        ftp_file: Optional[Path] = typer.Option(
            None, "--ftp-file",
            help="File containing FTP targets (one per line, same format as --ftp)",
            rich_help_panel="Targeting",
        ),
        ftp_tls: bool = typer.Option(
            False, "--ftp-tls",
            help="Use FTPS (FTP over TLS) for --ftp targets",
            rich_help_panel="Targeting",
        ),

        computer: Optional[List[str]] = typer.Option(
            None, "-c", "--computer",
            help="Target computer(s) by hostname, IP, CIDR (10.0.0.0/24), or range (10.0.0.1-50)",
            rich_help_panel="Targeting",
        ),

        computer_file: Optional[Path] = typer.Option(
            None, "--computer-file",
            help="File containing computer names (one per line)",
            rich_help_panel="Targeting",
        ),
        shares_only: bool = typer.Option(
            False, "-a", "--shares-only",
            help="Only enumerate shares, skip filesystem walking",
            rich_help_panel="Targeting",
        ),
        no_check_writable: bool = typer.Option(
            False, "--no-check-writable",
            help="Skip the per-share write-access probe (RW detection is on by default)",
            rich_help_panel="Targeting",
        ),
        check_writable: bool = typer.Option(
            False, "--check-writable",
            help="Force-enable the per-share write-access probe (overrides a config check_writable = false)",
            rich_help_panel="Targeting",
        ),
        rescan_unreadable: bool = typer.Option(
            False, "--rescan-unreadable",
            help="Re-test previously unreadable shares from state DB with current creds",
            rich_help_panel="Targeting",
        ),
        domain_users: bool = typer.Option(
            False, "--domain-users",
            help="Discover interesting AD users and match their names in file contents (requires -d)",
            rich_help_panel="Targeting",
        ),
        user_match: Optional[List[str]] = typer.Option(
            None, "--user-match",
            help="Keyword filter for interesting usernames (repeatable, default: sql,svc,service,...)",
            rich_help_panel="Targeting",
        ),
        user_min_len: int = typer.Option(
            6, "--user-min-len",
            help="Minimum username length for dynamic user rules",
            rich_help_panel="Targeting",
        ),
        grab: bool = typer.Option(
            False, "--grab",
            help="Bulk download mode: read file paths from stdin, download to -m dir (no scanning)",
            rich_help_panel="Targeting",
        ),
        include_disabled: bool = typer.Option(
            False,
            "--include-disabled",
            help="Include disabled and stale (4+ months inactive) computer accounts",
            rich_help_panel="Targeting",
        ),
        stdin_mode: bool = typer.Option(
            False,
            "--stdin",
            help="Read NXC SMB --shares output from stdin and use as UNC targets",
            rich_help_panel="Targeting",
        ),
        share: Optional[List[str]] = typer.Option(
            None,
            "--share",
            help="Only scan shares matching glob pattern (case-insensitive, repeatable)",
            rich_help_panel="Targeting",
        ),
        exclude_share: Optional[List[str]] = typer.Option(
            None,
            "--exclude-share",
            help="Skip shares matching glob pattern (case-insensitive, repeatable)",
            rich_help_panel="Targeting",
        ),
        exclude_unc: Optional[List[str]] = typer.Option(
            None,
            "--exclude-unc", "--exclude-path",
            help="Skip paths matching glob pattern (case-insensitive, repeatable). Works with both UNC and local paths.",
            rich_help_panel="Targeting",
        ),
        exclusions_file: Optional[Path] = typer.Option(
            None, "--exclusions",
            help="File of hostnames/IPs to skip (one per line)",
            rich_help_panel="Targeting",
        ),
        max_hosts: Optional[int] = typer.Option(
            None, "--max-hosts",
            help="Stop after scanning N hosts (applied after exclusions)",
            rich_help_panel="Targeting",
        ),

        # ---------------- NETWORK ----------------
        dc_host: Optional[str] = typer.Option(
            None,
            "--dc-host",
            help="Domain controller hostname, FQDN or IP (required for Kerberos LDAP)",
            rich_help_panel="Network",
        ),
        smb_timeout: int = typer.Option(
            DEFAULT_TIMEOUT_SECONDS,
            "--timeout",
            help=f"SMB connection timeout in seconds (default: {DEFAULT_TIMEOUT_SECONDS})",
            rich_help_panel="Network",
        ),
        socks_proxy: Optional[str] = typer.Option(
            None, "--socks",
            help="SOCKS proxy for pivoting (e.g. socks5://127.0.0.1:1080)",
            rich_help_panel="Network",
        ),
        nameserver: Optional[str] = typer.Option(
            None, "--nameserver", "--ns",
            help="Custom DNS server for hostname resolution (e.g. DC IP)",
            rich_help_panel="Network",
        ),

        # ---------------- OUTPUT ----------------
        output_file: Optional[Path] = typer.Option(
            None, "-o", "--output",
            help="Write results to file",
            rich_help_panel="Output",
        ),
        log_level: str = typer.Option(
            DEFAULT_LOG_LEVEL,
            "--log-level",
            help="Log verbosity: debug | info | data (data = findings only)",
            rich_help_panel="Output",
            click_type=click.Choice(
                ["debug", "info", "data"],
                case_sensitive=False,
            ),
        ),
        log_type: Optional[str] = typer.Option(
            None,
            "-t", "--log-type",
            help="Output format (auto-detected from -o extension if omitted)",
            rich_help_panel="Output",
            click_type=click.Choice(
                ["plain", "json", "tsv"],
                case_sensitive=False,
            ),
        ),
        no_banner: bool = typer.Option(
            False,
            "-q", "--no-banner",
            help="Disable startup banner",
            rich_help_panel="Output",
        ),
        no_color: bool = typer.Option(
            False,
            "--no-color",
            help="Disable colored output",
            rich_help_panel="Output",
        ),

        # ---------------- SCANNING ----------------
        min_interest: int = typer.Option(
            DEFAULT_MIN_INTEREST,
            "-b", "--min-interest",
            help="Minimum interest level to report (0=all, 3=high only)",
            rich_help_panel="Scanning",
            min=0,
            max=3,
        ),
         max_read_bytes: int = typer.Option(
             DEFAULT_MAX_READ_BYTES,
             "-r", "--max-read-bytes",
             help="Maximum bytes to read from a file for content scanning (default: 2 MB)",
             rich_help_panel="Scanning",
         ),
        max_file_bytes: int = typer.Option(
            DEFAULT_MAX_FILE_BYTES,
            "-l", "--max-file-bytes",
            help="Maximum file size allowed for scanning and downloading (default: 10 MB)",
            rich_help_panel="Scanning",
        ),

        snaffle_path: Optional[Path] = typer.Option(
            None, "-m", "--snaffle-path",
            help="Directory to copy interesting files into",
            rich_help_panel="Scanning",
        ),
        context: int = typer.Option(
            DEFAULT_MATCH_CONTEXT,
            "-j", "--context",
            help=f"Bytes of context around matched strings (default: {DEFAULT_MATCH_CONTEXT})",
            rich_help_panel="Scanning",
        ),
        max_depth: Optional[int] = typer.Option(
            None,
            "--max-depth",
            help="Maximum directory recursion depth (0 = share root only)",
            rich_help_panel="Scanning",
        ),
        fast: bool = typer.Option(
            False,
            "--fast",
            help="Skip known time-waster directories and interleave share walking",
            rich_help_panel="Scanning",
        ),
        match_filter: Optional[str] = typer.Option(
            None, "--match",
            help="Only output findings matching this regex (applied to path, rule, match, context)",
            rich_help_panel="Scanning",
        ),
        skip_binary: bool = typer.Option(
            False, "--skip-binary", "-I",
            help="Skip content scanning for native compiled binaries (ELF, PE, Mach-O) detected by magic bytes",
            rich_help_panel="Scanning",
        ),

        # ---------------- ADVANCED ----------------
        max_threads: int = typer.Option(
            DEFAULT_MAX_THREADS,
            "-x", "--max-threads",
            help=f"Maximum total worker threads (default: {DEFAULT_MAX_THREADS})",
            rich_help_panel="Advanced",
        ),
        dns_threads: int = typer.Option(
            100,
            "--dns-threads",
            help="Concurrent threads for DNS + port 445 reachability probes (default: 100)",
            rich_help_panel="Advanced",
        ),
        max_threads_per_share: int = typer.Option(
            0,
            "--max-threads-per-share",
            help="Max concurrent tree-walk threads per share (0 = unlimited, --fast auto-sets)",
            rich_help_panel="Advanced",
        ),
        config_file: Optional[Path] = typer.Option(
            None, "-z", "--config",
            help="Path to TOML configuration file",
            rich_help_panel="Advanced",
        ),
        rule_dir: Optional[Path] = typer.Option(
            None, "-R", "--rule-dir",
            help="Directory containing custom TOML rule files",
            rich_help_panel="Advanced",
        ),
        stealth: bool = typer.Option(
            False,
            "--stealth",
            help="OPSEC mode: pad LDAP queries with random attributes to break IDS signatures",
            rich_help_panel="Advanced",
        ),
        state: Optional[Path] = typer.Option(
            None,
            "--state",
            help="Path to state database (default: ./snaffler.db). Auto-resumes if DB exists.",
            rich_help_panel="Advanced",
        ),
        fresh: bool = typer.Option(
            False,
            "--fresh",
            help="Ignore existing state DB and start a clean scan",
            rich_help_panel="Advanced",
        ),

        # ---------------- WEB DASHBOARD ----------------
        web: bool = typer.Option(
            False,
            "--web",
            help="Enable live web dashboard (requires: pip install snaffler-ng[web])",
            rich_help_panel="Web Dashboard",
        ),
        web_port: int = typer.Option(
            8080,
            "--web-port",
            help="Port for web dashboard (default: 8080)",
            rich_help_panel="Web Dashboard",
        ),

):
    if ctx.invoked_subcommand is not None:
        return

    if not no_banner:
        banner()

    cfg = build_config(
        ctx,
        config_file=config_file,
        username=username, password=password, nthash=nthash,
        domain=domain, dc_host=dc_host, smb_timeout=smb_timeout,
        kerberos=kerberos, use_kcache=use_kcache,
        unc_targets=unc_targets, local=local, ftp=ftp, ftp_file=ftp_file, ftp_tls=ftp_tls,
        computer=computer, computer_file=computer_file,
        shares_only=shares_only, no_check_writable=no_check_writable,
        check_writable=check_writable, rescan_unreadable=rescan_unreadable,
        domain_users=domain_users, user_match=user_match, user_min_len=user_min_len,
        grab=grab, include_disabled=include_disabled, stdin_mode=stdin_mode,
        share=share, exclude_share=exclude_share, exclude_unc=exclude_unc,
        exclusions_file=exclusions_file, max_hosts=max_hosts,
        min_interest=min_interest, max_read_bytes=max_read_bytes,
        max_file_bytes=max_file_bytes, context=context, max_depth=max_depth,
        fast=fast, match_filter=match_filter, skip_binary=skip_binary,
        snaffle_path=snaffle_path,
        max_threads=max_threads, dns_threads=dns_threads,
        max_threads_per_share=max_threads_per_share,
        stealth=stealth, rule_dir=rule_dir,
        output_file=output_file, log_level=log_level, log_type=log_type, no_color=no_color,
        state=state, fresh=fresh,
        web=web, web_port=web_port,
        default_log_type=DEFAULT_LOG_TYPE,
    )

    if grab:
        run_grab(cfg)
        raise typer.Exit()

    run_scan(cfg, socks_proxy=socks_proxy, nameserver=nameserver)


if __name__ == "__main__":
    app()
