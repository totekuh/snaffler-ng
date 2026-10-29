"""Post-config scan execution: logging, rules, proxies, runner."""

import logging
from typing import Optional

import typer

from snaffler.config.configuration import SnafflerConfiguration

logger = logging.getLogger("snaffler")


def run_scan(
    cfg: SnafflerConfiguration,
    *,
    socks_proxy: Optional[str] = None,
    nameserver: Optional[str] = None,
):
    import snaffler.cli.main as _cli
    setup_logging = _cli.setup_logging
    RuleLoader = _cli.RuleLoader
    SnafflerRunner = _cli.SnafflerRunner

    setup_logging(
        log_level=cfg.output.log_level,
        log_to_file=cfg.output.to_file,
        log_file_path=cfg.output.output_file,
        log_to_console=True,
        log_type=cfg.output.log_type,
    )

    try:
        RuleLoader.load(cfg)
    except RuntimeError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1)

    # SOCKS must be set up before custom DNS
    if socks_proxy:
        cfg.auth.socks_proxy = socks_proxy
        try:
            from snaffler.transport.socks import setup_socks_proxy
            setup_socks_proxy(socks_proxy)
        except (ImportError, ValueError) as exc:
            raise typer.BadParameter(str(exc))

    if nameserver:
        try:
            from snaffler.transport.dns import setup_custom_dns
            setup_custom_dns(nameserver)
        except (ImportError, ValueError) as exc:
            raise typer.BadParameter(str(exc))

    if cfg.targets.domain_users:
        if not cfg.auth.domain:
            typer.echo(
                "Warning: --domain-users requires -d/--domain, ignoring",
                err=True,
            )
            cfg.targets.domain_users = False
        else:
            try:
                from snaffler.discovery.ad import ADDiscovery
                from snaffler.classifiers.loader import build_domain_user_rule

                logger.info("Discovering interesting domain users for content rules...")
                ad = ADDiscovery(cfg)
                users = ad.get_domain_users(
                    match_strings=cfg.targets.user_match_strings or None,
                    min_len=cfg.targets.user_min_len,
                )
                if users:
                    rule = build_domain_user_rule(users, domain=cfg.auth.domain)
                    cfg.rules.content.append(rule)
                    logger.info(
                        f"Added DynamicDomainUsers rule matching {len(users)} users"
                    )
                else:
                    logger.warning(
                        "No interesting domain users found, skipping dynamic rule"
                    )
            except Exception as e:
                logger.warning(f"Domain user discovery failed, continuing without: {e}")

    try:
        snaff = SnafflerRunner(cfg)
        snaff.execute()
    except KeyboardInterrupt:
        raise typer.Exit(code=130)
    except (ValueError, RuntimeError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1)
    except OSError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1)
    except SystemExit:
        raise
