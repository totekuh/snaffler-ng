"""Credential validation mixin for SnafflerRunner."""

import logging

from snaffler.utils.path_utils import extract_unc_host

logger = logging.getLogger('snaffler')


class AuthMixin:

    def _validate_credentials(self):
        """Preflight auth check — try a single login before starting the scan.

        Hard-fails with a clear error if credentials are invalid so we don't
        silently scan thousands of hosts with bad creds and come back empty.

        Skipped for --local-fs (no auth) and domain mode (LDAP connect
        validates creds as its first operation).
        """
        cfg = self.cfg

        # Local mode — no auth needed
        if cfg.targets.local_targets:
            return

        # Domain mode — LDAP connect is the first thing that happens,
        # it already raises on bad creds with a clear error.
        if (not cfg.targets.unc_targets
                and not cfg.targets.computer_targets
                and not cfg.targets.rescan_unreadable
                and not cfg.targets.ftp_targets
                and cfg.auth.domain):
            return

        # FTP mode — test FTP login
        if cfg.targets.ftp_targets:
            from snaffler.discovery.ftp_tree_walker import parse_ftp_url
            from snaffler.transport.ftp import FTPTransport

            target = cfg.targets.ftp_targets[0]
            parsed = parse_ftp_url(target)
            if not parsed:
                return
            host, port, _ = parsed
            transport = FTPTransport(cfg)
            try:
                ftp = transport.connect(host, port)
                try:
                    ftp.quit()
                except Exception:
                    pass
                logger.info(f"Auth OK: FTP login to {host}:{port} succeeded")
            except OSError as e:
                raise SystemExit(
                    f"FATAL: cannot reach FTP server {host}:{port} — {e}\n"
                    f"Check network connectivity and retry."
                ) from e
            except Exception as e:
                raise SystemExit(
                    f"FATAL: FTP authentication failed against {host}:{port} — {e}\n"
                    f"Fix credentials and retry."
                ) from e
            return

        # SMB modes — pick the first available target
        target = None
        if cfg.targets.rescan_unreadable and self.state:
            unreadable = self.state.load_unreadable_shares()
            if unreadable:
                target = extract_unc_host(unreadable[0])
        elif cfg.targets.unc_targets:
            for p in cfg.targets.unc_targets:
                host = extract_unc_host(p)
                if host is not None:
                    target = host
                    break
        elif cfg.targets.computer_targets:
            target = cfg.targets.computer_targets[0]

        if not target:
            return

        from snaffler.transport.smb import SMBTransport

        transport = SMBTransport(cfg)
        try:
            smb = transport.connect(target)
            try:
                smb.close()
            except Exception:
                pass
            logger.info(f"Auth OK: SMB login to {target} succeeded")
        except OSError as e:
            raise SystemExit(
                f"FATAL: cannot reach SMB target {target}:{cfg.auth.smb_port} — {e}\n"
                f"Check network connectivity and retry."
            ) from e
        except Exception as e:
            raise SystemExit(
                f"FATAL: SMB authentication failed against {target} — {e}\n"
                f"Fix credentials and retry."
            ) from e
