"""Discovery and rescan mixins for SnafflerRunner."""

import logging
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

from snaffler.utils.fatal import check_fatal_os_error
from snaffler.utils.path_utils import extract_unc_host, extract_unc_share_name

logger = logging.getLogger('snaffler')

_PHASE_COMPUTERS = "computer_discovery_done"
_PHASE_DNS = "dns_resolution_done"
_PHASE_SHARES = "share_discovery_done"
_PORT_CHECK_TIMEOUT = 3


class DiscoveryMixin:

    def _resume_computer_discovery(self, domain_pipeline) -> List[str]:
        """Discover or load computers, persisting to state on first run."""
        if self.state and self.state.is_phase_done(_PHASE_COMPUTERS):
            computers = self.state.load_computers()
            logger.info(f"Resume: loaded {len(computers)} computers from state")
            return computers

        computers = domain_pipeline.run()

        if self.state:
            if computers:
                self.state.store_computers(computers)
            # Only mark phase complete if LDAP finished without error.
            # On partial failure, leave unset so resume re-queries.
            if domain_pipeline.ad.discovery_complete:
                self.state.mark_phase_done(_PHASE_COMPUTERS)
            logger.info(f"Stored {len(computers)} computers in resume state")

        return computers

    def _resolve_computers(self, computers: List[str]) -> List[str]:
        """DNS pre-resolution: filter out hosts with no A record."""
        if not computers:
            return []

        # Resume: DNS phase already complete → load from state
        if self.state and self.state.is_phase_done(_PHASE_DNS):
            resolved = self.state.load_resolved_computers()
            self.progress.dns_total = len(computers)
            self.progress.dns_resolved = len(resolved)
            self.progress.dns_filtered = len(computers) - len(resolved)
            logger.info(
                f"Resume: loaded {len(resolved)} DNS-resolved computers from state"
            )
            return resolved

        # Ensure computers are in state DB (needed for --computer mode
        # where _resume_computer_discovery is not called)
        if self.state:
            self.state.store_computers(computers)
            to_resolve = self.state.load_unresolved_computers()
            already_resolved = self.state.load_resolved_computers()
        else:
            to_resolve = list(computers)
            already_resolved = []

        self.progress.dns_total = len(computers)
        self.progress.dns_resolved = len(already_resolved)
        self.progress.dns_start = time.monotonic()

        dns_timeout = self.cfg.auth.smb_timeout
        smb_port = self.cfg.auth.smb_port

        def resolve_one(hostname: str):
            try:
                result = socket.getaddrinfo(
                    hostname, smb_port, socket.AF_INET, socket.SOCK_STREAM,
                )
                ip = result[0][4][0]
            except (socket.gaierror, socket.herror, socket.timeout, OSError):
                logger.debug(f"DNS: no record for {hostname}, skipping")
                return None

            # Quick TCP probe — verify port is actually reachable
            try:
                with socket.create_connection(
                    (ip, smb_port), timeout=_PORT_CHECK_TIMEOUT,
                ):
                    pass
            except (OSError, socket.timeout):
                logger.debug(
                    f"DNS: {hostname} ({ip}) port {smb_port} unreachable, skipping"
                )
                return None

            return ip

        resolved = list(already_resolved)
        interrupted = False
        t0 = time.monotonic()

        with ThreadPoolExecutor(
            max_workers=self.cfg.advanced.dns_threads,
        ) as pool:
            futures = {
                pool.submit(resolve_one, h): h for h in to_resolve
            }
            try:
                for future in as_completed(futures):
                    hostname = futures[future]
                    try:
                        ip = future.result()
                    except Exception as e:
                        check_fatal_os_error(e)
                        ip = None
                        logger.info(f"DNS: probe failed for {hostname}")
                    if ip is not None:
                        resolved.append(hostname)
                        self.progress.dns_resolved += 1
                        if self.state:
                            self.state.set_computer_ip(hostname, ip)
                    else:
                        self.progress.dns_filtered += 1
            except KeyboardInterrupt:
                pool.shutdown(wait=False, cancel_futures=True)
                interrupted = True

        elapsed = time.monotonic() - t0
        filtered = len(computers) - len(resolved)
        logger.info(
            f"DNS pre-resolution: {len(resolved)}/{len(computers)} hosts resolved, "
            f"{filtered} filtered ({elapsed:.1f}s)"
        )

        # Only mark phase complete if all hosts were processed.
        # On interrupt, leave it unset so unresolved hosts get retried on resume.
        if self.state and not interrupted:
            self.state.mark_phase_done(_PHASE_DNS)

        if not resolved:
            logger.warning("DNS pre-resolution: no hosts resolved, share discovery will be skipped")

        if interrupted:
            raise KeyboardInterrupt

        return resolved

    def _resume_share_discovery(self, computers: List[str]) -> List[str]:
        """Discover or load shares, skipping already-checked computers."""
        if self.progress:
            self.progress.computers_total = len(computers)

        if self.state and self.state.is_phase_done(_PHASE_SHARES):
            shares = self.state.load_shares()
            shares = self._filter_paths_by_share(shares)
            if self.progress:
                self.progress.computers_done = len(computers)
                self.progress.shares_found = len(shares)
            logger.info(f"Resume: loaded {len(shares)} shares from state")
            if self.cfg.targets.shares_only:
                return []
            return shares

        # Filter out computers already enumerated in a previous run
        if self.state:
            remaining = [
                c for c in computers
                if not self.state.should_skip_computer(c)
            ]
            skipped = len(computers) - len(remaining)
            if skipped:
                logger.info(
                    f"Resume: skipped {skipped} already-enumerated computers"
                )
                if self.progress:
                    self.progress.computers_done = skipped
        else:
            remaining = computers

        # Pre-seed shares_found from state so the display is correct during
        # the entire resumed share phase (not just after run() completes).
        if self.state:
            existing_shares = self.state.load_shares()
            self.progress.shares_found = len(existing_shares)

        # Snapshot how many computers were already done before this run's
        # share discovery starts, so _shares_eta() only measures the current
        # session's throughput (avoids inflated ETA on resume).
        self.progress._shares_done_baseline = self.progress.computers_done

        new_shares = self.share_pipeline.run(remaining) if remaining else []

        if self.state:
            # Ensure pipeline return is persisted (idempotent — SharePipeline
            # stores incrementally, this catches any that slipped through).
            if new_shares:
                self.state.store_shares(new_shares)
            # Set phase flag and load ALL shares (old + new).
            self.state.mark_phase_done(_PHASE_SHARES)
            shares = self.state.load_shares()
            shares = self._filter_paths_by_share(shares)
            if self.progress:
                self.progress.shares_found = len(shares)
            logger.info(
                f"Share discovery complete: {len(shares)} total shares in state"
            )
            if self.cfg.targets.shares_only:
                return []
            return shares

        return self._filter_paths_by_share(new_shares)

    def _rescan_unreadable(self):
        """Re-test previously unreadable shares with current creds."""
        unreadable = self.state.load_unreadable_shares()

        # Apply --share / --exclude-share filters
        unreadable = self._filter_paths_by_share(unreadable)

        # Apply --exclusions host filter
        unreadable = self._filter_paths_by_exclusions(unreadable)

        if not unreadable:
            logger.warning("No unreadable shares in state DB — nothing to rescan")
            return

        logger.info(f"Rescan: testing {len(unreadable)} previously unreadable shares")

        from snaffler.discovery.shares import ShareFinder
        finder = ShareFinder(self.cfg)

        newly_readable = []
        errors = 0

        def _test_one(unc_path: str):
            computer = extract_unc_host(unc_path)
            share_name = extract_unc_share_name(unc_path)
            if computer is None or share_name is None:
                return None
            readable = finder.is_share_readable(computer, share_name)
            return readable

        try:
            with ThreadPoolExecutor(
                max_workers=self.cfg.advanced.share_threads or 2,
            ) as pool:
                futures = {pool.submit(_test_one, p): p for p in unreadable}
                try:
                    for future in as_completed(futures):
                        unc_path = futures[future]
                        try:
                            result = future.result()
                        except Exception as e:
                            check_fatal_os_error(e)
                            logger.debug(f"Rescan error for {unc_path}: {e}")
                            errors += 1
                            continue
                        if result is None:
                            # Malformed path
                            continue
                        if result:
                            logger.info(f"[NEW] Readable: {unc_path}")
                            self.state.update_share_readable(unc_path)
                            newly_readable.append(unc_path)
                        else:
                            logger.debug(f"Still unreadable: {unc_path}")
                except KeyboardInterrupt:
                    pool.shutdown(wait=False, cancel_futures=True)
                    raise
        finally:
            # Close all cached connections from rescan's ShareFinder
            try:
                finder.close()
            except Exception:
                pass

        still_denied = len(unreadable) - len(newly_readable) - errors
        msg = f"Rescan: {len(newly_readable)} newly readable, {still_denied} still denied"
        if errors:
            msg += f", {errors} errors"
        logger.info(msg)

        if newly_readable:
            self.progress.shares_found = len(newly_readable)
            self._run_file_pipeline(newly_readable)
