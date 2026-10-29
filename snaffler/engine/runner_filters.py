"""Filter and progress mixins for SnafflerRunner."""

import logging
from typing import List

from snaffler.discovery.shares import share_matches_filter
from snaffler.utils.path_utils import extract_unc_host, extract_unc_share_name

logger = logging.getLogger('snaffler')


class FilterMixin:

    def _sync_progress_from_state(self):
        """Refresh progress counters from resume database."""
        if not self.state:
            return
        try:
            p = self.progress
            p.computers_done = max(
                p.computers_done, self.state.count_checked_computers()
            )
            p.shares_walked = max(
                p.shares_walked, self.state.count_checked_shares()
            )
            p.files_scanned = max(
                p.files_scanned, self.state.count_checked_files()
            )
            # shares_found is set by _resume_share_discovery (filtered);
            # don't overwrite with unfiltered DB count.
            # Ensure totals are never less than done counts
            p.files_total = max(p.files_total, p.files_scanned)
            p.shares_total = max(p.shares_total, p.shares_walked)

            # Restore finding counts from DB (critical for resume)
            by_triage = self.state.count_findings_by_triage()
            total = 0
            for label, count in by_triage.items():
                total += count
                low = label.lower()
                if low == "black":
                    p.severity_black = max(p.severity_black, count)
                elif low == "red":
                    p.severity_red = max(p.severity_red, count)
                elif low == "yellow":
                    p.severity_yellow = max(p.severity_yellow, count)
                elif low == "green":
                    p.severity_green = max(p.severity_green, count)
            p.files_matched = max(p.files_matched, total)
        except Exception as e:
            logger.debug(f"Failed to sync progress from state DB: {e}")

    def _rebalance_file_threads(self):
        """Give the share thread budget to file scanning (shares are done)."""
        bonus = self.cfg.advanced.share_threads
        half = bonus // 2
        self.file_pipeline.tree_threads += half
        self.file_pipeline.file_threads += bonus - half
        logger.info(
            f"Thread rebalance: +{bonus} share threads → "
            f"tree={self.file_pipeline.tree_threads}, "
            f"file={self.file_pipeline.file_threads}"
        )

    def _filter_paths_by_share(self, paths: List[str]) -> List[str]:
        """Apply --share / --exclude-share filters to a list of UNC paths."""
        include = self.cfg.targets.share_filter
        exclude = self.cfg.targets.exclude_share
        if not include and not exclude:
            return paths

        filtered = []
        for p in paths:
            share_name = extract_unc_share_name(p)
            if share_name is None:
                filtered.append(p)
                continue
            if share_matches_filter(share_name, include, exclude):
                filtered.append(p)
            else:
                logger.debug(f"Skipping UNC path {p} (excluded by share filter)")
        return filtered

    def _cap_hosts(self, computers: List[str]) -> List[str]:
        """Limit computer list to --max-hosts if set."""
        limit = self.cfg.targets.max_hosts
        if isinstance(limit, int) and len(computers) > limit:
            logger.info(f"--max-hosts {limit}: capped from {len(computers)} to {limit} hosts")
            return computers[:limit]
        return computers

    def _apply_exclusions(self, computers: List[str]) -> List[str]:
        """Remove computers matching the --exclusions list."""
        if not self._exclusion_set:
            return computers
        before = len(computers)
        filtered = [c for c in computers if c.upper() not in self._exclusion_set]
        diff = before - len(filtered)
        if diff:
            logger.info(f"Excluded {diff} computer(s) via --exclusions")
        return filtered

    def _filter_paths_by_exclusions(self, paths: List[str]) -> List[str]:
        """Remove UNC paths whose hostname matches the --exclusions list."""
        if not self._exclusion_set:
            return paths
        filtered = []
        for p in paths:
            host = extract_unc_host(p)
            if host is None:
                filtered.append(p)
                continue
            if host.upper() not in self._exclusion_set:
                filtered.append(p)
        diff = len(paths) - len(filtered)
        if diff:
            logger.info(f"Excluded {diff} UNC path(s) via --exclusions")
        return filtered
