"""ScanState facade — delegates to store, adds bloom filter for fast dedup."""

import threading

from snaffler.utils.bloom import BloomFilter


class ScanState:
    def __init__(self, store):
        self.store = store
        count = store.count_checked_files()
        self._bloom = BloomFilter(max(count * 2, 100_000))
        self._bloom_lock = threading.Lock()
        self._seed_bloom()

    def _seed_bloom(self):
        """Populate bloom filter from existing checked files in DB."""
        for path_lower in self.store.iter_checked_file_keys():
            self._bloom.add(path_lower)

    # ---------- phase flags ----------

    def is_phase_done(self, phase: str) -> bool:
        return self.store.get_sync_flag(phase)

    def mark_phase_done(self, phase: str):
        self.store.set_sync_flag(phase)

    def get_sync_value(self, key: str) -> str | None:
        return self.store.get_sync_value(key)

    def set_sync_value(self, key: str, value: str):
        self.store.set_sync_value(key, value)

    def clear_phase_flags(self):
        self.store.clear_phase_flags()

    # ---------- computers ----------

    def store_computers(self, computers: list):
        self.store.store_computers([c.upper() for c in computers])

    def load_computers(self) -> list:
        return self.store.load_computers()

    def set_computer_ip(self, name: str, ip: str):
        self.store.update_computer_ip(name.upper(), ip)

    def load_resolved_computers(self) -> list:
        return self.store.load_resolved_computers()

    def load_unresolved_computers(self) -> list:
        return self.store.load_unresolved_computers()

    def should_skip_computer(self, name: str) -> bool:
        return self.store.has_checked_computer(name.upper())

    def mark_computer_done(self, name: str):
        self.store.mark_computer_checked(name.upper())

    # ---------- shares ----------

    def store_shares(self, shares: list):
        self.store.store_shares(shares)

    def load_shares(self) -> list:
        return self.store.load_shares()

    def load_unreadable_shares(self) -> list:
        return self.store.load_unreadable_shares()

    def update_share_readable(self, unc_path: str):
        self.store.update_share_readable(unc_path)

    def should_skip_share(self, unc_path: str) -> bool:
        return self.store.has_checked_share(unc_path)

    def mark_share_done(self, unc_path: str):
        self.store.mark_share_checked(unc_path)

    # ---------- files ----------

    def should_skip_file(self, unc_path: str) -> bool:
        path_lower = unc_path.lower()
        with self._bloom_lock:
            if path_lower not in self._bloom:
                return False
        return self.store.is_file_checked(path_lower)

    def mark_file_done(self, unc_path: str):
        """Mark file as checked in the bloom filter only.

        The DB write is batched by the caller (via ``_BatchWriter``) for
        dramatically lower SQLite contention under high thread counts.
        """
        path_lower = unc_path.lower()
        with self._bloom_lock:
            self._bloom.add(path_lower)

    # ---------- directories ----------

    def store_dir(self, unc_path: str, share: str):
        self.store.store_dir(unc_path, share)

    def store_dirs(self, dirs: list):
        self.store.store_dirs(dirs)

    def mark_dir_walked(self, unc_path: str):
        self.store.mark_dir_walked(unc_path)

    def load_unwalked_dirs(self, share: str | None = None) -> list:
        return self.store.load_unwalked_dirs(share)

    def load_walked_dirs(self) -> list:
        return self.store.load_walked_dirs()

    # ---------- files (batch) ----------

    def store_file(self, unc_path: str, share: str, size: int = 0, mtime: float = 0.0):
        self.store.store_file(unc_path, share, size, mtime)

    def store_files(self, files: list):
        self.store.store_files(files)

    def load_unchecked_files(self) -> list:
        return self.store.load_unchecked_files()

    def iter_unchecked_files(self):
        """Yield unchecked files via the streaming generator."""
        return self.store.iter_unchecked_files()

    def count_target_files(self) -> int:
        return self.store.count_target_files()

    # ---------- findings ----------

    def store_finding(self, **kwargs):
        self.store.store_finding(**kwargs)

    def load_findings(self):
        return self.store.load_findings()

    def count_findings(self) -> int:
        return self.store.count_findings()

    def count_findings_by_triage(self) -> dict:
        return self.store.count_findings_by_triage()

    # ---------- counts (for progress) ----------

    def count_checked_computers(self) -> int:
        return self.store.count_checked_computers()

    def count_checked_shares(self) -> int:
        return self.store.count_checked_shares()

    def count_checked_files(self) -> int:
        return self.store.count_checked_files()

    def close(self):
        self.store.close()
