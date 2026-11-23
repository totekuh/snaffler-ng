"""ScanState facade — delegates to store, adds bloom filter for fast dedup."""

import threading
from typing import Any, Iterator

from snaffler.utils.bloom import BloomFilter


class ScanState:
    def __init__(self, store: Any) -> None:
        self.store = store
        count: int = store.count_checked_files()
        self._bloom = BloomFilter(max(count * 2, 100_000))
        self._bloom_lock = threading.Lock()
        self._seed_bloom()

    def _seed_bloom(self) -> None:
        """Populate bloom filter from existing checked files in DB."""
        for path_lower in self.store.iter_checked_file_keys():
            self._bloom.add(path_lower)

    # ---------- phase flags ----------

    def is_phase_done(self, phase: str) -> bool:
        return self.store.get_sync_flag(phase)  # type: ignore[no-any-return]

    def mark_phase_done(self, phase: str) -> None:
        self.store.set_sync_flag(phase)

    def get_sync_value(self, key: str) -> str | None:
        return self.store.get_sync_value(key)  # type: ignore[no-any-return]

    def set_sync_value(self, key: str, value: str) -> None:
        self.store.set_sync_value(key, value)

    def clear_phase_flags(self) -> None:
        self.store.clear_phase_flags()

    # ---------- computers ----------

    def store_computers(self, computers: list[str]) -> None:
        self.store.store_computers([c.upper() for c in computers])

    def load_computers(self) -> list[str]:
        return self.store.load_computers()  # type: ignore[no-any-return]

    def set_computer_ip(self, name: str, ip: str) -> None:
        self.store.update_computer_ip(name.upper(), ip)

    def load_resolved_computers(self) -> list[tuple[str, str]]:
        return self.store.load_resolved_computers()  # type: ignore[no-any-return]

    def load_unresolved_computers(self) -> list[str]:
        return self.store.load_unresolved_computers()  # type: ignore[no-any-return]

    def should_skip_computer(self, name: str) -> bool:
        return self.store.has_checked_computer(name.upper())  # type: ignore[no-any-return]

    def mark_computer_done(self, name: str) -> None:
        self.store.mark_computer_checked(name.upper())

    # ---------- shares ----------

    def store_shares(self, shares: list[Any]) -> None:
        self.store.store_shares(shares)

    def load_shares(self) -> list[str]:
        return self.store.load_shares()  # type: ignore[no-any-return]

    def load_unreadable_shares(self) -> list[str]:
        return self.store.load_unreadable_shares()  # type: ignore[no-any-return]

    def update_share_readable(self, unc_path: str) -> None:
        self.store.update_share_readable(unc_path)

    def should_skip_share(self, unc_path: str) -> bool:
        return self.store.has_checked_share(unc_path)  # type: ignore[no-any-return]

    def mark_share_done(self, unc_path: str) -> None:
        self.store.mark_share_checked(unc_path)

    # ---------- files ----------

    def should_skip_file(self, unc_path: str) -> bool:
        path_lower = unc_path.lower()
        with self._bloom_lock:
            if path_lower not in self._bloom:
                return False
        return self.store.is_file_checked(path_lower)  # type: ignore[no-any-return]

    def mark_file_done(self, unc_path: str) -> None:
        """Mark file as checked in the bloom filter only.

        The DB write is batched by the caller (via ``_BatchWriter``) for
        dramatically lower SQLite contention under high thread counts.
        """
        path_lower = unc_path.lower()
        with self._bloom_lock:
            self._bloom.add(path_lower)

    # ---------- directories ----------

    def store_dir(self, unc_path: str, share: str) -> None:
        self.store.store_dir(unc_path, share)

    def store_dirs(self, dirs: list[tuple[str, str]]) -> None:
        self.store.store_dirs(dirs)

    def mark_dir_walked(self, unc_path: str) -> None:
        self.store.mark_dir_walked(unc_path)

    def load_unwalked_dirs(self, share: str | None = None) -> list[str]:
        return self.store.load_unwalked_dirs(share)  # type: ignore[no-any-return]

    def load_walked_dirs(self) -> list[str]:
        return self.store.load_walked_dirs()  # type: ignore[no-any-return]

    # ---------- files (batch) ----------

    def store_file(self, unc_path: str, share: str, size: int = 0, mtime: float = 0.0) -> None:
        self.store.store_file(unc_path, share, size, mtime)

    def store_files(self, files: list[tuple[str, str, int, float]]) -> None:
        self.store.store_files(files)

    def load_unchecked_files(self) -> list[tuple[str, int, float]]:
        return self.store.load_unchecked_files()  # type: ignore[no-any-return]

    def iter_unchecked_files(self) -> Iterator[tuple[str, int, float]]:
        """Yield unchecked files via the streaming generator."""
        return self.store.iter_unchecked_files()  # type: ignore[no-any-return]

    def count_target_files(self) -> int:
        return self.store.count_target_files()  # type: ignore[no-any-return]

    # ---------- findings ----------

    def store_finding(self, **kwargs: Any) -> None:
        self.store.store_finding(**kwargs)

    def load_findings(self) -> list[Any]:
        return self.store.load_findings()  # type: ignore[no-any-return]

    def count_findings(self) -> int:
        return self.store.count_findings()  # type: ignore[no-any-return]

    def count_findings_by_triage(self) -> dict[str, int]:
        return self.store.count_findings_by_triage()  # type: ignore[no-any-return]

    # ---------- counts (for progress) ----------

    def count_checked_computers(self) -> int:
        return self.store.count_checked_computers()  # type: ignore[no-any-return]

    def count_checked_shares(self) -> int:
        return self.store.count_checked_shares()  # type: ignore[no-any-return]

    def count_checked_files(self) -> int:
        return self.store.count_checked_files()  # type: ignore[no-any-return]

    def close(self) -> None:
        self.store.close()
