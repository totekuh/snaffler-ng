"""Common SMB test target abstraction and helpers."""

from dataclasses import dataclass
from unittest.mock import patch

from snaffler.engine.runner import SnafflerRunner


@dataclass
class SMBTarget:
    ip: str
    port: int
    share: str
    username: str = ""
    password: str = ""
    enforces_auth: bool = False

    @property
    def unc(self) -> str:
        return f"//{self.ip}/{self.share}"

    def unc_with_subpath(self, subpath: str) -> str:
        return f"//{self.ip}/{self.share}{subpath}"


no_auth_check = patch.object(SnafflerRunner, "_validate_credentials")


def make_cfg(target: SMBTarget, subpath: str = "", **overrides):
    from snaffler.classifiers.loader import RuleLoader
    from snaffler.config.configuration import SnafflerConfiguration

    unc = target.unc_with_subpath(subpath) if subpath else target.unc
    c = SnafflerConfiguration()
    c.targets.unc_targets = [unc]
    c.auth.username = target.username
    c.auth.password = target.password
    c.auth.smb_timeout = 10 if target.port != 445 else 30
    c.auth.smb_port = target.port
    c.scanning.max_read_bytes = 2 * 1024 * 1024
    c.scanning.max_file_bytes = 10 * 1024 * 1024
    c.scanning.match_context_bytes = 200
    c.scanning.min_interest = 0
    c.advanced.share_threads = 2
    c.advanced.tree_threads = 4
    c.advanced.file_threads = 4
    c.state.state_db = ":memory:"

    for key, value in overrides.items():
        parts = key.split("__")
        obj = c
        for part in parts[:-1]:
            obj = getattr(obj, part)
        setattr(obj, parts[-1], value)

    RuleLoader.load(c)
    return c


def run_scan(cfg):
    runner = SnafflerRunner(cfg)
    runner.execute()
    return runner, runner.progress
