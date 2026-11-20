#!/usr/bin/env python3
"""Build .deb, install in clean container, run e2e tests against installed package.

Usage:
    python tests/docker/run.py                     # base (smb_shared + integration)
    python tests/docker/run.py --ad                # + Samba AD DC
    python tests/docker/run.py --socks             # + SOCKS proxy
    python tests/docker/run.py --all               # all profiles
    python tests/docker/run.py --ad -- -k kerberos # pass pytest args after --
"""

import argparse
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
COMPOSE_FILE = REPO_ROOT / "tests" / "docker" / "docker-compose.yml"

SUITES = {
    "base": {
        "profiles": [],
        "runner": "testrunner",
    },
    "ad": {
        "profiles": ["ad"],
        "runner": "testrunner",
    },
    "socks": {
        "profiles": ["socks"],
        "runner": "socks-runner",
    },
}


def compose(*args: str) -> list[str]:
    return ["docker", "compose", "-f", str(COMPOSE_FILE), *args]


def run(cmd: list[str]) -> int:
    print(f"+ {' '.join(cmd)}", flush=True)
    return subprocess.call(cmd, cwd=REPO_ROOT)


def run_suite(name: str, pytest_args: list[str]) -> int:
    suite = SUITES[name]
    profile_flags: list[str] = []
    for p in suite["profiles"]:
        profile_flags.extend(["--profile", p])

    print(f"\n=== Building [{name}] ===", flush=True)
    rc = run(compose(*profile_flags, "build"))
    if rc != 0:
        return rc

    print(f"\n=== Running [{name}] via {suite['runner']} ===", flush=True)
    cmd = compose(*profile_flags, "run", "--rm", suite["runner"])
    if pytest_args:
        cmd.extend(["python3", "-m", "pytest", "-v", "--tb=short", *pytest_args])
    rc = run(cmd)

    print(f"\n=== Teardown [{name}] ===", flush=True)
    run(compose(*profile_flags, "down"))
    return rc


def main():
    parser = argparse.ArgumentParser(description="Run e2e tests against installed .deb")
    parser.add_argument("--ad", action="store_true", help="Include Samba AD DC")
    parser.add_argument("--socks", action="store_true", help="Include SOCKS proxy")
    parser.add_argument("--all", action="store_true", help="All suites")
    parser.add_argument("--no-base", action="store_true", help="Skip base suite")
    parser.add_argument("pytest_args", nargs="*", help="Extra pytest arguments (after --)")
    args = parser.parse_args()

    suites: list[str] = []
    if args.all:
        suites = ["base", "ad", "socks"]
    else:
        if not args.no_base and not args.socks:
            suites.append("base")
        if args.ad:
            if "base" in suites:
                suites.remove("base")
            suites.append("ad")
        if args.socks:
            suites.append("socks")

    if not suites:
        suites = ["base"]

    failed: list[str] = []
    for name in suites:
        rc = run_suite(name, args.pytest_args)
        if rc != 0:
            failed.append(name)

    if failed:
        print(f"\n!!! Failed suites: {', '.join(failed)} !!!", flush=True)
        return 1
    print(f"\n=== All {len(suites)} suite(s) passed ===", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
