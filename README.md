# snaffler-ng

[![Kali Linux](https://img.shields.io/badge/Kali%20Linux-official-557C94?logo=kalilinux)](https://www.kali.org/tools/snaffler-ng/)
[![PyPI](https://img.shields.io/pypi/v/snaffler-ng)](https://pypi.org/project/snaffler-ng/)
[![License](https://img.shields.io/github/license/totekuh/snaffler-ng)](LICENSE)

Impacket port of [Snaffler](https://github.com/SnaffCon/Snaffler).

**snaffler-ng** is a post-exploitation tool that discovers readable SMB shares, walks directory trees, and identifies credentials and sensitive data on Windows networks.

Unlike the original C# Snaffler which is limited to Windows SMB with NTLM, snaffler-ng adds Kerberos authentication, FTP server scanning, local filesystem scanning using the same rule engine, and Python C2 integration bindings.

## Install

```bash
# Kali Linux
sudo apt install snaffler-ng

# pip / pipx
pip install snaffler-ng
pipx install snaffler-ng
```

Pre-built binaries (no Python required) are available on the [Releases](https://github.com/totekuh/snaffler-ng/releases) page for Linux x86_64, Linux aarch64, and Windows x86_64.

Optional extras:

```bash
pip install snaffler-ng[socks]      # SOCKS proxy support
pip install snaffler-ng[web]        # live web dashboard
pip install snaffler-ng[7z,rar]     # 7z/RAR archive peeking
```

## Quick Start

```bash
# Full domain discovery
snaffler -u USER -p PASS -d DOMAIN.LOCAL

# Kerberos with ccache
snaffler -k --use-kcache -d DOMAIN.LOCAL --dc-host CORP-DC02

# Scan specific UNC paths
snaffler -u USER -p PASS --unc //10.0.0.5/Share --unc //10.0.0.6/Data

# Local filesystem (no auth needed)
snaffler --local-fs /mnt/share

# FTP server (anonymous)
snaffler --ftp ftp://10.0.0.5

# Pipe from NetExec
nxc smb 10.0.0.0/24 -u user -p pass --shares | snaffler -u user -p pass --stdin

# Fast mode — skip time-waster directories, interleave share walking
snaffler -u USER -p PASS -d DOMAIN.LOCAL --fast
```

![snaffler-ng run](https://github.com/user-attachments/assets/4cd12508-88f3-4724-9a1e-6c5991cddafa)

## Documentation

| Guide | Description |
|-------|-------------|
| [Targeting Modes](docs/targeting.md) | Domain discovery, UNC paths, FTP, local filesystem, NetExec pipe, rescan, bulk download |
| [Filtering](docs/filtering.md) | Share/path exclusions, depth limits, severity levels, regex post-filter |
| [Output](docs/output.md) | Formats (plain/JSON/TSV), resume, results query, export/import, web dashboard, archive peeking |
| [Authentication & Network](docs/authentication.md) | NTLM, Kerberos, pass-the-hash, SOCKS proxy, custom DNS, stealth mode |
| [Performance](docs/performance.md) | Fast mode, thread tuning, scanning limits |
| [Library API](docs/library-api.md) | Python API, C2 integration, two-phase classification, custom transports |
| [Custom Rules](docs/custom-rules.md) | TOML rule format for extending the built-in 106-rule set |

## Library API

```python
from snaffler import Snaffler, FileCheckStatus

s = Snaffler()
check = s.check_file(path, size=4096, mtime_epoch=1700000000.0)

if check.status == FileCheckStatus.NEEDS_CONTENT:
    result = s.scan_content(file_bytes, prior=check)
elif check.status == FileCheckStatus.MATCHED:
    result = check.result  # matched on filename alone
```

See [Library API docs](docs/library-api.md) for walk examples, custom transports, and constructor parameters.

## License

Apache-2.0
