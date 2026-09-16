# Library API

snaffler-ng works as a Python library for C2 integration and custom tooling.

## Walk a directory

```python
from snaffler import Snaffler

for finding in Snaffler().walk("/mnt/share"):
    print(f"[{finding.triage.label}] {finding.file_path}")
    if finding.match:
        print(f"  matched: {finding.match}")
```

## Two-phase classification (C2 integration)

Minimize beacon traffic -- most files are skipped at phase 1 (metadata-only, zero I/O):

```python
from snaffler import Snaffler, FileCheckStatus

s = Snaffler()

# Phase 1: metadata only — instant, no file read
check = s.check_file(path, size=4096, mtime_epoch=1700000000.0)

if check.status == FileCheckStatus.NEEDS_CONTENT:
    # Phase 2: only download + classify when needed
    result = s.scan_content(file_bytes, prior=check)
elif check.status == FileCheckStatus.MATCHED:
    result = check.result  # matched on filename alone (e.g. ntds.dit)
```

## Custom transport (duck-typed)

Plug in any transport -- no ABC required, just implement `walk_directory` and `read`:

```python
class BeaconWalker:
    def walk_directory(self, path, on_file=None, on_dir=None, cancel=None):
        for entry in beacon.ls(path):
            if entry.is_dir:
                if on_dir: on_dir(entry.path)
            elif on_file:
                on_file(entry.path, entry.size, entry.mtime)
        return [e.path for e in beacon.ls(path) if e.is_dir]

class BeaconReader:
    def read(self, path, max_bytes=None):
        return beacon.download(path, max_bytes)

s = Snaffler(walker=BeaconWalker(), reader=BeaconReader())
for finding in s.walk("C:\\Users"):
    beacon.report(finding.file_path, finding.triage.label)
```

## Constructor parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `walker` | `LocalTreeWalker()` | Directory listing provider |
| `reader` | `LocalFileAccessor()` | File content reader |
| `rule_dir` | `None` | Custom TOML rules directory |
| `min_interest` | `0` | Minimum severity (0=all, 3=Black only) |
| `max_read_bytes` | `2MB` | Content scan byte limit |
| `match_context_bytes` | `200` | Context bytes around regex matches |
| `cert_passwords` | built-in list | Passwords to try on PKCS12 certs |
| `exclude_unc` | `None` | Glob patterns to skip directories |
| `match_filter` | `None` | Regex post-filter on findings |
| `max_depth` | `None` | Maximum directory recursion depth |
