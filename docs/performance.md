# Performance

## Fast Mode (`--fast`)

Skips 30 known time-waster directories (Windows internals, package caches, VCS metadata, build artifacts) and enables fair-share thread scheduling so one deep share cannot monopolize all workers:

```bash
snaffler -u USER -p PASS -d DOMAIN.LOCAL --fast
```

Sensitive paths like `Windows\Panther` (contains `unattend.xml` with credentials) are deliberately not excluded.

## Thread Tuning

```bash
snaffler ... --max-threads 90           # total worker threads (default: 60)
snaffler ... --dns-threads 200          # DNS + port probe threads (default: 100)
snaffler ... --max-threads-per-share 5  # cap tree-walk threads per share (--fast auto-sets)
```

Threads are split equally across share discovery, tree walking, and file scanning. After share discovery completes, idle threads are rebalanced to file scanning.

## Scanning Limits

```bash
snaffler ... --max-read-bytes 4194304    # max bytes to read per file (default: 2 MB)
snaffler ... --max-file-bytes 20971520   # max file size for scanning/download (default: 10 MB)
snaffler ... --context 500               # bytes of context around matches (default: 200)
```
