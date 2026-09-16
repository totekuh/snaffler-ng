# Output

## Formats

Three output formats: **plain** (default), **JSON**, **TSV**. Auto-detected from `-o` file extension.

Log verbosity: `--log-level debug|info|data` (data = findings only). Disable banner with `--no-banner` / `-q`.

```bash
snaffler ... -o findings.json    # JSON
snaffler ... -o findings.tsv     # TSV
snaffler ... -o findings.txt     # plain
snaffler ... -o out.log -t json  # explicit override
```

## Resume

Scan state is tracked in SQLite (`snaffler.db`). Scans auto-resume when the DB exists:

```bash
snaffler -u USER -p PASS -d DOMAIN.LOCAL              # creates snaffler.db
# interrupted? re-run the same command — picks up where it left off
snaffler -u USER -p PASS -d DOMAIN.LOCAL              # resumes

snaffler ... --state /tmp/scan1.db                     # custom DB path
snaffler ... --fresh                                   # ignore existing state
```

Progressive deepening works across resumes: directories beyond `--max-depth` are stored but not walked. Re-running with a higher depth walks them automatically, skipping already-scanned files.

## Querying Results

```bash
snaffler results                              # plain text summary
snaffler results -f json                      # JSON
snaffler results -f html > report.html        # self-contained HTML report
snaffler results -b 2                         # Red+ severity only
snaffler results -r RuleName                  # filter by rule name
snaffler results -s /path/to/snaffler.db      # custom DB path
snaffler results --files                      # one file path per line (pipe into --grab)
```

The HTML report includes resizable columns, host filtering, inline severity/rule dropdowns, and a connect command copy button.

## Rule Stats

See which rules matched and how many findings each produced:

```bash
snaffler results rules              # plain text
snaffler results rules -f json      # JSON
```

## Export & Import

Share results with teammates or merge findings from parallel scans:

```bash
# Export — portable DB or JSON
snaffler results export scan-results.db
snaffler results export findings.json

# Import — merge into your local state DB
snaffler results import teammate-scan.db
snaffler results import findings.json

# Export from a specific state DB
snaffler results export -s /path/to/scan.db report.json

# Import into a specific state DB
snaffler results import -s /path/to/combined.db other-scan.db
```

Format is auto-detected from the file extension (`.db` or `.json`), or override with `-f`.

## Web Dashboard

Live browser dashboard for monitoring scan progress and findings:

```bash
snaffler ... --web --web-port 8080
```

Requires `pip install snaffler-ng[web]`.

## Archive Peeking

Scans filenames inside ZIP, 7z, and RAR archives without extraction:

```bash
pip install snaffler-ng[7z,rar]   # ZIP works out of the box
```
