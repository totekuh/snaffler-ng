# Targeting Modes

snaffler-ng supports multiple targeting modes that can be combined in a single scan.

## Domain User Discovery (`--domain-users`)

Discover interesting AD users (service accounts, admins) and match their names in file contents:

```bash
snaffler -u USER -p PASS -d DOMAIN.LOCAL --domain-users
snaffler ... --domain-users --user-match sql,svc,admin   # custom keywords
snaffler ... --domain-users --user-min-len 8              # minimum username length
```

Generates three pattern variants per username (bare sAMAccountName, NetBIOS `CORP\user`, and UPN `user@domain`).

## Domain Discovery (`-d`)

Queries AD for computers + DFS namespaces, resolves DNS, probes port 445, enumerates shares, then scans:

```bash
snaffler -u USER -p PASS -d DOMAIN.LOCAL
snaffler -u USER -p PASS -d DOMAIN.LOCAL --max-hosts 50   # cap at 50 hosts
snaffler -u USER -p PASS -d DOMAIN.LOCAL --shares-only    # enumerate shares without scanning
snaffler -u USER -p PASS -d DOMAIN.LOCAL --include-disabled  # include disabled/stale accounts
```

## Computer List (`--computer` / `--computer-file`)

Skip LDAP discovery, target specific hosts. Supports hostnames, IPs, CIDR ranges, and IP ranges:

```bash
snaffler -u USER -p PASS --computer 10.0.0.5 --computer 10.0.0.6
snaffler -u USER -p PASS --computer 10.0.0.0/24
snaffler -u USER -p PASS --computer-file targets.txt
```

## UNC Paths (`--unc`)

Skip share discovery, scan specific paths directly:

```bash
snaffler -u USER -p PASS --unc //10.0.0.5/Share --unc //10.0.0.6/IT
```

## Pipe from NetExec (`--stdin`)

```bash
nxc smb 10.0.0.0/24 -u user -p pass --shares | snaffler -u user -p pass --stdin
```

## FTP Servers (`--ftp` / `--ftp-file`)

Same classification engine, all 106 rules, content scanning, resume, and download:

```bash
snaffler --ftp ftp://10.0.0.5                                # anonymous
snaffler --ftp ftp://10.0.0.5/Data -u ftpuser -p ftppass     # with creds + subpath
snaffler --ftp ftp://10.0.0.5:2121 --ftp-tls                 # custom port + TLS
snaffler --ftp-file ftp_targets.txt -u ftpuser -p ftppass     # load from file
```

Bare hostnames accepted: `--ftp 10.0.0.5` becomes `ftp://10.0.0.5`. Without `-u`/`-p`, anonymous login is attempted.

## Local Filesystem (`--local-fs`)

No network, no auth -- useful for mounted shares, extracted filesystems, or testing rules:

```bash
snaffler --local-fs /mnt/share
snaffler --local-fs /tmp/extracted --local-fs /home/user/Documents
```

## Rescan Unreadable Shares (`--rescan-unreadable`)

Re-test previously access-denied shares with new credentials -- useful after password spraying:

```bash
# Initial scan with low-privilege creds
snaffler -u lowpriv -p 'Password1' -d CORP.LOCAL --state scan.db

# Later, with higher-privilege creds
snaffler --rescan-unreadable -u highpriv -p 'NewPass!' --state scan.db
```

The initial scan stores all discovered shares (readable and unreadable) in the state DB. `--rescan-unreadable` loads only the previously denied shares, re-tests them with current credentials, and scans any that are now accessible. Respects `--share`, `--exclude-share`, and `--exclusions` filters.

## Bulk Download (`--grab`)

Download specific files without scanning. Pipe file paths from `snaffler results --files` or provide them manually:

```bash
# List finding paths, then download them
snaffler results --files | snaffler -u USER -p PASS --grab -m ./loot

# Download from a file list
cat paths.txt | snaffler -u USER -p PASS --grab -m ./loot
```
