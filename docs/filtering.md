# Filtering

Control what snaffler-ng scans by share, path, depth, severity, and regex.

```bash
# Only scan specific shares
snaffler ... --share "SYSVOL" --share "IT*"

# Exclude shares
snaffler ... --exclude-share "IPC$" --exclude-share "print$"

# Exclude paths (glob, works with all modes)
snaffler ... --exclude-path "*/Windows/*" --exclude-path "*/.snapshot/*"

# Limit directory recursion depth
snaffler ... --max-depth 5

# Regex post-filter on findings (matches path, rule name, content)
snaffler ... --match "password|connectionstring"

# Skip specific hosts
snaffler ... --exclusions hosts_to_skip.txt

# Stop after N hosts
snaffler ... --max-hosts 50

# Minimum severity (0=all, 1=Yellow+, 2=Red+, 3=Black only)
snaffler ... -b 2
```
