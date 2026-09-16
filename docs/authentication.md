# Authentication & Network

## Options

| Flag | Description |
|------|-------------|
| `-u` / `-p` | NTLM username/password |
| `--hash` | NTLM pass-the-hash |
| `-k` | Kerberos authentication |
| `--use-kcache` | Kerberos via existing ccache (`KRB5CCNAME`) |
| `--socks` | SOCKS proxy pivoting (`socks5://127.0.0.1:1080`) |
| `--nameserver` / `--ns` | Custom DNS server (uses TCP, works through SOCKS) |
| `--dc-host` | Domain controller hostname or IP |
| `--stealth` | OPSEC mode: pad LDAP queries to break IDS signatures |

## SOCKS + Custom DNS

```bash
snaffler -u USER -p PASS -d DOMAIN.LOCAL \
  --socks socks5://127.0.0.1:1080 --ns 192.168.201.11 --dc-host 192.168.201.11
```

## Network Options

| Flag | Description |
|------|-------------|
| `--dc-host` | Domain controller hostname, FQDN or IP |
| `--timeout` | SMB connection timeout in seconds (default: 5) |
| `--socks` | SOCKS proxy pivoting (`socks5://127.0.0.1:1080`) |
| `--nameserver` / `--ns` | Custom DNS server (uses TCP, works through SOCKS) |

## Runtime Hotkeys

During a scan, press `d` for DEBUG output, `i` to switch back to INFO.
