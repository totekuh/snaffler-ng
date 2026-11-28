# Authentication & Network

## Options

| Flag | Description |
|------|-------------|
| `-u` / `-p` | NTLM username/password |
| `--hash` | NTLM pass-the-hash |
| `-k` | Kerberos authentication |
| `--use-kcache` | Kerberos via existing ccache (`KRB5CCNAME`) |
| `--socks` | SOCKS4/SOCKS5 proxy pivoting (`socks5://127.0.0.1:1080`) |
| `--nameserver` / `--ns` | Custom DNS server (uses TCP, works through SOCKS) |
| `--dc-host` | Domain controller hostname or IP |
| `--stealth` | OPSEC mode: pad LDAP queries to break IDS signatures |

## SOCKS Proxy

Requires `pip install snaffler-ng[socks]`. Accepted `--socks` formats:

| Format | Proxy type |
|--------|------------|
| `socks5://host:port` | SOCKS5 |
| `socks5://user:pass@host:port` | SOCKS5 with authentication |
| `socks4://host:port` | SOCKS4 |
| `host:port` | SOCKS5 (default when no scheme is given) |

Works with Chisel, Ligolo, `ssh -D`, and other standard SOCKS servers.

DNS resolution is routed through the proxy automatically (`rdns`), so
internal hostnames resolve on the remote side without `--ns`. Use
`--dc-host` when the domain name does not point to a domain controller:

```bash
snaffler -u USER -p PASS -d DOMAIN.LOCAL \
  --socks socks5://127.0.0.1:1080 --dc-host DC01.DOMAIN.LOCAL
```

DNS pre-resolution and TCP port probing are skipped in SOCKS mode to
avoid overwhelming the tunnel with concurrent connections.

## SOCKS + Custom DNS

When you need a specific nameserver (split DNS, lab environments), add
`--ns`. DNS queries use TCP so they also route through the tunnel:

```bash
snaffler -u USER -p PASS -d DOMAIN.LOCAL \
  --socks socks5://127.0.0.1:1080 --ns 192.168.201.11 --dc-host 192.168.201.11
```

## Network Options

| Flag | Description |
|------|-------------|
| `--dc-host` | Domain controller hostname, FQDN or IP |
| `--timeout` | SMB connection timeout in seconds (default: 5) |
| `--socks` | SOCKS4/SOCKS5 proxy pivoting (see [SOCKS Proxy](#socks-proxy)) |
| `--nameserver` / `--ns` | Custom DNS server (uses TCP, works through SOCKS) |

## Runtime Hotkeys

During a scan, press `d` for DEBUG output, `i` to switch back to INFO.
