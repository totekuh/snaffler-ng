#!/bin/bash
set -e

echo "[*] Starting Samba..."
smbd --no-process-group &
sleep 1

# Verify SMB is up
smbclient -L //127.0.0.1 -N -p 445 > /dev/null 2>&1 || {
    echo "[!] Samba failed to start"
    exit 1
}
echo "[*] Samba ready — share: testdata"

# Run real snaffler scan against local Samba share
echo "[*] Running snaffler scan..."
snaffler \
    --unc '\\127.0.0.1\testdata' \
    --state /tests/scan.db \
    --fresh \
    --no-banner \
    --log-level data \
    2>&1 | tail -10
echo "[*] Scan complete — $(sqlite3 /tests/scan.db 'SELECT COUNT(*) FROM finding') findings"

# Hand off to pytest
exec "$@"
