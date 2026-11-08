#!/bin/bash
set -e

# Samba needs root to start
echo "[*] Starting Samba..."
smbd --no-process-group &
sleep 1

smbclient -L //127.0.0.1 -N -p 445 > /dev/null 2>&1 || {
    echo "[!] Samba failed to start"
    exit 1
}
echo "[*] Samba ready — share: testdata"

# Run scan and tests as non-root user
su testrunner -c "
    snaffler \
        --unc '\\\\\\\\127.0.0.1\\\\testdata' \
        --state /work/scan.db \
        --fresh \
        --no-banner \
        --log-level data \
        2>&1 | tail -10
    echo \"[*] Scan complete — \$(sqlite3 /work/scan.db 'SELECT COUNT(*) FROM finding') findings\"
"

exec su testrunner -c "$*"
