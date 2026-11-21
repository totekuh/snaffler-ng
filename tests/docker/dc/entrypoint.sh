#!/bin/bash
set -e

MARKER="/var/lib/samba/.provisioned"
CURRENT_HASH=$(sha256sum /provision.sh | cut -d' ' -f1)

if [ -f "$MARKER" ] && [ "$(cat "$MARKER")" = "$CURRENT_HASH" ]; then
    echo "[*] Domain already provisioned (provision.sh unchanged), starting Samba"
else
    echo "[*] Provisioning domain (new or changed provision.sh)"
    /provision.sh
    echo "$CURRENT_HASH" > "$MARKER"
fi

exec samba -F --no-process-group
