#!/bin/bash
set -e

MARKER="/var/lib/samba/.provisioned"

if [ ! -f "$MARKER" ]; then
    echo "[*] First run — provisioning domain"
    /provision.sh
    touch "$MARKER"
else
    echo "[*] Domain already provisioned, starting Samba"
fi

exec samba -F --no-process-group
