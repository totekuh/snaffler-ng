#!/bin/bash
set -e

REALM="${REALM:-TESTLAB.LOCAL}"
DOMAIN="${DOMAIN:-TESTLAB}"
ADMIN_PASS="${ADMIN_PASS:-Passw0rd!Testing}"

echo "[*] Provisioning Samba AD DC: realm=$REALM domain=$DOMAIN"

rm -f /etc/samba/smb.conf
rm -rf /var/lib/samba/*
rm -rf /var/cache/samba/*

samba-tool domain provision \
  --realm="$REALM" \
  --domain="$DOMAIN" \
  --adminpass="$ADMIN_PASS" \
  --server-role=dc \
  --dns-backend=SAMBA_INTERNAL \
  --use-rfc2307 \
  --option="interfaces=lo eth0" \
  --option="bind interfaces only=yes"

# Fix krb5.conf
cat > /etc/krb5.conf <<EOF
[libdefaults]
    default_realm = $REALM
    dns_lookup_realm = false
    dns_lookup_kdc = true
    forwardable = true

[realms]
    $REALM = {
        kdc = 127.0.0.1
        admin_server = 127.0.0.1
    }

[domain_realm]
    .$(echo "$REALM" | tr '[:upper:]' '[:lower:]') = $REALM
    $(echo "$REALM" | tr '[:upper:]' '[:lower:]') = $REALM
EOF

# Start Samba temporarily to create objects
samba -D
sleep 3

echo "[*] Creating test computer objects"
samba-tool computer create FILESERVER1 2>/dev/null || true
samba-tool computer create DBSERVER1 2>/dev/null || true
samba-tool computer create WEBSERVER1 2>/dev/null || true
samba-tool computer create DISABLED-PC 2>/dev/null || true

# Enable computers (Samba creates them disabled by default like Windows)
for pc in FILESERVER1 DBSERVER1 WEBSERVER1; do
    samba-tool user enable "${pc}\$" 2>/dev/null || true
done
# DISABLED-PC stays disabled (test fixture for skip_disabled filter)

echo "[*] Creating test user objects"
samba-tool user create svc_sql "SvcPass123!" --description="SQL Service Account" 2>/dev/null || true
samba-tool user create admin_backup "AdminPass123!" --description="Backup Admin" 2>/dev/null || true
samba-tool user create normal_user "UserPass123!" --description="Regular User" 2>/dev/null || true
samba-tool user create scom_monitor "ScomPass123!" --description="SCOM Service" 2>/dev/null || true
samba-tool user create short "Short1!" --description="Short username" 2>/dev/null || true

# Auth test user with known password
samba-tool user create testrunner "TestRunner1!" 2>/dev/null || true

echo "[*] Creating test SMB shares"
mkdir -p /srv/shares/data /srv/shares/finance /srv/shares/it
echo "DB_HOST=prod-db.corp.local" > /srv/shares/data/config.ini
echo "password=s3cret" >> /srv/shares/data/config.ini
echo "svc_sql credentials here" > /srv/shares/finance/passwords.txt
echo "normal file content" > /srv/shares/it/readme.txt
chmod -R 0777 /srv/shares

cat >> /etc/samba/smb.conf <<'SHARES'

[data]
    path = /srv/shares/data
    read only = no
    guest ok = yes

[finance]
    path = /srv/shares/finance
    read only = yes
    guest ok = no

[it]
    path = /srv/shares/it
    read only = no
    guest ok = yes
SHARES

# Stop the temporary samba instance
kill "$(cat /run/samba/samba.pid 2>/dev/null)" 2>/dev/null || killall samba 2>/dev/null || true
sleep 1

echo "[*] Provisioning complete"
