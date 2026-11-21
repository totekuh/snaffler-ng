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

# Disabled account for auth rejection tests
samba-tool user create disabled_user "DisabledPass1!" --description="Disabled test account" 2>/dev/null || true
samba-tool user disable disabled_user 2>/dev/null || true

# Lockable account for lockout tests
samba-tool user create lockable_user "LockablePass1!" --description="Lockout test account" 2>/dev/null || true
samba-tool domain passwordsettings set --account-lockout-threshold=3 2>/dev/null || true

echo "[*] Creating test SMB shares"
mkdir -p /srv/shares/data /srv/shares/finance /srv/shares/it
echo "DB_HOST=prod-db.corp.local" > /srv/shares/data/config.ini
echo "password=s3cret" >> /srv/shares/data/config.ini
echo "svc_sql credentials here" > /srv/shares/finance/passwords.txt
echo "normal file content" > /srv/shares/it/readme.txt
chmod -R 0777 /srv/shares

echo "[*] Creating SCCM ContentLib test fixture"
mkdir -p /srv/shares/sccm/SCCMContentLib/DataLib
mkdir -p /srv/shares/sccm/SCCMContentLib/FileLib

# 1. deploy-script.ps1 — contains hardcoded creds (triggers content rules)
BLOB1_CONTENT='$cred = New-Object PSCredential("svc_deploy", (ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force))'
echo "$BLOB1_CONTENT" > /tmp/sccm_blob1
HASH1=$(sha256sum /tmp/sccm_blob1 | cut -d' ' -f1)
mkdir -p "/srv/shares/sccm/SCCMContentLib/FileLib/${HASH1:0:4}"
cp /tmp/sccm_blob1 "/srv/shares/sccm/SCCMContentLib/FileLib/${HASH1:0:4}/${HASH1}"
printf "[File]\nHash=%s\n" "$HASH1" > /srv/shares/sccm/SCCMContentLib/DataLib/deploy-script.ps1.INI

# 2. db-connection.ini — contains DB password (triggers filename + content rules)
printf '[database]\nserver=sqlprod.corp.local\nuser=sa\npassword=Str0ngDBP@ss!\n' > /tmp/sccm_blob2
HASH2=$(sha256sum /tmp/sccm_blob2 | cut -d' ' -f1)
mkdir -p "/srv/shares/sccm/SCCMContentLib/FileLib/${HASH2:0:4}"
cp /tmp/sccm_blob2 "/srv/shares/sccm/SCCMContentLib/FileLib/${HASH2:0:4}/${HASH2}"
printf "[File]\nHash=%s\n" "$HASH2" > /srv/shares/sccm/SCCMContentLib/DataLib/db-connection.ini.INI

# 3. readme.txt — benign, should NOT produce findings
echo "This is a normal SCCM package readme." > /tmp/sccm_blob3
HASH3=$(sha256sum /tmp/sccm_blob3 | cut -d' ' -f1)
mkdir -p "/srv/shares/sccm/SCCMContentLib/FileLib/${HASH3:0:4}"
cp /tmp/sccm_blob3 "/srv/shares/sccm/SCCMContentLib/FileLib/${HASH3:0:4}/${HASH3}"
printf "[File]\nHash=%s\n" "$HASH3" > /srv/shares/sccm/SCCMContentLib/DataLib/readme.txt.INI

# 4. id_rsa — SSH private key (triggers KeepSSHKeyByName by filename via display_name)
printf '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAA=\n-----END OPENSSH PRIVATE KEY-----\n' > /tmp/sccm_blob4
HASH4=$(sha256sum /tmp/sccm_blob4 | cut -d' ' -f1)
mkdir -p "/srv/shares/sccm/SCCMContentLib/FileLib/${HASH4:0:4}"
cp /tmp/sccm_blob4 "/srv/shares/sccm/SCCMContentLib/FileLib/${HASH4:0:4}/${HASH4}"
printf "[File]\nHash=%s\n" "$HASH4" > /srv/shares/sccm/SCCMContentLib/DataLib/id_rsa.INI

rm -f /tmp/sccm_blob1 /tmp/sccm_blob2 /tmp/sccm_blob3 /tmp/sccm_blob4
chmod -R 0777 /srv/shares/sccm

cat >> /etc/samba/smb.conf <<'SHARES'

[data]
    path = /srv/shares/data
    read only = no
    guest ok = yes

[finance]
    path = /srv/shares/finance
    read only = yes
    guest ok = no
    valid users = Administrator, testrunner

[it]
    path = /srv/shares/it
    read only = no
    guest ok = yes

[sccm]
    path = /srv/shares/sccm
    read only = yes
    guest ok = yes
SHARES

# Stop the temporary samba instance
kill "$(cat /run/samba/samba.pid 2>/dev/null)" 2>/dev/null || killall samba 2>/dev/null || true
sleep 1

echo "[*] Provisioning complete"
