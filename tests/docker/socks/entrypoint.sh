#!/bin/sh
set -e

MODE="${1:-socks5}"

case "$MODE" in
    socks4)
        cat > /tmp/3proxy.cfg <<EOF
auth none
socks -p1080 -4
EOF
        exec 3proxy /tmp/3proxy.cfg
        ;;
    socks5)
        exec microsocks -p 1080
        ;;
    both)
        cat > /tmp/3proxy.cfg <<EOF
auth none
socks -p1080
EOF
        exec 3proxy /tmp/3proxy.cfg
        ;;
    *)
        echo "Usage: $0 {socks4|socks5|both}"
        exit 1
        ;;
esac
