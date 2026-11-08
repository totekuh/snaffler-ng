FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    samba \
    samba-ad-provision \
    samba-dsdb-modules \
    samba-vfs-modules \
    krb5-user \
    krb5-kdc \
    winbind \
    libnss-winbind \
    libpam-winbind \
    procps \
    && rm -rf /var/lib/apt/lists/*

COPY provision.sh /provision.sh
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /provision.sh /entrypoint.sh

CMD ["/entrypoint.sh"]

EXPOSE 389 636 88 445 135 3268

HEALTHCHECK --interval=5s --timeout=10s --retries=24 \
  CMD samba-tool domain info 127.0.0.1 || exit 1
