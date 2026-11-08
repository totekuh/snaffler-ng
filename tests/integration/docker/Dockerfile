# Pinned 2026-11-08
FROM kalilinux/kali-rolling@sha256:8913de4b58eeeff681a1e62653c0f4369520f65fb419932cca0acac162f3509e

ENV DEBIAN_FRONTEND=noninteractive

# Build tools + runtime deps matching debian/control
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    debhelper=14.5 \
    dh-python=7.20261019 \
    pybuild-plugin-pyproject=7.20261019 \
    python3-all \
    python3-setuptools \
    python3-impacket=0.13.1-1 \
    python3-typer=0.20.0-2 \
    python3-rich=15.0.0-2 \
    python3-tomlkit=0.13.3-3 \
    python3-cryptography=49.0.0-2 \
    python3-rarfile \
    python3-flask=3.1.3-4 \
    python3-socks=1.7.1+dfsg-2 \
    python3-pytest=9.1.1-1 \
    python3-requests=2.34.2-1 \
    python3-pip=26.1.2+dfsg-1 \
    python3-pyftpdlib \
    python3-dnslib \
    # Samba for real SMB share testing
    samba \
    smbclient \
    procps \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Playwright + headless chromium (pinned)
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/playwright
RUN pip3 install --break-system-packages playwright==1.64.1 \
    && playwright install --with-deps chromium

WORKDIR /build
COPY . /build/

# Remove Kali repo snaffler-ng if apt pulled it in as dependency
RUN dpkg -r --force-depends snaffler-ng 2>/dev/null || true

# Build .deb from current source and install it
RUN dpkg-buildpackage -us -uc -b 2>&1 | tail -5
RUN dpkg -i --force-overwrite /snaffler-ng_*.deb
RUN snaffler --help > /dev/null

# Samba config — serves tests/data/ as SMB shares
COPY tests/integration/docker/smb.conf /etc/samba/smb.conf

# Test data is the single source of truth
RUN chmod -R 0755 /build/tests/data

# Reproduce source tree layout so `from tests.*` imports work
RUN mkdir -p /work/tests/integration && \
    cp -r /build/tests/__init__.py /work/tests/ 2>/dev/null; true && \
    touch /work/tests/__init__.py && \
    cp /build/tests/conftest.py /work/tests/conftest.py && \
    cp -r /build/tests/ad_env /work/tests/ad_env && \
    cp -r /build/tests/data /work/tests/data && \
    cp -r /build/tests/integration/*.py /work/tests/integration/

# Non-root test user
RUN useradd -m -s /bin/bash testrunner && chown -R testrunner:testrunner /work

COPY tests/integration/docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /work
ENTRYPOINT ["/entrypoint.sh"]
CMD ["python3", "-m", "pytest", "tests/integration/", "-v", "--tb=short"]
