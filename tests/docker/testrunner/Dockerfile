# Pinned 2026-11-08
FROM kalilinux/kali-rolling@sha256:8913de4b58eeeff681a1e62653c0f4369520f65fb419932cca0acac162f3509e

ENV DEBIAN_FRONTEND=noninteractive

# Build tools + runtime deps matching debian/control
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    debhelper \
    dh-python \
    pybuild-plugin-pyproject \
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
    python3-pip \
    python3-pyftpdlib \
    python3-dnslib \
    smbclient \
    tcpdump \
    procps \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/* \
    && setcap cap_net_raw+ep /usr/bin/tcpdump

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

# Copy test tree (minus unit/ and windows/ which don't run in Docker)
# Tests import snaffler from the installed .deb, not source
RUN mkdir -p /work && \
    cp -r /build/tests /work/tests && \
    rm -rf /work/tests/unit /work/tests/windows

# Non-root test user
RUN useradd -m -s /bin/bash testrunner && chown -R testrunner:testrunner /work

COPY tests/docker/testrunner/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /work
ENTRYPOINT ["/entrypoint.sh"]
CMD ["python3", "-m", "pytest", "tests/", "-v", "--tb=short"]
