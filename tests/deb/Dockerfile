# Pinned 2026-11-08
FROM kalilinux/kali-rolling@sha256:8913de4b58eeeff681a1e62653c0f4369520f65fb419932cca0acac162f3509e

ENV DEBIAN_FRONTEND=noninteractive

# Pin versions for reproducibility (captured 2026-11-08)
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
    python3-flask=3.1.3-4 \
    python3-socks=1.7.1+dfsg-2 \
    python3-pytest=9.1.1-1 \
    python3-requests=2.34.2-1 \
    python3-pip=26.1.2+dfsg-1 \
    && rm -rf /var/lib/apt/lists/*

# Playwright + headless chromium (pinned)
RUN pip3 install --break-system-packages playwright==1.64.1 \
    && playwright install --with-deps chromium

WORKDIR /build
COPY . /build/

# Build .deb
RUN dpkg-buildpackage -us -uc -b 2>&1 | tail -5

# Install it
RUN dpkg -i /snaffler-ng_*.deb 2>/dev/null || (apt-get update && apt-get install -f -y)
RUN snaffler --help > /dev/null

# Tests run against installed package, not source tree
RUN mkdir -p /tests && cp -r /build/tests/deb/suite/* /tests/
WORKDIR /tests

CMD ["python3", "-m", "pytest", "-v", "--tb=short"]
