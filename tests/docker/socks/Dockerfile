FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch 0.9.4 https://github.com/3proxy/3proxy.git /build \
    && cd /build && make -f Makefile.Linux

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    microsocks netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/bin/3proxy /usr/local/bin/3proxy
COPY --from=builder /build/bin/socks /usr/local/bin/3proxy-socks

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 1080

ENTRYPOINT ["/entrypoint.sh"]
CMD ["socks5"]
