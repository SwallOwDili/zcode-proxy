# ---------- builder ----------
FROM debian:bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake g++ ninja-build libssl-dev nlohmann-json3-dev ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY CMakeLists.txt ./
COPY src ./src
COPY third_party ./third_party
COPY tests ./tests
RUN cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
 && cmake --build build -j"$(nproc)"

# ---------- runtime ----------
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/build/zproxy /usr/local/bin/zproxy
COPY web /web
ENV ZPROXY_PORT=8787 \
    ZPROXY_STATE_DIR=/data/state \
    ZPROXY_WEB_DIR=/web
VOLUME /data/state
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s \
  CMD curl -sf http://localhost:8787/health || exit 1
ENTRYPOINT ["/usr/local/bin/zproxy"]
