FROM rust:1.84-bookworm AS builder
WORKDIR /src

COPY Cargo.toml Cargo.toml
RUN mkdir -p src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
COPY src/ src/
RUN cargo build --release

FROM debian:bookworm-slim
WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/dpi-detector /app/dpi-detector
COPY domains.txt /app/domains.txt
COPY tcp16.json /app/tcp16.json
COPY whitelist_sni.txt /app/whitelist_sni.txt

EXPOSE 9090

ENV RUN_MODE=schedule
ENV TESTS=123
ENV CHECK_INTERVAL=7200
ENV METRICS_PORT=9090
ENV MAX_CONCURRENT=30
ENV BODY_INSPECT_LIMIT=4096
# ENV METRICS_USER=prometheus
# ENV METRICS_PASSWORD=secret

CMD ["/app/dpi-detector"]