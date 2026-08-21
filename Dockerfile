FROM rust:1.93-slim-bookworm AS builder
WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libssl3 curl && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/pubky-fiat-verifier /usr/local/bin/pubky-fiat-verifier
ENV RUST_LOG=info
# Railway injects PORT; the service binds [::] (Railway private networking is IPv6).
CMD ["pubky-fiat-verifier"]
