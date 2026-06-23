FROM rust:1.88-slim AS builder

WORKDIR /app
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
# Cache dependencies layer — build dummy stubs to avoid re-downloading on src changes
RUN mkdir src && echo "fn main() {}" > src/main.rs && echo "" > src/lib.rs && cargo build --release && rm -rf src

COPY src ./src
COPY migrations ./migrations
RUN find src -name "*.rs" | xargs touch && cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates libssl3 curl && rm -rf /var/lib/apt/lists/*

RUN useradd -r -s /bin/false caas
WORKDIR /app
COPY --from=builder /app/target/release/caas-api .
COPY --from=builder /app/migrations ./migrations

USER caas
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD curl -fs http://localhost:8080/v1/health || exit 1

CMD ["./caas-api"]
