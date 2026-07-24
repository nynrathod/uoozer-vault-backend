# ── Build stage ───────────────────────────────────────────────
FROM rust:1.82-slim AS builder

WORKDIR /app

# Install dependencies for building
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests first for better layer caching
COPY Cargo.toml Cargo.lock ./
COPY migrations ./migrations
COPY config ./config

# Create a dummy src/main.rs to cache dependencies
RUN mkdir -p src && echo "fn main() {}" > src/main.rs
RUN cargo build --release || true

# Copy actual source
COPY src ./src

# Touch main.rs to force rebuild of actual app
RUN touch src/main.rs
RUN cargo build --release

# ── Runtime stage ─────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/uoozer-vault-backend /app/uoozer-vault-backend
COPY --from=builder /app/migrations /app/migrations
COPY --from=builder /app/config /app/config

EXPOSE 8080

# Non-root user
RUN useradd -r -s /bin/false vault
USER vault

ENV ENVIRONMENT=production
ENV RUST_LOG=info,uoozer_vault_backend=info,tower_http=warn

ENTRYPOINT ["/app/uoozer-vault-backend"]
