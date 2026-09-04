# ── Build Stage ──────────────────────────────────────────────
FROM rust:slim-bookworm AS builder

WORKDIR /app

# Build dependencies
# curl: needed by utoipa-swagger-ui's build script (downloads Swagger UI assets)
# ssl: aws-sdk may link OpenSSL depending on feature set
RUN apt-get update && apt-get install -y \
	pkg-config \
	libssl-dev \
	curl \
	&& rm -rf /var/lib/apt/lists/*

# Copy manifests for dependency layer caching
COPY Cargo.toml Cargo.lock ./

# Dummy sources (BOTH main.rs and lib.rs — this crate has both)
# so cargo compiles and caches all dependencies in one Docker layer
RUN mkdir -p src \
	&& echo 'fn main() {}' > src/main.rs \
	&& echo '' > src/lib.rs \
	&& cargo build --release \
	&& rm -rf src

# Real source + migrations
COPY src ./src
COPY migrations ./migrations

# Touch forces rebuild of the app crate, deps come from cache layer
RUN touch src/main.rs src/lib.rs && cargo build --release

# ── Runtime Stage ────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
	ca-certificates \
	libssl3 \
	&& rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/uoozer-vault-backend .
COPY --from=builder /app/migrations ./migrations

# Required: Settings::load() reads config/default.toml —
# without it the server panics with "missing field `server`"
COPY config ./config

EXPOSE 8080

CMD ["./uoozer-vault-backend"]