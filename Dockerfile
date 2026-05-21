# syntax=docker/dockerfile:1.7

# -------- Build stage --------
FROM rust:1.88-bookworm AS build

WORKDIR /work

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# BuildKit cache mounts speed up subsequent rebuilds (deps stay compiled across cache hits).
# On a cold cache (first deploy), this takes ~4-8 min. Subsequent deploys with only source
# changes take ~30-90s.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/work/target \
    cargo build --release -p clearhash-web && \
    cp /work/target/release/clearhash-web /usr/local/bin/clearhash-web

# -------- Runtime stage --------
FROM debian:bookworm-slim AS runtime

# ca-certificates: required for rustls to validate npm/PyPI/crates.io TLS chains.
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=build /usr/local/bin/clearhash-web /usr/local/bin/clearhash-web
COPY assets /app/assets

ENV RUST_LOG=clearhash_web=info,tower_http=info
ENV PORT=8080

EXPOSE 8080

RUN useradd --create-home --shell /usr/sbin/nologin app && chown -R app:app /app
USER app

# Fly.io health checks are configured in fly.toml — no Dockerfile HEALTHCHECK needed
# (would require curl/wget in the runtime image).
ENTRYPOINT ["/usr/local/bin/clearhash-web"]
