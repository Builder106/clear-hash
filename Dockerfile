# syntax=docker/dockerfile:1.7

# -------- Build stage --------
FROM rust:1.99-bookworm AS build

WORKDIR /work

COPY Cargo.toml Cargo.lock ./
COPY patches ./patches
COPY crates ./crates
COPY api ./api

ARG TARGETARCH

# BuildKit cache mounts speed up subsequent rebuilds (deps stay compiled across cache hits).
# Differentiate cache mounts by target architecture and lock sharing so concurrent multi-platform
# builds (e.g. linux/amd64 and linux/arm64) do not collide on registry locks or target artifacts.
RUN --mount=type=cache,id=cargo-registry-${TARGETARCH},target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=cargo-target-${TARGETARCH},target=/work/target,sharing=locked \
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
