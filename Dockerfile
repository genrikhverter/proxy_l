# --- Сборка -----------------------------------------------------------------
FROM rust:1-slim AS build
WORKDIR /app
# Сначала только манифест и исходники: слой с зависимостями кэшируется.
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

# --- Рантайм ----------------------------------------------------------------
FROM debian:bookworm-slim
# TLS на rustls, корневые сертификаты вшиты в бинарник — openssl/ca-certificates не нужны.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin proxy
COPY --from=build /app/target/release/llm-proxy /usr/local/bin/llm-proxy

USER 10001:10001
ENV PROXY_LISTEN=0.0.0.0:8080
EXPOSE 8080

# Секреты передаём при запуске: docker run -e UPSTREAM_API_KEY=... -e PROXY_API_KEYS=...
ENTRYPOINT ["llm-proxy"]
