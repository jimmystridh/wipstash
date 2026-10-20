FROM rust:1.99.1-bookworm AS build
WORKDIR /build
COPY . .
RUN cargo build --release --locked --bin wipstash && CARGO_TARGET_DIR=/build/target cargo build --release --locked --manifest-path services/transport/Cargo.toml

FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends git nodejs ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/target/release/wipstash /usr/local/bin/wipstash
COPY --from=build /build/target/release/wipstash-transport /usr/local/bin/wipstash-transport
COPY --from=ghcr.io/astral-sh/uv:0.9.3 /uv /usr/local/bin/uv
WORKDIR /app
COPY services/cloudrun/pyproject.toml services/cloudrun/uv.lock ./
RUN uv sync --frozen --no-dev
COPY services/cloudrun/*.py ./
RUN uv sync --frozen && uv run python -m unittest -v test_cloudrun && uv sync --frozen --no-dev
RUN useradd --create-home --uid 10001 wipstash && mkdir /srv/wipstash-parent && chown wipstash /srv/wipstash-parent
USER wipstash
ENV WIPSTASH_ROOT=/srv/wipstash-parent/authority PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
CMD ["/app/.venv/bin/uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]
