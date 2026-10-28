# Nimstead Assure: the API server with the web UI and agent it serves.
# Base images are pinned by digest (tag kept for reading), so a signed release commit pins what gets built.
# Refresh: look up each tag's current digest and update it in a release PR.
FROM node:25-slim@sha256:81db02c4b671288a03915da9534dbd54f96d0e7c24d80ccc54f5b36b2e684370 AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM python:3.14-slim@sha256:cd89c30eda26ee911a4611b18680086e0ea42e6f5f8cbe653d07fa7958c9cec8
COPY --from=ghcr.io/astral-sh/uv:0.9@sha256:538e0b39736e7feae937a65983e49d2ab75e1559d35041f9878b7b7e51de91e4 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never PYTHONUNBUFFERED=1
WORKDIR /app/api
COPY api/pyproject.toml api/uv.lock api/README.md ./
RUN uv sync --locked --no-dev --no-install-project
COPY api/ ./
RUN uv sync --locked --no-dev
COPY agent/ /app/agent/
COPY --from=web /src/web/dist /app/web/dist
RUN useradd --system --home-dir /data nimstead && mkdir -p /data && chown nimstead /data
USER nimstead
# Keys, checkpoints and (without NIMSTEAD_DB) the SQLite database live in /data: mount a volume there.
ENV PATH=/app/api/.venv/bin:$PATH \
    NIMSTEAD_DB=sqlite:////data/nimstead.db \
    NIMSTEAD_SECRET_KEY_FILE=/data/nimstead-secret.key \
    NIMSTEAD_SIGNING_KEY_FILE=/data/nimstead-signing.pem \
    NIMSTEAD_CHECKPOINT_DIR=/data/checkpoints \
    NIMSTEAD_RELEASE_DIR=/data/release
VOLUME /data
EXPOSE 8000
HEALTHCHECK --interval=30s --start-period=60s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=5)"
CMD ["sh", "-c", "alembic upgrade head && exec uvicorn --factory nimstead.app:create_app --host 0.0.0.0 --port 8000 --proxy-headers"]
