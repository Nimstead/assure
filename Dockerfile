# Nimstead Assure: the API server with the web UI and agent it serves.
FROM node:22-slim AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM python:3.14-slim
COPY --from=ghcr.io/astral-sh/uv:0.9 /uv /usr/local/bin/uv
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
    NIMSTEAD_CHECKPOINT_DIR=/data/checkpoints
VOLUME /data
EXPOSE 8000
HEALTHCHECK CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/')"
CMD ["sh", "-c", "alembic upgrade head && exec uvicorn --factory nimstead.app:create_app --host 0.0.0.0 --port 8000 --proxy-headers"]
