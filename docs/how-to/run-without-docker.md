# Run without Docker

Use this procedure for a local trial or a separately managed deployment. You must provide the process supervisor, database operations, and HTTPS configuration.

You need [uv](https://docs.astral.sh/uv/) and Node.js 22.22.2 or later in the Node 22 release line. Run each command from the repository root.

```bash
(cd web && npm ci && npm run build)
```

```bash
(cd api && uv sync --locked --no-dev && uv run alembic upgrade head)
```

```bash
(cd api && uv run uvicorn --factory nimstead.app:create_app --host 0.0.0.0 --port 8000 --proxy-headers)
```

Run `cd api && uv run python -m nimstead.feeds update` hourly with cron or a systemd timer. Without `NIMSTEAD_DB` it uses SQLite in the current directory, which is fine for a trial.

For remote access, [configure HTTPS](configure-https.md). Set the production database and signing options in the [configuration reference](../configuration.md).
