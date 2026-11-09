# Deploy with Docker Compose

Deploy the Assure API, web interface, PostgreSQL, and feed updater on one host. You need Docker Compose v2 and several GB of free disk space.

## Start the services

```bash
git clone https://github.com/Nimstead/assure.git && cd assure
```

```bash
cp .env.example .env
```

Edit `.env` before the first start:

1. Set `POSTGRES_PASSWORD` to a long random value. The database fixes this value on its first start.
2. Set `NIMSTEAD_PUBLIC_URL` to the address your machines will use.

```bash
docker compose up -d
```

Open http://localhost:8000 on the same machine and create an account. The first account in an organisation is its admin.

> [!IMPORTANT]
> Sign-in cookies only travel over HTTPS, or plain HTTP to `localhost`. From another computer, `http://<server-ip>:8000` will show the sign-in page but never sign you in. [Configure HTTPS](configure-https.md) first, or for a quick look tunnel the port: `ssh -L 8000:localhost:8000 <server>`, then open http://localhost:8000.

Three containers run:

| Service | What it does |
|---|---|
| `app` | The server on port 8000 of `127.0.0.1` only (the first account sets the server up, so nobody else on the network may create it first; your HTTPS proxy on this host forwards to it). Applies database migrations on start. Keys and checkpoints live in the `data` volume. |
| `feeds` | Every hour: refreshes CISA KEV, EPSS, NVD, OSV and MSRC, re-matches every asset, retries failed alerts and writes a signed ledger checkpoint. The first run takes a while. |
| `db` | PostgreSQL 17, in the `pg` volume. Not exposed outside Compose. |

**Windows third-party apps** are matched against NVD, which needs a one-off history load (a few minutes per year). Microsoft's own apps (VS Code, PowerShell and the like) also use MSRC, whose last five years load on their own over the first hourly runs:

```bash
docker compose exec feeds python -m nimstead.feeds nvd 2023 2024 2025 2026
```

## Confirm the deployment

Run `docker compose ps` and confirm that all three services are running. Open the local web interface and check `/api/health`. The health endpoint returns HTTP 200 when the database and migration checks pass.

If startup fails, inspect `docker compose logs app db feeds`. Correct the reported configuration before retrying. Keep the database volume when troubleshooting an existing installation.

Before you enrol remote machines, [configure HTTPS](configure-https.md). Then [enrol Linux](enrol-linux.md) or [enrol Windows](enrol-windows.md).
