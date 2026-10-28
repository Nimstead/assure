# Install

Nimstead Assure is one server (API, web UI and the agent it hands out) plus PostgreSQL and an hourly feed update. Docker Compose runs all three.

## With Docker Compose

You need Docker with Compose v2, and a few GB of disk for vulnerability data.

```bash
git clone https://github.com/Nimstead/assure.git && cd assure
```

```bash
cp .env.example .env
```

Edit `.env`: set `POSTGRES_PASSWORD` to a long random value now (it's fixed into the database on first start), and `NIMSTEAD_PUBLIC_URL` to the address your machines will use.

```bash
docker compose up -d
```

Open http://localhost:8000 on the same machine and create an account. The first account in an organisation is its admin.

> [!IMPORTANT]
> Sign-in cookies only travel over HTTPS, or plain HTTP to `localhost`. From another computer, `http://<server-ip>:8000` will show the sign-in page but never sign you in. [Put it behind HTTPS](#put-it-behind-https) first, or for a quick look tunnel the port: `ssh -L 8000:localhost:8000 <server>`, then open http://localhost:8000.

Three containers run:

| Service | What it does |
|---|---|
| `app` | The server on port 8000. Applies database migrations on start. Keys and checkpoints live in the `data` volume. |
| `feeds` | Every hour: refreshes CISA KEV, EPSS, NVD, OSV and MSRC, re-matches every asset, retries failed alerts and writes a signed ledger checkpoint. The first run takes a while. |
| `db` | PostgreSQL 17, in the `pg` volume. Not exposed outside Compose. |

**Windows third-party apps** are matched against NVD, which needs a one-off history load (a few minutes per year):

```bash
docker compose exec feeds python -m nimstead.feeds nvd 2023 2024 2025 2026
```

## Put it behind HTTPS

Agents refuse plain HTTP except for local testing, so anything beyond one machine needs TLS. Any reverse proxy works. With [Caddy](https://caddyserver.com), which gets a certificate for you:

```
assure.example.com {
	reverse_proxy localhost:8000
}
```

Then set in `.env`:

```
NIMSTEAD_PUBLIC_URL=https://assure.example.com
FORWARDED_ALLOW_IPS=<your proxy's address as the app container sees it>
```

and run `docker compose up -d` again.

## Add your first machine

In the app, **Add your first machine** gives you an enrolment token and the exact command. On Linux it looks like this:

```bash
curl -fsSL https://assure.example.com/install.sh | sudo sh -s -- --token nme_…
```

On Windows, in an elevated PowerShell:

```powershell
$env:NIMSTEAD_TOKEN = "nme_…"; irm https://assure.example.com/install.ps1 | iex
```

| | Linux | Windows |
|---|---|---|
| **Supported** | Debian, Ubuntu, RHEL family (AlmaLinux, Rocky), Alpine, SUSE | Windows Server 2025 and Windows 11 (proven); Windows 10 detection |
| **Needs** | Python 3.9+ and curl | Python for all users (`winget install Python.Python.3.13 --scope machine`) |
| **Runs** | a systemd timer every 6 hours | a SYSTEM scheduled task every 6 hours and at startup |

The agent is one readable file, [`agent/nimstead_agent.py`](../agent/nimstead_agent.py), using only Python's standard library.

### Fixing things automatically

Remediation is off until you turn it on in three places:

1. **The host opts in** at install with `--allow-remediation` (on Windows, `$env:NIMSTEAD_ALLOW_REMEDIATION = "1"` before the install command). The server can never turn this on.
2. **Start with sandbox hosts.** Tick *sandbox* when you create the enrolment token, for disposable test machines. Until you set `NIMSTEAD_ALLOW_PRODUCTION_REMEDIATION=1`, fixes only ever target those.
3. **You approve each fix,** or move up the **trust ladder** in **Settings** to let some fixes run on their own. Fixes go to canary hosts first, then the rest.

Every fix takes a rollback copy first, refuses to touch anything outside the plan, checks your services afterwards and rolls back on its own if they fail. It only counts as fixed when the next inventory shows it.

**Tell it which services matter.** On the **Assets** page, list each machine's important services under **Health units** (for example `nginx, postgresql`). After a change the agent waits 15 seconds, then each one must be running and must not have been restarted since the change, so a service stuck restarting counts as broken. On Windows it waits 60 seconds after the update, then checks each service is running.

## Upgrade

```bash
git pull && docker compose up -d --build
```

Migrations run on start. When a release changes the agent, hosts show **Agent outdated** on the Assets page; rerun the install command on each (enrolment is kept).

## Back up

Back up both volumes: `pg` (the database) and `data` (signing keys and checkpoints). Without the signing key, new evidence packs get a new fingerprint and you'll need to send it to your auditor again.

```bash
docker compose exec -T db pg_dump -U nimstead nimstead > nimstead.sql
```

```bash
docker compose cp app:/data ./nimstead-data
```

## Without Docker

You need [uv](https://docs.astral.sh/uv/) and Node.js 22.

```bash
cd web && npm ci && npm run build
```

```bash
cd api && uv sync --no-dev && uv run alembic upgrade head
```

```bash
cd api && uv run uvicorn --factory nimstead.app:create_app --host 0.0.0.0 --port 8000 --proxy-headers
```

Run `cd api && uv run python -m nimstead.feeds update` hourly with cron or a systemd timer. Without `NIMSTEAD_DB` it uses SQLite in the current directory, which is fine for a trial.

## Production checklist

- [ ] HTTPS in front, `NIMSTEAD_PUBLIC_URL` set, `FORWARDED_ALLOW_IPS` set to the proxy
- [ ] A strong `POSTGRES_PASSWORD`, and both volumes backed up
- [ ] Keys in Vault (`NIMSTEAD_VAULT_ADDR`, `NIMSTEAD_VAULT_TOKEN`) and checkpoints in an object-locked S3 bucket (`NIMSTEAD_CHECKPOINT_S3`)
- [ ] The evidence key fingerprint (`GET /api/evidence/public-key`) sent to your auditor
- [ ] Alerts configured in **Settings** (webhook or email), so a rollback never goes unnoticed
- [ ] Single sign-on tested before turning on **Require SSO**

Every setting is in [configuration.md](configuration.md).
