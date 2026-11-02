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
| `app` | The server on port 8000 of `127.0.0.1` only (the first account sets the server up, so nobody else on the network may create it first; your HTTPS proxy on this host forwards to it). Applies database migrations on start. Keys and checkpoints live in the `data` volume. |
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

The first account you create sets the server up and is its admin. Later sign-ups (another organisation on the same server) finish from an emailed link, so set up SMTP (`docs/configuration.md`) if you need them; colleagues in your own organisation join through single sign-on.

## Add your first machine

In the app, **Add your first machine** gives you an enrolment token and the exact command. On Linux it looks like this:

```bash
export NIMSTEAD_TOKEN=nme_…; curl -fsSL --proto '=https' https://assure.example.com/install.sh | sudo --preserve-env=NIMSTEAD_TOKEN sh; unset NIMSTEAD_TOKEN
```

The token travels in an environment variable, never as a command-line argument, which every user on the machine (and sudo's log) could read. A token works for 30 days and for any number of machines: revoke it in the app when you've finished enrolling.

On Windows, in an elevated PowerShell:

```powershell
$env:NIMSTEAD_TOKEN = "nme_…"; irm https://assure.example.com/install.ps1 | iex
```

| | Linux | Windows |
|---|---|---|
| **Supported** | Debian, Ubuntu, RHEL family (AlmaLinux, Rocky), Alpine, SUSE | Windows 10 / Server 2016 and newer (fixes proven on Server 2025 and Windows 11) |
| **Needs** | Python 3.9+ and curl | nothing: the installer brings Python's official embeddable runtime (see below) |
| **Runs** | a systemd timer every 6 hours | a SYSTEM scheduled task every 6 hours and at startup |
| **With remediation** | plus a 15-minute check for approved fixes | plus a 15-minute check for approved fixes |

The agent is one readable file, [`agent/nimstead_agent.py`](../agent/nimstead_agent.py), using only Python's standard library.

**On Windows nothing needs to be installed first.** The installer downloads Python's official embeddable runtime (the
version pinned in [`agent/windows-runtime.json`](../agent/windows-runtime.json)) from your server, checks that every
program file in it is signed by the Python Software Foundation, and keeps it under `Program Files\Nimstead\runtime\`,
which only administrators can change. It prints the runtime's `sha256` next to the agent's. The agent keeps the runtime
current from signed releases, as it does itself. Windows 8.1 / Server 2012 R2 and older are refused: current Python
doesn't run there, and those systems no longer get security updates.

**Java libraries on disk (opt-in):** enrol with `--scan-jars` (on Windows, `$env:NIMSTEAD_SCAN_JARS = "1"` before
the install command) and each report also looks through local disks for `.jar`, `.war` and `.ear` files, including
jars nested one level inside them, and reports the libraries they contain (log4j-style findings name the file). It
never follows links or enters network shares, and stops after 5 minutes or 500,000 files, saying the scan was partial.

**Behind a proxy:** set `$env:NIMSTEAD_PROXY = "http://proxy.example:8080"` before the install command (on Linux, pass
`--proxy` to `enroll`). Without it, Windows machines use the machine-wide WinHTTP proxy if one is set (`netsh winhttp
show proxy`), the same one Windows Update uses. TLS to your server stays end to end; a plain-HTTP server is refused
through a proxy. Scheduled runs start at a random point within 30 minutes (job checks within 2), at below-normal
priority, so a large fleet doesn't report all at once.

Windows Update fixes behind a proxy with no direct internet access: Windows downloads updates with Delivery
Optimization, which on Windows 11 26H2 ignored the proxy and stalled every download (seen in our VM test). Set the
**Download Mode** policy to **Bypass** (Computer Configuration > Administrative Templates > Windows Components >
Delivery Optimization; registry `DODownloadMode` = 100) and a device-wide proxy, or allow direct HTTP to
`*.delivery.mp.microsoft.com`. Without either, the fix's download step times out and the job stops with nothing changed.

### The agent updates itself

At each run the agent asks your server for a newer release. It installs one only if the release is signed by the Nimstead release key built into the agent, and only if it's newer than the version already running. Your server passes the release along but can't sign one, so even a compromised server can't push code to your machines. The agent then runs the new version's inventory on the machine before switching. If that fails, it keeps the old version and the reason shows on the **Assets** page. The previous version is kept beside it as `nimstead_agent.py.prev`.

- **Pause it for the whole organisation:** **Settings → Agent updates**.
- **Turn it off on one machine:** enrol with `--no-auto-update`. That machine then shows **Agent outdated** after each release until you rerun the install command.
- **Agents older than 0.2.0** can't update themselves. Rerun the install command on each once; the enrolment is kept.
- **Channels:** an agent takes releases signed for its server's channel at install time (`--channel`, set by the install command) or anything more proven, so a stable machine never runs a preview build, whatever the server hands it. Agents enrolled before 0.3.0 take every channel until you rerun the install command.

### Install without trusting the server

Updates have to be signed, but the first copy of the agent comes from your server, so a compromised server could hand new machines a modified one (machines already enrolled are unaffected). The install command prints the `agent sha256` it installed. To be sure of a machine, compare it with the signed release:

1. From the [GitHub release](https://github.com/Nimstead/assure/releases) your server runs, download `release.json`, `release.json.sig` and `nimstead_agent.py`.
2. Check the signature with an agent you already trust: `python3 nimstead_agent.py verify-release release.json release.json.sig` prints the manifest only if a pinned Nimstead release key signed it (key fingerprints `a91fa653…` and backup `2438f2cc…`, also in `RELEASE_KEYS` at the top of the agent).
3. The manifest's `agent_sha256` must equal `sha256sum nimstead_agent.py` and the `agent sha256` the installer printed. On Windows, the `runtime sha256` it printed must equal the manifest's `runtimes.amd64.sha256` (or `arm64` / `win32`). Or skip the installer: copy this verified file to `/usr/local/lib/nimstead/` yourself, then run its `enroll --server https://… --channel stable`, `report` and `schedule` as root, with `NIMSTEAD_TOKEN` set.

A machine that hasn't reported for 14 hours shows **Not reporting** and sends one alert, so a stopped agent doesn't quietly leave stale findings.

### Troubleshooting

Run `doctor` on the machine. It checks the server, proxy, clock, schedule, disk and Python, and on Windows also the state folder's permissions and the Windows Update service. Each check prints `ok` or `FAIL` with one line on how to fix it, and the command exits non-zero if any failed. It changes nothing on the machine and doesn't send the agent key.

```bash
sudo python3 /usr/local/lib/nimstead/nimstead_agent.py doctor
```

On Windows, in an elevated PowerShell: `& (Resolve-Path "$env:ProgramFiles\Nimstead\runtime\*\python.exe")[0] -I "$env:ProgramFiles\Nimstead\nimstead_agent.py" doctor`. A stopped Windows Update service is normal, because it starts when needed; only a disabled one fails.

The agent logs each run's start and end, job outcomes and errors to `/var/lib/nimstead/agent.log` on Linux and `C:\ProgramData\Nimstead\agent.log` on Windows. Only root or Administrators can read it. It keeps at most about 2 MB (`agent.log` and `agent.log.1`), and leaves out the agent key and enrolment token.

### Remove the agent

```bash
sudo python3 /usr/local/lib/nimstead/nimstead_agent.py uninstall --yes
```

On Windows, in an elevated PowerShell: `& (Resolve-Path "$env:ProgramFiles\Nimstead\runtime\*\python.exe")[0] -I "$env:ProgramFiles\Nimstead\nimstead_agent.py" uninstall --yes`. This removes the timers or scheduled tasks, the agent key, saved state, the local log and the agent itself, then tells you to delete the machine on the **Assets** page. It's refused while a Windows update is waiting for its restart.

### Fixing things automatically

Remediation is off until you turn it on in three places:

1. **The host opts in** at install with `--allow-remediation` (on Windows, `$env:NIMSTEAD_ALLOW_REMEDIATION = "1"` before the install command). The server can never turn this on.
2. **Start with test machines.** When you add a machine, choose **Test machines** (sandbox) for disposable or staging hosts; the choice is fixed for every machine enrolled with that command. Until you set `NIMSTEAD_ALLOW_PRODUCTION_REMEDIATION=1` in `.env` and restart, fixes only ever target test machines.
3. **You approve each fix,** or move up the **trust ladder** in **Settings** to let some fixes run on their own. Fixes go to canary hosts first, then the rest.

Every fix takes a rollback copy first, refuses to touch anything outside the plan, checks your services afterwards and rolls back on its own if they fail. It only counts as fixed when the next inventory shows it.

**Tell it which services matter.** On the **Assets** page, list each machine's important services under **Health units** (for example `nginx, postgresql`). After a change the agent waits 15 seconds, then each one must be running and must not have been restarted since the change, so a service stuck restarting counts as broken. On Windows it waits 60 seconds after the update, then checks each service is running.

## Upgrade

**Settings → This server** shows your version and says when a newer release is out on your **channel** (alert targets hear about it once). Releases come in three channels: **preview** (earliest, may break), **beta** (feature-complete, being proven) and **stable** (public). `NIMSTEAD_UPDATE_CHANNEL` in `.env` picks one. It defaults to `stable`, and a server also takes anything more stable than its channel. There's no stable release yet, so set `NIMSTEAD_UPDATE_CHANNEL=preview` to follow the current releases.

To install the update, run this in the checkout on the Docker host:

```bash
sudo deploy/update.sh
```

It updates only to a release signed by the Nimstead release key, and only if the release tag points at exactly the signed commit. Your checkout must have no local changes or untracked files (`.env`, `backups/` and other ignored files are fine; a `compose.override.yaml` is not used), and when run as root every file in the checkout must be owned by root and not writable by anyone else, because the timer runs this script as root. It builds the new version while the old one keeps serving, then stops the server for a moment to back up a quiet database to `backups/`. It starts the new version (migrations run on start) and waits up to 5 minutes for `/api/health` to answer for it, then restarts the feed updates. If that doesn't happen, it puts the previous version back with the database from the backup. The outcome shows in **Settings**, and a failure alerts. Add `--dry-run` to see what it would do.

To install releases on their own each night (03:00–04:00), turn on the timer once:

```bash
sudo deploy/update.sh --install-timer
```

Agents then update themselves from the new release at their next run.

## Back up

Back up both volumes together: `pg` (the database) and `data` (signing keys and checkpoints). Without the signing key, new evidence packs get a new fingerprint and you'll need to send it to your auditor again. Pause `feeds` meanwhile, because it writes signed checkpoints of the ledger, so the two copies match. Write the backups outside the checkout (`deploy/update.sh` refuses untracked files in it):

```bash
docker compose stop feeds
```

```bash
docker compose exec -T db pg_dump -U nimstead nimstead > ~/nimstead.sql
```

```bash
docker compose cp app:/data ~/nimstead-data
```

```bash
docker compose start feeds
```

Run this at least daily and keep copies off the host. What a restore loses is what changed since the last backup: inventories come back at the agents' next 6-hourly run, but ledger entries made after the backup are gone. With checkpoints in object-locked S3, a restore from before the newest checkpoint shows as a shortened ledger on **Evidence**. That's the tamper evidence doing its job: restore the newest backup, and note the restore in your records for the auditor. A restore takes minutes.

### Restore

On a fresh host, with the same release checked out and the same `.env`, from the checkout:

```bash
docker compose up -d db
```

```bash
docker compose exec -T db psql -U nimstead -d nimstead < ~/nimstead.sql
```

```bash
docker compose run --rm --no-deps -T --user root -v "$HOME/nimstead-data:/restore:ro" --entrypoint sh app -c 'cp -R /restore/. /data/ && chown -R nimstead /data'
```

```bash
docker compose up -d
```

Then open **Evidence**: *Chain verified* means the ledger matches its signed checkpoints, and the key fingerprint should be the one your auditor has.

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

## Scan Windows hosts with no agent

From a Windows machine with the agent's files, signed in as an admin of the hosts:

```powershell
$env:NIMSTEAD_TOKEN = '<enrolment token>'   # only the first time a host is seen
python nimstead_agent.py scan-remote --server https://your-server host1 host2
```

It uses PowerShell remoting as you: no credential is typed, stored or sent to the server. Each host needs remoting on. Note that `Enable-PSRemoting` on a machine outside a domain sets `LocalAccountTokenFilterPolicy=1`, which Nimstead then reports as `remote-uac`. Hosts scanned this way get findings but not fixes: fixes need the agent. Each host's report key is saved in `.nimstead-remote-scan.json` in your profile, so keep that file private.
