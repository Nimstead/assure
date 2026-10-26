<h1 align="center">Nimstead Assure</h1>

<p align="center"><b>Find what's vulnerable. Fix it safely. Prove it to an auditor.</b></p>

<p align="center">
  <a href="https://github.com/Nimstead/assure/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/Nimstead/assure/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="Python 3.14" src="https://img.shields.io/badge/python-3.14-0b0b0b">
  <img alt="PostgreSQL 17" src="https://img.shields.io/badge/postgresql-17-0b0b0b">
  <img alt="Licence: proprietary" src="https://img.shields.io/badge/licence-proprietary-b3122e">
</p>

<p align="center"><img src="docs/images/home-1440.png" alt="The Fix first screen: open findings by priority, and the one upgrade that clears the most risk" width="900"></p>

Vulnerability scanning, patch assurance, audit evidence and safe automatic remediation in one product. It shows the upgrades that clear the most risk instead of a wall of CVEs, can apply those upgrades for you with rollback, and records each step in a tamper-evident ledger an auditor can check offline.

## What it does

- **Accurate, low-noise detection:** agents report installed packages, and Nimstead matches them against OSV advisories using each distro's own version rules and source-package names. Backported fixes aren't flagged. Results are tested to agree with the OSV API on real data.
- **Application dependencies too:** add an application on the Assets page and upload a CycloneDX (JSON 1.4-1.6) or SPDX (JSON 2.2/2.3) SBOM (not XML or SPDX tag-value; via the UI or `POST /api/assets/{id}/sbom` from CI with the asset's upload token); PyPI, npm, Maven, NuGet, RubyGems, Go, crates.io, Packagist (Composer), Hex and Pub packages are matched like OS packages.
- **Prioritised by real-world risk:** CISA KEV first, then EPSS likelihood, CVSS, asset criticality and internet exposure, with a plain-English reason for every score. The home screen shows fix *actions* ("upgrade openssl → fixes 12 vulnerabilities on 3 hosts"), not a wall of CVEs.
- **Evidence an auditor can check:** every detection, fix and decision is recorded in a hash-chained ledger with signed off-database checkpoints. Ed25519-signed evidence packs map to Cyber Essentials, ISO 27001 A.8.8, NIST RA-5/SI-2, PCI DSS 6.3.3 and CIS 7, and verify offline against a pinned key fingerprint.
- **Remediation you can switch on:**
  - Every change saves a rollback package first (rebuilt from the installed files if the archive no longer has it).
  - A dry run refuses any change that would touch packages outside the plan.
  - Services are health-checked, and a failure triggers automatic rollback.
  - Changes go to canaries first; the broad ring is pinned to the versions the canaries proved.
  - Success is confirmed by the next inventory, never by the agent's say-so.

| Why a finding matched, and why it's ranked there | Controls an auditor can check | Light and dark, down to phone width |
|---|---|---|
| ![Finding detail: installed vs fixed version, risk signals, advisories](docs/images/findings-1440.png) | ![Evidence: Cyber Essentials, ISO 27001, NIST, PCI DSS and CIS control status](docs/images/evidence-1440.png) | ![Fix first in dark mode at 375px](docs/images/home-375-dark.png) |

## How it works

```mermaid
flowchart LR
  subgraph Hosts
    A["Agent<br/>(Linux / Windows)"]
  end
  CI["CI pipeline"] -- "SBOM" --> API
  A -- "inventory every 6 h" --> API["API server"]
  API -- "approved fix jobs" --> A
  F["Feeds hourly<br/>OSV · NVD · KEV · EPSS · MSRC"] --> API
  API --> DB[("PostgreSQL")]
  API --> L["Hash-chained ledger<br/>+ signed checkpoints"]
  L --> P["Ed25519 evidence pack<br/>(verifies offline)"]
  API --> UI["Web UI"]
  API -. "TCP + TLS checks<br/>(DNS-proven owned hosts)" .-> X["Internet-facing hosts"]
```

1. **Inventory.** The agent (one stdlib-only Python file) reports installed packages. CI uploads SBOMs for applications.
2. **Match.** The server matches packages against advisories using each ecosystem's own version rules, then scores each finding by real-world risk.
3. **Fix.** An admin approves a fix (or turns on auto-remediation). It goes to canary hosts first, with a dry run, health checks and automatic rollback.
4. **Verify.** A fix only counts once the next inventory shows the vulnerability is gone. Every step lands in the ledger.

## Proven on real systems

Not just unit tests. Each of these ran end to end in a disposable VM or WSL distro; the logs are in [`sandbox/`](sandbox) and the details in [STATUS.md](STATUS.md).

| Platform | Detect | Fix verified by inventory | Automatic rollback |
|---|---|---|---|
| Debian 13 · Ubuntu 24.04 | ✓ | ✓ apt | ✓ after a real service failure |
| AlmaLinux 9 | ✓ | ✓ dnf | ✓ after a real service failure |
| Alpine 3.21 | ✓ | ✓ apk | ✓ after an injected failure |
| openSUSE Leap 16.0 | ✓ | ✓ zypper | ✓ after a real service failure; snapper also undoes install-script side effects |
| Windows Server 2025 | ✓ | ✓ cumulative update as SYSTEM | ✓ after an injected failure (DISM removal); permanent updates refused up front |

Plus real Keycloak SSO, DNS, SMTP and webhook integrations, Vault and S3 object-lock key storage, and 1,000-host performance runs on SQLite and PostgreSQL 17.

## Repository layout

| Directory | What it is |
|---|---|
| [`api/`](api) | Server: FastAPI + SQLAlchemy (SQLite for dev, PostgreSQL in production), feeds, matching, risk, remediation, evidence |
| [`agent/`](agent) | The agent: one stdlib-only Python file for Linux (apt, dnf, zypper, apk) and Windows |
| [`web/`](web) | The UI: React + TanStack, served by the API once built |
| [`sandbox/`](sandbox) | Real-host and real-service proofs in disposable WSL distros and VMs |
| [`docs/`](docs) | Images for this README |

The brand guidelines live in [Nimstead/brand](https://github.com/Nimstead/brand).

## Quick start (local)

```bash
cd web && npm install && npm run build
```

```bash
cd api && NIMSTEAD_SECURE_COOKIES=0 uv run uvicorn --factory nimstead.app:create_app --port 8000
```

Open http://localhost:8000, create an account, and follow "Add your first machine". To load real vulnerability data:

```bash
cd api && uv run python -m nimstead.feeds update
```

Run that hourly (cron or a systemd timer). It refreshes KEV, EPSS, NVD and OSV for the ecosystems your assets use, re-matches every asset, and writes a ledger checkpoint.

## Production notes

- **Database:** set `NIMSTEAD_DB=postgresql+psycopg://…` and run `cd api && uv run alembic upgrade head`.
- **Public URL:** set `NIMSTEAD_PUBLIC_URL` to the HTTPS address agents use. Keep `NIMSTEAD_SECURE_COOKIES` on (the default).
- **Keys and evidence storage:** for production, set `NIMSTEAD_VAULT_ADDR` + `NIMSTEAD_VAULT_TOKEN`. Evidence signing, the SSO secret and domain tokens then use Vault transit, and keys never leave Vault. Set `NIMSTEAD_CHECKPOINT_S3=s3://bucket/prefix` (bucket created with object lock; `NIMSTEAD_S3_ENDPOINT` for non-AWS) for write-once ledger checkpoints. Without these, on-disk key files are used (dev only). Publish the key fingerprint (`GET /api/evidence/public-key`) to auditors out of band.
- **Remediation guard:** remediation only targets assets enrolled with a sandbox token until you set `NIMSTEAD_ALLOW_PRODUCTION_REMEDIATION=1`.
- **Single sign-on (OIDC):** an org admin sets issuer, client ID/secret and allowed email domains in Settings, and registers `<NIMSTEAD_PUBLIC_URL>/api/auth/sso/callback` at the IdP. Authorization code flow with PKCE, state and nonce; ID tokens are checked for signature (JWKS), issuer, audience, expiry, nonce, verified email and allowed domain. Users are created on first sign-in (never admins), and an email that already belongs to another organisation is refused. "Require SSO" turns off password login for the org, so test SSO first. Each email domain must be proven with a DNS TXT record before it routes sign-ins. Pending logins live in the database, so several API processes are fine.
- **Failure alerts:** admins set an `https` webhook (Slack-compatible `{"text": …}` or generic JSON) and/or email recipients in Settings. For email set `NIMSTEAD_SMTP_URL` (`smtp://user:pass@host:587` with STARTTLS, or `smtps://host:465`; credentials are never sent unencrypted) and `NIMSTEAD_SMTP_FROM`. Alerts fire on remediation `rolled_back`, `rollback_failed` (urgent), `failed`, `not_fixed`, `aborted`, and when findings newly become fix-now (one message per machine per rescan). Delivery is in a background thread with short timeouts; webhook targets that resolve to private, loopback or link-local addresses are refused, and the connection goes to the address that was checked. Every attempt is recorded, a failed one shows in Settings, and failed alerts are retried up to 3 times by the hourly `feeds update`.
- **Behind a reverse proxy:** run uvicorn with `--proxy-headers --forwarded-allow-ips <proxy IP>` so sign-in throttling sees real client addresses (otherwise every user shares the proxy's).
- **Roles:** the person who signs up is the org admin. Users created by SSO can view everything but only admins can enrol machines, plan or approve fixes, change the remediation policy, accept risk or delete assets.
- **Windows agents:** need an all-users Python under Program Files (`winget install Python.Python.3.13 --scope machine`); the installer refuses a per-user one, because the SYSTEM task would run it.
- **External scans:** admins add internet hostnames on the Assets page and prove ownership with a DNS TXT record; scans run on demand and with the hourly `feeds update`. The server needs outbound access to the targets; names resolving to private addresses are refused.
- **AI (optional):** set `ANTHROPIC_API_KEY` to enable plain-English explanations and natural-language search.

## Tests

- **API:** `cd api && uv run pytest -q`
- **Web:** `cd web && npm test && npm run e2e`
- **Real-host end to end in a disposable WSL distro:** `cd api && uv run python ../sandbox/sbx.py`
- **Full suite on PostgreSQL in a disposable distro:** `cd api && uv run python ../sandbox/pg.py`

See [STATUS.md](STATUS.md) for what is and isn't proven, [DECISIONS.md](DECISIONS.md) for why things are the way they are, and [CONTRIBUTING.md](CONTRIBUTING.md) for how to work on it.

## Licence

Proprietary. All rights reserved; see [LICENSE](LICENSE). Report security issues as described in [SECURITY.md](SECURITY.md).
