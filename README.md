# Nimstead

Vulnerability scanning, patch assurance, audit evidence and safe automatic remediation in one product.

- **Accurate, low-noise detection:** agents report installed packages, and Nimstead matches them against OSV advisories using each distro's own version rules and source-package names. Backported fixes aren't flagged. Results are tested to agree with the OSV API on real data.
- **Prioritised by real-world risk:** CISA KEV first, then EPSS likelihood, CVSS, asset criticality and internet exposure, with a plain-English reason for every score. The home screen shows fix *actions* ("upgrade openssl → fixes 12 vulnerabilities on 3 hosts"), not a wall of CVEs.
- **Evidence an auditor can check:** every detection, fix and decision is recorded in a hash-chained ledger with signed off-database checkpoints. Ed25519-signed evidence packs map to Cyber Essentials, ISO 27001 A.8.8, NIST RA-5/SI-2, PCI DSS 6.3.3 and CIS 7, and verify offline against a pinned key fingerprint.
- **Remediation you can switch on:**
  - Every change saves a rollback package first (rebuilt from the installed files if the archive no longer has it).
  - A dry run refuses any change that would touch packages outside the plan.
  - Services are health-checked, and a failure triggers automatic rollback.
  - Changes go to canaries first; the broad ring is pinned to the versions the canaries proved.
  - Success is confirmed by the next inventory, never by the agent's say-so.

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
- **Evidence storage:** set `NIMSTEAD_SIGNING_KEY_FILE`, and point `NIMSTEAD_CHECKPOINT_DIR` at WORM/object-locked storage. Publish the key fingerprint (`GET /api/evidence/public-key`) to auditors out of band.
- **Remediation guard:** remediation only targets assets enrolled with a sandbox token until you set `NIMSTEAD_ALLOW_PRODUCTION_REMEDIATION=1`.
- **Single sign-on (OIDC):** an org admin sets issuer, client ID/secret and allowed email domains in Settings, and registers `<NIMSTEAD_PUBLIC_URL>/api/auth/sso/callback` at the IdP. Authorization code flow with PKCE, state and nonce; ID tokens are checked for signature (JWKS), issuer, audience, expiry, nonce, verified email and allowed domain. Users are created on first sign-in (never admins), and an email that already belongs to another organisation is refused. "Require SSO" turns off password login for the org, so test SSO first. Login flows are held in memory: run one API process (or move them to a shared store). Domains are not verified by DNS: don't offer self-service SSO to untrusted tenants yet.
- **Failure alerts:** admins set an `https` webhook (Slack-compatible `{"text": �}` or generic JSON) and/or email recipients in Settings. For email set `NIMSTEAD_SMTP_URL` (`smtp://user:pass@host:587`, STARTTLS when offered, or `smtps://host:465`) and `NIMSTEAD_SMTP_FROM`. Alerts fire on remediation `rolled_back`, `rollback_failed` (urgent), `failed`, `not_fixed`, `aborted`, and when findings newly become fix-now (one message per machine per rescan). Delivery is in a background thread with short timeouts; webhook targets that resolve to private, loopback or link-local addresses are refused. Every attempt is recorded and a failed one shows in Settings. There is no retry or persistent queue.
- **AI (optional):** set `ANTHROPIC_API_KEY` to enable plain-English explanations and natural-language search.

## Tests

- **API:** `cd api && uv run pytest -q`
- **Web:** `cd web && npm test && npm run e2e`
- **Real-host end to end in a disposable WSL distro:** `cd api && uv run python ../sandbox/sbx.py`
- **Full suite on PostgreSQL in a disposable distro:** `cd api && uv run python ../sandbox/pg.py`

See [STATUS.md](STATUS.md) for what is and isn't proven, and [DECISIONS.md](DECISIONS.md) for why things are the way they are.
