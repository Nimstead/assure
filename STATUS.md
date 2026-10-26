# Nimstead — status

Read this first each session. Decisions and their reasons: DECISIONS.md (items 1–21). Quick start: README.md.

## Done (with evidence)
| Area | Where | Evidence |
|---|---|---|
| Version comparators: dpkg, rpm, apk, semver, PEP 440, Maven, NuGet, RubyGems, Windows build | `api/src/nimstead/versions.py` | Table tests from each reference suite |
| OSV matcher (source-package, backports, CVE dedup, withdrawn) | `match.py` | Exact agreement with the OSV API on 31 real package/version cases across Debian, Ubuntu, Alpine, Rocky, PyPI, npm, Maven (log4j-core, jackson-databind), NuGet, RubyGems |
| Windows OS detection via MSRC (FixedBuild/KB per product) | `feeds.py` (`sync_msrc`), agent | Real MSRC sync + real agent→server run on this Windows 11 machine (0 findings, fully patched; 1,009 at one build below, all one KB) |
| SBOM ingest (CycloneDX 1.4–1.6, purl → ecosystem), application assets with upload tokens | `sbom.py`, `app.py` | `tests/test_sbom.py` incl. log4j-core 2.14.1 → CVE-2021-44228 |
| Risk scorer (KEV override, EPSS, CVSS, criticality, exposure, fix) with reasons | `risk.py` | `tests/test_risk.py` |
| Feeds: OSV (incremental, releases in use only), KEV, EPSS, NVD CVSS, MSRC; `feeds update` re-matches assets, checkpoints the ledger, retries failed alerts | `feeds.py` | Mocked tests + real runs (KEV 1,756; EPSS 395k; OSV Debian 196k, Ubuntu 3.3M, Alpine, AlmaLinux 26k; MSRC 46k) |
| API: auth (argon2, throttled in DB), enrol tokens, agent enrol/inventory, findings, assets, summary, install.sh + install.ps1, serves the built UI | `app.py`, `db.py`, `scan.py` | `tests/test_api.py` incl. tenant isolation, CSRF/Origin, 413, Host-header injection |
| SSO (OIDC code + PKCE, state, nonce, JWKS), DNS-TXT domain verification, encrypted client secret, admin break-glass | `sso.py`, `app.py` | `tests/test_sso.py` (27, fake IdP + fake DNS) |
| Failure alerts (Slack-compatible/generic webhook, SMTP), SSRF-guarded, recorded, retried up to 3× | `notify.py`, `netguard.py` | `tests/test_notify.py` (21, mocked transports) |
| Multi-worker safe state: login throttle, inventory rate limit, SSO pending logins in the DB | `db.py`, `app.py` | Full suite |
| DB: SQLite (dev), PostgreSQL via Alembic (linear history) | `migrations/` | `tests/test_migrations.py`; full suite on PostgreSQL 17 via `sandbox/pg.py` |
| Evidence: hash-chained ledger, signed off-DB checkpoints, Ed25519 packs (pinned fingerprint), control mapping, ledger-derived timings | `evidence.py`, `verify_pack.py` | `tests/test_evidence.py` incl. forgery, consistent rewrite, truncation |
| Remediation server: trust ladder, canary + soak, broad ring pinned to canary versions, halts, kill switch, sweeps, inventory-verified success | `remediate.py` | `tests/test_remediate.py` |
| Agent remediation: apt (old .deb or rebuilt), apk + dnf (file + package-DB snapshot); dry-run scope check, health checks, auto-rollback, persisted outcomes, Windows key ACL | `agent/nimstead_agent.py` | Unit tests + **real-host E2E PASS in disposable VMs on Debian 13, Ubuntu 24.04, AlmaLinux 9 and Alpine 3.21** (`sandbox/last_run_*.json`) |
| Windows remediation: one cumulative update by KB via Windows Update Agent (as SYSTEM), state persisted across reboots, health checks, rollback = DISM removal of the new package with retries for servicing-busy errors | agent `WinJob`, `remediate.py` | `tests/test_winjob.py` (9) + **real Windows Server 2025 VM PASS**: install.ps1 elevated (enrol, report, SYSTEM task with startup trigger); forced-failure rollback 26100.33650 → DISM removal → reboot → 26100.32230 restored; then the installed scheduled task alone installed KB5126646, rebooted, resumed at startup and reported, and the server marked the job succeeded from fresh inventory (0 open findings, evidence verified) — `sandbox/last_run_windows*.json` |
| Real-service integrations: Keycloak OIDC login, DNS TXT verification (dnsmasq), SMTP + HTTPS webhook alerts, dead-webhook retry | `sandbox/integrations.py` | **PASS** in a disposable WSL VM (`sandbox/last_run_integrations.json`) |
| Optional AI (Claude Opus 5.5): explanations, NL search → validated filter | `ai.py` | Mocked client only |
| Web UI: onboarding, Fix-first home, findings, assets (+applications/SBOM), remediation, evidence, settings (trust ladder, tokens, SSO + domain verification, alerts) | `web/` | build clean; 17 vitest; Playwright e2e + axe (0 serious/critical) |

Real-host E2E (fresh WSL distro each, destroyed after):

| Distro | Packages | Findings | Upgrade verified by inventory | Rollback |
|---|---|---|---|---|
| Debian 13 | 164 | 274 | openssl | perl, real service failure, rebuilt .deb |
| Ubuntu 24.04 | 523 | 369 | curl | glib2.0, real service failure |
| AlmaLinux 9 | 207 | 50 | glibc | libxml2, real service failure, snapshot |
| Alpine 3.21 | 32 | 45 | musl | openssl, injected failure (no systemd), snapshot |

All four evidence packs verified, with 6/6 controls met. On Alpine, the dry run refused the openssl fix because it also needed musl. Re-planning "including musl" (which pulls in musl-utils, from the same source package) succeeded and was verified fixed (40 findings resolved).

**Last runs (final code):** API 358 passed on SQLite (foreign keys enforced) and 358 passed on PostgreSQL 17 · web 18 unit + 4 Playwright e2e (axe clean in light and dark) · real-host E2E PASS on all four distros.

## NOT proven / known gaps (honest)
- **AI** has never been called against the real API (no key on this machine).
- **Windows remediation:** proven on Windows Server 2025 Core. Windows 10/11 clients are not yet run in a VM, and a cumulative update Windows marks permanent can't be removed (reported as rollback_failed, never as success). The VM run was split into rollback and success passes because a VirtualBox update interrupted it.
- **Windows third-party apps** are not covered: there's no reliable advisory source keyed by installed software.
- **Snapshot rollback** doesn't reverse maintainer-script side effects (health checks cover the visible ones). Kernel/install-only packages are refused.
- **Dependency upgrades are never silent:** when a fix needs another package, the dry run refuses it and the user re-plans "including X" with one click. Nothing expands on its own.
- **SBOM:** CycloneDX JSON only (no SPDX/VEX). Findings mean "present", not "reachable".
- **Secrets:** the signing and secret keys are files on disk; use KMS in production. Checkpoints need WORM storage.
- **Ecosystems:** no Go/crates beyond semver, and no Conda/Composer/Hex comparators.

## Needs the user
- Optional: an Anthropic API key to enable and live-test AI.

## Run
- **API:** `cd api && uv run pytest -q` · lint: `uv run ruff check src tests ../agent ../sandbox`
- **App:** `cd web && npm run build`, then `cd api && NIMSTEAD_SECURE_COOKIES=0 uv run uvicorn --factory nimstead.app:create_app --port 8000`
- **Feeds:** `cd api && uv run python -m nimstead.feeds update` (hourly)
- **Web:** `cd web && npm test` · `npm run e2e`
- **Real-host E2E:** `cd api && uv run python ../sandbox/sbx.py --distro Debian|Ubuntu-24.04|AlmaLinux-9|alpine-3.21.0`
- **PostgreSQL suite:** `cd api && uv run python ../sandbox/pg.py`
