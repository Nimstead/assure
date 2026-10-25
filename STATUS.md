# Nimstead — status

Read this first each session. Decisions and their reasons: DECISIONS.md (items 1–15). Quick start: README.md.

**State: v1 complete.** All planned milestones (M0–M8) are built, tested, and proven end to end on real Linux hosts in disposable VMs. What isn't proven is listed below.

## Done (with evidence)
| Area | Where | Evidence |
|---|---|---|
| Version comparators dpkg/rpm/apk/semver/PEP 440 | `api/src/nimstead/versions.py` | 60 table tests from reference suites |
| OSV matcher (source-package, backports, CVE dedup, withdrawn) | `match.py` | Exact agreement with the OSV API on 16 real cases (`tests/test_match.py`) |
| Risk scorer (KEV override, EPSS, CVSS, criticality, exposure, fix) with reasons | `risk.py` | `tests/test_risk.py` |
| Feeds: OSV bulk (incremental, only releases in use), CISA KEV, FIRST EPSS, NVD CVSS 2.0; `feeds update` re-matches all assets and checkpoints the ledger | `feeds.py` | Mocked tests + real runs: KEV 1,756, EPSS 395,308, NVD 21,041, OSV Debian 195,692 / Ubuntu 3.3M rows |
| API: auth (argon2, timing-safe, throttled), enrol tokens (expiry, revoke), agent enrol/inventory (rate-limited), findings, assets, fix-action summary, install.sh, serves the built UI | `app.py`, `db.py`, `scan.py` | `tests/test_api.py` incl. tenant isolation, CSRF/Origin, 413, Host-header injection |
| DB: SQLite (dev) and PostgreSQL via Alembic | `migrations/` | `tests/test_migrations.py`; **full suite (163) passes on PostgreSQL 17** (`sandbox/pg.py`) |
| Evidence: hash-chained ledger, signed off-database checkpoints, Ed25519 packs with pinned-fingerprint verification, control mapping, ledger-derived timings | `evidence.py`, `verify_pack.py` | `tests/test_evidence.py` incl. re-signed forgery, consistent full-chain rewrite, truncation, findings-table edits |
| Remediation server: trust ladder, canary + soak, broad ring pinned to canary versions, halt on failure, kill switch at dispatch, stale-job sweep, late reports, inventory-verified success | `remediate.py` | `tests/test_remediate.py` |
| Agent (apt): dry-run scope check, rollback package (archive copy, or rebuilt from installed files), sha256-checked, health checks with settle, auto-rollback, persisted outcomes, run lock | `agent/nimstead_agent.py` | Unit tests + **real hosts:** Debian 13 and Ubuntu 24.04 sandbox E2E PASS (`sandbox/last_run_*.json`) |
| Optional AI (Claude Opus 5.5, fallbacks on): explanations, NL search → validated filter | `ai.py` | `tests/test_ai.py`, mocked client only |
| OIDC SSO per org (code + PKCE + state + nonce, JIT users, SSO-required, same-org only) | `sso.py`, `app.py` | `tests/test_sso.py` (fake IdP, 22 cases) |
| Failure alerts (Slack/JSON webhook, SMTP), SSRF-guarded, recorded, off the request path | `notify.py`, `netguard.py`, hooks in `remediate.py`/`scan.py` | `tests/test_notify.py` |
| Web UI: onboarding, Fix-first home, findings + drawer, assets, remediation, evidence, settings, Ctrl+K, dark/light, mobile | `web/` | build clean; 14 vitest; 4 Playwright e2e incl. full flow + axe (0 serious/critical) |

Real-host E2E (each in a fresh WSL distro, destroyed afterwards):
- **Debian 13:** 164 packages, 274 findings. The openssl upgrade was proven fixed by the next inventory (38 resolved). A forced service failure after the perl upgrade rolled back with versions restored. Evidence pack verified; 6/6 controls met.
- **Ubuntu 24.04:** 523 packages, 369 findings. Same flow, with curl upgraded and glib2.0 rolled back. Evidence pack verified.

Last runs: API 205 passed on SQLite (the 163 earlier tests also passed on PostgreSQL 17; the new SSO/alert tests were not re-run there) · web 15 unit passed, build clean; Playwright e2e not re-run.

## NOT proven / known gaps (honest)
- **AI never called against the real API** (no key on this machine). The UI hides it unless `ANTHROPIC_API_KEY` is set.
- **Remediation is apt-only** (Debian/Ubuntu). Alpine and RHEL-family are detection-only: no trustworthy rollback artefact yet (DECISIONS 15).
- **Windows** agent reports no packages, so there's no Windows detection. Maven/NuGet/RubyGems comparators are missing.
- **Single API process assumed:** the login and inventory throttles are in-memory. Run one worker, or move them to a shared store.
- **SSO and alerts (new) are tested against a fake IdP / mocked webhook and SMTP only**, never a real IdP, Slack or mail server. The web UI for both is build- and unit-checked only; the Playwright e2e was not re-run or extended.
- SSO: login flows in memory (single process); email domains aren't DNS-verified; client secret stored unencrypted in the DB; no SCIM/deprovisioning, no group/role mapping, and "Require SSO" has no break-glass if the IdP breaks. Roles are just admin (org creator) or not; existing users were migrated as admins.
- Alerts: no retry or persistent outbox (a restart drops queued messages), SSRF check resolves DNS before connecting so a rebinding window remains, no notification retention policy.
- Web e2e doesn't cover the AI UI, token revoke or asset delete. Moderate/minor axe issues unreviewed.
- Signed checkpoints are only as strong as their storage: point `NIMSTEAD_CHECKPOINT_DIR` at WORM/object-lock storage in production.

## Needs the user
- Optional: an Anthropic API key to enable and live-test the AI features.

## Next (v2)
1. Windows inventory (winget/registry) + matching source.
2. Alpine rollback strategy (local apk cache from enrolment onward), then apk remediation; dnf via `dnf download` + sandbox proof on AlmaLinux 9.
3. Shared store for throttles and SSO flows; DNS-verified SSO domains; alert retry/outbox.

## Run
- API tests: `cd api && uv run pytest -q` · lint: `uv run ruff check src tests ../agent ../sandbox`
- API + UI: `cd web && npm run build`, then `cd api && NIMSTEAD_SECURE_COOKIES=0 uv run uvicorn --factory nimstead.app:create_app --port 8000`
- Feeds: `cd api && uv run python -m nimstead.feeds update` (hourly in prod)
- Web dev: `cd web && npm run dev` · `npm test` · `npm run e2e`
- Real-host E2E: `cd api && uv run python ../sandbox/sbx.py [--distro Ubuntu-24.04]` · Postgres suite: `uv run python ../sandbox/pg.py`
