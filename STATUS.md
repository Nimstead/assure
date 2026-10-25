# Nimstead — status

Read this first each session. Decisions and their reasons: DECISIONS.md (items 1–14).

## Done (with evidence)
| Area | Where | Evidence |
|---|---|---|
| Version comparators dpkg/rpm/apk/semver/PEP 440 | `api/src/nimstead/versions.py` | 60 table tests from reference suites |
| OSV matcher (source-package, backports, CVE dedup, withdrawn) | `match.py` | Exact agreement with the OSV API on 16 real cases (`tests/test_match.py`) |
| Risk scorer (KEV override, EPSS, CVSS, criticality, exposure, fix) with reasons | `risk.py` | `tests/test_risk.py` |
| Feeds: OSV bulk (incremental), CISA KEV, FIRST EPSS, NVD CVSS 2.0; `feeds update` re-matches all assets | `feeds.py` | Mocked tests + real runs: KEV 1,756, EPSS 395,308, OSV Alpine 44,512, NVD modified 21,041 |
| API: auth (argon2, timing-safe), enrol tokens (30-day expiry, revoke), agent enrol/inventory, findings (+kev filter), assets (+delete), fix-action summary, install.sh + agent download | `app.py`, `db.py`, `scan.py` | `tests/test_api.py` incl. tenant isolation, Origin/CSRF, 413, Host-header injection |
| Evidence: hash-chained ledger, Ed25519 packs with pinned-fingerprint verification, control mapping, ledger-derived timings, chain head | `evidence.py`, `verify_pack.py` | `tests/test_evidence.py` incl. re-signed forgery, DB edits of findings table |
| Remediation server: trust ladder, canary + soak, broad ring pinned to canary versions, halt on failure, kill switch at dispatch, stale-job sweep, late reports, inventory-verified success | `remediate.py` | `tests/test_remediate.py` (13 tests) |
| Agent executor (apt, apk): dry-run scope check, rollback copies + sha256, health checks with settle, auto-rollback, outcomes persisted + retried, run lock, no-redirect HTTP, local opt-in | `agent/nimstead_agent.py` | `tests/test_agent_remediate.py` simulated apt host (15 tests) |
| Optional AI (Claude Opus 5.5, fallbacks on): plain-English explanations, NL search → validated filter | `ai.py` | `tests/test_ai.py` with a mocked client only |
| Web UI: onboarding, Fix-first home, findings + drawer (AI explain/ask when enabled, KEV filter), assets, remediation, evidence (key fingerprint), settings (tokens), Ctrl+K, dark/light, mobile | `web/` | build clean; 14 vitest; `npm run e2e` 4 Playwright tests incl. full flow + axe (0 serious/critical, light+dark) + 375px overflow checks |
| Sandbox harness: disposable WSL distro E2E (detect → remediate → verify → forced-failure rollback → evidence) | `sandbox/sbx.py` | **Written, not yet run** (see blockers) |

Last runs: `cd api && uv run pytest -q` → 152 passed · `cd web && npm test` → passing (count in last web report).

## NOT tested / known gaps (honest)
- **Agent has never run on a real Linux host**, and the sandbox E2E has never run. apk executor path untested. dnf removed from remediation until proven.
- **AI never called against the real API** (no key on this machine).
- Ledger can still be rewritten wholesale by a DB-level attacker (DECISIONS 14). No off-database checkpoints yet.
- No login rate limiting / AI rate limiting, no OIDC, no Alembic migrations (create_all; a dev DB must be deleted after schema changes).
- No inventory throttling per asset; advisory lookups are per package (fine for hundreds, slow at tens of thousands).
- Maven/NuGet/RubyGems comparators missing; Windows agent reports no packages.
- Web e2e runs with AI off: AI UI, token revoke and asset delete flows not covered by e2e. Axe moderate/minor issues unreviewed.

## Blockers needing the user
- Permission to let the sandbox harness download the official Debian WSL image (via `wsl --install Debian --name nimstead-sbx-…`, from Microsoft's distro list, a few hundred MB) plus the OSV Debian advisory zip (~79 MB). The distro is unregistered after each run.
- Optional: an Anthropic API key (env `ANTHROPIC_API_KEY`) to switch on AI features and test them for real.

## Next
1. Run `sandbox/sbx.py` once allowed; fix whatever breaks on a real host; record results here.
2. Signed off-database ledger checkpoints; login/AI rate limiting; Alembic.
3. Batch advisory lookups; per-asset inventory throttle.
4. Windows inventory (winget/registry + MSRC/OSV), more ecosystems.

## Run
- API tests: `cd api && uv run pytest -q` · lint: `uv run ruff check src tests ../agent ../sandbox`
- API dev server: `cd api && NIMSTEAD_SECURE_COOKIES=0 uv run uvicorn --factory nimstead.app:create_app --port 8000`
- Feeds: `cd api && uv run python -m nimstead.feeds update` (hourly via cron/systemd timer in prod)
- Seed dev advisories: `cd api && uv run python ../web/scripts/seed.py`
- Web: `cd web && npm run dev` · `npm test` · `npm run build`
- Sandbox E2E: `cd api && uv run python ../sandbox/sbx.py` → `sandbox/last_run.json`
