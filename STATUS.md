# Nimstead — status

Read this first each session. Decisions and their reasons: DECISIONS.md. Original plan: milestones below.

## Done (with evidence)
| Area | Where | Evidence |
|---|---|---|
| Version comparators dpkg/rpm/apk/semver/PEP 440 | `api/src/nimstead/versions.py` | 60 table tests from reference suites |
| OSV matcher (source-package, backports, CVE dedup, withdrawn) | `api/src/nimstead/match.py` | Exact agreement with OSV API on 16 real cases — `tests/test_match.py` |
| Risk scorer (KEV override, EPSS, CVSS, criticality, exposure, fix) with reasons | `risk.py` | `tests/test_risk.py` |
| Feed sync: OSV bulk zips (incremental), CISA KEV, FIRST EPSS | `feeds.py` | Mocked tests + real smoke run: KEV 1,756, EPSS 395,308, OSV Alpine 44,512 rows |
| API: signup/login (argon2, cookie), enrol tokens, agent enrol + inventory, findings, assets, fix-action summary | `app.py`, `db.py`, `scan.py` | `tests/test_api.py` incl. tenant isolation, forged tokens |
| Evidence: hash-chained ledger, Ed25519-signed packs, control mapping (CE, ISO 27001 A.8.8, NIST RA-5/SI-2, PCI 6.3.3, CIS 7), offline verifier | `evidence.py`, `verify_pack.py` | `tests/test_evidence.py` incl. tamper detection, refusal to sign a broken chain |
| Risk acceptance (reason required, expires, ledgered) | `app.py` | `tests/test_evidence.py` |
| Remediation server: plans, trust ladder (suggest/approve/auto), canary ring + soak, halt on any failure, sandbox-only dev guard, inventory-verified success, silent-agent timeout | `remediate.py` | `tests/test_remediate.py` (9 tests) |
| Agent: collector (dpkg/rpm/apk), enrol/report, remediation executor (apt/apk/dnf) with rollback artefacts saved before change, health checks, auto-rollback, local opt-in | `agent/nimstead_agent.py` | `tests/test_agent.py` parsers; `tests/test_agent_remediate.py` simulated apt host (9 tests) |
| Web UI: auth, onboarding, Fix-first home, virtualised findings + drawer, assets, Ctrl+K, dark/light, mobile | `web/` | `npm run build` clean, 9 vitest tests; manually screenshotted desktop + 375px |

Totals at last run: `cd api && uv run pytest -q` → 130 passed; `cd web && npm test` → 9 passed.

## NOT yet tested / known gaps (be honest)
- **Agent never run on a real Linux host.** Collector parsers and executor are tested on sample text / a simulated apt host only. apk and dnf executor paths have no tests at all.
- **No real sandbox yet.** No Docker; WSL sudo needs the user's password. Plan: disposable WSL distros via `wsl --install Debian --name nimstead-sbx-N` / `wsl --import` (no admin), removed with `wsl --unregister` after each test. Needs user OK to download a distro image.
- Web UI has no pages yet for remediation jobs, evidence/ledger, settings. Nothing serves `/install.sh`.
- No feed scheduler (feeds run via CLI only). No CVSS for Debian/Ubuntu records lacking `severity` (NVD enrichment not built) → impact defaults to 5.0.
- No login rate limiting, no OIDC, no CSRF token (SameSite=Strict cookie only). No Alembic migrations (create_all).
- AI features (M7) not started; need an Anthropic API key from the user.
- Maven/NuGet/RubyGems comparators missing → no findings for those ecosystems. Windows agent reports no packages.
- No accessibility audit (axe) run on the UI; no Playwright e2e.

## Next (in order)
1. Web pages: Remediation (plan/approve/status with step log), Evidence (ledger, download pack, control status), Settings (trust ladder mode, soak). Serve `/install.sh` + agent from API.
2. Security review of auth/agent/remediation (Opus reviewer) and fix findings.
3. Real sandbox E2E in a disposable WSL distro: enrol, detect, remediate, rollback, verify, evidence pack.
4. Feed scheduler + NVD CVSS enrichment. 5. AI explanations / NL search (needs key). 6. Playwright + axe.

## Run
- API tests: `cd api && uv run pytest -q` · lint: `uv run ruff check src tests ../agent`
- API dev server: `cd api && NIMSTEAD_SECURE_COOKIES=0 uv run uvicorn --factory nimstead.app:create_app --port 8000`
- Seed dev advisories: `cd api && uv run python ../web/scripts/seed.py`; real feeds: `uv run python -m nimstead.feeds kev|epss|osv Debian ...`
- Web: `cd web && npm run dev` (proxies /api to :8000) · `npm test` · `npm run build`
- Refresh OSV oracle fixtures: `cd api && uv run python tests/fetch_fixtures.py`

## Working method
Opus (main) for design and safety-critical code; Sonnet subagents for UI and feature work; Haiku for boilerplate/search. Commit small increments; update this file each time.
