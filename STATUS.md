# Nimstead — status

Read this first each session. Decisions and their reasons: DECISIONS.md (items 1–15). Quick start: README.md.

**State: v1 complete.** All planned milestones (M0–M8) are built, tested, and proven end to end on real Linux hosts in disposable VMs. What isn't proven is listed below.

## Done (with evidence)
| Area | Where | Evidence |
|---|---|---|
| Version comparators dpkg/rpm/apk/semver/PEP 440, plus Maven (`ComparableVersion` port), NuGet (SemVer 2, 4-part), RubyGems (`Gem::Version`) | `api/src/nimstead/versions.py` | Table tests from reference suites incl. Maven's ComparableVersionTest orderings |
| CycloneDX SBOM ingest (1.4-1.6): application assets without an agent, purl -> OSV ecosystem (PyPI, npm, Maven, NuGet, RubyGems, Go, crates.io), per-origin package replacement, `sbom_received` ledger entry, per-asset upload token for CI | `sbom.py`, `app.py`, `db.py` (`origin`, `kind`), migration `f6f1d7ace414` | `tests/test_sbom.py` (purl table, nesting, replace semantics, Log4Shell on log4j-core 2.14.1, tenant isolation, 413/422); web upload test |
| OSV matcher (source-package, backports, CVE dedup, withdrawn) | `match.py` | Exact agreement with the OSV API on 31 real cases incl. Maven, NuGet, RubyGems (`tests/test_match.py`) |
| Risk scorer (KEV override, EPSS, CVSS, criticality, exposure, fix) with reasons | `risk.py` | `tests/test_risk.py` |
| Windows OS detection: agent reports MSRC product name + full build; `sync_msrc` loads MSRC CVRF (FixedBuild, KB, CVSS) as OSV-shaped rows; `windows_cmp` | `agent/nimstead_agent.py`, `feeds.py`, `versions.py` | `tests/test_windows.py` (trimmed real CVRF fixture, e2e old build -> finding, fixed build -> resolved); real sync of 2 months = 45,975 rows, 0 findings on this patched machine, 1,009 when the build is set one below the October fix |
| Feeds: OSV bulk (incremental, only releases in use), CISA KEV, FIRST EPSS, NVD CVSS 2.0; `feeds update` re-matches all assets and checkpoints the ledger | `feeds.py` | Mocked tests + real runs: KEV 1,756, EPSS 395,308, NVD 21,041, OSV Debian 195,692 / Ubuntu 3.3M rows |
| API: auth (argon2, timing-safe, throttled), enrol tokens (expiry, revoke), agent enrol/inventory (rate-limited), findings, assets, fix-action summary, install.sh, serves the built UI | `app.py`, `db.py`, `scan.py` | `tests/test_api.py` incl. tenant isolation, CSRF/Origin, 413, Host-header injection |
| DB: SQLite (dev) and PostgreSQL via Alembic | `migrations/` | `tests/test_migrations.py`; **full suite (163) passes on PostgreSQL 17** (`sandbox/pg.py`) |
| Evidence: hash-chained ledger, signed off-database checkpoints, Ed25519 packs with pinned-fingerprint verification, control mapping, ledger-derived timings | `evidence.py`, `verify_pack.py` | `tests/test_evidence.py` incl. re-signed forgery, consistent full-chain rewrite, truncation, findings-table edits |
| Remediation server: trust ladder, canary + soak, broad ring pinned to canary versions, halt on failure, kill switch at dispatch, stale-job sweep, late reports, inventory-verified success | `remediate.py` | `tests/test_remediate.py` |
| Agent (apt): dry-run scope check, rollback package (archive copy, or rebuilt from installed files), sha256-checked, health checks with settle, auto-rollback, persisted outcomes, run lock | `agent/nimstead_agent.py` | Unit tests + **real hosts:** Debian 13 and Ubuntu 24.04 sandbox E2E PASS (`sandbox/last_run_*.json`) |
| Optional AI (Claude Opus 5.5, fallbacks on): explanations, NL search → validated filter | `ai.py` | `tests/test_ai.py`, mocked client only |
| Web UI: onboarding, Fix-first home, findings + drawer, assets, remediation, evidence, settings, Ctrl+K, dark/light, mobile | `web/` | build clean; 14 vitest; 4 Playwright e2e incl. full flow + axe (0 serious/critical) |

Real-host E2E (each in a fresh WSL distro, destroyed afterwards):
- **Debian 13:** 164 packages, 274 findings. The openssl upgrade was proven fixed by the next inventory (38 resolved). A forced service failure after the perl upgrade rolled back with versions restored. Evidence pack verified; 6/6 controls met.
- **Ubuntu 24.04:** 523 packages, 369 findings. Same flow, with curl upgraded and glib2.0 rolled back. Evidence pack verified.

Last runs: API 189 passed (SQLite; PostgreSQL 17 last run at 163, not re-run with the Windows tests) · web 14 unit + 4 e2e passed.

## NOT proven / known gaps (honest)
- **AI never called against the real API** (no key on this machine). The UI hides it unless `ANTHROPIC_API_KEY` is set.
- **Remediation is apt-only** (Debian/Ubuntu). Alpine and RHEL-family are detection-only: no trustworthy rollback artefact yet (DECISIONS 15).
- **Windows is OS-only:** the agent reports the OS build (registry CurrentBuild+UBR) and MSRC matches it by product name. Not covered: Office, Edge, .NET, SQL Server, drivers and other third-party Windows apps (no installed-software inventory); Server 2012/R2, Server 23H2 and Insider builds (unmapped, agent refuses); MSRC lists no "introduced in" build, so a CVE is assumed to affect every build below the fix. Windows remediation is detection-only. Proven: unit and mocked-feed tests plus a real MSRC sync (Aug-Oct 2026) matched against this Windows 11 machine, not yet a full agent-to-server run on a Windows host.
- **SBOM/dependencies:** CycloneDX JSON only (no SPDX, XML or VEX); components without a purl or version, and purl types outside the seven mapped ones, are counted and skipped, never guessed. A flat SBOM can't say whether a vulnerable function is reachable, so findings are "present", not "exploitable". Package names are used as written in the purl (NuGet/RubyGems/crates case, no folding). Detection-only: no dependency remediation. The Maven comparator is a port of Maven 3.9 `ComparableVersion` and the OSV oracle agrees on all 15 new Maven/NuGet/RubyGems cases, but only the OSV `ECOSYSTEM`/`SEMVER` ranges and `versions` lists are evaluated (no GIT ranges). No upload rate limit; the upload token cannot be rotated (delete and re-create the application). Web e2e not re-run for the Assets page change.
- **Single API process assumed:** the login and inventory throttles are in-memory. Run one worker, or move them to a shared store.
- No OIDC/SSO. Web e2e doesn't cover the AI UI, token revoke or asset delete. Moderate/minor axe issues unreviewed.
- Signed checkpoints are only as strong as their storage: point `NIMSTEAD_CHECKPOINT_DIR` at WORM/object-lock storage in production.

## Needs the user
- Optional: an Anthropic API key to enable and live-test the AI features.

## Next (v2)
1. Windows third-party software inventory (winget/registry Uninstall keys) + a source for it; Windows remediation (Windows Update) is out of scope until there is a rollback story.
2. Alpine rollback strategy (local apk cache from enrolment onward), then apk remediation; dnf via `dnf download` + sandbox proof on AlmaLinux 9.
3. OIDC/SSO; shared throttle store; notifications (email/Slack) for failed jobs.

## Run
- API tests: `cd api && uv run pytest -q` · lint: `uv run ruff check src tests ../agent ../sandbox`
- API + UI: `cd web && npm run build`, then `cd api && NIMSTEAD_SECURE_COOKIES=0 uv run uvicorn --factory nimstead.app:create_app --port 8000`
- Feeds: `cd api && uv run python -m nimstead.feeds update` (hourly in prod)
- Web dev: `cd web && npm run dev` · `npm test` · `npm run e2e`
- Real-host E2E: `cd api && uv run python ../sandbox/sbx.py [--distro Ubuntu-24.04]` · Postgres suite: `uv run python ../sandbox/pg.py`
