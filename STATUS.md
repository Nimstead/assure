# Nimstead — status

Read this first each session. Decisions and their reasons: DECISIONS.md (items 1–26). Quick start: README.md.

## Done (with evidence)
| Area | Where | Evidence |
|---|---|---|
| Version comparators: dpkg, rpm, apk, semver, PEP 440, Maven, NuGet, RubyGems, Composer, Windows build; Hex and Pub reuse semver | `api/src/nimstead/versions.py` | Table tests from each reference suite |
| OSV matcher (source-package, backports, CVE dedup, withdrawn) | `match.py` | Exact agreement with the OSV API on 49 real package/version cases across Debian, Ubuntu, Alpine, Rocky, PyPI, npm, Maven (log4j-core, jackson-databind), NuGet, RubyGems, Packagist (laravel/framework, symfony/http-kernel, guzzle), Hex (plug, phoenix), Pub (http, archive) |
| Windows OS detection via MSRC (FixedBuild/KB per product) | `feeds.py` (`sync_msrc`), agent | Real MSRC sync + real agent→server run on this Windows 11 machine (0 findings, fully patched; 1,009 at one build below, all one KB) |
| SBOM ingest (CycloneDX 1.4–1.6 and SPDX 2.2/2.3 JSON, purl → ecosystem), application assets with upload tokens | `sbom.py`, `app.py` | `tests/test_sbom.py` incl. log4j-core 2.14.1 → CVE-2021-44228 from both formats |
| Risk scorer (KEV override, EPSS, CVSS, criticality, exposure, fix) with reasons | `risk.py` | `tests/test_risk.py` |
| Feeds: OSV (incremental, releases in use only), KEV, EPSS, NVD CVSS, MSRC; `feeds update` re-matches assets, checkpoints the ledger, retries failed alerts | `feeds.py` | Mocked tests + real runs (KEV 1,756; EPSS 395k; OSV Debian 196k, Ubuntu 3.3M, Alpine, AlmaLinux 26k; MSRC 46k) |
| API: auth (argon2, throttled in DB), enrol tokens, agent enrol/inventory, findings, assets, summary, install.sh + install.ps1, serves the built UI | `app.py`, `db.py`, `scan.py` | `tests/test_api.py` incl. tenant isolation, CSRF/Origin, 413, Host-header injection |
| SSO (OIDC code + PKCE, state, nonce, JWKS), DNS-TXT domain verification, encrypted client secret, admin break-glass | `sso.py`, `app.py` | `tests/test_sso.py` (27, fake IdP + fake DNS) |
| Failure alerts (Slack-compatible/generic webhook, SMTP), SSRF-guarded, recorded, retried up to 3× | `notify.py`, `netguard.py` | `tests/test_notify.py` (21, mocked transports) |
| Multi-worker safe state: login throttle, inventory rate limit, SSO pending logins in the DB | `db.py`, `app.py` | Full suite |
| DB: SQLite (dev), PostgreSQL via Alembic (linear history) | `migrations/` | `tests/test_migrations.py`; full suite on PostgreSQL 17 via `sandbox/pg.py` |
| Evidence: hash-chained ledger, signed off-DB checkpoints, Ed25519 packs (pinned fingerprint), control mapping, ledger-derived timings | `evidence.py`, `verify_pack.py` | `tests/test_evidence.py` incl. forgery, consistent rewrite, truncation |
| Remediation server: trust ladder, canary + soak, broad ring pinned to canary versions, halts, kill switch, sweeps, inventory-verified success | `remediate.py` | `tests/test_remediate.py` |
| Agent remediation: apt (old .deb or rebuilt), apk + dnf (file + package-DB snapshot), zypper (btrfs + snapper pre/post, `undochange` reverts install-script side effects too; file snapshot without snapper); after a rollback, crashed health units are restarted on the restored version; dry-run scope check, health checks, auto-rollback, persisted outcomes, Windows key ACL | `agent/nimstead_agent.py` | Unit tests + **real-host E2E PASS in disposable VMs on Debian 13, Ubuntu 24.04, AlmaLinux 9 and Alpine 3.21** (`sandbox/last_run_*.json`) + **openSUSE Leap 16.0 VirtualBox VM PASS** (`sandbox/suse.py`): official image, four real fixes, a fix that broke a service rolled back by `snapper undochange`: all four nss packages back to 3.125-160000.2.1, `/etc/ld.so.cache` (rewritten by the install scripts, owned by no package) restored byte-for-byte, service restarted and healthy |
| Windows remediation: one cumulative update by KB via Windows Update Agent (as SYSTEM), state persisted across reboots, health checks, rollback = DISM removal of the new package with retries for servicing-busy errors; **permanent updates refused before install** (the downloaded package's own update.mum is read from the .wim/.cab; WUA's IsUninstallable is unusable: it says False for cumulative updates DISM removes fine) | agent `WinJob`, `remediate.py` | `tests/test_winjob.py` (11) + real manifest check in the VM (KB5126646 .wim: not permanent, 3 permanent Feature-on-Demand parts listed; .NET KB5127690 .cab: not permanent; servicing stack .cab: **permanent → would be refused**) and in the real agent flow (2026-10-26 rerun on the final code: check passed → KB5126646 installed → reboot → injected failure → DISM removal → reboot → 26100.32230 restored, `rolled_back`; the scheduled-task success pass, whose code didn't change, was not rerun; the VM hung under NEM mid-run and the job was finished with `winresume.py`: `last_run_windows_final_code.json` + `last_run_windows_resume.json`) + **real Windows Server 2025 VM PASS**: install.ps1 elevated (enrol, report, SYSTEM task with startup trigger); forced-failure rollback 26100.33650 → DISM removal → reboot → 26100.32230 restored; then the installed scheduled task alone installed KB5126646, rebooted, resumed at startup and reported, and the server marked the job succeeded from fresh inventory (0 open findings, evidence verified) — `sandbox/last_run_windows*.json` |
| Real-service integrations: Keycloak OIDC login, DNS TXT verification (dnsmasq), SMTP + HTTPS webhook alerts, dead-webhook retry | `sandbox/integrations.py` | **PASS** in a disposable WSL VM (`sandbox/last_run_integrations.json`) |
| Windows third-party apps (Chrome, Edge, Firefox/ESR, 7-Zip, Notepad++, VLC, Zoom, Acrobat Reader, Oracle JDK 11+, Git for Windows, Python, Node.js, PuTTY, WinRAR, Wireshark, VS Code): registry inventory → curated CPE map → NVD CPE ranges, exact comparator | `winapps.py`, `feeds.py` (`sync_winapps`, run by `sync_nvd`), `scan.py`, agent `windows_apps` | `tests/test_winapps.py` (88: map positives/near-misses, comparator table, real NVD fixtures, fake registry, end to end) + real run on this machine (see below) |
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

**Last runs (final code):** API 550 passed on SQLite and 550 passed on PostgreSQL 17 · ruff clean · web 18 unit + 4 Playwright e2e (axe clean in light and dark) · real-host E2E PASS on Debian 13, Ubuntu 24.04, AlmaLinux 9, Alpine 3.21, openSUSE Leap 16.0 (snapper) and Windows Server 2025 · real-service integrations PASS (Keycloak, DNS, SMTP, webhook).

## NOT proven / known gaps (honest)
- **AI:** tested with a mocked client only. Owner decision (2026-10-26): skip live AI testing. The features stay off unless `ANTHROPIC_API_KEY` is set.
- **Windows remediation:** proven on Windows Server 2025 Core. Windows 10/11 clients are not run in a VM (owner decision 2026-10-26: the Server 2025 pass is sufficient proof of the mechanism), and a permanent update is now refused before install. Only cumulative updates delivered as .wim or .cab are checked; any other format (or an unreadable manifest) is refused, never installed blind. Permanent Feature-on-Demand parts inside a removable update stay after rollback (rollback is judged by the build returning). The VM run was split into rollback and success passes because a VirtualBox update interrupted it.
- **Windows third-party apps:** only the ~18 curated products are matched (DECISIONS 22); everything else is inventory. NVD data limits apply: an NVD range typo produces a finding (seen for real: CVE-2026-113344 lists Chrome fixed at 156.0.8087.47 while its own text says 156.0.8078.47, so 156.0.8078.48 is flagged); NVD can lag vendors; Chromium CVEs that Microsoft tracks only in MSRC aren't seen for Edge; Oracle JDK CVEs list exact affected versions only (no fix version, older unlisted versions are missed); Java 8 and Temurin aren't covered; only CVEs from the synced NVD years are present (run `feeds nvd 2023 2024 2025 2026` once; `update` adds the modified feed); Zoom, Acrobat, Firefox ESR, WinRAR, PuTTY, Wireshark registry formats were not checked on a real install; two installs of one app report the oldest; no remediation (Windows Update can't patch them).
- **Install-script side effects:** reversed only with zypper + snapper (btrfs root, as openSUSE/SLES ship). apt, apk and dnf rollbacks restore package files and the package database but not what maintainer scripts changed elsewhere (health checks cover the visible effects). Snapper excludes separate subvolumes such as /var, /home and /srv by design, so script changes there aren't undone. Kernel/install-only packages are refused.
- **Dependency upgrades are never silent:** when a fix needs another package, the dry run refuses it and the user re-plans "including X" with one click. Nothing expands on its own.
- **SBOM:** CycloneDX and SPDX JSON only (no XML, SPDX tag-value or VEX); SPDX relationships are ignored, so every package with a purl is scanned. Findings mean "present", not "reachable".
- **Key storage:** Vault transit (signing, encryption, HMAC) and S3 object-lock checkpoints are built and pass against real Vault 2.1.1 and an S3 gateway with COMPLIANCE lock (`sandbox/keystore.py`). Cloud KMS (AWS/GCP/Azure) adapters aren't built; on-disk keys remain the dev default.
- **Ecosystems:** Go/crates/Hex/Pub use the semver comparator (Pub build-metadata ordering differs); Composer `dev-*` branches are refused; no Conda comparator.

## Needs the user
- Nothing. Live AI testing and a Windows 11 client VM were both scoped out by the owner on 2026-10-26.

## Run
- **API:** `cd api && uv run pytest -q` · lint: `uv run ruff check src tests ../agent ../sandbox`
- **App:** `cd web && npm run build`, then `cd api && NIMSTEAD_SECURE_COOKIES=0 uv run uvicorn --factory nimstead.app:create_app --port 8000`
- **Feeds:** `cd api && uv run python -m nimstead.feeds update` (hourly)
- **Web:** `cd web && npm test` · `npm run e2e`
- **Real-host E2E:** `cd api && uv run python ../sandbox/sbx.py --distro Debian|Ubuntu-24.04|AlmaLinux-9|alpine-3.21.0` · openSUSE + snapper: `uv run python ../sandbox/suse.py` · Windows: `../sandbox/winvm.py create ISO`, then `../sandbox/wine2e.py VM`
- **PostgreSQL suite:** `cd api && uv run python ../sandbox/pg.py`
