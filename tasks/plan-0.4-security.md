# Plan 0.4: close round-4 security findings, make Assure sellable to a first design partner

Owner: product (security PM review, 2026-10-28). Target: **release 0.4.0 (agent 0.3.0)**, promoted to **stable**.
Status at start: 0.3.1 preview, API 673 passed (SQLite), npm audit 0, pip-audit 0, three security rounds already closed (F1–F21, DECISIONS 27/30).

## Why this plan, in one paragraph
The remediation engine, signed updates and evidence ledger are ahead of the category. What blocks a first paying design partner is the
layer around them: one admin per org with no way to add or remove users, no MFA on the password login that can drive root/SYSTEM
remediation, a sign-up flow that lets an attacker pre-own a victim's account, and a fresh install that hears about no updates
(default channel `stable`, no stable release exists). Round 4 (three parallel reviews, top claims re-verified in the code) found
1 high + 3 medium server issues, 1 high + 4 medium agent/supply-chain issues and the gaps below. Fix the security items first, then
the minimum enterprise features, then ship stable.

## Rules for whoever executes this (/goal)
- House rules apply: read STATUS.md first; a test for every fix; real-host proof where the change touches a host (`sandbox/`);
  record each new "why" in DECISIONS.md (next numbers 34+); STATUS, CHANGELOG and README updated at the end.
- Smallest complete change: reuse `over_limit`, `owned_asset`, `Admin`, the ledger `append`, `keys.py` sealing, `notify` email.
  No new dependency unless a task says so.
- Do not weaken DECISIONS 7, 27, 31 (the server never hands out agent code; admin is an attacker capability across tenants).
- Commit per phase on a branch `security-round-4`; do not push, tag or release (owner-only, see "Needs the owner").
- Verify after every phase:
  `cd api && uv run pytest -q && uv run ruff check src tests ../agent ../sandbox ../scripts` ·
  `cd web && npm test && npm run build && npm run e2e` · PostgreSQL: `cd api && uv run python ../sandbox/pg.py`

---

## Phase 1: Server security (round 4 findings). Highest risk first.

### S1 [HIGH] Sign-up pre-hijack: the password must come from the address owner
Verified: `app.py:299` stores the requester's `password_hash` in `PendingSignup`; `app.py:1021` creates the account with it.
- Sign-up request (non-first account) takes email + org name only. The confirm page (`GET /api/auth/signup/confirm`) shows a
  password field; `POST` sets it. Drop `PendingSignup.password_hash` (Alembic migration, linear history).
- A new pending sign-up for an email deletes older pending rows for that email.
- First-account path unchanged (local setup).
- **Done when:** test: attacker requests sign-up for victim, victim confirms with their own password, attacker's password fails;
  old link invalid after a second request; the UI "check your email" copy still right; migration test passes on SQLite + PG.

### S2 [MEDIUM] Chunked bodies bypass the 10 MB cap (unauthenticated DoS)
Verified: `app.py:188-190` checks `Content-Length` only (comment admits it); Compose publishes uvicorn with no proxy.
- Pure ASGI middleware that counts `receive()` bytes and returns 413 past `MAX_BODY`; delete the shortcut comment.
  Keep `upload_sbom`'s own limit.
- **Done when:** test sends a chunked body > MAX_BODY to `/api/auth/login` and gets 413 without the handler running.

### S3 [MEDIUM] Per-tenant quotas (one self-signup org can load the shared server)
- `over_limit` on enrol per token (e.g. 100/hour) and per org; cap assets per org (`NIMSTEAD_MAX_ASSETS_PER_ORG`, default 5000,
  documented in `docs/configuration.md`); org-wide inventory rate on top of the per-asset 30 s; cap application assets per org.
- **Done when:** tests for each limit (429 / 403 with a clear message); `sandbox/perf.py --assets 1000` still passes under the default.

### S4 [MEDIUM] AI endpoints: rate and cost limit (OWASP LLM10)
Verified by the code's own note at `app.py:1038-1055` ("no per-user AI rate limit yet").
- `over_limit` per user and per org on `/api/ai/search` and `/api/ai/explain`; cache explain on the advisory + package facts,
  not the hostname.
- **Done when:** tests: Nth call in the window gets 429; two hosts with the same finding hit one cache entry (mocked client).

### S5 [LOW] Fresh Docker install can be claimed by whoever connects first
- `compose.yaml`: publish `127.0.0.1:${NIMSTEAD_PORT:-8000}:8000` by default; `docs/install.md` says to put the HTTPS proxy in
  front (already required for agents via `NIMSTEAD_PUBLIC_URL`). Fix the misplaced comment on the `NIMSTEAD_UPDATE_CHANNEL` line.
- **Done when:** `docker compose config` shows the loopback bind; `sandbox/compose.py` PASS.

### S6 [LOW] Security headers
- One middleware: `Strict-Transport-Security` (only when `SECURE_COOKIES`), `Content-Security-Policy` (`default-src 'self'`;
  check the built SPA needs nothing else), `frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`. Do not break `/api/docs` (allow its CDN or serve it only to signed-in admins; pick the smaller).
- **Done when:** API test asserts headers; Playwright e2e + axe still pass with no CSP console errors.

### S7 [LOW] Ledger gaps for user actions
- Ledger `asset_enrolled` (asset, token id prefix, by-token), `password_login`, `org_created`; store the enrolling token id on the asset.
- **Done when:** tests assert each entry; evidence pack still verifies (`tests/test_evidence.py`).

---

## Phase 2: Identity and access, the minimum an enterprise buyer checks first

### I1 [P0] User management and offboarding
Verified: `admin=True` is set only at org creation (`app.py:270`); no routes to list, promote, demote or remove users.
- Admin routes: list users, set admin on/off, remove a user (deletes their sessions). Refuse demoting/removing the last admin.
  Invite = SSO for SSO orgs; for password orgs, an emailed invite link (reuse the sign-up confirm flow from S1, joining the org).
- Sessions: add a 12 h idle timeout alongside the 14-day max; "sign out everywhere" for self.
- Every change goes to the ledger with `by`. Settings page section; non-admins see it read-only.
- **Done when:** API tests (tenant isolation, last-admin guard, sessions gone on removal, idle expiry); e2e: admin promotes and removes a user.

### I2 [P0, gap HIGH] MFA for password accounts (TOTP)
The break-glass admin login (`app.py:331-337`) skips the IdP's MFA with a password alone, and that account can drive remediation.
- TOTP (RFC 6238) in stdlib (`hmac`, `base64`, `struct`; ~20 lines, RFC test vectors), secret sealed with `keys.py`;
  10 one-time recovery codes stored argon2-hashed. Required for admins who sign in with a password (enrol at next login);
  optional for others. Failed codes count toward the existing login throttle.
- Why not WebAuthn now: bigger surface, needs a library; TOTP closes the gap today (record as a DECISION).
- **Done when:** RFC 6238 vectors; tests: admin password login without code refused, recovery code single-use,
  break-glass needs TOTP; e2e enrol + login with a generated code.

### I3 [P0] Password change and reset
- Change (signed in, needs current password + TOTP). Reset by emailed single-use 256-bit link (1 h), only when SMTP is set,
  same answer whether or not the email exists, rate-limited; reset kills all sessions; TOTP still required after reset.
- **Done when:** tests for each path incl. enumeration-equal responses and token reuse.

### I4 [P0] Org API tokens for automation
- Admin-created, named, hashed at rest, shown once, optional expiry, read-only scope (findings, assets, summary, evidence pack).
  Bearer header, no Origin check for bearer requests, revocable, ledgered. Write scopes are out of scope for 0.4.
- **Done when:** tests: token reads its own org only, can't call admin/mutating routes, revoked token 401.

### I5 [P0] Findings export (CSV)
- `GET /api/findings.csv` with the same filters as the list, org-scoped; spreadsheet-formula cells (`= + - @`) escaped.
- **Done when:** test incl. a formula-injection package name; Findings page has an Export button.

---

## Phase 3: Agent, installers, platform update (round 4 findings)

### A1 [HIGH] First install trusts the server completely
Verified: `install.sh:24` fetches the agent from the server with no signature check, `curl -L` without proto restriction.
- `curl --proto '=https' --proto-redir '=https'` everywhere in `install.sh` (keep the explicit dev `http://` path).
- Document an out-of-band install in `docs/install.md`: download `nimstead_agent.py` + `release.json` + `.sig` from the GitHub
  release, check the agent's SHA-256 against the signed manifest with the published key fingerprint, then `enroll`.
  The installer prints the agent SHA-256 it installed so an admin can compare.
- Record the residual in DECISIONS (a compromised server at first install = new hosts compromised; existing hosts unaffected).
- **Done when:** shellcheck-clean `install.sh`; doc steps run once by hand in `sandbox/sbx.py --distro Debian` and recorded.

### A2 [MEDIUM] Remediation must never downgrade
`agent/nimstead_agent.py:497,508,654-656`: `to` is never compared with `from`; `Downgrading` counts as an allowed change.
- Refuse a job whose `to` is not newer than `from` (the package manager's own comparison: `apk version -t`, `rpm`/`zypper vcmp`,
  `dpkg --compare-versions`); treat any `Downgrading` line in the dry run as out of scope.
- **Done when:** unit tests per manager; real-host: `sbx.py --distro alpine-3.21.0` refuses a forged downgrade job, normal fix still PASS.

### A3 [MEDIUM] Rollback artefacts fill the disk
- Delete `/var/lib/nimstead/rollback/<id>` once the final outcome is persisted (applied+verified or rolled back);
  refuse a new job below a free-space floor (e.g. 2 GiB or 3x the snapshot size) with a clear error.
- **Done when:** unit test; real-host run shows the directory gone after success and after rollback.

### A4 [MEDIUM] Signed channel and a floor for agents
`verify_release` ignores `channel`; a compromised server can push any signed newer build (e.g. preview) to the fleet.
- The agent records its channel locally at enrol (from the server's channel at that moment, or `--channel`); it refuses manifests
  less stable than that. Releases sign a `min_agent_version`; agents below it say "reinstall needed" (UI already has that state).
- Write `docs/release-keys.md`: rotation and compromised-release runbook (sign N+1 with the backup key, raise `min_agent_version`).
- **Done when:** `test_agent_update.py` cases: preview manifest refused by a stable agent, beta taken by a beta agent; runbook reviewed.

### A5 [LOW] Small agent/installer hardening, one commit
- `re.fullmatch` (or `\Z`) for `SAFE_NAME`, `SAFE_VERSION`, `SAFE_KB` and the other job regexes (`:267,268,793,797,799`).
- Cap JSON response reads (`:1196`) like `raw=True` already does.
- `install.ps1:22`: `TrimEnd('')+''` → `TrimEnd('\') + '\'` (verified: the backslash is missing, so
  `C:\Program Files Evil\python.exe` passes the installer's check; the agent's own check is correct). Add a test that reads the
  served script and asserts the literal.
- **Done when:** tests for each; Windows proof optional (`sandbox/winlocal.py`) since `schedule()` already blocked it.

### A6 [MEDIUM/LOW] `deploy/update.sh`
- Refuse untracked files too (`git status --porcelain`), pass `-f compose.yaml` explicitly (no silent `compose.override.yaml`).
- `git checkout "$COMMIT"` (the verified commit), not the tag name.
- `--install-timer` refuses unless the checkout is root-owned and not group/other-writable.
- `pg_restore --list "$DUMP"` before dropping the database on rollback.
- **Done when:** `sandbox/platform_update.py` PASS plus new cases: untracked override file refused, same-name branch ignored.

---

## Phase 4: Supply chain and CI (cheap, visible to auditors)

- C1 `ci.yml`: pin actions to SHAs (as release.yml), top-level `permissions: contents: read`, pin `postgres:17` by digest.
- C2 Dependabot: add `uv` (`/api`) and `npm` (`/web`) ecosystems.
- C3 One CI step: `uvx pip-audit` on the exported lock + `npm audit --omit=dev --audit-level=high`.
- C4 Release publishes the product's own SBOMs (`uv export --format cyclonedx1.5`, `npm sbom --sbom-format cyclonedx`) and the
  release notes say Assure scans itself: upload them to a demo org in `sandbox/demo.py` (dogfood, 0 fix-now expected).
- C5 Pin the signing step's `cryptography` by hash (`--with` from a hashed requirements file).
- **Done when:** CI green on the branch (owner pushes); `release.yml` dry-read checked; SBOM ingests via `/api/apps/.../sbom`.

---

## Phase 5: Product readiness and ship

- P1 Default update channel: `.env.example` and `compose.yaml` stay `stable`, and 0.4.0 becomes the first stable release
  (owner approves). Until then README says "follow beta".
- P2 Evidence control map (`evidence.py:153-173`): add SOC 2 CC7.1 / CC8.1 and NIS2 Art. 21(2)(e); make SLA days per priority
  configurable per org (shown in the pack, so "organisation-defined" in NIST SI-2 is true). Keep the mapping wording honest:
  timings run from first detection (say so in the pack).
- P3 Risk acceptance: revoke, and accept one CVE across every affected asset in one action (ledgered).
- P4 Docs truth pass: README "Early access (v0.1)" → 0.4; test counts from the real run; STATUS line 63 newline; mark DECISIONS
  13/15/17 superseded; delete or archive stale `tasks/todo.md`; restore procedure + RPO/RTO in `docs/install.md`;
  `SECURITY.md`: safe harbour, `/.well-known/security.txt` served by the app, response targets per severity.
- P5 Record DECISIONS 34+ (TOTP over WebAuthn; first-install residual; agent channel; quotas), update STATUS "Last runs",
  CHANGELOG 0.4.0, bump `pyproject.toml`, `package.json`, `compose.yaml` image tag, `AGENT_VERSION` 0.3.0.

### Checkpoint (release gate)
All of: API suite on SQLite and PostgreSQL, ruff, web unit + e2e + axe, `sandbox/compose.py`, `sandbox/platform_update.py`,
`sandbox/sbx.py --distro alpine-3.21.0` and `--distro Debian`, `sandbox/agent_schedule.py`: PASS, recorded in STATUS.
Then a fresh read-only security review of the branch diff (the `/code-review` or Claude Security "scan changes"), with every
medium-or-higher finding fixed before handing over.

## Needs the owner (not for /goal)
- Approve the Release environment run for v0.4.0, then promote it to **stable**.
- GitHub settings: enable secret scanning + push protection and CodeQL default setup; require CI on `main` before tagging.
- Book an independent human pentest (rounds 2–4 were AI reviews); buyers will ask.
- Legal: CLA/DCO in CONTRIBUTING, DPA + sub-processor list (Anthropic when AI is on), copyright holder (company vs individual).
- Product call on the **Python-on-Windows** install requirement: most Windows fleets will refuse it. Options for 0.5: a frozen
  single-file agent (signed), or a documented all-users Python package. Not in this plan.

## Not doing in 0.4 (on purpose)
WebAuthn, SCIM, roles beyond admin/read-only, write-scoped API tokens, Jira/ServiceNow/SIEM connectors, finding webhooks,
trend reporting, macOS/container/cloud coverage, HA and `/metrics`, air-gapped installs, Cloud KMS, Windows 10 remediation proof,
ledger erasure policy (document only when a buyer asks). Each is a 0.5+ roadmap item; none is a security hole today.

## Suggested /goal
> Complete tasks/plan-0.4-security.md phases 1–5 on branch `security-round-4`: every task's "Done when" met, the release-gate
> checkpoint PASS and recorded in STATUS.md, a fresh security review of the diff with no open medium+ findings. Don't push,
> tag or release.

---

## Done (2026-10-28): each "Done when", and what proves it

Tests are in `api/tests/test_round4.py` (r4), `test_agent_round4.py` (a4), `test_workflows.py` (wf), `test_evidence.py` (ev);
real-host logs in `sandbox/last_run_*.json`. Branch `security-round-4`, commits c228cf1 … final.

| Task | Done when | Evidence | Met |
|---|---|---|---|
| S1 | victim confirms with own password, attacker's fails; old link invalid; check-email copy; migration on SQLite + PG | r4 `test_attacker_cannot_preset_the_password…` (both); `test_upgrade_ends_admin_password_sessions`; `test_migrations` on SQLite and `pg.py` (732 PG); `auth.tsx` copy | yes |
| S2 | chunked body > MAX_BODY to `/api/auth/login` → 413 before the handler | r4 `test_chunked_body_over_the_cap…`; `test_sbom.py::test_oversized_body_413` (streamed route) | yes |
| S3 | a test per limit (429/403, clear message); `perf.py --assets 1000` passes under defaults | r4 `test_asset_cap_per_org`, `test_enrolments_per_token_and_inventories_per_org…`; perf run: 1,000 hosts, ingest median 0.47 s, summary 0.30 s, re-match 20.8 s (`last_run_perf_sqlite.json`). The run caught a too-tight enrolment default (100/h): raised to 2,000/h, configurable | yes |
| S4 | Nth AI call 429; two hosts, same finding, one cache entry | r4 `test_ai_is_rate_limited_per_user_and_cached_across_hosts` | yes |
| S5 | `docker compose config` shows the loopback bind; `compose.py` PASS | `compose.py` PASS: `docker-compose port app 8000` = `127.0.0.1:8000` (`last_run_compose.json`) | yes |
| S6 | headers asserted; e2e + axe pass with no CSP console errors | r4 `test_security_headers`, `test_csp_allows…by_hash`; e2e 5 passed, axe clean light/dark; built SPA served by the API in the browser pane: CSP header present, theme script runs, 0 CSP console messages | yes |
| S7 | each ledger entry asserted; packs still verify | r4 `test_enrolment_org_creation_and_password_login_are_ledgered`; ev suite passes; sbx packs verified | yes |
| I1 | tenant isolation, last-admin guard, sessions gone on removal, idle expiry; e2e promote + remove | r4 `test_invite_promote_demote_and_remove`, `test_idle_sessions_expire_and_sign_out_everywhere`; e2e "admins sign in with their code, manage people…" | yes |
| I2 | RFC 6238 vectors; admin password login without code refused; recovery code single use; break-glass needs TOTP; e2e enrol + login | r4 `test_totp_matches_rfc6238_vectors`, `test_admin_password_sign_in_needs_mfa`, `test_code_guesses_are_capped…`, `test_no_admin_session_without_a_second_factor`; `test_sso.py::test_break_glass…`; e2e first two tests | yes |
| I3 | each path incl. enumeration-equal responses and token reuse | r4 `test_password_change_needs_current…`, `test_password_change_revokes_api_tokens`, `test_password_reset_by_email`, `test_reset_and_invite_need_smtp` | yes |
| I4 | own org only, no admin/mutating routes, revoked → 401 | r4 `test_api_tokens_are_read_only_and_scoped_to_their_org`, `test_api_token_ends_with_its_admin`, `test_expired_api_token`, `test_recovery_ends_api_tokens_too`; e2e token + CSV + 403 | yes |
| I5 | formula-injection test; Export button | r4 `test_csv_export_escapes_formulas`, `test_csv_exports_are_rate_limited`; `findings.tsx` Export CSV; e2e CSV by token | yes |
| A1 | shellcheck-clean `install.sh`; doc steps run once in a Debian sandbox and recorded | shellcheck clean (`install.sh`, `update.sh`); `sandbox/oob_install.py` PASS in a disposable Debian distro against the real v0.3.1 release, tampered agent and manifest both caught (`last_run_oob_install.json`) | yes |
| A2 | unit tests per manager; Alpine refuses a forged downgrade, normal fix PASS | a4 `test_pinned_older_version…` (apt), `test_apk_pinned_downgrade_and_dry_run_downgrade…`, `test_dnf_and_zypper_downgrade_sections…`; `sbx.py` Alpine and Debian PASS with the forged job refused by real `apk` / `dpkg` | yes |
| A3 | unit test; real host shows the directory gone after success and rollback | a4 `test_rollback_copy_is_removed…`, `test_no_change_without_room…`, `test_a_reused_job_id…`; sbx Alpine + Debian: 0 copies left | yes |
| A4 | preview refused by a stable agent, beta taken by a beta agent; runbook reviewed | a4 `test_channel_matrix`, `test_stable_host_skips_a_preview_build…`, `test_enrol_records_the_channel`; `platform_update.py` beta agent 0.3.0 → 0.3.1; `docs/release-keys.md` (matches `sign_release.py`'s CLI). `min_agent_version` dropped on purpose (DECISIONS 39) | yes |
| A5 | a test each; Windows proof optional | a4 `test_a_trailing_newline…`, `test_json_responses_are_capped`, `test_installers_pass_the_channel_and_check_the_trusted_folder_properly` (asserts the backslash). Windows proof done anyway: `winlocal.py` on a fresh Windows 11 26H2 VM PASS (`last_run_windows_local.json`). Its first run passed on permissions while `install.ps1` had failed at scheduling: a real bug since agent 0.2.0 (installs without remediation; a silenced "not found" as the last `-Command` statement exits 1), reproduced in the VM with the agent's own `ps()`, fixed, guarded by `test_agent_schedule.py::test_removing_a_missing_job_poll_still_exits_0`, and `winlocal.py` now also requires the install to finish and the SYSTEM task to exist | yes |
| A6 | `platform_update.py` PASS plus: untracked override refused, same-name branch ignored | `platform_update.py` PASS with both new cases (`last_run_platform_update.json`) | yes |
| C1–C5 | CI green on the branch (owner pushes); `release.yml` dry-read; SBOM ingests | wf `test_actions_are_pinned…`, `test_signing_runs_only_hash_pinned_code…`, `test_the_signing_job_downloads_no_package_tool`; audit steps run locally (pip-audit 0, npm audit 0); hashed signing install checked locally; both CycloneDX SBOMs ingested (55 + 92 components mapped). **CI on GitHub: needs the owner's push** (the goal forbids pushing) | yes, except the owner's push |
| P1 | default stays stable; 0.4.0 promoted by the owner; README says which channel until then | `compose.yaml` / `.env.example` default `stable`; README early-access note; promotion is the owner's (STATUS "Needs the user") | yes, promotion is the owner's |
| P2 | SOC 2 CC7.1/CC8.1, NIS2; per-org SLA in the pack; honest timing wording | ev `test_org_sla_and_new_framework_mappings_are_in_the_pack`; r4 `test_sla_changes_in_the_period_are_in_the_pack`; sbx packs list the new controls | yes |
| P3 | revoke; accept one CVE everywhere (ledgered) | r4 `test_accept_a_vulnerability_everywhere_and_revoke_one` | yes |
| P4 | README version, test counts, STATUS newline, DECISIONS superseded, todo.md gone, restore + RPO/RTO, SECURITY.md, security.txt | README v0.4 + 731→732 counts; STATUS fixed; DECISIONS 13/15/17 marked; `tasks/todo.md` removed; restore proven by `compose.py`; r4 `test_security_txt` | yes |
| P5 | DECISIONS 34+, STATUS, CHANGELOG 0.4.0, versions | DECISIONS 34–40; STATUS "Last runs (0.4.0)"; CHANGELOG [0.4.0]; pyproject/package.json/compose 0.4.0, `AGENT_VERSION` 0.3.0 | yes |
| Gate | all listed runs PASS, recorded in STATUS; fresh review, medium+ fixed | STATUS "Last runs (0.4.0)". On the final server code (after the last server change, the enrolment default): PostgreSQL 17 suite 732, `compose.py` PASS, `platform_update.py` PASS; SQLite suite 733 after the Windows-only agent fix (that line runs only on Windows, proven by `winlocal.py`); sbx Alpine + Debian and `agent_schedule.py` rerun on the final commit: PASS. Review (full reports: tasks/security-review-0.4.md): 1 high + 3 medium + 7 lower found and fixed; two re-reviews, the last concluding "Both residuals are closed. I found nothing medium or higher in the new working-tree change." | yes |
| C1–C5, P1 | CI green on GitHub; 0.4.0 promoted to stable | **Can't be met under this goal:** both need a push or a release, which the goal forbids. Every CI job's steps ran locally on this code (ruff, both suites, Docker build via `compose.py`, web build + unit + e2e, the audit job); promotion is the owner's | owner |
