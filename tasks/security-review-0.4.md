# Security review of branch `security-round-4` (0.4.0, agent 0.3.0)

An independent read-only reviewer (a security-auditor agent given the diff and the threat model, not this branch's
conclusions) reviewed `git diff main...HEAD`, then verified the fixes twice. Its reports, as delivered, condensed only
where marked; file:line references are to the code at the time of each pass.

## Pass 1: the diff (after phases 1-5)

1 high, 3 medium, 6 low, 1 info. Round-4 tests: 46 passed.

1. **HIGH, TOTP brute force over IPv6 /64s.** A wrong code counted as an ordinary login failure. The per-email cap of 100
   only stops addresses that have already failed, so every fresh /64 gets one guess per 15 minutes. With the password
   and a /48 (65,536 /64s): about 55% success in an hour. Fix: a per-user wrong-code counter across all addresses.
2. **MEDIUM, admins with sessions that never passed MFA.** Sign-up (first account and the emailed link) started an admin
   session; promotion kept password-only sessions; the migration kept old admin sessions. Whoever signs in first with
   the password enrols their own authenticator. Fix: no admin session without TOTP; end sessions on promotion.
3. **MEDIUM, API tokens survive account recovery.** Reset, sign-out-everywhere and password change deleted only
   sessions; tokens could be made without expiry and without a code. Fix: revoke on recovery, need a code, cap expiry.
4. **MEDIUM (supply chain), unpinned uv binary in the signing job.** `setup-uv` without a version installs the latest uv,
   which builds the venv that later runs with the release key. Fix: pin it, or use the runner's python3 + pip --require-hashes.
5. LOW, a reused job id could delete a kept rollback copy (the job aborts, `discard_rollback` removes the folder).
6. LOW, the last-admin check races (two admins demoting each other).
7. LOW, a TOTP or recovery code can be used twice by concurrent requests.
8. LOW, pending links cancelled across tenants; the tenant's org name (could contain a URL) in invitation email.
9. LOW, evidence packs apply today's SLA to the whole period.
10. LOW, CSV export builds up to 200k rows in memory, unthrottled.
11. INFO, Swagger UI at `/api/docs` exempt from the CSP and loads CDN scripts.

Checked clean: API token scoping, cross-org user management, risk acceptance, link purposes and single use, the MFA setup
blob, BodyLimit, CSP hashing, CSV escaping, agent regexes, downgrade refusal, channel check, response cap, installer
changes, update.sh ordering, CI triggers and pinning.

## Pass 2: the fixes (commit 0097e91)

| # | Status |
|---|---|
| 1 | Partly fixed (see A) |
| 2 | Fixed: `admin_user`, sign-up, link confirm, promotion, migration |
| 3 | Mostly fixed (see B) |
| 4 | Fixed: release.yml uses runner python3 + pip --require-hashes --only-binary |
| 5 | Fixed: precheck refuses an existing folder; only a folder this run made is deleted |
| 6 | Fixed on PostgreSQL (SQLite still races) |
| 7 | Fixed on PostgreSQL |
| 8 | Fixed |
| 9 | Partly fixed: changes disclosed in the pack; status uses today's SLA. Acceptable as documented |
| 10 | Fixed enough: 30 an hour per org, 100k rows, still in memory |
| 11 | Fixed: Swagger UI opt-in |

- **A. LOW-MEDIUM:** concurrent requests could pass the per-account cap. The count ran before the row lock, `fail()`
  rolled back (releasing it) before committing the failure, and the alert fired only on exactly 10.
- **B. LOW:** password change didn't revoke tokens; SSO admins need no code to make a token (their MFA is the IdP's).

New issues introduced by the fixes: none at medium or above (cap-based lockout needs the password; no MFA bypass;
`with_for_update` really locks; migration SQL correct; agent mkdir race fails closed; signing step downloads nothing).

## Pass 3: residuals A and B (commit 9558e4d)

> Both residuals are closed. I found nothing medium or higher in the new working-tree change.

- A fixed on PostgreSQL: the user row is locked before counting `mfa:` failures, `fail()` no longer rolls back on a
  wrong code and commits the failure while holding the lock, so a queued request sees it; the alert is `>=` and once
  per window. On SQLite it doesn't serialise (expected; SQLite is dev only).
- Nothing committed by mistake on the failure path: `second_factor` and `finish_mfa_setup` change nothing when they fail.
- B fixed: `change_password` deletes the user's tokens; covered by a new test.
- Low, not security: `test_admin_password_sign_in_needs_mfa` was flaky near a 30 s boundary (since fixed by pinning the
  clock; five consecutive clean runs).

Not tested by the reviewer: the locking on real PostgreSQL (the PostgreSQL suite passes), deadlocks from housekeeping
deletes under the lock (no cycle seen).

## Pass 4: the last two changes (`git diff 9558e4d HEAD -- agent api/src deploy .github`)

> Neither change opens anything medium or higher, and the rest of the diff is clean.

- Windows scheduling fix: no security issue. It removes only an existing task named exactly 'Nimstead jobs'; nothing in it
  comes from the server; remediation is still gated by the agent's local opt-in. The error text adds PowerShell's exit
  code and local output only.
- Enrolment default 100 → 2,000 an hour per token: low. A leaked token reaches the org's 5,000-asset cap in about 2.5 hours
  instead of about 50; the damage stays in that org, and the asset cap and the per-org inventory limit still protect a
  shared server. A non-numeric value stops the app at startup (operator error).
- update.sh lint fixes: behaviour unchanged.

**Verdict on the whole branch: no medium-or-higher finding open.** Remaining low items: packs judge the period against
today's SLA (changes listed), the in-memory CSV export (capped), the PostgreSQL-only row locks, and the sign-in test the
reviewer saw flake once (already fixed by pinning the clock; five clean runs since).

## After the review

One later change touched security-relevant code: the Windows schedule fix (agent: remove the job-poll task only if it
exists; the failure message names PowerShell's exit code). It removes a silently failing statement and adds no input
handling; proven on a real Windows 11 VM (`sandbox/winlocal.py`) and unit-guarded. The enrolment-rate default rose from
100 to 2,000 an hour per token (asset cap unchanged); a quota value, not a new path.
