# Key decisions

Short log; newest last. Why, not what.

1. **Inventory-based detection over network banner scanning.** An agent reports installed packages; matching happens server-side against OSV. Banner/version guessing is the main source of Tenable/Qualys noise. Network scanning may come later, gated on verified ownership.
2. **OSV.dev as primary advisory source.** One schema covering Debian, Ubuntu, Alpine, RHEL-family, SUSE, PyPI, npm, Go, crates etc., with distro-native fixed versions (backport-aware). Mirrored locally (bulk zips) so detection is fast, offline and auto-updating.
3. **Match distro packages by source package name**, which is what distro advisories reference. Agent must report source names (dpkg `${source:Package}`, rpm SOURCERPM, apk origin).
4. **Refuse to guess.** Unknown ecosystem or unparseable version → no finding (and later a data-quality metric), never a fuzzy match.
5. **Accuracy is tested against OSV itself.** `tests/fetch_fixtures.py` stores real OSV records plus OSV API answers; tests require exact agreement.
6. **Stack:** Python 3.14 + FastAPI 0.162 + SQLAlchemy 2.1 + Pydantic 2.14 (uv). SQLite in dev/tests, Postgres in prod. React + Vite + TS SPA for the UI (logged-in app, no SEO need → no SSR framework).
7. **Remediation never runs shell from the server.** Jobs are closed descriptions (manager + validated package names/versions); the agent maps them to fixed argv templates. A compromised server can't turn the fleet into RCE beyond "upgrade these packages", and only on hosts that opted in locally (`enroll --allow-remediation`).
8. **Reversible or not at all.** The agent saves a rollback package (apt/apk cache or download, sha256 recorded) for every package before changing anything, and aborts if it can't. Health checks (systemd units) run before and after; failure → automatic rollback → verify versions restored. Rollback failure is reported as `rollback_failed`, never swallowed.
9. **Success = proof, not a claim.** A job is `succeeded` only when the next inventory shows its findings resolved; otherwise `not_fixed`.
10. **Trust ladder + canaries.** Org mode suggest → approve → auto. Auto changes land on ring-0 canaries first; the broad ring waits for a canary success that has soaked N hours, and any failure of that change anywhere halts rollout.
11. **Dev guard:** until `NIMSTEAD_ALLOW_PRODUCTION_REMEDIATION=1`, jobs only go to assets enrolled with a sandbox token.
12. **Evidence = hash-chained ledger + Ed25519-signed packs** verifiable offline with a shipped script; the server refuses to sign if the chain fails verification. Time-to-remediate is measured from first detection to the first inventory proving the fix (stated in each pack).
