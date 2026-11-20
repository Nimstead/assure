# Todo: programme view (spec-programme.md, plan-programme.md)

## Phase 1: foundation

- [ ] **T1 Replay** — `progress.replay(s, org_id, days, end=None)` from the ledger and current finding rows.
  - Acceptance: daily `open[priority]`, `overdue`, `accepted` for `days` UTC days ending today; weekly `opened`/`resolved`;
    per-owner rows; `basis` {entries, head_hash, no_ledger_record, mismatched}. Oracle test passes on 200 seeded histories.
  - Verify: `cd api && uv run pytest -q tests/test_progress.py`; timing on the demo DB (`days=365`) recorded.
  - Files: `api/src/nimstead/progress.py`, `api/tests/test_progress.py`. Depends on: none (owner read via getattr until T2).

- [ ] **T2 Migration** — `asset.owner`, `enroll_token.owner` (String(100) NULL), `org.weekly_summary` (bool, server default false).
  - Acceptance: models + one Alembic revision on the current head; upgrade/downgrade test passes.
  - Verify: `uv run pytest -q tests/test_migrations.py`.
  - Files: `api/src/nimstead/db.py`, `api/migrations/versions/<rev>_owners_and_weekly_summary.py`, `api/tests/test_migrations.py`.

- [ ] **T3 Owners API** — PATCH owner (normalised, ledgered, no rescan when alone, allowed on images); `owner` in
  `/api/assets` and finding JSON/CSV; `owner` filter on findings (empty = none) and its count/groups/CSV; `owner` on
  enrolment token create/list, copied at `/api/agent/enroll`.
  - Acceptance: tests for each; read-only can't write; 100-char limit; "payments" reuses "Payments".
  - Verify: `uv run pytest -q tests/test_owners.py tests/test_api.py`.
  - Files: `api/src/nimstead/app.py`, `api/tests/test_owners.py`.

### Checkpoint A
- [ ] `uv run pytest -q` green · `uv run ruff check src tests ../agent ../sandbox ../scripts` clean

## Phase 2: features

- [ ] **T4 Progress API** — `GET /api/progress?days=30|90|365` and `GET /api/progress.csv?days=…&table=days|owners`.
  - Acceptance: last day == open counts by priority from findings; range resolved/on-time/mean days == `build_pack`
    metrics for the same period; read-only token can read; CSV formula-safe; export quota shared.
  - Verify: `uv run pytest -q tests/test_progress.py`.
  - Files: `api/src/nimstead/app.py`, `api/src/nimstead/progress.py`, `api/tests/test_progress.py`.

- [ ] **T5 Owners in the web** — drawer owner field (datalist, saves on change with Saved/Undo), bulk bar owner,
  Assets owner filter, Findings owner filter (URL), owner on a new enrolment token.
  - Acceptance: unit tests for the patch payloads and filters; build passes.
  - Verify: `cd web && npm test && npm run build`.
  - Files: `web/src/assets.tsx`, `web/src/findings.tsx`, `web/src/settings.tsx` or `onboarding.tsx`, `web/src/lib.ts`, `web/src/ux.test.tsx`.

- [ ] **T6 Progress page** — route `/progress`, nav "Progress" (after Remediation), command palette entry; sentence,
  range chips, stacked chart + table alternative, weekly flow, owners table (overdue first, names link to Findings),
  CSV links, "How this is judged".
  - Acceptance: unit tests for the sentence (falling, rising, flat, empty), owner order and links; no new dependency.
  - Verify: `npm test && npm run build`; browser check on a seeded server, light/dark, 375/1440.
  - Files: `web/src/progress.tsx`, `web/src/main.tsx`, `web/src/shell.tsx`, `web/src/lib.ts`, `web/src/ux.test.tsx`.

### Checkpoint B
- [ ] API + web unit green, build green, the page seen working in the browser

## Phase 3: reach and polish

- [ ] **T7 Weekly summary** — `Org.weekly_summary` in `/api/settings` (admin, ledgered as `policy_changed`); switch in
  Settings → Alerts; `progress.send_weekly_summaries` in the hourly feeds run.
  - Acceptance: once per ISO week per org, not before Monday 08:00 UTC, not when off, two runs send one; text has no
    hostnames; tests.
  - Verify: `uv run pytest -q tests/test_progress.py tests/test_notify.py`.
  - Files: `api/src/nimstead/progress.py`, `api/src/nimstead/feeds.py`, `api/src/nimstead/app.py`, `web/src/settings.tsx`.

- [ ] **T8 e2e, axe, screenshots** — Progress in `web/e2e/app.spec.ts` (axe light/dark, 375/1440); a demo history for
  the README shot; `docs/images/progress-1440.png`.
  - Verify: `cd web && npm run e2e`.
  - Files: `web/e2e/app.spec.ts`, `web/e2e/start-api.mjs` seed if needed, `sandbox/…`, `docs/images/`.

- [ ] **T9 Docs and release prep** — how-to (owners and Progress), API reference, README bullet + shot, CHANGELOG
  0.11.0 with Highlights, DECISIONS 145-147, STATUS section, versions 0.11.0 (api, web, compose image).
  - Verify: `uv run pytest -q tests/test_docs.py`; links resolve.

### Checkpoint C
- [ ] Full API suite, web unit, build, lint, e2e green
- [ ] Code review + security review of the branch; every finding fixed or answered
- [ ] PR, CI green (SQLite + PostgreSQL 17), squash-merge, tag v0.11.0, release gate (owner), verify
