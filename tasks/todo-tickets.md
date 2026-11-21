# Todo: tickets (plan: `tasks/plan-tickets.md`)

## Phase 1: foundation
- [ ] **T1 Schema.** `TicketSettings` (org_id PK; kind `jira|gitlab`; site; user (Jira Cloud email, "" = bearer); token
  sealed; default_project; routes `[{owner, project}]`; min_priority; enabled; sync_started; last_sync dict) and
  `Ticket` (id; org_id; fingerprint, unique per org; owner; group `{kind, ecosystem, package | asset_id}`; project;
  key; state `open|closed`; title; body_sha; machines; opened_at; closed_at; checked_at; error). One migration.
  - Acceptance: tables on SQLite via `create_all` and on PostgreSQL via Alembic; upgrade/downgrade round trip.
  - Verify: `uv run pytest -q tests/test_migrations.py`
  - Files: `db.py`, `migrations/versions/…_tickets.py`
- [ ] **T2 Operator-named private hosts.** `NIMSTEAD_ALLOW_PRIVATE_HOSTS` (comma-separated hostnames, case-insensitive)
  lets those hosts resolve to private addresses; literal IPs and every other host unchanged; address still pinned.
  - Acceptance: a named host resolving to 10.x passes; an unnamed one fails; a lookalike (`jira.corp.example.evil`) fails.
  - Verify: `uv run pytest -q tests/test_tickets.py -k private`
  - Files: `netguard.py`, `tests/test_tickets.py`
- [ ] **T3 `tickets.desired`.** Groups open findings at or above the threshold by (owner, ecosystem, package) on
  machines and (owner, image) on images; routes owner → project (casefold), else default, else skipped (counted);
  title, body (priority, due, fix, machines, CVEs capped with "and N more", Findings link), labels, due = earliest
  deadline; most urgent first.
  - Acceptance: 300 findings of one package on 14 machines of one owner are one group; two owners, two groups; an
    unrouted owner with no default is counted as skipped; below-threshold findings excluded; image findings in their own
    group; escaping holds for hostile strings.
  - Verify: `uv run pytest -q tests/test_tickets.py -k desired`
  - Files: `tickets.py`, `tests/test_tickets.py`

### Checkpoint A
- [ ] API suite passes; groups on the demo DB match Fix first's actions for the same owner-less org.

## Phase 2: the loop
- [ ] **T4 Clients.** `Jira` (Basic for Cloud email+token, Bearer for a Data Center PAT; myself, project + issue
  types, create with due date and fallback without, update, comment, status category, transitions by category,
  search by label on `/search/jql` then `/search`) and `GitLab` (PRIVATE-TOKEN; user, project, create, update,
  state_event, notes, get, label search). `test_connection` returns words. Stateful fakes for both.
  - Acceptance: every call validated against the fake's contract; keys validated; replies capped; errors carry the
    tracker's message, trimmed.
  - Verify: `uv run pytest -q tests/test_tickets.py -k client`
  - Files: `tickets.py`, `tests/test_tickets.py`
- [ ] **T5 `tickets.sync`.** Claim, read back up to 200 open tickets, diff, write in order (close, reopen, update,
  open) up to 100, comment on change, close with why each machine left, reopen on regression / hand close, recreate a
  deleted ticket, find a keyless row by label before creating, ledger `ticket_opened|ticket_closed|ticket_reopened`,
  record `last_sync`. `sync_all` for the hourly run, isolated per org.
  - Acceptance: the lifecycle tests in the spec's testing strategy pass against both fakes.
  - Verify: `uv run pytest -q tests/test_tickets.py`
  - Files: `tickets.py`, `feeds.py`, `tests/test_tickets.py`
- [ ] **T6 API.** `GET/PUT /api/settings/tickets` (admin session; token write-only; kind/site change forgets old
  rows, ledgered), `POST /test` (6/h), `GET /preview`, `POST /sync` (6/h); `ticket` on finding detail and list rows,
  `tickets` on Fix first actions, `ticket` on images to rebuild.
  - Acceptance: admin-only writes; read-only token can read links; tenant isolation; validation (URL, project, routes).
  - Verify: `uv run pytest -q tests/test_tickets.py -k api`; `uv run python ../scripts/export_api_docs.py --check`
  - Files: `app.py`, `tests/test_tickets.py`, `docs/reference/…`

### Checkpoint B
- [ ] API suite and ruff pass; full lifecycle green on both fakes.

## Phase 3: the product
- [ ] **T7 Web.** `tickets.tsx`: tracker, site, email (Jira), token (write-only), default project, team routes (owners
  from the org's list), threshold, switch; Test connection, Preview (grouped by project), Sync now; last sync and errors.
  Links in the findings drawer and rows, Fix first and Rebuild images.
  - Verify: `npm test`, `npm run build`
  - Files: `web/src/tickets.tsx`, `settings.tsx`, `lib.ts`, `findings.tsx`, `home.tsx`, a test file
- [ ] **T8 e2e.** Settings → Ticketing renders, validates and previews; axe clean at 1440 and 375 in light and dark.
  - Verify: `npm run e2e`
- [ ] **T9 Real tracker.** `sandbox/tickets.py`: disposable WSL distro, Docker, GitLab CE behind TLS (own CA), the real
  API server and the real agent; open, route, update, close on a verified fix, reopen after a hand close and a
  regression, a deleted issue reopened afresh, a hostile package name inert. Writes `last_run_tickets.json`.
- [ ] **T10 Performance.** `perf.py --tickets`: a no-change sync at 1,000 hosts under 5 s of Nimstead's own time.
- [ ] **T11 Docs.** How-to (Jira and GitLab), reference, configuration, CHANGELOG (Highlights), DECISIONS 150+, STATUS.
  - Verify: `PYTHONUTF8=1 uv run python ../scripts/check_docs.py`

### Checkpoint C
- [ ] API, web unit, build, lint, docs, e2e green; `last_run_tickets.json` PASS.
- [ ] Independent code review and security audit; each finding fixed with a test that failed first.
- [ ] Ship: PR, CI green on SQLite and PostgreSQL 17, release 0.12.0 on preview at the owner's gate approval, verify.
