# Spec: programme view — owners, progress over time, a weekly summary

Status: **written 2026-11-20; the owner set the goal "spec, plan, build, test, review, ship. Next phase. Impress me.
Market leader tool."**, the same goal that produced the containers phase, so each open question below is answered with the
recommendation and the reason, and the gates between phases are passed on that goal. Plan: `tasks/plan-programme.md`.
Tasks: `tasks/todo-programme.md`. DECISIONS from 145.

## Objective

**The gap.** Nimstead tells an operator what to fix today and proves to an auditor what was fixed in a period. It can't
answer the questions the person who runs the vulnerability programme asks every week: *is our risk going down? which
team is behind? are we fixing faster than we find?* There's no notion of who owns a machine, no history on screen (the
Evidence page shows one period's totals), and nothing reaches anyone who doesn't sign in. Every tool a buyer compares us
with has all three: Tenable (asset ownership tags, trend dashboards, scheduled reports), Qualys VMDR (tags, TruRisk trends,
scheduled reports), Rapid7 InsightVM (remediation owners, trend cards, report schedules), Microsoft Defender VM (device
groups, exposure trend, weekly digest).

**Who.** The security lead or IT manager who runs patching across teams and reports upward; the team leads who own
machines; the auditor who reads the same numbers.

**What sets ours apart** (the promises the rest of Nimstead keeps):
1. **A trend you can prove.** Every point on the chart is rebuilt from the hash-chained ledger, the same record the
   signed evidence pack rests on, not from snapshots a database edit could change. The page names the ledger head it was
   built from, and a period's on-time share and mean days to resolve agree exactly with the evidence pack for that period.
2. **Today's point is the Findings page.** The last day of every series equals the live counts on Findings, by priority.
   A finding whose ledger history disagrees with its current state is counted and named, never smoothed over.
3. **Plain Sight, not a wall of tiles.** One sentence that answers "better or worse?", one chart, one table of owners
   ordered by who is behind. No risk score nobody can explain.
4. **Ownership costs nothing to set up.** An enrolment token can carry an owner, so a team's machines arrive owned; bulk
   edit sets the rest; owners are typed once and reused, case-insensitively.

### User stories and acceptance
- **S1.** As an admin I set an asset's owner (a team name) in its drawer, in bulk on Assets, or on an enrolment token so
  every machine enrolled with it starts with that owner. Owner names are reused: typing "payments" when "Payments" exists
  saves "Payments". Clearing it leaves the asset with no owner. The change is recorded in the ledger.
- **S2.** I filter Assets and Findings by owner (including "No owner"), and the findings CSV has an owner column.
- **S3.** On a new **Progress** page I see open findings per day for the last 30, 90 or 365 days, stacked by priority, with
  how many were overdue each day; the last point equals the Findings page's open counts by priority.
- **S4.** I see findings opened and resolved per week, so I can tell whether we fix faster than we find, and a one-line
  answer: "Open findings fell from 1,240 to 1,183 in 90 days; 12 are overdue." When the fix-now count is falling, the line
  also says at what pace and when it would reach zero at that pace; when it is rising, it says so.
- **S5.** I see each owner's open, fix-now and overdue findings now, findings resolved in the range, the share resolved
  within their deadline, mean days to resolve, and the change in open findings over the range, ordered by overdue first.
  An owner's name opens Findings filtered to that owner.
- **S6.** "How this is judged" says what the page was built from (ledger entries read, the head hash), that each finding
  counts at its current priority and against the deadline in force when it was detected, and lists anything not charted
  (findings with no ledger record, ledger history that disagrees with a finding's state).
- **S7.** I can download the daily series and the owner table as CSV.
- **S8.** With **Weekly summary** switched on in Settings, the org's alert destinations (webhook and confirmed emails)
  get one message each Monday after 08:00 UTC: open findings and the change over the week, fix-now and overdue counts,
  findings resolved and the share on time, and the owners with the most overdue findings, with a link to Progress. Off by
  default, so an upgrade sends nobody a message they didn't ask for. Never more than one per org per ISO week, even
  across restarts and several API workers.
- **S9.** A read-only user and a read-only API token can read Progress and its CSV; only admins change owners, tokens and
  the summary switch.

### Answered open questions (owner: "impress me", the same autonomy as the containers phase)
1. **Owner or tags?** One owner per asset (a team), not free tags. *Why:* the questions are "who is behind" and "who do
   I chase"; a finding needs exactly one accountable team. Tags answer a different question (grouping) and can come later
   without undoing this. (DECISIONS 145)
2. **Snapshots or replay?** Replay the ledger. *Why:* snapshots start empty on upgrade and can be edited; the ledger has
   every open, reopen, resolve and acceptance since day one, and the evidence pack already trusts it for timing. Replay
   gives full history on the first day after upgrade. Cost is bounded (measured, see success criteria). (DECISIONS 146)
3. **Priority as judged then, or now?** Now. *Why:* otherwise today's point disagrees with Findings the first time EPSS
   moves, and the evidence pack also judges each finding at its current priority. Said on the page. (DECISIONS 146)
4. **Deleted assets.** Their findings drop out of every point, as they drop out of the evidence pack (rows cascade). Said
   on the page. Re-deriving them from ledger hostnames would guess. (DECISIONS 146)
5. **Accepted findings.** Not open (they're a recorded decision), shown as their own line so accepting risk can't make
   the chart look better unseen. (DECISIONS 146)
6. **Days in UTC.** The org has no single time zone (maintenance windows are per asset). Labelled "days in UTC".
7. **Weekly summary default.** Off. *Why:* destinations were set up for failure alerts; a new kind of message after an
   upgrade is a surprise. One switch in Settings → Alerts turns it on. (DECISIONS 147)
8. **Image owners.** An image can have its own owner (the team that builds it), set like any asset; the PATCH that
   refuses criticality changes on images accepts an owner. (DECISIONS 145)
9. **Owner on the agent?** No agent change. The enrolment token carries the owner on the server, so no agent release
   is needed and a host can't claim a team. (DECISIONS 145)

## Tech stack
Unchanged: Python 3.14, FastAPI, SQLAlchemy 2, Alembic, SQLite (dev/tests) and PostgreSQL 17; React 19, TanStack
Router/Query, Tailwind 4, Vitest, Playwright + axe. **No new dependency**: the charts are hand-drawn SVG (two charts).

## Commands
```
API tests:     cd api && uv run pytest -q
One file:      cd api && uv run pytest -q tests/test_progress.py
Lint:          cd api && uv run ruff check src tests ../agent ../sandbox ../scripts
Web unit:      cd web && npm test
Web build:     cd web && npm run build
Web e2e:       cd web && npm run e2e
Migrations:    cd api && uv run pytest -q tests/test_migrations.py   (PostgreSQL: CI, or ../sandbox/pg.py)
Performance:   cd api && uv run python ../sandbox/perf.py --assets 1000
Dev server:    cd api && NIMSTEAD_SECURE_COOKIES=0 NIMSTEAD_API_PORT=8010 uv run uvicorn --factory nimstead.app:create_app --port 8010
```

## Project structure (what's new)
```
api/src/nimstead/progress.py      replay of the ledger into daily/weekly series and the owner table; the summary text
api/src/nimstead/app.py           /api/progress, /api/progress.csv; owner on assets, findings, enrolment tokens; settings switch
api/src/nimstead/feeds.py         the hourly run sends the weekly summary when due
api/src/nimstead/db.py            Asset.owner, EnrollToken.owner, Org.weekly_summary
api/migrations/versions/…         one migration for the three columns
api/tests/test_progress.py        replay against a brute-force oracle, pack agreement, API, CSV, summary
web/src/progress.tsx              the Progress page (sentence, chart, weekly flow, owners table, CSV)
web/src/assets.tsx, findings.tsx  owner field, filter and bulk edit
web/src/settings.tsx              Weekly summary switch; owner on new enrolment tokens
docs/how-to/…, docs/reference/…   owners and Progress; API reference
```

## Code style
Match the module you're in. Server: plain functions over rows, docstrings that say what is and isn't done, comments only
for the why. For example, the replay keeps the evidence pack's shape:
```python
for e in rows:  # ordered by ledger seq
    if e.kind == "finding_resolved":
        close(e.subject, ts)
    elif e.kind == "finding_reopened":  # a regression is a new exposure, timed from its return (as the pack times it)
        open_(e.subject, ts)
```
Web: one file per page, `lib.ts` for types and fetchers, Tailwind tokens from `index.css`, DESIGN.md's glossary
("overdue", never "SLA" outside a standard's wording; "resolved"; "finding"), priority ramp with marks, never colour alone.

## Testing strategy
- **Replay is exact:** a brute-force oracle (for each day, scan every event up to that day) against `progress.replay` on
  generated histories (opens, reopens, resolves, accepts, revokes, expiries, policy changes) with a fixed seed.
- **Agrees with the rest of the product:** the last day equals the open counts by priority from the findings table; a
  range's on-time share and mean days to resolve equal `evidence.build_pack`'s metrics for the same period.
- **API contracts:** auth (read-only can read; admins write), range validation, CSV shape, owner filter on findings and
  assets, owner normalisation, enrolment token owner applied at enrolment, image owner allowed.
- **Summary:** due once per ISO week per org, not before Monday 08:00 UTC, not when off, idempotent across two runs.
- **Migration:** upgrade and downgrade in `test_migrations.py` (SQLite here, PostgreSQL 17 in CI).
- **Web:** unit tests for the page (sentence wording, table order, empty states), axe in e2e at 1440 and 375, light/dark.
- **Performance:** the 206-asset, 44k-finding demo database and `perf.py`.

## Boundaries
- **Always:** tests before commits; ledger entries for every owner and settings change; same numbers as Findings and the
  evidence pack; DESIGN.md glossary and copy budget.
- **Ask first (answered by the owner's goal for this phase):** the schema migration; push, PR, merge, tag and the preview
  release. Approving the release gate stays the owner's.
- **Never:** a new web or Python dependency for charts; a stored trend a database edit could change silently; hostnames
  or addresses in the weekly summary (it goes to chat tools: counts and owner names only); changing the evidence pack
  format.

## Success criteria
1. Owners: set in drawer, bulk and via enrolment token; normalised; ledgered; filterable on Assets and Findings; in the
   findings CSV and the assets API. Images accept an owner.
2. `/api/progress?days=30|90|365` returns daily open-by-priority, overdue and accepted series, weekly opened/resolved,
   the owner table and the basis (entries read, head hash, not-charted counts). The oracle test passes on 200 generated
   histories; the last day equals the findings table; the range metrics equal the evidence pack's.
3. **Speed:** `/api/progress?days=365` under 1.0 s on the 206-asset, 44k-finding demo database (SQLite, this machine),
   measured and recorded in STATUS.
4. The Progress page answers "better or worse" in one sentence, renders the chart with a table alternative, sorts owners
   by overdue, links to filtered Findings, and passes axe at 1440 and 375 in light and dark.
5. The weekly summary is sent once per org per ISO week when on, never when off, never with hostnames, through the
   existing webhook and email paths and their retries.
6. API suite, web unit tests, web build, lint and e2e pass; CI green on SQLite and PostgreSQL 17.
7. Docs: a how-to (owners and Progress), the API reference, CHANGELOG with a Highlights summary, STATUS, DECISIONS 145+.
8. Released as 0.11.0 on the preview channel once the owner approves the gate; signature and agent hash verified.

## Not doing (this phase)
Free-form tags; per-owner deadlines; a team's members or notifications per owner (the summary goes to the org's
destinations); Jira/ServiceNow tickets (next candidate phase: owners are the prerequisite); PDF reports; risk scores;
time zones other than UTC; an owner column in the evidence pack (format change); the agent.
