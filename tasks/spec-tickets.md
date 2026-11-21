# Spec: tickets — fixes reach the owning team's tracker and close on evidence

Status: **written 2026-11-21; the owner set the goal "spec, plan, build, test, review, ship. Next phase. Impress me.
Market leader tool."**, the goal that produced the containers and programme phases. The programme spec named this phase
as the next candidate ("owners are the prerequisite"). Each open question is answered with the recommendation and the
reason, and the gates between phases are passed on that goal. Plan: `tasks/plan-tickets.md`. Tasks:
`tasks/todo-tickets.md`. DECISIONS from 150.

## Objective

**The gap.** Since 0.11 Nimstead knows which team owns each machine and shows who is behind. The work itself still
lives only in Nimstead: a team that plans its week in Jira or GitLab never sees it there, and the security lead copies
findings into tickets by hand, then chases tickets that say "Done" while the machine is still vulnerable. Every tool a
buyer compares us with sends findings to a tracker: Tenable (Jira, ServiceNow), Qualys (ServiceNow ITSM, Jira), Rapid7
InsightVM (Jira, ServiceNow), Microsoft Defender VM (ServiceNow, Intune remediation requests). The common complaint is
a flood of tickets, one per vulnerability per machine, that someone closes by hand on trust.

**Who.** The security lead who runs the programme; the team leads whose queues the tickets land in; the auditor who
asks how a ticket came to be closed.

**What sets ours apart** (the promises the rest of Nimstead keeps):
1. **One ticket per fix per team, not per CVE.** "Upgrade openssl to 3.0.15 on 14 machines" is one ticket in the
   Payments team's project, listing the machines and the CVEs it clears. 300 findings become 9 tickets.
2. **A ticket closes only on evidence.** Nimstead closes it when the machines' own inventory shows the fix (or a person
   accepted the risk in Nimstead, a recorded decision that expires). The closing comment says, machine by machine, why
   each left: fixed and verified at what time, risk accepted by whom until when, moved to another team, machine removed.
3. **"Done" can't hide a vulnerable machine.** If someone closes the ticket while machines are still exposed, or a fix
   regresses, Nimstead reopens it with the machines and the evidence. To stop tracking something, accept the risk in
   Nimstead: that's recorded and expires.
4. **Nothing is sent until you've seen it.** A preview shows every ticket that would be opened, in which project, before
   the switch is on. Every ticket opened, closed and reopened is in the hash-chained ledger.

### User stories and acceptance
- **S1.** As an admin, in Settings → Ticketing, I choose Jira (Cloud or Data Center) or GitLab (gitlab.com or
  self-managed), enter the site URL and a token (and for Jira Cloud, the account email), and a default project. The token
  is write-only: never shown again, never returned by the API. **Test connection** says whether the token works and the
  project exists, in words ("Signed in to Jira as ops-bot; project PAY found").
- **S2.** I route teams to projects: "Payments → PAY", "Platform → OPS". A finding on a machine whose owner has no route
  goes to the default project; with no default, it isn't sent and the preview says how many weren't and why.
- **S3.** I choose which findings become tickets by priority: Fix now (default), Next and above, Planned and above, or
  all. Every open finding at or above it is in exactly one ticket.
- **S4.** **Preview** lists, before anything is sent, the tickets that would be opened, updated, closed or reopened, by
  project, with their titles. Nothing is written to the tracker until I switch ticketing on.
- **S5.** With ticketing on, the hourly feed run (and **Sync now**, rate-limited) opens one ticket per (team, fix):
  package upgrades on machines grouped by ecosystem and package as Fix first groups them; a container image's findings
  as one "Rebuild image …" ticket for the team that owns the image; a setting as "Change … on N machines"; end of support
  as "Upgrade or replace …". Each ticket says the priority, the due date (the earliest deadline among its findings, set
  as the tracker's due date where it has one), the fix, the machines (hostname and installed version), the CVEs, and a
  link to Findings filtered to it. Labels: `nimstead`, the priority and a stable `nimstead-<id>` label.
- **S6.** As machines are fixed or join, the ticket's description is kept current, with one comment per change: "Fixed
  on db-1, db-2 (verified by inventory 21 Nov 10:14 UTC). 12 machines left."
- **S7.** When none of its findings is open any more, Nimstead comments why each machine left and closes the ticket
  (moves it to the first status in the Done category on Jira; closes the issue on GitLab).
- **S8.** If a finding in a closed ticket's group opens again (a regression, a new machine, an acceptance ending), or the
  ticket was closed in the tracker while findings are open, Nimstead reopens it with a comment naming the machines. A
  ticket deleted in the tracker is opened afresh.
- **S9.** Findings, Fix first on Home and Rebuild images show each finding's ticket as a link (key and state).
- **S10.** Settings → Ticketing shows the last sync (when, opened, updated, closed, reopened, failed, waiting for the
  next run), open tickets by project, and the last errors in the tracker's own words.
- **S11.** A read-only member and a read-only API token see ticket links; only admins change ticketing, test, preview or
  sync. Every settings change and every ticket opened, closed and reopened is in the ledger.

### Answered open questions (owner: "impress me", the same autonomy as the last two phases)
1. **Which trackers?** Jira (Cloud and Data Center, REST API v2, which both serve) and GitLab (gitlab.com and
   self-managed, API v4). *Why:* Jira is the tracker most buyers name; GitLab is the second most common for engineering
   and IT teams and, being free to self-host, lets us prove the whole loop on a real server here. ServiceNow needs an
   instance we can't run here; it's the next tracker, behind the same sync. (DECISIONS 150)
2. **Ticket per CVE, per machine, or per fix?** Per (owner, fix): the grouping Fix first already uses (ecosystem and
   package for machines; the image for images). *Why:* that's the unit of work a team does, and it ends the flood.
   (DECISIONS 150)
3. **Who owns ticket state?** Nimstead. The tracker's "Done" is not evidence; the machine's inventory is. A ticket closed
   by hand while findings are open is reopened with the evidence; accepting the risk in Nimstead is the way to stop
   tracking (recorded, expires). Nimstead never closes a finding because a ticket closed. (DECISIONS 151)
4. **How often?** In the hourly feed run, right after the re-match, plus Sync now (6 an hour per org). A fix verified by
   inventory closes its ticket within the hour. Each sync reads the tracker state of up to 200 open tickets, least
   recently checked first, so with up to 200 open tickets a hand-closed one is reopened within the hour. (DECISIONS 152)
5. **Floods and runaway writes.** At most 100 tracker writes per org per sync, the most urgent tickets first (KEV, then
   worst score); the rest wait for the next run and Settings says how many. (DECISIONS 152)
6. **Self-hosted trackers on private networks.** Ticket requests use the same SSRF guard as webhooks and SSO: HTTPS,
   public addresses, connection pinned to the checked address. A server operator (not an org admin) can allow named
   private hosts with `NIMSTEAD_ALLOW_PRIVATE_HOSTS=jira.corp.example,gitlab.corp.example`, which applies to webhooks
   and SSO too. *Why:* on a shared server an org admin must not be able to reach the operator's network, but an
   intranet Jira is the common enterprise case. (DECISIONS 153)
7. **Hostnames in tickets?** Yes. Unlike the weekly summary (chat tools), a ticket is the work item the org chose to
   send, and a team can't act without the machine names. The settings page says so. (DECISIONS 153)
8. **Changing tracker or site.** Nimstead forgets the tickets it opened in the old one (it stops updating them) and
   opens fresh ones in the new one. The UI says how many it will stop updating before saving. (DECISIONS 150)
9. **Duplicates after a crash.** A ticket row is written before the tracker call; if the process dies between the
   tracker's create and saving the key, the next sync finds the ticket by its `nimstead-<id>` label before creating.
   (DECISIONS 152)
10. **Agent change?** None. No agent release.

## Tech stack
Unchanged: Python 3.14, FastAPI, SQLAlchemy 2, Alembic, httpx through `netguard.guarded_client`, SQLite (dev/tests) and
PostgreSQL 17; React 19, TanStack Router/Query, Tailwind 4, Vitest, Playwright + axe. **No new dependency.**

## Commands
```
API tests:     cd api && uv run pytest -q
One file:      cd api && uv run pytest -q tests/test_tickets.py
Lint:          cd api && uv run ruff check src tests ../agent ../sandbox ../scripts
Web unit:      cd web && npm test
Web build:     cd web && npm run build
Web e2e:       cd web && npm run e2e
Docs checks:   cd api && PYTHONUTF8=1 uv run python ../scripts/check_docs.py && uv run python ../scripts/export_api_docs.py --check
Migrations:    cd api && uv run pytest -q tests/test_migrations.py   (PostgreSQL: CI, or ../sandbox/pg.py)
Real tracker:  cd api && uv run python ../sandbox/tickets.py              (GitLab CE in a disposable WSL distro)
               cd api && uv run python ../sandbox/tickets.py --jira URL   (a real Jira site; email and token from env)
Performance:   cd api && uv run python ../sandbox/perf.py --assets 1000 --tickets
```

## Project structure (what's new)
```
api/src/nimstead/tickets.py       grouping findings into tickets, the sync (open/update/close/reopen), Jira and GitLab clients
api/src/nimstead/netguard.py      NIMSTEAD_ALLOW_PRIVATE_HOSTS: operator-named private hosts
api/src/nimstead/app.py           /api/settings/tickets (+ /test, /preview, /sync); ticket links on findings, Fix first, images
api/src/nimstead/feeds.py         the hourly run syncs tickets after the re-match
api/src/nimstead/db.py            TicketSettings (one per org), Ticket (one per team and fix)
api/migrations/versions/…         one migration for the two tables
api/tests/test_tickets.py         stateful fake Jira and GitLab; lifecycle, routing, caps, crash recovery, escaping, auth
sandbox/tickets.py                the whole loop against a real GitLab CE (and a real Jira site when given one)
web/src/tickets.tsx               Settings → Ticketing (connection, routes, preview, status)
web/src/findings.tsx, home.tsx    ticket links
docs/how-to/…, docs/reference/…   how-to for Jira and GitLab; API reference; configuration (the new variable)
```

## Code style
Match the module you're in. Server: plain functions over rows; docstrings that say what is and isn't done; comments only
for the why. A tracker client is a few small methods over one guarded httpx client:
```python
class GitLab:
    def create(self, project: str, t: dict) -> str:
        r = self._call("POST", f"/api/v4/projects/{quote(project, safe='')}/issues",
                       json={"title": t["title"], "description": t["body"], "labels": ",".join(t["labels"]), "due_date": t["due"]})
        return str(_int(r, "iid"))  # the key; the link is built from the site URL, never taken from the reply
```
Web: one file per section, `lib.ts` for types and fetchers, `ui.tsx` primitives (`Field`, `Done`, `ErrorState`,
`HowJudged`, `ConfirmDialog`), DESIGN.md's glossary ("finding", "resolved", "overdue", "owner"), priority with marks,
never colour alone.

## Testing strategy
- **Lifecycle against stateful fakes** (`httpx.MockTransport`) of Jira and GitLab that keep issues, statuses, comments,
  labels and transitions: open, group by fix, route by owner, default project, threshold, update on change, close on
  evidence with why each machine left, accepted closes, reopen on regression and on a hand close, a deleted ticket
  reopened afresh, write cap and order, a crash between create and save found by label, one org's tracker failing costs
  no other org its sync, a failing ticket costs no other ticket.
- **Contracts the fakes enforce from the trackers' documented APIs:** Jira transitions chosen by status category (a
  workflow whose Done is named "Shipped" still closes), a create screen without a due date (retried without it), Cloud's
  `/search/jql` and Data Center's `/search`; GitLab state events, label filters, `due_date`.
- **Safety:** tracker replies capped and validated (key format, sizes); links built from the site URL, never the
  reply; every agent-reported string (package, hostname, version) escaped for Jira wiki markup and GitLab Markdown so a
  hostile package name can't add links, mentions or markup; token never returned; private addresses refused unless the
  operator named the host; admin-only writes; tenant isolation; ledger entries for every lifecycle step.
- **Concurrency:** two syncs at once open each ticket once (PostgreSQL in CI and `pg.py`).
- **Migration:** upgrade and downgrade in `test_migrations.py`.
- **Web:** unit tests for the Settings section (connection, routes, preview, status, errors) and the links; axe in e2e
  at 1440 and 375 in light and dark on Settings → Ticketing.
- **Real tracker:** `sandbox/tickets.py` runs the full loop on a real GitLab CE behind TLS in a disposable WSL distro,
  with real findings from the real agent: opened, routed, updated, closed on a verified fix, reopened after a hand close
  and after a regression, a deleted issue reopened afresh, and a hostile package name rendered inert.
- **Performance:** `perf.py --tickets` at 1,000 hosts: a sync's own cost (grouping and diffing) with a fake tracker.

## Boundaries
- **Always:** tests before commits (a test that fails first for each fix); ledger entries for settings and ticket
  lifecycle; the SSRF guard for every tracker request; the DESIGN.md glossary and copy budget.
- **Ask first (answered by the owner's goal for this phase):** the schema migration; push, PR, merge, tag and the
  preview release. Approving the release gate stays the owner's. Creating an account on any external service (Jira
  Cloud, gitlab.com) is not done: the real-tracker proof runs on a self-hosted GitLab; a real Jira run needs the owner's
  site.
- **Never:** close a finding because a ticket closed; send anything before ticketing is switched on; return or log the
  token; follow a link or redirect a tracker sends; a new dependency; an agent change.

## Success criteria
1. Settings → Ticketing configures Jira or GitLab with a write-only token, team routes, a default project and a
   threshold; Test connection and Preview work without sending anything; switching on starts syncing.
2. Every open finding at or above the threshold on a routed machine is in exactly one open ticket; no ticket is open
   without an open finding at or above the threshold (checked by the tests and by `sandbox/tickets.py`).
3. A ticket closes only when none of its findings is open, with a comment naming why each machine left; it reopens on a
   regression or a hand close while findings are open; each step is ledgered.
4. **Real proof:** `sandbox/tickets.py` PASS on a real GitLab CE with the real agent (`last_run_tickets.json`).
5. **Speed:** a sync with nothing to change at 1,000 hosts (297k open findings, fix-now threshold) costs under 5 s of
   Nimstead's own time with a fake tracker, measured and recorded in STATUS.
6. API suite, web unit tests, web build, lint, docs checks and e2e pass; CI green on SQLite and PostgreSQL 17.
7. An independent code review and a security audit of the branch; every finding fixed with a test that failed first.
8. Docs: a how-to (Jira and GitLab), the API reference, configuration (the new variable), CHANGELOG with a Highlights
   summary, STATUS, DECISIONS 150+.
9. Released as 0.12.0 on the preview channel once the owner approves the gate; signature and agent hash verified.

## Not doing (this phase)
ServiceNow, GitHub Issues and Azure Boards (the next trackers, behind the same sync); two-way field sync (assignee,
priority, custom fields); closing or accepting findings from the tracker; tickets per CVE or per machine; per-project
issue types or field mappings; webhooks from the tracker (Nimstead polls); ticket counts in the evidence pack (format
change); the agent.
