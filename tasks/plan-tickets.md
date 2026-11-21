# Plan: tickets (spec: `tasks/spec-tickets.md`; tasks: `tasks/todo-tickets.md`)

Written 2026-11-21 on the owner's goal (spec, plan, build, test, review, ship), which passes the gates between phases.

## Overview
One server module, `tickets.py`, turns open findings into the tickets they should be in (one per owner and fix),
compares that with the tickets it already opened, and makes the tracker match: open, update, close with the reason each
machine left, reopen. Two small clients (Jira REST v2, GitLab API v4) behind one interface, both over
`netguard.guarded_client`. The hourly feed run calls the sync after the re-match; Settings → Ticketing configures it,
tests the connection, previews and syncs now. No agent change.

## Architecture decisions
- **Desired state, then diff** (DECISIONS 150, 152). `desired(s, org)` is a pure read: every open finding at or above the
  threshold on a routed asset lands in one group, keyed `owner|ecosystem|package` (machines) or `owner|image|<asset id>`
  (images). Its fingerprint is the first 12 hex of SHA-256 of the key; the ticket's `nimstead-<fingerprint>` label is how
  a lost create is found again. The sync diffs desired groups against `Ticket` rows. Preview is the same diff with the
  writes left out, so what it shows is what sync does.
- **Rows record what was sent.** `Ticket.machines` keeps `{asset_id: [hostname, version]}` as last written, so the next
  sync can say who left and why (look up the asset: gone, other owner, findings resolved with time, accepted until),
  and `body_sha` keeps the description from being rewritten when nothing changed.
- **Row before remote** (DECISIONS 152). A new group's row is committed with no key first; after the tracker answers,
  the key is saved. A row with no key is searched for by label before creating, so a crash between can't duplicate.
- **One sync at a time per org.** `TicketSettings.sync_started` is claimed under the row's lock (`with_for_update`) and
  committed before any tracker call; a claim older than 15 minutes is stale. The lock is never held across HTTP.
- **Reads before writes.** Each sync first reads the tracker state of up to 200 open tickets (least recently checked
  first) so a hand close is seen, then writes: closes, reopens, updates, opens, most urgent first, at most 100 writes.
- **Links never come from the tracker.** Jira `{site}/browse/{key}`; GitLab `{site}/{project path}/-/issues/{iid}`.
  Keys are validated (`^[A-Z][A-Z0-9_]+-\d+$`, a positive integer). Replies are capped at 1 MB.
- **Escaping.** Every agent-reported string goes in a code span: Jira `{{…}}` with wiki markup characters backslash
  escaped; GitLab backtick spans with the fence longer than any run of backticks inside, and no newline. Titles are
  plain text, control characters dropped, 255 characters at most.
- **Private hosts** (DECISIONS 153). `netguard.check_public_url` skips the public-address check only for hosts named in
  `NIMSTEAD_ALLOW_PRIVATE_HOSTS` (exact, case-insensitive hostname match); addresses are still pinned.
- **Secret handling.** The token is sealed with `sso.seal` like the webhook URL; the API returns only `token_set: true`.

## Phases and tasks (details and checks in `tasks/todo-tickets.md`)
### Phase 1: foundation
- T1 Schema: `TicketSettings`, `Ticket`, one migration.
- T2 `NIMSTEAD_ALLOW_PRIVATE_HOSTS` in netguard.
- T3 `tickets.desired`: grouping, routing, threshold, titles, bodies, labels, due dates.
### Checkpoint A: API suite passes; `desired` matches Fix first's grouping on the demo DB.
### Phase 2: the loop
- T4 Jira and GitLab clients with stateful fakes; Test connection.
- T5 `tickets.sync`: diff, open/update/close/reopen, reads, cap, row-before-remote, lock, ledger.
- T6 API (settings, test, preview, sync), hourly hook, ticket links on findings, Fix first and images.
### Checkpoint B: API suite, ruff; the whole lifecycle against both fakes.
### Phase 3: the product
- T7 Settings → Ticketing (web) and the links in Findings and Home.
- T8 e2e and axe for Settings → Ticketing.
- T9 `sandbox/tickets.py`: the loop on a real GitLab CE with the real agent.
- T10 `perf.py --tickets`.
- T11 Docs, CHANGELOG, DECISIONS 150+, STATUS.
### Checkpoint C: everything green; then review (code review + security audit), fixes, ship.

## Risks and mitigations
| Risk | Impact | Mitigation |
|---|---|---|
| No real Jira here | High | Fakes follow Atlassian's documented v2 contract (status categories, transitions, Cloud `/search/jql` vs Data Center `/search`, a create screen without a due date); every call checked against Atlassian's published OpenAPI spec (`sandbox/jira_contract.py`, added at review); a live run needs the owner's site; STATUS says so |
| GitLab CE is heavy (4 GB RAM, minutes to boot) in WSL | Med | 32 GB host; time-box the boot wait; the harness checks `/-/readiness` and fails clearly |
| Ticket storms on first switch-on | High | Preview first; fix-now default; 100 writes per sync, most urgent first |
| Fighting a team that closes by hand | Med | Reopen comment says how to stop it (accept the risk in Nimstead); never more than one reopen per ticket per sync |
| Hostile package names | Med | Code spans with escaping; tests with markup, mentions, links and backticks |
| Tracker slow or down | Med | 10 s timeouts, guarded client's total deadline, one org's failure isolated, errors shown in Settings |
| Two syncs at once | Med | claim under the row lock; unique `(org_id, fingerprint)`; PostgreSQL race test in CI |

## Open questions
None blocking. A real Jira site (the owner's) would turn the Jira proof from fakes into a live run.
