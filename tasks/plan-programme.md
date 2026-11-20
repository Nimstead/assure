# Implementation plan: programme view (owners, progress, weekly summary)

Spec: `tasks/spec-programme.md`. Tasks: `tasks/todo-programme.md`. Branch: `programme`. Release: 0.11.0 (preview).
No agent change (agent stays 0.8.1).

## Overview
Three slices on one foundation. The foundation is `progress.replay`, a pure function that turns the ledger's finding
events plus the current finding rows into per-day open counts by priority, overdue and accepted, weekly opened and
resolved, and per-owner numbers. Owners add one column on assets (and one on enrolment tokens). The Progress page and
the weekly summary both read the same replay, so the page, the CSV and the message can't disagree.

## Architecture decisions
- **Replay, not snapshots (DECISIONS 146).** Read `finding_opened|reopened|resolved|accepted|acceptance_revoked|
  acceptance_expired` rows `(seq, ts, kind, subject)` in seq order, with `policy_changed` for deadlines through
  `evidence.sla_history`. Join to current finding rows (`id, asset_id, priority, status`) and asset owners. Findings with
  no row (deleted assets) are skipped; findings with no ledger record are counted, not charted.
- **Interval model.** Each finding becomes a list of state intervals `[t0, t1)` with state `open` or `accepted`.
  A day's count is the state at the day's end (23:59:59.999999 UTC; today: now). Built with a sweep: each interval adds
  +1 at its first day and −1 after its last, then a prefix sum. O(events + days × priorities). Overdue needs the age, so
  per open interval the overdue start day is `opened + deadline` and the same sweep counts overdue.
- **Deadline basis.** As the pack: the deadline in force when the exposure began (open or reopen), at current priority.
  An accepted finding isn't overdue; when acceptance ends it is judged from its original open time (as Findings does).
- **Self-check.** After replay, each finding's final state must equal its row's status; disagreements are counted in
  `basis.mismatched` and those findings are left out of every series (named in "How this is judged").
- **Owner (DECISIONS 145).** `Asset.owner String(100) NULL`. Normalised on write: trim, collapse whitespace, empty →
  NULL, and if any asset in the org has the same owner case-insensitively, take that spelling. `EnrollToken.owner`
  copies to the asset at enrolment. Owner-only PATCH skips the rescan (scores don't depend on it) and is allowed on images.
  Findings filter `owner=<name>` or `owner=` (empty = no owner) through the asset join.
- **Weekly summary (DECISIONS 147).** `Org.weekly_summary Boolean default false`. The hourly feeds run calls
  `progress.send_weekly_summaries(s)`: for each org with it on, if now is Monday 08:00 UTC or later in an ISO week with no
  `notification` row of kind `weekly_summary` for that org since that Monday 00:00 UTC, build the text and `notify()`.
  The notification row (written by the delivery path) is the "already sent" marker, so restarts and several workers don't
  double-send; a lock on the org row serialises two concurrent runs.
  *Check while building:* that `notify._deliver` writes a `Notification` row per attempt with `kind`; if it writes only on
  failure, write a marker row explicitly.
- **Web.** One new page `progress.tsx`, hand-drawn SVG (stacked areas by priority with the ramp fills plus a direct label
  and mark at the right edge; weekly bars opened vs resolved). A visually hidden table carries every number for screen
  readers, and a "Show as table" disclosure for everyone. No chart library.

## Dependency graph
```
T1 replay (pure) ──► T4 /api/progress + CSV ──► T6 Progress page ──► T8 e2e/axe + screenshots
T2 migration ──► T3 owners API ──► T5 owners web          │
        └──────────────► T7 weekly summary (needs T1, T2) ─┘ ──► T9 docs, versions, release notes
```

## Task list (details in todo-programme.md)
### Phase 1: foundation (riskiest first)
- T1 Replay with an oracle test and a speed check
- T2 Migration: owner on assets and enrolment tokens, weekly summary switch
- T3 Owners API: patch, normalise, enrolment token, findings and assets filter, CSV
#### Checkpoint A: `uv run pytest -q` green, ruff clean, replay oracle passes 200 histories, timing recorded
### Phase 2: the features
- T4 `/api/progress` and `/api/progress.csv`, agreement with Findings and the evidence pack
- T5 Owners in the web: drawer, bulk bar, filters, enrolment token
- T6 Progress page
#### Checkpoint B: web unit + build green; the page checked in the browser on a seeded server, light/dark, 375/1440
### Phase 3: reach and polish
- T7 Weekly summary
- T8 e2e and axe for Progress; demo history and README screenshot
- T9 Docs, DECISIONS 145-147, CHANGELOG Highlights, STATUS, version 0.11.0
#### Checkpoint C: full API suite, web unit, build, lint, e2e; then review (code + security), fixes, PR, CI, release

## Parallel work
T1 and T2 are independent; T5 and T6 are independent once T3 and T4 are in. Built in one session in order; the review
uses independent agents (code reviewer, security auditor) on the finished diff.

## Risks and mitigations
| Risk | Impact | Mitigation |
|---|---|---|
| Replay disagrees with Findings (missed event kind, accepted→resolved path, container closes) | High: the page's core promise | Oracle test + end-state self-check counted on screen; grep every `evidence.append(... "finding_` and `acceptance_` kind first |
| Slow on big ledgers (inventory events dominate the table) | Med | Filter by kind in SQL, read 4 columns as tuples; add an `(org_id, kind)` index only if measured > 1 s |
| Chart unreadable at 375px or in dark mode | Med | Tokens from `index.css`, direct labels, table alternative, axe + screenshots in both themes |
| Summary sent twice (two workers, restart) | Med | Notification row as marker + org row lock; test two runs |
| Demo history for screenshots looks synthetic | Low | Label it in README as history replayed over 90 days from the demo's real inventories |
| Owner spelling drift ("Payments" vs "payments ") | Low | Case-insensitive reuse on write + datalist in the UI |

## Open questions
None blocking; answered in the spec under the owner's goal.
