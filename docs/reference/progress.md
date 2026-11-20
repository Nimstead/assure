# Progress reference

`GET /api/progress` and `GET /api/progress.csv` rebuild open findings over time, findings opened and resolved per week, and each owner's numbers from the organisation's evidence ledger and its current finding rows. Nothing is stored. A user session or a read-only organisation API token can read both.

## Parameters

| Parameter | Meaning |
| --- | --- |
| `days` | Whole UTC days ending today, 7 to 365. Default 90. The web page offers 30, 90 and 365 |
| `table` | CSV only: `days` (default) or `owners` |

## Response

| Field | Value |
| --- | --- |
| `start`, `end` | The range: midnight UTC at the start of its first day, and now (naive UTC timestamps) |
| `days` | One row per UTC day, oldest first: `date`, `open` (counts by priority: `fix-now`, `next`, `planned`, `low`), `overdue`, `accepted` |
| `weeks` | One row per week from the Monday on or before the first day: `start` (the Monday), `opened`, `resolved`, `partial` (true for the current week) |
| `owners` | One row per owner, most overdue first, then most fix-now, then most open; `owner` is `null` for assets with none |
| `totals` | The same counts as an owner row, for every finding charted |
| `basis` | What the result rests on: `entries` (finding events read), `head_seq` and `head_hash` (the ledger entry it read up to), `findings` (rows of the organisation's live assets), `no_ledger_record`, `mismatched`, and `problems`: the ledger's integrity check, as on Evidence (empty when the chain verifies; a verified prefix is trusted from cache for up to an hour) |

Each owner row and `totals` has:

| Field | Meaning |
| --- | --- |
| `open`, `fix_now`, `overdue`, `accepted` | Now |
| `open_at_start` | Open at the end of the range's first day |
| `resolved`, `resolved_on_time` | Findings whose latest resolution is in the range and that are still resolved, and how many within their deadline |
| `mean_days_to_resolve` | Mean days from detection (or return) to that resolution, one decimal; `null` when none |

## Rules

- A past day counts the state at its midnight end; today counts the state now, which equals the open findings on Findings by priority.
- Events are the ledger's `finding_opened`, `finding_reopened`, `finding_resolved`, `finding_accepted`, `finding_acceptance_revoked` and `acceptance_expired`, in ledger order. A reopen starts a new exposure, timed from its return.
- Each finding counts at its current priority. It is overdue when open longer than the deadline in force when its exposure began, as the evidence pack judges it. An accepted finding isn't overdue; when acceptance ends it is judged from its original exposure.
- `resolved`, `resolved_on_time` and `mean_days_to_resolve` follow the evidence pack's period rules, so they equal a pack's `resolved`, `resolved_within_sla` and `mttr_days` for the same period.
- Findings on deleted assets aren't counted. A finding with no ledger event is counted in `no_ledger_record`; one whose replayed final state differs from its row's status is counted in `mismatched`; neither is charted.
- Weekly `opened` counts first detections and returns; `resolved` counts every resolution, including one later undone by a return.

Reads are limited to 120 an hour per organisation (`429` beyond that), since each one reads the organisation's whole finding history.

## CSV

`table=days` columns: `date`, `open_fix-now`, `open_next`, `open_planned`, `open_low`, `overdue`, `accepted`. `table=owners` columns: `owner` (empty for none), `open`, `fix_now`, `overdue`, `accepted`, `open_at_start`, `resolved`, `resolved_on_time`, `mean_days_to_resolve`. Owner names that begin with `=`, `+`, `-`, `@`, tab or carriage return get a leading apostrophe. The download shares the 30-per-hour export quota with the findings CSV; a refused attempt returns `429`.

## Weekly summary

See [Notification reference](notifications.md#weekly-summary).
