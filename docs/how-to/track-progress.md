# Track progress and who is behind

Give each asset an owner, then use **Progress** to see whether open findings are going down, whether fixes keep up with what's found, and which team is behind. You need an organisation admin session to set owners and the weekly summary. Every member and read-only API token can read Progress.

## Give assets an owner

An owner is the team accountable for an asset, such as `Payments` or `IT`. Each asset has at most one.

- **One asset:** open **Assets**, select the asset's name, type the team under **Owner**, then leave the field or press Enter.
- **Several assets:** select them on **Assets**, type the team under **Owner** in the selection bar, and select **Apply**.
- **New machines:** on **Add a machine**, type the team under **Owner** before you select **Create install command**. Every machine enrolled with that command starts with that owner.
- **Container images:** open the image on **Assets → Container images** and set its owner: usually the team that builds it.

Names are reused: typing `payments` when `Payments` already exists saves `Payments`, so one team never splits in two. Empty the field to remove an owner. Each change is recorded in the evidence ledger. An owner changes no finding's priority.

Filter **Assets** or **Findings** by owner (Findings keeps it under **More filters**), including **No owner**. The findings CSV has an `owner` column at the end.

## Read Progress

1. Open **Progress**.
2. Choose **30 days**, **90 days** or **1 year**.
3. Read the sentence at the top: whether open findings fell or rose over the range, how many are overdue, and the pace on fix-now findings over the last four weeks.
4. Read the six small charts: overdue, each priority, and accepted risk. Move the pointer over one, or focus them and use the arrow keys, to read any day on all six.
5. Read **Found and fixed, week by week**: opened findings (new, or a fixed one come back) beside resolved findings.
6. Read **By owner**, ordered by overdue findings. Select an owner's name to see their findings.

Each chart has **Show these numbers as a table**. **Daily counts (CSV)** and **Owners (CSV)** download the same numbers.

Each small chart runs from zero on its own scale. Compare the numbers, not the heights of two charts.

## How the numbers are judged

Progress is rebuilt from the evidence ledger every time it loads, not from stored snapshots, so the history is there the day you upgrade and a database edit can't change it unseen. **How this is judged** names the ledger entry it read up to.

- Today's point is the open findings now, as **Findings** shows them. A past day counts what was open at its end (midnight UTC).
- Each finding counts at its current priority. It is overdue once it has been open longer than the deadline in force when it was detected, as the evidence pack judges it.
- Accepted findings aren't open; they have their own chart.
- Resolved on time and mean time to resolve cover findings resolved in the range and still resolved now, the evidence pack's rule, so they match a pack for the same period.
- Findings on deleted assets aren't counted, as in the evidence pack. A finding with no ledger record, or whose ledger history disagrees with its current state, is counted under **How this is judged** and left out of the charts.

## Send a weekly summary

1. Open **Settings** and find the alert settings.
2. Configure a webhook or confirmed email recipients. See [Configure alerts](configure-alerts.md).
3. Select **Weekly summary** and save.

From Monday 08:00 UTC, the hourly feed run sends one summary a week to those destinations: open, fix-now and overdue findings with their change since the same day last week, what was resolved and how much on time, and the owners with the most overdue findings. It names no machine. Set `NIMSTEAD_PUBLIC_URL` for it to link to Progress.

## Use the API

```bash
curl -fsS -H "Authorization: Bearer $NIMSTEAD_API_TOKEN" "https://assure.example.com/api/progress?days=90"
```

`days` is 7 to 365. See the [progress reference](../reference/progress.md) for the fields, and [create a read-only API token](create-api-token.md).
