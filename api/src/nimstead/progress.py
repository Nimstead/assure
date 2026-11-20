"""Progress over time (DECISIONS 146): open findings per day by priority, opened and resolved per week, and each owner's
numbers, rebuilt from the hash-chained ledger and the current finding rows on the evidence pack's basis. Each finding
counts at its current priority, against the deadline in force when its exposure began; a deleted asset's findings drop
out, as they drop out of the pack. Nothing is stored: the same ledger always gives the same chart."""

import os
from bisect import bisect_left, bisect_right
from datetime import datetime, time, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from nimstead import evidence, notify
from nimstead.db import Asset, Finding, LedgerEntry, Org, now

KINDS = ("finding_opened", "finding_reopened", "finding_resolved", "finding_accepted", "finding_acceptance_revoked",
         "acceptance_expired")
PRIORITIES = ("fix-now", "next", "planned", "low")
RANGES = (30, 90, 365)
DAY = timedelta(days=1)


def history(events: list) -> dict:
    """One finding's ledger events [(ts, kind)], in ledger order, as state intervals.

    Return {intervals, moves, final, exposure, resolved}: intervals are (state, start, stop, exposure) with state "open"
    or "accepted" and stop None while it lasts; moves are the applied (ts, "opened"|"resolved") changes; final is "open",
    "accepted", "resolved" or None (nothing opened it); exposure is when the latest exposure began (a reopen starts a new
    one, as the pack times it); resolved is the latest resolution, cleared by a reopen. An event that doesn't apply to
    the state it finds is skipped: the end-state check against the finding's row counts what that hides."""
    out, moves, state, since, exposure, resolved = [], [], None, None, None, None
    for ts, kind in events:
        if kind in ("finding_opened", "finding_reopened") and state in (None, "resolved"):
            state, since, exposure, resolved = "open", ts, ts, None
            moves.append((ts, "opened"))
        elif kind == "finding_resolved" and state in ("open", "accepted"):
            out.append((state, since, ts, exposure))
            state, resolved = "resolved", ts
            moves.append((ts, "resolved"))
        elif kind == "finding_accepted" and state == "open":
            out.append(("open", since, ts, exposure))
            state, since = "accepted", ts
        elif kind in ("finding_acceptance_revoked", "acceptance_expired") and state == "accepted":
            out.append(("accepted", since, ts, exposure))
            state, since = "open", ts
    if state in ("open", "accepted"):
        out.append((state, since, None, exposure))
    return {"intervals": out, "moves": moves, "final": state, "exposure": exposure, "resolved": resolved}


def _row(owner):
    return {"owner": owner, "open": 0, "fix_now": 0, "overdue": 0, "accepted": 0, "open_at_start": 0, "resolved": 0,
            "resolved_on_time": 0, "mean_days_to_resolve": None, "_ttr": []}


def build(findings: list, days: int, end: datetime, sla_at) -> dict:
    """The series for `days` UTC days ending at `end` (naive UTC) from findings [{priority, owner, **history()}].

    A past day counts the state at its midnight end; today counts the state at `end`. Overdue: open past the deadline in
    force when its exposure began, at its current priority (`sla_at(t)` gives that policy, as evidence.sla_history).
    Owner rows and totals use the pack's period rules: resolved means resolved now, last resolved in [start, end]."""
    dates = [(end - (days - 1 - i) * DAY).date() for i in range(days)]
    start = datetime.combine(dates[0], time())
    ts = [datetime.combine(d + DAY, time()) for d in dates[:-1]] + [end]  # the instant each day is read at
    opens = {p: [0] * (days + 1) for p in PRIORITIES}
    overdue, accepted = [0] * (days + 1), [0] * (days + 1)
    monday = dates[0] - timedelta(days=dates[0].weekday())
    weeks = (dates[-1] - monday).days // 7 + 1
    flow = [[0, 0] for _ in range(weeks)]  # opened, resolved
    week0 = datetime.combine(monday, time())
    owners, totals = {}, _row(None)
    for f in findings:
        p = f["priority"]

        def due(x, p=p):
            return x + timedelta(days=sla_at(x).get(p, 180))
        for state, a, b, x in f["intervals"]:
            i, j = bisect_left(ts, a), days if b is None else bisect_left(ts, b)  # counted on the days a <= T < b
            if i >= j:
                continue
            arr = accepted if state == "accepted" else opens[p]
            arr[i] += 1
            arr[j] -= 1
            if state == "open":
                k = max(i, bisect_right(ts, due(x)))  # overdue once T is past the deadline
                if k < j:
                    overdue[k] += 1
                    overdue[j] -= 1
        for t, move in f["moves"]:
            w = (t - week0).days // 7
            if 0 <= w < weeks:
                flow[w][move == "resolved"] += 1
        row = owners.setdefault(f["owner"], _row(f["owner"]))
        was_open = any(st == "open" and a <= ts[0] and (b is None or ts[0] < b) for st, a, b, _ in f["intervals"])
        for r in (row, totals):
            r["open_at_start"] += was_open
            if f["final"] == "open":
                r["open"] += 1
                r["fix_now"] += p == "fix-now"
                r["overdue"] += end > due(f["exposure"])
            elif f["final"] == "accepted":
                r["accepted"] += 1
            elif f["final"] == "resolved" and f["resolved"] and start <= f["resolved"] <= end:
                d = (f["resolved"] - f["exposure"]).total_seconds() / 86400
                r["resolved"] += 1
                r["resolved_on_time"] += d <= sla_at(f["exposure"]).get(p, 180)
                r["_ttr"].append(d)
    for r in (*owners.values(), totals):
        ttr = r.pop("_ttr")
        r["mean_days_to_resolve"] = round(sum(ttr) / len(ttr), 1) if ttr else None

    def run(arr):
        out, n = [], 0
        for v in arr[:days]:
            n += v
            out.append(n)
        return out
    o, od, ac = {p: run(opens[p]) for p in PRIORITIES}, run(overdue), run(accepted)
    return {
        "start": start.isoformat(), "end": end.isoformat(),
        "days": [{"date": d.isoformat(), "open": {p: o[p][i] for p in PRIORITIES}, "overdue": od[i], "accepted": ac[i]}
                 for i, d in enumerate(dates)],
        "weeks": [{"start": (monday + timedelta(weeks=w)).isoformat(), "opened": flow[w][0], "resolved": flow[w][1],
                   "partial": w == weeks - 1} for w in range(weeks)],
        # who is behind first: overdue, then fix now, then open; no owner sorts after a named owner with the same numbers
        "owners": sorted(owners.values(), key=lambda r: (-r["overdue"], -r["fix_now"], -r["open"], r["owner"] is None,
                                                         (r["owner"] or "").lower())),
        "totals": {k: v for k, v in totals.items() if k != "owner"},
    }


def replay(s: Session, org_id: str, days: int) -> dict:
    """build() for org_id from its ledger, read up to the head it names, and its current finding rows.

    basis says what it rests on: finding events read, the ledger head, and findings left out because they have no
    ledger record or their history disagrees with their current state (each counted, never guessed). No write."""
    head = s.execute(select(LedgerEntry.seq, LedgerEntry.hash).where(LedgerEntry.org_id == org_id)
                     .order_by(LedgerEntry.seq.desc()).limit(1)).first()
    rows = {i: (p, st, o) for i, p, st, o in s.execute(
        select(Finding.id, Finding.priority, Finding.status, Asset.owner).join(Asset, Asset.id == Finding.asset_id)
        .where(Finding.org_id == org_id))}
    events, read = {}, 0
    if head:
        for ts, kind, subject in s.execute(select(LedgerEntry.ts, LedgerEntry.kind, LedgerEntry.subject).where(
                LedgerEntry.org_id == org_id, LedgerEntry.kind.in_(KINDS), LedgerEntry.seq <= head.seq).order_by(LedgerEntry.seq)):
            read += 1
            if subject in rows:  # a deleted asset's findings are gone from the table, and from the pack
                events.setdefault(subject, []).append((datetime.fromisoformat(ts).replace(tzinfo=None), kind))
    findings, mismatched = [], 0
    for fid, (priority, status, owner) in rows.items():
        if fid not in events:
            continue
        h = history(events[fid])
        if h["final"] != status:
            mismatched += 1
            continue
        findings.append({"priority": priority, "owner": owner, **h})
    out = build(findings, days, now(), evidence.sla_history(s, org_id))
    out["basis"] = {"entries": read, "head_seq": head.seq if head else 0, "head_hash": head.hash if head else evidence.GENESIS,
                    "findings": len(rows), "no_ledger_record": len(rows) - len(events), "mismatched": mismatched}
    return out


SUMMARY_AT = 8  # hour (UTC) on Monday from which the week's summary goes out
SUMMARY_DAYS = 8  # today and the seven days before: "since" the same weekday last week


def summary_text(org_name: str, r: dict, base_url: str | None) -> str:
    """The weekly summary (DECISIONS 147): counts and owner names only, never a hostname or address, since it goes to
    chat tools. The first line is the email subject."""
    def change(now_, then):
        d = now_ - then
        return f"{d:+,}".replace("-", "\u2212") if d else "no change"
    first, last, t = r["days"][0], r["days"][-1], r["totals"]
    start = datetime.fromisoformat(r["start"])
    since = f"{start.day} {start:%b}"
    open_now, open_then = sum(last["open"].values()), sum(first["open"].values())
    lines = [f"Weekly summary for {org_name}",
             f"Open findings: {open_now:,} ({change(open_now, open_then)} since {since}); fix now: {last['open']['fix-now']:,} "
             f"({change(last['open']['fix-now'], first['open']['fix-now'])}); overdue: {last['overdue']:,} ({change(last['overdue'], first['overdue'])}).",
             f"Resolved since {since}: {t['resolved']:,}" + (f", {t['resolved_on_time']:,} of them on time." if t["resolved"] else ".")]
    behind = [o for o in r["owners"] if o["overdue"]][:5]
    if behind:
        lines.append("Most overdue: " + ", ".join(f"{o['owner'] or 'no owner'} {o['overdue']:,}" for o in behind) + ".")
    if base_url:
        lines.append(f"Progress: {base_url}/progress")
    return "\n".join(lines)


def send_weekly_summaries(s: Session, at: datetime | None = None) -> int:
    """For each org with the weekly summary on, send it once per ISO week, from Monday SUMMARY_AT:00 UTC on (DECISIONS 147).

    The week is marked on the org row, under its lock, before the message is queued, so two runs or a restart never send
    it twice; a delivery that fails is retried by notify.retry_failed like any alert. An org with no destination is
    marked too (there was nothing to send). Commits per org. Return the number of summaries queued."""
    at = at or now()
    year, week, weekday = at.isocalendar()
    if weekday == 1 and at.hour < SUMMARY_AT:
        return 0  # Monday before the hour: last week's summary has gone; this one waits until Monday next
    label, sent = f"{year}-W{week:02d}", 0
    for org_id in s.scalars(select(Org.id).where(Org.weekly_summary.is_(True))).all():
        org = s.get(Org, org_id, with_for_update=True, populate_existing=True)
        if org is None or org.weekly_summary_sent == label:
            s.rollback()
            continue
        org.weekly_summary_sent = label
        text = summary_text(org.name, replay(s, org_id, SUMMARY_DAYS), (os.environ.get("NIMSTEAD_PUBLIC_URL") or "").rstrip("/") or None)
        s.commit()
        sent += notify.notify(s, org_id, "weekly_summary", text)
    return sent
