import csv
import io
import random
from datetime import datetime, time, timedelta

from sqlalchemy import func, select, update
from sqlalchemy.orm import sessionmaker
from test_api import INV, enrol, user

from nimstead import evidence, progress
from nimstead.db import Asset, Finding, LedgerEntry, Org, make_engine, now

SLA = dict(evidence.SLA_DAYS)
END = datetime(2026, 11, 20, 13, 30, 7)


# ---- an independent oracle: the state at each instant, replayed from scratch ----------------------------------------

def state_at(events, t):
    """(state, exposure, resolved) after every event at or before t, by the rules the ledger's writers follow."""
    state = exposure = resolved = None
    for ts, kind in events:
        if ts > t:
            break
        if kind in ("finding_opened", "finding_reopened") and state in (None, "resolved"):
            state, exposure, resolved = "open", ts, None
        elif kind == "finding_resolved" and state in ("open", "accepted"):
            state, resolved = "resolved", ts
        elif kind == "finding_accepted" and state == "open":
            state = "accepted"
        elif kind in ("finding_acceptance_revoked", "acceptance_expired") and state == "accepted":
            state = "open"
    return state, exposure, resolved


def moves(events):
    out, state = [], None
    for ts, kind in events:
        before = state
        if kind in ("finding_opened", "finding_reopened") and before in (None, "resolved"):
            state = "open"
            out.append((ts, "opened"))
        elif kind == "finding_resolved" and before in ("open", "accepted"):
            state = "resolved"
            out.append((ts, "resolved"))
        elif kind == "finding_accepted" and before == "open":
            state = "accepted"
        elif kind in ("finding_acceptance_revoked", "acceptance_expired") and before == "accepted":
            state = "open"
    return out


def oracle(findings, days, end, sla_at):
    dates = [(end - (days - 1 - i) * progress.DAY).date() for i in range(days)]
    start = datetime.combine(dates[0], time())
    instants = [datetime.combine(d + progress.DAY, time()) for d in dates[:-1]] + [end]
    out = []
    for t in instants:
        row = {"open": dict.fromkeys(progress.PRIORITIES, 0), "overdue": 0, "accepted": 0}
        for f in findings:
            st, x, _ = state_at(f["events"], t)
            if st == "open":
                row["open"][f["priority"]] += 1
                row["overdue"] += t > x + timedelta(days=sla_at(x)[f["priority"]])
            row["accepted"] += st == "accepted"
        out.append(row)
    monday = dates[0] - timedelta(days=dates[0].weekday())
    weeks = {}
    for f in findings:
        for ts, m in moves(f["events"]):
            if ts.date() >= monday:
                w = weeks.setdefault((ts.date() - monday).days // 7, [0, 0])
                w[m == "resolved"] += 1
    totals = {"open": 0, "overdue": 0, "accepted": 0, "resolved": 0, "on_time": 0, "open_at_start": 0}
    for f in findings:
        st, x, r = state_at(f["events"], end)
        sla = lambda t, f=f: timedelta(days=sla_at(t)[f["priority"]])  # noqa: E731
        totals["open"] += st == "open"
        totals["overdue"] += st == "open" and end > x + sla(x)
        totals["accepted"] += st == "accepted"
        totals["open_at_start"] += state_at(f["events"], instants[0])[0] == "open"
        if st == "resolved" and start <= r <= end:
            totals["resolved"] += 1
            totals["on_time"] += r - x <= sla(x)
    return out, weeks, totals


def random_history(rng, end):
    t = end - timedelta(days=rng.randint(0, 420), minutes=rng.randint(0, 1440))
    events = []
    for _ in range(rng.randint(1, 9)):
        if rng.random() < 0.1:
            t = datetime.combine(t.date() + progress.DAY, time())  # exactly midnight, the instant a day is read at (forward: ledger time never runs back)
        if t > end:
            break
        # mostly the transitions writers make, sometimes one that doesn't apply (the replay must skip it as the oracle does)
        events.append((t, rng.choice(progress.KINDS[:3] * 3 + progress.KINDS[3:])))
        t += timedelta(minutes=rng.randint(1, 60 * 24 * 50))
    return events


def test_replay_matches_a_brute_force_oracle_on_generated_histories():
    rng = random.Random(146)  # noqa: S311 - a fixed seed, so a failing history can be rerun
    for n in range(200):
        days = progress.RANGES[n % 3]
        changes = sorted((END - timedelta(days=rng.randint(0, 400)), {p: rng.randint(1, 120) for p in SLA}) for _ in range(rng.randint(0, 2)))

        def sla_at(t, changes=changes):
            return next((d for ts, d in reversed(changes) if ts <= t), SLA)
        findings = [{"priority": rng.choice(progress.PRIORITIES), "owner": rng.choice(["Payments", "IT", None]), "events": random_history(rng, END)}
                    for _ in range(rng.randint(1, 40))]
        got = progress.build([{**f, **progress.history(f["events"])} for f in findings], days, END, sla_at)
        want_days, want_weeks, want = oracle(findings, days, END, sla_at)
        assert [{k: d[k] for k in ("open", "overdue", "accepted")} for d in got["days"]] == want_days, n
        assert {i: [w["opened"], w["resolved"]] for i, w in enumerate(got["weeks"]) if w["opened"] or w["resolved"]} == want_weeks, n
        t = got["totals"]
        assert (t["open"], t["overdue"], t["accepted"], t["resolved"], t["resolved_on_time"], t["open_at_start"]) == (
            want["open"], want["overdue"], want["accepted"], want["resolved"], want["on_time"], want["open_at_start"]), n
        assert sum(o["open"] for o in got["owners"]) == t["open"] and sum(o["resolved"] for o in got["owners"]) == t["resolved"]


def test_the_range_has_one_point_a_day_and_weeks_start_on_monday():
    got = progress.build([], 90, END, lambda t: SLA)
    assert len(got["days"]) == 90 and got["days"][-1]["date"] == "2026-11-20" and got["days"][0]["date"] == "2026-08-23"
    assert got["start"] == "2026-08-23T00:00:00"
    assert got["weeks"][0]["start"] == "2026-08-17" and got["weeks"][-1] == {"start": "2026-11-16", "opened": 0, "resolved": 0, "partial": True}
    assert all(datetime.fromisoformat(w["start"]).weekday() == 0 for w in got["weeks"])
    assert got["totals"]["mean_days_to_resolve"] is None and got["owners"] == []


def test_owners_are_ordered_by_who_is_behind():
    old = END - timedelta(days=60)
    f = lambda owner, p, ev: {"priority": p, "owner": owner, **progress.history(ev)}  # noqa: E731
    got = progress.build([
        f("IT", "low", [(old, "finding_opened")]),                         # open, not overdue (180 days)
        f("Payments", "fix-now", [(old, "finding_opened")]),               # open and overdue (14 days)
        f(None, "fix-now", [(old, "finding_opened")]),                     # the same, with no owner
        f("Payments", "next", [(old, "finding_opened"), (old + timedelta(days=10), "finding_resolved")]),
    ], 90, END, lambda t: SLA)
    assert [o["owner"] for o in got["owners"]] == ["Payments", None, "IT"]
    pay = got["owners"][0]
    assert (pay["open"], pay["fix_now"], pay["overdue"], pay["resolved"], pay["resolved_on_time"], pay["mean_days_to_resolve"]) == (1, 1, 1, 1, 1, 10.0)


# ---- against the database: the Findings page and the evidence pack ---------------------------------------------------

def flow(env):
    c = user(env)
    h = {"Authorization": f"Bearer {enrol(c)['agent_key']}"}
    c.post("/api/agent/inventory", json=INV, headers=h)
    upgraded = {**INV, "packages": INV["packages"][:2] + [{"ecosystem": "PyPI", "name": "requests", "version": "2.32.4"}]}
    c.post("/api/agent/inventory", json=upgraded, headers=h)
    s = sessionmaker(make_engine(env))()
    return c, s, s.scalar(select(Finding.org_id))


def test_today_is_the_findings_page_and_the_range_is_the_evidence_pack(env, monkeypatch):
    c, s, org_id = flow(env)
    one = s.scalars(select(Finding).where(Finding.status == "open")).first()
    assert c.post(f"/api/findings/{one.id}/accept", json={"reason": "compensating control in place", "days": 30}).status_code == 200
    s.expire_all()
    for later in (0, 200):  # today, and 200 days on (every open finding past its deadline)
        t = now() + timedelta(days=later)
        monkeypatch.setattr(progress, "now", lambda t=t: t)
        got = progress.replay(s, org_id, 90)
        open_now = dict(s.execute(select(Finding.priority, func.count()).where(Finding.org_id == org_id, Finding.status == "open")
                                  .group_by(Finding.priority)).all())
        assert got["days"][-1]["open"] == {p: open_now.get(p, 0) for p in progress.PRIORITIES}
        assert got["days"][-1]["accepted"] == got["totals"]["accepted"] == 1
        m = evidence.build_pack(s, org_id, datetime.fromisoformat(got["start"]), t, with_entries=False)["metrics"]
        tot = got["totals"]
        assert (tot["resolved"], tot["resolved_on_time"], tot["mean_days_to_resolve"], tot["overdue"]) == (
            m["resolved"], m["resolved_within_sla"], m["mttr_days"], m["overdue_open"])
        assert (tot["resolved"] > 0, tot["overdue"] > 0) == (later == 0, later > 0)  # 200 days on, the fixes are before the range
    b = got["basis"]
    assert b["mismatched"] == b["no_ledger_record"] == 0 and b["entries"] >= b["findings"] > 0 and len(b["head_hash"]) == 64


def test_a_finding_whose_history_disagrees_with_its_row_is_counted_not_charted(env):
    c, s, org_id = flow(env)
    before = progress.replay(s, org_id, 30)
    one = s.scalars(select(Finding).where(Finding.status == "open")).first()
    s.execute(update(Finding).where(Finding.id == one.id).values(status="resolved"))  # an edit the ledger never saw
    s.add(Finding(org_id=org_id, asset_id=one.asset_id, ecosystem="Debian:12", package="x", installed_version="1", vuln_id="CVE-0000-0001",
                  advisory_ids=[], reasons=[], priority="fix-now"))  # a row with no ledger record at all
    s.commit()
    got = progress.replay(s, org_id, 30)
    assert got["basis"]["mismatched"] == 1 and got["basis"]["no_ledger_record"] == 1
    assert sum(got["days"][-1]["open"].values()) == sum(before["days"][-1]["open"].values()) - 1


def test_a_deleted_assets_findings_drop_out_as_they_do_from_the_pack(env):
    c, s, org_id = flow(env)
    aid = s.scalar(select(Asset.id).where(Asset.org_id == org_id))
    assert c.delete(f"/api/assets/{aid}").status_code in (200, 204)
    got = progress.replay(s, org_id, 30)
    assert got["totals"]["open"] == 0 and got["basis"]["findings"] == 0 and got["basis"]["entries"] > 0


def test_the_api_and_its_csv_say_the_same_and_a_read_only_token_can_read_them(env):
    c, s, org_id = flow(env)
    aid = s.scalar(select(Asset.id).where(Asset.org_id == org_id))
    assert c.patch(f"/api/assets/{aid}", json={"owner": "=HYPERLINK(1)"}).status_code == 200  # a name a spreadsheet would run
    ro = {"Authorization": "Bearer " + c.post("/api/tokens", json={"name": "ro"}).json()["token"]}
    got = c.get("/api/progress", params={"days": 30}, headers=ro).json()
    assert len(got["days"]) == 30 and got["owners"][0]["owner"] == "=HYPERLINK(1)" and got["basis"]["mismatched"] == 0
    assert [c.get("/api/progress", params={"days": n}).status_code for n in (6, 45, 366)] == [422, 200, 422]
    rows = list(csv.DictReader(io.StringIO(c.get("/api/progress.csv", params={"days": 30}, headers=ro).text)))
    assert len(rows) == 30 and rows[-1]["date"] == got["days"][-1]["date"]
    assert int(rows[-1]["open_fix-now"]) == got["days"][-1]["open"]["fix-now"] and int(rows[-1]["overdue"]) == got["days"][-1]["overdue"]
    owners = list(csv.DictReader(io.StringIO(c.get("/api/progress.csv", params={"days": 30, "table": "owners"}).text)))
    assert owners[0]["owner"] == "'=HYPERLINK(1)" and int(owners[0]["open"]) == got["owners"][0]["open"]
    assert c.get("/api/progress.csv", params={"table": "all"}).status_code == 422


def test_the_weekly_summary_goes_once_a_week_from_monday_morning_and_names_no_host(env, monkeypatch):
    c, s, org_id = flow(env)
    aid = s.scalar(select(Asset.id).where(Asset.org_id == org_id))
    c.patch(f"/api/assets/{aid}", json={"owner": "Payments"})
    sent = []
    monkeypatch.setattr(progress.notify, "notify", lambda s_, o, kind, text, urgent=False: sent.append((o, kind, text)) or True)
    monkeypatch.setenv("NIMSTEAD_PUBLIC_URL", "https://nimstead.example/")
    monday = datetime(2026, 11, 23, 7, 59)  # ISO week 48
    assert progress.send_weekly_summaries(s, monday + timedelta(hours=1)) == 0  # off by default: nobody asked for it
    r = c.put("/api/settings/notifications", json={"weekly_summary": True})
    assert r.status_code == 200 and r.json()["weekly_summary"] is True
    assert progress.send_weekly_summaries(s, monday) == 0  # Monday before 08:00 UTC
    assert progress.send_weekly_summaries(s, monday + timedelta(minutes=1)) == 1
    for later in (timedelta(hours=1), timedelta(days=3)):  # every later run that week: already sent
        assert progress.send_weekly_summaries(s, monday + later) == 0
    assert progress.send_weekly_summaries(s, monday + timedelta(days=7, hours=1)) == 1  # week 49
    (o, kind, text), _ = sent
    assert (o, kind) == (org_id, "weekly_summary") and text.splitlines()[0] == "Weekly summary for Acme"
    assert "Open findings: " in text and "Progress: https://nimstead.example/progress" in text
    assert "web-1" not in text  # it goes to chat tools: counts and owner names, never a host
    assert c.put("/api/settings/notifications", json={"weekly_summary": False}).json()["weekly_summary"] is False
    assert progress.send_weekly_summaries(s, monday + timedelta(days=14, hours=1)) == 0
    logged = [e.data for e in s.scalars(select(LedgerEntry).where(LedgerEntry.kind == "notifications_configured").order_by(LedgerEntry.seq))]
    assert [d["weekly_summary"] for d in logged] == [True, False]


def test_the_summary_reads_as_plain_counts():
    days = [{"date": "2026-11-16", "open": {"fix-now": 5, "next": 3, "planned": 10, "low": 2}, "overdue": 4, "accepted": 0},
            {"date": "2026-11-23", "open": {"fix-now": 2, "next": 3, "planned": 10, "low": 2}, "overdue": 4, "accepted": 0}]
    r = {"start": "2026-11-16T00:00:00", "days": days, "owners": [{"owner": "IT", "overdue": 3}, {"owner": None, "overdue": 1}, {"owner": "Data", "overdue": 0}],
         "totals": {"resolved": 1200, "resolved_on_time": 1100}}
    assert progress.summary_text("Acme", r, None).splitlines() == [
        "Weekly summary for Acme",
        "Open findings: 17 (−3 since 16 Nov); fix now: 2 (−3); overdue: 4 (no change).",
        "Resolved since 16 Nov: 1,200, 1,100 of them on time.",
        "Most overdue: IT 3, no owner 1.",
    ]


def test_a_week_with_nowhere_to_send_is_marked_and_nothing_goes_twice(env):
    c, s, org_id = flow(env)
    assert c.put("/api/settings/notifications", json={"weekly_summary": True}).status_code == 200  # but no webhook, no email
    monday = datetime(2026, 11, 23, 9, 0)
    assert progress.send_weekly_summaries(s, monday) == 0  # notify() had no destination
    org = s.get(Org, org_id, populate_existing=True)
    assert org.weekly_summary_sent == "2026-W48"
    assert progress.send_weekly_summaries(s, datetime(2026, 12, 31, 12, 0)) == 0
    assert s.get(Org, org_id, populate_existing=True).weekly_summary_sent == "2026-W53"  # ISO year 2026 has 53 weeks
