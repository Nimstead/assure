"""Give a demo database months of history for the Progress page (README screenshots, UI review).

The demo's findings are real (real inventories, real advisories), but they were all detected in one sitting, so every
line on Progress is flat. This replays a simulated history over them: each finding is detected at some point in the
last DAYS days (most at the first enrolment), fixed after a time that depends on its priority (or not yet), and a few
come back or are accepted. Owners go on the assets. The org's ledger is rebuilt in time order with a valid hash chain,
and every finding row ends in the state its history says, so Progress, Findings and the evidence pack agree.

The history is simulated: say so wherever its screenshots are shown. Run it on a copy, never a real server's database,
and point the server at a fresh checkpoint directory (the old checkpoints sign the old chain).

    cd api && uv run python ../sandbox/progress_demo.py sqlite:///path/to/copy.db [--days 120] [--seed 146]
"""

import argparse
import random
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.orm import sessionmaker

from nimstead.db import Asset, Finding, LedgerEntry, Org, make_engine
from nimstead.evidence import GENESIS
from nimstead.verify_pack import entry_hash

TEAMS = ["Payments", "Platform", "IT", "Data"]
FIXED_SHARE = {"fix-now": 0.96, "next": 0.88, "planned": 0.65, "low": 0.4}  # ever fixed
MEAN_DAYS = {"fix-now": 6, "next": 14, "planned": 30, "low": 55}  # how long a fix takes, on average


def iso(t: datetime) -> str:
    return t.replace(tzinfo=UTC).isoformat(timespec="microseconds")


def simulate(rng: random.Random, priority: str, now: datetime, days: int) -> list[tuple[datetime, str]]:
    """One finding's events, in time order, all before now."""
    start = now - timedelta(days=days)
    if rng.random() < 0.7:  # found at the first enrolment
        t = start + timedelta(hours=rng.uniform(0, 48))
    else:  # found later: new advisories, new machines, new software
        t = start + timedelta(days=rng.uniform(2, days - 0.5))
    events = [(t, "finding_opened")]
    while True:
        done = t + timedelta(days=rng.expovariate(1 / MEAN_DAYS[priority]))
        if rng.random() > FIXED_SHARE[priority] or done >= now:  # not fixed (yet)
            if rng.random() < 0.02 and (now - t).days > 2:  # accepted, with a reason, rather than fixed
                events.append((t + timedelta(days=rng.uniform(1, (now - t).days)), "finding_accepted"))
            break
        events.append((done, "finding_resolved"))
        if rng.random() > 0.03 or (now - done).days < 3:  # most stay fixed
            break
        t = done + timedelta(days=rng.uniform(1, (now - done).days))  # the vulnerable version came back
        events.append((t, "finding_reopened"))
    return sorted(events)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("db", help="SQLAlchemy URL of a copy of a demo database with one organisation")
    ap.add_argument("--days", type=int, default=120)
    ap.add_argument("--seed", type=int, default=146)
    a = ap.parse_args()
    rng = random.Random(a.seed)  # noqa: S311 - a fixed seed, so the screenshots can be made again
    s = sessionmaker(make_engine(a.db))()
    (org_id,) = s.execute(select(Org.id)).one()
    now = datetime.now(UTC).replace(tzinfo=None) - timedelta(minutes=5)
    for i, asset in enumerate(s.scalars(select(Asset).where(Asset.org_id == org_id).order_by(Asset.hostname))):
        asset.owner = None if i % 7 == 6 else TEAMS[i % len(TEAMS)]  # a few left without an owner
    rows = []
    for f in s.scalars(select(Finding).where(Finding.org_id == org_id)):
        events = simulate(rng, f.priority if f.priority in FIXED_SHARE else "low", now, a.days)
        state, opened, resolved = "open", events[0][0], None
        for t, kind in events:
            if kind == "finding_resolved":
                state, resolved = "resolved", t
            elif kind == "finding_reopened":
                state, opened, resolved = "open", t, None
            elif kind == "finding_accepted":
                state = "accepted"
        f.status, f.first_seen, f.resolved_at = state, opened, resolved
        f.accepted_until = now + timedelta(days=60) if state == "accepted" else None
        data = {"host": "", "vuln_id": f.vuln_id, "package": f.package, "installed_version": f.installed_version,
                "fixed_version": f.fixed_version, "priority": f.priority}
        rows += [(t, kind, f.id, {**data, **({"by": "demo@example.com", "reason": "Compensating control: not reachable from outside",
                                               "expires_in_days": 90} if kind == "finding_accepted" else {})}) for t, kind in events]
    # the rest of the org's record keeps its own times; finding events from the demo's single sitting are replaced
    kept = [(datetime.fromisoformat(e.ts).replace(tzinfo=None), e.kind, e.subject, e.data) for e in s.scalars(
        select(LedgerEntry).where(LedgerEntry.org_id == org_id, LedgerEntry.kind.not_like("finding_%")))]
    s.execute(delete(LedgerEntry).where(LedgerEntry.org_id == org_id))
    s.flush()
    prev = GENESIS
    for seq, (t, kind, subject, data) in enumerate(sorted(kept + rows, key=lambda r: r[0]), start=1):
        e = {"seq": seq, "ts": iso(t), "kind": kind, "subject": subject, "data": data, "prev_hash": prev}
        prev = entry_hash(e)
        s.add(LedgerEntry(org_id=org_id, hash=prev, **e))
    s.commit()
    print(f"{len(rows)} finding events over {a.days} days; ledger rebuilt with {len(kept) + len(rows)} entries, head {prev[:10]}")


if __name__ == "__main__":
    main()
