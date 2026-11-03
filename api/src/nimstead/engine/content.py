"""The detection content one evaluation reads: the existing advisories, as data, with a version that names exactly what was used (T34).

The only module here that touches the database. Advisories change in place with each feed update, so the version is a hash of
what this host's evaluation consulted, plus the newest date in it so a person can read its age. Same inventory and same
content version: same verdicts."""

import hashlib
import json
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from nimstead import msproducts, updates, winapps
from nimstead.db import Advisory, Cvss, Kev
from nimstead.engine.collection import Inventory, installs
from nimstead.scan import HOTPATCH

ECOSYSTEMS = ("Windows", msproducts.ECOSYSTEM, winapps.ECOSYSTEM)


@dataclass(frozen=True)
class Content:
    records: dict[tuple[str, str], list[dict]]  # (ecosystem, product key) -> OSV-shaped records, sorted by id
    kev: frozenset[str]
    cvss: dict[str, float]  # NVD's, for what the advisory itself doesn't score
    feeds: frozenset[str]  # ecosystems with any advisory at all
    version: str

    @classmethod
    def make(cls, records: dict, kev=(), cvss: dict | None = None, feeds=None) -> Content:
        records = {k: sorted(v, key=lambda r: r["id"]) for k, v in records.items()}
        kev, cvss = frozenset(kev), cvss or {}
        feeds = frozenset(feeds if feeds is not None else {e for (e, _), v in records.items() if v})
        body = json.dumps({"app": updates.current_version(), "records": sorted((k, v) for k, v in records.items()), "kev": sorted(kev),
                           "cvss": cvss, "feeds": sorted(feeds)}, sort_keys=True, default=str)
        newest = max((str(r.get("modified", ""))[:10] for v in records.values() for r in v), default="") or "none"
        return cls(records, kev, cvss, feeds, f"{newest}.{hashlib.sha256(body.encode()).hexdigest()[:12]}")


def load(s: Session, inv: Inventory) -> Content:
    wanted = {(i.ecosystem, k) for i in installs(inv) for k in i.keys}
    wanted |= {(e, k + HOTPATCH) for e, k in wanted if e == "Windows"}
    records: dict[tuple[str, str], list[dict]] = {k: [] for k in wanted}
    for eco in ECOSYSTEMS:
        names = sorted(k for e, k in wanted if e == eco)
        for i in range(0, len(names), 500):  # stay under SQL parameter limits
            for pkg, rec in s.execute(select(Advisory.package, Advisory.record).where(Advisory.ecosystem == eco, Advisory.package.in_(names[i:i + 500]))):
                records[eco, pkg].append(rec)
    cves = sorted({a for v in records.values() for r in v for a in [r["id"], *r.get("aliases", [])] if a.startswith("CVE-")})
    kev, cvss = set(), {}
    for i in range(0, len(cves), 500):
        part = cves[i:i + 500]
        kev.update(s.scalars(select(Kev.cve).where(Kev.cve.in_(part))))
        cvss |= dict(s.execute(select(Cvss.cve, Cvss.score).where(Cvss.cve.in_(part))).all())
    feeds = {e for e in ECOSYSTEMS if s.scalar(select(Advisory.id).where(Advisory.ecosystem == e).limit(1))}
    return Content.make(records, kev, cvss, feeds)
