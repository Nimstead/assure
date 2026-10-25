"""Turn an asset's inventory into findings, and close findings the inventory proves fixed."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from nimstead import risk
from nimstead.db import Advisory, Asset, Epss, Finding, InstalledPackage, Kev, now
from nimstead.match import Package, match_package, normalize_ecosystem


def rescan(s: Session, asset: Asset) -> dict:
    t = now()
    pkgs = s.scalars(select(InstalledPackage).where(InstalledPackage.asset_id == asset.id)).all()
    existing = {
        (f.ecosystem, f.package, f.vuln_id): f
        for f in s.scalars(select(Finding).where(Finding.asset_id == asset.id))
    }
    seen: set[tuple[str, str, str]] = set()

    # ponytail: one advisory query per package; batch by ecosystem if large inventories are slow
    for p in pkgs:
        eco = normalize_ecosystem(p.ecosystem)
        name = p.source or p.name
        records = [a.record for a in s.scalars(select(Advisory).where(Advisory.ecosystem == eco, Advisory.package == name))]
        if not records:
            continue
        for m in match_package(Package(p.name, p.version, p.source), p.ecosystem, records):
            key = (eco, name, m.vuln_id)
            if key in seen:  # several binaries from one source package -> one finding
                continue
            seen.add(key)
            cve = m.vuln_id if m.vuln_id.startswith("CVE-") else None
            kev = s.get(Kev, cve) if cve else None
            ep = s.get(Epss, cve) if cve else None
            cvss = risk.cvss_base(m.record.get("severity"))
            r = risk.score(
                kev=kev is not None,
                epss=ep.score if ep else None,
                cvss=cvss,
                criticality=asset.criticality,
                internet_facing=asset.internet_facing,
                fix_available=m.fixed is not None,
            )
            f = existing.get(key)
            if f is None:
                f = Finding(org_id=asset.org_id, asset_id=asset.id, ecosystem=eco, package=name, vuln_id=m.vuln_id, first_seen=t)
                s.add(f)
            elif f.status == "resolved":  # regression: vulnerable version came back
                f.status, f.resolved_at = "open", None
            f.installed_version = p.version
            f.advisory_ids = sorted(m.advisory_ids)
            f.fixed_version = m.fixed
            f.summary = (m.summary or "")[:1000]
            f.cvss, f.epss, f.kev = cvss, (ep.score if ep else None), kev is not None
            f.score, f.priority, f.reasons = r.score, r.priority, r.reasons
            f.last_seen = t

    resolved = 0
    for key, f in existing.items():
        if key not in seen and f.status == "open":
            f.status, f.resolved_at = "resolved", t  # inventory proves the vulnerable version is gone
            resolved += 1
    s.commit()
    return {"open": len(seen), "resolved": resolved}
