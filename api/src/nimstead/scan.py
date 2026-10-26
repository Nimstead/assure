"""Turn an asset's inventory into findings, and close findings the inventory proves fixed."""

import hashlib
import json
from collections import defaultdict

from sqlalchemy import select
from sqlalchemy.orm import Session

from nimstead import evidence, risk, winapps
from nimstead.db import Advisory, Asset, Cvss, Epss, Finding, InstalledPackage, Kev, now
from nimstead.match import Package, match_package, normalize_ecosystem
from nimstead.notify import notify


def rescan(s: Session, asset: Asset, inventory_received: bool = True) -> dict:
    t = now()
    pkgs = s.scalars(select(InstalledPackage).where(InstalledPackage.asset_id == asset.id)).all()
    existing = {
        (f.ecosystem, f.package, f.vuln_id): f
        for f in s.scalars(select(Finding).where(Finding.asset_id == asset.id))
    }
    seen: set[tuple[str, str, str]] = set()
    inv = sorted((p.ecosystem, p.name, p.version, p.source or "") for p in pkgs)
    if inventory_received:
        evidence.append(s, asset.org_id, "inventory_received", asset.id, {
            "hostname": asset.hostname, "packages": len(inv),
            "inventory_sha256": hashlib.sha256(json.dumps(inv).encode()).hexdigest(),
        })
    events: list[tuple[str, Finding]] = []
    fix_now: list[str] = []  # findings that became fix-now in this rescan

    # (package, advisory ecosystem, advisory package name, version to compare). Installed Windows apps are looked up by
    # the curated product key only; an app the map doesn't know is inventory and never matched.
    targets = []
    for p in pkgs:
        eco = normalize_ecosystem(p.ecosystem)
        if eco == winapps.ECOSYSTEM:
            if hit := winapps.identify(p.name, p.source, p.version):
                targets.append((p, eco, hit[0], hit[1]))
        else:
            targets.append((p, eco, p.source or p.name, p.version))
    targets.sort(key=lambda t: winapps.appver_parts(t[3]) if t[1] == winapps.ECOSYSTEM else [])  # stable: oldest install of an app is reported
    wanted: dict[str, set[str]] = defaultdict(set)
    for _, eco, name, _ in targets:
        wanted[eco].add(name)
    advisories: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for eco, names in wanted.items():
        names_l = sorted(names)
        for i in range(0, len(names_l), 500):  # stay under SQL parameter limits
            for a in s.scalars(select(Advisory).where(Advisory.ecosystem == eco, Advisory.package.in_(names_l[i:i + 500]))):
                advisories[(eco, a.package)].append(a.record)

    for p, eco, name, version in targets:
        records = advisories.get((eco, name))
        if not records:
            continue
        for m in match_package(Package(p.name, version, name), p.ecosystem, records):
            key = (eco, name, m.vuln_id)
            if key in seen:  # several binaries from one source package -> one finding
                continue
            seen.add(key)
            cve = m.vuln_id if m.vuln_id.startswith("CVE-") else None
            kev = s.get(Kev, cve) if cve else None
            ep = s.get(Epss, cve) if cve else None
            cvss = risk.cvss_base(m.record.get("severity"))
            if cvss is None and cve and (nvd := s.get(Cvss, cve)):
                cvss = nvd.score
            r = risk.score(
                kev=kev is not None,
                epss=ep.score if ep else None,
                cvss=cvss,
                criticality=asset.criticality,
                internet_facing=asset.internet_facing,
                fix_available=m.fixed is not None,
            )
            f = existing.get(key)
            was_fix_now = f is not None and f.status == "open" and f.priority == "fix-now"
            if f is None:
                f = Finding(org_id=asset.org_id, asset_id=asset.id, ecosystem=eco, package=name, vuln_id=m.vuln_id, first_seen=t)
                s.add(f)
                events.append(("finding_opened", f))
            elif f.status == "resolved":  # regression: vulnerable version came back
                f.status, f.resolved_at = "open", None
                events.append(("finding_reopened", f))
            elif f.status == "accepted" and f.accepted_until and f.accepted_until < t:
                f.status, f.accepted_until = "open", None
                events.append(("acceptance_expired", f))
            f.installed_version = version  # normalised for WinApp (Python: 3.14-64 -> 3.14.5)
            f.advisory_ids = sorted(m.advisory_ids)
            f.fixed_version = m.fixed
            f.summary = (m.summary or "")[:1000]
            f.cvss, f.epss, f.kev = cvss, (ep.score if ep else None), kev is not None
            f.score, f.priority, f.reasons = r.score, r.priority, r.reasons
            f.last_seen = t
            if f.priority == "fix-now" and f.status in (None, "open") and not was_fix_now:  # status None: new row, default not yet applied
                fix_now.append(m.vuln_id)

    resolved = 0
    for key, f in existing.items():
        if key not in seen and f.status in ("open", "accepted"):
            f.status, f.resolved_at = "resolved", t  # inventory proves the vulnerable version is gone
            resolved += 1
            events.append(("finding_resolved", f))
    s.flush()
    for kind, f in events:
        evidence.append(s, asset.org_id, kind, f.id, {
            "host": asset.hostname, "vuln_id": f.vuln_id, "package": f.package,
            "installed_version": f.installed_version, "fixed_version": f.fixed_version, "priority": f.priority,
        })
    s.commit()
    if fix_now:  # one message per rescan (per host), not per CVE
        shown = ", ".join(fix_now[:5]) + (f" and {len(fix_now) - 5} more" if len(fix_now) > 5 else "")
        notify(s, asset.org_id, "fix_now", f"{len(fix_now)} new fix-now finding{'s' * (len(fix_now) > 1)} on {asset.hostname}: {shown}")
    return {"open": len(seen), "resolved": resolved}
