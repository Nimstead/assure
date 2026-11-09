"""Turn an asset's inventory into findings, and close findings the inventory proves fixed."""

import functools
import hashlib
import json
import logging
import os
import re
from collections import defaultdict
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from nimstead import evidence, lifecycle, msproducts, risk, sbom, winapps, winconfig, windrivers
from nimstead.db import Advisory, Asset, Cvss, Epss, Finding, InstalledPackage, Kev, now
from nimstead.match import Match, Package, canonical_id, match_package, normalize_ecosystem
from nimstead.notify import notify

log = logging.getLogger(__name__)
HOTPATCH = " (Hotpatch)"  # advisory package suffix for MSRC hotpatch fixes (DECISIONS 52)
INVENTORY_LOG_EVERY = timedelta(days=1)  # an unchanged inventory is written to the ledger at most this often
# the collection sources (engine/collection.py) each finding ecosystem is read from: one that wasn't read proves nothing is gone
READ_FROM = {"Windows": ("windows_build",), winapps.ECOSYSTEM: ("uninstall", "user_hives"),
             msproducts.ECOSYSTEM: ("microsoft_products", "uninstall")}


def unread(collection: dict | None) -> set[str]:
    """Finding ecosystems whose sources the agent says it couldn't read in full (failed, partial, or an empty Uninstall list)."""
    sources = (collection or {}).get("sources") or {}

    def bad(name):
        s = sources.get(name)
        return s is not None and (s.get("state") in ("failed", "partial") or (name == "uninstall" and not s.get("count")))
    return {eco for eco, names in READ_FROM.items() if any(bad(n) for n in names)}


@functools.lru_cache(maxsize=20_000)  # a fleet's distinct app names: few, where (name, version) pairs are not
def _named(name: str, source: str | None) -> bool:
    """Whether any curated rule names this app at all. Most installed apps match none, whatever their version."""
    return winapps.names_product(name, source) or msproducts.names_product(name, source)


def app_assessed(name: str, source: str | None, version: str) -> bool:
    # the name decides for most apps (1,000 hosts x 150 apps: 1.7 s a page load when every version was its own cache entry)
    """Return whether Windows app name, publisher source, and version match a curated product identity."""
    return _named(name, source) and bool(winapps.identify(name, source, version) or msproducts.from_winapp(name, source, version))


# A .NET runtime's Uninstall entry, judged through the agent's own ".NET runtime" / "ASP.NET Core" fact rather than its name
_RUNTIME = re.compile(r"Microsoft (?:(?P<asp>ASP\.NET Core)|Windows Desktop Runtime|\.NET Runtime)(?: -)? (?P<v>\d+\.\d+\.\d+)(?: .*)?")


def runtime_fact(name: str) -> tuple[str, str] | None:
    """(fact name, version) the same host reports for this Uninstall entry, if it's a .NET runtime."""
    m = _RUNTIME.fullmatch(name)
    return ("ASP.NET Core" if m["asp"] else ".NET runtime", m["v"]) if m else None


def app_coverage(s: Session, org_id: str) -> tuple[dict[str, dict], dict[tuple[str, str | None], set[str]]]:
    """Windows apps we check against those we only list: counts per asset, and the assets holding each unchecked app. A runtime
    counts as checked only when its host also reports the matching fact at that version: that fact is what the server checks."""
    per_asset: dict[str, dict] = defaultdict(lambda: {"assessed": 0, "inventory_only": 0})
    missed: dict[tuple[str, str | None], set[str]] = defaultdict(set)
    base = (select(InstalledPackage.asset_id, InstalledPackage.name, InstalledPackage.source, InstalledPackage.version)
            .join(Asset, Asset.id == InstalledPackage.asset_id).where(Asset.org_id == org_id))
    facts = {(a, n, v) for a, n, _, v in s.execute(base.where(InstalledPackage.ecosystem == msproducts.ECOSYSTEM,
                                                              InstalledPackage.name.in_([".NET runtime", "ASP.NET Core"])))}
    for asset_id, name, source, version in s.execute(base.where(InstalledPackage.ecosystem == winapps.ECOSYSTEM)):
        if app_assessed(name, source, version) or ((f := runtime_fact(name)) and (asset_id, *f) in facts):
            per_asset[asset_id]["assessed"] += 1
        else:
            per_asset[asset_id]["inventory_only"] += 1
            missed[name, source].add(asset_id)
    return per_asset, missed


def cve_ids(m: Match) -> list[str]:
    """Every CVE one match stands for: a distro fix record (RLSA, DSA) names several, and the finding carries the lowest."""
    r = m.record
    return sorted({m.vuln_id, *(i for i in (r.get("id", ""), *r.get("aliases", []), *r.get("upstream", [])) if i.startswith("CVE-"))})


def hotpatch_track(hot: list[dict], version: str) -> tuple[set[str], list[dict]] | None:
    """A host whose build is a hotpatch build is on the hotpatch track: (CVEs with a hotpatch fix, those records).
    Every other host is compared with cumulative builds only, the stricter answer (DECISIONS 52)."""
    if not any(r["affected"][0]["ranges"][0]["events"][-1].get("fixed") == version for r in hot):
        return None
    return {a for r in hot for a in r["aliases"]}, hot


def host_checks(pkgs: list, facts: dict, today, eol: dict | None = None, drivers: dict | None = None) -> list[dict]:
    """Findings from the host's own state rather than an advisory: end of support (lifecycle.py), Windows
    configuration (winconfig.py) and listed driver files (windrivers.py). `risk` None = score it as the CVE it names (KEV, EPSS, CVSS)."""
    out = []
    for x in lifecycle.findings(pkgs, facts, today, eol):
        out.append({**x, "ecosystem": lifecycle.ECOSYSTEM, "risk": risk.Risk(
            90 if x["ended"] else 40, "fix-now" if x["ended"] else "planned",
            [x["summary"], "Upgrade, or enrol in Extended Security Updates" if x["ended"] else "Plan the upgrade"])})
    os_version = next((p.version for p in pkgs if p.ecosystem == "Windows"), "")
    out += [{**x, "ecosystem": winconfig.ECOSYSTEM} for x in winconfig.evaluate(facts, os_version, today)]
    out += [{**x, "ecosystem": windrivers.ECOSYSTEM} for x in windrivers.findings(pkgs, drivers or {})]
    return out


def engine_findings() -> bool:
    """Phase 3 of tasks/plan-engine-findings.md is on unless NIMSTEAD_ENGINE_FINDINGS=0, the way back to rescan's own matching."""
    return os.environ.get("NIMSTEAD_ENGINE_FINDINGS", "1") != "0"


def _linux_eol(key: tuple) -> bool:
    """A Linux release's end of support (`EOL:<distro>-<release>`), which only the engine judges (DECISIONS 85). Windows and app
    end of support share the `EOL:` prefix but come from host_checks, so the distro's name tells them apart."""
    return key[0] == lifecycle.ECOSYSTEM and key[2].startswith(tuple(f"EOL:{p}-" for p in lifecycle.DISTRO_EOL.values()))


def _engine(s: Session, asset: Asset, pkgs: list, matches: list, seen: set, prior: list, cache: dict, keep: bool) -> tuple[list, list]:
    """The engine decides what opens (phase 3): for the slice it judges, a VULNERABLE verdict opens a finding, a verdict
    that proves it absent drops rescan's match, and no decision (an old agent, a blocked source) leaves rescan's match as it
    was. rescan's own loop is the shadow: a difference neither side explains goes to the ledger once per new inventory
    (`keep`), not on every hourly re-match. Returns (matches, ledger rows to append). If the engine fails, rescan's matches
    open and nothing closes: a crash isn't evidence of a fix (R4.6)."""
    from nimstead import engine
    from nimstead.engine import parity
    from nimstead.engine.model import Outcome
    try:
        verdicts, c, p = engine.judge(s, asset, pkgs, seen, prior, cache, keep)
    except Exception:
        log.exception("engine failed on %s; findings from rescan's own matching, none closed", asset.hostname)
        seen.update(prior)
        return matches, []
    rows = [("engine_disagrees", {"host": asset.hostname, "agree": p["agree"], "count": len(p["unexplained"]),
                                  "unexplained": p["unexplained"][:20]})] if p["unexplained"] and keep else []
    if not engine_findings():
        seen.update(k for k in prior if _linux_eol(k))  # only the engine judges these: switching it off isn't evidence of a fix
        return matches, rows
    by_key: dict[tuple, list] = defaultdict(list)
    for v in verdicts:
        if v.vuln_id:
            by_key[v.ecosystem, v.product, v.vuln_id].append(v)
    out = []
    for m in matches:
        vs = by_key.get(m[0])
        if parity.in_slice(m[0][0]) and vs and all(v.proves_absent for v in vs):
            seen.discard(m[0])  # evidence it's fixed, not silence: closes like any finding inventory no longer shows
            continue
        out.append(m)
    for key, vs in sorted(by_key.items()):
        v = next((v for v in vs if v.outcome == Outcome.VULNERABLE), None)
        linux_eol = _linux_eol(key)
        if v is None or key in seen or not (parity.in_slice(key[0]) or linux_eol):
            continue
        seen.add(key)
        if linux_eol:
            rec = {"_risk": (90, "fix-now", [v.summary or key[2], "Upgrade to a supported release"])}  # as Windows end of support (host_checks)
            out.append((key, key[0], key[1], v.instance or key[1], Match(key[2], [key[2]], None, v.summary or "", rec)))
            continue
        recs = [r for r in c.records.get(key[:2], []) if canonical_id(r) == key[2] and not r.get("withdrawn")]
        out.append((key, key[0], key[1], v.version, Match(key[2], sorted(r["id"] for r in recs) or [key[2]], v.fixed, v.summary or "",
                                                         recs[0] if recs else {})))
    return out, rows


def rescan(s: Session, asset: Asset, inventory_received: bool = True, cache: dict | None = None) -> dict:
    """`cache`: decoded advisory records by (ecosystem, package), shared across hosts within one feed-update pass."""
    if asset.kind == "external":  # no inventory: findings come from external.scan(); only re-score here
        from nimstead import external
        return external.rescore(s, asset)
    t = now()
    pkgs = s.scalars(select(InstalledPackage).where(InstalledPackage.asset_id == asset.id)).all()
    existing = {
        (f.ecosystem, f.package, f.vuln_id): f
        for f in s.scalars(select(Finding).where(Finding.asset_id == asset.id))
    }
    prior = [k for k, f in existing.items() if f.status in ("open", "accepted")]  # before this rescan changes them
    seen: set[tuple[str, str, str]] = set()
    inv = sorted((p.ecosystem, p.name, p.version, p.source or "", *([p.source_version] if p.source_version else [])) for p in pkgs)
    events: list[tuple[str, Finding]] = []
    fix_now: list[str] = []  # findings that became fix-now in this rescan

    # (package, advisory ecosystem, advisory package name, version to compare). Installed Windows apps are looked up by
    # the curated product key only; an app the map doesn't know is inventory and never matched.
    # Microsoft products (msproducts.py) come from Uninstall entries or the agent's own facts; their name is a tuple of
    # candidate keys, the first with advisories wins (Store apps MSRC lists per OS).
    os_product = next((p.name for p in pkgs if p.ecosystem == "Windows"), None)
    targets = []
    for p in pkgs:
        eco = normalize_ecosystem(p.ecosystem)
        if eco == windrivers.ECOSYSTEM:  # judged by exact hash in host_checks, never by name and version
            continue
        if eco == winapps.ECOSYSTEM:
            if hit := winapps.identify(p.name, p.source, p.version):
                targets.append((p, eco, hit[0], hit[1]))
            elif ms := msproducts.from_winapp(p.name, p.source, p.version):
                targets.append((p, msproducts.ECOSYSTEM, (ms[0],), ms[1]))
        elif eco == msproducts.ECOSYSTEM:
            if ms := msproducts.targets(p.name, p.version, os_product, p.source):
                targets.append((p, eco, *ms))
        elif eco in sbom.ECOSYSTEMS:  # a language package's `source` is where it was found, never another name (DECISIONS 91)
            targets.append((p, eco, p.name, p.version))
        else:
            targets.append((p, eco, p.source or p.name, p.source_version or p.version))  # advisories name source versions (DECISIONS 84)
    # stable sort: the oldest vulnerable install of an app is the finding's row (one per asset, package and vulnerability), and a
    # later install still affected is named in its summary. Each is judged, so fixing one of two leaves the finding open (DECISIONS 73)
    targets.sort(key=lambda t: winapps.appver_parts(t[3]) if t[1] in (winapps.ECOSYSTEM, msproducts.ECOSYSTEM) else [])
    wanted: dict[str, set[str]] = defaultdict(set)
    for _, eco, name, _ in targets:
        wanted[eco].update(name if isinstance(name, tuple) else [name])
        if eco == "Windows":
            wanted[eco].add(name + HOTPATCH)
    advisories = cache if cache is not None else {}
    for eco, names in wanted.items():
        names_l = sorted(n for n in names if (eco, n) not in advisories)
        for n in names_l:
            advisories[(eco, n)] = []
        for i in range(0, len(names_l), 500):  # stay under SQL parameter limits
            for pkg, rec in s.execute(select(Advisory.package, Advisory.record)
                                      .where(Advisory.ecosystem == eco, Advisory.package.in_(names_l[i:i + 500]))):
                advisories[(eco, pkg)].append(rec)

    matches = []
    also: dict[tuple, dict[str, str | None]] = defaultdict(dict)  # finding key -> other affected installs of the app, and their fixes
    for p, eco, name, version in targets:
        if isinstance(name, tuple):
            name = next((n for n in name if advisories.get((eco, n))), name[-1])
        records = advisories.get((eco, name))
        if eco == "Windows" and (hot := hotpatch_track(advisories.get((eco, name + HOTPATCH)) or [], version)):
            records = [r for r in records or [] if not set(r["aliases"]) & hot[0]] + hot[1]
        if not records:
            continue
        mkey = ("match", eco, p.name, version, name)  # pure function of these: same answer on every host
        if (found := advisories.get(mkey)) is None:
            found = advisories[mkey] = match_package(Package(p.name, version, name), eco, records)
        for m in found:
            key = (eco, name, m.vuln_id)
            if key in seen:  # several binaries from one source package -> one finding
                if eco in (winapps.ECOSYSTEM, msproducts.ECOSYSTEM):
                    also[key][version] = m.fixed
                continue
            seen.add(key)
            matches.append((key, eco, name, version, m))
    # findings that aren't advisory matches (end of support, configuration) carry their own score and reasons
    if ("eol",) not in advisories:  # endoflife.date cycles, once per feed-update pass
        advisories[("eol",)] = {pkg: rec["cycles"] for pkg, rec in s.execute(
            select(Advisory.package, Advisory.record).where(Advisory.ecosystem == "EOL"))}
    if ("drivers",) not in advisories:  # LOLDrivers' hashes, once per pass
        stored = s.scalar(select(Advisory.record).where(Advisory.ecosystem == windrivers.ECOSYSTEM)) or {}
        advisories[("drivers",)] = stored.get("drivers", {})
    for x in host_checks(pkgs, asset.facts or {}, t.date(), advisories[("eol",)], advisories[("drivers",)]):
        key = (x["ecosystem"], x["package"], x["vuln_id"])
        seen.add(key)
        rec = {"_risk": (x["risk"].score, x["risk"].priority, x["risk"].reasons)} if x.get("risk") else {}
        matches.append((key, x["ecosystem"], x["package"], x["version"],
                        Match(x["vuln_id"], [x["vuln_id"]], x.get("fixed"), x["summary"], rec)))
    matches, engine_rows = _engine(s, asset, pkgs, matches, seen, prior, advisories, inventory_received)
    # exploitation and severity context in three queries, not three lookups per CVE
    cves = sorted({c for *_, m in matches for c in cve_ids(m) if c.startswith("CVE-")})
    kevs, ransomware, epss, nvd = set(), set(), {}, {}
    for i in range(0, len(cves), 500):
        part = cves[i:i + 500]
        for cve, ransom in s.execute(select(Kev.cve, Kev.ransomware).where(Kev.cve.in_(part))):
            kevs.add(cve)
            if ransom:
                ransomware.add(cve)
        epss |= dict(s.execute(select(Epss.cve, Epss.score).where(Epss.cve.in_(part))).all())
        nvd |= dict(s.execute(select(Cvss.cve, Cvss.score).where(Cvss.cve.in_(part))).all())
    if ("exploits",) not in advisories:  # CVEs with a public exploit by source (Metasploit, Exploit-DB), once per pass
        advisories[("exploits",)] = {pkg: set(rec.get("cves", [])) for pkg, rec in s.execute(
            select(Advisory.package, Advisory.record).where(Advisory.ecosystem == "Exploit"))}
    exploits = advisories[("exploits",)]
    roles = (asset.facts or {}).get("roles")
    listeners = winconfig.reachable_listeners(asset.facts or {})

    for key, eco, name, version, m in matches:
        ids = cve_ids(m)  # one fix for several CVEs is as exploited, as likely and as severe as the worst of them
        kev = any(c in kevs for c in ids)
        ep = max((epss[c] for c in ids if c in epss), default=None)
        cvss = risk.cvss_base(m.record.get("severity"))
        if cvss is None:
            cvss = max((nvd[c] for c in ids if c in nvd), default=None)
        r = risk.Risk(*m.record["_risk"]) if "_risk" in m.record else risk.score(
            kev=kev,
            epss=ep,
            cvss=cvss,
            criticality=asset.criticality,
            internet_facing=asset.internet_facing,
            fix_available=m.fixed is not None or eco == "WinConfig",  # a setting is fixed by changing it
        )
        if "_risk" not in m.record:
            r = risk.context(r, kev=kev, ransomware=any(c in ransomware for c in ids),
                             public_exploit=any(c in exploits.get("metasploit", ()) for c in ids),
                             exploit_db=any(c in exploits.get("exploitdb", ()) for c in ids),
                             msrc=(m.record.get("database_specific") or {}), roles=roles,
                             listening=next((why for keys, why in listeners if eco in (winapps.ECOSYSTEM, msproducts.ECOSYSTEM) and name.startswith(keys)), None))
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
        locs = (((asset.facts or {}).get("jar_scan") or {}).get("locations") or []) if eco == "Maven" else []
        loc = next((x[2] for x in locs if isinstance(x, list) and len(x) == 3 and x[:2] == [name, version]), None)
        others = [f"{v} (fixed in {fix})" if fix else v for v, fix in also.get(key, {}).items() if v != version]
        same_fix = [c for c in ids if c != m.vuln_id]
        f.summary = ((m.summary or "") + (f" (in {loc})" if loc else "")  # a jar the agent found on disk
                     + (f" Also affected on this host: {', '.join(others[:5])}." if others else "")
                     + (f" The same fix covers {', '.join(same_fix[:10])}{' and more' if len(same_fix) > 10 else ''}." if same_fix else ""))[:1000]
        f.cvss, f.epss, f.kev = cvss, ep, kev
        f.score, f.priority, f.reasons = r.score, r.priority, r.reasons
        f.last_seen = t
        if f.priority == "fix-now" and f.status in (None, "open") and not was_fix_now:  # status None: new row, default not yet applied
            fix_now.append(m.vuln_id)

    resolved = 0
    scan = (asset.facts or {}).get("driver_scan")
    drivers_complete = isinstance(scan, dict) and scan.get("complete") is True
    blocked = unread(asset.collection)  # the latest report's: the hourly re-match reads the same short list
    for key, f in existing.items():
        if key[0] == windrivers.ECOSYSTEM and not drivers_complete:  # a scan that failed or stopped early proves nothing is gone
            continue
        if key[0] in blocked:  # e.g. Uninstall access denied: the apps' findings stay as they were until a full read
            continue
        if key not in seen and f.status in ("open", "accepted"):
            f.status, f.resolved_at = "resolved", t  # inventory proves the vulnerable version is gone
            resolved += 1
            events.append(("finding_resolved", f))
    s.flush()
    # ledger entries last: the first append locks the org row until the commit below, so matching above never holds it
    if inventory_received:
        digest = hashlib.sha256(json.dumps(inv).encode()).hexdigest()
        # an unchanged inventory goes on the record once a day, not every report: hourly agents made the ledger (and every
        # evidence pack, which must hold a period's entries whole) grow by 24 rows per host a day (DECISIONS 121)
        if (digest != asset.inventory_logged_sha256 or not asset.inventory_logged_at
                or asset.inventory_logged_at <= t - INVENTORY_LOG_EVERY):
            evidence.append(s, asset.org_id, "inventory_received", asset.id, {
                "hostname": asset.hostname, "packages": len(inv), "inventory_sha256": digest})
            asset.inventory_logged_sha256, asset.inventory_logged_at = digest, t
    for kind, data in engine_rows:
        evidence.append(s, asset.org_id, kind, asset.id, data)
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
