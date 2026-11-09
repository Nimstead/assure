"""Match stored inventory to findings and resolve absent identities subject to collection guards.

This persistence path is separate from the engine's evidence-qualified verdict report.
An absent match is not a universal proof of repair or complete collection.
"""

import functools
import hashlib
import json
import logging
import re
from collections import defaultdict
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from nimstead import evidence, lifecycle, msproducts, risk, sbom, winapps, winconfig, windrivers
from nimstead.db import Advisory, Asset, Cvss, Epss, Finding, InstalledPackage, Kev, now
from nimstead.match import Match, Package, match_package, normalize_ecosystem
from nimstead.notify import notify

log = logging.getLogger(__name__)
HOTPATCH = " (Hotpatch)"  # advisory package suffix for MSRC hotpatch fixes (DECISIONS 52)
INVENTORY_LOG_EVERY = timedelta(days=1)  # an unchanged inventory is written to the ledger at most this often
# the collection sources (engine/collection.py) each finding ecosystem is read from: one that wasn't read proves nothing is gone
READ_FROM = {"Windows": ("windows_build",), winapps.ECOSYSTEM: ("uninstall", "user_hives"),
             msproducts.ECOSYSTEM: ("microsoft_products", "uninstall")}


def unread(collection: dict | None) -> set[str]:
    """Return Windows finding ecosystems blocked by collection source declarations.

    collection is an agent metadata dictionary or None. Explicit failed/partial
    sources block their READ_FROM ecosystems. A present uninstall source without
    a truthy count also blocks. Missing documents/sources do not block. This does
    not apply the engine's count-consistency or Linux/application source rules.
    Malformed nested values can raise AttributeError. Does not change collection."""
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
    """Return whether Windows app name, publisher source and version map to a curated identity.

    This tests mapping capability, not loaded advisories, complete collection or an
    actual check result. Source/name lookup uses a process cache. Mapper errors from
    incompatible values propagate. Does not query or mutate data."""
    return _named(name, source) and bool(winapps.identify(name, source, version) or msproducts.from_winapp(name, source, version))


# A .NET runtime's Uninstall entry, judged through the agent's own ".NET runtime" / "ASP.NET Core" fact rather than its name
_RUNTIME = re.compile(r"Microsoft (?:(?P<asp>ASP\.NET Core)|Windows Desktop Runtime|\.NET Runtime)(?: -)? (?P<v>\d+\.\d+\.\d+)(?: .*)?")


def runtime_fact(name: str) -> tuple[str, str] | None:
    """Return (fact name, version) represented by Uninstall name string, or None.

    Full-match supported Microsoft runtime display names. The result names .NET
    runtime or ASP.NET Core and its three-component version. Does not verify that
    the host sent the fact. Incompatible nonstrings can raise TypeError."""
    m = _RUNTIME.fullmatch(name)
    return ("ASP.NET Core" if m["asp"] else ".NET runtime", m["v"]) if m else None


def app_coverage(s: Session, org_id: str) -> tuple[dict[str, dict], dict[tuple[str, str | None], set[str]]]:
    """Windows apps we check against those we only list: counts per asset, and the assets holding each unchecked app. A runtime
    counts as checked only when its host also reports the matching fact at that version: that fact is what the server checks.

    Query Session s for organisation org_id. Return (per_asset, missed): per_asset
    maps asset IDs to assessed/inventory_only integer counts. missed maps (name,
    publisher) to asset-ID sets. Counts describe identity mapping, not advisory
    availability or completed verdicts. Assets without WinApp rows are absent.
    Does not commit. Queries can autoflush caller changes. Database/mapper errors propagate."""
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
    """Return sorted unique m.vuln_id plus CVE-prefixed record ID/aliases/upstream values.

    The main identity is included even when it is not a CVE. m must be a Match
    with compatible record fields. Does not change it. Malformed records or ID
    values can raise AttributeError or TypeError."""
    r = m.record
    return sorted({m.vuln_id, *(i for i in (r.get("id", ""), *r.get("aliases", []), *r.get("upstream", [])) if i.startswith("CVE-"))})


def hotpatch_track(hot: list[dict], version: str) -> tuple[set[str], list[dict]] | None:
    """A host whose build is a hotpatch build is on the hotpatch track: (CVEs with a hotpatch fix, those records).
    Every other host is compared with cumulative builds only, the stricter answer (DECISIONS 52).
    Recognition checks the last event in each record's first affected/range entry
    for fixed equal to version. On any hit, return all supplied records unchanged
    and all their aliases. Does not validate dates or runtime hotpatch activation.
    Missing/nondictionary nested fields can raise KeyError, IndexError or TypeError."""
    if not any(r["affected"][0]["ranges"][0]["events"][-1].get("fixed") == version for r in hot):
        return None
    return {a for r in hot for a in r["aliases"]}, hot


def host_checks(pkgs: list, facts: dict, today, eol: dict | None = None, drivers: dict | None = None) -> list[dict]:
    """Findings from the host's own state rather than an advisory: end of support (lifecycle.py), Windows
    configuration (winconfig.py) and listed driver files (windrivers.py). `risk` None = score it as the CVE it names (KEV, EPSS, CVSS).

    pkgs contains package-like objects. facts is host metadata, today is a date,
    eol contains lifecycle cycles and drivers maps exact file hashes to metadata.
    Return component finding dictionaries plus ecosystem and optional Risk objects.
    No query or persistence occurs. Component validation/date/type errors propagate."""
    out = []
    for x in lifecycle.findings(pkgs, facts, today, eol):
        out.append({**x, "ecosystem": lifecycle.ECOSYSTEM, "risk": risk.Risk(
            90 if x["ended"] else 40, "fix-now" if x["ended"] else "planned",
            [x["summary"], "Upgrade, or enrol in Extended Security Updates" if x["ended"] else "Plan the upgrade"])})
    os_version = next((p.version for p in pkgs if p.ecosystem == "Windows"), "")
    out += [{**x, "ecosystem": winconfig.ECOSYSTEM} for x in winconfig.evaluate(facts, os_version, today)]
    out += [{**x, "ecosystem": windrivers.ECOSYSTEM} for x in windrivers.findings(pkgs, drivers or {})]
    return out


def _shadow(s: Session, asset: Asset, pkgs: list, seen: set, prior: list) -> None:
    """The engine beside rescan (tasks/plan-engine-findings.md, phase 1): a difference neither side explains goes to the ledger,
    once per host per rescan, and never changes a finding. Its failure is logged and never stops rescan."""
    from nimstead import engine
    try:
        p = engine.shadow(s, asset, pkgs, seen, prior)
    except Exception:
        log.exception("engine shadow failed on %s; findings unaffected", asset.hostname)
        return
    if p["unexplained"]:
        evidence.append(s, asset.org_id, "engine_disagrees", asset.id, {"host": asset.hostname, "agree": p["agree"],
                                                                          "count": len(p["unexplained"]), "unexplained": p["unexplained"][:20]})


def rescan(s: Session, asset: Asset, inventory_received: bool = True, cache: dict | None = None) -> dict:
    """Update findings for Asset asset from stored package rows through Session s.

    Caller checks tenant ownership. inventory_received controls receipt logging and
    engine shadow evaluation, not whether matching/resolution occurs. Optional cache
    is mutated with advisory, match, lifecycle, driver and exploit entries. Share it
    only within one feed-update pass while those inputs remain unchanged.

    Commit finding/ledger changes and all other pending session changes. Return open
    (unique seen identities, including accepted) and resolved (new transitions).
    Matching resolved findings reopen. Matching expired acceptances reopen. Unseen
    open/accepted findings resolve unless unread() or incomplete driver collection
    blocks their ecosystem. Missing collection metadata does not itself block this.
    External assets instead delegate to external.rescore() without network checks.
    Queue one notification for newly fix-now open findings after commit. Database,
    malformed input and matching errors propagate without automatic rollback."""
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
        _shadow(s, asset, pkgs, seen, prior)  # new inventories only: on the hourly re-match it made 1,000 hosts take 585 s, not 29 s
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
