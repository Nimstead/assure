"""Turn an asset's inventory into findings, and close findings the inventory proves fixed."""

import functools
import hashlib
import json
import logging
import re
from collections import defaultdict
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from nimstead import evidence, lifecycle, msproducts, risk, winapps, winconfig, windrivers
from nimstead.db import Advisory, Asset, Cvss, Epss, Finding, InstalledPackage, Kev, now
from nimstead.match import Match, canonical_id
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


def _linux_eol(key: tuple) -> bool:
    """A Linux release's end of support (`EOL:<distro>-<release>`), which only the engine judges (DECISIONS 85). Windows and app
    end of support share the `EOL:` prefix but come from host_checks, so the distro's name tells them apart."""
    return key[0] == lifecycle.ECOSYSTEM and key[2].startswith(tuple(f"EOL:{p}-" for p in lifecycle.DISTRO_EOL.values()))


def _closing_index(verdicts: list | None) -> tuple[dict, set] | None:
    """The engine's answers by finding key, and the products it found not applicable, built once per rescan for _held_open."""
    if verdicts is None:
        return None
    from nimstead.engine.model import Outcome
    by_key: dict[tuple, list] = defaultdict(list)
    for v in verdicts:
        if v.vuln_id:
            by_key[v.ecosystem, v.product, v.vuln_id].append(v)
    return by_key, {(v.ecosystem, v.product) for v in verdicts if not v.vuln_id and v.outcome == Outcome.NOT_APPLICABLE}


def _held_open(key: tuple, index: tuple[dict, set] | None, asset: Asset) -> str | None:
    """Phase 4 of tasks/plan-engine-findings.md: why an in-slice finding rescan no longer matches stays open, or None to close it.
    Closes on a verdict that proves it absent (not vulnerable, or not applicable: removed, or the product not installed); anything
    else is no evidence of a fix. An agent without a collection document can't say what it read, so nothing of it closes."""
    from nimstead.engine import parity
    from nimstead.engine.model import REASONS
    if index is None or not (parity.in_slice(key[0]) or _linux_eol(key)):
        return None
    if not asset.collection and asset.kind == "host":  # an SBOM application asset has no agent, so no document
        return REASONS["no-collection-document"][0]
    answer = index[0].get(key, [])
    # "end-of-life": a fixed version judged not vulnerable, held back from the report only because the release gets no more advisories
    if any(v.proves_absent or v.reason == "end-of-life" for v in answer) or key[:2] in index[1]:
        return None
    reason = next((v.reason for v in answer if v.reason in REASONS), "not-reassessed")
    return REASONS[reason][0]


def _live_by_id(c, product: tuple) -> dict:
    """A product's live advisory records by canonical id, built once per feed pass (`c.memo`), not once per finding per host."""
    if (out := c.memo.get(("scan", "by_id", *product))) is None:
        out = c.memo["scan", "by_id", *product] = defaultdict(list)
        for r in c.records.get(product, []):
            if not r.get("withdrawn"):
                out[canonical_id(r)].append(r)
    return out


def _engine(s: Session, asset: Asset, pkgs: list, matches: list, seen: set, prior: list, cache: dict, keep: bool) -> tuple[list, dict, list | None]:
    """The engine decides which findings exist in its slice (Windows OS, Microsoft products, curated apps, distro packages, language
    packages, SBOMs) and Linux end of support: each VULNERABLE verdict opens one, and nothing else does (phase 5 of
    tasks/plan-engine-findings.md, DECISIONS 125). Returns (matches, other affected installs by finding key, the verdicts closing
    reads, or None). If the engine fails, nothing in its slice opens and nothing closes: a crash isn't evidence of a fix (R4.6)."""
    from nimstead import engine
    from nimstead.engine import parity
    from nimstead.engine.model import Outcome
    matches = list(matches)  # the caller keeps its own list
    try:
        verdicts, c = engine.judge(s, asset, pkgs, prior, cache, keep)
    except Exception:
        log.exception("engine failed on %s; no findings opened or closed", asset.hostname)
        seen.update(prior)
        return matches, {}, None
    vulnerable: dict[tuple, list] = defaultdict(list)
    for v in verdicts:
        if v.vuln_id and v.outcome == Outcome.VULNERABLE:
            vulnerable[v.ecosystem, v.product, v.vuln_id].append(v)
    also: dict[tuple, dict[str, str | None]] = {}
    for key, vs in sorted(vulnerable.items()):
        linux_eol = _linux_eol(key)
        if key in seen or not (parity.in_slice(key[0]) or linux_eol):
            continue
        seen.add(key)
        if linux_eol:
            v = vs[0]
            rec = {"_risk": (90, "fix-now", [v.summary or key[2], "Upgrade to a supported release"])}  # as Windows end of support (host_checks)
            matches.append((key, key[0], key[1], v.instance or key[1], Match(key[2], [key[2]], None, v.summary or "", rec)))
            continue
        if key[0] in (winapps.ECOSYSTEM, msproducts.ECOSYSTEM):  # the oldest affected install is the finding's row, later ones named in its summary (DECISIONS 73)
            vs = sorted(vs, key=lambda v: winapps.appver_parts(v.version))
            also[key] = {o.version: o.fixed for o in vs[1:]}
        v = vs[0]
        recs = _live_by_id(c, key[:2]).get(key[2]) or []
        matches.append((key, key[0], key[1], v.version, Match(key[2], sorted(r["id"] for r in recs) or [key[2]], v.fixed, v.summary or "",
                                                             recs[0] if recs else {})))
    return matches, also, verdicts


def rescan(s: Session, asset: Asset, inventory_received: bool = True, cache: dict | None = None) -> dict:
    """`cache`: decoded advisory records by (ecosystem, package), shared across hosts within one feed-update pass.

    Commits s, including the caller's pending changes: callers stage their own writes and ledger entries (a new
    package list, a context change, an SBOM) and rely on this commit to land them with the findings they caused."""
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

    advisories = cache if cache is not None else {}
    matches: list = []
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
    matches, also, verdicts = _engine(s, asset, pkgs, matches, seen, prior, advisories, inventory_received)
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
    index = None  # built on the first finding that needs a closing decision: most rescans close none
    for key, f in existing.items():
        if key[0] == windrivers.ECOSYSTEM and not drivers_complete:  # a scan that failed or stopped early proves nothing is gone
            continue
        if key[0] in blocked:  # e.g. Uninstall access denied: the apps' findings stay as they were until a full read
            continue
        if key not in seen and f.status in ("open", "accepted"):
            index = index or _closing_index(verdicts)
            if (why := _held_open(key, index, asset)) is not None:  # phase 4: in the engine's slice, only evidence closes (R4.6)
                f.reasons = [r for r in f.reasons or [] if not r.startswith("Still open: ")] + [f"Still open: {why}"]
                continue
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
