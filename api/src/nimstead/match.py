"""Match installed packages against OSV advisories.

Low-noise rules:
- Only ECOSYSTEM/SEMVER ranges for the asset's exact ecosystem; never guess
  across ecosystems or with an unknown comparator.
- Distro packages are matched by *source* package name (what Debian, Ubuntu,
  Alpine and RHEL advisories reference), so distro backports are honoured.
- Withdrawn advisories are ignored; duplicate advisories for one CVE
  (e.g. DSA + DEBIAN-CVE) collapse into one finding.
"""

from dataclasses import dataclass, field

from nimstead.versions import Cmp, comparator_for, sort_key


@dataclass(frozen=True)
class Package:
    name: str  # binary/installed name
    version: str
    source: str | None = None  # source package (distros); falls back to name


@dataclass
class Match:
    package: Package
    vuln_id: str  # canonical id, CVE where known
    advisory_ids: list[str]
    fixed: str | None  # lowest fixed version above installed, None = no fix yet
    summary: str
    record: dict = field(repr=False)


def normalize_ecosystem(eco: str) -> str:
    """'Ubuntu:22.04:LTS' -> 'Ubuntu:22.04'. Other ecosystems unchanged."""
    parts = eco.split(":")
    if parts[0] == "Ubuntu" and parts[-1] == "LTS":
        parts = parts[:-1]
    return ":".join(parts)


def canonical_id(record: dict) -> str:
    ids = [record["id"], *record.get("aliases", []), *record.get("upstream", [])]
    cves = sorted(i for i in ids if i.startswith("CVE-"))
    return cves[0] if cves else record["id"]


def _affected(version: str, events: list[dict], cmp: Cmp) -> bool:
    """OSV spec evaluation of one range's events."""
    key = sort_key(cmp)

    def ev_version(e: dict) -> str:
        return next(iter(e.values()))

    def order(e: dict):
        v = ev_version(e)
        return (0, None) if v == "0" else (1, key(v))

    affected = False
    for e in sorted((e for e in events if "limit" not in e), key=order):
        if "introduced" in e:
            if e["introduced"] == "0" or cmp(version, e["introduced"]) >= 0:
                affected = True
        elif "fixed" in e:
            if cmp(version, e["fixed"]) >= 0:
                affected = False
        elif "last_affected" in e:
            if cmp(version, e["last_affected"]) > 0:
                affected = False
    return affected


def _fixed_above(version: str, events: list[dict], cmp: Cmp) -> str | None:
    fixes = [e["fixed"] for e in events if "fixed" in e and cmp(e["fixed"], version) > 0]
    return min(fixes, key=sort_key(cmp)) if fixes else None


def match_package(pkg: Package, ecosystem: str, records: list[dict]) -> list[Match]:
    """Records are OSV entries already filtered to this package name."""
    cmp = comparator_for(ecosystem)
    if cmp is None:
        return []
    eco = normalize_ecosystem(ecosystem)
    name = pkg.source or pkg.name
    by_id: dict[str, Match] = {}
    for rec in records:
        if rec.get("withdrawn"):
            continue
        for aff in rec.get("affected", []):
            p = aff.get("package", {})
            if p.get("name") != name or normalize_ecosystem(p.get("ecosystem", "")) != eco:
                continue
            try:
                hit, fixed = False, None
                for r in aff.get("ranges", []):
                    if r.get("type") not in ("ECOSYSTEM", "SEMVER"):
                        continue
                    if _affected(pkg.version, r["events"], cmp):
                        hit, fixed = True, _fixed_above(pkg.version, r["events"], cmp)
                        break
                if not hit and pkg.version in aff.get("versions", []):
                    hit = True
            except ValueError:
                # ponytail: unparseable versions skipped silently per record; surface as a data-quality metric later
                continue
            if not hit:
                continue
            cid = canonical_id(rec)
            if cid in by_id:
                m = by_id[cid]
                m.advisory_ids.append(rec["id"])
                if fixed and (m.fixed is None or cmp(fixed, m.fixed) < 0):
                    m.fixed = fixed
            else:
                by_id[cid] = Match(pkg, cid, [rec["id"]], fixed, rec.get("summary") or rec.get("details", "")[:200], rec)
            break
    return list(by_id.values())
