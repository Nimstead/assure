"""The detection content one evaluation reads: the existing advisories, as data, with a version that names exactly what was used (T34).

The only module here that touches the database. Advisories change in place with each feed update, so the version is a hash of
what this host's evaluation consulted, plus the newest date in it so a person can read its age. Same inventory and same
content version: same verdicts."""

import hashlib
import json
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from nimstead import lifecycle, msproducts, updates, winapps
from nimstead.db import Advisory, Cvss, Kev
from nimstead.engine.collection import Inventory, app_installs, installs, linux
from nimstead.match import normalize_ecosystem
from nimstead.scan import HOTPATCH

ECOSYSTEMS = ("Windows", msproducts.ECOSYSTEM, winapps.ECOSYSTEM)


@dataclass(frozen=True)
class Content:
    """Detection input snapshot keyed by (ecosystem, product), with KEV, CVSS, feed coverage, and a version.

    universe contains distro packages with advisories; eol optionally holds distro lifecycle data."""
    records: dict[tuple[str, str], list[dict]]  # (ecosystem, product key) -> OSV-shaped records, sorted by id
    kev: frozenset[str]
    cvss: dict[str, float]  # NVD's, for what the advisory itself doesn't score
    feeds: frozenset[str]  # ecosystems with any advisory at all
    version: str
    universe: frozenset[str] = frozenset()  # Linux: every package the host's distro release has an advisory for
    eol: dict | None = None  # Linux: endoflife.date's cycles for the host's distro, None when not loaded
    memo: dict = field(default_factory=dict, compare=False, repr=False)  # the feed pass's cache (see make), for evaluate's per-pass reuse

    @classmethod
    def make(cls, records: dict, kev=(), cvss: dict | None = None, feeds=None, universe=(), eol: dict | None = None,
             memo: dict | None = None) -> Content:
        """Return a sorted Content snapshot with a hash-derived version.

        records maps (ecosystem, product) tuples to OSV dictionaries with id keys. kev and universe
        are iterables of strings; cvss maps CVEs to scores. feeds overrides inferred loaded ecosystems.
        eol is optional lifecycle data. `memo`: the feed pass's cache, so each product's records are sorted and hashed (with
        their KEV and CVSS) once a pass, not once a host: serialising them per host was most of the hourly cost. Advisories,
        KEV and CVSS don't change within a pass. Missing record IDs raise KeyError."""
        memo = {} if memo is None else memo
        kev, cvss, universe = frozenset(kev), cvss or {}, frozenset(universe)
        feeds = frozenset(feeds if feeds is not None else {e for (e, _), v in records.items() if v})
        out, digests, newest = {}, [], ""
        for k in sorted(records):
            if (d := memo.get(("engine", "digest", *k))) is None:
                v = sorted(records[k], key=lambda r: r["id"])
                ids = sorted(cves(v))
                body = [v, [c for c in ids if c in kev], {c: cvss[c] for c in ids if c in cvss}]
                d = memo["engine", "digest", *k] = (v, hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest(),
                                                     max((str(r.get("modified", ""))[:10] for r in v), default=""))
            out[k] = d[0]
            digests.append((k, d[1]))
            newest = max(newest, d[2])
        if universe and (u := memo.get(("engine", "udigest", universe))) is None:  # a frozenset caches its own hash
            u = memo["engine", "udigest", universe] = hashlib.sha256(json.dumps(sorted(universe)).encode()).hexdigest()
        body = json.dumps({"app": updates.current_version(), "records": digests, "feeds": sorted(feeds),
                           "universe": u if universe else None, "eol": eol}, sort_keys=True, default=str)
        return cls(out, kev, cvss, feeds, f"{newest or 'none'}.{hashlib.sha256(body.encode()).hexdigest()[:12]}", universe, eol, memo)


def cves(records: list[dict]) -> set[str]:
    """The CVE ids an advisory list names: its own ids, aliases and upstream ids."""
    return {a for r in records for a in [r["id"], *r.get("aliases", []), *r.get("upstream", [])] if a.startswith("CVE-")}


def _once(cache: dict, key: tuple, fn):
    """`fn()` once per feed pass: `cache` is `scan.rescan`'s, shared across hosts, so per-pass constants are read once, not per host."""
    if key not in cache:
        cache[key] = fn()
    return cache[key]


def load(s: Session, inv: Inventory, cache: dict | None = None) -> Content:
    """Read the advisories and risk metadata needed for Inventory inv from Session s.

    `cache`: `scan.rescan`'s per-pass dict, `(ecosystem, package) -> decoded records`. Records already in it are reused and
    those read here are added; engine-only entries use 3-tuple `("engine", ...)` keys so they can't collide with rescan's.
    Return Content with feed-coverage and lifecycle metadata. Does not write; database errors propagate."""
    cache = {} if cache is None else cache
    wanted = {(i.ecosystem, k) for i in installs(inv) for k in i.keys}
    wanted |= {(e, k + HOTPATCH) for e, k in wanted if e == "Windows"}
    apps = {(i.ecosystem, i.keys[0]) for i in app_installs(inv)}
    wanted |= apps
    distro = normalize_ecosystem(inv.ecosystem) if linux(inv.ecosystem) else None
    app_ecos = sorted({e for e, _ in apps})
    queried = (*ECOSYSTEMS, *app_ecos, *([distro] if distro else []))
    for eco in queried:
        names = sorted(k for e, k in wanted if e == eco and (e, k) not in cache)
        for n in names:
            cache[eco, n] = []
        for i in range(0, len(names), 500):  # stay under SQL parameter limits
            for pkg, rec in s.execute(select(Advisory.package, Advisory.record).where(Advisory.ecosystem == eco, Advisory.package.in_(names[i:i + 500]))):
                cache[eco, pkg].append(rec)
    records: dict[tuple[str, str], list[dict]] = {k: cache[k] if k[0] in queried else [] for k in wanted}  # outside the queried ecosystems: empty, as before
    todo = sorted(k for k in records if ("engine", "kev", *k) not in cache)
    cves_of = {k: cves(records[k]) for k in todo}
    ids = sorted(set().union(*cves_of.values()))
    kev_found, cvss_found = set(), {}
    for i in range(0, len(ids), 500):
        part = ids[i:i + 500]
        kev_found.update(s.scalars(select(Kev.cve).where(Kev.cve.in_(part))))
        cvss_found |= dict(s.execute(select(Cvss.cve, Cvss.score).where(Cvss.cve.in_(part))).all())
    for k in todo:  # per product, so the next host with the same product asks nothing
        cache["engine", "kev", *k] = frozenset(cves_of[k] & kev_found)
        cache["engine", "cvss", *k] = {c: cvss_found[c] for c in cves_of[k] if c in cvss_found}
    kev = set().union(*(cache["engine", "kev", *k] for k in records))
    cvss = {c: v for k in records for c, v in cache["engine", "cvss", *k].items()}
    loaded = {e for e in (*app_ecos, *([] if distro else ECOSYSTEMS))
              if _once(cache, ("engine", "loaded", e), lambda e=e: s.scalar(select(Advisory.id).where(Advisory.ecosystem == e).limit(1)) is not None)}
    if not distro:
        return Content.make(records, kev, cvss, loaded, memo=cache)
    universe = _once(cache, ("engine", "universe", distro),
                     lambda: frozenset(s.scalars(select(Advisory.package).where(Advisory.ecosystem == distro).distinct())))
    cycle = lifecycle.distro_cycle(distro)
    eol = _once(cache, ("engine", "eol", distro), lambda: s.scalar(select(Advisory.record).where(Advisory.ecosystem == "EOL", Advisory.package == cycle[0])) if cycle else None)
    return Content.make(records, kev, cvss, loaded | ({distro} if universe else set()), universe, (eol or {}).get("cycles"), memo=cache)
