"""The evaluator: inventory and content in, verdicts out. No database, no network, no clock (spec section 14, T34).

Whether a version is affected is decided by `match_package` and the comparators, the same code `scan.rescan` uses, so the two can't
disagree on the numbers. What's new is everything around them: an answer for what doesn't match, and "couldn't tell" as an answer."""

import re
from collections import defaultdict
from dataclasses import replace

from nimstead import lifecycle, msproducts, risk, winapps
from nimstead.engine.collection import MS_FACTS, MS_UNINSTALL, Install, Inventory, Source, installs, linux, manager
from nimstead.engine.content import Content
from nimstead.engine.model import Grade, Outcome, Verdict
from nimstead.match import Package, canonical_id, match_package, normalize_ecosystem
from nimstead.scan import HOTPATCH, hotpatch_track
from nimstead.versions import comparator_for

ENGINE_VERSION = "2"  # 2: Linux
# what each package manager would install (Debian policy 5.6.12, RPM's EVR as the agent sends it, apk-tools' own rule)
_DISTRO_VERSION = {"dpkg": re.compile(r"(\d+:)?\d[A-Za-z0-9.+~-]*(?<!-)"), "rpm": re.compile(r"(\d+:)?[A-Za-z0-9._+~^]+-[A-Za-z0-9._+~^]+"),
                   "apk": re.compile(r"\d.*")}
_MODULE = re.compile(r"\.module[+_]")  # a modular RPM's release: el9 module builds carry ".module+el9…" or ".module_el9…"
APP_SOURCES = ("uninstall", "user_hives")  # where an app's installs can be listed: a product is only absent if both were read
_RAISE = {"unread": "A source it depends on wasn't fully read: fix that and scan again to raise this",
          "self-reported": "The version is what the product says of itself, and the range is NVD's: not a file reading against the vendor's own statement",
          "self-reported-vendor": "The version is what the product says of itself, not read from its files; the fix is the vendor's own statement"}


def _ceiling(i: Install) -> Grade:
    return Grade.CONFIRMED if i.read_directly else Grade.REASONABLE


def _fixes(recs: list[dict], key: str, eco: str | None) -> list[str]:
    """Fixed versions in these records; with `eco`, only this package's in this release (a distro record covers several)."""
    return [e["fixed"] for r in recs for a in r.get("affected", [])
            if eco is None or (a.get("package", {}).get("name") == key and normalize_ecosystem(a.get("package", {}).get("ecosystem", "")) == eco)
            for g in a.get("ranges", []) for e in g.get("events", []) if "fixed" in e]


def _same_stream(version: str, recs: list[dict], key: str, eco: str) -> list[dict]:
    """The records whose fixes are for the installed module stream: modular or not, and the same major version.
    shortcut: two streams of one major version (nginx 1.22 and 1.24) still compare; use the module label once advisories carry it."""
    mine, major = bool(_MODULE.search(version)), version.split(":", 1)[-1].split(".")[0]
    return [r for r in recs if all(bool(_MODULE.search(f)) == mine and (not mine or f.split(":", 1)[-1].split(".")[0] == major)
                                   for f in _fixes([r], key, eco))]


def _vendor_status(recs: list[dict], key: str, eco: str) -> str:
    """R7.5, from what the distro's own records carry: Debian marks what it won't fix in a stable release as `unimportant`."""
    planned = any((a.get("ecosystem_specific") or {}).get("urgency") == "unimportant" for r in recs for a in r.get("affected", [])
                  if a.get("package", {}).get("name") == key and normalize_ecosystem(a.get("package", {}).get("ecosystem", "")) == eco)
    return "no-fix-planned" if planned else "no-fix-yet"


def _fix_source(rec: dict, eco: str) -> str:
    if linux(eco):  # OSV carries each distro's own feed: Debian's tracker, Ubuntu's notices, AlmaLinux's errata, ...
        return eco.split(":")[0]
    rid = rec["id"]
    if rid.startswith("OFFICE-") or rid.startswith("MSRC-") or eco in ("Windows", msproducts.ECOSYSTEM):
        return "MSRC"
    return "CVE List" if rid.endswith("-v5") else "NVD"


def _other_line(version: str, recs: list[dict], key: str) -> bool:
    """R5.3: a Windows fix for another build number belongs to another release line, and the numbers mean nothing against this one."""
    line = version.split(".")[:3]
    return any("fixed" in e and e["fixed"].split(".")[:3] != line
               for r in recs for a in r.get("affected", []) if a.get("package", {}).get("name") == key
               for g in a.get("ranges", []) for e in g.get("events", []))


def _incomparable(version: str, recs: list[dict], key: str, cmp) -> bool:
    try:
        for r in recs:
            for a in r.get("affected", []):
                if a.get("package", {}).get("name") == key:
                    for g in a.get("ranges", []):
                        for e in g.get("events", []):
                            for v in e.values():
                                if v != "0":
                                    cmp(version, v)
    except ValueError:
        return True
    return False


def _product_key(i: Install, c: Content) -> str:
    return next((k for k in i.keys if c.records.get((i.ecosystem, k))), i.keys[-1])


def _records(i: Install, key: str, c: Content) -> list[dict]:
    recs = c.records.get((i.ecosystem, key)) or []
    if i.ecosystem == "Windows" and (hot := hotpatch_track(c.records.get((i.ecosystem, key + HOTPATCH)) or [], i.version)):
        recs = [r for r in recs if not set(r["aliases"]) & hot[0]] + hot[1]
    return [r for r in recs if not r.get("withdrawn")]


def _judge(inv: Inventory, i: Install, c: Content) -> list[Verdict]:
    """Every advisory for this product, against this one install."""
    read = inv.source(i.source)
    if not i.comparable:
        return [Verdict(f"product:{i.keys[0]}", i.family, i.ecosystem, i.keys[0], Outcome.UNDETERMINED, instance=i.instance, reason="unreadable-version",
                        observed=f"{i.version} ({i.observed})", version=i.version)]
    key = _product_key(i, c)
    recs = _records(i, key, c)
    base = {"family": i.family, "ecosystem": i.ecosystem, "product": key, "instance": i.instance, "observed": f"{i.version} ({i.observed})", "version": i.version,
            "kernel": i.kernel}
    if not recs and i.family == "distro":  # the distro's tracker covers its whole archive: nothing to check against
        return []
    if not recs:
        missing = i.ecosystem not in c.feeds
        return [Verdict(f"product:{key}", outcome=Outcome.NOT_RUN if missing else Outcome.UNDETERMINED, reason="feed-missing" if missing else "no-advisories", **base)]
    pending = inv.facts.get("pending_reboot")
    grade = _ceiling(i)
    if read.state != "ok" or (i.family == "os" and pending is None):  # R6.1: the method actually used lowers the ceiling
        grade, why = Grade.UNVERIFIED, _RAISE["unread"]
    else:
        why = None if grade == Grade.CONFIRMED else _RAISE["self-reported" if _fix_source(recs[0], i.ecosystem) in ("NVD", "CVE List") else "self-reported-vendor"]
    cmp = comparator_for(i.ecosystem)
    by_cve = defaultdict(list)
    for r in recs:
        by_cve[canonical_id(r)].append(r)
    out = []
    distro = i.family == "distro"
    valid = not distro or _DISTRO_VERSION[manager(i.ecosystem)].fullmatch(i.version)  # dpkg and rpm order any string; neither installs one
    for cve, group in sorted(by_cve.items()):
        rec = group[0]
        fix = next(iter(_fixes(group, key, i.ecosystem if distro else None)), None)
        v = dict(base, check=f"{cve}/{key}", vuln_id=cve, source=_fix_source(rec, i.ecosystem), kb=(rec.get("database_specific") or {}).get("kb"),
                 summary=(rec.get("summary") or "")[:200] or None, kev=cve in c.kev)
        score = risk.cvss_base(rec.get("severity"))
        v |= {"cvss": score, "cvss_source": v["source"]} if score is not None else {"cvss": c.cvss.get(cve), "cvss_source": "NVD" if cve in c.cvss else None}
        if i.family == "os" and _other_line(i.version, group, key):
            out.append(Verdict(outcome=Outcome.UNDETERMINED, reason="release-line", fixed=fix, **v))
            continue
        if distro and manager(i.ecosystem) == "rpm":
            group = _same_stream(i.version, group, key, i.ecosystem)
            if not group:  # every fix for it is another module stream's (R7.4, T12)
                out.append(Verdict(outcome=Outcome.UNDETERMINED, reason="other-stream", fixed=fix, **v))
                continue
            fix = next(iter(_fixes(group, key, i.ecosystem)), None)
        found = match_package(Package(i.instance, i.version, key), i.ecosystem, group) if valid else []
        if not found and (not valid or _incomparable(i.version, group, key, cmp)):  # R5.2: it skips what it can't compare, and that isn't "not affected"
            out.append(Verdict(outcome=Outcome.UNDETERMINED, reason="incomparable", fixed=fix, **v))
        elif found:
            status = (_vendor_status(group, key, i.ecosystem) if distro else "no-fix-yet") if found[0].fixed is None else None
            out.append(Verdict(outcome=Outcome.VULNERABLE, grade=grade, fixed=found[0].fixed, detail=why, pending_reboot=bool(i.family == "os" and pending),
                               vendor_status=status, **v))
        elif i.family == "os" and pending:  # T16: reported as pending, not as fixed
            out.append(Verdict(outcome=Outcome.UNDETERMINED, reason="pending-reboot", fixed=fix, **v))
        else:
            out.append(Verdict(outcome=Outcome.NOT_VULNERABLE, grade=grade, fixed=fix, detail=why, **v))
    return out


def _absent_or_blocked(check: str, family: str, eco: str, product: str, present: bool, s: Source) -> Verdict | None:
    """The product as a whole. Absent counts only if the list it would be on was read to its end (R4.2)."""
    base = {"check": f"product:{check}", "family": family, "ecosystem": eco, "product": product}
    if s.state == "ok":
        return None if present else Verdict(outcome=Outcome.NOT_APPLICABLE, detail=f"not on the {s.name} list, which was read in full", **base)
    return Verdict(outcome=Outcome.UNDETERMINED if s.state == "partial" else Outcome.NOT_RUN, reason=s.reason, blocker=s.name, detail=s.error, **base)


def _os_blocked(inv: Inventory) -> Verdict:
    s = inv.source("windows_build")
    base = {"check": "product:windows", "family": "os", "ecosystem": "Windows", "product": "Windows"}
    if s.state in ("failed", "partial"):
        return Verdict(outcome=Outcome.NOT_RUN, reason=s.reason, blocker=s.name, detail=s.error, **base)
    if why := inv.facts.get("os_unmatched"):
        return Verdict(outcome=Outcome.NOT_RUN, reason="unsupported-platform", detail=str(why)[:300], **base)
    if s.state != "ok":
        return Verdict(outcome=Outcome.NOT_RUN, reason=s.reason, blocker=s.name, detail=s.error, **base)
    return Verdict(outcome=Outcome.NOT_RUN, reason="precondition-unknown", blocker=s.name, detail="the agent says it read the build, but sent no Windows entry", **base)


def _carry_forward(verdicts: list[Verdict], prior) -> list[Verdict]:
    """T7, R4.6: an open finding this scan has no answer for stays open, flagged. Without a positive verdict, nothing is fixed."""
    answered = {(v.ecosystem, v.product, v.vuln_id) for v in verdicts if v.vuln_id}
    gone = {(v.ecosystem, v.product) for v in verdicts if v.outcome == Outcome.NOT_APPLICABLE}
    out = []
    for eco, product, vuln in sorted(set(prior)):
        if (eco in ("Windows", msproducts.ECOSYSTEM, winapps.ECOSYSTEM) or linux(eco)) and (eco, product, vuln) not in answered and (eco, product) not in gone:
            family = {"Windows": "os", msproducts.ECOSYSTEM: "microsoft", winapps.ECOSYSTEM: "app"}.get(eco, "distro")
            out.append(Verdict(f"{vuln}/{product}", family, eco, product, Outcome.UNDETERMINED, vuln_id=vuln, grade=Grade.UNVERIFIED, reason="not-reassessed"))
    return out


def _kernels(inv: Inventory, found: list[Install], verdicts: list[Verdict], eco: str) -> list[Verdict]:
    """R7.7: a kernel that's installed and not running is its own state, and a fix in a newer installed kernel means a restart is waiting."""
    running = {i.keys[0]: i.version for i in found if i.kernel == "running"}
    cmp = comparator_for(eco)

    def newer(v: Verdict) -> bool:
        try:
            return v.product in running and cmp(v.version, running[v.product]) > 0
        except ValueError:
            return False
    newer_fixed = {(v.product, v.vuln_id) for v in verdicts if v.kernel == "not-running" and v.outcome == Outcome.NOT_VULNERABLE and newer(v)}
    out = [replace(v, pending_reboot=True) if v.kernel == "running" and v.outcome == Outcome.VULNERABLE and (v.product, v.vuln_id) in newer_fixed else v
           for v in verdicts]
    release = inv.facts.get("kernel_release")
    if isinstance(release, str) and not running:
        kernels = sorted(i.instance for i in found if i.kernel)
        out.append(Verdict("product:running-kernel", "distro", eco, "running kernel", Outcome.UNDETERMINED, instance=release[:100], reason="kernel-unpackaged",
                           detail=f"running {release[:100]}; " + (f"installed kernel packages: {', '.join(kernels[:5])}" if kernels else "no kernel package is installed")))
    return out


def _end_of_life(inv: Inventory, c: Content, eco: str) -> Verdict | None:
    """R7.6: past its end of support, a release gets no advisories, so their absence proves nothing. Judged as of when the inventory was read."""
    if not (cycle := lifecycle.distro_cycle(eco)):
        return None
    product, release = cycle
    vid = f"EOL:{product}-{release}"
    base = {"check": vid, "family": "distro", "ecosystem": lifecycle.ECOSYSTEM, "product": f"{product} {release}", "vuln_id": vid,
            "instance": f"{product} {release}", "source": "endoflife.date", "observed": f"{eco} (os-release)"}
    end, read = (c.eol or {}).get(release), (inv.collected_at or "")[:10]
    if end is None or (isinstance(end, str) and not read):
        why = "no end-of-support data is loaded for it" if c.eol is None else f"endoflife.date lists no {product} {release}" if end is None else "when the inventory was read isn't known"
        return Verdict(outcome=Outcome.UNDETERMINED, reason="eol-unknown", detail=why, **base)
    raise_ = "The date is endoflife.date's summary of the distribution's own lifecycle page"
    if end is True or (isinstance(end, str) and end < read):
        return Verdict(outcome=Outcome.VULNERABLE, grade=Grade.REASONABLE, detail=raise_,
                       summary=f"{product} {release}: no security updates" + (f" since {end}" if isinstance(end, str) else ""), **base)
    return Verdict(outcome=Outcome.NOT_VULNERABLE, grade=Grade.REASONABLE, detail=raise_,
                   summary=f"{product} {release}: supported" + (f" until {end}" if isinstance(end, str) else ", no end date announced"), **base)


def _evaluate_linux(inv: Inventory, c: Content, prior) -> list[Verdict]:
    """R7.4: not installed is not-applicable, at or above the distro's fix not-vulnerable, below it vulnerable, incomparable undetermined.
    Only a package list read in full is judged: one that isn't may not be this read's at all (the server keeps the last one)."""
    eco = normalize_ecosystem(inv.ecosystem)
    db = inv.source("package_db")
    out: list[Verdict] = []
    if eco not in c.feeds:
        out.append(Verdict(f"product:{eco}", "distro", eco, eco, Outcome.NOT_RUN, reason="feed-missing"))
    else:
        found = installs(inv) if db.state == "ok" else []
        for i in found:
            if c.records.get((eco, i.keys[0])):  # a package no advisory names isn't a check, just inventory
                out += _judge(inv, i, c)
        if db.state == "ok":
            out = _kernels(inv, found, out, eco)
        held = {i.keys[0] for i in found}
        out += [v for k in sorted(c.universe) if (v := _absent_or_blocked(k, "distro", eco, k, k in held, db))]
    if eol := _end_of_life(inv, c, eco):
        if eol.outcome == Outcome.VULNERABLE:
            out = [replace(v, outcome=Outcome.UNDETERMINED, reason="end-of-life", grade=None) if v.outcome == Outcome.NOT_VULNERABLE else v for v in out]
        out.append(eol)
    out += _carry_forward(out, prior)
    return sorted(out, key=lambda v: (v.family, v.product, v.check, v.instance or ""))


def evaluate(inv: Inventory, content: Content, prior: tuple | list = ()) -> list[Verdict]:
    """`prior`: (ecosystem, package, vuln_id) of findings already open on this host."""
    if not inv.received:
        if linux(inv.ecosystem):
            return [Verdict("product:platform", "distro", inv.ecosystem, inv.ecosystem, Outcome.NOT_RUN, reason="no-inventory")]
        return [Verdict("product:windows", "os", "Windows", "Windows", Outcome.NOT_RUN, reason="no-inventory")]
    if linux(inv.ecosystem):
        return _evaluate_linux(inv, content, prior)
    if inv.ecosystem != "Windows":
        why = inv.facts.get("os_unmatched") or f"this host reports {inv.ecosystem or 'nothing'}"
        return [Verdict("product:platform", "distro" if inv.is_linux else "os", inv.ecosystem, inv.ecosystem or "unknown", Outcome.NOT_RUN,
                        reason="unsupported-platform", detail=str(why)[:300])]
    found = installs(inv)
    out: list[Verdict] = []
    if not any(i.family == "os" for i in found):
        out.append(_os_blocked(inv))
    for i in found:
        out += _judge(inv, i, content)
    # the whole curated list, so "not installed" and "couldn't tell" are both said out loud (R3.7)
    held = {k for i in found for k in i.keys} | {p["name"] for p in inv.packages if p.get("ecosystem") == msproducts.ECOSYSTEM}
    apps, ms = inv.worst(*APP_SOURCES), inv.worst("microsoft_products")
    for key in sorted({p.key for p in winapps.PRODUCTS}):
        out.append(_absent_or_blocked(key, "app", winapps.ECOSYSTEM, key, key in held, apps))
    for label in MS_UNINSTALL:
        out.append(_absent_or_blocked(label, "microsoft", msproducts.ECOSYSTEM, label, any(k.startswith(label) for k in held), apps))
    for name in MS_FACTS:
        out.append(_absent_or_blocked(name, "microsoft", msproducts.ECOSYSTEM, name, name in held, ms))
    out = [v for v in out if v]
    out += _carry_forward(out, prior)
    return sorted(out, key=lambda v: (v.family, v.product, v.check, v.instance or ""))
