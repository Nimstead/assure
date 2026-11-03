"""The evaluator: inventory and content in, verdicts out. No database, no network, no clock (spec section 14, T34).

Whether a version is affected is decided by `match_package` and the comparators, the same code `scan.rescan` uses, so the two can't
disagree on the numbers. What's new is everything around them: an answer for what doesn't match, and "couldn't tell" as an answer."""

from collections import defaultdict

from nimstead import msproducts, risk, winapps
from nimstead.engine.collection import MS_FACTS, MS_UNINSTALL, Install, Inventory, Source, installs
from nimstead.engine.content import Content
from nimstead.engine.model import Grade, Outcome, Verdict
from nimstead.match import Package, canonical_id, match_package
from nimstead.scan import HOTPATCH, hotpatch_track
from nimstead.versions import comparator_for

ENGINE_VERSION = "1"
APP_SOURCES = ("uninstall", "user_hives")  # where an app's installs can be listed: a product is only absent if both were read
_RAISE = {"unread": "A source it depends on wasn't fully read: fix that and scan again to raise this",
          "self-reported": "The version is what the product says of itself, and the range is NVD's: not a file reading against the vendor's own statement",
          "self-reported-vendor": "The version is what the product says of itself, not read from its files; the fix is the vendor's own statement"}


def _ceiling(i: Install) -> Grade:
    return Grade.CONFIRMED if i.read_directly else Grade.REASONABLE


def _fix_source(rec: dict, eco: str) -> str:
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
    base = {"family": i.family, "ecosystem": i.ecosystem, "product": key, "instance": i.instance, "observed": f"{i.version} ({i.observed})", "version": i.version}
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
    for cve, group in sorted(by_cve.items()):
        rec = group[0]
        fix = next((e["fixed"] for r in group for a in r.get("affected", []) for g in a.get("ranges", []) for e in g.get("events", []) if "fixed" in e), None)
        v = dict(base, check=f"{cve}/{key}", vuln_id=cve, source=_fix_source(rec, i.ecosystem), kb=(rec.get("database_specific") or {}).get("kb"),
                 summary=(rec.get("summary") or "")[:200] or None, kev=cve in c.kev)
        score = risk.cvss_base(rec.get("severity"))
        v |= {"cvss": score, "cvss_source": v["source"]} if score is not None else {"cvss": c.cvss.get(cve), "cvss_source": "NVD" if cve in c.cvss else None}
        if i.family == "os" and _other_line(i.version, group, key):
            out.append(Verdict(outcome=Outcome.UNDETERMINED, reason="release-line", fixed=fix, **v))
            continue
        found = match_package(Package(i.instance, i.version, key), i.ecosystem, group)
        if not found and _incomparable(i.version, group, key, cmp):  # R5.2: it skips what it can't compare, and that isn't "not affected"
            out.append(Verdict(outcome=Outcome.UNDETERMINED, reason="incomparable", fixed=fix, **v))
        elif found:
            out.append(Verdict(outcome=Outcome.VULNERABLE, grade=grade, fixed=found[0].fixed, detail=why, pending_reboot=bool(i.family == "os" and pending), **v))
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
        if eco in ("Windows", msproducts.ECOSYSTEM, winapps.ECOSYSTEM) and (eco, product, vuln) not in answered and (eco, product) not in gone:
            family = {"Windows": "os", msproducts.ECOSYSTEM: "microsoft", winapps.ECOSYSTEM: "app"}[eco]
            out.append(Verdict(f"{vuln}/{product}", family, eco, product, Outcome.UNDETERMINED, vuln_id=vuln, grade=Grade.UNVERIFIED, reason="not-reassessed"))
    return out


def evaluate(inv: Inventory, content: Content, prior: tuple | list = ()) -> list[Verdict]:
    """`prior`: (ecosystem, package, vuln_id) of findings already open on this host."""
    if not inv.received:
        return [Verdict("product:windows", "os", "Windows", "Windows", Outcome.NOT_RUN, reason="no-inventory")]
    if inv.ecosystem != "Windows":
        return [Verdict("product:windows", "os", "Windows", "Windows", Outcome.NOT_RUN, reason="unsupported-platform", detail=f"this host reports {inv.ecosystem or 'nothing'}")]
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
