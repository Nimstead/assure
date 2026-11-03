"""The report: what's vulnerable and how sure we are, then what couldn't be determined and what to do about it, then coverage.
Plain data first (JSON, the API), and a text rendering of that same data. A clean claim is only ever made when everything was read."""

import hashlib
import json
import re
from collections import Counter, defaultdict

from nimstead import lifecycle
from nimstead.engine.collection import Inventory
from nimstead.engine.content import Content
from nimstead.engine.evaluate import ENGINE_VERSION
from nimstead.engine.model import REASONS, Outcome, Verdict
from nimstead.versions import comparator_for, sort_key

FAMILIES = {"os": "Windows itself", "microsoft": "Microsoft products", "app": "Third-party apps", "distro": "Distribution packages"}
SOURCE_NAMES = {"windows_build": "Windows build", "uninstall": "Uninstall entries", "user_hives": "Signed-out users' apps",
                "microsoft_products": "Microsoft products", "host_facts": "Host facts", "drivers": "Drivers",
                "os_release": "Platform (os-release)", "package_db": "Package database"}
NOT_YET = "End of support, Windows settings, drivers and Java archives aren't judged by this report yet: they stay findings in the normal view."
NOT_YET_LINUX = ("Livepatch, services still running replaced libraries, and software outside the package manager (Java archives included) "
                 "aren't judged by this report yet. Kernels installed but not running are judged, and marked so.")
DETERMINED = (Outcome.VULNERABLE, Outcome.NOT_VULNERABLE, Outcome.NOT_APPLICABLE)
_SHOWN = 5


def digest(verdicts: list[Verdict]) -> str:
    return hashlib.sha256(json.dumps([v.as_dict() for v in verdicts], sort_keys=True).encode()).hexdigest()


def _highest(versions: set[str], eco: str) -> str | None:
    cmp = comparator_for(eco)
    try:
        return max(versions, key=sort_key(cmp)) if versions else None
    except ValueError:
        return sorted(versions)[-1]


def _vulnerable(verdicts: list[Verdict]) -> list[dict]:
    by_install: dict[tuple, list[Verdict]] = defaultdict(list)
    for v in verdicts:
        if v.outcome == Outcome.VULNERABLE:
            by_install[v.family, v.product, v.instance].append(v)
    groups = []
    for (family, product, instance), vs in by_install.items():
        vs.sort(key=lambda v: (not v.kev, -(v.cvss or 0), v.vuln_id))
        fix = _highest({v.fixed for v in vs if v.fixed}, vs[0].ecosystem)
        kb = next((v.kb for v in vs if v.fixed == fix and v.kb), None)
        action = ((f"Install KB{kb}, then restart" if kb else f"Update Windows to build {fix} or later") if family == "os" else f"Update to {fix} or later") if fix else "No fix is published yet"
        expected = f"at least {fix}" if fix else "no fixed version published"
        if vs[0].ecosystem == lifecycle.ECOSYSTEM:
            action, expected = "Upgrade to a supported release", "a release that still gets security updates"
        groups.append({"family": family, "product": product, "instance": instance, "grade": vs[0].grade, "version": vs[0].version, "observed": vs[0].observed,
                       "expected": expected, "source": vs[0].source, "action": action, "kernel": vs[0].kernel,
                       "pending_reboot": any(v.pending_reboot for v in vs), "fixed_after_restart": sum(v.pending_reboot for v in vs),
                       "raise_confidence": vs[0].detail, "count": len(vs), "no_fix": sum(not v.fixed for v in vs),
                       "no_fix_planned": sum(v.vendor_status == "no-fix-planned" for v in vs),
                       "known_exploited": sum(v.kev for v in vs), "worst_cvss": max((v.cvss or 0 for v in vs), default=0) or None,
                       "vulnerabilities": [{"id": v.vuln_id, "kev": v.kev, "cvss": v.cvss, "cvss_source": v.cvss_source, "fixed": v.fixed, "kb": v.kb, "summary": v.summary,
                                            "vendor_status": v.vendor_status} for v in vs]})
    return sorted(groups, key=lambda g: (-g["known_exploited"], -(g["worst_cvss"] or 0), g["product"], g["instance"] or ""))


def _undetermined(verdicts: list[Verdict]) -> list[dict]:
    groups: dict[tuple, list[Verdict]] = defaultdict(list)
    for v in verdicts:
        if v.outcome in (Outcome.UNDETERMINED, Outcome.NOT_RUN):
            groups[v.outcome, v.reason, v.blocker, v.detail].append(v)
    out = []
    for (outcome, reason, blocker, detail), vs in groups.items():
        why, todo = REASONS[reason]
        out.append({"outcome": outcome, "reason": reason, "blocked_by": blocker, "why": why, "source_said": detail, "what_to_do": todo, "count": len(vs),
                    "examples": sorted({v.vuln_id or v.instance or v.product for v in vs})[:_SHOWN]})
    return sorted(out, key=lambda g: (-g["count"], g["reason"]))


def _coverage(inv: Inventory, verdicts: list[Verdict]) -> dict:
    families = {}
    main = ("distro",) if inv.is_linux else ("os", "microsoft", "app")
    for fam, label in FAMILIES.items():
        vs = [v for v in verdicts if v.family == fam]
        n = Counter(v.outcome.value for v in vs)
        if vs or fam in main:
            families[fam] = {"label": label, "attempted": len(vs), "determined": sum(v.outcome in DETERMINED for v in vs), "outcomes": dict(sorted(n.items()))}
    stated = []
    if not _assessed(verdicts):
        stated.append(f"This host's {'package' if inv.is_linux else 'Windows'} patch state was not assessed.")
    for fam, label in (("microsoft", "Microsoft products"), ("app", "third-party apps"), ("distro", "distribution packages")):
        f = families.get(fam)
        if not f or (fam == "distro" and not _assessed(verdicts)):
            continue
        if f["attempted"] and not f["determined"]:
            stated.append(f"This host's {label} were not assessed.")
        elif f["determined"] < f["attempted"]:
            stated.append(f"{label[0].upper()}{label[1:]}: {f['attempted'] - f['determined']:,} of {f['attempted']:,} checks couldn't be determined.")
    if inv.is_linux and inv.facts.get("pending_reboot"):
        stated.append("The distribution says a restart is waiting: what's running may be older than what's installed.")
    return {"sources": [{"name": s.name, "label": SOURCE_NAMES.get(s.name, s.name), "state": s.state, "count": s.count, "error": s.error} for s in inv.sources()],
            "families": families, "statements": [*stated, NOT_YET_LINUX if inv.is_linux else NOT_YET]}


def _assessed(verdicts: list[Verdict]) -> bool:
    """Patch state was judged: an OS or package verdict with evidence. A release's end-of-support date alone isn't that."""
    return any(v.outcome in DETERMINED and v.family in ("os", "distro") and v.ecosystem != lifecycle.ECOSYSTEM for v in verdicts)


def _headline(verdicts: list[Verdict], inv: Inventory) -> dict:
    vuln = sum(v.outcome == Outcome.VULNERABLE for v in verdicts)
    installs = len({(v.product, v.instance) for v in verdicts if v.outcome == Outcome.VULNERABLE})
    open_ = sum(v.outcome in (Outcome.UNDETERMINED, Outcome.NOT_RUN) for v in verdicts)
    assessed = _assessed(verdicts)
    tail = f" {open_:,} checks couldn't be determined." if open_ else ""
    if vuln:
        return {"status": "vulnerable", "text": f"VULNERABLE: {vuln:,} vulnerabilities across {installs} install{'s' * (installs > 1)}.{tail}"}
    if not assessed:
        return {"status": "not-assessed", "text": f"NOT ASSESSED: this host's patch state wasn't determined, so this is not a clean result.{tail}"}
    if open_:
        return {"status": "undetermined", "text": f"NOT CLEAN, NOT PROVEN VULNERABLE: nothing found in what was read, but {open_:,} checks couldn't be determined."}
    return {"status": "no-known-vulnerabilities", "text": "NO KNOWN VULNERABILITIES in what this report judges. Everything it depends on was read."}


def build(inv: Inventory, content: Content, verdicts: list[Verdict]) -> dict:
    per_install: Counter = Counter((v.family, v.product, v.instance, v.grade) for v in verdicts if v.outcome == Outcome.NOT_VULNERABLE)
    return {"host": inv.hostname, "os": inv.os_name, "agent_version": inv.agent_version, "inventory_read_at": inv.collected_at,
            "engine_version": ENGINE_VERSION, "content_version": content.version, "inventory_sha256": inv.sha256(), "verdicts_sha256": digest(verdicts),
            "headline": _headline(verdicts, inv), "vulnerable": _vulnerable(verdicts), "undetermined": _undetermined(verdicts),
            "not_vulnerable": [{"family": f, "product": p, "instance": i, "grade": g, "checks": n} for (f, p, i, g), n in sorted(per_install.items(), key=str)],
            "not_applicable": sum(v.outcome == Outcome.NOT_APPLICABLE for v in verdicts), "coverage": _coverage(inv, verdicts)}


def _safe(line: str) -> str:
    """T31: what a host reports never reaches a terminal as control characters."""
    return re.sub(r"[\x00-\x1f\x7f-\x9f]", "?", line)


def render(r: dict) -> str:
    """The report as a person reads it."""
    out = [f"Scan report: {r['host'] or 'this host'}", f"{r['os'] or 'Unknown OS'}, agent {r['agent_version'] or 'unknown'}" + (f", inventory read {r['inventory_read_at']}" if r["inventory_read_at"] else ""),
           "", r["headline"]["text"]]
    if r["vulnerable"]:
        out += ["", "What's vulnerable"]
    for g in r["vulnerable"]:
        extra = "".join([f", {g['known_exploited']} known exploited" if g["known_exploited"] else "", f", worst CVSS {g['worst_cvss']}" if g["worst_cvss"] else ""])
        out += [f"  {g['instance']}   how sure: {g['grade']}", f"    {g['count']} CVE{'s' * (g['count'] > 1)}{extra}",
                f"    Seen:     {g['observed']}", f"    Expected: {g['expected']} ({g['source']})", f"    Do:       {g['action']}"]
        if g["kernel"] == "running" and g["pending_reboot"]:
            out.append(f"    Note:     {g['fixed_after_restart']} of these are fixed in a newer kernel that's already installed: restart into it, then scan again")
        elif g["pending_reboot"]:
            out.append("    Note:     a restart is waiting. The fix may already be installed and not yet effective: restart, then scan again")
        if g["kernel"] == "not-running":
            out.append("    Note:     this kernel is installed but not running: it matters if the host boots it. Removing it clears these")
        if g["no_fix_planned"]:
            rest = g["no_fix"] - g["no_fix_planned"]
            out.append(f"    No fix:   the vendor doesn't plan to fix {g['no_fix_planned']} of these" + (f"; {rest} more {'has' if rest == 1 else 'have'} no fix yet" if rest else ""))
        elif g["no_fix"] and g["no_fix"] < g["count"]:
            out.append(f"    No fix:   {g['no_fix']} of these have no fixed version yet")
        if g["raise_confidence"]:
            out.append(f"    Why not surer: {g['raise_confidence']}")
        shown = [v["id"] + (" (known exploited)" if v["kev"] else "") + (f" CVSS {v['cvss']}" if v["cvss"] else "") for v in g["vulnerabilities"][:_SHOWN]]
        more = g["count"] - len(shown)
        out.append("    Worst:    " + "; ".join(shown) + (f"; and {more:,} more" if more > 0 else ""))
    if r["undetermined"]:
        out += ["", "What couldn't be determined"]
    for g in r["undetermined"]:
        out += [f"  {g['count']:,} {g['outcome']}: {g['why']}"]
        if g["blocked_by"]:
            out.append(f"    Stopped by: {SOURCE_NAMES.get(g['blocked_by'], g['blocked_by'])}" + (f" ({g['source_said']})" if g["source_said"] else ""))
        elif g["source_said"]:
            out.append(f"    Said:       {g['source_said']}")
        out += [f"    Do:         {g['what_to_do']}", f"    For:        {', '.join(g['examples'])}" + (" and others" if g["count"] > len(g["examples"]) else "")]
    c = r["coverage"]
    out += ["", "Coverage", "  What was read:"]
    for s in c["sources"]:
        out.append(f"    {s['label']:<24}{s['state']:<14}{s['count']:>6}" + (f"   {s['error']}" if s["error"] else ""))
    out.append("  What was concluded:")
    for f in c["families"].values():
        out.append(f"    {f['label']:<24}{f['determined']:,} of {f['attempted']:,} determined   " + ", ".join(f"{n:,} {k}" for k, n in f["outcomes"].items()))
    out += [f"  {x}" for x in c["statements"]]
    out += ["", f"Engine {r['engine_version']}, content {r['content_version']}, inventory {r['inventory_sha256'][:12]}, verdicts {r['verdicts_sha256'][:12]}"]
    return "\n".join(_safe(x) for x in out)
