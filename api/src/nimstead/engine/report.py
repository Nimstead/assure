"""The report: what's vulnerable and how sure we are, then what couldn't be determined and what to do about it, then coverage.
Plain data first (JSON, the API), and a text rendering of that same data. A clean claim is only ever made when everything was read."""

import functools
import hashlib
import json
import re
from collections import Counter, defaultdict

from nimstead import lifecycle
from nimstead.engine import paths
from nimstead.engine.collection import AGENT_APPS, NOT_REPORTED, Inventory, app_installs
from nimstead.engine.content import Content
from nimstead.engine.evaluate import ENGINE_VERSION
from nimstead.engine.model import REASONS, Outcome, Verdict
from nimstead.versions import comparator_for, sort_key

FAMILIES = {"os": "Windows itself", "microsoft": "Microsoft products", "app": "Third-party apps", "distro": "Distribution packages",
            "application": "Applications outside the package manager"}
SOURCE_NAMES = {"windows_build": "Windows build", "uninstall": "Uninstall entries", "user_hives": "Signed-out users' apps",
                "microsoft_products": "Microsoft products", "host_facts": "Host facts", "drivers": "Drivers",
                "os_release": "Platform (os-release)", "package_db": "Package database",
                **{src: label for src, _, label in AGENT_APPS}, "sbom": "SBOM"}
NOT_YET = ("End of support, Windows settings and drivers aren't judged by this report yet: they stay findings in the normal view. "
           "Settings are read here only to show how they combine with vulnerabilities into attack paths.")
NOT_YET_LINUX = ("Livepatch, services still running replaced libraries, and software outside the package manager other than Python and npm packages "
                 "and Java archives (vendored binaries, containers, self-installed tools) aren't judged by this report yet. "
                 "Kernels installed but not running are judged, and marked so.")
NOT_YET_SBOM = "Only components with a package URL in an ecosystem the advisory feeds cover are judged."
SBOM_IS_NOT_RUNNING = "An SBOM states what was built, not what's running, so nothing judged from it is better than unverified."
DETERMINED = (Outcome.VULNERABLE, Outcome.NOT_VULNERABLE, Outcome.NOT_APPLICABLE)
_GRADES = ("unverified", "reasonable", "confirmed")  # weakest first: an install is as sure as its weakest reading
_SHOWN = 5


@functools.lru_cache(maxsize=131_072)  # verdicts are immutable, and a fleet shares most (a distro's not-installed packages: R7.4)
def _verdict_json(v: Verdict) -> str:
    return json.dumps(v.as_dict(), sort_keys=True)


def digest(verdicts: list[Verdict]) -> str:
    """sha256 of json.dumps([v.as_dict() ...], sort_keys=True), each verdict serialised once per process."""
    return hashlib.sha256(("[" + ", ".join(map(_verdict_json, verdicts)) + "]").encode()).hexdigest()


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


def _applications(inv: Inventory, content: Content, verdicts: list[Verdict]) -> tuple[list[str], dict]:
    """R4.4 for software outside the package manager, as counts and as sentences: what wasn't looked for, what the agent left to the
    package manager (R7.9), what has no advisory at all, and what an SBOM couldn't name. Each said, so none of it reads as clean."""
    out, found, sb = [], app_installs(inv), inv.sbom or {}
    off = [] if inv.kind == "application" else [label for src, _, label in AGENT_APPS if inv.source(src).state in ("off", NOT_REPORTED)]
    if off:
        out.append(f"Not looked for on this host, so not assessed: {', '.join(off)} (the agent's opt-in scans are off, or it predates them).")
    owned = sum(x for x in ((inv.facts.get("app_scan") or {}).get("owned"), (inv.facts.get("jar_scan") or {}).get("owned")) if isinstance(x, int))
    if owned and inv.kind != "application":
        out.append(f"{owned:,} found that the package manager owns were left to it and judged as distribution packages.")
    quiet = sum(not content.records.get((i.ecosystem, i.keys[0])) and i.ecosystem in content.feeds for i in found)
    if quiet:
        out.append(f"{quiet:,} of {len(found):,} installs outside the package manager have no published advisory: no known vulnerability, which isn't proof of none.")
    skipped = sum(n for n in (sb.get("skipped") or {}).values() if isinstance(n, int))
    if any(i.source == "sbom" for i in found) or inv.kind == "application":
        when = f" (received {sb['received'][:10]})" if sb.get("received") else ""
        out.append(f"SBOM{when}: {SBOM_IS_NOT_RUNNING}" + (f" {skipped:,} of its {sb.get('components') or 0:,} components weren't assessed." if skipped else ""))
    vulnerable = {(v.product, v.instance) for v in verdicts if v.family == "application" and v.outcome == Outcome.VULNERABLE}
    return out, {"installs": len(found), "judged": sum(bool(content.records.get((i.ecosystem, i.keys[0]))) for i in found), "vulnerable": len(vulnerable),
                 "no_advisory": quiet, "left_to_package_manager": owned, "sbom_components_not_assessed": skipped, "not_looked_for": off}


def _installs(verdicts: list[Verdict]) -> list[dict]:
    """One line per application install that was checked: where it is, what was concluded and how sure (R4.5). Vulnerable ones also
    get their full entry in `vulnerable`."""
    rows: dict[tuple, Counter] = defaultdict(Counter)
    grade: dict[tuple, str] = {}
    for v in verdicts:
        if v.family == "application" and v.vuln_id and v.instance:
            k = (v.ecosystem, v.product, v.instance)
            rows[k][v.outcome.value] += 1
            if v.grade and (k not in grade or _GRADES.index(v.grade) < _GRADES.index(grade[k])):
                grade[k] = v.grade
    return [{"ecosystem": e, "product": p, "instance": i, "grade": grade.get((e, p, i)), "outcomes": dict(sorted(n.items()))} for (e, p, i), n in sorted(rows.items())]


def _coverage(inv: Inventory, content: Content, verdicts: list[Verdict]) -> dict:
    families = {}
    main = ("application",) if inv.kind == "application" else ("distro", "application") if inv.is_linux else ("os", "microsoft", "app", "application")
    for fam, label in FAMILIES.items():
        vs = [v for v in verdicts if v.family == fam]
        n = Counter(v.outcome.value for v in vs)
        if vs or fam in main:
            families[fam] = {"label": label, "attempted": len(vs), "determined": sum(v.outcome in DETERMINED for v in vs), "outcomes": dict(sorted(n.items()))}
    stated = []
    if not _assessed(verdicts, inv):
        stated.append("This application's components were not assessed." if inv.kind == "application" else
                      f"This host's {'package' if inv.is_linux else 'Windows'} patch state was not assessed.")
    for fam, label in (("microsoft", "Microsoft products"), ("app", "third-party apps"), ("distro", "distribution packages"),
                       ("application", "applications outside the package manager")):
        f = families.get(fam)
        if not f or (fam == "distro" and not _assessed(verdicts, inv)):
            continue
        if f["attempted"] and not f["determined"]:
            stated.append(f"This host's {label} were not assessed.")
        elif f["determined"] < f["attempted"]:
            stated.append(f"{label[0].upper()}{label[1:]}: {f['attempted'] - f['determined']:,} of {f['attempted']:,} checks couldn't be determined.")
    if inv.is_linux and inv.facts.get("pending_reboot"):
        stated.append("The distribution says a restart is waiting: what's running may be older than what's installed.")
    said, apps = _applications(inv, content, verdicts)
    return {"sources": [{"name": s.name, "label": SOURCE_NAMES.get(s.name, s.name), "state": s.state, "count": s.count, "error": s.error} for s in inv.sources()],
            "families": families, "applications": apps,
            "statements": [*stated, *said, NOT_YET_SBOM if inv.kind == "application" else NOT_YET_LINUX if inv.is_linux else NOT_YET]}


def _assessed(verdicts: list[Verdict], inv: Inventory) -> bool:
    """Patch state was judged: an OS or package verdict with evidence (an SBOM's components, for an application). A release's
    end-of-support date alone isn't that."""
    fams = ("application",) if inv.kind == "application" else ("os", "distro")
    return any(v.outcome in DETERMINED and v.family in fams and v.ecosystem != lifecycle.ECOSYSTEM for v in verdicts)


def _headline(verdicts: list[Verdict], inv: Inventory) -> dict:
    vuln = sum(v.outcome == Outcome.VULNERABLE for v in verdicts)
    installs = len({(v.product, v.instance) for v in verdicts if v.outcome == Outcome.VULNERABLE})
    open_ = sum(v.outcome in (Outcome.UNDETERMINED, Outcome.NOT_RUN) for v in verdicts)
    assessed = _assessed(verdicts, inv)
    tail = f" {open_:,} checks couldn't be determined." if open_ else ""
    if vuln:
        return {"status": "vulnerable", "text": f"VULNERABLE: {vuln:,} vulnerabilities across {installs} install{'s' * (installs > 1)}.{tail}"}
    if not assessed:
        what = "this application's components weren't" if inv.kind == "application" else "this host's patch state wasn't"
        return {"status": "not-assessed", "text": f"NOT ASSESSED: {what} determined, so this is not a clean result.{tail}"}
    if open_:
        return {"status": "undetermined", "text": f"NOT CLEAN, NOT PROVEN VULNERABLE: nothing found in what was read, but {open_:,} checks couldn't be determined."}
    return {"status": "no-known-vulnerabilities", "text": "NO KNOWN VULNERABILITIES in what this report judges. Everything it depends on was read."}


def build(inv: Inventory, content: Content, verdicts: list[Verdict]) -> dict:
    per_install: Counter = Counter((v.family, v.product, v.instance, v.grade) for v in verdicts if v.outcome == Outcome.NOT_VULNERABLE)
    return {"host": inv.hostname, "kind": inv.kind, "os": inv.os_name, "agent_version": inv.agent_version, "inventory_read_at": inv.collected_at,
            "engine_version": ENGINE_VERSION, "content_version": content.version, "inventory_sha256": inv.sha256(), "verdicts_sha256": digest(verdicts),
            "headline": _headline(verdicts, inv), "vulnerable": _vulnerable(verdicts), "undetermined": _undetermined(verdicts),
            "not_vulnerable": [{"family": f, "product": p, "instance": i, "grade": g, "checks": n} for (f, p, i, g), n in sorted(per_install.items(), key=str)],
            "not_applicable": sum(v.outcome == Outcome.NOT_APPLICABLE for v in verdicts), "applications": _installs(verdicts),
            "attack_paths": paths.build(inv, content, verdicts),
            "coverage": _coverage(inv, content, verdicts)}


def _safe(line: str) -> str:
    """T31: what a host reports never reaches a terminal as control characters."""
    return re.sub(r"[\x00-\x1f\x7f-\x9f]", "?", line)


def render(r: dict) -> str:
    """The report as a person reads it."""
    who = "Application, from its SBOM (no agent)" if r.get("kind") == "application" else f"{r['os'] or 'Unknown OS'}, agent {r['agent_version'] or 'unknown'}"
    out = [f"Scan report: {r['host'] or 'this host'}", who + (f", inventory read {r['inventory_read_at']}" if r["inventory_read_at"] else ""),
           "", r["headline"]["text"]]
    host = [g for g in r["vulnerable"] if g["family"] != "application"]
    apps = [g for g in r["vulnerable"] if g["family"] == "application"]
    if host:
        out += ["", "What's vulnerable"]
    for g in host:
        out += _group(g)
    if apps or r.get("applications"):  # each install where it was found, vulnerable first, then the rest one line each
        out += ["", "Components, from the SBOM" if r.get("kind") == "application" else "Applications outside the package manager, by location"]
    for g in apps:
        out += _group(g)
    for a in r.get("applications", []):
        if not (n := a["outcomes"]).get("vulnerable"):
            out.append(f"  {a['instance']}   {'no known vulnerability' if set(n) == {'not-vulnerable'} else 'not proven either way'} "
                       f"({', '.join(f'{x:,} {k}' for k, x in n.items())})" + (f"   how sure: {a['grade']}" if a["grade"] else ""))
    out += paths.render(r.get("attack_paths") or [])
    out += _rest(r)
    return "\n".join(_safe(x) for x in out)


def _group(g: dict) -> list[str]:
    """One vulnerable install, the same way whatever kind of software it is."""
    extra = "".join([f", {g['known_exploited']} known exploited" if g["known_exploited"] else "", f", worst CVSS {g['worst_cvss']}" if g["worst_cvss"] else ""])
    out = [f"  {g['instance']}   how sure: {g['grade']}", f"    {g['count']} CVE{'s' * (g['count'] > 1)}{extra}",
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
    return out


def _rest(r: dict) -> list[str]:
    """What couldn't be determined, and coverage."""
    out = []
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
        out.append(f"    {f['label'] + ' ':<24}{f['determined']:,} of {f['attempted']:,} determined   " + ", ".join(f"{n:,} {k}" for k, n in f["outcomes"].items()))
    if (a := c.get("applications")) and (a["installs"] or a["left_to_package_manager"] or a["sbom_components_not_assessed"]):
        out.append(f"  Outside the package manager: {a['installs']:,} installs found, {a['judged']:,} with advisories judged, {a['vulnerable']:,} vulnerable, "
                   f"{a['no_advisory']:,} with no advisory; {a['left_to_package_manager']:,} left to the package manager"
                   + (f"; {a['sbom_components_not_assessed']:,} SBOM components not assessed" if a["sbom_components_not_assessed"] else ""))
    out += [f"  {x}" for x in c["statements"]]
    out += ["", f"Engine {r['engine_version']}, content {r['content_version']}, inventory {r['inventory_sha256'][:12]}, verdicts {r['verdicts_sha256'][:12]}"]
    return out
