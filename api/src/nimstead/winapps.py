"""Third-party Windows apps: a small curated map from what the registry says is installed to an exact NVD CPE,
and the translation of NVD CPE match data for those CPEs into OSV-shaped advisories (ecosystem `WinApp`).

No fuzzy matching (DECISIONS 4, 22): an installed app is matched only if its DisplayName (and, where the name is
generic, its Publisher) fully matches a pattern below. Everything else is inventory and is never compared.
Products whose registry version can't be mapped exactly to NVD's convention are left out on purpose:
- Oracle Java 8: registry "8.0.4310.10" vs NVD "1.8.0 update431".
- Eclipse Temurin: no CPE exists (its CVEs are filed under oracle:jdk/openjdk); equating them would be a guess.
"""

import re
from collections.abc import Callable
from dataclasses import dataclass

from nimstead.versions import appver_parts

ECOSYSTEM = "WinApp"
_ARCH = r"(?:32|64)-bit"


@dataclass(frozen=True)
class Product:
    key: str  # advisory package name (vendor:product of the primary CPE)
    name: re.Pattern  # fullmatch on the registry DisplayName
    cpes: tuple[str, ...] = ()  # NVD vendor:product values whose matches feed this key (default: just key)
    publisher: re.Pattern | None = None  # fullmatch on Publisher; required when set (use where the name is generic)
    version: Callable[[re.Match, str], str] = lambda m, v: v  # registry (match, DisplayVersion) -> NVD-style version
    branch: bool = False  # parallel release branches (ESR, Node): a start-less range applies to the fix's own branch only


def _p(pattern: str) -> re.Pattern:
    return re.compile(pattern)


PRODUCTS: tuple[Product, ...] = (
    Product("google:chrome", _p(r"Google Chrome")),
    Product("microsoft:edge_chromium", _p(r"Microsoft Edge")),  # not "Microsoft Edge WebView2 Runtime"
    Product("mozilla:firefox", _p(r"Mozilla Firefox(?: [\d.]+)? \((?:x64|x86|arm64) [A-Za-z-]+\)")),
    Product("mozilla:firefox_esr", _p(r"Mozilla Firefox ESR(?: [\d.]+)? \((?:x64|x86|arm64) [A-Za-z-]+\)"),
            version=lambda m, v: re.sub(r"(?i)\s*esr$", "", v), branch=True),
    Product("7-zip:7-zip", _p(r"7-Zip \d+\.\d+(?: \((?:x64|x86|arm64)(?: edition)?\))?")),
    Product("notepad-plus-plus:notepad++", _p(r"Notepad\+\+ \((?:64-bit x64|32-bit x86|ARM 64-bit)\)")),
    Product("videolan:vlc_media_player", _p(r"VLC media player")),
    Product("zoom:workplace_desktop", _p(rf"Zoom(?: Workplace| Meetings)?(?: \({_ARCH}\))?"), ("zoom:workplace_desktop", "zoom:zoom", "zoom:meetings"),
            publisher=_p(r"Zoom(?: Video Communications, Inc\.)?")),
    Product("adobe:acrobat_reader", _p(rf"Adobe Acrobat Reader(?: DC)?(?: \({_ARCH}\))?"), ("adobe:acrobat_reader", "adobe:acrobat_reader_dc")),
    Product("oracle:jdk", _p(rf"Java\(TM\) SE Development Kit (?P<v>(?:1[1-9]|[2-9]\d)\.\d+\.\d+)(?: \({_ARCH}\))?"),
            publisher=_p(r"Oracle(?: Corporation)?"), version=lambda m, v: m["v"]),
    Product("git-scm:git", _p(r"Git"), ("git-scm:git", "git_for_windows_project:git_for_windows", "gitforwindows:git"),
            publisher=_p(r"The Git Development Community"),
            version=lambda m, v: ".".join(v.split(".")[:3])),  # Git for Windows 2.47.0.2 = upstream 2.47.0, 2nd Windows build
    Product("python:python", _p(rf"Python (?P<v>\d+\.\d+\.\d+)(?: \({_ARCH}\))?"),
            publisher=_p(r"Python Software Foundation"), version=lambda m, v: m["v"]),  # DisplayVersion is "3.14-64"
    Product("nodejs:node.js", _p(r"Node\.js"), publisher=_p(r"(?:Node\.js|OpenJS) Foundation"), branch=True),
    Product("putty:putty", _p(rf"PuTTY release \d+\.\d+(?: \({_ARCH}\))?")),
    Product("rarlab:winrar", _p(rf"WinRAR \d+\.\d+(?: \({_ARCH}\))?")),
    Product("wireshark:wireshark", _p(rf"Wireshark \d+\.\d+\.\d+(?: (?:x64|x86|arm64|{_ARCH}))?")),
    Product("microsoft:visual_studio_code", _p(r"Microsoft Visual Studio Code(?: \((?:User|System)\))?")),
)

_BY_CPE = {c: p for p in PRODUCTS for c in (p.cpes or (p.key,))}


def identify(name: str, publisher: str | None, version: str) -> tuple[str, str] | None:
    """(product key, version in NVD's convention) for an installed app, or None (inventory only, never matched)."""
    name, publisher = name.strip(), (publisher or "").strip()
    for p in PRODUCTS:
        m = p.name.fullmatch(name)
        if not m or (p.publisher and not p.publisher.fullmatch(publisher)):
            continue
        try:
            v = p.version(m, version.strip())
            appver_parts(v)
        except (ValueError, KeyError):
            return None  # exactly this product, but a version we can't read: refuse rather than guess
        return p.key, v
    return None


# ---- NVD CPE match configurations -> OSV-shaped advisories ----------------------------------------------

def _fields(criteria: str) -> list[str]:
    return [re.sub(r"\\(.)", r"\1", f) for f in re.split(r"(?<!\\):", criteria)]


def _version_ok(v: str) -> bool:
    try:
        appver_parts(v)
        return True
    except ValueError:
        return False


def _events(p: Product, f: list[str], m: dict) -> list[dict] | None:
    """OSV events for one vulnerable cpeMatch, or None when it can't be stated exactly (skipped, never guessed)."""
    ver = f[5]
    if ver == "-":
        return None
    if ver != "*":  # one exact version
        return [{"introduced": ver}, {"last_affected": ver}] if _version_ok(ver) else None
    vsi, vse, vei, vex = (m.get(k) for k in ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding"))
    # ponytail: no end bound = "every version" (usually an unmaintained or unscoped CPE) and an exclusive start can't be
    # written in OSV events; both are skipped rather than approximated.
    if vse or not (vei or vex) or not all(_version_ok(x) for x in (vsi, vei, vex) if x):
        return None
    lo = vsi or "0"
    if p.branch and not vsi:
        lo = f"{appver_parts(vex or vei)[0]}.0"
    return [{"introduced": lo}, {"fixed": vex} if vex else {"last_affected": vei}]


def _windows_possible(cfg: dict) -> bool:
    """False when an AND configuration pins the app to operating systems that don't include Windows."""
    nodes = [n for n in cfg["nodes"] if not n.get("negate")]
    if cfg.get("operator") != "AND" and not any(n.get("operator") == "AND" for n in nodes):
        return True
    oses = [m["criteria"] for n in nodes for m in n["cpeMatch"] if m["criteria"].startswith("cpe:2.3:o:")]
    return not oses or any(":microsoft:windows" in o for o in oses)


def advisories(cve: dict) -> list[tuple[str, dict]]:
    """[(product key, OSV-shaped record)] for the curated products this CVE's configurations list as vulnerable.
    Matches where the app is only the non-vulnerable half of an AND, other platforms, pre-releases, classic-track
    Acrobat and anything with a non-numeric version are dropped. The OS half of an AND is not otherwise required."""
    ranges: dict[str, list[list[dict]]] = {}
    for cfg in cve.get("configurations") or []:
        if cfg.get("negate") or not _windows_possible(cfg):
            continue
        for node in cfg["nodes"]:
            if node.get("negate"):
                continue
            for m in node["cpeMatch"]:
                f = _fields(m["criteria"])
                p = _BY_CPE.get(f[3] + ":" + f[4]) if f[2] == "a" else None
                if (not p or not m.get("vulnerable") or f[6] not in ("*", "-") or f[10] not in ("*", "-", "windows")
                        or f[9] == "classic"):
                    continue
                if (ev := _events(p, f, m)) and ev not in ranges.setdefault(p.key, []):
                    ranges[p.key].append(ev)
    if not ranges:
        return []
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    sev = [{"type": "CVSS_V3", "score": d["vectorString"]} for k in ("cvssMetricV31", "cvssMetricV30")
           for d in (x["cvssData"] for x in (cve.get("metrics") or {}).get(k, [])) if d.get("vectorString", "").startswith("CVSS:3")][:1]
    return [(key, {"id": cve["id"], "aliases": [], "modified": cve.get("lastModified", ""), "summary": desc[:500],
                   **({"severity": sev} if sev else {}),
                   "affected": [{"package": {"ecosystem": ECOSYSTEM, "name": key},
                                 "ranges": [{"type": "ECOSYSTEM", "events": ev} for ev in evs]}]})
            for key, evs in ranges.items() if evs]
