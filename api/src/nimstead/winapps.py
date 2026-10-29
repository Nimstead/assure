"""Third-party Windows apps: a small curated map from what the registry says is installed to an exact NVD CPE,
and the translation of NVD CPE match data for those CPEs into OSV-shaped advisories (ecosystem `WinApp`).

No fuzzy matching (DECISIONS 4, 22): an installed app is matched only if its DisplayName (and, where the name is
generic, its Publisher) fully matches a pattern below. Everything else is inventory and is never compared.
Products whose registry version can't be mapped exactly to NVD's convention are left out on purpose:
- Oracle Java 8: registry "8.0.4310.10" vs NVD "1.8.0 update431".
- Eclipse Temurin: no CPE exists (its CVEs are filed under oracle:jdk/openjdk); equating them would be a guess.
Microsoft's own apps (Edge, VS Code, PowerShell, Visual Studio) are matched from MSRC instead: msproducts.py.
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


# ---- CVE List v5 (CNA and CISA ADP "Vulnrichment" data): second source when NVD has no configuration (plan T30) ---
# CNA vendor/product names -> curated key, exact (case-insensitive). CPEs in `affected[].cpes` go through _BY_CPE.
CNA_NAMES = {("google", "chrome"): "google:chrome", ("mozilla", "firefox"): "mozilla:firefox",
             ("mozilla", "firefox esr"): "mozilla:firefox_esr", ("7-zip", "7-zip"): "7-zip:7-zip",
             ("videolan", "vlc media player"): "videolan:vlc_media_player", ("wireshark", "wireshark"): "wireshark:wireshark",
             ("zoom communications, inc", "zoom workplace"): "zoom:workplace_desktop", ("rarlab", "winrar"): "rarlab:winrar",
             ("python software foundation", "cpython"): "python:python", ("nodejs", "node"): "nodejs:node.js",
             ("git", "git"): "git-scm:git", ("adobe", "acrobat reader"): "adobe:acrobat_reader"}
_PLATFORM_OK = re.compile(r"(?i)windows|all|x64|x86|arm64")


def _v5_events(p: Product, v: dict) -> list[dict] | None:
    """OSV events for one CVE v5 `versions` entry, or None when it can't be stated exactly."""
    if v.get("status") != "affected" or v.get("versionType") not in (None, "custom", "semver", "dotted"):
        return None
    lo, lt, le = str(v.get("version", "")), v.get("lessThan"), v.get("lessThanOrEqual")
    lo = "0" if lo in ("0", "*", "") else lo
    if lt or le:
        hi = str(lt or le)
        if hi == "*" or not _version_ok(hi) or (lo != "0" and not _version_ok(lo)):
            return None
        if lo != "0" and appver_parts(lo) >= appver_parts(hi):  # Google's CNA writes version == lessThan for "below X"
            lo = "0"
        if p.branch and lo == "0":
            lo = f"{appver_parts(hi)[0]}.0"
        return [{"introduced": lo}, {"fixed": hi} if lt else {"last_affected": hi}]
    return [{"introduced": lo}, {"last_affected": lo}] if lo != "0" and _version_ok(lo) else None


def advisories_v5(rec: dict) -> list[tuple[str, dict]]:
    """[(product key, OSV-shaped record)] from a CVE JSON 5 record's CNA and ADP `affected` entries for curated products.
    Record ids are "<CVE>-v5" (the CVE is the alias), so NVD's rows for the same CVE replace them (feeds.sync_winapps)."""
    meta = rec.get("cveMetadata") or {}
    if meta.get("state") != "PUBLISHED":
        return []
    cve, conts = meta["cveId"], rec.get("containers") or {}
    ranges: dict[str, list[list[dict]]] = {}
    for c in [conts.get("cna") or {}, *(conts.get("adp") or [])]:
        for a in c.get("affected") or []:
            if a.get("platforms") and not any(_PLATFORM_OK.search(str(x)) for x in a["platforms"]):
                continue
            keys = {_BY_CPE[f[3] + ":" + f[4]].key for cpe in a.get("cpes") or [] if (f := _fields(cpe))[2:3] == ["a"]
                    and len(f) > 4 and f[3] + ":" + f[4] in _BY_CPE}
            if k := CNA_NAMES.get((str(a.get("vendor", "")).lower(), str(a.get("product", "")).lower())):
                keys.add(k)
            for key in keys:
                p = next(x for x in PRODUCTS if x.key == key)
                for v in a.get("versions") or []:
                    if (ev := _v5_events(p, v)) and ev not in ranges.setdefault(key, []):
                        ranges[key].append(ev)
    desc = next((d["value"] for d in (conts.get("cna") or {}).get("descriptions", []) if d.get("lang", "").startswith("en")), "")
    sev = [{"type": "CVSS_V3", "score": m[k]["vectorString"]} for c in [conts.get("cna") or {}, *(conts.get("adp") or [])]
           for m in c.get("metrics") or [] for k in ("cvssV3_1", "cvssV3_0") if k in m][:1]
    return [(key, {"id": f"{cve}-v5", "aliases": [cve], "modified": meta.get("dateUpdated", ""), "summary": desc[:500],
                   **({"severity": sev} if sev else {}),
                   "affected": [{"package": {"ecosystem": ECOSYSTEM, "name": key},
                                 "ranges": [{"type": "ECOSYSTEM", "events": ev} for ev in evs]}]})
            for key, evs in ranges.items() if evs]


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
