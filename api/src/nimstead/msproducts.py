"""Microsoft products beyond Windows itself, matched against MSRC's own fixed builds (plan T5–T8, T19, T20, T29;
DECISIONS 51, 53). An explicit allowlist on both sides, never a pattern that admits whatever MSRC adds:

- feed side, `key_for`: an MSRC product name (+ one fixed build) -> a stable product key, or None;
- host side, `targets`: what the agent reports -> the product keys to compare with, or [].

The agent reports raw facts (ecosystem `Microsoft`: ".NET runtime", ".NET SDK", ".NET Framework", "ASP.NET Core", "SQL Server", "Exchange Server",
"SharePoint Server", "Defender platform", "Defender engine", or a Store package family), and Uninstall-key entries
arrive as `WinApp` packages; the mapping to keys lives only here, so the server decides what is compared.
Tracks MSRC lists side by side (SQL Server GDR / CU, each Exchange cumulative update) become separate keys derived
from the build itself on both sides, so a host is compared only with the fixes for its own track.
"""

import re

ECOSYSTEM = "Microsoft"
SQL_YEAR = {"13": "2016", "14": "2017", "15": "2019", "16": "2022", "17": "2025"}
SQL_CU_FROM = {"13": 7000, "14": 3000, "15": 4000, "16": 4000, "17": 4000}  # third part at/above = CU track, below = GDR
# Store package family -> MSRC product label. Labels MSRC also publishes per OS ("... on Windows 11 Version 26H2 for
# x64-based Systems") are tried with the host's own OS product first.
STORE = {"Microsoft.Paint": "Microsoft Paint", "Microsoft.SecHealthUI": "Windows Security App",
         "Microsoft.HEVCVideoExtension": "HEVC Video Extensions", "Microsoft.MPEG2VideoExtension": "MPEG-2 Video Extension",
         "Microsoft.RawImageExtension": "Raw Image Extension", "Microsoft.GamingServices": "Xbox Gaming Services"}
STORE_PACKAGES = tuple(STORE)  # the agent queries exactly these (it holds its own copy; tests keep them equal)


def norm(v: str) -> str | None:
    """'15.02.1748.053' -> '15.2.1748.53', 'v4.04' -> '4.4', '30.104.13001.0.' -> '30.104.13001.0'; non-numeric -> None."""
    v = (v or "").strip().removeprefix("v").rstrip(".")
    return ".".join(str(int(x)) for x in v.split(".")) if re.fullmatch(r"\d+(\.\d+)+", v) else None


def _sql(build: str) -> str | None:
    p = build.split(".")
    return f"SQL Server {SQL_YEAR[p[0]]} {'CU' if int(p[2]) >= SQL_CU_FROM[p[0]] else 'GDR'}" if p[0] in SQL_YEAR and len(p) >= 3 else None


def _sharepoint(build: str) -> str | None:
    p = [int(x) for x in build.split(".")]
    if p[:2] != [16, 0] or len(p) < 3:
        return None
    return "SharePoint Server 2016" if p[2] < 10000 else "SharePoint Server 2019" if p[2] < 14000 else "SharePoint Server Subscription Edition"


def _minor(prefix: str, v: str, parts: int = 2) -> str:
    return f"{prefix} {'.'.join(v.split('.')[:parts])}"


def _netfx_line(release: str | None) -> str | None:
    """The line MSRC lists a host under, from the registry's Release number (Microsoft's published minimums)."""
    r = int(release) if release and release.isdigit() else 0
    return "4.8.1" if r >= 533320 else "4.8" if r >= 528040 else "4.7" if r >= 394802 else None


def _netfx_os(os_product: str | None) -> str | None:
    """'Windows 11 Version 26H2 for x64-based Systems' -> 'Windows 11 version 26H2', as MSRC names its .NET Framework products."""
    if m := re.match(r"(Windows 1[01]) Version (\w+)", os_product or ""):
        return f"{m[1]} version {m[2]}"
    return m[0] if (m := re.match(r"Windows Server \d{4}", os_product or "")) else None


def _sdk(v: str) -> str | None:
    """'8.0.426' -> '.NET 8.0 SDK 4xx': each feature band gets its own fixes. A third part below 100 is a runtime."""
    band = int(v.split(".")[2]) // 100
    return f"{_minor('.NET', v)} SDK {band}xx" if band else None


FEED = [  # (MSRC product name, key from (match, normalised build)); fullmatch, first wins
    (r"Microsoft Edge \(Chromium-based\)", lambda m, b: "Microsoft Edge"),
    (r"\.NET (\d+\.\d+) runtime installed on Windows", lambda m, b: _sdk(b) or f".NET {m[1]} runtime"),
    (r"\.NET \d+\.\d+ installed on Windows", lambda m, b: _sdk(b)),  # MSRC files SDK fixes under both names
    (r"Microsoft \.NET Framework (?:3\.5 AND )?(4\.[\d./]+) on (Windows .+)",
     lambda m, b: f".NET Framework {m[1] if m[1] in ('4.8', '4.8.1') else '4.7'} on {m[2]}"),  # 4.6.2/4.7/4.7.1/4.7.2 share a fix
    (r"ASP\.NET Core (\d+\.\d+)", lambda m, b: f"ASP.NET Core {m[1]}"),  # MSRC doesn't split ASP.NET Core by OS
    (r"Microsoft SQL Server (20\d\d) for x64-based Systems .*\((?:GDR|CU ?\d+)\)", lambda m, b: _sql(b)),
    (r"Microsoft Exchange Server (?:2016|2019) Cumulative Update \d+|Microsoft Exchange Server Subscription Edition RTM",
     lambda m, b: _minor("Exchange Server", b, 3)),
    (r"Microsoft SharePoint (?:Enterprise Server 2016|Server 2019|Server Subscription Edition)", lambda m, b: _sharepoint(b)),
    (r"Microsoft Defender for Endpoint for Windows", lambda m, b: "Defender platform"),
    (r"Windows Defender", lambda m, b: "Defender engine"),
    (r"PowerShell (7\.\d+)", lambda m, b: f"PowerShell {m[1]}"),
    (r"Microsoft Visual Studio (20(?:19|22|26)) version (\d+\.\d+)", lambda m, b: f"Visual Studio {m[1]} version {m[2]}"),
    (r"Visual Studio Code", lambda m, b: "Visual Studio Code"),
    (r"Azure Connected Machine Agent", lambda m, b: "Azure Connected Machine Agent"),
    (r"Microsoft PowerToys", lambda m, b: "Microsoft PowerToys"),
    (rf"({'|'.join(map(re.escape, STORE.values()))})(?: on (Windows .+))?",
     lambda m, b: m[1] + (" on " + re.sub(r"^(Windows 11) version", r"\1 Version", m[2]) if m[2] else "")),
]
_FEED = [(re.compile(p), f) for p, f in FEED]


def key_for(msrc_name: str, fixed: str) -> tuple[str, str] | None:
    """(key, normalised fixed build) for an allowlisted MSRC product, or None."""
    b = norm(fixed)
    if not b:
        return None
    for pat, f in _FEED:
        if m := pat.fullmatch(msrc_name):
            k = f(m, b)
            return (k, b) if k else None
    return None


VS_YEAR = {"16": "2019", "17": "2022", "18": "2026"}
UNINSTALL = [  # (DisplayName, Publisher, (match, version) -> key); fullmatch on both
    (r"Microsoft Edge", r"Microsoft Corporation", lambda m, v: "Microsoft Edge"),  # not "Microsoft Edge WebView2 Runtime"
    (r"Microsoft Visual Studio Code(?: \((?:User|System)\))?", r"Microsoft Corporation", lambda m, v: "Visual Studio Code"),
    (r"PowerShell 7(?:\.\d+)?-(?:x64|x86|arm64)", r"Microsoft Corporation", lambda m, v: _minor("PowerShell", v)),
    (r"Visual Studio (?:Community|Professional|Enterprise|Build Tools) (2019|2022|2026)", r"Microsoft Corporation",
     lambda m, v: f"Visual Studio {m[1]} version {'.'.join(v.split('.')[:2])}" if VS_YEAR.get(v.split(".")[0]) == m[1] else None),
    (r"Azure Connected Machine Agent", r"Microsoft Corporation", lambda m, v: "Azure Connected Machine Agent"),
    (r"PowerToys(?: \(Preview\))?(?: (?:x64|arm64))?", r"Microsoft Corporation", lambda m, v: "Microsoft PowerToys"),
]
_UNINSTALL = [(re.compile(n), re.compile(p), f) for n, p, f in UNINSTALL]


def from_winapp(name: str, publisher: str | None, version: str) -> tuple[str, str] | None:
    """An Uninstall-key entry that is an allowlisted Microsoft product: (key, normalised version)."""
    v = norm(version)
    if not v:
        return None
    for n, p, f in _UNINSTALL:
        if (m := n.fullmatch(name)) and p.fullmatch(publisher or ""):
            k = f(m, v)
            return (k, v) if k else None
    return None


def targets(name: str, version: str, os_product: str | None, source: str | None = None) -> tuple[tuple[str, ...], str] | None:
    """An agent-reported Microsoft fact -> (candidate keys, first with advisories wins; normalised version)."""
    v = norm(version)
    if not v:
        return None
    if name == "Microsoft 365 Apps":  # Click-to-Run: its channel (source) and version line (office.py)
        from nimstead.office import host_key
        return ((k,), v) if (k := host_key(v, source or "")) else None
    if name == ".NET runtime":
        return (_minor(".NET", v) + " runtime",), v
    if name == ".NET Framework":
        line, on = _netfx_line(source), _netfx_os(os_product)
        return ((f".NET Framework {line} on {on}",), v) if line and on else None
    if name == ".NET SDK":
        return ((k,), v) if (k := _sdk(v)) else None
    if name == "ASP.NET Core":
        return (_minor("ASP.NET Core", v),), v
    if name == "SQL Server":
        return ((k,), v) if (k := _sql(v)) else None
    if name == "Exchange Server":
        return (_minor("Exchange Server", v, 3),), v
    if name == "SharePoint Server":
        return ((k,), v) if (k := _sharepoint(v)) else None
    if name in ("Defender platform", "Defender engine"):
        return (name,), v
    if label := STORE.get(name):
        return ((f"{label} on {os_product}",) if os_product else ()) + (label,), v
    return None
