"""End of support: a curated, dated table (plan decision 5), not a live feed. A wrong date is a wrong security claim,
so every row names its Microsoft Lifecycle source and `CHECKED` records when the table was last reviewed;
tests/test_lifecycle.py fails while a date within 60 days of today hasn't been reviewed in the last 30.

Findings use ecosystem "Lifecycle" and vuln_id "EOL:<key>": one per unsupported product on a host.
"""

import re
from dataclasses import dataclass
from datetime import date

ECOSYSTEM = "Lifecycle"
CHECKED = date(2026, 10, 29)
WARN_DAYS = 90
LC = "https://learn.microsoft.com/lifecycle/products/"


@dataclass(frozen=True)
class Row:
    key: str  # stable id, part of the finding's vuln_id
    label: str
    end: date  # last day of security updates (the date Microsoft names)
    source: str
    esu_end: date | None = None  # last day ESU can extend it to (any ESU year)


ROWS = [Row(*r) for r in [
    # Windows 10: Home/Pro/Enterprise/Education 22H2 ended 2025-10-14; ESU (consumer one year, commercial up to three)
    ("win10-22h2", "Windows 10 22H2", date(2025, 10, 14), LC + "windows-10-home-and-pro", date(2028, 10, 10)),
    ("win10-21h2-ee", "Windows 10 21H2 Enterprise/Education", date(2024, 6, 11), LC + "windows-10-enterprise-and-education"),
    ("win10-ltsb-2016", "Windows 10 Enterprise LTSB 2016", date(2026, 10, 13), LC + "windows-10-2016-ltsb"),
    ("win10-ltsc-2019", "Windows 10 Enterprise LTSC 2019", date(2029, 1, 9), LC + "windows-10-enterprise-ltsc-2019"),
    ("win10-ltsc-2021", "Windows 10 Enterprise LTSC 2021", date(2027, 1, 12), LC + "windows-10-enterprise-ltsc-2021"),
    ("win10-iot-ltsc-2021", "Windows 10 IoT Enterprise LTSC 2021", date(2032, 1, 13), LC + "windows-10-iot-enterprise-ltsc-2021"),
    ("win11-21h2", "Windows 11 21H2", date(2024, 10, 8), LC + "windows-11-enterprise-and-education"),
    ("win11-22h2-hp", "Windows 11 22H2 Home/Pro", date(2024, 10, 8), LC + "windows-11-home-and-pro"),
    ("win11-22h2-ee", "Windows 11 22H2 Enterprise/Education", date(2025, 10, 14), LC + "windows-11-enterprise-and-education"),
    ("win11-23h2-hp", "Windows 11 23H2 Home/Pro", date(2025, 11, 11), LC + "windows-11-home-and-pro"),
    ("win11-23h2-ee", "Windows 11 23H2 Enterprise/Education", date(2026, 11, 10), LC + "windows-11-enterprise-and-education"),
    ("win11-24h2-hp", "Windows 11 24H2 Home/Pro", date(2026, 10, 13), LC + "windows-11-home-and-pro"),
    ("win11-24h2-ee", "Windows 11 24H2 Enterprise/Education", date(2027, 10, 12), LC + "windows-11-enterprise-and-education"),
    ("win11-25h2-hp", "Windows 11 25H2 Home/Pro", date(2027, 10, 12), LC + "windows-11-home-and-pro"),
    ("win11-25h2-ee", "Windows 11 25H2 Enterprise/Education", date(2028, 10, 10), LC + "windows-11-enterprise-and-education"),
    ("win11-ltsc-2024", "Windows 11 Enterprise LTSC 2024", date(2029, 10, 9), LC + "windows-11-enterprise-ltsc-2024"),
    ("win11-iot-ltsc-2024", "Windows 11 IoT Enterprise LTSC 2024", date(2034, 10, 10), LC + "windows-11-iot-enterprise-ltsc-2024"),
    ("ws2012", "Windows Server 2012", date(2023, 10, 10), LC + "windows-server-2012", date(2026, 10, 13)),
    ("ws2012r2", "Windows Server 2012 R2", date(2023, 10, 10), LC + "windows-server-2012-r2", date(2026, 10, 13)),
    ("ws2016", "Windows Server 2016", date(2027, 1, 12), LC + "windows-server-2016"),
    ("ws2019", "Windows Server 2019", date(2029, 1, 9), LC + "windows-server-2019"),
    ("ws2022", "Windows Server 2022", date(2031, 10, 14), LC + "windows-server-2022"),
    ("ws2025", "Windows Server 2025", date(2034, 10, 10), LC + "windows-server-2025"),
    ("ws-23h2", "Windows Server 23H2 (Annual Channel)", date(2025, 10, 24), LC + "windows-server-annual-channel"),
    # only seen in Active Directory (the agent doesn't run there): plan T43
    ("win7", "Windows 7", date(2020, 1, 14), LC + "windows-7", date(2023, 1, 10)),
    ("win81", "Windows 8.1", date(2023, 1, 10), LC + "windows-81"),
    ("ws2008", "Windows Server 2008 / 2008 R2", date(2020, 1, 14), LC + "windows-server-2008-r2", date(2023, 1, 10)),
    # Microsoft products beyond the OS (plan T28)
    ("dotnet-core-3.1", ".NET Core 3.1", date(2022, 12, 13), LC + "microsoft-net-and-net-core"),
    ("dotnet-5", ".NET 5", date(2022, 5, 10), LC + "microsoft-net-and-net-core"),
    ("dotnet-6", ".NET 6", date(2024, 11, 12), LC + "microsoft-net-and-net-core"),
    ("dotnet-7", ".NET 7", date(2024, 5, 14), LC + "microsoft-net-and-net-core"),
    ("dotnet-8", ".NET 8", date(2026, 11, 10), LC + "microsoft-net-and-net-core"),
    ("dotnet-9", ".NET 9", date(2026, 11, 10), LC + "microsoft-net-and-net-core"),
    ("dotnet-10", ".NET 10", date(2028, 11, 14), LC + "microsoft-net-and-net-core"),
    ("sql-2012", "SQL Server 2012", date(2022, 7, 12), LC + "sql-server-2012", date(2025, 7, 8)),
    ("sql-2014", "SQL Server 2014", date(2024, 7, 9), LC + "sql-server-2014", date(2027, 7, 13)),
    ("sql-2016", "SQL Server 2016", date(2026, 7, 14), LC + "sql-server-2016"),
    ("sql-2017", "SQL Server 2017", date(2027, 10, 12), LC + "sql-server-2017"),
    ("sql-2019", "SQL Server 2019", date(2030, 1, 8), LC + "sql-server-2019"),
    ("sql-2022", "SQL Server 2022", date(2033, 1, 11), LC + "sql-server-2022"),
    ("exchange-2016", "Exchange Server 2016", date(2025, 10, 14), LC + "exchange-server-2016"),
    ("exchange-2019", "Exchange Server 2019", date(2025, 10, 14), LC + "exchange-server-2019"),
    ("sharepoint-2016", "SharePoint Server 2016", date(2026, 7, 14), LC + "sharepoint-server-2016"),
    ("sharepoint-2019", "SharePoint Server 2019", date(2026, 7, 14), LC + "sharepoint-server-2019"),
    ("office-2016", "Office 2016", date(2025, 10, 14), LC + "office-2016"),
    ("office-2019", "Office 2019", date(2025, 10, 14), LC + "office-2019"),
    ("office-ltsc-2021", "Office LTSC 2021", date(2026, 10, 13), LC + "office-ltsc-2021"),
    ("office-ltsc-2024", "Office LTSC 2024", date(2029, 10, 9), LC + "office-ltsc-2024"),
]]
# third-party apps: the curated WinApp key -> (endoflife.date product, the release cycle from our normalised version)
# A branch-tracked product's CVEs count only on the branch that got the fix (winapps.Product.branch), so a dead branch stops
# gaining findings: this is what says so. Not oracle:openjdk: one key for several vendors' builds, whose dates differ.
_MAJOR, _MINOR = (lambda v: v.split(".")[0]), (lambda v: ".".join(v.split(".")[:2]))
APP_EOL = {"nodejs:node.js": ("nodejs", _MAJOR), "python:python": ("python", _MINOR), "oracle:jdk": ("oracle-jdk", _MAJOR),
           "mozilla:firefox_esr": ("firefox", _MAJOR), "mozilla:thunderbird": ("thunderbird", _MAJOR),
           "libreoffice:libreoffice": ("libreoffice", _MINOR), "apache:tomcat": ("tomcat", _MINOR), "golang:go": ("go", _MINOR),
           "postgresql:postgresql": ("postgresql", _MAJOR), "mariadb:mariadb": ("mariadb", _MINOR), "grafana:grafana": ("grafana", _MINOR),
           "oracle:mysql_server": ("mysql", _MINOR), "mongodb:mongodb": ("mongodb", _MINOR), "elastic:elasticsearch": ("elasticsearch", _MINOR),
           "perl:perl": ("perl", _MINOR), "ruby-lang:ruby": ("ruby", _MINOR), "openssl:openssl": ("openssl", _MINOR), "clamav:clamav": ("clamav", _MINOR),
           "atlassian:confluence_data_center": ("confluence", _MINOR)}
EOL_URL = "https://endoflife.date/api/{}.json"
THUNDERBIRD_URL = "https://product-details.mozilla.org/1.0/thunderbird_versions.json"  # endoflife.date has no Thunderbird
BY_KEY = {r.key: r for r in ROWS}

HOME_PRO = re.compile(r"^(Core|CoreN|CoreSingleLanguage|CoreCountrySpecific|Professional|ProfessionalN|ProfessionalWorkstation|"
                      r"ProfessionalWorkstationN|ProfessionalEducation|ProfessionalEducationN)$")
ENT_EDU = re.compile(r"^(Enterprise|EnterpriseN|Education|EducationN|IoTEnterprise|ServerRdsh|EnterpriseG)$")


def windows_row(product: str, edition: str) -> Row | None:
    """The lifecycle row for an MSRC product name + the registry EditionID, or None if we can't say exactly."""
    m = re.match(r"Windows (10|11)(?: Version (\w+))? for ", product)
    if m:
        os_, ver = m.group(1), (m.group(2) or "1507").lower()
        if edition in ("EnterpriseS", "EnterpriseSN", "IoTEnterpriseS"):  # LTSC/LTSB: fixed by version
            iot = edition == "IoTEnterpriseS"
            key = {("10", "1607"): "win10-ltsb-2016", ("10", "1809"): "win10-ltsc-2019",
                   ("10", "21h2"): "win10-iot-ltsc-2021" if iot else "win10-ltsc-2021",
                   ("11", "24h2"): "win11-iot-ltsc-2024" if iot else "win11-ltsc-2024"}.get((os_, ver))
            return BY_KEY.get(key) if key else None
        if os_ == "10":
            if ver == "22h2":
                return BY_KEY["win10-22h2"]
            if ver == "21h2" and ENT_EDU.match(edition):
                return BY_KEY["win10-21h2-ee"]
            return None  # older Windows 10 versions: their own CVEs say enough; no edition table kept
        family = "hp" if HOME_PRO.match(edition) else "ee" if ENT_EDU.match(edition) else None
        if ver == "21h2":
            return BY_KEY["win11-21h2"]
        return BY_KEY.get(f"win11-{ver}-{family}") if family else None
    if product.startswith("Windows Server 2022, 23H2 Edition"):  # before "Windows Server 2022": same prefix
        return BY_KEY["ws-23h2"]
    m = re.match(r"Windows Server (2012 R2|2012|2016|2019|2022|2025)\b", product)
    if m:
        return BY_KEY["ws" + m.group(1).replace(" ", "").lower()]
    return None


WIN10_BUILDS = {"19045": "22H2", "19044": "21H2", "17763": "1809", "14393": "1607"}
WIN11_BUILDS = {"22631": "23H2", "26100": "24H2", "26200": "25H2"}


def directory_row(os_name: str, os_version: str) -> Row | None:
    """Lifecycle row from Active Directory's operatingSystem / operatingSystemVersion ("10.0 (19045)"), or None."""
    m = re.search(r"\((\d+)\)", os_version or "")
    build = m[1] if m else ""
    for prefix, key in (("Windows 7", "win7"), ("Windows 8.1", "win81"), ("Windows Server 2008", "ws2008")):
        if os_name.startswith(prefix):
            return BY_KEY[key]
    if (m := re.match(r"Windows Server (2012 R2|2012|2016|2019|2022|2025)\b", os_name)):
        return BY_KEY["ws" + m[1].replace(" ", "").lower()]
    edition = "Enterprise" if "Enterprise" in os_name or "Education" in os_name else "Professional"
    if os_name.startswith("Windows 10") and (v := WIN10_BUILDS.get(build)):
        return windows_row(f"Windows 10 Version {v} for x64-based Systems", "EnterpriseS" if "LTSC" in os_name else edition)
    if os_name.startswith("Windows 11") and (v := WIN11_BUILDS.get(build)):
        return windows_row(f"Windows 11 Version {v} for x64-based Systems", "EnterpriseS" if "LTSC" in os_name else edition)
    return None


def verdict(row: Row, esu: bool | None, today: date) -> tuple[str, str] | None:
    """(severity, text) for a host on `row`, or None while it is supported and not ending soon."""
    if esu and row.esu_end and today <= row.esu_end:
        return None if (row.esu_end - today).days > WARN_DAYS else (
            "ending", f"{row.label}: Extended Security Updates end on {row.esu_end:%Y-%m-%d}")
    if today > row.end:
        return "ended", f"{row.label}: no security updates since {row.end:%Y-%m-%d}" + (
            " (Extended Security Updates available)" if row.esu_end and today <= row.esu_end else "")
    if (row.end - today).days <= WARN_DAYS:
        return "ending", f"{row.label}: security updates end on {row.end:%Y-%m-%d}"
    return None


def microsoft_row(p) -> Row | None:
    """Lifecycle row for an agent-reported Microsoft fact or a Microsoft Uninstall entry (msproducts.py's inputs)."""
    v = p.version or ""
    parts = v.split(".")
    if p.ecosystem == "Microsoft" and p.name in (".NET runtime", "ASP.NET Core") and len(parts) >= 2 and parts[0].isdigit():
        return BY_KEY.get(f"dotnet-{parts[0]}" if int(parts[0]) >= 5 else f"dotnet-core-{parts[0]}.{parts[1]}")
    if p.ecosystem == "Microsoft" and p.name == "SQL Server":
        return BY_KEY.get("sql-" + {"11": "2012", "12": "2014", "13": "2016", "14": "2017", "15": "2019", "16": "2022"}.get(parts[0], "?"))
    if p.ecosystem == "Microsoft" and p.name == "Exchange Server" and len(parts) >= 3 and parts[2].isdigit():
        return BY_KEY["exchange-2016"] if parts[:2] == ["15", "1"] else BY_KEY["exchange-2019"] if parts[:2] == ["15", "2"] and int(parts[2]) < 2562 else None
    if p.ecosystem == "Microsoft" and p.name == "SharePoint Server" and len(parts) >= 3 and parts[2].isdigit():
        return BY_KEY["sharepoint-2016"] if int(parts[2]) < 10000 else BY_KEY["sharepoint-2019"] if int(parts[2]) < 14000 else None
    if p.ecosystem == "Microsoft" and p.name == "Microsoft 365 Apps":
        ch = (p.source or "").rstrip("/").rsplit("/", 1)[-1].lower()
        return BY_KEY.get({"f2e724c1-748f-4b47-8fb8-8e0d210e9208": "office-2019", "5030841d-c919-4594-8d2d-84ae4f96e58e": "office-ltsc-2021",
                           "7983bac0-e531-40cf-be00-fd24fe66619c": "office-ltsc-2024"}.get(ch, "?"))
    if p.ecosystem == "WinApp" and (p.source or "") == "Microsoft Corporation" and (m := re.fullmatch(r"Microsoft Office .*\b(2016|2019)\b.*", p.name)):
        return BY_KEY[f"office-{m[1]}"]  # Office 2016/2019 installed from MSI
    return None


def app_verdict(key: str, version: str, eol: dict, today: date) -> tuple[str, str] | None:
    """A curated third-party app on a release cycle endoflife.date says has ended: (severity, text)."""
    product, cycle_of = APP_EOL.get(key, (None, None))
    if not product or not (cycles := eol.get(product)):
        return None
    cycle = cycle_of(version)
    if cycle not in cycles:  # endoflife.date lists some old branches by major alone (Elasticsearch 6, Grafana 6)
        cycle = version.split(".")[0]
    end = cycles.get(cycle)
    if end is True or (isinstance(end, str) and date.fromisoformat(end) < today):
        return "ended", f"{product} {cycle}: no more security fixes" + (f" since {end}" if isinstance(end, str) else "")
    return None


def parse_thunderbird(versions: dict) -> dict:
    """Mozilla patches only the newest release and the newest ESR, so every other major below the release has ended."""
    latest, esr = (int(str(versions[k]).split(".")[0]) for k in ("LATEST_THUNDERBIRD_VERSION", "THUNDERBIRD_ESR"))
    if not 1 < esr <= latest:
        raise ValueError(f"Thunderbird versions: unexpected {latest}, {esr}")
    return {str(m): True for m in range(1, latest) if m != esr}


def parse_eol(cycles) -> dict:
    """endoflife.date's cycles -> {cycle: ISO date | True | False}; ValueError on an unexpected shape."""
    if not isinstance(cycles, list) or not cycles:
        raise ValueError("endoflife.date: expected a non-empty list of cycles")
    out = {}
    for c in cycles:
        eol = c.get("eol") if isinstance(c, dict) else None
        if not isinstance(c.get("cycle"), str) or not (isinstance(eol, bool) or (isinstance(eol, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", eol))):
            raise ValueError(f"endoflife.date: unexpected cycle {str(c)[:200]}")
        out[c["cycle"]] = eol
    return out


def findings(packages: list, facts: dict, today: date, eol: dict | None = None) -> list[dict]:
    """Lifecycle findings for one host: [{package, version, vuln_id, summary, ended}]. `eol`: endoflife.date cycles
    by product for curated third-party apps (feeds.sync_eol)."""
    out = []
    products = [(p.name, p.version) for p in packages if p.ecosystem == "Windows"]
    if facts.get("os_product"):  # an OS named but not CVE-matchable (Server 2012/R2)
        products.append((str(facts["os_product"]), ""))
    seen = set()

    def add(row, version, v):
        if row.key not in seen:
            seen.add(row.key)
            out.append({"package": row.label, "version": version, "vuln_id": f"EOL:{row.key}", "summary": v[1],
                        "ended": v[0] == "ended", "source": row.source})
    for name, version in products:
        row = windows_row(name, str(facts.get("edition_id") or ""))
        if row and (v := verdict(row, facts.get("esu"), today)):
            add(row, version, v)
    for p in packages:
        if (row := microsoft_row(p)) and (v := verdict(row, None, today)):
            add(row, p.version, v)
        if p.ecosystem == "WinApp" and eol:
            from nimstead.winapps import identify
            if (hit := identify(p.name, p.source, p.version)) and (v := app_verdict(hit[0], hit[1], eol, today)):
                key = f"app-{hit[0]}-{APP_EOL[hit[0]][1](hit[1])}"
                if key not in seen:
                    seen.add(key)
                    out.append({"package": hit[0], "version": hit[1], "vuln_id": f"EOL:{key}", "summary": v[1], "ended": True,
                                "source": "https://endoflife.date/" + APP_EOL[hit[0]][0]})
    return out
