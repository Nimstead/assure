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
]]
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


def findings(packages: list, facts: dict, today: date) -> list[dict]:
    """Lifecycle findings for one host: [{package, version, vuln_id, summary, ended}]."""
    out = []
    products = [(p.name, p.version) for p in packages if p.ecosystem == "Windows"]
    if facts.get("os_product"):  # an OS named but not CVE-matchable (Server 2012/R2)
        products.append((str(facts["os_product"]), ""))
    for name, version in products:
        row = windows_row(name, str(facts.get("edition_id") or ""))
        if row and (v := verdict(row, facts.get("esu"), today)):
            out.append({"package": name, "version": version, "vuln_id": f"EOL:{row.key}", "summary": v[1],
                        "ended": v[0] == "ended", "source": row.source})
    return out
