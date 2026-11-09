"""End-of-support findings (plan T3): the curated table, its review rule, and findings end to end."""

from datetime import date

import pytest
from test_api import user

from nimstead import lifecycle
from nimstead.lifecycle import BY_KEY, CHECKED, ROWS, verdict, windows_row

W10 = "Windows 10 Version 22H2 for x64-based Systems"


def test_every_row_has_a_source_and_dates_in_order():
    assert len({r.key for r in ROWS}) == len(ROWS)
    for r in ROWS:
        assert r.source.startswith("https://learn.microsoft.com/lifecycle/")
        assert r.esu_end is None or r.esu_end > r.end


def test_dates_coming_up_have_been_reviewed_recently():
    # fails while any end date within 60 days of today was last reviewed more than 30 days ago: re-check the table
    # against Microsoft Lifecycle, then move CHECKED
    today = date.today()
    soon = [r.key for r in ROWS for d in (r.end, r.esu_end) if d and 0 <= (d - today).days <= 60]
    assert not soon or (today - CHECKED).days <= 30, f"review lifecycle dates for {soon}"


@pytest.mark.parametrize("product,edition,key", [
    (W10, "Professional", "win10-22h2"),
    ("Windows 10 Version 21H2 for x64-based Systems", "EnterpriseS", "win10-ltsc-2021"),
    ("Windows 10 Version 21H2 for x64-based Systems", "IoTEnterpriseS", "win10-iot-ltsc-2021"),
    ("Windows 10 Version 21H2 for x64-based Systems", "Enterprise", "win10-21h2-ee"),
    ("Windows 10 Version 21H2 for x64-based Systems", "Professional", None),
    ("Windows 10 Version 1809 for x64-based Systems", "EnterpriseS", "win10-ltsc-2019"),
    ("Windows 11 Version 23H2 for x64-based Systems", "Core", "win11-23h2-hp"),
    ("Windows 11 Version 23H2 for ARM64-based Systems", "Enterprise", "win11-23h2-ee"),
    ("Windows 11 Version 24H2 for x64-based Systems", "EnterpriseS", "win11-ltsc-2024"),
    ("Windows 11 Version 24H2 for x64-based Systems", "", None),  # edition unknown: never guessed
    ("Windows 11 Version 26H2 for x64-based Systems", "Professional", None),  # no row yet
    ("Windows Server 2016 (Server Core installation)", "ServerStandard", "ws2016"),
    ("Windows Server 2012 R2", "ServerDatacenter", "ws2012r2"),
    ("Windows Server 2022, 23H2 Edition (Server Core installation)", "ServerDatacenterACor", "ws-23h2"),
])
def test_windows_row(product, edition, key):
    row = windows_row(product, edition)
    assert (row.key if row else None) == key


def test_verdicts():
    w10 = BY_KEY["win10-22h2"]
    assert verdict(w10, False, date(2026, 10, 29)) == ("ended", "Windows 10 22H2: no security updates since 2025-10-14 (Extended Security Updates available)")
    assert verdict(w10, True, date(2026, 10, 29)) is None
    assert verdict(w10, True, date(2028, 8, 1))[0] == "ending"
    assert verdict(w10, True, date(2028, 10, 11))[0] == "ended"
    assert verdict(BY_KEY["ws2016"], None, date(2026, 11, 1)) == ("ending", "Windows Server 2016: security updates end on 2027-01-12")
    assert verdict(BY_KEY["ws2025"], None, date(2026, 11, 1)) is None


def test_lifecycle_finding_opens_and_closes_with_esu(env):
    c = user(env)
    token = c.post("/api/enroll-tokens").json()["token"]
    a = c.post("/api/agent/enroll", json={"token": token, "hostname": "pc-10", "ecosystem": "Windows"}).json()
    h = {"Authorization": f"Bearer {a['agent_key']}"}

    def inv(facts):
        return c.post("/api/agent/inventory", headers=h, json={"ecosystem": "Windows", "facts": facts, "packages": [
            {"ecosystem": "Windows", "name": W10, "version": "10.0.19045.6456", "source": None}]})

    assert inv({"edition_id": "Professional", "esu": False}).status_code == 200
    [f] = c.get("/api/findings").json()
    assert f["vuln_id"] == "EOL:win10-22h2" and f["ecosystem"] == lifecycle.ECOSYSTEM and f["priority"] == "fix-now"
    assert "no security updates since 2025-10-14" in f["summary"]
    assert [x["vuln_id"] for x in c.get("/api/findings", params={"fixable": True}).json()] == ["EOL:win10-22h2"]  # the default view
    inv({"edition_id": "Professional", "esu": True})
    assert not c.get("/api/findings").json()
    assert c.get("/api/findings", params={"status": "resolved"}).json()[0]["vuln_id"] == "EOL:win10-22h2"


def test_facts_are_bounded(env):
    c = user(env)
    token = c.post("/api/enroll-tokens").json()["token"]
    a = c.post("/api/agent/enroll", json={"token": token, "hostname": "pc-11", "ecosystem": "Windows"}).json()
    h = {"Authorization": f"Bearer {a['agent_key']}"}
    body = {"ecosystem": "Windows", "packages": [{"ecosystem": "Windows", "name": W10, "version": "10.0.19045.1", "source": None}]}
    for bad in ({"x": "y" * 501}, {"a": {"b": {"c": {"d": {"e": 1}}}}}):  # dropped; the packages still count
        assert c.post("/api/agent/inventory", headers=h, json={**body, "facts": bad}).status_code == 200
        assert c.get("/api/assets").json()[0]["facts"] == {}


# ---- beyond the OS (plan T28)

class P:
    def __init__(self, ecosystem, name, version, source=None):
        self.ecosystem, self.name, self.version, self.source = ecosystem, name, version, source


@pytest.mark.parametrize("pkg,key", [
    (P("Microsoft", ".NET runtime", "6.0.36"), "dotnet-6"),
    (P("Microsoft", "ASP.NET Core", "3.1.32"), "dotnet-core-3.1"),
    (P("Microsoft", "SQL Server", "12.0.6449.1"), "sql-2014"),
    (P("Microsoft", "Exchange Server", "15.2.1748.50"), "exchange-2019"),
    (P("Microsoft", "Exchange Server", "15.2.2562.50"), None),  # Subscription Edition
    (P("Microsoft", "SharePoint Server", "16.0.5561.1000"), "sharepoint-2016"),
    (P("Microsoft", "Microsoft 365 Apps", "16.0.14334.20974", "http://officecdn.microsoft.com/pr/5030841d-c919-4594-8d2d-84ae4f96e58e"), "office-ltsc-2021"),
    (P("Microsoft", "Microsoft 365 Apps", "16.0.20430.20180", "http://officecdn.microsoft.com/pr/55336b82-a18d-4dd6-b5f6-9e5095c314a6"), None),
    (P("WinApp", "Microsoft Office Professional Plus 2016", "16.0.4266.1001", "Microsoft Corporation"), "office-2016"),
    (P("WinApp", "Microsoft Office Professional Plus 2016", "16.0.4266.1001", "Contoso"), None),
])
def test_microsoft_row(pkg, key):
    row = lifecycle.microsoft_row(pkg)
    assert (row.key if row else None) == key


def test_findings_beyond_the_os():
    pkgs = [P("Microsoft", ".NET runtime", "6.0.36"), P("Microsoft", ".NET runtime", "6.0.36"),  # one finding per product
            P("Microsoft", ".NET runtime", "10.0.14"), P("WinApp", "Node.js", "18.20.4", "OpenJS Foundation")]
    eol = {"nodejs": lifecycle.parse_eol([{"cycle": "18", "eol": "2025-04-30"}, {"cycle": "24", "eol": "2028-04-30"}])}
    got = {(x["vuln_id"], x["ended"]) for x in lifecycle.findings(pkgs, {}, date(2026, 10, 29), eol)}
    assert got == {("EOL:dotnet-6", True), ("EOL:app-nodejs:node.js-18", True)}
    assert lifecycle.findings(pkgs, {}, date(2026, 10, 29), {}) and len(lifecycle.findings(pkgs, {}, date(2026, 10, 29), None)) == 1


@pytest.mark.parametrize("bad", [[], [{"cycle": 18, "eol": "2025-04-30"}], [{"cycle": "18", "eol": "soon"}], {"cycle": "18"}])
def test_parse_eol_refuses_unexpected_shapes(bad):
    with pytest.raises(ValueError):
        lifecycle.parse_eol(bad)


def test_sync_eol_keeps_stored_cycles_on_failure(env):
    import httpx

    from nimstead.db import Advisory, make_sessionmaker
    from nimstead.feeds import sync_eol
    good = [{"cycle": "18", "eol": "2025-04-30"}]
    s = make_sessionmaker(env)()
    sync_eol(s, httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json=good))))
    assert s.get(Advisory, ("EOL-nodejs", "EOL", "nodejs")).record["cycles"] == {"18": "2025-04-30"}
    out = sync_eol(s, httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json=[{"cycle": "x"}]))))
    assert "error" in out["nodejs"] and s.get(Advisory, ("EOL-nodejs", "EOL", "nodejs")).record["cycles"] == {"18": "2025-04-30"}


@pytest.mark.parametrize("eco,want", [("Debian:13", ("debian", "13")), ("Ubuntu:22.04:LTS", ("ubuntu", "22.04")), ("Alpine:v3.21", ("alpine-linux", "3.21")),
                                      ("AlmaLinux:9", ("almalinux", "9")), ("Rocky Linux:8", ("rocky-linux", "8")), ("openSUSE:Leap 15.6", ("opensuse", "15.6")),
                                      ("SUSE:Linux Enterprise Server 15 SP6", ("sles", "15.6")), ("openSUSE:Tumbleweed", None), ("Debian", None), ("PyPI", None)])
def test_a_linux_release_maps_to_its_end_of_support_cycle(eco, want):
    assert lifecycle.distro_cycle(eco) == want


def test_an_impossible_end_date_is_refused_when_parsed():
    """The feed run keeps the stored cycles on ValueError, so app_verdict never meets a date it can't read."""
    for bad in ([{"cycle": "x", "eol": "2026-99-99"}], [{"cycle": "x", "eol": "2026-02-30"}], [None]):
        with pytest.raises(ValueError):
            lifecycle.parse_eol(bad)
    assert lifecycle.parse_eol([{"cycle": "x", "eol": "2024-02-29"}]) == {"x": "2024-02-29"}
