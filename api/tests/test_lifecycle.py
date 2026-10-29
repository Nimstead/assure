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
    inv({"edition_id": "Professional", "esu": True})
    assert not c.get("/api/findings").json()
    assert c.get("/api/findings", params={"status": "resolved"}).json()[0]["vuln_id"] == "EOL:win10-22h2"


def test_facts_are_bounded(env):
    c = user(env)
    token = c.post("/api/enroll-tokens").json()["token"]
    a = c.post("/api/agent/enroll", json={"token": token, "hostname": "pc-11", "ecosystem": "Windows"}).json()
    h = {"Authorization": f"Bearer {a['agent_key']}"}
    body = {"ecosystem": "Windows", "packages": [{"ecosystem": "Windows", "name": W10, "version": "10.0.19045.1", "source": None}]}
    assert c.post("/api/agent/inventory", headers=h, json={**body, "facts": {"x": "y" * 501}}).status_code == 422
    assert c.post("/api/agent/inventory", headers=h, json={**body, "facts": {"a": {"b": {"c": {"d": 1}}}}}).status_code == 422
