"""Windows detection: agent product naming, MSRC feed parsing, and matching end to end."""

import copy
import json
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select
from test_agent import agent
from test_api import user

from nimstead.db import Advisory, Cvss, make_sessionmaker
from nimstead.feeds import sync_msrc

FIX = Path(__file__).parent / "fixtures" / "msrc"
W11 = "Windows 11 Version 25H2 for x64-based Systems"


@pytest.mark.parametrize("build,dv,itype,machine,want", [
    (26200, "25H2", "Client", "AMD64", W11),
    (26100, "24H2", "Client", "ARM64", "Windows 11 Version 24H2 for ARM64-based Systems"),
    (22000, "21H2", "Client", "AMD64", "Windows 11 Version 21H2 for x64-based Systems"),
    (19045, "22H2", "Client", "AMD64", "Windows 10 Version 22H2 for x64-based Systems"),
    (19045, "22H2", "Client", "x86", "Windows 10 Version 22H2 for 32-bit Systems"),
    (10240, "1507", "Client", "AMD64", "Windows 10 for x64-based Systems"),
    (14393, "1607", "Client", "AMD64", "Windows 10 Version 1607 for x64-based Systems"),
    (26100, "24H2", "Server", "AMD64", "Windows Server 2025"),  # same build as Windows 11 24H2: InstallationType decides
    (26100, "24H2", "Server Core", "AMD64", "Windows Server 2025 (Server Core installation)"),
    (20348, "21H2", "Server", "AMD64", "Windows Server 2022"),
    (17763, "1809", "Server", "AMD64", "Windows Server 2019"),
    (9600, "", "Server", "AMD64", "Windows Server 2012 R2"),  # named for end of support; no UBR, so never CVE-matched
    (25398, "23H2", "Server Core", "AMD64", "Windows Server 2022, 23H2 Edition (Server Core installation)"),
    (99999, "", "Server", "AMD64", ""),  # unknown server build: never guessed
    (26200, "", "Client", "AMD64", ""),  # no DisplayVersion
    (26200, "25H2", "Client", "riscv64", ""),
])
def test_msrc_product_name(build, dv, itype, machine, want):
    assert agent.msrc_product_name(build, dv, itype, machine) == want


def doc():
    return json.loads((FIX / "2026-Oct.json").read_text())


def msrc_client(d=None, fetched=None):
    def handler(req: httpx.Request):
        assert req.headers["accept"] == "application/json"
        if fetched is not None:
            fetched.append(req.url.path)
        if req.url.path.endswith("/updates"):
            return httpx.Response(200, json=json.loads((FIX / "updates.json").read_text()))
        if req.url.path.endswith("/cvrf/2026-Oct"):
            return httpx.Response(200, json=d or doc())
        return httpx.Response(404)  # Mariner and out-of-window months must not be fetched
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_sync_msrc_shapes_osv_records_and_is_incremental():
    s = make_sessionmaker("sqlite://")()
    fetched: list[str] = []
    n = sync_msrc(s, 60, msrc_client(fetched=fetched))
    assert fetched == ["/cvrf/v3.0/updates", "/cvrf/v3.0/cvrf/2026-Oct"]
    rows = s.scalars(select(Advisory)).all()
    assert n["inserted"] == len(rows) and n["documents"] == 1
    assert {r.ecosystem for r in rows} == {"Windows", "Microsoft"}
    assert {r.package for r in rows if r.ecosystem == "Microsoft"} == {"Visual Studio Code"}  # allowlisted (DECISIONS 53)
    assert all(r.package.startswith("Windows") for r in rows if r.ecosystem == "Windows")
    assert "Windows 11 Version 26H1 for x64-based Systems" in {r.package for r in rows}  # lowercase "version" normalised
    assert not [r for r in rows if "ADV" in r.id]

    r = next(r for r in rows if r.package == W11 and r.record["aliases"] == ["CVE-2026-100201"]).record
    assert r["id"].startswith("MSRC-CVE-2026-100201-")
    assert r["affected"][0]["ranges"][0]["events"] == [{"introduced": "0"}, {"fixed": "10.0.26200.9711"}]
    assert r["severity"][0]["type"] == "CVSS_V3" and r["severity"][0]["score"].startswith("CVSS:3.1/")
    assert r["database_specific"]["kb"] == "5127648" and "(KB5127648)" in r["summary"]

    again = sync_msrc(s, 60, msrc_client(fetched=(f2 := [])))
    assert again["documents"] == 0 and again["skipped_documents"] == 1 and f2 == ["/cvrf/v3.0/updates"]


def test_sync_msrc_score_without_vector_goes_to_cvss_table():
    d = doc()
    for v in d["Vulnerability"]:
        if v["CVE"] == "CVE-2026-100202":
            for sc in v["CVSSScoreSets"]:
                sc.pop("Vector")
                sc["BaseScore"] = 8.8
    s = make_sessionmaker("sqlite://")()
    sync_msrc(s, 60, msrc_client(d))
    assert s.get(Cvss, "CVE-2026-100202").score == 8.8 and s.get(Cvss, "CVE-2026-100201") is None
    assert all("severity" not in a.record for a in s.scalars(select(Advisory)) if a.record["aliases"] == ["CVE-2026-100202"])


def test_sync_msrc_keeps_lowest_fixed_build_per_product():
    d = copy.deepcopy(doc())
    v = next(v for v in d["Vulnerability"] if v["CVE"] == "CVE-2026-100201")
    r = next(r for r in v["Remediations"] if r["FixedBuild"] == "10.0.26200.9711")
    v["Remediations"].append({**r, "FixedBuild": "10.0.26200.10003", "Description": {"Value": "9999999"}})
    s = make_sessionmaker("sqlite://")()
    sync_msrc(s, 60, msrc_client(d))
    a = next(a for a in s.scalars(select(Advisory)) if a.package == W11 and a.record["aliases"] == ["CVE-2026-100201"])
    assert a.record["affected"][0]["ranges"][0]["events"][1] == {"fixed": "10.0.26200.9711"}


def test_windows_asset_end_to_end(env):
    with make_sessionmaker(env)() as s:
        sync_msrc(s, 60, msrc_client())
    c = user(env)
    token = c.post("/api/enroll-tokens").json()["token"]
    a = c.post("/api/agent/enroll", json={"token": token, "hostname": "pc-1", "os_name": "Windows 11 Pro", "ecosystem": "Windows"}).json()
    h = {"Authorization": f"Bearer {a['agent_key']}"}

    def inv(build):
        return {"ecosystem": "Windows", "packages": [{"ecosystem": "Windows", "name": W11, "version": build, "source": None}]}

    assert c.post("/api/agent/inventory", json=inv("10.0.26200.6899"), headers=h).status_code == 200
    f = {x["vuln_id"]: x for x in c.get("/api/findings").json()}
    assert set(f) == {"CVE-2026-100201", "CVE-2026-100202"}  # the VS Code CVE is not a Windows finding
    x = f["CVE-2026-100201"]
    assert x["package"] == W11 and x["installed_version"] == "10.0.26200.6899" and x["fixed_version"] == "10.0.26200.9711"
    assert x["cvss"] and "KB5127648" in x["summary"]
    top = c.get("/api/summary").json()["top_actions"][0]
    assert top["package"] == W11 and top["fixed_version"] == "10.0.26200.9711"

    # one build short of the fix is still vulnerable; the fixed build and newer are not
    c.post("/api/agent/inventory", json=inv("10.0.26200.9710"), headers=h)
    assert len(c.get("/api/findings").json()) == 2
    r = c.post("/api/agent/inventory", json=inv("10.0.26200.9711"), headers=h).json()
    assert r["open"] == 0 and r["resolved"] == 2
    assert not c.get("/api/findings").json()
    assert {x["status"] for x in c.get("/api/findings", params={"status": "resolved"}).json()} == {"resolved"}

    # a product MSRC doesn't list for this CVE (e.g. Windows 10) is never matched
    other = {"ecosystem": "Windows", "packages": [{"ecosystem": "Windows", "name": "Windows 11 Version 21H2 for x64-based Systems",
                                                   "version": "10.0.22000.1", "source": None}]}
    assert c.post("/api/agent/inventory", json=other, headers=h).json()["open"] == 1  # only its end-of-support finding
    assert [x["vuln_id"] for x in c.get("/api/findings").json()] == ["EOL:win11-21h2"]


def test_windows_fix_is_planned_as_one_kb_with_target_build(env):
    with make_sessionmaker(env)() as s:
        sync_msrc(s, 60, msrc_client())
    c = user(env)
    token = c.post("/api/enroll-tokens", json={"sandbox": True}).json()["token"]
    a = c.post("/api/agent/enroll", json={"token": token, "hostname": "pc-1", "ecosystem": "Windows"}).json()
    h = {"Authorization": f"Bearer {a['agent_key']}"}
    c.post("/api/agent/inventory", json={"ecosystem": "Windows", "packages": [
        {"ecosystem": "Windows", "name": W11, "version": "10.0.26200.6899", "source": None}]}, headers=h)
    r = c.post("/api/remediation/jobs", json={"asset_id": a["asset_id"], "ecosystem": "Windows", "package": W11})
    assert r.status_code == 201, r.text
    j = r.json()
    assert j["manager"] == "windows"
    assert j["packages"] == [{"name": W11, "from": "10.0.26200.6899", "kb": "5127648", "to": "10.0.26200.9711"}]
    c.post(f"/api/remediation/jobs/{j['id']}/approve")
    [job] = c.get("/api/agent/jobs", headers=h).json()
    assert job["packages"][0]["kb"] == "5127648"


def test_only_one_windows_job_in_flight_per_host(env):
    from nimstead.db import RemediationJob
    with make_sessionmaker(env)() as s:
        sync_msrc(s, 60, msrc_client())
    c = user(env)
    token = c.post("/api/enroll-tokens", json={"sandbox": True}).json()["token"]
    a = c.post("/api/agent/enroll", json={"token": token, "hostname": "pc-1", "ecosystem": "Windows"}).json()
    h = {"Authorization": f"Bearer {a['agent_key']}"}
    c.post("/api/agent/inventory", json={"ecosystem": "Windows", "packages": [
        {"ecosystem": "Windows", "name": W11, "version": "10.0.26200.6899", "source": None}]}, headers=h)
    j = c.post("/api/remediation/jobs", json={"asset_id": a["asset_id"], "ecosystem": "Windows", "package": W11}).json()
    c.post(f"/api/remediation/jobs/{j['id']}/approve")
    with make_sessionmaker(env)() as s:  # a second approved Windows job for the same host
        first = s.get(RemediationJob, j["id"])
        s.add(RemediationJob(org_id=first.org_id, asset_id=first.asset_id, action_key=first.action_key + "-2", manager="windows",
                             packages=first.packages, finding_ids=[], summary="second", created_by="test", status="approved", approved_by="test"))
        s.commit()
    assert len(c.get("/api/agent/jobs", headers=h).json()) == 1  # the first may reboot the machine
    assert c.get("/api/agent/jobs", headers=h).json() == []  # still in flight: the second waits
    c.post(f"/api/agent/jobs/{j['id']}/report", json={"outcome": "applied", "versions": {W11: "10.0.26200.9711"}}, headers=h)
    assert len(c.get("/api/agent/jobs", headers=h).json()) == 1  # now the second goes out


# ---- hotpatch (DECISIONS 52): real September 2025 CVRF, cumulative KB5065426 -> .6584, hotpatch KB5065474 -> .6508
WS25 = "Windows Server 2025"


def hotpatch_doc():
    return json.loads((FIX / "2025-Sep-hotpatch.json").read_text())


def test_sync_msrc_keeps_hotpatch_fixes_apart():
    s = make_sessionmaker("sqlite://")()
    sync_msrc(s, 60, msrc_client(hotpatch_doc()))
    rows = {(a.package, a.record["aliases"][0]): a.record for a in s.scalars(select(Advisory))}
    cum, hot = rows[(WS25, "CVE-2025-49734")], rows[(WS25 + " (Hotpatch)", "CVE-2025-49734")]
    assert cum["affected"][0]["ranges"][0]["events"][1] == {"fixed": "10.0.26100.6584"}
    assert cum["database_specific"].items() >= {"kb": "5065426", "hotpatch": False}.items()
    assert hot["affected"][0]["ranges"][0]["events"][1] == {"fixed": "10.0.26100.6508"}
    assert hot["affected"][0]["package"]["name"] == WS25 and hot["database_specific"].items() >= {"kb": "5065474", "hotpatch": True}.items()


def _ws25_host(env, build):
    with make_sessionmaker(env)() as s:
        sync_msrc(s, 60, msrc_client(hotpatch_doc()))
    c = user(env)
    token = c.post("/api/enroll-tokens", json={"sandbox": True}).json()["token"]
    a = c.post("/api/agent/enroll", json={"token": token, "hostname": "srv-1", "ecosystem": "Windows"}).json()
    h = {"Authorization": f"Bearer {a['agent_key']}"}

    def inv(b):
        return c.post("/api/agent/inventory", json={"ecosystem": "Windows", "packages": [
            {"ecosystem": "Windows", "name": WS25, "version": b, "source": None}]}, headers=h).json()
    inv(build)
    return c, a, inv


def test_non_hotpatch_host_is_compared_with_cumulative_builds_only(env):
    c, _, inv = _ws25_host(env, "10.0.26100.4946")
    f = {x["vuln_id"]: x for x in c.get("/api/findings").json()}
    assert set(f) == {"CVE-2025-49734", "CVE-2025-53796"} and {x["fixed_version"] for x in f.values()} == {"10.0.26100.6584"}
    # a non-hotpatch build above the hotpatch build but below the cumulative one is still vulnerable
    assert inv("10.0.26100.6510")["open"] == 2
    assert inv("10.0.26100.6584")["open"] == 0


def test_host_on_a_hotpatch_build_is_compared_with_hotpatch_builds(env):
    c, _, inv = _ws25_host(env, "10.0.26100.6508")
    assert not c.get("/api/findings").json()  # the hotpatch fixed it; no second finding under another name
    assert inv("10.0.26100.4946")["open"] == 2
    assert {x["package"] for x in c.get("/api/findings").json()} == {WS25}


def test_windows_plan_carries_the_hotpatch_kb_as_the_alternative(env):
    c, a, _ = _ws25_host(env, "10.0.26100.4946")
    r = c.post("/api/remediation/jobs", json={"asset_id": a["asset_id"], "ecosystem": "Windows", "package": WS25})
    assert r.status_code == 201, r.text
    assert r.json()["packages"] == [{"name": WS25, "from": "10.0.26100.4946", "kb": "5065426", "to": "10.0.26100.6584",
                                     "alt": {"kb": "5065474", "to": "10.0.26100.6508"}}]


class FakeReg:
    HKEY_LOCAL_MACHINE, HKEY_USERS, HKEY_CURRENT_USER, KEY_READ, KEY_WOW64_64KEY, KEY_WOW64_32KEY = 1, 2, 3, 0, 0, 0

    def EnumKey(self, k, i):  # noqa: N802 - no apps, no user hives
        raise OSError("none")

    def __init__(self, values):
        self.values = values

    def OpenKey(self, root, path, *a):  # noqa: N802 - winreg's names
        if "Uninstall" in path or root == self.HKEY_USERS:
            raise OSError("none")
        return self

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def QueryValueEx(self, k, name):  # noqa: N802
        if name not in self.values:
            raise OSError(name)
        return self.values[name], 1


@pytest.mark.parametrize("values,machine,os_pkg,unmatched", [
    ({"CurrentBuild": "26100", "UBR": 4946, "DisplayVersion": "24H2", "ProductName": "Windows Server 2025 Datacenter",
      "InstallationType": "Server", "EditionID": "ServerDatacenter"}, "AMD64", "Windows Server 2025", False),
    ({"CurrentBuild": "9600", "ProductName": "Windows Server 2012 R2 Standard", "InstallationType": "Server",
      "EditionID": "ServerStandard"}, "AMD64", None, True),
    ({"CurrentBuild": "27900", "UBR": 1, "DisplayVersion": "", "ProductName": "Windows 10 Pro", "InstallationType": "Client",
      "EditionID": "Professional"}, "AMD64", None, True),  # Insider: apps still reported
])
def test_collect_windows_reports_facts_and_never_refuses_an_unmapped_os(monkeypatch, values, machine, os_pkg, unmatched):
    import sys
    monkeypatch.setitem(sys.modules, "winreg", FakeReg(values))
    monkeypatch.setattr(agent.platform, "machine", lambda: machine)
    monkeypatch.setattr(agent, "esu_active", lambda product, run=None: None)
    monkeypatch.setattr(agent, "windows_microsoft", lambda reg, run=None, dotnet_dirs=None: ([], None))
    monkeypatch.setattr(agent, "windows_drivers", lambda run=None: ([], {"complete": False}))
    inv = agent.collect_windows()
    assert [p["name"] for p in inv["packages"] if p["ecosystem"] == "Windows"] == ([os_pkg] if os_pkg else [])
    assert inv["facts"]["edition_id"] == values["EditionID"] and bool(inv["facts"].get("os_unmatched")) == unmatched


def test_esu_is_only_asked_where_it_applies():
    calls = []

    def run(cmd):
        calls.append(cmd)
        return 0, "1\r\n"
    assert agent.esu_active("Windows 11 Version 24H2 for x64-based Systems", run) is None and not calls
    assert agent.esu_active("Windows 10 Version 22H2 for x64-based Systems", run) is True
    assert agent.esu_active("Windows Server 2012 R2", lambda c: (1, "error")) is None


def test_server_2012_r2_gets_its_end_of_support_finding(env):
    c = user(env)
    token = c.post("/api/enroll-tokens").json()["token"]
    a = c.post("/api/agent/enroll", json={"token": token, "hostname": "old-srv", "ecosystem": "Windows"}).json()
    h = {"Authorization": f"Bearer {a['agent_key']}"}
    r = c.post("/api/agent/inventory", headers=h, json={"ecosystem": "Windows", "packages": [], "facts": {
        "edition_id": "ServerStandard", "esu": False, "os_product": "Windows Server 2012 R2", "os_unmatched": "no UBR"}})
    assert r.status_code == 200, r.text
    [f] = c.get("/api/findings").json()
    assert f["vuln_id"] == "EOL:ws2012r2" and f["priority"] == "fix-now"
    assert c.get("/api/assets").json()[0]["facts"]["os_unmatched"] == "no UBR"


def test_a_job_can_step_through_the_earlier_cumulative_but_a_hotpatch_comes_first():
    from nimstead.remediate import HOTPATCH, windows_kbs
    s = make_sessionmaker("sqlite://")()

    def row(cve, package, kb, build):
        s.add(Advisory(id=f"{cve}-{kb}", ecosystem="Windows", package=package, modified="", record={
            "aliases": [cve], "database_specific": {"kb": kb}, "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": build}]}]}]}))
    row("CVE-1", WS25, "5122871", "10.0.26100.33438")
    row("CVE-2", WS25, "5126646", "10.0.26100.33650")
    s.commit()
    assert windows_kbs(s, WS25, ["CVE-1", "CVE-2"]) == {"kb": "5126646", "to": "10.0.26100.33650", "alt": {"kb": "5122871", "to": "10.0.26100.33438"}}
    assert windows_kbs(s, WS25, ["CVE-2"]) == {"kb": "5126646", "to": "10.0.26100.33650"}
    row("CVE-1", WS25 + HOTPATCH, "5000001", "10.0.26100.33000")
    row("CVE-2", WS25 + HOTPATCH, "5000002", "10.0.26100.33100")
    s.commit()
    assert windows_kbs(s, WS25, ["CVE-1", "CVE-2"])["alt"]["kb"] == "5000002"


def test_a_job_that_reached_its_step_build_succeeded_and_a_short_one_did_not():
    from types import SimpleNamespace

    from nimstead.remediate import _stepped
    job = lambda manager, build: SimpleNamespace(manager=manager, result_versions={WS25: build}, packages=[  # noqa: E731
        {"kb": "5126646", "to": "10.0.26100.33650", "alt": {"kb": "5122871", "to": "10.0.26100.33438"}}])
    assert _stepped(job("windows", "10.0.26100.33438")) == "10.0.26100.33438"
    assert _stepped(job("windows", "10.0.26100.1742")) is None
    assert _stepped(job("winget", "10.0.26100.33438")) is None
