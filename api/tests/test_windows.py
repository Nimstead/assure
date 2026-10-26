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
    (9600, "", "Server", "AMD64", ""),  # Server 2012 R2: unmapped, never guessed
    (25398, "23H2", "Server Core", "AMD64", ""),
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
    assert {r.ecosystem for r in rows} == {"Windows"}
    assert not {r.package for r in rows if not r.package.startswith("Windows")}  # VS Code etc. dropped
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
    assert c.post("/api/agent/inventory", json=other, headers=h).json()["open"] == 0


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
