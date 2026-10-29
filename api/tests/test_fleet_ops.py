"""Fleet-grade remediation (plan T40, T42): maintenance windows, the restart deadline, and one Windows job at a time per
failover cluster or per domain's controllers."""

from datetime import datetime

import pytest
from sqlalchemy import select
from test_api import user
from test_windows import W11, msrc_client

from nimstead import remediate
from nimstead.db import Asset, RemediationJob, make_sessionmaker
from nimstead.feeds import sync_msrc

SAT_NIGHT = {"days": [5], "start": "22:00", "hours": 4, "tz": "Europe/London"}


@pytest.mark.parametrize("when,inside,edge", [
    (datetime(2026, 10, 31, 22, 30), True, datetime(2026, 11, 1, 2, 0)),  # Sat 22:30 UTC = 22:30 GMT: inside, ends 02:00
    (datetime(2026, 11, 1, 1, 59), True, datetime(2026, 11, 1, 2, 0)),  # past midnight, still the Saturday window
    (datetime(2026, 11, 1, 2, 0), False, datetime(2026, 11, 7, 22, 0)),  # just closed: next Saturday
    (datetime(2026, 10, 29, 12, 0), False, datetime(2026, 10, 31, 22, 0)),
    (datetime(2026, 10, 24, 21, 30), True, datetime(2026, 10, 25, 1, 0)),  # BST: 22:30 local = 21:30 UTC
])
def test_window_state(when, inside, edge):
    assert remediate.window_state(SAT_NIGHT, when) == (inside, edge)
    assert remediate.window_state(None, when) == (True, None)


@pytest.mark.parametrize("bad", [{}, {"days": [7], "start": "22:00", "hours": 4, "tz": "UTC"}, {"days": [1], "start": "24:00", "hours": 4, "tz": "UTC"},
                                 {"days": [1], "start": "22:00", "hours": 0, "tz": "UTC"}, {"days": [1], "start": "22:00", "hours": 4, "tz": "Mars/Base"},
                                 {"days": [True], "start": "22:00", "hours": 4, "tz": "UTC"}, {**SAT_NIGHT, "extra": 1}])
def test_invalid_windows_are_refused(bad):
    assert not remediate.valid_window(bad)


def windows_host(c, env, name, facts=None):
    token = c.post("/api/enroll-tokens", json={"sandbox": True}).json()["token"]
    a = c.post("/api/agent/enroll", json={"token": token, "hostname": name, "ecosystem": "Windows"}).json()
    h = {"Authorization": f"Bearer {a['agent_key']}"}
    c.post("/api/agent/inventory", headers=h, json={"ecosystem": "Windows", "facts": facts, "packages": [
        {"ecosystem": "Windows", "name": W11, "version": "10.0.26200.6899", "source": None}]})
    j = c.post("/api/remediation/jobs", json={"asset_id": a["asset_id"], "ecosystem": "Windows", "package": W11}).json()
    assert c.post(f"/api/remediation/jobs/{j['id']}/approve").status_code == 200
    return a, h, j


def test_jobs_wait_for_the_window_and_say_when(env, monkeypatch):
    with make_sessionmaker(env)() as s:
        sync_msrc(s, 60, msrc_client())
    c = user(env)
    always_closed = {"days": [0], "start": "00:00", "hours": 1, "tz": "UTC"}
    monkeypatch.setattr(remediate, "now", lambda: datetime(2026, 10, 29, 12, 0))  # a Thursday
    assert c.patch("/api/settings", json={"maintenance_window": always_closed, "reboot_deadline_hours": 8}).status_code == 200
    assert c.patch("/api/settings", json={"maintenance_window": {"days": [9]}}).status_code == 422
    a, h, j = windows_host(c, env, "pc-1")
    assert c.get("/api/agent/jobs", headers=h).json() == []  # outside the window: nothing handed out
    [listed] = [x for x in c.get("/api/remediation/jobs").json() if x["id"] == j["id"]]
    assert listed["status"] == "approved" and listed["waits_for_window"] == "2026-11-02T00:00:00Z"
    # this host's own window overrides the org's
    assert c.patch(f"/api/assets/{a['asset_id']}", json={"maintenance_window": {"days": [3], "start": "11:00", "hours": 2, "tz": "UTC"}}).status_code == 200
    [job] = c.get("/api/agent/jobs", headers=h).json()
    assert job["id"] == j["id"] and job["reboot_by"] == "2026-10-29T20:00:00Z"  # dispatch + 8 h restart deadline
    assert c.patch(f"/api/assets/{a['asset_id']}", json={"maintenance_window": {}}).json()["maintenance_window"] is None


def test_one_windows_job_at_a_time_per_cluster_and_per_domain_controllers(env):
    with make_sessionmaker(env)() as s:
        sync_msrc(s, 60, msrc_client())
    c = user(env)
    node = {"cluster": "SQLCLUS01", "domain_role": 3, "domain": "corp.example"}
    _, h1, j1 = windows_host(c, env, "sql-a", node)
    _, h2, j2 = windows_host(c, env, "sql-b", {**node, "cluster": "sqlclus01"})
    _, h3, j3 = windows_host(c, env, "app-1", {"domain_role": 3, "domain": "corp.example"})
    assert [x["id"] for x in c.get("/api/agent/jobs", headers=h1).json()] == [j1["id"]]
    assert c.get("/api/agent/jobs", headers=h2).json() == []  # the other node waits for the first to report
    assert [x["id"] for x in c.get("/api/agent/jobs", headers=h3).json()] == [j3["id"]]  # not in the group
    dc = {"domain_role": 5, "domain": "corp.example"}
    _, hd1, d1 = windows_host(c, env, "dc-1", dc)
    _, hd2, _ = windows_host(c, env, "dc-2", dc)
    assert len(c.get("/api/agent/jobs", headers=hd1).json()) == 1 and c.get("/api/agent/jobs", headers=hd2).json() == []
    with make_sessionmaker(env)() as s:
        assert s.scalar(select(RemediationJob.status).where(RemediationJob.id == j2["id"])) == "approved"
        assert remediate.serial_group(s.scalar(select(Asset).where(Asset.hostname == "sql-b"))) == "cluster:sqlclus01"


# ---- Windows computers with no agent, from Active Directory (plan T43)

def test_unmanaged_computers_from_the_directory(env):
    from datetime import timedelta

    from nimstead.db import now
    c = user(env)
    token = c.post("/api/enroll-tokens").json()["token"]
    a = c.post("/api/agent/enroll", json={"token": token, "hostname": "SRV-1.corp.example", "ecosystem": "Windows"}).json()
    h = {"Authorization": f"Bearer {a['agent_key']}"}
    recent, stale = (now() - timedelta(days=2)).isoformat() + "Z", (now() - timedelta(days=90)).isoformat() + "Z"
    r = c.post("/api/agent/directory", headers=h, json={"domain": "CORP.example", "computers": [
        {"name": "SRV-1", "os": "Windows Server 2022 Standard", "os_version": "10.0 (20348)", "last_logon": recent},  # has the agent
        {"name": "OLD-FS", "os": "Windows Server 2012 R2 Standard", "os_version": "6.3 (9600)", "last_logon": recent},
        {"name": "PC-7", "os": "Windows 10 Pro", "os_version": "10.0 (19045)", "last_logon": recent},
        {"name": "GONE", "os": "Windows 10 Pro", "os_version": "10.0 (19045)", "last_logon": stale},  # stale: left out
        {"name": "=cmd|'/c calc'!A1", "os": "Windows 11 Pro", "os_version": "10.0 (26100)", "last_logon": recent}]})
    assert r.status_code == 200 and r.json() == {"computers": 5}
    got = {x["name"]: x for x in c.get("/api/directory/unmanaged").json()}
    assert set(got) == {"old-fs", "pc-7", "=cmd|'/c calc'!a1"}
    assert got["old-fs"]["end_of_support"] == "Windows Server 2012 R2" and got["pc-7"]["end_of_support"] == "Windows 10 22H2"
    csv_text = c.get("/api/directory/unmanaged", params={"format": "csv"}).text
    assert "'=cmd" in csv_text and csv_text.splitlines()[0].startswith("domain,name")  # no formula injection
    assert c.post("/api/agent/directory", headers=h, json={"domain": "x", "computers": [{"name": ""}]}).status_code == 422


def test_agent_reads_the_directory_with_one_closed_query():
    import json as j

    from test_agent import agent
    out = j.dumps({"domain": "corp.example", "computers": [{"name": "PC-7", "os": "Windows 10 Pro", "os_version": "10.0 (19045)", "last_logon": None}]})
    assert agent.ad_computers(lambda cmd: (0, out))["computers"][0]["name"] == "PC-7"
    assert "adsisearcher" in agent.PS_AD_COMPUTERS and "userAccountControl:1.2.840.113556.1.4.803:=2" in agent.PS_AD_COMPUTERS
    with pytest.raises(agent.AgentError):
        agent.ad_computers(lambda cmd: (1, "The specified domain either does not exist or could not be contacted."))
