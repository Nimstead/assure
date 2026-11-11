"""Devices seen with no agent (tasks/plan-network.md N7, DECISIONS 128): stored from each agent's own neighbour table,
matched against the fleet's own addresses, named by maker, scoped to the org, dropped after 30 days."""

from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select
from test_api import user

from nimstead import oui
from nimstead.app import create_app
from nimstead.db import Advisory, Neighbour, make_sessionmaker, now
from nimstead.feeds import update_all

MANUF = "\n".join(["# comment", "00:00:01\tXerox\tXerox Corporation", "BC:BA:C2\tHangzhou\tHangzhou Hikvision Digital Technology Co.,Ltd.",
                   "00:55:DA:00/28\tShinkoTechno\tShinko Technos co.,ltd.", "70:B3:D5:00:00/36\tVendorX\tVendor X Ltd",
                   "B8:27:EB\tRaspberr\tRaspberry Pi Foundation"] + [f"{i >> 16 & 255:02X}:{i >> 8 & 255:02X}:{i & 255:02X}\tV\tVendor {i}" for i in range(0x100000, 0x100400)])


def agent(c, host, eco="Debian:13"):
    token = c.post("/api/enroll-tokens").json()["token"]
    a = c.post("/api/agent/enroll", json={"token": token, "hostname": host, "ecosystem": eco}).json()
    return {"Authorization": f"Bearer {a['agent_key']}"}


def report(c, h, seen, own=None, **extra):
    body = {"os_name": "Debian 13", "ecosystem": "Debian:13", "packages": [], "agent_version": "0.7.0", **extra}
    if seen is not None:
        body["neighbours"] = {"seen": seen, "own": own or {"ips": [], "macs": []}}
    r = c.post("/api/agent/inventory", headers=h, json=body)
    assert r.status_code == 200, r.text
    return r


def row(ip, mac, interface="eth0"):
    return {"ip": ip, "mac": mac, "interface": interface}


def test_two_agents_that_see_each_other_and_one_unknown_device(env):
    c = user(env)
    web, db = agent(c, "web-1"), agent(c, "db-1")
    camera = row("192.168.1.64", "bc:ba:c2:11:22:33")
    report(c, web, [row("192.168.1.11", "52:54:00:00:00:11"), camera], own={"ips": ["192.168.1.10"], "macs": ["52:54:00:00:00:10"]})
    report(c, db, [row("192.168.1.10", "52:54:00:00:00:10"), camera], own={"ips": ["192.168.1.11"], "macs": ["52:54:00:00:00:11"]})
    got = c.get("/api/network/unmanaged").json()
    assert [(d["mac"], d["addresses"], d["seen_by"]) for d in got] == [("bc:ba:c2:11:22:33", ["192.168.1.64"], ["db-1", "web-1"])]
    assert got[0]["vendor"] == ""  # no registry fetched yet: no guess
    csv = c.get("/api/network/unmanaged", params={"format": "csv"}).text
    assert csv.splitlines()[0] == "mac,vendor,addresses,seen_by,first_seen,last_seen" and "bc:ba:c2:11:22:33" in csv


def test_a_windows_agents_own_addresses_from_its_facts_count_too(env):
    c = user(env)
    lin, win = agent(c, "lin-1"), agent(c, "win-1", "Windows")
    report(c, lin, [row("10.0.0.5", "00:15:5d:01:02:03")])
    assert len(c.get("/api/network/unmanaged").json()) == 1
    report(c, win, [], facts={"addresses": ["10.0.0.5"]})  # an older Windows agent: its address is in its facts (DECISIONS 112)
    assert c.get("/api/network/unmanaged").json() == []


def test_bad_rows_are_dropped_never_the_inventory_and_old_agents_still_report(env):
    c = user(env)
    h = agent(c, "web-1")
    report(c, h, None)  # an agent older than 0.7.0
    report(c, h, [row("not-an-ip", "bc:ba:c2:11:22:33"), row("10.0.0.9", "BC-BA-C2-11-22-33"), {"ip": 5}, "x",
                  row("10.0.0.8", "bc:ba:c2:00:00:08", "x" * 500)] + [row(f"10.1.{i // 250}.{i % 250}", f"02:00:00:00:{i // 256:02x}:{i % 256:02x}") for i in range(2000)])
    s = make_sessionmaker(env)()
    stored = s.scalars(select(Neighbour)).all()
    assert len(stored) == 1020 and any(n.ip == "10.0.0.8" and len(n.interface) == 64 for n in stored)  # the first 1,024 sent, less 4 that did not fit
    assert not any(n.ip == "10.0.0.9" for n in stored)  # a MAC not in the agent's own form is dropped, not reinterpreted
    r = c.post("/api/agent/inventory", headers=h, json={"os_name": "x", "ecosystem": "Debian:13", "packages": [], "neighbours": "nonsense"})
    assert r.status_code == 200


def test_another_org_sees_none_of_it_and_read_only_users_do(env):
    c = user(env)
    report(c, agent(c, "web-1"), [row("192.168.1.64", "bc:ba:c2:11:22:33")])
    other = TestClient(create_app(env))
    other.post("/api/auth/signup", json={"email": "b@example.org", "password": "correct horse battery", "org_name": "B"})
    assert other.get("/api/network/unmanaged").json() == []
    tok = c.post("/api/tokens", json={"name": "ro"}).json()
    ro = TestClient(create_app(env))
    assert len(ro.get("/api/network/unmanaged", headers={"Authorization": f"Bearer {tok['token']}"}).json()) == 1


def test_rows_unseen_for_30_days_are_gone(env):
    c = user(env)
    h = agent(c, "web-1")
    report(c, h, [row("192.168.1.64", "bc:ba:c2:11:22:33"), row("192.168.1.65", "bc:ba:c2:11:22:34")])
    s = make_sessionmaker(env)()
    for n in s.scalars(select(Neighbour).where(Neighbour.ip == "192.168.1.64")):
        n.last_seen = now() - timedelta(days=31)
    s.commit()
    assert [d["addresses"] for d in c.get("/api/network/unmanaged").json()] == [["192.168.1.65"]]
    report(c, h, [row("192.168.1.65", "bc:ba:c2:11:22:34")])  # the next report deletes the expired row
    assert len(make_sessionmaker(env)().scalars(select(Neighbour)).all()) == 1


def test_vendor_names_longest_block_first_and_randomised_macs_say_so():
    table = oui.parse(MANUF)
    assert table["BCBAC2"].startswith("Hangzhou Hikvision") and table["0055DA0"] == "Shinko Technos co.,ltd." and table["70B3D5000"] == "Vendor X Ltd"
    assert oui.vendor("bc:ba:c2:11:22:33", table).startswith("Hangzhou Hikvision")
    assert oui.vendor("00:55:da:0f:00:01", table) == "Shinko Technos co.,ltd."  # the /28 block, not a /24 guess
    assert oui.vendor("70:b3:d5:00:00:42", table) == "Vendor X Ltd"
    assert oui.vendor("da:a1:19:00:00:01", table) == "randomised MAC"
    assert oui.vendor("00:00:99:00:00:01", table) == ""


class Manuf:
    def __init__(self, body=MANUF, status=200):
        self.body, self.status, self.calls = body, status, []

    def get(self, url, **k):
        import httpx
        self.calls.append(url)
        if "wireshark" not in url:
            return httpx.Response(404, request=httpx.Request("GET", url))
        return httpx.Response(self.status, content=self.body.encode(), request=httpx.Request("GET", url))


def test_the_registry_is_fetched_weekly_once_devices_exist_and_a_bad_fetch_keeps_the_last(env):
    c = user(env)
    s = make_sessionmaker(env)()
    feed = Manuf()
    update_all(s, client=feed)
    assert oui.URL not in feed.calls  # no agent has reported a neighbour: nothing to name
    report(c, agent(c, "web-1"), [row("192.168.1.64", "bc:ba:c2:11:22:33")])
    update_all(s, client=feed)
    assert feed.calls.count(oui.URL) == 1
    assert c.get("/api/network/unmanaged").json()[0]["vendor"].startswith("Hangzhou Hikvision")
    update_all(s, client=feed)
    assert feed.calls.count(oui.URL) == 1  # fresh: not fetched again within the week (the file's own request)
    row_ = s.get(Advisory, oui.KEY)
    row_.modified = (now() - timedelta(days=8)).isoformat()
    s.commit()
    update_all(s, client=Manuf(body="truncated"))
    assert c.get("/api/network/unmanaged").json()[0]["vendor"].startswith("Hangzhou Hikvision")  # the stored copy stayed
