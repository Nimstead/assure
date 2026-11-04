"""Vulnerable drivers by exact hash (DECISIONS 71): the feed's real shape, a changed format keeps the stored list, the
agent's collector output, and findings end to end. No test here loads or hashes a real driver."""

import json
import re
import subprocess
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select
from test_agent_proxy import agent
from test_api import user

from nimstead import windrivers
from nimstead.db import Advisory, make_sessionmaker
from nimstead.feeds import sync_loldrivers

FEED = json.loads((Path(__file__).parent / "fixtures" / "loldrivers" / "drivers-sample.json").read_text(encoding="utf-8"))
RTCORE = "01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862444af32e87f1fd"
MALICIOUS = "090d409f86430e078694e621ad0bd5e458d32aa727f0eb99bda3961577df8d49"
UNVERIFIED = "4e3eb5b9bce2"
UNRELATED = "ab" * 32


def full_feed():
    """The real entries, plus enough of the same shape to clear the floor that catches a changed format."""
    return [*FEED, *({**FEED[0], "KnownVulnerableSamples": [{"SHA256": f"{i:064x}"}]} for i in range(windrivers.MIN_HASHES))]


def test_real_feed_shape_keeps_verified_file_hashes_only():
    listed = windrivers.parse(full_feed())
    assert listed[RTCORE] == ["rtcore64.sys", "vulnerable driver", "e32bc3da-4db1-4858-a62c-6fbe4db6afbd"]
    assert listed[MALICIOUS][1] == "malicious"
    assert not [h for h in listed if h.startswith(UNVERIFIED)]  # an entry LOLDrivers hasn't verified
    assert "" not in listed  # a sample with only an Authenticode hash can't match a file hash


@pytest.mark.parametrize("feed", [
    {"drivers": []},
    [],
    [{**FEED[0], "Category": "new kind"}],
    [{k: v for k, v in FEED[0].items() if k != "KnownVulnerableSamples"}],
    [{**FEED[0], "Id": "../../evil"}],
    [{**FEED[0], "Verified": "FALSE"}] * 1001,  # nothing usable left
    [{k: v for k, v in e.items() if k != "Verified"} for e in FEED],
    FEED,  # far too few hashes
])
def test_changed_format_raises(feed):
    with pytest.raises(ValueError):
        windrivers.parse(feed)


def test_sync_stores_the_list_and_a_broken_update_keeps_it(env):
    sm = make_sessionmaker(env)
    body = {"v": json.dumps(full_feed())}
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, text=body["v"])))
    with sm() as s:
        assert sync_loldrivers(s, client) > windrivers.MIN_HASHES
        for bad in ('{"changed": true}', "<html>maintenance</html>"):
            body["v"] = bad
            with pytest.raises(ValueError):
                sync_loldrivers(s, client)
            s.rollback()
            assert RTCORE in s.scalar(select(Advisory.record).where(Advisory.ecosystem == windrivers.ECOSYSTEM))["drivers"]


def enrol(c):
    token = c.post("/api/enroll-tokens").json()["token"]
    a = c.post("/api/agent/enroll", json={"token": token, "hostname": "srv", "ecosystem": "Windows"}).json()
    return {"Authorization": f"Bearer {a['agent_key']}"}


def drv(name, sha, source="on disk"):
    return {"ecosystem": "WinDriver", "name": name, "version": sha, "source": source}


def store_list(env):
    with make_sessionmaker(env)() as s:
        s.merge(Advisory(id="DRIVERS-loldrivers", ecosystem=windrivers.ECOSYSTEM, package="loldrivers", modified="1",
                         record={"id": "DRIVERS-loldrivers", "drivers": windrivers.parse(full_feed())}))
        s.commit()


def test_only_an_exact_hash_opens_a_finding_and_a_partial_scan_closes_nothing(env):
    store_list(env)
    c = user(env)
    h = enrol(c)

    def inv(pkgs, scan):
        r = c.post("/api/agent/inventory", headers=h, json={"ecosystem": "Windows", "packages": pkgs, "facts": {"driver_scan": scan}})
        assert r.status_code == 200, r.text
        return {x["vuln_id"]: x for x in c.get("/api/findings", params={"status": "open"}).json()}

    done = {"complete": True}
    # same file name as the listed driver, other bytes: nothing. A name is never evidence
    assert inv([drv("rtcore64.sys", UNRELATED, "loaded")], done) == {}
    found = inv([drv("rtcore64.sys", RTCORE), drv("evil.sys", MALICIOUS, "loaded"), drv("ntfs.sys", UNRELATED, "loaded")], done)
    assert set(found) == {f"DRV:{RTCORE}", f"DRV:{MALICIOUS}"}
    disk, bad = found[f"DRV:{RTCORE}"], found[f"DRV:{MALICIOUS}"]
    assert (disk["priority"], disk["ecosystem"], disk["installed_version"]) == ("planned", "WinDriver", RTCORE)
    assert "not loaded" in disk["summary"] and "rtcore64.sys" in disk["summary"]
    assert bad["priority"] == "fix-now"
    assert inv([drv("rtcore64.sys", RTCORE, "loaded")], done)[f"DRV:{RTCORE}"]["priority"] == "next"  # loaded now
    # a driver finding has no fixed version but does have a fix, so the default view must show it
    assert f"DRV:{RTCORE}" in {x["vuln_id"] for x in c.get("/api/findings", params={"fixable": True}).json()}

    # the row is gone, but the scan didn't finish or the agent can't say: still open
    for scan in ({"complete": False, "stopped": True}, {"complete": False, "problem": "driver check failed"}, None):
        assert f"DRV:{RTCORE}" in inv([], scan)
    assert inv([], done) == {}  # a complete scan proves it's gone


def test_old_agents_without_drivers_change_nothing(env):
    store_list(env)
    c = user(env)
    assert c.post("/api/agent/inventory", headers=enrol(c), json={"ecosystem": "Windows", "packages": [], "facts": {}}).status_code == 200
    assert c.get("/api/findings").json() == []


def ps_out(**kw):
    return 0, "noise\r\n" + json.dumps({"drivers": [["RTCore64.sys", RTCORE, False], ["ntfs.sys", UNRELATED, True]],
                                        "unreadable": 0, "too_large": 1, "stopped": False, **kw}) + "\r\n"


def test_agent_reports_rows_as_inventory_and_says_how_far_it_got():
    pkgs, scan = agent.windows_drivers(lambda cmd: ps_out())
    assert pkgs == [drv("rtcore64.sys", RTCORE), drv("ntfs.sys", UNRELATED, "loaded")]
    assert scan == {"hashed": 2, "too_large": 1, "unreadable": 0, "stopped": False, "complete": True}  # too large can't be a listed hash seen before
    assert agent.windows_drivers(lambda cmd: ps_out(unreadable=2))[1]["complete"] is False
    assert agent.windows_drivers(lambda cmd: ps_out(stopped=True))[1]["complete"] is False


@pytest.mark.parametrize("run", [
    lambda cmd: (1, "boom"), lambda cmd: (0, ""), lambda cmd: (0, "not json"), lambda cmd: (0, '{"drivers": []}'), lambda cmd: (0, "[1]"),
])
def test_agent_failed_collector_is_not_a_clean_host(run):
    pkgs, scan = agent.windows_drivers(run)
    assert pkgs == [] and scan["complete"] is False and "problem" in scan


def test_agent_drops_rows_that_are_not_a_name_and_a_hash():
    rows = [["x.sys", "ABC", False], ["", RTCORE, False], [1, RTCORE, False], ["x.sys", RTCORE], "x", ["ok.sys", RTCORE, True]]
    pkgs, _ = agent.windows_drivers(lambda cmd: (0, json.dumps({"drivers": rows, "unreadable": 0, "stopped": False})))
    assert pkgs == [drv("ok.sys", RTCORE, "loaded")]


def test_collector_only_reads():
    s = agent.PS_DRIVERS
    assert "Started = TRUE" in s and "Get-FileHash" in s
    assert not re.search(r"(?i)\bsc(\.exe)?\s|New-Service|Start-Service|fltmc|pnputil|driverquery|Set-|Remove-|New-Item|Invoke-", s)


@pytest.mark.skipif(agent.os.name != "nt", reason="needs Windows PowerShell's parser")
def test_collector_parses_without_running():
    script = "$e = $null; [void][Management.Automation.Language.Parser]::ParseInput(($input | Out-String), [ref]$null, [ref]$e); $e.Count"
    p = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], input=agent.PS_DRIVERS,
                       capture_output=True, text=True, check=True, timeout=60)
    assert p.stdout.strip() == "0", p.stderr
