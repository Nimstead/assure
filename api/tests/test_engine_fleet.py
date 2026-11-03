"""Attack paths across hosts (engine/fleet.py): an edge only where each part of it is evidence, graded no better than reasonable."""

from test_api import user
from test_engine import doc, seed
from test_engine_paths import LOCAL, WEAK, rec, run

from nimstead.engine import fleet

CORP = {"domain": "corp.example", "domain_role": 1}
OPEN_445 = [{"port": 445, "process": "System", "firewall": "allowed"}]


def host(hid, config, facts=None, recs=()):
    facts = {**CORP, **(facts or {})}
    _, r = run(*recs, config=config, facts=facts)
    return {"id": hid, "hostname": hid, "facts": {"config": config, **facts}, "os_version": "10.0.26200.7000", "report": r, "internet_facing": False}


def test_credentials_taken_on_one_host_reach_another_in_the_same_domain():
    a = host("a", WEAK, recs=[rec("CVE-2026-1001", LOCAL)])
    b = host("b", {"remote_uac_off": 1}, {"listening": OPEN_445})
    out = fleet.build([a, b])
    e = next(x for x in out["edges"] if (x["from"], x["to"]) == ("a", "b"))
    assert e["grade"] == "reasonable" and e["ways"][0]["via"] == "CFG:remote-uac" and e["ways"][0]["port"] == 445
    assert "corp.example".upper() in e["ways"][0]["because"]
    assert out["chains"][0]["start"] == "a" and out["chains"][0]["reach"][0]["host"] == "b"
    assert out["chains"][0]["reach"][0]["fix_on_host"] == ["CFG:remote-uac"]


def test_no_edge_without_each_piece_of_evidence():
    a = host("a", WEAK, recs=[rec("CVE-2026-1001", LOCAL)])
    blocked = host("b", {"remote_uac_off": 1}, {"listening": [{**OPEN_445[0], "firewall": "blocked"}]})
    unread = host("c", {"remote_uac_off": 1})  # listeners not read: not seen open
    safe = host("d", {"remote_uac_off": 0}, {"listening": OPEN_445})
    assert fleet.build([a, blocked, unread, safe])["edges"] == []
    # nothing taken on A (no path at all): it gives an attacker nothing
    assert fleet.build([host("a", {}), host("b", {"remote_uac_off": 1}, {"listening": OPEN_445})])["edges"] == []


def test_outside_a_shared_domain_the_edge_says_what_cant_be_seen():
    a = host("a", WEAK, {"domain": "WORKGROUP", "domain_role": 0}, recs=[rec("CVE-2026-1001", LOCAL)])
    b = host("b", {"remote_uac_off": 1}, {"domain": "WORKGROUP", "domain_role": 0, "listening": OPEN_445})
    e = fleet.build([a, b])["edges"][0]
    assert e["grade"] == "unverified" and "can't be seen" in e["ways"][0]["because"]


def test_name_poisoning_relays_to_a_host_that_doesnt_require_smb_signing():
    a = host("a", {**WEAK, "llmnr": None}, recs=[rec("CVE-2026-1001", LOCAL)])  # no LLMNR policy: on, Windows' default
    b = host("b", {"smb_signing_required": False}, {"listening": OPEN_445})
    e = fleet.build([a, b])["edges"][0]
    assert e["ways"][0]["via"] == "CFG:smb-signing" and "name poisoning" in e["ways"][0]["because"]


def test_a_host_without_a_report_is_listed_as_not_judged():
    out = fleet.build([host("a", WEAK), {"id": "z", "hostname": "z", "facts": {}, "report": None}])
    assert out["hosts"]["z"]["judged"] is False and not any("z" in (e["from"], e["to"]) for e in out["edges"])


def test_attack_paths_endpoint_reads_stored_reports_and_is_org_scoped(env):
    seed(env)
    c = user(env)

    for name, config, facts in (("a", WEAK, {}), ("b", {"remote_uac_off": 1}, {"listening": OPEN_445})):
        token = c.post("/api/enroll-tokens").json()["token"]
        k = c.post("/api/agent/enroll", json={"token": token, "hostname": name, "ecosystem": "Windows"}).json()["agent_key"]
        inv = doc(facts={"pending_reboot": False, "config": config, **CORP, **facts})
        inv["hostname"] = name
        assert c.post("/api/agent/inventory", headers={"Authorization": f"Bearer {k}"}, json=inv).status_code == 200
    ids = [a["id"] for a in c.get("/api/assets").json()]  # each inventory stored its engine report after the response
    out = c.get("/api/attack-paths").json()
    assert set(out["hosts"]) == set(ids) and all(h["judged"] for h in out["hosts"].values())
    name = {i: h["hostname"] for i, h in out["hosts"].items()}
    assert [(name[e["from"]], name[e["to"]]) for e in out["edges"]] == [("a", "b")]  # a: seeded known-exploited flaw in, WDigest out
    assert user(env, "other@example.com").get("/api/attack-paths").json()["hosts"] == {}
