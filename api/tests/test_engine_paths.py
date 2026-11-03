"""Attack paths on one host (engine/paths.py): chains only from evidence the engine holds, as sure as the weakest step."""

from test_engine import BUILD, W11, content, doc, msrc

from nimstead.engine import paths, report
from nimstead.engine.collection import Inventory
from nimstead.engine.evaluate import evaluate

LOCAL = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
REMOTE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
WEAK = {"wdigest": 1, "smb_signing_required": False, "rdp_enabled": True, "rdp_nla": 0}


def rec(cve, vector, fixed="10.0.26200.7100"):
    r = msrc(cve, fixed)
    r["severity"] = [{"type": "CVSS_V3", "score": vector}]
    return r


def run(*recs, config=None, kev=(), facts=None, sources=None):
    inv = Inventory.from_doc(doc(facts={"config": config or {}, **(facts or {})}, sources=sources))
    c = content(*recs, kev=kev)
    return paths.build(inv, c, evaluate(inv, c)), report.build(inv, c, evaluate(inv, c))


def test_network_entry_to_system_to_credentials_with_where_to_break_it():
    p, r = run(rec("CVE-2026-1001", LOCAL), config=WEAK)
    net = next(x for x in p if x["kind"] == "network")
    assert [s["stage"] for s in net["steps"]] == ["entry", "escalate", "credentials"]
    assert net["steps"][0]["ways"][0]["ref"] == "CFG:rdp-nla" and net["steps"][1]["ways"][0]["ref"] == "CVE-2026-1001"
    assert net["then"]["ways"][0]["ref"] == "CFG:smb-signing"
    assert net["break_at"]["stage"] == "entry" and net["break_at"]["refs"] == ["CFG:rdp-nla"]  # the first single way through
    assert r["attack_paths"] == p and "How these combine" in report.render(r)


def test_flaws_one_update_fixes_are_one_way_through():
    p, _ = run(rec("CVE-2026-1001", LOCAL), rec("CVE-2026-1002", LOCAL), rec("CVE-2026-1003", LOCAL), config={"wdigest": 1})
    esc = p[0]["steps"][0]
    assert esc["count"] == 1 and esc["ways"][0]["flaws"] == 3 and "2 more like it in the same install" in esc["ways"][0]["what"]


def test_a_path_is_as_sure_as_its_weakest_step():
    p, _ = run(rec("CVE-2026-1001", LOCAL), config=WEAK, sources={"host_facts": {"state": "partial", "count": 3, "error": "x"}})
    assert all(x["grade"] == "unverified" for x in p)


def test_a_remote_flaw_is_entry_only_when_exposure_or_exploitation_is_shown():
    # AV:N alone in an OS component: no listener, not exploited -> no network path from it
    p, _ = run(rec("CVE-2026-2002", REMOTE), config={"wdigest": 1})
    assert not any(x["kind"] == "network" for x in p)
    p, _ = run(rec("CVE-2026-2002", REMOTE), rec("CVE-2026-1001", LOCAL), config={"wdigest": 1}, kev={"CVE-2026-2002"})
    entry = next(x for x in p if x["kind"] == "network")["steps"][0]["ways"][0]
    assert entry["ref"] == "CVE-2026-2002" and "exploited" in entry["what"] and entry["kev"]


def test_no_vector_falls_back_to_msrcs_impact_title():
    r = msrc("CVE-2026-3003", "10.0.26200.7100")
    r.pop("severity")
    r["summary"] = "Windows Kernel Elevation of Privilege Vulnerability (KB5066835)"
    p, _ = run(r, config={"wdigest": 1})
    assert p[0]["kind"] == "foothold" and "MSRC: Elevation of Privilege" in p[0]["steps"][0]["ways"][0]["what"]


def test_nothing_to_chain_means_no_path_and_unread_settings_open_nothing():
    assert run(config={"smb_signing_required": False})[0] == []  # lateral only: nothing gets an attacker there
    assert run(rec("CVE-2026-1001", LOCAL), config={"wdigest": None})[0] == []  # can't tell is never a weakness
    assert run(rec("CVE-2026-1001", LOCAL, fixed=BUILD), config={"wdigest": 1})[0] == []  # fixed: not a step
    assert W11 in doc()["packages"][0]["name"]
