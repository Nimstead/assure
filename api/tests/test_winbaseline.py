"""Benchmark references (DECISIONS 75): the XCCDF script stays out on any doubt, the tables hold facts and no benchmark text, the
agent reads only its closed list, and "can't tell" never reads as a fail."""

import csv
import importlib.util
import io
import json
import re
import subprocess
from pathlib import Path

import pytest
from test_agent_proxy import agent
from test_api import user

from nimstead import winbaseline
from nimstead.winbaseline import FAIL, NOT_APPLICABLE, NOT_ASSESSED, PASS, reg_id

spec = importlib.util.spec_from_file_location("xccdf_rules", Path(__file__).parents[2] / "scripts" / "xccdf_rules.py")
xccdf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(xccdf)

BLOCK = "Registry Hive: HKEY_LOCAL_MACHINE\nRegistry Path: \\SOFTWARE\\Policies\\Example\\\n\nValue Name: Thing\n\nType: REG_DWORD\nValue: {}\n"
STOCK = "If the following registry value does not exist or is not configured as specified, this is a finding:\n\n"


def reg(value, before=STOCK, after=""):
    return xccdf.classify(before + BLOCK.format(value) + after, "WN25-CC-000010")


@pytest.mark.parametrize(("value", "want"), [
    ("0x00000001 (1)", {"eq": 1}),
    ("1", {"eq": 1}),
    ("0x00008000 (32768) (or greater)", {"ge": 32768}),
    ("0x0000001e (30) (or less, but not 0)", {"le": 30, "min": 1}),
    ('0x00000384 (900) (or less, excluding "0" which is effectively disabled)', {"le": 900, "min": 1}),
    ("1, 3, or 8", {"in": [1, 3, 8]}),
    ("0x00000000 (0) (or if the Value Name does not exist)", {"absent_ok": True, "eq": 0}),
    ("0x00000002 (2) (Prompt for consent)", {"eq": 2}),
])
def test_expected_values_understood(value, want):
    rule, why = reg(value)
    assert rule == {"scope": "all", "reg": ["SOFTWARE\\Policies\\Example", "Thing"], "want": want}, why


@pytest.mark.parametrize(("kw", "why"), [
    ({"value": "0x49960800 (5120000) (or greater)"}, "expected value"),  # hex and decimal disagree
    ({"value": "See message text below"}, "expected value"),
    ({"value": "1", "after": "\nIf the system has a camera, this is not applicable.\n"}, "condition"),
    ({"value": "1", "after": "\nAny sentence nobody has read yet.\n"}, "condition"),
])
def test_anything_unclear_stays_manual(kw, why):
    rule, reason = reg(**kw)
    assert rule is None and why in reason


def test_other_shapes_stay_manual():
    assert xccdf.classify("Run this tool and read the result.", "WN25-00-000010")[0] is None
    assert xccdf.classify(STOCK + BLOCK.format("1").replace("HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER"), "WN25-UC-000010")[0] is None
    two = BLOCK.format("1") + "\nValue Name: Other\nType: REG_DWORD\nValue: 1\n"
    assert xccdf.classify(STOCK + two, "WN25-CC-000010")[0] is None
    assert xccdf.classify(STOCK + BLOCK.format("1").replace("Example\\", "Example\\[guid]\\"), "WN25-CC-000010")[0] is None


def test_applicability_comes_from_text_and_id():
    dc = "This applies to domain controllers. It is not applicable for other systems.\n\n"
    assert xccdf.classify(dc + STOCK + BLOCK.format("1"), "WN25-DC-000010")[0]["scope"] == "dc"
    assert xccdf.classify(STOCK + BLOCK.format("1"), "WN25-DC-000010")[0]["scope"] == "dc"
    assert xccdf.classify(STOCK + BLOCK.format("1"), "WN25-MS-000010")[0]["scope"] == "not_dc"
    assert xccdf.classify(dc + STOCK + BLOCK.format("1"), "WN25-MS-000010")[0] is None  # disagree: left to a person


def test_doctype_is_refused_before_parsing(tmp_path):
    bomb = tmp_path / "x.xml"
    bomb.write_text('<!DOCTYPE b [<!ENTITY a "aaaa">]><Benchmark>&a;</Benchmark>')
    with pytest.raises(SystemExit, match="DOCTYPE"):
        xccdf.load_benchmark(str(bomb))


def test_build_reads_ids_and_version(tmp_path):
    ns = 'xmlns="http://checklists.nist.gov/xccdf/1.1"'
    body = (f'<Benchmark {ns}><plain-text id="release-info">Release: 4 Benchmark Date: 30 Sep 2026</plain-text><plain-text id="generator">3.5</plain-text>'
            f'<version>1</version><Group id="V-1"><Rule id="SV-1r1" severity="high"><version>WN25-CC-000010</version><check><check-content>{STOCK}{BLOCK.format("1")}</check-content></check></Rule></Group>'
            '<Group id="V-2"><Rule id="SV-2r1" severity="low"><version>WN25-00-000010</version><check><check-content>Ask someone.</check-content></check></Rule></Group></Benchmark>')
    f = tmp_path / "x.xml"
    f.write_text(body)
    table, why = xccdf.build(xccdf.load_benchmark(str(f)), "t", "T", "^T", "src", "hash")
    assert (table["version"], table["date"], table["total"]) == ("V1R4", "30 Sep 2026", 2)
    assert table["rules"][0]["id"] == "WN25-CC-000010" and table["rules"][0]["sev"] == "high"
    assert table["not_automated"] == [{"id": "WN25-00-000010", "v": "V-2", "sev": "low"}] and why[0][0] == "WN25-00-000010"


# ---- the shipped tables

RULE_KEYS = {"id", "v", "sev", "scope", "reg", "want", "no_core", "audit", "label", "bit", "right", "only", "require", "require_domain", "exception"}


def test_tables_hold_facts_and_no_benchmark_text():
    assert {b["id"] for b in winbaseline.baselines()} == {"windows-server-2025", "windows-11"}
    for b in winbaseline.baselines():
        assert b["total"] == len(b["rules"]) + len(b["not_automated"])
        for r in b["rules"]:
            assert set(r) <= RULE_KEYS and r["sev"] in ("high", "medium", "low")
        assert not ({k for x in b["not_automated"] for k in x} - {"id", "v", "sev"})
        assert max(len(s) for s in json.dumps(b).split('"')) < 150  # no sentence of anyone's text fits


def test_every_registry_rule_is_on_the_agents_closed_list():
    closed = {agent.baseline_id(e) for e in agent.BASELINE_REG}
    assert len(closed) == len(agent.BASELINE_REG) <= 200  # facts_ok: at most 200 keys in a dict
    used = {reg_id(*r["reg"]) for b in winbaseline.baselines() for r in b["rules"] if "reg" in r}
    assert used == closed  # nothing missing, and the agent reads nothing no rule needs
    for b in winbaseline.baselines():
        assert {r["audit"] for r in b["rules"] if "audit" in r} <= set(agent.BASELINE_AUDIT)
        assert {r["right"] for r in b["rules"] if "right" in r} <= set(agent.BASELINE_RIGHTS)
    assert not any("'" in e or ";" in e for e in agent.BASELINE_REG)  # how PS_BASELINE carries them
    assert len(agent.PS_BASELINE) < 30_000  # a command line tops out at 32,767 characters


def rule_of(baseline, rid):
    return next(r for r in next(b for b in winbaseline.baselines() if b["id"] == baseline)["rules"] if r["id"] == rid)


# ---- judging

SERVER = "Windows Server 2025 Standard 24H2 (AMD64) build 10.0.26100.32230"


def statuses(values, os_name=SERVER, **facts):
    out = winbaseline.evaluate(os_name, {"baseline": {"reg": values}, "domain_role": 3, "installation_type": "Server", **facts})
    return out, {r["id"]: r["status"] for r in out["rules"]}


def rid_of(rule):
    return reg_id(*rule["reg"])


def test_baseline_is_chosen_by_os():
    assert winbaseline.for_host(SERVER)["id"] == "windows-server-2025"
    assert winbaseline.for_host("Windows 11 Pro 24H2 (AMD64) build 10.0.26100.1")["id"] == "windows-11"
    for other in ("Windows Server 2022 Standard", "Windows 10 Pro", "Debian GNU/Linux 12", "", None):
        assert winbaseline.evaluate(other, {}) is None


@pytest.mark.parametrize(("rid", "value", "want"), [
    ("WN25-CC-000430", 0, PASS),
    ("WN25-CC-000430", 1, FAIL),
    ("WN25-CC-000430", None, FAIL),  # not set, and this rule says that's a finding
    ("WN25-CC-000430", "0", FAIL),  # wrong type: Windows won't read it as a number
    ("WN25-CC-000310", None, PASS),  # not set is fine for this one
    ("WN25-CC-000310", 1, FAIL),
    ("WN25-CC-000250", 1, PASS),
    ("WN25-CC-000250", 2, FAIL),
    ("WN25-SO-000100", 30, PASS),
    ("WN25-SO-000100", 0, FAIL),  # at most 30, but not 0
    ("WN25-SO-000100", 31, FAIL),
    ("WN25-MS-000050", "4", PASS),  # a number kept as text
    ("WN25-MS-000050", "5", FAIL),
    ("WN25-MS-000050", 4, FAIL),
    ("WN25-MS-000060", "O:BAG:BAD:(A;;RC;;;BA)", PASS),
    ("WN25-MS-000060", "O:BAG:BAD:", FAIL),
])
def test_values_are_judged(rid, value, want):
    r = rule_of("windows-server-2025", rid)
    assert statuses({rid_of(r): value})[1][rid] == want


def test_a_value_the_agent_did_not_read_is_not_assessed():
    out, st = statuses({})
    assert set(st.values()) <= {NOT_ASSESSED, NOT_APPLICABLE} and out["pass"] == out["fail"] == 0
    assert winbaseline.evaluate(SERVER, None)["fail"] == 0  # an agent older than this, or no facts at all
    assert winbaseline.evaluate(SERVER, {"baseline": "junk"})["fail"] == 0
    assert winbaseline.evaluate(SERVER, {"baseline": {"reg": "junk"}})["fail"] == 0


def test_applicability():
    dc, member = rule_of("windows-server-2025", "WN25-DC-000330"), rule_of("windows-server-2025", "WN25-MS-000030")
    values = {rid_of(dc): 1, rid_of(member): 1}  # both wrong, so a judged rule reads fail
    assert statuses(values, domain_role=3)[1][dc["id"]] == NOT_APPLICABLE and statuses(values, domain_role=3)[1][member["id"]] == FAIL
    assert statuses(values, domain_role=5)[1][dc["id"]] == FAIL and statuses(values, domain_role=5)[1][member["id"]] == NOT_APPLICABLE
    assert statuses(values, domain_role=2)[1][member["id"]] == NOT_APPLICABLE  # standalone: member-only
    for unknown in (None, "3", True, 9):
        st = statuses(values, domain_role=unknown)[1]
        assert st[dc["id"]] == NOT_ASSESSED and st[member["id"]] == NOT_ASSESSED  # never judged when we can't tell


def test_uac_rules_need_to_know_the_install_type():
    r = rule_of("windows-server-2025", "WN25-SO-000440")
    assert r["no_core"] is True
    assert statuses({rid_of(r): 0})[1][r["id"]] == FAIL
    assert statuses({rid_of(r): 0}, installation_type="Server Core")[1][r["id"]] == NOT_APPLICABLE
    assert statuses({rid_of(r): 0}, installation_type=None)[1][r["id"]] == NOT_ASSESSED


# ---- audit policy and user rights (by GUID and SID: DECISIONS 68, 76)

GUID_LOGON = "{0CCE9215-69AE-11D9-BED3-505054503030}"


def test_audit_rules_read_the_numeric_setting():
    ok, fail = rule_of("windows-server-2025", "WN25-AU-000190"), rule_of("windows-server-2025", "WN25-AU-000200")  # logon success, failure
    assert ok["audit"] == fail["audit"] == GUID_LOGON and (ok["bit"], fail["bit"]) == (1, 2)
    def audit(v):
        return winbaseline.evaluate(SERVER, {"baseline": {"audit": {GUID_LOGON: v}}, "domain_role": 3})
    def status(v, rid):
        return next(r["status"] for r in audit(v)["rules"] if r["id"] == rid)
    assert (status(3, ok["id"]), status(3, fail["id"])) == (PASS, PASS)
    assert (status(1, ok["id"]), status(1, fail["id"])) == (PASS, FAIL)
    assert (status(2, ok["id"]), status(2, fail["id"])) == (FAIL, PASS)
    assert (status(0, ok["id"]), status(0, fail["id"])) == (FAIL, FAIL)
    for junk in (None, 7, True, "3"):
        assert status(junk, ok["id"]) == NOT_ASSESSED


def rights(rid, held, baseline="windows-server-2025", role=3):
    r = rule_of(baseline, rid)
    os_name = SERVER if baseline == "windows-server-2025" else "Windows 11 Pro"
    facts = {"baseline": {"rights": {r["right"]: held}}, "domain_role": role, "installation_type": "Server"}
    return next(x for x in winbaseline.evaluate(os_name, facts)["rules"] if x["id"] == rid)


DOMAIN = "S-1-5-21-1-2-3"


@pytest.mark.parametrize(("rid", "held", "want"), [
    ("WN25-UR-000020", [], PASS),  # nobody may hold it
    ("WN25-UR-000020", ["S-1-5-32-544"], FAIL),
    ("WN25-UR-000100", ["S-1-5-32-544"], PASS),  # held only by Administrators
    ("WN25-UR-000100", [], PASS),
    ("WN25-UR-000100", ["S-1-5-32-544", f"{DOMAIN}-1105"], FAIL),
    ("WN25-UR-000100", ["S-1-5-32-544", "?"], NOT_ASSESSED),  # a holder we couldn't name by SID
    ("WN25-UR-000100", None, NOT_ASSESSED),
    ("WN25-MS-000110", ["S-1-5-32-546", f"{DOMAIN}-512", f"{DOMAIN}-519"], PASS),  # deny right: must include
    ("WN25-MS-000110", ["S-1-5-32-546", f"{DOMAIN}-512", f"{DOMAIN}-519", "S-1-5-32-555"], PASS),  # more is fine
    ("WN25-MS-000110", ["S-1-5-32-546", f"{DOMAIN}-512"], FAIL),
    ("WN25-MS-000110", ["S-1-5-32-546", "S-1-5-21-1-2-3-1512"], FAIL),  # a RID that merely ends in 512
])
def test_rights_are_judged_by_sid(rid, held, want):
    assert rights(rid, held)["status"] == want


def test_domain_only_holders_need_a_domain():
    assert rights("WN25-MS-000110", ["S-1-5-32-546"], role=2)["status"] == PASS  # standalone: Guests is enough
    assert rights("WN25-MS-000110", ["S-1-5-32-546"], role=3)["status"] == FAIL
    assert rights("WN25-MS-000110", ["S-1-5-32-546"], role=None)["status"] == NOT_ASSESSED


def test_a_fail_on_a_right_with_exceptions_says_so():
    assert "exception" in rights("WN25-UR-000020", ["S-1-5-32-544"])["note"]
    assert rights("WN25-UR-000020", [])["note"] == ""


def test_no_translated_words_are_read():
    """DECISIONS 68: nothing in the collector compares against a name Windows translates."""
    assert not re.search(r"Success|Failure|Erfolg|BUILTIN|NT AUTHORITY|\bAdministrators\b", agent.PS_BASELINE)
    assert "/get" not in agent.PS_BASELINE  # that table has only translated settings, no number


def run_collector_regex(line):
    return re.search(r"(\{[0-9A-Fa-f-]{36}\}),.*,([0-3])\s*$", line)


@pytest.mark.parametrize("line", [
    r"HOST,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success and Failure,,3",
    r"HOST,System,Anmelden,{0CCE9215-69AE-11D9-BED3-505054503030},Erfolg und Fehler,,3",
    r'HOST,System,"Abmelden, lokal",{0CCE9215-69AE-11D9-BED3-505054503030},"Erfolg, Fehler",,3',
])
def test_audit_table_rows_read_alike_in_any_language(line):
    m = run_collector_regex(line)
    assert m.group(1) == GUID_LOGON and m.group(2) == "3"
    assert re.search(re.escape(m.re.pattern), agent.PS_BASELINE.replace("\\", "\\"))


@pytest.mark.skipif(agent.os.name != "nt", reason="needs PowerShell")
def test_collector_script_parses(tmp_path):
    """Parsed, not run: PowerShell only checks the syntax here."""
    f = tmp_path / "s.ps1"
    f.write_text(agent.PS_BASELINE, encoding="utf-8-sig")
    check = f"$e = $null; [void][Management.Automation.Language.Parser]::ParseFile('{f}', [ref]$null, [ref]$e); $e.Count"
    out = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", check], capture_output=True, text=True, check=True).stdout
    assert out.strip() == "0"


# ---- the agent's collector

KEY = agent.BASELINE_REG[0]


def fake(answer):
    return lambda cmd, **kw: (0, json.dumps(answer))


def test_collector_keeps_only_its_closed_list():
    other = agent.BASELINE_REG[1]
    third = agent.BASELINE_REG[2]
    got = agent.windows_baseline_facts(fake({"reg": {KEY: 1, other: None, third: [1, 2], "HKLM\\planted|x": 7}}))
    assert got["reg"] == {agent.baseline_id(KEY): 1, agent.baseline_id(other): None}  # a list is a type no rule expects: not assessed


def test_collector_checks_audit_and_rights():
    g, r = agent.BASELINE_AUDIT[0], agent.BASELINE_RIGHTS[0]
    other = agent.BASELINE_RIGHTS[1]
    third = agent.BASELINE_RIGHTS[2]
    got = agent.windows_baseline_facts(fake({"reg": {}, "audit": {g: 3, "{planted}": 1, agent.BASELINE_AUDIT[1]: 9},
                                             "rights": {r: ["S-1-5-32-544", "?"], other: ["Administrators"], third: "S-1-5-32-544", "SePlanted": []}}))
    assert got["audit"] == {g: 3} and got["rights"] == {r: ["S-1-5-32-544", "?"]}  # names and other shapes aren't kept


def test_collector_failures_cost_only_these_rules():
    assert agent.windows_baseline_facts(lambda cmd, **kw: (1, "boom")) is None
    assert agent.windows_baseline_facts(lambda cmd, **kw: (0, "not json")) is None
    assert agent.windows_baseline_facts(fake(["reg"])) is None
    assert agent.windows_baseline_facts(fake({"reg": "x"})) is None


def test_collector_caps_its_size():
    long = ["S-1-5-21-1111111111-2222222222-3333333333-1234"] * 30
    answer = {"reg": dict.fromkeys(agent.BASELINE_REG, "x" * 5000), "audit": dict.fromkeys(agent.BASELINE_AUDIT, 3), "rights": dict.fromkeys(agent.BASELINE_RIGHTS, long)}
    got = agent.windows_baseline_facts(fake(answer))
    assert len(json.dumps(got)) < agent.BASELINE_MAX_BYTES  # the longest rights lists are what gives way, not the rest of the report
    assert got["rights"] == {} and len(got["reg"]) == len(agent.BASELINE_REG) and len(got["audit"]) == len(agent.BASELINE_AUDIT)


def test_results_are_not_findings_and_the_report_fits(env):
    c = user(env)
    token = c.post("/api/enroll-tokens").json()["token"]
    a = c.post("/api/agent/enroll", json={"token": token, "hostname": "srv", "ecosystem": "Windows"}).json()
    h = {"Authorization": f"Bearer {a['agent_key']}"}
    # the most the agent can send, beside a large but plausible report: the server keeps facts whole or drops them all
    baseline = {"reg": {agent.baseline_id(e): "x" * 100 for e in agent.BASELINE_REG}, "audit": dict.fromkeys(agent.BASELINE_AUDIT, 3),
                "rights": {r: ["S-1-5-21-1-2-3-500"] * 8 for r in agent.BASELINE_RIGHTS}}
    assert len(json.dumps(baseline)) < agent.BASELINE_MAX_BYTES
    facts = {"baseline": baseline, "domain_role": 3, "installation_type": "Server", "roles": ["R" * 30] * 400,
             "config": {f"k{i}": 1 for i in range(100)}}
    r = c.post("/api/agent/inventory", headers=h, json={"os_name": SERVER, "ecosystem": "Windows", "packages": [], "facts": facts})
    assert r.status_code == 200
    from nimstead.db import Asset, make_sessionmaker
    with make_sessionmaker(env)() as s:  # stored whole; the asset list leaves baseline out (DECISIONS 101)
        assert s.query(Asset).filter_by(hostname="srv").one().facts.get("baseline") == baseline
    assert not [x for x in c.get("/api/findings").json() if x["ecosystem"] != "WinConfig"]  # the host's own config checks may fire


# ---- the view and the export (W20)


def enrol_host(c, name, os_name=SERVER, facts=None, ecosystem="Windows"):
    token = c.post("/api/enroll-tokens").json()["token"]
    a = c.post("/api/agent/enroll", json={"token": token, "hostname": name, "ecosystem": ecosystem}).json()
    r = c.post("/api/agent/inventory", headers={"Authorization": f"Bearer {a['agent_key']}"},
               json={"os_name": os_name, "ecosystem": ecosystem, "packages": [], "facts": facts or {}})
    assert r.status_code == 200
    return a["asset_id"]


def test_host_and_fleet_views(env):
    c = user(env)
    r = rule_of("windows-server-2025", "WN25-CC-000430")
    good = enrol_host(c, "srv-good", facts={"domain_role": 3, "installation_type": "Server", "baseline": {"reg": {rid_of(r): 0}}})
    enrol_host(c, "srv-bad", facts={"domain_role": 3, "installation_type": "Server", "baseline": {"reg": {rid_of(r): 1}}})
    enrol_host(c, "win11", os_name="Windows 11 Pro 25H2 (AMD64) build 10.0.26200.1", facts={"domain_role": 1})
    enrol_host(c, "old", os_name="Windows Server 2019 Standard")
    enrol_host(c, "linux", os_name="Debian 12", ecosystem="Debian:12")
    got = c.get("/api/baselines").json()
    assert got["no_baseline"] == 1  # the 2019 host; Linux isn't a Windows host at all
    assert {h["hostname"] for h in got["hosts"]} == {"srv-good", "srv-bad", "win11"} and not any("rules" in h for h in got["hosts"])
    server = next(b for b in got["baselines"] if b["baseline_id"] == "windows-server-2025")
    assert (server["version"], server["hosts"], server["pass"], server["fail"]) == ("V1R4", 2, 1, 1)
    assert server["manual"] == 291 - server["automated"]
    assert next(b for b in got["baselines"] if b["baseline_id"] == "windows-11")["hosts"] == 1
    one = c.get(f"/api/baselines/{good}").json()
    row = next(x for x in one["rules"] if x["id"] == "WN25-CC-000430")
    assert row["status"] == PASS and row["found"] == "0" and "AlwaysInstallElevated" in row["setting"]


def test_views_are_per_tenant_and_a_host_without_a_baseline_says_so(env):
    a, b = user(env), user(env, "b@example.com")
    host = enrol_host(a, "srv")
    assert b.get(f"/api/baselines/{host}").status_code == 404
    assert b.get("/api/baselines").json()["hosts"] == []
    old = enrol_host(a, "old", os_name="Windows Server 2019 Standard")
    assert a.get(f"/api/baselines/{old}").status_code == 404


def test_export_is_csv_injection_safe_and_lists_manual_rules(env):
    c = user(env)
    r = rule_of("windows-server-2025", "WN25-CC-000430")
    enrol_host(c, "=cmd|calc", facts={"domain_role": 3, "installation_type": "Server", "baseline": {"reg": {rid_of(r): "=2+2"}}})
    res = c.get("/api/baselines.csv")
    assert res.status_code == 200 and res.headers["content-type"].startswith("text/csv")
    rows = list(csv.reader(io.StringIO(res.text)))
    assert rows[0][:3] == ["hostname", "baseline", "version"]
    body = rows[1:]
    assert len(body) == 291
    assert all(x[0] == "'=cmd|calc" for x in body)
    assert next(x for x in body if x[3] == "WN25-CC-000430")[9] == "'=2+2"
    assert sum(x[6] == "not assessed (manual)" for x in body) == 291 - len(next(b for b in winbaseline.baselines() if b["id"] == "windows-server-2025")["rules"])
    assert "conform" not in res.text.lower()


def test_a_tools_error_after_the_answer_doesnt_lose_the_answer():
    # real Windows 11: auditpol wrote "Error 0x00000522 occurred:" and its message after the JSON, and every rule read "not assessed"
    out = '{"reg": {}, "audit": {}, "rights": {}}\nError 0x00000522 occurred:\n\nA required privilege is not held by the client.\n'
    assert agent.windows_baseline_facts(lambda cmd, **kw: (0, out)) == {"reg": {}, "audit": {}, "rights": {}}
    assert "2>$null" in agent.PS_BASELINE.split("auditpol /backup")[1].splitlines()[0]
