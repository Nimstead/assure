"""The engine's first slice (docs/engine/design-e2.md): verdicts from a fake inventory, T-numbers from the spec."""

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest
from sqlalchemy import select
from test_agent_proxy import agent
from test_api import user

from nimstead import engine
from nimstead.db import Advisory, Asset, Finding, InstalledPackage, Kev, ScanRecord, make_sessionmaker
from nimstead.engine import parity, report
from nimstead.engine.collection import Inventory, valid_document
from nimstead.engine.content import Content
from nimstead.engine.evaluate import evaluate
from nimstead.engine.model import Grade, Outcome

W11 = "Windows 11 Version 25H2 for x64-based Systems"
BUILD = "10.0.26200.7000"
SEVEN = "7-zip:7-zip"


def msrc(cve, fixed, kb="5066835", product=W11, eco="Windows"):
    return {"id": f"MSRC-{cve}-1", "aliases": [cve], "modified": "2026-10-14T07:00:00", "summary": f"Flaw {cve} (KB{kb})",
            "database_specific": {"kb": kb, "hotpatch": False},
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            "affected": [{"package": {"ecosystem": eco, "name": product}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}]}]}


def nvd(cve, fixed, key=SEVEN):
    return {"id": cve, "aliases": [], "modified": "2026-10-01T00:00:00", "summary": f"Flaw {cve}",
            "affected": [{"package": {"ecosystem": "WinApp", "name": key}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}]}]}


def content(*os_recs, apps=(), ms=None, **kw):
    recs = {("Windows", W11): list(os_recs), ("WinApp", SEVEN): list(apps), **{("Microsoft", k): v for k, v in (ms or {}).items()}}
    return Content.make(recs, feeds=kw.pop("feeds", ("Windows", "WinApp", "Microsoft")), **kw)


def ok(n=0):
    return {"state": "ok", "count": n}


def doc(*pkgs, sources=None, facts=None, build=BUILD):
    os_pkg = [{"ecosystem": "Windows", "name": W11, "version": build, "source": None}] if build else []
    pkgs = [*os_pkg, *pkgs]
    if not any(p["ecosystem"] == "WinApp" for p in pkgs):  # every Windows lists something (R4.3): here, nothing in the curated map
        pkgs.append({"ecosystem": "WinApp", "name": "Some Inventory Tool", "version": "1.0", "source": "Acme"})

    def count(eco):
        return sum(p["ecosystem"] == eco for p in pkgs)
    src = {"windows_build": ok(count("Windows")), "uninstall": ok(count("WinApp")), "user_hives": ok(), "microsoft_products": ok(count("Microsoft")), "host_facts": ok(11)}
    return {"hostname": "lab-1", "os_name": "Windows 11 Pro", "ecosystem": "Windows", "agent_version": "0.4.0", "facts": {"pending_reboot": False, **(facts or {})},
            "collection": {"v": 1, "sources": {**src, **(sources or {})}}, "packages": pkgs}


def app(name="7-Zip 24.08 (x64)", version="24.08"):
    return {"ecosystem": "WinApp", "name": name, "version": version, "source": "Igor Pavlov"}


def run(d, c, prior=()):
    return evaluate(Inventory.from_doc(d), c, prior)


def one(verdicts, **kw):
    hit = [v for v in verdicts if all(getattr(v, k) == x for k, x in kw.items())]
    assert len(hit) == 1, (kw, hit)
    return hit[0]


def determined(verdicts):
    return [v for v in verdicts if v.outcome in (Outcome.VULNERABLE, Outcome.NOT_VULNERABLE)]


# ---- Windows (spec section 12)

def test_t14_t17_a_patched_host_never_installed_the_old_update_and_has_no_hotfix_list():
    c = content(msrc("CVE-2026-1", "10.0.26200.6000", kb="5000001"), msrc("CVE-2026-2", "10.0.26200.7000", kb="5000002"))
    vs = run(doc(), c)
    assert {v.vuln_id: (v.outcome, v.grade) for v in determined(vs)} == {
        "CVE-2026-1": (Outcome.NOT_VULNERABLE, Grade.CONFIRMED), "CVE-2026-2": (Outcome.NOT_VULNERABLE, Grade.CONFIRMED)}
    assert report.build(Inventory.from_doc(doc()), c, vs)["headline"]["status"] == "no-known-vulnerabilities"


@pytest.mark.parametrize("build,want", [("10.0.26200.6999", Outcome.VULNERABLE), ("10.0.26200.7000", Outcome.NOT_VULNERABLE), ("10.0.26200.7001", Outcome.NOT_VULNERABLE)])
def test_t15_one_revision_below_the_fix_is_vulnerable_at_the_fix_is_not(build, want):
    v = one(run(doc(build=build), content(msrc("CVE-2026-1", BUILD))), vuln_id="CVE-2026-1")
    assert v.outcome == want and v.grade == Grade.CONFIRMED and v.source == "MSRC" and v.fixed == BUILD
    assert v.version == build and "registry" in v.observed and v.cvss == 9.8


def test_t16_a_pending_restart_is_reported_as_pending_never_as_fixed():
    d = doc(facts={"pending_reboot": True})
    at_fix = one(run(d, content(msrc("CVE-2026-1", BUILD))), vuln_id="CVE-2026-1")
    assert (at_fix.outcome, at_fix.reason) == (Outcome.UNDETERMINED, "pending-reboot") and not at_fix.proves_absent
    below = one(run(d, content(msrc("CVE-2026-1", "10.0.26200.7001"))), vuln_id="CVE-2026-1")
    assert below.outcome == Outcome.VULNERABLE and below.pending_reboot
    assert "restart is waiting" in report.render(report.build(Inventory.from_doc(d), content(msrc("CVE-2026-1", "10.0.26200.7001")), [below]))


def test_t18_build_read_denied_is_not_run_access_denied_naming_what_was_refused():
    d = doc(build=None, facts={"os_unmatched": "no exact MSRC product"}, sources={
        "windows_build": {"state": "failed", "count": 0, "error": r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion: access denied", "code": "access-denied"}})
    vs = run(d, content())
    v = one(vs, check="product:windows")
    assert (v.outcome, v.reason, v.blocker) == (Outcome.NOT_RUN, "access-denied", "windows_build") and "CurrentVersion" in v.detail
    r = report.build(Inventory.from_doc(d), content(), vs)
    assert r["headline"]["status"] == "not-assessed" and "This host's Windows patch state was not assessed." in r["coverage"]["statements"]


def test_t19_two_versions_side_by_side_get_a_verdict_each():
    d = doc(app("7-Zip 19.00 (x64)", "19.00"), app("7-Zip 24.08 (x64)", "24.08"))
    vs = [v for v in run(d, content(apps=[nvd("CVE-2026-9", "20.00")])) if v.vuln_id == "CVE-2026-9"]
    assert {v.instance: v.outcome for v in vs} == {"7-Zip 19.00 (x64) 19.00": Outcome.VULNERABLE, "7-Zip 24.08 (x64) 24.08": Outcome.NOT_VULNERABLE}
    assert {v.grade for v in vs} == {Grade.REASONABLE} and {v.source for v in vs} == {"NVD"}
    assert all("NVD" in v.detail for v in vs)


def test_a_dotnet_folder_is_confirmed_and_an_uninstall_entry_only_reasonable():
    net, edge = ".NET 8.0 runtime", "Microsoft Edge"
    d = doc({"ecosystem": "Microsoft", "name": ".NET runtime", "version": "8.0.10", "source": "native"},
            {"ecosystem": "WinApp", "name": edge, "version": "140.0.1.1", "source": "Microsoft Corporation"})
    vs = run(d, content(ms={net: [msrc("CVE-2026-3", "8.0.11", product=net, eco="Microsoft")], edge: [msrc("CVE-2026-4", "141.0.0.0", product=edge, eco="Microsoft")]}))
    assert one(vs, vuln_id="CVE-2026-3").grade == Grade.CONFIRMED and one(vs, vuln_id="CVE-2026-4").grade == Grade.REASONABLE
    assert one(vs, vuln_id="CVE-2026-3").instance == ".NET runtime 8.0.10 (native)"
    assert "NVD" not in one(vs, vuln_id="CVE-2026-4").detail  # Microsoft states this fix, not NVD (seen wrong on a real VM)


# ---- verdict integrity

def test_t3_a_list_shorter_than_what_was_read_is_incomplete_and_absent_is_not_not_applicable():
    d = doc(app(), sources={"uninstall": ok(40)})  # the agent read 40, one arrived
    vs = run(d, content(apps=[nvd("CVE-2026-9", "20.00")]))
    v = one(vs, check="product:mozilla:firefox")
    assert (v.outcome, v.reason, v.blocker) == (Outcome.UNDETERMINED, "source-partial", "uninstall") and "read 40" in v.detail
    assert one(vs, vuln_id="CVE-2026-9").grade == Grade.UNVERIFIED
    assert not [x for x in vs if x.outcome == Outcome.NOT_APPLICABLE and x.family == "app"]


def test_r43_an_empty_uninstall_list_is_a_failure_not_a_clean_host():
    d = doc()
    d["packages"] = [p for p in d["packages"] if p["ecosystem"] != "WinApp"]
    d["collection"]["sources"]["uninstall"] = ok(0)
    v = one(run(d, content()), check="product:google:chrome")
    assert (v.outcome, v.reason) == (Outcome.NOT_RUN, "empty-list")


def test_t5_a_failed_producer_stops_what_depends_on_it_and_is_named():
    d = doc(sources={"microsoft_products": {"state": "failed", "count": 0, "error": "Microsoft product check failed: timed out"}})
    vs = run(d, content())
    v = one(vs, check="product:.NET runtime")
    assert (v.outcome, v.reason, v.blocker) == (Outcome.NOT_RUN, "precondition-unknown", "microsoft_products") and "timed out" in v.detail
    assert one(vs, check="product:google:chrome").outcome == Outcome.NOT_APPLICABLE  # other sources are unaffected


def test_an_old_agent_is_never_clean():
    d = doc(app())
    del d["collection"]
    c = content(msrc("CVE-2026-1", BUILD), apps=[nvd("CVE-2026-9", "20.00")])
    inv = Inventory.from_doc(d)
    vs = evaluate(inv, c)
    assert one(vs, vuln_id="CVE-2026-1").grade == Grade.UNVERIFIED
    assert not [v for v in vs if v.outcome == Outcome.NOT_APPLICABLE]
    v = one(vs, check="product:google:chrome")
    assert (v.outcome, v.reason) == (Outcome.NOT_RUN, "no-collection-document")
    r = report.build(inv, c, vs)
    assert r["headline"]["status"] == "undetermined" and "NOT CLEAN" in r["headline"]["text"]
    assert "doesn't say what it managed to read" in report.render(r)


def test_a_document_that_breaks_the_rules_reads_as_not_reported():
    for bad in ({"v": 1, "sources": {}}, {"v": 2, "sources": {"uninstall": ok()}}, {"v": 1, "sources": {"Bad Name": ok()}}, {"v": 1, "sources": {"uninstall": {"state": "fine"}}},
                {"v": 1, "sources": {"uninstall": {"state": "ok", "count": -1}}}, {"v": 1, "sources": {"uninstall": {"state": "ok", "count": True}}},
                {"v": 1, "sources": {"uninstall": {"state": "ok", "extra": 1}}}, {"v": 1, "sources": {"uninstall": {"state": "failed", "error": "x" * 301}}},
                {"v": 1, "sources": {f"s{'a' * i}": ok() for i in range(17)}}, "ok", None):
        assert not valid_document(bad), bad
    d = doc()
    d["collection"] = {"v": 2, "sources": {}}
    assert Inventory.from_doc(d).source("uninstall").reason == "no-collection-document"


def test_t7_an_open_finding_with_no_evidence_stays_open_and_flagged_and_only_evidence_closes_it():
    gone = doc(sources={"uninstall": {"state": "failed", "count": 0, "error": "access denied", "code": "access-denied"}})
    prior = [("WinApp", SEVEN, "CVE-2026-9"), ("WinConfig", "smb-signing", "smb-off")]
    vs = run(gone, content(), prior)
    v = one(vs, vuln_id="CVE-2026-9")
    assert (v.outcome, v.reason, v.grade) == (Outcome.UNDETERMINED, "not-reassessed", Grade.UNVERIFIED) and not v.proves_absent
    assert not [x for x in vs if x.vuln_id == "smb-off"]  # not this slice's to judge
    removed = run(doc(), content(), prior)  # the list was read in full and it isn't there: positive evidence
    assert not [x for x in removed if x.vuln_id == "CVE-2026-9"] and one(removed, check=f"product:{SEVEN}").proves_absent


# ---- version logic

def test_t10_versions_that_cannot_be_compared_are_undetermined():
    bad = nvd("CVE-2026-9", "not-a-version")
    v = one(run(doc(app()), content(apps=[bad])), vuln_id="CVE-2026-9")
    assert (v.outcome, v.reason) == (Outcome.UNDETERMINED, "incomparable")
    refused = run(doc(app(version="beta-2")), content(apps=[nvd("CVE-2026-9", "20.00")]))
    v = one(refused, reason="unreadable-version")
    assert v.product == SEVEN and v.outcome == Outcome.UNDETERMINED and "beta-2" in v.observed
    assert not [x for x in refused if x.check == f"product:{SEVEN}" and x.outcome == Outcome.NOT_APPLICABLE]  # it's there, just unreadable


def test_r53_a_fix_from_another_release_line_is_not_compared():
    v = one(run(doc(), content(msrc("CVE-2026-1", "10.0.26100.9999"))), vuln_id="CVE-2026-1")
    assert (v.outcome, v.reason) == (Outcome.UNDETERMINED, "release-line")


def test_no_advisories_is_not_a_clean_answer():
    vs = run(doc(), Content.make({("Windows", W11): []}, feeds=()))
    assert (one(vs, check=f"product:{W11}").outcome, one(vs, check=f"product:{W11}").reason) == (Outcome.NOT_RUN, "feed-missing")
    v = one(run(doc(), content()), check=f"product:{W11}")
    assert (v.outcome, v.reason) == (Outcome.UNDETERMINED, "no-advisories")


def test_hotpatch_host_is_judged_on_the_hotpatch_track():
    hp = "10.0.26200.7005"
    hot = msrc("CVE-2026-1", hp) | {"id": "MSRC-CVE-2026-1-1-hotpatch"}
    c = Content.make({("Windows", W11): [msrc("CVE-2026-1", "10.0.26200.7100")], ("Windows", W11 + " (Hotpatch)"): [hot]}, feeds=("Windows",))
    assert one(run(doc(build=hp), c), vuln_id="CVE-2026-1").outcome == Outcome.NOT_VULNERABLE
    assert one(run(doc(build="10.0.26200.7004"), c), vuln_id="CVE-2026-1").outcome == Outcome.VULNERABLE


# ---- reproducibility and the report

def test_t34_same_inventory_and_content_same_verdicts_whatever_the_order():
    a, b = msrc("CVE-2026-1", "10.0.26200.7100"), msrc("CVE-2026-2", BUILD)
    d1, d2 = doc(app("7-Zip 19.00 (x64)", "19.00"), app()), doc(app(), app("7-Zip 19.00 (x64)", "19.00"))
    c1, c2 = content(a, b, apps=[nvd("CVE-2026-9", "20.00")]), content(b, a, apps=[nvd("CVE-2026-9", "20.00")])
    assert c1.version == c2.version and c1.version.startswith("2026-10-14.")
    assert report.digest(run(d1, c1)) == report.digest(run(json.loads(json.dumps(d2)), c2))
    assert content(msrc("CVE-2026-1", "10.0.26200.7200")).version != content(msrc("CVE-2026-1", "10.0.26200.7100")).version


def test_the_report_leads_with_what_is_vulnerable_groups_by_install_and_escapes_what_the_host_says():
    many = [msrc(f"CVE-2026-{n}", "10.0.26200.7100") for n in range(1, 13)]
    c = content(*many, apps=[nvd("CVE-2026-90", "20.00")], kev=["CVE-2026-7"])
    d = doc(app("7-Zip 19.00 (x64)", "19.00"), sources={"microsoft_products": {"state": "failed", "count": 0, "error": "evil\x1b[31m"}})
    d["hostname"] = "lab\x1b[2J"
    inv = Inventory.from_doc(d)
    r = report.build(inv, c, evaluate(inv, c))
    assert r["headline"]["status"] == "vulnerable" and [g["count"] for g in r["vulnerable"]] == [12, 1]
    assert r["vulnerable"][0]["known_exploited"] == 1 and r["vulnerable"][0]["vulnerabilities"][0]["id"] == "CVE-2026-7"
    assert r["vulnerable"][0]["action"] == "Install KB5066835, then restart"
    text = report.render(r)
    assert "\x1b" not in text and text.index("What's vulnerable") < text.index("What couldn't be determined") < text.index("Coverage")
    assert "and 7 more" in text and "CVE-2026-7 (known exploited)" in text
    json.dumps(r)


# ---- agent: an empty list and a failed read are different

class Reg:
    """winreg over {path: {subkey: values}} with the errors the real one raises."""
    HKEY_LOCAL_MACHINE, HKEY_USERS, HKEY_CURRENT_USER, KEY_READ, KEY_WOW64_64KEY, KEY_WOW64_32KEY = "HKLM", "HKU", "HKCU", 0, 0x100, 0x200

    def __init__(self, keys=None, denied=(), cut=None, values=None):
        self.keys, self.denied, self.cut, self.values = keys or {}, denied, cut, values or {}

    def OpenKey(self, root, path, *a):  # noqa: N802
        base = root if isinstance(root, str) else root["path"]
        full = f"{base}\\{path}"
        if any(full.endswith(x) for x in self.denied):
            raise PermissionError(13, "Zugriff verweigert")  # translated text must decide nothing
        if full not in self.keys and not any(k.startswith(full + "\\") for k in self.keys):
            raise FileNotFoundError(2, "nicht gefunden")
        return _Key(full, self.keys.get(full, {}))

    def EnumKey(self, k, i):  # noqa: N802
        if not isinstance(k, _Key):
            raise OSError(259, "no more")
        subs = sorted({x[len(k["path"]) + 1:].split("\\")[0] for x in self.keys if x.startswith(k["path"] + "\\")})
        if self.cut is not None and i >= self.cut:
            e = OSError(22, "cut")
            e.winerror = 1359
            raise e
        if i >= len(subs):
            e = OSError(22, "no more")
            e.winerror = 259
            raise e
        return subs[i]

    def QueryValueEx(self, k, n):  # noqa: N802
        if n not in k["values"]:
            raise FileNotFoundError(n)
        return k["values"][n], 1


class _Key(dict):
    def __init__(self, path, values):
        super().__init__(path=path, values=values)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


UN = agent.UNINSTALL


def entry(name):
    return {"DisplayName": name, "DisplayVersion": "1.0", "Publisher": "Acme"}


def test_windows_apps_tells_a_missing_key_from_a_refused_one_and_a_cut_short_list():
    problems = []
    assert agent.windows_apps(Reg(), problems=problems) == [] and problems == []  # nothing there: an empty list, read fine
    problems = []
    agent.windows_apps(Reg(denied=[UN]), problems=problems)
    assert problems and "access denied" in problems[0] and "Zugriff" not in problems[0]
    problems = []
    keys = {f"HKLM\\{UN}\\A": entry("A"), f"HKLM\\{UN}\\B": entry("B")}
    assert len(agent.windows_apps(Reg(keys, cut=1), problems=problems)) == 1 and "1359" in problems[0]


def test_collect_reports_a_document_the_server_accepts_on_clean_json(monkeypatch):
    keys = {r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion": {"CurrentBuild": "26200", "UBR": 7000, "DisplayVersion": "25H2", "ProductName": "Windows 11 Pro", "InstallationType": "Client", "EditionID": "Pro"},
            f"HKLM\\{UN}\\A": entry("A")}
    run_ = lambda cmd, **kw: (1, "denied")  # noqa: E731 - every PowerShell part fails
    inv = agent.collect_windows(Reg(keys), run_, "AMD64", lambda p: [])
    assert valid_document(inv["collection"]) and json.loads(json.dumps(inv))["collection"] == inv["collection"]
    src = inv["collection"]["sources"]
    assert src["windows_build"] == {"state": "ok", "count": 1} and src["uninstall"]["state"] == "ok"
    assert src["microsoft_products"]["state"] == "failed" and src["host_facts"]["state"] == "failed" and src["drivers"]["state"] == "failed"
    assert src["user_hives"]["state"] == "partial"  # remote: what isn't read over remoting is said, not skipped


def test_collect_survives_a_refused_build_read_and_says_so(monkeypatch):
    run_ = lambda cmd, **kw: (1, "x")  # noqa: E731
    inv = agent.collect_windows(Reg({f"HKLM\\{UN}\\A": entry("A")}, denied=["CurrentVersion"]), run_, "AMD64", lambda p: [])
    b = inv["collection"]["sources"]["windows_build"]
    assert (b["state"], b["code"]) == ("failed", "access-denied") and not [p for p in inv["packages"] if p["ecosystem"] == "Windows"]
    assert inv["facts"]["os_unmatched"] and [p["name"] for p in inv["packages"] if p["ecosystem"] == "WinApp"] == ["A"]


def test_remote_reg_says_refused_for_what_the_dump_reports_refused():
    r = agent.RemoteReg({"hkey_local_machine\\software\\a": {}}, ["hkey_local_machine\\software\\b"])
    r.OpenKey(r.HKEY_LOCAL_MACHINE, "SOFTWARE\\a")
    with pytest.raises(PermissionError):
        r.OpenKey(r.HKEY_LOCAL_MACHINE, "SOFTWARE\\b")
    with pytest.raises(FileNotFoundError):
        r.OpenKey(r.HKEY_LOCAL_MACHINE, "SOFTWARE\\c")


def test_collect_remote_reads_the_refused_list(monkeypatch):
    dump = {"host": "H", "machine": "AMD64", "dirs": {}, "denied": [f"hkey_local_machine\\{UN.lower()}"],
            "keys": {"hkey_local_machine\\software\\microsoft\\windows nt\\currentversion": {"values": {"CurrentBuild": "26200", "UBR": 1, "DisplayVersion": "25H2", "ProductName": "W", "InstallationType": "Client", "EditionID": "Pro"}, "subkeys": []}}}

    def run_(cmd, **kw):
        return (0, json.dumps(dump)) if "Invoke-Command" in " ".join(cmd) and not getattr(run_, "done", False) and not setattr(run_, "done", True) else (1, "no")
    _, inv = agent.collect_remote("H", run_)
    assert inv["collection"]["sources"]["uninstall"]["code"] == "access-denied"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows PowerShell")
@pytest.mark.parametrize("script", ["PS_REMOTE_DUMP", "PS_MICROSOFT"])
def test_the_powershell_parses(script):
    parse = "$e = $null; [void][Management.Automation.Language.Parser]::ParseInput(($input | Out-String), [ref]$null, [ref]$e); $e.Count"
    p = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", parse], input=getattr(agent, script), capture_output=True, text=True, timeout=60)
    assert p.stdout.strip() == "0", p.stdout + p.stderr


def test_valid_document_bounds_hold_for_the_largest_real_document():
    long = {"state": "partial", "count": 9_999, "error": "x" * 300, "code": "access-denied"}
    assert valid_document({"v": 1, "sources": {n: dict(long) for n in ("windows_build", "uninstall", "user_hives", "microsoft_products", "host_facts", "drivers")}})


# ---- end to end, against rescan

def seed(url):
    s = make_sessionmaker(url)()
    for eco, pkg, rec in [("Windows", W11, msrc("CVE-2026-1", "10.0.26200.7100", kb="5100000")), ("Windows", W11, msrc("CVE-2026-2", "10.0.26200.6000", kb="5000000")),
                          ("WinApp", SEVEN, nvd("CVE-2026-9", "20.00")),
                          ("WinApp", "notepad-plus-plus:notepad++", nvd("CVE-2026-8", "8.0", key="notepad-plus-plus:notepad++")),
                          ("Microsoft", "Microsoft Edge", msrc("CVE-2026-4", "141.0.0.0", product="Microsoft Edge", eco="Microsoft")),
                          ("Microsoft", ".NET 8.0 runtime", msrc("CVE-2026-3", "8.0.11", product=".NET 8.0 runtime", eco="Microsoft"))]:
        s.merge(Advisory(id=rec["id"], ecosystem=eco, package=pkg, modified=rec["modified"], record=rec))
    s.add(Kev(cve="CVE-2026-1", date_added="2026-10-14"))
    s.commit()
    return s


def enrolled(c, inv):
    token = c.post("/api/enroll-tokens").json()["token"]
    a = c.post("/api/agent/enroll", json={"token": token, "hostname": "lab-1", "ecosystem": "Windows"}).json()
    h = {"Authorization": f"Bearer {a['agent_key']}"}
    assert c.post("/api/agent/inventory", headers=h, json=inv).status_code == 200
    return c.get("/api/assets").json()[0]["id"], h


RICH = doc(app("7-Zip 19.00 (x64)", "19.00"), app("7-Zip 24.08 (x64)", "24.08"),
           {"ecosystem": "WinApp", "name": "Notepad++ (x64)", "version": "8.9", "source": "Notepad++ Team"},
           {"ecosystem": "WinApp", "name": "Microsoft Edge", "version": "140.0.1.1", "source": "Microsoft Corporation"},
           {"ecosystem": "Microsoft", "name": ".NET runtime", "version": "8.0.10", "source": "native"},
           {"ecosystem": "WinDriver", "name": "x.sys", "version": "a" * 64, "source": "loaded"},
           facts={"pending_reboot": False, "uac_lua": 1})
RICH["collection"]["sources"]["drivers"] = {"state": "ok", "count": 1}


def test_scan_report_endpoint_is_org_scoped_and_parity_holds_with_rescan(env):
    s = seed(env)
    c = user(env)
    aid, h = enrolled(c, RICH)
    r = c.get(f"/api/assets/{aid}/scan-report")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["headline"]["status"] == "vulnerable" and body["host"] == "lab-1"
    assert [g["instance"] for g in body["vulnerable"]][0] == W11 and body["vulnerable"][0]["known_exploited"] == 1
    assert {x["name"]: x["state"] for x in body["coverage"]["sources"]}["uninstall"] == "ok"

    other = user(env, "other@example.com")
    assert other.get(f"/api/assets/{aid}/scan-report").status_code == 404
    assert c.get("/api/assets/nope/scan-report").status_code == 404

    s.expire_all()
    asset = s.get(Asset, aid)
    assert asset.collection == RICH["collection"]
    inv = Inventory.from_asset(asset, s.scalars(select(InstalledPackage).where(InstalledPackage.asset_id == aid)).all())
    verdicts, _ = engine.scan_inventory(s, inv, engine.prior_findings(s, asset))
    found = [(f.ecosystem, f.package, f.vuln_id) for f in s.scalars(select(Finding).where(Finding.asset_id == aid, Finding.status.in_(("open", "accepted"))))]
    p = parity.compare(verdicts, found)
    assert found and p["ok"], p
    assert p["agree"] == 4 and not p["explained"]


def test_parity_explains_a_difference_and_lists_what_it_cannot(env):
    vs = run(doc(), content(msrc("CVE-2026-1", "10.0.26100.9999"), msrc("CVE-2026-2", "10.0.26200.7100")))
    p = parity.compare(vs, [("Windows", W11, "CVE-2026-1"), ("Windows", W11, "CVE-2026-2"), ("WinConfig", "uac", "uac-off"), ("Windows", W11, "CVE-2026-5")])
    assert p["agree"] == 1 and p["outside_this_slice"] == {"WinConfig": 1} and p["explained"][0]["engine"] == "release-line"
    assert [x["vuln_id"] for x in p["unexplained"]] == ["CVE-2026-5"] and not p["ok"]
    assert [x["vuln_id"] for x in parity.compare(vs, [])["unexplained"]] == ["CVE-2026-2"]


def test_t7_through_the_api_an_unread_source_closes_nothing_and_the_report_says_it_has_no_evidence(env):
    seed(env)
    c = user(env)
    aid, h = enrolled(c, RICH)
    worse = copy.deepcopy(RICH)
    worse["packages"] = [p for p in worse["packages"] if p["ecosystem"] != "WinApp"]
    worse["collection"]["sources"]["uninstall"] = {"state": "failed", "count": 0, "error": "Uninstall: access denied", "code": "access-denied"}
    assert c.post("/api/agent/inventory", headers=h, json=worse).status_code == 200
    body = c.get(f"/api/assets/{aid}/scan-report").json()
    carried = next(g for g in body["undetermined"] if g["reason"] == "not-reassessed")
    assert "CVE-2026-9" in carried["examples"]
    assert any(g["reason"] == "access-denied" and g["blocked_by"] == "uninstall" for g in body["undetermined"])
    from nimstead.scan import rescan
    s = make_sessionmaker(env)()

    def still_open():
        return {f.vuln_id for f in s.scalars(select(Finding).where(Finding.asset_id == aid, Finding.ecosystem == "WinApp", Finding.status == "open"))}
    assert "CVE-2026-9" in still_open()  # rescan doesn't call it fixed either: nobody read the apps
    rescan(s, s.get(Asset, aid), inventory_received=False)  # nor does the hourly re-match of the same short list
    assert "CVE-2026-9" in still_open()


def test_a_scan_is_recorded_once_with_what_explains_it_and_can_be_replayed(env):
    s = seed(env)
    c = user(env)
    aid, _ = enrolled(c, RICH)
    first = c.get(f"/api/assets/{aid}/scan-report").json()
    assert c.get(f"/api/assets/{aid}/scan-report").json() == first
    s.expire_all()
    [rec] = s.scalars(select(ScanRecord).where(ScanRecord.asset_id == aid)).all()
    assert rec.content_version == first["content_version"] and rec.verdicts_sha256 == first["verdicts_sha256"] and rec.engine_version == "3"
    inv = Inventory.from_doc(rec.inventory)
    assert inv.sha256() == rec.inventory_sha256
    replay = evaluate(inv, engine.content.load(s, inv), engine.prior_findings(s, s.get(Asset, aid)))
    assert report.digest(replay) == rec.verdicts_sha256
    assert c.delete(f"/api/assets/{aid}").status_code == 204
    s.expire_all()
    assert not s.scalars(select(ScanRecord)).all()


def test_inventory_drops_a_bad_document_but_never_the_packages_and_forgets_the_last_one(env):
    seed(env)
    c = user(env)
    aid, h = enrolled(c, RICH)
    bad = {**RICH, "collection": {"v": 1, "sources": {"uninstall": {"state": "ok", "count": 1, "error": "x" * 1000}}}}
    assert c.post("/api/agent/inventory", headers=h, json=bad).status_code == 200
    body = c.get(f"/api/assets/{aid}/scan-report").json()
    assert any(g["reason"] == "no-collection-document" for g in body["undetermined"]) and body["vulnerable"]
    old = {k: v for k, v in RICH.items() if k != "collection"}
    assert c.post("/api/agent/inventory", headers=h, json=old).status_code == 200
    assert c.get(f"/api/assets/{aid}/scan-report").json()["headline"]["status"] == "vulnerable"
    assert c.get("/api/findings").json()  # rescan is untouched


def test_stored_facts_that_are_too_big_to_keep_mark_host_facts_failed(env):
    seed(env)
    c = user(env)
    aid, h = enrolled(c, RICH)
    big = {**RICH, "facts": {"huge": ["x" * 400] * 500}}
    assert c.post("/api/agent/inventory", headers=h, json=big).status_code == 200
    rows = {x["name"]: x["state"] for x in c.get(f"/api/assets/{aid}/scan-report").json()["coverage"]["sources"]}
    assert rows["host_facts"] == "failed"


def test_a_host_with_no_inventory_and_a_linux_host_say_so(env):
    c = user(env)
    token = c.post("/api/enroll-tokens").json()["token"]
    c.post("/api/agent/enroll", json={"token": token, "hostname": "new", "ecosystem": "Windows"})
    aid = c.get("/api/assets").json()[0]["id"]
    body = c.get(f"/api/assets/{aid}/scan-report").json()
    assert body["headline"]["status"] == "not-assessed" and body["undetermined"][0]["reason"] == "no-inventory"
    vs = evaluate(Inventory.from_doc({"ecosystem": "Debian:12", "packages": []}), Content.make({}))
    assert (vs[0].outcome, vs[0].reason) == (Outcome.NOT_RUN, "feed-missing")  # Linux is judged now (test_engine_linux.py)


def test_the_cli_prints_the_report_and_json(env, tmp_path, capsys):
    seed(env)
    from nimstead.engine.__main__ import main
    p = tmp_path / "inv.json"
    p.write_text(json.dumps(RICH), encoding="utf-8-sig")
    assert main([str(p), "--db", env]) == 0
    p2 = tmp_path / "bad.json"
    p2.write_text("[]")
    assert main([str(p2), "--db", env]) == 2
    assert main([str(Path(tmp_path) / "none.json"), "--db", env]) == 2
    assert "isn't an inventory" in capsys.readouterr().err


# ---- phases 1 and 3 of tasks/plan-engine-findings.md: the engine judges every rescan; rescan's own loop is the shadow

def _disagreements(c):
    return [e for e in c.get("/api/evidence/ledger").json()["entries"] if e["kind"] == "engine_disagrees"]


def test_the_engine_shadows_every_rescan_and_agrees_on_a_rich_host(env):
    seed(env)
    c = user(env)
    enrolled(c, RICH)
    assert _disagreements(c) == []  # Windows, Microsoft and app findings: the engine says vulnerable on each one rescan opened


def test_a_disagreement_is_one_ledger_entry_and_changes_no_finding(env, monkeypatch):
    seed(env)
    c = user(env)
    gap = [{"ecosystem": "WinApp", "package": SEVEN, "vuln_id": "CVE-2026-9", "problem": "rescan opened it and the engine has no verdict for it"}]
    monkeypatch.setattr(engine, "judge", lambda *a: ([], Content.make({}), {"agree": 3, "unexplained": gap}))
    enrolled(c, RICH)
    (d,) = _disagreements(c)
    assert d["data"]["count"] == 1 and d["data"]["unexplained"] == gap and d["data"]["host"] == "lab-1"
    assert any(f["vuln_id"] == "CVE-2026-9" for f in c.get("/api/findings").json())  # no verdict either way: rescan's match stands


def test_a_failing_engine_never_stops_rescan_and_its_matches_stand(env, monkeypatch):
    seed(env)
    c = user(env)
    _, h = enrolled(c, RICH)
    before = sorted((f["package"], f["vuln_id"]) for f in c.get("/api/findings").json())

    def boom(*a):
        raise RuntimeError("engine bug")
    monkeypatch.setattr(engine, "judge", boom)
    assert c.post("/api/agent/inventory", headers=h, json=RICH).status_code == 200  # the same inventory again
    assert sorted((f["package"], f["vuln_id"]) for f in c.get("/api/findings").json()) == before and before and _disagreements(c) == []


def test_parity_explains_a_product_the_engine_wouldnt_judge_as_a_whole():
    """An inventory with no collection document (an old agent): one "not run" verdict per product, which explains its CVEs."""
    from nimstead.engine.model import Verdict
    v = Verdict("product:openssl", "distro", "Debian:12", "openssl", Outcome.NOT_RUN, reason="no-collection-document", blocker="package_db")
    p = parity.compare([v], [("Debian:12", "openssl", "CVE-2023-5678")])
    assert p["ok"] and p["explained"][0]["engine"] == "no-collection-document"
    assert not parity.compare([v], [("Debian:12", "curl", "CVE-2023-1")])["ok"]  # only its own product


@pytest.mark.parametrize("sources, blocked", [
    ({"uninstall": {"state": "ok", "count": 40}, "windows_build": {"state": "ok", "count": 1}}, set()),
    ({"uninstall": {"state": "ok", "count": 0}}, {"WinApp", "Microsoft"}),  # read to its end with nothing in it (R4.3)
    ({"uninstall": {"state": "ok", "count": 9}, "user_hives": {"state": "partial", "count": 2}}, {"WinApp"}),
    ({"windows_build": {"state": "failed", "count": 0, "code": "access-denied"}}, {"Windows"}),
    ({"user_hives": {"state": "off", "count": 0}}, set()),  # excluded by policy is a decision, not a failed read
])
def test_unread_sources_block_resolving_their_ecosystems(sources, blocked):
    from nimstead.scan import unread
    assert unread({"v": 1, "sources": sources}) == blocked
    assert unread(None) == set()  # an agent too old to say: today's behaviour


def test_one_inventory_is_evaluated_once_and_its_record_still_stored(env, monkeypatch):
    """rescan's shadow evaluates the inventory; the stored scan report after the response reuses those verdicts."""
    import nimstead.engine as eng
    seed(env)
    calls = []
    real = eng.evaluate
    monkeypatch.setattr(eng, "evaluate", lambda *a, **k: calls.append(1) or real(*a, **k))
    c = user(env)
    aid, _ = enrolled(c, RICH)
    assert len(calls) == 1
    s = make_sessionmaker(env)()
    assert s.scalar(select(ScanRecord).where(ScanRecord.asset_id == aid)) is not None
