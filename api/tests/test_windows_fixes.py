"""Fix paths beyond the OS update (plan T17, T21, T22, T38): winget (forward-only, pinned ids), Microsoft 365 Apps with
rollback to the previous build, and reversible settings; the closed maps on both sides; never automated."""

import json

import pytest
from test_agent_remediate import agent
from test_api import user

from nimstead import remediate
from nimstead.db import Advisory, Asset, RemediationJob, make_sessionmaker


def test_agent_and_server_maps_are_the_same():
    from nimstead import winapps
    assert set(agent.WINGET_IDS) == remediate.WINGET_KEYS
    assert set(agent.CONFIG_FIXES) == remediate.CONFIG_FIXES
    assert remediate.WINGET_KEYS - {"Microsoft Edge", "Visual Studio Code"} <= {p.key for p in winapps.PRODUCTS}


class Host:
    """A fake Windows host for WinAppJob: winget, the Click-to-Run client and the registry."""

    def __init__(self, show_hash=True, office_open="0", reg=None):
        self.log, self.show_hash, self.office_open = [], show_hash, office_open
        self.reg, self.office = dict(reg or {}), "16.0.20430.20100"
        self.winget_cwds, self.c2r_drops = [], 0

    def __call__(self, cmd, cwd=None):
        self.log.append(cmd)
        if cmd[0] == "powershell":
            s = cmd[-1]
            if "DesktopAppInstaller" in s:
                return 0, "C:\\Program Files\\WindowsApps\\Microsoft.DesktopAppInstaller_1.25_x64__8wekyb3d8bbwe\\winget.exe"
            if "VCLibs" in s:
                return 0, "C:\\Program Files\\WindowsApps\\Microsoft.VCLibs.140.00.UWPDesktop_14_x64__8wekyb3d8bbwe\\msvcp140.dll"
            if "VersionToReport" in s:
                return 0, self.office
            if "Get-Process" in s:
                return 0, self.office_open
            if "Get-Service" in s:
                return 0, "Running"
        if cmd[0].endswith("winget.exe"):
            self.winget_cwds.append(cwd)
            if cmd[1] == "show":
                return 0, "Found 7-Zip [7zip.7zip]\nInstaller:\n  Installer Type: msi\n" + ("  Installer SHA256: " + "a" * 64 + "\n" if self.show_hash else "")
            return 0, "Successfully installed"
        if cmd[0].endswith("OfficeC2RClient.exe"):
            if self.c2r_drops:  # exit 0, nothing happens
                self.c2r_drops -= 1
                return 0, ""
            self.office = cmd[3].split("=", 1)[1]
            return 0, ""
        if cmd[:2] == ["reg", "query"]:
            v = self.reg.get(cmd[4])
            return (0, f"    {cmd[4]}    {v[0]}    {v[1]}") if v else (1, "ERROR: unable to find the specified registry key or value.")
        if cmd[:2] == ["reg", "add"]:
            self.reg[cmd[4]] = (cmd[6], cmd[8])
            return 0, ""
        if cmd[:2] == ["reg", "delete"]:
            self.reg.pop(cmd[4], None)
            return 0, ""
        raise AssertionError(cmd)


def job(mgr, name, frm="23.01", to="24.09", units=()):
    return {"id": "j1", "manager": mgr, "health_units": list(units), "packages": [{"name": name, "from": frm, "to": to}]}


def test_winget_upgrades_only_a_pinned_id_with_a_published_hash():
    h = Host()
    outcome, steps, err = agent.WinAppJob(job("winget", "7-zip:7-zip"), run=h).execute()
    assert outcome == "applied", (steps, err)
    inst = next(c for c in h.log if c[0].endswith("winget.exe") and c[1] == "install")
    assert inst[inst.index("--id") + 1] == "7zip.7zip" and "--exact" in inst and inst[inst.index("--source") + 1] == "winget"
    assert inst[inst.index("--version") + 1] == "24.09"
    assert len(h.winget_cwds) == 2 and all("Microsoft.VCLibs" in c for c in h.winget_cwds)  # as SYSTEM its DLLs are found from there


@pytest.mark.parametrize(("line", "want"), [("  Installer-SHA256: " + "a" * 64, "applied"),  # winget's labels follow Windows' language
                                            ("  Installer-SHA256: ", "aborted")])
def test_winget_finds_the_hash_by_its_value_not_its_label(line, want):
    class German(Host):
        def __call__(self, cmd, **kw):
            return (0, f"Installer:\n{line}\n") if cmd[0].endswith("winget.exe") and cmd[1] == "show" else super().__call__(cmd, **kw)
    outcome, steps, err = agent.WinAppJob(job("winget", "7-zip:7-zip"), run=German()).execute()
    assert outcome == want, (steps, err)


@pytest.mark.parametrize("j,why", [
    (job("winget", "Contoso.Evil"), "unknown product"),
    (job("winget", "7-zip:7-zip", to="24.09; calc"), "invalid version"),
    (job("winget", "7-zip:7-zip", frm="24.09", to="23.01"), "fix is newer"),
])
def test_winget_refuses_before_anything_runs(j, why):
    h = Host()
    outcome, steps, err = agent.WinAppJob(j, run=h).execute()
    assert outcome == "aborted" and why in json.dumps(steps) + (err or "")
    assert not [c for c in h.log if c[0].endswith("winget.exe")]


def test_winget_without_an_installer_hash_changes_nothing():
    h = Host(show_hash=False)
    outcome, _, _ = agent.WinAppJob(job("winget", "7-zip:7-zip"), run=h).execute()
    assert outcome == "aborted" and not [c for c in h.log if c[0].endswith("winget.exe") and c[1] == "install"]


def test_office_rolls_back_to_the_build_it_found(monkeypatch):
    monkeypatch.setattr(agent.time, "sleep", lambda s: None)
    h = Host()
    j = job("office", "Microsoft 365 Apps", "16.0.20430.20100", "16.0.20430.20180", units=["W3SVC"])
    outcome, steps, _ = agent.WinAppJob(j, run=h, fail_after_apply=True).execute()
    assert outcome == "rolled_back" and h.office == "16.0.20430.20100"
    assert [s["step"] for s in steps if s["step"].startswith("Office updated to")] == [
        "Office updated to 16.0.20430.20180", "Office updated to 16.0.20430.20100"]


def test_office_request_the_client_dropped_is_sent_again(monkeypatch):
    monkeypatch.setattr(agent.time, "sleep", lambda s: None)
    h = Host()
    h.c2r_drops = 1
    outcome, steps, err = agent.WinAppJob(job("office", "Microsoft 365 Apps", frm="16.0.20430.20100", to="16.0.20430.20200"), run=h).execute()
    assert outcome == "applied", (steps, err)
    assert h.office == "16.0.20430.20200"


def test_office_never_force_closes_open_apps():
    h = Host(office_open="2")
    outcome, _, err = agent.WinAppJob(job("office", "Microsoft 365 Apps", "16.0.20430.20100", "16.0.20430.20180"), run=h).execute()
    assert outcome == "aborted" and "Office app" in err and not [c for c in h.log if c[0].endswith("OfficeC2RClient.exe")]


@pytest.mark.parametrize("before", [None, ("REG_DWORD", "0x1")])
def test_setting_is_put_back_exactly_on_failure(before):
    h = Host(reg={"UseLogonCredential": before} if before else {})
    outcome, _, _ = agent.WinAppJob(job("winconfig", "wdigest", "current", "fixed"), run=h, fail_after_apply=True).execute()
    assert outcome == "rolled_back"
    assert h.reg.get("UseLogonCredential") == before  # absent stays absent; a value comes back as it was
    assert agent.WinAppJob(job("winconfig", "wdigest", "current", "fixed"), run=Host()).execute()[0] == "applied"


def test_a_server_supplied_setting_or_path_is_refused():
    h = Host()
    assert agent.WinAppJob(job("winconfig", "HKLM\\SOFTWARE\\Evil"), run=h).execute()[0] == "aborted"
    assert not [c for c in h.log if c[0] == "reg"]


def _winapp_host(c, pkgs, facts=None):
    token = c.post("/api/enroll-tokens", json={"sandbox": True}).json()["token"]
    a = c.post("/api/agent/enroll", json={"token": token, "hostname": "pc", "ecosystem": "Windows"}).json()
    h = {"Authorization": f"Bearer {a['agent_key']}"}
    c.post("/api/agent/inventory", headers=h, json={"ecosystem": "Windows", "packages": pkgs, "facts": facts})
    return a, h


def test_forward_only_needs_a_persons_explicit_approval_and_never_the_ladder(env):
    with make_sessionmaker(env)() as s:
        rec = {"id": "CVE-2026-1-7z", "aliases": [], "modified": "", "summary": "7-Zip bug",
               "affected": [{"package": {"ecosystem": "WinApp", "name": "7-zip:7-zip"},
                             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "24.09"}]}]}]}
        s.add(Advisory(id=rec["id"], ecosystem="WinApp", package="7-zip:7-zip", record=rec))
        s.commit()
    c = user(env)
    a, h = _winapp_host(c, [{"ecosystem": "WinApp", "name": "7-Zip 23.01 (x64)", "version": "23.01", "source": "Igor Pavlov"}])
    r = c.post("/api/remediation/jobs", json={"asset_id": a["asset_id"], "ecosystem": "WinApp", "package": "7-zip:7-zip"})
    assert r.status_code == 201, r.text
    j = r.json()
    assert j["manager"] == "winget" and j["forward_only"] and j["packages"] == [{"name": "7-zip:7-zip", "from": "23.01", "to": "24.09"}]
    assert c.post(f"/api/remediation/jobs/{j['id']}/approve").status_code == 409  # no acknowledgement
    assert c.post(f"/api/remediation/jobs/{j['id']}/approve", json={"forward_only": True}).status_code == 200
    [sent] = c.get("/api/agent/jobs", headers=h).json()
    assert sent["manager"] == "winget"
    c.patch("/api/settings", json={"remediation_mode": "auto"})  # auto mode never plans or approves these
    with make_sessionmaker(env)() as s:
        remediate.auto_remediate(s, s.get(Asset, a["asset_id"]))
        s.commit()
    assert not [x for x in c.get("/api/remediation/jobs").json() if x["approved_by"] == "policy"]


def test_setting_fix_planned_from_a_config_finding(env):
    c = user(env)
    a, _ = _winapp_host(c, [{"ecosystem": "Windows", "name": "Windows Server 2025", "version": "10.0.26100.4946", "source": None}],
                        {"installation_type": "Server", "config": {"wdigest": 1, "run_as_ppl": None}})
    r = c.post("/api/remediation/jobs", json={"asset_id": a["asset_id"], "ecosystem": "WinConfig", "package": "wdigest"})
    assert r.status_code == 201, r.text
    assert r.json()["manager"] == "winconfig" and not r.json()["forward_only"]
    r = c.post("/api/remediation/jobs", json={"asset_id": a["asset_id"], "ecosystem": "WinConfig", "package": "lsa-protection"})
    assert r.status_code >= 400 and "reported, not changed" in r.text


def test_fix_first_lists_settings_with_the_same_rules_and_never_auto(env):
    c = user(env)
    a, _ = _winapp_host(c, [{"ecosystem": "Windows", "name": "Windows Server 2025", "version": "10.0.26100.4946", "source": None}],
                        {"installation_type": "Server", "config": {"wdigest": 1, "run_as_ppl": 0}})
    findings = {f["package"]: f for f in c.get("/api/findings", params={"limit": 500}).json()}
    assert "lsa-protection" in findings and not findings["lsa-protection"]["setting_fix"]
    actions = {x["package"]: x for x in c.get("/api/summary").json()["top_actions"]}
    assert "lsa-protection" not in actions  # reported, not changed: nothing on Home could fix it
    w = actions["wdigest"]
    assert w["fixed_version"] is None and w["summary"] and w["asset_ids"] == [a["asset_id"]]
    assert (w["fix"], w["plannable"], w["person_only"], w["forward_only"]) == ("winconfig", True, True, False)
    c.patch("/api/settings", json={"remediation_mode": "auto"})  # the ladder neither plans nor approves it
    with make_sessionmaker(env)() as s:
        remediate.auto_remediate(s, s.get(Asset, a["asset_id"]))
        s.commit()
    assert not c.get("/api/remediation/jobs").json()
    j = c.post("/api/remediation/jobs", json={"asset_id": a["asset_id"], "ecosystem": "WinConfig", "package": "wdigest"}).json()
    w = next(x for x in c.get("/api/summary").json()["top_actions"] if x["package"] == "wdigest")
    assert w["job"]["id"] == j["id"] and w["busy_asset_ids"] == [a["asset_id"]]
    with make_sessionmaker(env)() as s:
        job = s.get(RemediationJob, j["id"])
        with pytest.raises(remediate.RemediationError, match="only ever approved by a person"):
            remediate.approve(s, job, "policy", policy=True)
    assert c.post(f"/api/remediation/jobs/{j['id']}/approve").json()["status"] == "approved"  # a person can


@pytest.mark.parametrize("eco,pkg,fix,plannable,person,forward", [
    ("WinConfig", "wdigest", "winconfig", True, True, False),
    ("WinConfig", "lsa-protection", "winconfig", False, True, False),
    ("WinApp", "7-zip:7-zip", "winget", True, True, True),
    ("WinApp", "python:python", "winget", False, True, True),  # no pinned winget package
    ("Microsoft", "Microsoft 365 Apps Current", "office", True, True, False),
    ("Microsoft", ".NET Framework 4.8 on Windows 11", "windows", True, True, False),
    ("Windows", "Windows Server 2025", "windows", True, False, False),
    ("Debian:12", "openssl", "apt", True, False, False),
    ("PyPI", "requests", None, False, False, False),
])
def test_fix_path_agrees_with_plan_and_the_ladder(eco, pkg, fix, plannable, person, forward):
    assert remediate.fix_path(eco, pkg) == {"fix": fix, "plannable": plannable, "person_only": person, "forward_only": forward}


def test_evidence_pack_lists_forward_only_changes_apart(env):
    test_forward_only_needs_a_persons_explicit_approval_and_never_the_ladder(env)
    from datetime import timedelta

    from nimstead.db import Org, now
    from nimstead.evidence import build_pack
    with make_sessionmaker(env)() as s:
        org = s.query(Org).first()
        pack = build_pack(s, org.id, now() - timedelta(days=1), now() + timedelta(minutes=1))
    [fo] = pack["forward_only_changes"]
    assert fo["summary"].endswith("(forward-only: can't be undone)") and fo["approved_by"] and pack["metrics"]["forward_only_changes"] == 1


def test_cert_padding_fix_sets_both_registry_views_and_restores_both():
    calls = []

    def run(cmd, **k):
        calls.append(cmd)
        if cmd[:2] == ["reg", "query"]:
            return 1, ""
        return 0, "Running"
    out = agent.WinAppJob(job("winconfig", "cert-padding-check", "current", "fixed"), run=run, fail_after_apply=True).execute()
    added = [c[2] for c in calls if c[:2] == ["reg", "add"]]
    removed = [c[2] for c in calls if c[:2] == ["reg", "delete"]]
    assert out[0] == "rolled_back" and len(added) == 2 and any("WOW6432Node" in k for k in added) and sorted(removed) == sorted(added)
