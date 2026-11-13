"""Windows remediation state machine against a simulated host (real proof: sandbox/winvm.py on Windows Server 2025
and Windows 11)."""

import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
from test_agent_remediate import agent

FIX = Path(__file__).parent / "fixtures" / "windows"
WIN11 = json.loads((FIX / "win11-express-permanence.json").read_text())  # the real check's output on the Windows 11 VM

OLD, NEW = "10.0.26100.32230", "10.0.26100.33650"
BASE_PKG = "Package_for_RollupFix~31bf3856ad364e35~amd64~~26100.32230.1.10"
NEW_PKG = "Package_for_RollupFix~31bf3856ad364e35~amd64~~26100.33650.1.3"


class FakeWin:
    def __init__(self, offered=("5126646",), service_breaks_on_new=False, removal_works=True, busy_removals=0, manifest="removable",
                 battery="", cluster=False, drain="Paused", crashes="", why="", install_times_out=False, free_gb="50", instead=None, esu=0):
        self.build, self.pkgs, self.manifest = OLD, {BASE_PKG: "Installed"}, manifest
        self.offered, self.breaks, self.removal_works = list(offered), service_breaks_on_new, removal_works
        self.pending_remove, self.log, self.busy = [], [], busy_removals
        self.battery, self.cluster, self.drain, self.crashes, self.why = battery, cluster, drain, crashes, why
        self.boot, self.install_times_out, self.free_gb = 1_700_000_000, install_times_out, free_gb
        self.instead = instead  # PS_FIND's second line as Windows Update wrote it, or None for an older fake's one line
        self.esu, self.searches = esu, 0

    def __call__(self, cmd, cwd=None, timeout=None):
        self.log.append(cmd)
        if cmd[0] == "powershell":
            script = cmd[-1]
            if "Win32_Battery" in script:
                return 0, self.battery
            if "Get-PSDrive" in script:
                return 0, self.free_gb
            if "HKLM:\\Cluster" in script:
                return 0, "NODE1" if self.cluster else ""
            if "Suspend-ClusterNode" in script:
                return (0, self.drain) if self.drain else (1, "drain failed: roles couldn't move")
            if "Resume-ClusterNode" in script:
                return 0, "Up"
            if "Service Control Manager" in script:
                return 0, self.crashes if self.build == NEW else ""
            if "mscorlib.dll" in script:  # a .NET Framework job's build
                return 0, self.build
            if "UseWUServer" in script:
                return 0, self.why
            if "RebootPending" in script:
                return 0, "False"
            if "Get-Service" in script:
                return 0, "Stopped" if self.breaks and self.build == NEW else "Running"
            if "CreateUpdateInstaller" in script:
                assert timeout == agent.INSTALL_TIMEOUT
                if self.install_times_out:  # Windows Update carries on installing; dism doesn't list it yet
                    self.late = True
                    return 127, "Command '[...]' timed out after 7200 seconds"
                self.pkgs[NEW_PKG] = "Install Pending"
                return 0, json.dumps({"download": 2, "install": 2, "reboot": True})
            if "CreateUpdateDownloader" in script:
                return 0, "2"
            if "update.mum" in script:
                if self.manifest == "unreadable":
                    return 1, "downloaded package for KB5126646 not found"
                if isinstance(self.manifest, list):  # Windows 11 express: every package in ActionList.xml
                    return 0, json.dumps(self.manifest)
                return 0, json.dumps([{"file": "Windows11.0-KB5126646-x64.wim", "reason": "CumulativeUpdate", "partition": "MainOS",
                                       "permanent": self.manifest == "permanent",
                                       "permanent_parts": ["Microsoft-Windows-SenseClient-FoD-Package.mum"]}])
            if "Where-Object { $_.Name -match 'ESU' }" in script:
                return 0, str(self.esu)
            if "KBArticleIDs" in script:
                kbs = script.split("foreach ($kb in @(")[1].split(")")[0].replace("'", "").split(",")
                self.searches += 1
                found = json.dumps({kb: [{"title": f"Cumulative Update (KB{kb})", "uninstallable": False}] if kb in self.offered else []
                                    for kb in kbs})
                return 0, found + ("" if self.instead is None else "\r\n" + self.instead)
        if cmd[:3] == ["dism", "/online", "/get-packages"]:
            return 0, "\n".join(f"Package Identity : {k}\nState : {v}\n" for k, v in self.pkgs.items())
        if cmd[:3] == ["dism", "/online", "/remove-package"]:
            if not self.removal_works:
                return 87, "Error: 0x800f0825 The package is permanent"
            if self.busy:  # servicing still finalising right after the reboot
                self.busy -= 1
                return 0x80010108, "Error: 0x80010108\n\nDISM failed. No operation was performed."
            self.pending_remove.append(cmd[3].split(":", 1)[1])
            return 3010, "The operation completed successfully. Restart required."
        raise AssertionError(cmd)

    def reboot(self):
        self.boot += 3600
        if getattr(self, "late", False):
            self.late, self.pkgs[NEW_PKG] = False, "Install Pending"
        if self.pkgs.get(NEW_PKG) == "Install Pending":
            self.pkgs[NEW_PKG], self.build = "Installed", NEW
        for p in self.pending_remove:
            self.pkgs.pop(p, None)
            self.build = OLD
        self.pending_remove = []


JOB = {"id": "w1", "manager": "windows", "health_units": ["W3SVC"], "settle_seconds": 0,
       "packages": [{"name": "Windows Server 2025 (Server Core installation)", "from": OLD, "to": NEW, "kb": "5126646"}]}


def make(tmp_path, host, job=JOB):
    return agent.WinJob(job, run=host, state_path=str(tmp_path / "state.json"), build=lambda: host.build, retry_wait=0,
                        booted=lambda: host.boot)


def resume(tmp_path, host):
    return agent.WinJob(run=host, state_path=str(tmp_path / "state.json"), build=lambda: host.build, retry_wait=0,
                        booted=lambda: host.boot).advance()


def test_update_survives_reboot_and_is_verified(tmp_path):
    h = FakeWin()
    r = make(tmp_path, h).advance()
    assert r["outcome"] == "pending_reboot" and (tmp_path / "state.json").exists()
    h.reboot()
    r = resume(tmp_path, h)
    assert r["outcome"] == "applied" and r["versions"] == {JOB["packages"][0]["name"]: NEW}
    assert not (tmp_path / "state.json").exists()


def test_broken_service_after_update_is_rolled_back_across_two_reboots(tmp_path):
    h = FakeWin(service_breaks_on_new=True)
    assert make(tmp_path, h).advance()["outcome"] == "pending_reboot"
    h.reboot()
    r = resume(tmp_path, h)
    assert r["outcome"] == "pending_reboot"  # removal of the new package needs its own restart
    assert h.pending_remove == [NEW_PKG]  # only the package this job added, never the baseline
    h.reboot()
    r = resume(tmp_path, h)
    assert r["outcome"] == "rolled_back" and h.build == OLD and BASE_PKG in h.pkgs
    assert "W3SVC" in r["error"]


def test_irremovable_update_is_reported_loudly(tmp_path):
    h = FakeWin(service_breaks_on_new=True, removal_works=False)
    make(tmp_path, h).advance()
    h.reboot()
    r = resume(tmp_path, h)
    assert r["outcome"] == "rollback_failed" and "ROLLBACK FAILED" in r["error"]


def test_update_not_offered_changes_nothing(tmp_path):
    h = FakeWin(offered=())
    r = make(tmp_path, h).advance()
    assert r["outcome"] == "aborted" and r["error"].startswith("No changes made")
    assert not any("CreateUpdateInstaller" in c[-1] for c in h.log if c[0] == "powershell")


def test_permanent_or_uncheckable_update_is_refused_before_install(tmp_path):
    for manifest in ("permanent", "unreadable"):
        h = FakeWin(manifest=manifest)
        r = make(tmp_path, h).advance()
        assert r["outcome"] == "aborted" and r["error"].startswith("No changes made") and "removable" in r["error"]
        assert not any("CreateUpdateInstaller" in c[-1] for c in h.log if c[0] == "powershell")
        assert h.pkgs == {BASE_PKG: "Installed"}


def test_removable_update_notes_permanent_parts(tmp_path):
    r = make(tmp_path, FakeWin()).advance()
    step = next(s for s in r["steps"] if "removable" in s["step"])
    assert step["ok"] and "SenseClient" in step["output"]


def test_windows11_express_update_with_its_companions_is_installed(tmp_path):
    h = FakeWin(manifest=WIN11)
    assert make(tmp_path, h).advance()["outcome"] == "pending_reboot"
    step = next(s for s in h_steps(tmp_path) if "removable" in s["step"])
    # the cumulative update itself is removable; the permanent servicing stack and WinRE update are named as staying
    assert step["ok"] and "Windows11.0-KB5127648-x64: update.mum not permanent" in step["output"]
    assert "SenseClient" in step["output"] and "stays after rollback" in step["output"]
    assert "SafeOSDU, WinRE, permanent" in step["output"] and "ServicingStackUpdate, MainOS, permanent" in step["output"]


def h_steps(tmp_path):
    return json.loads((tmp_path / "state.json").read_text())["steps"]


def changed(pkgs, file, **kw):
    return [{**p, **kw} if p["file"] == file else p for p in pkgs]


@pytest.mark.parametrize("pkgs, why", [
    (changed(WIN11, "Windows11.0-KB5127648-x64", permanent=True), "cumulative update itself permanent"),
    (changed(WIN11, "Windows11.0-KB5121794-x64.cab", permanent=True), "permanent companion that isn't servicing infrastructure"),
    (changed(WIN11, "Windows11.0-KB5127654-x64.cab", partition="MainOS"), "permanent Safe OS update outside WinRE"),
    (changed(WIN11, "SSU-26100.9703-x64.cab", permanent=None), "companion manifest unreadable"),
    ([p for p in WIN11 if p["reason"] != "CumulativeUpdate"], "no cumulative update in the plan"),
    (WIN11 + [p for p in WIN11 if p["reason"] == "CumulativeUpdate"], "two cumulative updates in the plan"),
    ([], "empty plan"),
])
def test_windows11_express_update_refused_before_install(tmp_path, pkgs, why):
    h = FakeWin(manifest=pkgs)
    r = make(tmp_path, h).advance()
    assert r["outcome"] == "aborted" and r["error"].startswith("No changes made") and "removable" in r["error"], why
    assert not any("CreateUpdateInstaller" in c[-1] for c in h.log if c[0] == "powershell")


def test_real_windows11_action_list_matches_what_the_check_reads():
    # the real ActionList.xml Windows Update wrote on the Windows 11 VM for KB5127648
    ns = {"a": "urn:schemas-microsoft-com:os-update-actionlist"}
    root = ET.parse(FIX / "win11-express-ActionList.xml").getroot()  # noqa: S314 — checked-in fixture
    acts = root.findall("a:Actions/a:InstallPackage", ns)
    assert re.search(agent.PS_PERMANENCE.split("FeatureId=")[1].split("'")[0].replace("%KB%", "5127648"),
                     (FIX / "win11-express-ActionList.xml").read_text())
    plan = {(a.get("Reason"), a.get("Partition")) for a in acts}
    assert ("CumulativeUpdate", "MainOS") in plan and agent.PERMANENT_COMPANIONS <= plan
    express = next(a for a in acts if a.get("PayloadType") == "Express")
    assert express.get("ExpressPackagePath") == "metadata\\Windows11.0-KB5127648-x64"  # where update.mum is read
    assert [p["file"] for p in WIN11] == [(a.get("ExpressPackagePath") or a.get("FilePath")).split("\\")[-1] for a in acts]


def _cut_power_during_install(tmp_path, host, leaves):
    """Run a job up to the install, then lose everything but the state file it saved."""
    w = make(tmp_path, host)
    real = host.__call__

    class PowerCut(Exception):
        pass

    def run(cmd, cwd=None, timeout=None):
        if cmd[0] == "powershell" and "CreateUpdateInstaller" in cmd[-1]:
            if leaves:
                host.pkgs[NEW_PKG] = leaves
            raise PowerCut
        return real(cmd, cwd=cwd, timeout=timeout)
    w.run = run
    with pytest.raises(PowerCut):
        w._start()
    return agent.WinJob(run=host, state_path=w.state_path, build=lambda: host.build, retry_wait=0, booted=lambda: host.boot)


def test_power_cut_before_the_install_starts_the_job_over(tmp_path):
    host = FakeWin()
    w = make(tmp_path, host)
    w.build = lambda: (_ for _ in ()).throw(KeyboardInterrupt())  # the machine stops during the first check
    with pytest.raises(KeyboardInterrupt):
        w.advance()
    res = resume(tmp_path, host)
    assert res["outcome"] == "pending_reboot" and NEW_PKG in host.pkgs
    assert sum(s["step"] == "job validated" for s in res["steps"]) == 1


def test_power_cut_during_install_with_nothing_new_says_so_and_clears(tmp_path):
    host = FakeWin()
    resumed = _cut_power_during_install(tmp_path, host, None)
    res = resumed.advance()
    assert res["outcome"] == "aborted" and "nothing new is installed" in res["error"]
    assert not Path(resumed.state_path).exists()
    assert not any("CreateUpdateInstaller" in c[-1] for c in host.log)  # never retried blindly


def test_power_cut_during_install_leaving_a_package_is_rolled_back(tmp_path):
    host = FakeWin()
    resumed = _cut_power_during_install(tmp_path, host, "Install Pending")
    res = resumed.advance()  # the build never moved, so verification fails and the package is removed
    assert res["outcome"] == "pending_reboot" and resumed.s["phase"] == "rolled_back_pending"
    assert any("/remove-package" in c and f"/packagename:{NEW_PKG}" in c for c in host.log)


def test_power_cut_on_a_drained_cluster_node_brings_it_back(tmp_path):
    host = FakeWin(cluster=True)
    res = _cut_power_during_install(tmp_path, host, None).advance()
    assert res["outcome"] == "aborted" and any(s["step"] == "cluster node resumed" and s["ok"] for s in res["steps"])


def test_tampered_state_is_never_resumed(tmp_path):
    for field, value in (("units", ["x' -EA Stop).Status; Start-Process calc; (Get-Service -Name 'y"]),
                         ("new_packages", ["Package_for_ServicingStack~31bf3856ad364e35~amd64~~26100.1"]),
                         ("kb", "1; calc"), ("phase", "anything")):
        h = FakeWin()
        assert make(tmp_path, h).advance()["outcome"] == "pending_reboot"
        state = json.loads((tmp_path / "state.json").read_text())
        state[field] = value
        (tmp_path / "state.json").write_text(json.dumps(state))
        h.reboot()
        with pytest.raises(agent.AgentError, match="failed validation"):
            resume(tmp_path, h)
        (tmp_path / "state.json").unlink()


def test_build_drift_aborts(tmp_path):
    h = FakeWin()
    h.build = "10.0.26100.33000"
    assert make(tmp_path, h).advance()["outcome"] == "aborted"


def test_hostile_job_rejected_before_any_command(tmp_path):
    for bad in ({**JOB, "packages": [{**JOB["packages"][0], "kb": "5126646'; Remove-Item C:\\ -Recurse #"}]},
                {**JOB, "packages": [{**JOB["packages"][0], "name": "Windows'; calc #"}]},
                {**JOB, "health_units": ["W3SVC'; calc #"]}):
        h = FakeWin()
        r = make(tmp_path, h, bad).advance()
        assert r["outcome"] == "aborted" and h.log == []


def test_rollback_that_does_not_restore_the_build_is_a_failure(tmp_path):
    h = FakeWin(service_breaks_on_new=True)
    make(tmp_path, h).advance()
    h.reboot()
    resume(tmp_path, h)
    h.pending_remove = []  # removal silently didn't take effect
    h.reboot()
    r = resume(tmp_path, h)
    assert r["outcome"] == "rollback_failed" and "expected" in r["error"]


def test_an_update_that_lands_after_the_install_timed_out_is_still_rolled_back(tmp_path):
    h = FakeWin(install_times_out=True)  # what the real Windows 11 VM did with a user signed in
    r = make(tmp_path, h).advance()
    assert r["outcome"] == "pending_reboot" and h.pending_remove == []  # nothing listed yet to remove
    h.reboot()  # the update finishes installing during this restart
    assert h.build == NEW
    r = resume(tmp_path, h)
    assert r["outcome"] == "pending_reboot" and h.pending_remove == [NEW_PKG]
    assert any("after the agent stopped waiting" in s["step"] for s in r["steps"])
    h.reboot()
    r = resume(tmp_path, h)
    assert r["outcome"] == "rolled_back" and h.build == OLD


def test_transient_dism_errors_right_after_reboot_are_retried(tmp_path):
    h = FakeWin(service_breaks_on_new=True, busy_removals=3)  # what the real Server 2025 VM did
    make(tmp_path, h).advance()
    h.reboot()
    r = resume(tmp_path, h)
    assert r["outcome"] == "pending_reboot" and h.pending_remove == [NEW_PKG]
    assert sum("servicing busy" in s["step"] for s in r["steps"]) == 3
    h.reboot()
    assert resume(tmp_path, h)["outcome"] == "rolled_back"


def test_persistent_dism_failure_still_fails_loudly(tmp_path):
    h = FakeWin(service_breaks_on_new=True, busy_removals=99)
    make(tmp_path, h).advance()
    h.reboot()
    r = resume(tmp_path, h)
    assert r["outcome"] == "rollback_failed" and "0x80010108" in r["error"]


HOT_JOB = {**JOB, "packages": [{**JOB["packages"][0], "alt": {"kb": "5126999", "to": "10.0.26100.33001"}}]}


@pytest.mark.parametrize("offered,kb", [(("5126646",), "5126646"), (("5126999",), "5126999")])
def test_installs_whichever_of_cumulative_or_hotpatch_windows_update_offers(tmp_path, offered, kb):
    host = FakeWin(offered=offered)
    r = make(tmp_path, host, HOT_JOB).advance()
    assert r["outcome"] == "pending_reboot", r
    assert any("one of KB5126646 / KB5126999" in s["step"] and s["ok"] for s in r["steps"])
    st = json.loads((tmp_path / "state.json").read_text())
    assert st["kb"] == kb and any(f"'{kb}'" in c[-1] for c in host.log if c[0] == "powershell" and "CreateUpdateInstaller" in c[-1])


@pytest.mark.parametrize("offered", [(), ("5126646", "5126999")])
def test_neither_or_both_offered_changes_nothing(tmp_path, offered):
    host = FakeWin(offered=offered)
    r = make(tmp_path, host, HOT_JOB).advance()
    assert r["outcome"] == "aborted" and r["error"].startswith("No changes made")
    assert not any("CreateUpdateInstaller" in c[-1] for c in host.log if c[0] == "powershell")


def test_state_with_a_bad_alternative_kb_is_not_resumed(tmp_path):
    host = FakeWin()
    make(tmp_path, host, HOT_JOB).advance()
    st = json.loads((tmp_path / "state.json").read_text())
    st["alt"] = {"kb": "5126999; calc", "to": "10.0.1.1"}
    (tmp_path / "state.json").write_text(json.dumps(st))
    with pytest.raises(agent.AgentError):
        agent.WinJob(run=host, state_path=str(tmp_path / "state.json"), build=lambda: host.build)


# ---- fleet operations on the host (plan T13, T14, T41, T42)

def test_never_starts_on_battery(tmp_path):
    h = FakeWin(battery="battery 31%")
    r = make(tmp_path, h).advance()
    assert r["outcome"] == "aborted" and "battery 31%" in r["error"]
    assert not any("CreateUpdateDownloader" in c[-1] for c in h.log if c[0] == "powershell")


def test_never_downloads_onto_a_nearly_full_system_drive(tmp_path):
    h = FakeWin(free_gb="3")
    r = make(tmp_path, h).advance()
    assert r["outcome"] == "aborted" and "3 GB free" in r["error"]
    assert not any("CreateUpdateDownloader" in c[-1] for c in h.log if c[0] == "powershell")


def test_not_offered_says_why_from_the_machines_update_settings(tmp_path):
    h = FakeWin(offered=(), why="this machine gets updates from WSUS (http://wsus:8530); WSUS hasn't approved KB5126646 for it")
    r = make(tmp_path, h).advance()
    assert r["outcome"] == "aborted" and "WSUS hasn't approved KB5126646" in r["steps"][-1]["output"]
    r = make(tmp_path, FakeWin(offered=())).advance()
    assert "not needed, superseded, or not released" in r["steps"][-1]["output"]
    win10 = {**HOT_JOB, "packages": [{**HOT_JOB["packages"][0], "name": "Windows 10 Version 22H2 for x64-based Systems"}]}
    r = make(tmp_path, FakeWin(offered=()), win10).advance()  # real Windows 10 22H2 without a licence
    assert r["outcome"] == "aborted" and "0 offered" in r["steps"][-1]["output"] and "Extended Security Updates" in r["steps"][-1]["output"]
    r = make(tmp_path, FakeWin(offered=(), esu=1), win10).advance()
    assert "Extended Security Updates" not in r["steps"][-1]["output"]
    # Server 2022 is supported without ESU: a real VM was told it needed a licence
    ws22 = {**HOT_JOB, "packages": [{**HOT_JOB["packages"][0], "name": "Windows Server 2022 (Server Core installation)"}]}
    h = FakeWin(offered=())
    r = make(tmp_path, h, ws22).advance()
    assert "Extended Security Updates" not in r["steps"][-1]["output"] and h.searches == 1  # one search for both KBs


def test_a_long_reason_is_cut_at_a_clause_not_mid_word():
    assert agent.clause_tail("short") == "short"
    cut = agent.clause_tail("x" * 400 + "; no Extended Security Updates licence is active; it offers instead: " + "y" * 200)
    assert cut.startswith("...it offers instead") or cut.startswith("...no Extended")


# ---- what Windows Update offers instead (DECISIONS 95): a real Server 2022 VM at 20348.587 was offered only 2023-11
WS22_OFFERS = ('[{"kb":"5032198","title":"2023-11 Cumulative Update for Microsoft server operating system version 21H2 for x64-based Systems (KB5032198)"},'
               '{"kb":"5032005","title":"2023-11 Cumulative Update for .NET Framework 3.5, 4.8 and 4.8.1 for Microsoft server operating system version 21H2 for x64 (KB5032005)"}]')


def test_not_offered_reports_what_windows_update_offers_instead_and_installs_none_of_it(tmp_path):
    h = FakeWin(offered=(), instead=WS22_OFFERS)
    r = make(tmp_path, h, HOT_JOB).advance()
    assert r["outcome"] == "aborted" and r["error"].startswith("No changes made")
    assert [x["kb"] for x in r["offered"]] == ["5032198", "5032005"] and r["offered"][0]["title"].startswith("2023-11 Cumulative Update")
    assert "it offers instead: KB5032198 (2023-11 Cumulative Update" in r["steps"][-1]["output"]
    assert not any(s in c[-1] for c in h.log if c[0] == "powershell" for s in ("CreateUpdateDownloader", "CreateUpdateInstaller"))
    script = agent.PS_FIND  # one search: the job's KBs first, then the security updates by classification ID, at most 10
    assert script.index("@(%KBS%)") < script.index("0fa1201d-4330-4fa8-8ae9-b877473b6441") and "-First 10" in script
    assert json.loads(json.dumps(r))["offered"] == r["offered"]  # it goes in the report as it is


def test_a_translated_offer_is_reported_as_is(tmp_path):
    # German Windows (real VM; "ü" arrives as "?"): picked by classification ID, so no English word decides anything
    german = '[{"kb":"5122878","title":"2026-09 Kumulatives Update f?r Windows 10 Version 21H2 f?r x64-basierte Systeme (KB5122878)"}]'
    r = make(tmp_path, FakeWin(offered=(), instead=german)).advance()
    assert r["offered"] == [{"kb": "5122878", "title": "2026-09 Kumulatives Update f?r Windows 10 Version 21H2 f?r x64-basierte Systeme (KB5122878)"}]
    assert "Cumulative" not in agent.PS_FIND and "-match" not in agent.PS_FIND  # no title is matched on the host


@pytest.mark.parametrize("instead", [
    "not json", '{"kb": "5032198"}', "[]", '["KB5032198", {"kb": "50321; calc", "title": "x"}, {"title": "no kb"}, {"kb": null}]'])
def test_a_garbled_offer_list_is_dropped(tmp_path, instead):
    r = make(tmp_path, FakeWin(offered=(), instead=instead)).advance()
    assert r["outcome"] == "aborted" and "offered" not in r and "Windows Update offers exactly KB5126646" in r["steps"][-1]["step"]
    assert "offers instead" not in r["steps"][-1]["output"]


def test_offer_list_is_bounded_and_only_sent_when_nothing_the_job_names_is_offered(tmp_path):
    many = json.dumps([{"kb": str(5000000 + i), "title": "t" * 500} for i in range(40)])
    r = make(tmp_path, FakeWin(offered=(), instead=many)).advance()
    assert len(r["offered"]) == 10 and all(len(x["title"]) == 200 for x in r["offered"])
    r = make(tmp_path, FakeWin(instead=WS22_OFFERS)).advance()  # the job's KB is offered: installed, nothing else said
    assert r["outcome"] == "pending_reboot" and "offered" not in r
    netfx = {**JOB, "packages": [{**JOB["packages"][0], "name": ".NET Framework 4.8.1 on Windows Server 2022"}]}
    r = agent.WinJob(netfx, run=FakeWin(offered=(), instead=WS22_OFFERS), state_path=str(tmp_path / "n.json"), build=lambda: OLD,
                     retry_wait=0).advance()  # the OS update on offer isn't its business; the combined .NET cumulative is (DECISIONS 118)
    assert r["outcome"] == "aborted" and "Windows Update offers exactly KB5126646" in r["steps"][-1]["step"]
    assert [x["kb"] for x in r["offered"]] == ["5032005"]
    r = agent.WinJob(netfx, run=FakeWin(offered=(), instead=json.dumps(json.loads(WS22_OFFERS)[:1])), state_path=str(tmp_path / "n2.json"),
                     build=lambda: OLD, retry_wait=0).advance()
    assert r["outcome"] == "aborted" and "offered" not in r  # only OS updates on offer: nothing said


def test_a_netfx_umbrella_is_judged_by_the_per_version_package_it_downloads(tmp_path):
    """Real Server 2019 (2026-11-08): KB5128923 (the combined cumulative) arrives as Windows10.0-KB5127666-x64.cab."""
    class Umbrella(FakeWin):
        def __call__(self, cmd, cwd=None, timeout=None):
            script = cmd[-1] if isinstance(cmd, list) else ""
            if "downloaded package for KB%" not in script and "CumulativeUpdate_KB5128923" in script:
                return 1, "downloaded package for KB5128923 not found"
            return super().__call__(cmd, cwd=cwd, timeout=timeout)
    netfx = {**JOB, "packages": [{**JOB["packages"][0], "name": ".NET Framework 4.7 on Windows Server 2019", "kb": "5127666",
                                  "alt": {"kb": "5128923", "to": JOB["packages"][0]["to"]}}]}
    h = Umbrella(offered=("5128923",))
    h.pkgs["Package_for_DotNetRollup~31bf3856ad364e35~amd64~~10.0.4005.2"] = "Installed"  # as the real server's own rollup
    r = agent.WinJob(netfx, run=h, state_path=str(tmp_path / "n.json"), build=lambda: OLD, retry_wait=0).advance()
    [rm] = [s for s in r["steps"] if s["step"].startswith("update is removable")]
    assert rm["ok"], rm
    j = agent.WinJob(netfx, run=h, state_path=str(tmp_path / "n.json"), build=lambda: OLD)
    j.s = dict(json.load(open(tmp_path / "n.json")))
    assert j.valid() and j.s["named_kb"] == "5127666"
    j.s["named_kb"] = "5127666; calc"  # the saved state is never trusted: it goes into PowerShell after the restart
    assert not j.valid()
    for field, bad in (("to", "10.0.26100.abc"), ("from", "10.0.x"), ("alt", {"kb": "5128923", "to": "4.8.v2"})):
        j.s = {**dict(json.load(open(tmp_path / "n.json"))), field: bad}
        assert not j.valid(), field  # a build that only fails to compare after the install would roll a good update back


def test_a_service_that_crashed_since_the_change_fails_health_even_if_running(tmp_path):
    h = FakeWin(crashes="event 7031 at 2026-10-29T03:01:00")
    make(tmp_path, h).advance()
    h.reboot()
    r = resume(tmp_path, h)
    assert r["outcome"] == "pending_reboot"  # rolled back
    st = json.loads((tmp_path / "state.json").read_text())
    assert "event 7031" in st["error"] and st["phase"] == "rolled_back_pending"


def test_cluster_node_is_drained_first_and_resumed_after(tmp_path):
    h = FakeWin(cluster=True)
    make(tmp_path, h).advance()
    scripts = [c[-1] for c in h.log if c[0] == "powershell"]
    assert next(i for i, s in enumerate(scripts) if "Suspend-ClusterNode" in s) < next(i for i, s in enumerate(scripts) if "CreateUpdateInstaller" in s)
    h.reboot()
    r = resume(tmp_path, h)
    assert r["outcome"] == "applied" and r["steps"][-1]["step"] == "cluster node resumed"


def test_failed_drain_changes_nothing_and_resumes_the_node(tmp_path):
    h = FakeWin(cluster=True, drain="")
    r = make(tmp_path, h).advance()
    assert r["outcome"] == "aborted" and r["error"].startswith("No changes made")
    assert any("Resume-ClusterNode" in c[-1] for c in h.log if c[0] == "powershell")
    assert not any("CreateUpdateInstaller" in c[-1] for c in h.log if c[0] == "powershell")


def restart_host(tmp_path, signed_in):
    h = FakeWin()
    make(tmp_path, h, {**JOB, "reboot_by": "2026-10-30T12:00:00Z"}).advance()
    calls = []

    def run(cmd, cwd=None):
        calls.append(cmd)
        if cmd[0] == "powershell" and "explorer.exe" in cmd[-1]:
            return 0, "1" if signed_in else "0"
        return h(cmd) if cmd[0] != "msg" and cmd[0] != "shutdown" else (0, "")
    return run, calls


def test_workstation_restart_is_put_off_until_the_deadline_then_forced(tmp_path):
    run, calls = restart_host(tmp_path, signed_in=True)
    deadline = 1793361600  # 2026-10-30T12:00:00Z
    before = deadline - 3600 * 5
    assert agent.restart_for_update(run, str(tmp_path / "state.json"), client=True, now=before)[0] == "later"
    assert [c[0] for c in calls if c[0] in ("msg", "shutdown")] == ["msg"]
    agent.restart_for_update(run, str(tmp_path / "state.json"), client=True, now=before + 600)
    assert [c[0] for c in calls if c[0] == "msg"] == ["msg"]  # reminded at most hourly
    assert agent.restart_for_update(run, str(tmp_path / "state.json"), client=True, now=deadline + 1)[0] == "now"
    assert [c for c in calls if c[0] == "shutdown"][0][:4] == ["shutdown", "/r", "/t", "900"]  # 15-minute warning


def test_servers_and_empty_workstations_restart_now(tmp_path):
    run, calls = restart_host(tmp_path, signed_in=False)
    assert agent.restart_for_update(run, str(tmp_path / "state.json"), client=True, now=0)[0] == "now"
    assert [c for c in calls if c[0] == "shutdown"][0][:4] == ["shutdown", "/r", "/t", "60"]
    run, calls = restart_host(tmp_path, signed_in=True)
    assert agent.restart_for_update(run, str(tmp_path / "state.json"), client=False, now=0)[0] == "now"


def test_a_job_whose_restart_was_put_off_is_not_judged_early(tmp_path):
    h = FakeWin()
    make(tmp_path, h).advance()

    def run(cmd, cwd=None):
        if cmd[0] == "powershell" and "RebootPending" in cmd[-1]:
            return 0, "True"
        return h(cmd)
    import os
    if os.name != "nt":
        pytest.skip("Windows resume path")
    problems, reboot = agent.run_jobs("https://s", "k", False, run=run, outcome_dir=str(tmp_path / "out"),
                                      win_state=str(tmp_path / "state.json"))
    assert reboot and json.loads((tmp_path / "state.json").read_text())["phase"] == "verify"


def test_microsoft_update_source_is_local_only(tmp_path, monkeypatch):
    h = FakeWin()
    make(tmp_path, h).advance()
    assert not any("ServerSelection = 2" in c[-1] for c in h.log if c[0] == "powershell")  # default: the host's own source
    monkeypatch.setattr(agent, "WU_SOURCE", "microsoft")
    h2 = FakeWin()
    (tmp_path / "b").mkdir()
    make(tmp_path / "b", h2).advance()
    searches = [c[-1] for c in h2.log if c[0] == "powershell" and "CreateUpdateSearcher" in c[-1]]
    assert searches and all("$q.ServerSelection = 2" in s for s in searches)
    assert "windows_update_source" not in json.dumps(JOB)  # never part of a job


def test_a_rollback_is_never_judged_before_its_restart(tmp_path):
    """Seen for real on Windows 11: DISM /norestart sets no reboot-pending flag, a job poll resumed the job before the
    restart, saw the new build still running and reported ROLLBACK FAILED."""
    h = FakeWin(service_breaks_on_new=True)
    make(tmp_path, h).advance()
    h.reboot()
    assert resume(tmp_path, h)["outcome"] == "pending_reboot"  # rollback started, waits for its own restart
    for _ in range(3):  # polls before that restart change and judge nothing
        assert resume(tmp_path, h)["outcome"] == "pending_reboot" and h.build == NEW
    h.reboot()
    r = resume(tmp_path, h)
    assert r["outcome"] == "rolled_back" and h.build == OLD


def test_windows_10_plan_is_the_servicing_stack_with_the_update_only_a_download():
    # real ActionList.xml, Windows 10 LTSC 2021: its actions name the servicing stack alone, the cumulative update is a <Downloads> cab
    assert "$plan.Downloads.Package" in agent.PS_PERMANENCE and "FeatureId -eq 'CumulativeUpdate_KB%KB%'" in agent.PS_PERMANENCE
    ok, detail = agent.removable([
        {"file": "SSU-19041.7714-x64-express", "reason": "ServicingStackUpdate", "partition": "MainOS", "permanent": True, "permanent_parts": ["update.mum"]},
        {"file": "Windows10.0-KB5122878-x64.cab", "reason": "CumulativeUpdate", "partition": "MainOS", "permanent": False, "permanent_parts": []}])
    assert ok and "Windows10.0-KB5122878-x64.cab" in detail and "stays after rollback" in detail


# ---- a forward-only servicing step (DECISIONS 105): installed only as what its own manifest says, verified by the KB being there
class FakeSSU(FakeWin):
    def __init__(self, name="KB5062799|selfUpdate=true|permanent", installs=True, **kw):  # as Server 2016's real update.mum reads
        super().__init__(offered=kw.pop("offered", ("5062799",)), **kw)
        self.mum, self.installs, self.hotfix = name, installs, False

    def __call__(self, cmd, cwd=None, timeout=None):
        if cmd[0] == "powershell":
            script = cmd[-1]
            if "selfUpdate" in script:
                return 0, self.mum
            if "Get-HotFix" in script:
                return 0, str(self.hotfix)
            if "CreateUpdateInstaller" in script and "5062799" in script:
                self.hotfix = self.installs
                return 0, json.dumps({"download": 2, "install": 2 if self.installs else 4, "reboot": False})
        return super().__call__(cmd, cwd, timeout)


SSU_JOB = {**JOB, "packages": [{**JOB["packages"][0], "alt": {"kb": "5062799", "to": OLD}, "servicing": True}]}


def test_a_servicing_stack_update_is_installed_only_as_its_manifest_says_and_verified_by_the_kb(tmp_path):
    h = FakeSSU()
    r = make(tmp_path, h, SSU_JOB).advance()
    assert r["outcome"] == "applied" and r["versions"] == {JOB["packages"][0]["name"]: OLD}  # the build doesn't move
    names = [s["step"] for s in r["steps"]]
    assert "update is a servicing stack update (its own manifest)" in names and "KB5062799 installed" in names
    assert not any("removable" in n for n in names)  # its permanence isn't the question here: it's the agreed exception
    assert not any(c[:3] == ["dism", "/online", "/remove-package"] for c in h.log)


def test_anything_else_on_the_servicing_path_is_refused_with_no_changes(tmp_path):
    h = FakeSSU(name="KB5062799|selfUpdate=|permanent")  # permanent but not a servicing stack update: a cumulative's mum
    r = make(tmp_path, h, SSU_JOB).advance()
    assert r["outcome"] == "aborted" and r["error"].startswith("No changes made")
    assert not any("CreateUpdateInstaller" in c[-1] for c in h.log if c[0] == "powershell")
    # if Windows Update offers the cumulative itself instead, it's the normal, reversible path
    r = make(tmp_path, FakeSSU(offered=("5126646",)), SSU_JOB).advance()
    assert r["outcome"] == "pending_reboot" and any("removable" in s["step"] for s in r["steps"])


def test_a_servicing_install_that_fails_its_check_is_reported_as_needing_attention_not_rolled_back(tmp_path):
    from nimstead.remediate import AGENT_OUTCOMES
    h = FakeSSU(installs=False)
    r = make(tmp_path, h, SSU_JOB).advance()
    assert r["outcome"] in AGENT_OUTCOMES and r["outcome"] not in ("rolled_back", "applied"), r  # the server must accept it
    assert not any(c[:3] == ["dism", "/online", "/remove-package"] for c in h.log)


def test_a_power_cut_during_a_servicing_install_is_judged_by_the_kb(tmp_path):
    for there, outcome in ((True, "applied"), (False, "aborted")):
        h = FakeSSU()
        w = make(tmp_path, h, SSU_JOB)
        w.s.update(kb="5062799", to=OLD, installing=True, baseline={BASE_PKG: "Installed"})
        w.save()
        h.hotfix = there
        assert resume(tmp_path, h)["outcome"] == outcome



@pytest.mark.skipif(sys.platform != "win32", reason="needs Windows PowerShell and a real service")
def test_the_service_check_reads_a_running_service_and_gives_up_on_a_missing_one():
    """The wait only applies to an automatic service still starting: one already running reads at once."""
    rc, out = agent.ps(agent.sh, agent.PS_SERVICE_UP.replace("%SVC%", "EventLog"), timeout=60)
    assert rc == 0 and out.strip().splitlines()[-1] == "Running"
    rc, _ = agent.ps(agent.sh, agent.PS_SERVICE_UP.replace("%SVC%", "NoSuchServiceNimstead"), timeout=60)
    assert rc != 0
    rc, out = agent.ps(agent.sh, agent.PS_CRASHES.replace("%SVC%", "EventLog").replace("%SINCE%", "0"), timeout=60)
    assert rc == 0, out  # from the last boot, not 1970: runs, and finds nothing for a service that hasn't crashed
