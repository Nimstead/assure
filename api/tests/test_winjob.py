"""Windows remediation state machine against a simulated host (real proof: sandbox/winvm.py on Windows Server 2025
and Windows 11)."""

import json
import re
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
                 battery="", cluster=False, drain="Paused", crashes="", why="", install_times_out=False, free_gb="50"):
        self.build, self.pkgs, self.manifest = OLD, {BASE_PKG: "Installed"}, manifest
        self.offered, self.breaks, self.removal_works = list(offered), service_breaks_on_new, removal_works
        self.pending_remove, self.log, self.busy = [], [], busy_removals
        self.battery, self.cluster, self.drain, self.crashes, self.why = battery, cluster, drain, crashes, why
        self.boot, self.install_times_out, self.free_gb = 1_700_000_000, install_times_out, free_gb

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
            if "KBArticleIDs" in script:
                kb = script.split("-contains '")[1].split("'")[0]
                return 0, json.dumps([{"title": f"Cumulative Update (KB{kb})", "uninstallable": False}] if kb in self.offered else [])
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
