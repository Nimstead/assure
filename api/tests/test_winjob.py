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
    def __init__(self, offered=("5126646",), service_breaks_on_new=False, removal_works=True, busy_removals=0, manifest="removable"):
        self.build, self.pkgs, self.manifest = OLD, {BASE_PKG: "Installed"}, manifest
        self.offered, self.breaks, self.removal_works = list(offered), service_breaks_on_new, removal_works
        self.pending_remove, self.log, self.busy = [], [], busy_removals

    def __call__(self, cmd, cwd=None):
        self.log.append(cmd)
        if cmd[0] == "powershell":
            script = cmd[-1]
            if "RebootPending" in script:
                return 0, "False"
            if "Get-Service" in script:
                return 0, "Stopped" if self.breaks and self.build == NEW else "Running"
            if "CreateUpdateInstaller" in script:
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
        if self.pkgs.get(NEW_PKG) == "Install Pending":
            self.pkgs[NEW_PKG], self.build = "Installed", NEW
        for p in self.pending_remove:
            self.pkgs.pop(p, None)
            self.build = OLD
        self.pending_remove = []


JOB = {"id": "w1", "manager": "windows", "health_units": ["W3SVC"], "settle_seconds": 0,
       "packages": [{"name": "Windows Server 2025 (Server Core installation)", "from": OLD, "to": NEW, "kb": "5126646"}]}


def make(tmp_path, host, job=JOB):
    return agent.WinJob(job, run=host, state_path=str(tmp_path / "state.json"), build=lambda: host.build, retry_wait=0)


def resume(tmp_path, host):
    return agent.WinJob(run=host, state_path=str(tmp_path / "state.json"), build=lambda: host.build, retry_wait=0).advance()


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
