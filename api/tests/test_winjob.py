"""Windows remediation state machine against a simulated host (real proof: sandbox/winvm.py on Windows Server 2025)."""

import json

from test_agent_remediate import agent

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
                return 0, json.dumps({"file": "Windows11.0-KB5126646-x64.wim", "permanent": self.manifest == "permanent",
                                      "permanent_parts": ["Microsoft-Windows-SenseClient-FoD-Package.mum"]})
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
