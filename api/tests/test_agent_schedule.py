"""The agent's own schedule (systemd timers / scheduled tasks), the 15-minute job poll, and uninstall."""

import json
import os
import sys

import pytest
from test_agent_remediate import agent

CFG = {"server": "https://nimstead.example", "agent_key": "nma_x"}


class FakeSystemctl:
    def __init__(self, fail=None):
        self.calls, self.fail = [], fail

    def __call__(self, cmd, cwd=None):
        self.calls.append(cmd)
        return (1, "boom") if self.fail and self.fail in cmd else (0, "")


@pytest.fixture
def cfgfile(tmp_path, monkeypatch):
    p = tmp_path / "etc" / "agent.json"
    monkeypatch.setattr(agent, "config_path", lambda: str(p))
    monkeypatch.setattr(agent, "secure_windows_dir", lambda *a, **k: [])
    return p


def test_units_report_every_6h_and_poll_for_jobs_only_when_opted_in():
    plain = agent.schedule_units(CFG)
    assert set(plain) == {"nimstead-agent.service", "nimstead-agent.timer"}
    assert plain["nimstead-agent.service"].rstrip().endswith(" report") and "OnUnitActiveSec=6h" in plain["nimstead-agent.timer"]
    assert " -I " in plain["nimstead-agent.service"]  # isolated interpreter, as root
    fixes = agent.schedule_units({**CFG, "allow_remediation": True})
    assert fixes["nimstead-agent.service"].rstrip().endswith(" remediate")
    assert fixes["nimstead-agent-jobs.service"].rstrip().endswith(" remediate --if-jobs") and "OnUnitActiveSec=15min" in fixes["nimstead-agent-jobs.timer"]
    assert "--insecure-http" in agent.schedule_units({**CFG, "server": "http://localhost:8000"})["nimstead-agent.service"]


def test_schedule_writes_enables_and_records_its_version(tmp_path, cfgfile, monkeypatch):
    monkeypatch.setattr(agent.os, "name", "posix")
    run = FakeSystemctl()
    msg = agent.schedule({**CFG, "allow_remediation": True}, run=run, unit_dir=str(tmp_path), systemd=True)
    assert "15 minutes" in msg
    assert sorted(f.name for f in tmp_path.glob("nimstead-*")) == sorted(agent.schedule_units({**CFG, "allow_remediation": True}))
    assert ["systemctl", "enable", "--now", "nimstead-agent-jobs.timer"] in run.calls
    assert json.loads(cfgfile.read_text())["schedule_version"] == agent.SCHEDULE_VERSION
    # host re-enrolled without remediation: the job poll goes away
    run = FakeSystemctl()
    agent.schedule(CFG, run=run, unit_dir=str(tmp_path), systemd=True)
    assert not (tmp_path / "nimstead-agent-jobs.timer").exists() and ["systemctl", "disable", "--now", "nimstead-agent-jobs.timer"] in run.calls


def test_schedule_failures_are_loud_and_cron_hosts_get_the_lines(tmp_path, cfgfile, monkeypatch):
    monkeypatch.setattr(agent.os, "name", "posix")
    with pytest.raises(agent.AgentError, match="daemon-reload"):
        agent.schedule(CFG, run=FakeSystemctl(fail="daemon-reload"), unit_dir=str(tmp_path), systemd=True)
    msg = agent.schedule({**CFG, "allow_remediation": True}, run=FakeSystemctl(), unit_dir=str(tmp_path), systemd=False)
    assert "cron" in msg and "remediate --if-jobs" in msg


def test_windows_tasks_are_quoted_and_the_poll_is_removed_when_not_opted_in():
    s = agent.schedule_windows_script({**CFG, "allow_remediation": True})
    assert "'Nimstead jobs'" in s and "remediate --if-jobs" in s and "-AtStartup" in s and "-User 'SYSTEM'" in s
    last = agent.schedule_windows_script(CFG).splitlines()[-1]
    assert "'Nimstead jobs'" in last and "Unregister-ScheduledTask" in last and "SilentlyContinue" not in last
    assert agent._ps_quote("C:\\it's\\python.exe") == "'C:\\it''s\\python.exe'"


@pytest.mark.skipif(agent.os.name != "nt", reason="PowerShell's -Command exit code")
def test_removing_a_missing_job_poll_still_exits_0():
    """Seen on a real Windows 11 VM: a silenced 'not found' as the last statement made powershell -Command exit 1 with no
    output, so every install without remediation failed at scheduling. Uses a task name that can't exist: changes nothing."""
    last = agent.schedule_windows_script(CFG).splitlines()[-1].replace("'Nimstead jobs'", "'nimstead-test-no-such-task'")
    old = "Unregister-ScheduledTask -TaskName 'nimstead-test-no-such-task' -Confirm:$false -ErrorAction SilentlyContinue"
    assert agent.ps(agent.sh, f"$ErrorActionPreference = 'Stop'\n{old}")[0] == 1  # the bug, as Windows behaves
    assert agent.ps(agent.sh, f"$ErrorActionPreference = 'Stop'\n{last}")[0] == 0


def test_schedule_if_changed_does_nothing_when_current(cfgfile, monkeypatch):
    cfgfile.parent.mkdir(parents=True)
    cfgfile.write_text(json.dumps({**CFG, "schedule_version": agent.SCHEDULE_VERSION}))
    monkeypatch.setattr(agent, "schedule", lambda *a, **k: pytest.fail("rescheduled"))
    assert agent.main(["--no-self-update", "schedule", "--if-changed"]) == 0


def test_job_poll_reports_inventory_only_when_a_job_ran(cfgfile, monkeypatch):
    cfgfile.parent.mkdir(parents=True)
    cfgfile.write_text(json.dumps({**CFG, "allow_remediation": True}))
    monkeypatch.setattr(agent, "run_lock", type("L", (), {"__enter__": lambda s: s, "__exit__": lambda s, *a: None}))
    monkeypatch.setattr(agent, "collect", lambda: {"packages": [{"name": "x"}]})
    posted, jobs = [], []
    monkeypatch.setattr(agent, "post", lambda server, path, body, insecure, key=None, raw=False: posted.append(path) or {})

    def fake_run_jobs(server, key, insecure, ran):
        ran.extend(jobs)
        return 0, False
    monkeypatch.setattr(agent, "run_jobs", fake_run_jobs)
    assert agent.main(["--no-self-update", "remediate", "--if-jobs"]) == 0 and posted == []  # idle poll: nothing sent
    jobs.append("j1")
    assert agent.main(["--no-self-update", "remediate", "--if-jobs"]) == 0 and posted == ["/api/agent/inventory"]
    jobs.clear()
    posted.clear()
    assert agent.main(["--no-self-update", "remediate"]) == 0 and posted == ["/api/agent/inventory"]  # the 6-hourly run always reports


def test_busy_lock_skips_the_update_instead_of_failing_the_run(cfgfile, monkeypatch):
    cfgfile.parent.mkdir(parents=True)
    cfgfile.write_text(json.dumps(CFG))

    class Busy:
        def __enter__(self):
            raise agent.AgentError("another nimstead-agent run is in progress")

        def __exit__(self, *a):
            pass
    monkeypatch.setattr(agent, "run_lock", Busy)
    monkeypatch.setattr(agent, "self_update", lambda *a: pytest.fail("updated while another run held the lock"))
    monkeypatch.setattr(agent, "collect", lambda: {"packages": [{"name": "x"}]})
    monkeypatch.setattr(agent, "post", lambda *a, **k: {})
    assert agent.main(["report"]) == 0


def test_update_reapplies_the_schedule_with_the_new_agent(cfgfile, monkeypatch):
    cfgfile.parent.mkdir(parents=True)
    cfgfile.write_text(json.dumps({**CFG, "schedule_version": 1}))
    monkeypatch.setattr(agent, "run_lock", type("L", (), {"__enter__": lambda s: s, "__exit__": lambda s, *a: None}))
    monkeypatch.setattr(agent, "self_update", lambda c, i: ("9.0.0", None))
    calls = []
    monkeypatch.setattr(agent.subprocess, "call", lambda argv: calls.append(argv[-3:] if "schedule" in argv else argv[-1:]) or 0)
    assert agent.main(["remediate"]) == 0
    assert calls == [["--no-self-update", "schedule", "--if-changed"], ["remediate"]]


# --- uninstall ------------------------------------------------------------------------------------------------------

@pytest.fixture
def installed(tmp_path, monkeypatch):
    monkeypatch.setattr(agent.os, "name", "posix")
    units, state, lib = tmp_path / "units", tmp_path / "etc-nimstead", tmp_path / "lib"
    for d in (units, state, lib):
        d.mkdir()
    for u in ("nimstead-agent.service", "nimstead-agent.timer", "nimstead-agent-jobs.service", "nimstead-agent-jobs.timer"):
        (units / u).write_text("x")
    (state / "agent.json").write_text(json.dumps(CFG))
    (lib / "nimstead_agent.py").write_text("x")
    (lib / "nimstead_agent.py.prev").write_text("x")
    return units, state, lib


def test_uninstall_removes_schedule_state_and_agent(installed, tmp_path):
    units, state, lib = installed
    outside = tmp_path / "precious"
    outside.mkdir()
    (outside / "keep.txt").write_text("keep")
    if hasattr(os, "symlink"):
        try:
            os.symlink(outside, state / "link", target_is_directory=True)
        except OSError:
            pass  # no symlink privilege on this Windows account
    run = FakeSystemctl()
    removed = agent.uninstall(run=run, unit_dir=str(units), state_dirs=[str(state)], agent_path=str(lib / "nimstead_agent.py"))
    assert not list(units.iterdir()) and not state.exists() and not lib.exists()
    assert (outside / "keep.txt").read_text() == "keep"  # a link inside the state dir is removed, never followed
    assert ["systemctl", "daemon-reload"] in run.calls and str(state) in removed


def test_uninstall_needs_yes(cfgfile):
    assert agent.main(["uninstall"]) == 1


@pytest.mark.skipif(sys.platform != "win32", reason="Windows job state path")
def test_uninstall_refused_while_a_windows_job_waits_for_its_restart(tmp_path, monkeypatch):
    state = tmp_path / "pending-job.json"
    state.write_text("{}")
    monkeypatch.setattr(agent, "WIN_STATE", str(state))
    with pytest.raises(agent.AgentError, match="restart"):
        agent.uninstall(run=FakeSystemctl(), state_dirs=[str(tmp_path / "none")], agent_path=str(tmp_path / "a.py"))


def test_windows_schedule_refuses_an_interpreter_users_can_modify(cfgfile, monkeypatch):
    monkeypatch.setattr(agent.os, "name", "nt")
    monkeypatch.setenv("ProgramFiles", r"C:\Program Files")
    monkeypatch.delenv("ProgramFiles(x86)", raising=False)
    monkeypatch.setattr(agent.sys, "executable", r"C:\Users\bob\AppData\Local\Programs\Python\python.exe")
    with pytest.raises(agent.AgentError, match="Program Files"):
        agent.schedule(CFG, run=lambda *a, **k: pytest.fail("registered a task"))
    monkeypatch.setattr(agent.sys, "executable", r"C:\Program Files\Python313\python.exe")
    monkeypatch.setattr(agent, "ps", lambda run, script: (0, ""))
    assert "every 6 hours" in agent.schedule(CFG)


def test_unwritable_lock_folder_skips_the_update_but_still_reports(cfgfile, monkeypatch, tmp_path):
    """Regression (CI, non-root): the self-update step's lock folder can't be created; the run must still report."""
    cfgfile.parent.mkdir(parents=True)
    cfgfile.write_text(json.dumps(CFG))
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("x")
    monkeypatch.setattr(agent.run_lock, "dir", str(blocker / "lock"))
    monkeypatch.setattr(agent, "self_update", lambda *a: pytest.fail("updated without the lock"))
    monkeypatch.setattr(agent, "collect", lambda: {"packages": [{"name": "x"}]})
    posted = []
    monkeypatch.setattr(agent, "post", lambda server, path, *a, **k: posted.append(path) or {})
    assert agent.main(["report"]) == 0 and posted == ["/api/agent/inventory"]
