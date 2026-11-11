"""`doctor` (reads the host, changes nothing) and the agent's local log (bounded, no secrets, never stops a run)."""

import json
import os
import sys
import urllib.error

import pytest
from test_agent_remediate import agent

KEY = "nma_the-agent-key"
TOKEN = "nme_the-enrol-token"
DATE = "Mon, 02 Nov 2026 12:00:00 GMT"
NOW = 1793620800  # that Date
REAL_LOG_PATH = agent.LOG_PATH  # read at import: tests run with it pointed at a temp folder
ACL_OK = "S-1-5-32-544\nTrue\nS-1-5-18\nS-1-5-32-544\n"
GB = 1 << 30


@pytest.fixture(autouse=True)
def reset(monkeypatch):
    monkeypatch.setattr(agent, "_proxy", None)
    monkeypatch.setattr(agent, "_opener", agent._opener)
    monkeypatch.setattr(agent, "_agent_key", None)
    monkeypatch.setattr(agent, "_log_on", False)


class Host:
    """A healthy host; a test breaks one thing. Records every command and refuses anything but the expected reads."""

    def __init__(self, acl=ACL_OK, tasks="Nimstead agent|Ready\nNimstead jobs|Running\n", wu="Stopped|Manual", enabled=True):
        self.acl, self.tasks, self.wu, self.enabled, self.calls = acl, tasks, wu, enabled, []

    def __call__(self, cmd, cwd=None, **kw):
        self.calls.append(cmd)
        if cmd[:2] == ["systemctl", "is-enabled"]:
            return (0, "enabled") if self.enabled else (1, "disabled")
        if cmd[:3] == ["netsh", "winhttp", "show"]:
            return 0, "    Direct access (no proxy server).\r\n"
        if cmd[0] == "powershell":
            script = cmd[-1]
            for marker, reply in (("Get-Acl", self.acl), ("Get-ScheduledTask", self.tasks), ("wuauserv", self.wu)):
                if marker in script:
                    return (0, reply) if isinstance(reply, str) else reply
        pytest.fail(f"doctor ran something it shouldn't: {cmd}")


def run_doctor(capsys, host=None, windows=True, cfg=None, **kw):
    monkey_defaults = {
        "run": host or Host(), "read": lambda: cfg if cfg is not None else {"server": "https://n.example", "agent_key": KEY, "allow_remediation": True},
        "fetch": lambda url: (200, DATE), "connect": lambda addr, timeout: FakeSock(), "now": lambda: NOW, "disk": lambda p: 5 * GB,
        "exists": lambda p: True, "windows": windows, "state_dir": "/no/such/state", "systemd": True, "version": (3, 13),
    }
    rc = agent.doctor(**{**monkey_defaults, **kw})
    return rc, capsys.readouterr().out


class FakeSock:
    def close(self):
        pass


@pytest.fixture
def program_files(monkeypatch):
    monkeypatch.setenv("ProgramFiles", r"C:\Program Files")
    monkeypatch.setattr(agent.sys, "executable", r"C:\Program Files\Nimstead\runtime\abc\python.exe")


def line(out, name):
    return next(x for x in out.splitlines() if x.split(":")[0].split(None, 1)[1:] == [name])


# --- doctor ---------------------------------------------------------------------------------------------------------


def test_healthy_windows_host_passes_every_check(capsys, program_files):
    rc, out = run_doctor(capsys)
    assert rc == 0, out
    assert "FAIL" not in out and "all 9 checks passed" in out
    for name in ("config", "proxy", "server", "clock", "schedule", "state folder", "Windows Update", "disk", "runtime"):
        assert line(out, name).startswith("ok ")
    assert f"log: {agent.LOG_PATH}" in out


def test_healthy_linux_host_uses_timers_and_skips_windows_only_checks(capsys):
    host = Host()
    rc, out = run_doctor(capsys, host, windows=False)
    assert rc == 0, out
    assert "state folder" not in out and "Windows Update" not in out
    assert ["systemctl", "is-enabled", "nimstead-agent-jobs.timer"] in host.calls


@pytest.mark.parametrize("kw,name,says", [
    ({"fetch": lambda url: (_ for _ in ()).throw(urllib.error.URLError("no route"))}, "server", "cannot reach"),
    ({"fetch": lambda url: (503, DATE)}, "server", "HTTP 503"),
    ({"fetch": lambda url: (302, DATE)}, "server", "don't follow redirects"),
    ({"fetch": lambda url: (200, None)}, "clock", "no usable Date"),
    ({"fetch": lambda url: (200, "not a date")}, "clock", "no usable Date"),
    ({"now": lambda: NOW + 301}, "clock", "301 seconds ahead of"),
    ({"now": lambda: NOW - 7200}, "clock", "7200 seconds behind"),
    ({"disk": lambda p: GB - 1}, "disk", "fixes need 1024 MiB"),
    ({"version": (3, 8)}, "runtime", "older than 3.9"),
    ({"exists": lambda p: False}, "runtime", "doesn't exist"),
    ({"cfg": {"server": "https://n.example", "python": r"C:\Users\Public\python.exe"}}, "runtime", "isn't under Program Files"),
    ({"cfg": {"server": "http://n.example"}}, "server", "is not HTTPS"),
    ({"insecure_http": True, "cfg": {"server": "http://n.example", "proxy": "http://p:3128"}}, "server", "refused through a proxy"),
    ({"cfg": {"server": "https://n.example", "proxy": "http://bad/$(calc)"}}, "proxy", "proxy must be"),
    ({"connect": lambda addr, timeout: (_ for _ in ()).throw(OSError("refused")), "cfg": {"server": "https://n.example", "proxy": "http://p:3128"}},
     "proxy", "cannot connect"),
])
def test_each_failure_is_named_with_a_fix_and_exits_non_zero(capsys, program_files, kw, name, says):
    rc, out = run_doctor(capsys, **kw)
    assert rc == 1
    assert line(out, name).startswith("FAIL") and says in line(out, name) and "Fix: " in line(out, name)
    assert "checks failed" in out


@pytest.mark.parametrize("host,name,says", [
    (Host(tasks="Nimstead jobs|Ready\n"), "schedule", "Nimstead agent"),  # the task removed
    (Host(tasks="Nimstead agent|Ready\nNimstead jobs|Disabled\n"), "schedule", "Nimstead jobs"),
    (Host(acl=(5, "Access is denied.")), "state folder", "cannot read"),
    (Host(acl="S-1-5-21-1-2-3-1001\nTrue\nS-1-5-18\n"), "state folder", "owner S-1-5-21-1-2-3-1001"),
    (Host(acl="S-1-5-32-544\nFalse\nS-1-5-18\n"), "state folder", "inheritance off: False"),
    (Host(acl="S-1-5-32-544\nTrue\nS-1-5-18\nS-1-5-32-545\n"), "state folder", "also allowed: S-1-5-32-545"),
    (Host(wu="Stopped|Disabled"), "Windows Update", "disabled"),
    (Host(wu=(1, "Cannot find any service")), "Windows Update", "cannot read"),
])
def test_windows_failures(capsys, program_files, host, name, says):
    rc, out = run_doctor(capsys, host)
    assert rc == 1 and line(out, name).startswith("FAIL") and says in line(out, name) and "Fix: " in line(out, name)


def test_windows_update_stopped_is_healthy_because_it_starts_on_demand(capsys, program_files):
    rc, out = run_doctor(capsys, Host(wu="Stopped|Manual"))
    assert rc == 0 and line(out, "Windows Update").startswith("ok ")


def test_acl_is_judged_by_sid_not_by_localised_name(capsys, program_files):
    rc, _ = run_doctor(capsys, Host(acl="S-1-5-32-544\nTrue\nS-1-5-18\nS-1-5-32-544\n"))
    assert rc == 0
    rc, out = run_doctor(capsys, Host(acl="Administratoren\nTrue\nSYSTEM\nAdministratoren\n"))
    assert rc == 1 and line(out, "state folder").startswith("FAIL")
    assert "[Security.Principal.SecurityIdentifier]" in agent.PS_DOCTOR_ACL


def test_linux_timer_missing_or_no_systemd(capsys):
    rc, out = run_doctor(capsys, Host(enabled=False), windows=False)
    assert rc == 1 and "nimstead-agent.timer" in line(out, "schedule")
    rc, out = run_doctor(capsys, Host(enabled=False), windows=False, systemd=False)
    assert rc == 0 and "isn't checked" in line(out, "schedule")


def test_no_config_fails_what_needs_it_and_still_runs_the_rest(capsys, program_files):
    def unreadable():
        raise PermissionError("denied")
    rc, out = run_doctor(capsys, read=unreadable)
    assert rc == 1 and "Run this as Administrator" in line(out, "config")
    assert "not checked" in line(out, "server") and line(out, "disk").startswith("ok ")


def test_a_check_that_blows_up_is_a_failure_and_the_rest_run(capsys, program_files):
    def boom(path):
        raise RuntimeError("boom")
    rc, out = run_doctor(capsys, disk=boom)
    assert rc == 1 and "could not check" in line(out, "disk") and line(out, "runtime").startswith("ok ")


def test_only_reads_and_sends_no_key(capsys, monkeypatch, tmp_path, program_files):
    seen = []

    class Reply:
        status, headers = 200, {"Date": DATE}

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

    class Opener:
        def open(self, req, timeout):
            seen.append(req)
            return Reply()

    monkeypatch.setattr(agent, "_opener", Opener())
    state = tmp_path / "state"
    state.mkdir()
    (state / "agent.json").write_text("{}")
    before = sorted(os.listdir(state))
    host = Host()
    rc, out = run_doctor(capsys, host, fetch=agent._server_reply, state_dir=str(state))
    assert rc == 0, out
    assert [(r.get_method(), r.full_url) for r in seen] == [("GET", "https://n.example/api/health")]
    assert all(k.lower() != "authorization" for r in seen for k in r.headers)
    assert sorted(os.listdir(state)) == before  # and Host fails the test on any command but the reads
    assert KEY not in out
    assert not any(c[0] == "icacls" or "Register-" in c[-1] or "Set-" in c[-1] for c in host.calls)


def test_a_redirect_is_reported_not_followed():
    err = urllib.error.HTTPError("https://n.example/api/health", 302, "Found", {"Date": DATE}, None)

    class Opener:
        def open(self, req, timeout):
            raise err
    orig, agent._opener = agent._opener, Opener()
    try:
        assert agent._server_reply("https://n.example/api/health") == (302, DATE)
    finally:
        agent._opener = orig


def test_main_doctor_runs_no_lockdown_and_writes_no_log(capsys, monkeypatch, tmp_path):
    seen = []
    monkeypatch.setattr(agent, "secure_windows_dir", lambda *a, **k: pytest.fail("doctor must not lock anything down"))
    monkeypatch.setattr(agent, "LOG_PATH", str(tmp_path / "agent.log"))
    monkeypatch.setattr(agent, "doctor", lambda insecure: seen.append(insecure) or 1)
    assert agent.main(["--insecure-http", "doctor"]) == 1  # its exit code reaches the shell
    assert seen == [True] and not (tmp_path / "agent.log").exists()


@pytest.mark.skipif(sys.platform != "win32", reason="real PowerShell")
def test_the_read_scripts_parse_and_answer_in_sids_on_real_powershell(tmp_path):
    rc, out = agent.ps(agent.sh, agent.PS_DOCTOR_ACL.replace("%DIR%", agent._ps_quote(str(tmp_path))))
    lines = [x.strip() for x in out.splitlines() if x.strip()]
    assert rc == 0 and lines[0].startswith("S-1-") and lines[1] in ("True", "False") and all(x.startswith("S-1-") for x in lines[2:]), out
    rc, out = agent.ps(agent.sh, agent.PS_DOCTOR_WU)
    assert rc == 0 and "|" in out, out
    rc, out = agent.ps(agent.sh, agent.PS_DOCTOR_TASKS)
    assert rc == 0, out


# --- the log --------------------------------------------------------------------------------------------------------


@pytest.fixture
def enrolled(tmp_path, monkeypatch):
    log = tmp_path / "state" / "agent.log"
    cfg = tmp_path / "agent.json"
    cfg.write_text(json.dumps({"server": "https://n.example", "agent_key": KEY}))
    monkeypatch.setattr(agent, "config_path", lambda: str(cfg))
    monkeypatch.setattr(agent, "LOG_PATH", str(log))
    monkeypatch.setattr(agent, "collect", lambda: {"os_name": "x", "ecosystem": "y", "packages": [{"name": "a"}]})
    monkeypatch.setattr(agent, "neighbours", lambda: [])
    return log


def test_a_report_logs_start_and_end_and_never_the_key_or_token(enrolled, monkeypatch):
    monkeypatch.setenv("NIMSTEAD_TOKEN", TOKEN)
    monkeypatch.setattr(agent, "post", lambda *a, **k: {})
    assert agent.main(["--no-self-update", "report"]) == 0
    text = enrolled.read_text()
    assert "run start: report" in text and "reported 1 packages" in text and "run end: exit 0" in text
    assert KEY not in text and TOKEN not in text


def test_secrets_a_server_error_echoes_never_reach_the_log(enrolled, monkeypatch, capsys):
    monkeypatch.setenv("NIMSTEAD_TOKEN", "plain-enrol-value")

    def post(*a, **k):
        raise agent.AgentError(f"server returned 401: bad key {KEY} and nme_abc-DEF_1 and plain-enrol-value and nmt_other")
    monkeypatch.setattr(agent, "post", post)
    assert agent.main(["--no-self-update", "report"]) == 1
    text = enrolled.read_text()
    assert "error: server returned 401" in text and "run end: exit 1" in text
    for secret in (KEY, "nme_abc", "plain-enrol-value", "nmt_other"):
        assert secret not in text


def test_an_unprefixed_key_is_left_out_too(enrolled, monkeypatch, tmp_path):
    (tmp_path / "agent.json").write_text(json.dumps({"server": "https://n.example", "agent_key": "oldstylekey123"}))

    def post(*a, **k):
        raise agent.AgentError("echo oldstylekey123")
    monkeypatch.setattr(agent, "post", post)
    agent.main(["--no-self-update", "report"])
    assert "oldstylekey123" not in enrolled.read_text()


def test_job_outcomes_and_errors_are_logged(enrolled, monkeypatch, tmp_path):
    monkeypatch.setattr(agent, "_log_on", True)
    monkeypatch.setattr(agent, "post", lambda server, path, *a, **k: [{"id": "j1", "manager": "nonsense"}] if path == "/api/agent/jobs" else {})
    monkeypatch.setattr(agent, "Job", lambda *a, **k: (_ for _ in ()).throw(ValueError("bad job")))
    agent.run_jobs("https://n.example", KEY, False, run=lambda *a, **k: (0, ""), outcome_dir=str(tmp_path / "out"), win_state=str(tmp_path / "w.json"))
    assert "job j1: aborted (No changes made: malformed job: bad job)" in enrolled.read_text()


def test_a_crash_is_logged_and_still_raised(enrolled, monkeypatch):
    def post(*a, **k):
        raise RuntimeError("unexpected")
    monkeypatch.setattr(agent, "post", post)
    with pytest.raises(RuntimeError):
        agent.main(["--no-self-update", "report"])
    assert "run crashed" in enrolled.read_text()
    assert agent._log_on is False


def test_logging_failure_never_stops_a_run(enrolled, monkeypatch, capsys):
    def no_disk(*a, **k):
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(agent.os, "open", no_disk)
    monkeypatch.setattr(agent, "post", lambda *a, **k: {})
    assert agent.main(["--no-self-update", "report"]) == 0
    out = capsys.readouterr()
    assert out.out == "reported 1 packages\n" and out.err == ""


def test_log_folder_that_cannot_be_made_does_not_stop_a_run(enrolled, monkeypatch, tmp_path):
    (tmp_path / "file").write_text("")
    monkeypatch.setattr(agent, "LOG_PATH", str(tmp_path / "file" / "agent.log"))  # e.g. `report` as a non-root user
    monkeypatch.setattr(agent, "post", lambda *a, **k: {})
    assert agent.main(["--no-self-update", "report"]) == 0


def test_log_is_bounded_to_two_files_and_one_line_per_event(enrolled, monkeypatch):
    monkeypatch.setattr(agent, "_log_on", True)
    monkeypatch.setattr(agent, "LOG_MAX_BYTES", 1000)
    agent.log_event("forged\n2026-01-01T00:00:00Z run end: exit 0")
    assert len(enrolled.read_text().splitlines()) == 1
    for i in range(500):
        agent.log_event(f"event {i} " + "x" * 50)
    assert sorted(p.name for p in enrolled.parent.iterdir()) == ["agent.log", "agent.log.1"]
    assert enrolled.stat().st_size < 1100 and (enrolled.parent / "agent.log.1").stat().st_size < 1100
    agent.log_event("y" * 100_000)
    assert enrolled.stat().st_size < 1000 + 2100


@pytest.mark.skipif(os.name == "nt", reason="POSIX modes")
def test_log_is_private_on_linux(enrolled, monkeypatch):
    monkeypatch.setattr(agent, "_log_on", True)
    agent.log_event("x")
    assert enrolled.stat().st_mode & 0o077 == 0


def test_collect_output_stays_clean_json_and_writes_no_log(enrolled, capsys):
    assert agent.main(["collect"]) == 0
    out = capsys.readouterr()
    assert json.loads(out.out)["packages"] == [{"name": "a"}] and out.err == ""
    assert not enrolled.exists()


def test_nothing_is_logged_when_the_lockdown_failed(enrolled, monkeypatch):
    def refused(*a, **k):
        raise agent.AgentError("could not lock down")
    monkeypatch.setattr(agent, "secure_windows_dir", refused)
    monkeypatch.setattr(agent.os, "name", "nt")
    try:
        assert agent.main(["--no-self-update", "report"]) == 1
    finally:
        monkeypatch.undo()
    assert not enrolled.exists()


@pytest.mark.real_lockdown
def test_lockdown_keeps_the_agents_log_and_removes_a_planted_one(tmp_path):
    d = tmp_path / "Nimstead"
    d.mkdir()
    (d / "agent.log").write_text("ours")
    (d / "agent.log.1").write_text("planted")

    def run(cmd, cwd=None):
        if cmd[0] == "powershell":
            return 0, f"{d / 'agent.log'}|S-1-5-18|0\n{d / 'agent.log.1'}|S-1-5-21-1-2-3-1001|0\n"
        return 0, ""
    assert agent.secure_windows_dir(run, str(d)) == [str(d / "agent.log.1")]
    assert (d / "agent.log").exists() and not (d / "agent.log.1").exists()


def test_uninstall_removes_the_log_because_it_lives_in_a_state_folder(tmp_path, monkeypatch):
    assert os.path.basename(REAL_LOG_PATH) == "agent.log"
    if os.name == "nt":
        assert os.path.dirname(REAL_LOG_PATH) == os.path.dirname(agent.WIN_STATE)
    else:
        assert os.path.dirname(REAL_LOG_PATH) == "/var/lib/nimstead"
    state = tmp_path / "state"
    state.mkdir()
    (state / "agent.log").write_text("x")
    (state / "agent.log.1").write_text("x")
    monkeypatch.setattr(agent, "WIN_STATE", str(tmp_path / "no-pending.json"))
    agent.uninstall(run=lambda *a, **k: (0, ""), unit_dir=str(tmp_path), state_dirs=[str(state)], agent_path=str(tmp_path / "none.py"))
    assert not state.exists()


def test_uninstall_does_not_recreate_the_log(tmp_path, monkeypatch):
    log = tmp_path / "state" / "agent.log"
    monkeypatch.setattr(agent, "LOG_PATH", str(log))
    monkeypatch.setattr(agent, "uninstall", lambda: [])
    assert agent.main(["uninstall", "--yes"]) == 0
    assert not log.exists()
