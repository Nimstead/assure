import importlib.util
import json
import os
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("nimstead_agent", Path(__file__).parents[2] / "agent" / "nimstead_agent.py")
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)


@pytest.mark.parametrize("text,eco", [
    ('ID=debian\nVERSION_ID="12"\n', "Debian:12"),
    ('ID=ubuntu\nVERSION_ID="22.04"\nVERSION="22.04.3 LTS"\n', "Ubuntu:22.04"),
    ("ID=alpine\nVERSION_ID=3.18.4\n", "Alpine:v3.18"),
    ('ID="rocky"\nVERSION_ID="9.3"\n', "Rocky Linux:9"),
    ('ID="almalinux"\nVERSION_ID="8.9"\n', "AlmaLinux:8"),
    ("ID=debian\n", ""),  # sid/testing: no VERSION_ID
    ("ID=arch\n", ""),
])
def test_ecosystem(text, eco):
    assert agent.ecosystem_from_os_release(text) == eco


def test_dpkg_installed_only_and_source_fallback():
    out = ("libssl3\t3.0.11-1~deb12u2\topenssl\tii \n"
           "bash\t5.2.15-2+b2\t\tii \n"
           "oldpkg\t1.0\t\trc \n"
           "wanted\t2.0\t\tin \n")
    assert agent.parse_dpkg(out) == [
        {"name": "libssl3", "version": "3.0.11-1~deb12u2", "source": "openssl"},
        {"name": "bash", "version": "5.2.15-2+b2", "source": "bash"}]


def test_rpm_source_name_and_gpg_pubkey():
    out = ("openssl-libs\t1:3.0.7-27.el9\topenssl-3.0.7-27.el9.src.rpm\n"
           "kernel-core\t0:5.14.0-362.el9\tkernel-5.14.0-362.el9.src.rpm\n"
           "gpg-pubkey\t0:abc-123\t(none)\n"
           "weird\t0:1-1\t(none)\n")
    assert agent.parse_rpm(out) == [
        {"name": "openssl-libs", "version": "1:3.0.7-27.el9", "source": "openssl"},
        {"name": "kernel-core", "version": "0:5.14.0-362.el9", "source": "kernel"},
        {"name": "weird", "version": "0:1-1", "source": "weird"}]


def test_apk_installed_db():
    db = "C:Q1abc=\nP:libssl3\nV:3.1.4-r5\nA:x86_64\no:openssl\n\nP:busybox\nV:1.36.1-r15\no:busybox\n\n"
    assert agent.parse_apk(db) == [
        {"name": "libssl3", "version": "3.1.4-r5", "source": "openssl"},
        {"name": "busybox", "version": "1.36.1-r15", "source": "busybox"}]


def test_refuses_plain_http():
    with pytest.raises(agent.AgentError):
        agent.post("http://x", "/p", {}, insecure_http=False)


@pytest.mark.real_lockdown
def test_lockdown_removes_files_users_planted_then_restricts_the_folder(tmp_path):
    d = tmp_path / "Nimstead"
    d.mkdir()
    (d / "pending-job.json").write_text("{}")  # planted by a normal user: would run as SYSTEM after the next boot
    (d / "agent.json").write_text("{}")
    calls = []

    def run(cmd, cwd=None):
        calls.append(cmd)
        if cmd[0] == "powershell":
            return 0, f"{d / 'pending-job.json'}|S-1-5-21-1-2-3-1001|0\n{d / 'agent.json'}|S-1-5-32-544|0\n"
        return 0, ""
    assert agent.secure_windows_dir(run, str(d)) == [str(d / "pending-job.json")]
    assert (d / "agent.json").exists() and not (d / "pending-job.json").exists()
    steps = [c[2:] if c[0] == "icacls" else "list" for c in calls]
    # the folder is taken before anything is listed: owner first, then every explicit ACE dropped (a user who created the
    # folder could have granted themselves access, and /grant:r alone keeps such an ACE), then SYSTEM + Administrators only
    assert steps[:4] == [["/setowner", "*S-1-5-32-544", "/Q"], ["/reset", "/Q"],
                         ["/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "/grant:r", "*S-1-5-32-544:(OI)(CI)F", "/Q"], "list"]
    assert steps[4:] == [["/setowner", "*S-1-5-32-544", "/T", "/C", "/Q"], ["/reset", "/T", "/C", "/Q"]]


@pytest.mark.real_lockdown
@pytest.mark.skipif(os.name != "nt", reason="directory junctions are Windows-only")
def test_lockdown_never_follows_junctions_out_of_the_folder(tmp_path):
    import _winapi
    victim = tmp_path / "Users" / "victim"
    victim.mkdir(parents=True)
    (victim / "Documents.txt").write_text("not ours")
    d = tmp_path / "Nimstead"
    d.mkdir()
    _winapi.CreateJunction(str(victim), str(d / "x"))  # planted by a standard user before install

    def run(cmd, cwd=None):  # as if PowerShell had listed through the junction anyway, with the victim as owner
        if cmd[0] == "powershell":
            return 0, f"{d / 'x'}||1\n{d / 'x' / 'Documents.txt'}|S-1-5-21-1-2-3-1002|0\n"
        return 0, ""
    removed = agent.secure_windows_dir(run, str(d))
    assert removed == [str(d / "x")] and not os.path.lexists(d / "x")  # the link is gone...
    assert (victim / "Documents.txt").read_text() == "not ours"  # ...and nothing it pointed at was touched


@pytest.mark.real_lockdown
@pytest.mark.skipif(os.name != "nt", reason="directory junctions are Windows-only")
def test_lockdown_replaces_a_folder_planted_as_a_junction(tmp_path):
    import _winapi
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "keep.txt").write_text("x")
    d = tmp_path / "Nimstead"
    _winapi.CreateJunction(str(elsewhere), str(d))
    calls = []
    agent.secure_windows_dir(lambda cmd, cwd=None: (calls.append(cmd), (0, ""))[1], str(d))
    assert not agent.is_link(str(d)) and os.path.isdir(d) and (elsewhere / "keep.txt").exists()
    assert all(c[1] == str(d) for c in calls if c[0] == "icacls" and "/T" not in c)


def test_windows_enroll_locks_the_folder_before_the_key_is_written(tmp_path, monkeypatch):
    cfg = tmp_path / "Nimstead" / "agent.json"
    seen = []
    monkeypatch.setattr(agent, "config_path", lambda: str(cfg))
    monkeypatch.setattr(agent, "secure_windows_dir", lambda d=None, **k: seen.append((d, cfg.exists())))
    monkeypatch.setattr(agent.os, "name", "nt")
    agent.save_config({"agent_key": "nma_x"})
    monkeypatch.undo()
    assert seen == [(str(cfg.parent), False)] and json.loads(cfg.read_text()) == {"agent_key": "nma_x"}


@pytest.mark.real_lockdown
def test_lockdown_failure_is_loud(tmp_path):
    with pytest.raises(agent.AgentError):
        agent.secure_windows_dir(lambda cmd, cwd=None: (5, "Access is denied."), str(tmp_path))
