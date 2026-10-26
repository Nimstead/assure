import importlib.util
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
            return 0, f"{d / 'pending-job.json'}|S-1-5-21-1-2-3-1001\n{d / 'agent.json'}|S-1-5-32-544\n"
        return 0, ""
    assert agent.secure_windows_dir(run, str(d)) == [str(d / "pending-job.json")]
    assert (d / "agent.json").exists() and not (d / "pending-job.json").exists()
    icacls = [c[2:] for c in calls if c[0] == "icacls"]
    assert icacls[0] == ["/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "/grant:r", "*S-1-5-32-544:(OI)(CI)F", "/Q"]
    assert ["/setowner", "*S-1-5-32-544", "/T", "/C", "/Q"] in icacls and ["/reset", "/T", "/C", "/Q"] in icacls


@pytest.mark.real_lockdown
def test_lockdown_failure_is_loud(tmp_path):
    with pytest.raises(agent.AgentError):
        agent.secure_windows_dir(lambda cmd, cwd=None: (5, "Access is denied."), str(tmp_path))
