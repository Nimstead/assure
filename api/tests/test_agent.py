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
    out = ("libssl3\t3.0.11-1~deb12u2\topenssl\t3.0.11-1~deb12u2\tii \n"
           "bash\t5.2.15-2+b2\t\t5.2.15-2\tii \n"  # a binNMU: the source's version, without +b2
           "bsdutils\t1:2.41-5\tutil-linux\t2.41-5\tii \n"  # Debian 13, real: the binary's epoch isn't the source's
           "oldpkg\t1.0\t\t1.0\trc \n"
           "wanted\t2.0\t\t2.0\tin \n")
    assert agent.parse_dpkg(out) == [
        {"name": "libssl3", "version": "3.0.11-1~deb12u2", "source": "openssl"},
        {"name": "bash", "version": "5.2.15-2+b2", "source": "bash", "source_version": "5.2.15-2"},
        {"name": "bsdutils", "version": "1:2.41-5", "source": "util-linux", "source_version": "2.41-5"}]


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


def _linux(tmp_path, os_release, answer, tool="dpkg-query"):
    f = tmp_path / "os-release"
    f.write_text(os_release)
    ran = []

    def query(cmd, timeout=600):
        ran.append(cmd)
        return answer
    which = lambda name: f"/usr/bin/{name}" if name == tool else None  # noqa: E731
    return agent.collect_linux(query, files=(str(tmp_path / "missing"), str(f)), apk_db=str(tmp_path / "no-apk"), which=which, kernel="6.12.48+deb13-amd64"), ran


def test_linux_collect_reports_what_it_read_with_the_command_status(tmp_path):
    from nimstead.engine.collection import valid_document
    inv, ran = _linux(tmp_path, 'ID=debian\nVERSION_ID="13"\nPRETTY_NAME="Debian GNU/Linux 13 (trixie)"\n', (0, "libssl3t64\t3.5.1-1\topenssl\t3.5.1-1\tii \nbash\t5.2-1\t\t5.2-1\tii \n", ""))
    assert ran == [agent.DPKG_QUERY]  # read-only, fixed argv
    assert inv["ecosystem"] == "Debian:13" and inv["collection"]["sources"] == {"os_release": {"state": "ok", "count": 1}, "package_db": {"state": "ok", "count": 2, "exit": 0}}
    assert inv["facts"] == {"os_id": "debian", "os_version_id": "13", "kernel_release": "6.12.48+deb13-amd64", "pending_reboot": None}
    assert valid_document(inv["collection"]) and inv["packages"][0] == {"name": "libssl3t64", "version": "3.5.1-1", "source": "openssl", "ecosystem": "Debian:13"}


def test_linux_collect_tells_a_failed_read_a_cut_short_one_and_an_empty_one_apart(tmp_path):
    rel = 'ID="almalinux"\nVERSION_ID="9.6"\n'
    failed, _ = _linux(tmp_path, rel, (1, "", "error: rpmdb open failed\n"), tool="rpm")
    assert failed["collection"]["sources"]["package_db"] == {"state": "failed", "count": 0, "error": "rpm exited 1: error: rpmdb open failed", "exit": 1}
    cut, _ = _linux(tmp_path, rel, (0, "openssl\t1:3.0.7-27.el9\topenssl-3.0.7-27.el9.src.rpm\nbash\t0:5.1", ""), tool="rpm")  # T3: a line cut off
    assert cut["collection"]["sources"]["package_db"] == {"state": "partial", "count": 1, "error": "1 lines couldn't be read", "exit": 0}
    killed, _ = _linux(tmp_path, rel, (-9, "openssl\t1:3.0.7-27.el9\topenssl-3.0.7-27.el9.src.rpm\n", ""), tool="rpm")
    assert killed["collection"]["sources"]["package_db"]["state"] == "partial" and killed["collection"]["sources"]["package_db"]["exit"] == -9
    empty, _ = _linux(tmp_path, rel, (0, "", ""), tool="rpm")  # sent as read; the server calls it a failure (R4.3)
    assert empty["collection"]["sources"]["package_db"] == {"state": "ok", "count": 0, "exit": 0} and empty["packages"] == []
    none, _ = _linux(tmp_path, rel, (None, "", "boom"), tool="nothing")
    assert none["collection"]["sources"]["package_db"]["state"] == "failed" and "no package database" in none["collection"]["sources"]["package_db"]["error"]


def test_linux_collect_reports_an_unknown_platform_instead_of_failing(tmp_path):
    inv, _ = _linux(tmp_path, "ID=linuxmint\nVERSION_ID=22\n", (0, "bash\t5.2-1\t\t5.2-1\tii \n", ""))
    assert inv["ecosystem"] == "" and "ID=linuxmint VERSION_ID=22" in inv["facts"]["os_unmatched"] and inv["packages"]
    gone = agent.collect_linux(lambda cmd, timeout=600: (0, "bash\t5.2-1\t\t5.2-1\tii \n", ""), files=(str(tmp_path / "x"),), apk_db=str(tmp_path / "y"),
                               which=lambda n: "/usr/bin/dpkg-query" if n == "dpkg-query" else None, kernel="6.1")
    assert gone["collection"]["sources"]["os_release"] == {"state": "failed", "count": 0, "error": "no os-release file"}


def test_pending_reboot_only_where_the_distro_says_so():
    yes = lambda path: True  # noqa: E731
    assert agent.reboot_pending(exists=yes) is True
    assert agent.reboot_pending(exists=lambda p: p == agent.NOTIFY_REBOOT) is False
    asked = lambda rc: (lambda cmd, timeout=0: (rc, "", ""))  # noqa: E731
    which = lambda n: "/usr/bin/needs-restarting" if n == "needs-restarting" else None  # noqa: E731
    assert [agent.reboot_pending(asked(rc), which, lambda p: False) for rc in (1, 0, 2)] == [True, False, None]
    assert agent.reboot_pending(asked(1), lambda n: None, lambda p: False) is None


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


UN = "hkey_local_machine\\software\\microsoft\\windows\\currentversion\\uninstall"
REMOTE_DUMP = {"host": "SRV1", "machine": "AMD64", "dirs": {r"c:\program files\dotnet\sdk": ["8.0.425"]}, "keys": {
    "hkey_local_machine\\software\\microsoft\\windows nt\\currentversion": {"values": {
        "CurrentBuild": "26100", "UBR": 100, "DisplayVersion": "24H2", "ProductName": "Windows Server 2025", "InstallationType": "Server", "EditionID": "ServerStandard"}, "subkeys": []},
    UN: {"values": {}, "subkeys": ["7-Zip"]},
    UN + "\\7-zip": {"values": {"DisplayName": "7-Zip 23.01 (x64)", "DisplayVersion": "23.01", "Publisher": "Igor Pavlov"}, "subkeys": []},
    "hkey_local_machine\\software\\microsoft\\net framework setup\\ndp\\v4\\full": {"values": {"Release": 533509}, "subkeys": []}}}


def fake_remote(calls, dump=REMOTE_DUMP):
    def run(cmd, **kw):
        calls.append(cmd[-1])
        path = cmd[-1].split("-FilePath '")[1].split("'")[0]
        script = open(path, encoding="utf-8-sig").read()
        if "ValidCommunities" in script or "$c.secure_boot" in script:
            return 0, json.dumps({"config": {"uac_lua": 1}})
        if "GetValueNames" in script:
            return 0, json.dumps(dump)
        if "netfx" in script:
            return 0, json.dumps({"netfx": "4.8.9363.0 built by: x", "store": []})
        return 0, "0"
    return run


def test_remote_scan_reads_another_host_with_the_agents_own_collectors():
    calls = []
    name, inv = agent.collect_remote("srv1.corp.example", fake_remote(calls))
    got = {(p["ecosystem"], p["name"], p["version"]) for p in inv["packages"]}
    assert name == "SRV1" and inv["ecosystem"] == "Windows"
    assert ("WinApp", "7-Zip 23.01 (x64)", "23.01") in got and ("Microsoft", ".NET SDK", "8.0.425") in got and ("Microsoft", ".NET Framework", "4.8.9363.0") in got
    assert any(n.startswith("Windows Server 2025") and e == "Windows" and v == "10.0.26100.100" for e, n, v in got)
    assert inv["facts"]["config"] == {"uac_lua": 1}
    assert all("Invoke-Command -ComputerName srv1.corp.example" in c for c in calls)


@pytest.mark.parametrize("bad", ["a b", "x;Remove-Item c:\\", "$(calc)", "-ComputerName", "a'b"])
def test_remote_scan_refuses_what_isnt_a_host_name(bad):
    with pytest.raises(agent.AgentError, match="not a host name"):
        agent.collect_remote(bad, lambda *a, **k: pytest.fail("ran something"))


def test_remote_scan_says_when_a_host_cant_be_reached():
    with pytest.raises(agent.AgentError, match="remoting"):
        agent.collect_remote("srv1", lambda cmd, **k: (1, "WinRM cannot complete the operation"))


def test_scan_remote_enrols_once_keeps_going_past_a_failure_and_sends_no_credentials(tmp_path):
    calls, sent = [], []

    def run(cmd, **kw):
        if "-ComputerName down " in cmd[-1]:
            return 1, "unreachable"
        return fake_remote(calls)(cmd, **kw)

    def post_fn(server, path, body, insecure, key=None):
        sent.append((path, body, key))
        return {"agent_key": "k1", "asset_id": "a1"} if path.endswith("enroll") else {}
    keys = str(tmp_path / "keys.json")
    failed = agent.scan_remote("https://n", ["down", "srv1"], "tok", keys_path=keys, run=run, post_fn=post_fn)
    assert list(failed) == ["down"] and [p for p, _, _ in sent] == ["/api/agent/enroll", "/api/agent/inventory"] and sent[1][2] == "k1"
    sent.clear()
    assert not agent.scan_remote("https://n", ["srv1"], None, keys_path=keys, run=run, post_fn=post_fn)
    assert [p for p, _, _ in sent] == ["/api/agent/inventory"]  # the second scan needs no token
    assert agent.scan_remote("https://other", ["srv1"], None, keys_path=keys, run=run, post_fn=post_fn)  # another server's key isn't reused
