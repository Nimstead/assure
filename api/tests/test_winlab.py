"""The real-VM proofs (W7-W10, W16, W25, W26) run by hand on a host; these cover what can go wrong without a VM: their pure logic, the VM
options, and that every PowerShell script they send at least parses."""

import json
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sandbox"))
import wincluster  # noqa: E402
import windc  # noqa: E402
import winexposure  # noqa: E402
import winfailures  # noqa: E402
import winfootprint  # noqa: E402
import wingpo  # noqa: E402
import winlab  # noqa: E402
import winremote_lab  # noqa: E402
import winvm  # noqa: E402

from nimstead import remediate, winconfig  # noqa: E402


def creating(monkeypatch, tmp_path, **kw):
    calls = []
    monkeypatch.setattr(winvm, "STATE", tmp_path)
    monkeypatch.setattr(winvm, "vbox", lambda *a, **k: calls.append(a) or "OS Languages = en-US, Windows2025")
    name = winvm.create("x.iso", **kw)
    return name, calls, json.loads((tmp_path / name / "creds.json").read_text())


def test_create_keeps_its_defaults(monkeypatch, tmp_path):
    name, calls, c = creating(monkeypatch, tmp_path)
    modify = next(a for a in calls if a[0] == "modifyvm" and "--memory" in a)
    assert modify[modify.index("--memory") + 1] == "4096" and not any("--nic2" in a for a in calls)
    install = next(a for a in calls if a[:2] == ("unattended", "install"))
    assert "--image-index=1" in install and "--hostname=nimstead-sbx.local" in install and c["password"].startswith("Nim!")


def test_create_for_a_lab(monkeypatch, tmp_path):
    name, calls, c = creating(monkeypatch, tmp_path, memory=2560, lab=True, image=3, computer="NIMDC1", password="Nim!same")
    assert name.startswith(winvm.PREFIX) and c["password"] == "Nim!same"
    assert ("modifyvm", name, "--nic2", "intnet", "--intnet2", "nimstead-sbx-lab") in calls
    modify = next(a for a in calls if a[0] == "modifyvm" and "--memory" in a)
    assert modify[modify.index("--memory") + 1] == "2560"
    install = next(a for a in calls if a[:2] == ("unattended", "install"))
    assert "--image-index=3" in install and "--hostname=NIMDC1.local" in install


def test_lab_plan_gives_each_machine_a_name_and_address():
    plan = winlab.plan_lab(3)
    assert [p["role"] for p in plan] == ["dc", "member", "member"]
    assert len({p["ip"] for p in plan}) == 3 and len({p["computer"] for p in plan}) == 3 and all(len(p["computer"]) <= 15 for p in plan)
    with pytest.raises(ValueError):
        winlab.plan_lab(2)  # member to member needs two members


def test_host_gate_says_what_is_short():
    assert winlab.parse_host_mem("16358400 8179200\r\n") == (15975, 7987)
    assert winlab.host_short(3, 2560, 3 * 2560 + winlab.HOST_RESERVE_MB, 90) is None
    assert "free memory" in winlab.host_short(3, 2560, 3 * 2560 + winlab.HOST_RESERVE_MB - 1, 90)
    assert "disk" in winlab.host_short(3, 2560, 99999, 89)


def test_peak_tracks_each_phase_and_stops_a_host_that_runs_out(monkeypatch):
    p, free = winlab.Peak(), [4000]
    monkeypatch.setattr(winlab, "host_memory", lambda: (16000, free[0]))
    p.phase = "2 VMs running"
    p.check()
    free[0] = 3000
    p.sample()
    assert p.seen["2 VMs running"] == {"total_mb": 16000, "peak_used_mb": 13000, "min_free_mb": 3000}
    p.phase, free[0] = "3 VMs running", winlab.HOST_MIN_FREE_MB - 1
    with pytest.raises(winlab.HostShort, match="free host memory fell"):
        p.check()


def test_second_nic_mac_and_kerberos_proof():
    assert winlab.nic2_mac('nic1="nat"\nmacaddress1="080027000001"\nmacaddress2="080027000002"\n') == "080027000002"
    good = "NIMM2|nimstead-sbx\\administrator\nCurrent LogonId...\n#2> Client: Administrator @ NIMSTEAD-SBX.TEST\n   Server: HTTP/NIMM2.nimstead-sbx.test @ NIMSTEAD-SBX.TEST\n"
    assert winlab.kerberos_proved(good, "NIMM2")
    assert not winlab.kerberos_proved(good, "NIMM3")
    assert not winlab.kerberos_proved("NIMM2|nimstead-sbx\\administrator\nno tickets", "NIMM2")  # could have been NTLM
    assert not winlab.kerberos_proved("NIMM2|nimm2\\administrator\nHTTP/NIMM2.nimstead-sbx.test", "NIMM2")  # a local account


def test_secrets_never_reach_a_run_file(monkeypatch, tmp_path):
    monkeypatch.setattr(winlab, "ROOT", tmp_path)
    (tmp_path / "sandbox").mkdir()
    monkeypatch.setattr(winlab.h, "log", [])
    monkeypatch.setattr(winlab, "SECRETS", {"Nim!hunter2"})
    winlab.h.note("step", output="password is Nim!hunter2")
    assert winlab.harness(lambda: (_ for _ in ()).throw(RuntimeError("failed: Nim!hunter2")), "r.json") == 1
    text = (tmp_path / "sandbox" / "r.json").read_text()
    assert "hunter2" not in text and "RESULT: FAIL" in text


def test_a_host_that_cannot_hold_the_lab_says_so(monkeypatch, tmp_path):
    monkeypatch.setattr(winlab, "ROOT", tmp_path)
    (tmp_path / "sandbox").mkdir()
    monkeypatch.setattr(winlab, "LAB_FILE", tmp_path / "lab.json")
    monkeypatch.setattr(winlab.h, "log", [])
    monkeypatch.setattr(winlab, "host_memory", lambda: (8000, 4000))
    created = []
    monkeypatch.setattr(winlab.winvm, "create", lambda *a, **k: created.append(a))
    assert winlab.harness(lambda: winlab.build("x.iso"), "r.json") == 3
    assert created == [] and "HOST CANNOT HOLD" in (tmp_path / "sandbox" / "r.json").read_text()


def test_overlap_finds_two_jobs_in_flight_together():
    assert winlab.overlap([{"t": 1, "a": "dispatched", "b": "approved"}, {"t": 2, "a": "verifying", "b": "approved"}, {"t": 3, "a": "succeeded", "b": "dispatched"}]) == []
    both = {"t": 4, "a": "verifying", "b": "dispatched"}
    assert winlab.overlap([both]) == [both]


def test_dc_health_and_directory_checks():
    assert windc.dc_healthy({"services": ["Running"] * 4, "repl_failures": 0})
    assert not windc.dc_healthy({"services": ["Running"] * 3 + ["Stopped"], "repl_failures": 0})
    assert not windc.dc_healthy({"services": ["Running"] * 4, "repl_failures": 1})
    assert not windc.dc_healthy({})
    real, managed = {"nimdc1", "nimm1", "nimm2"}, {"nimdc1", "nimm2"}
    good = windc.directory_checks(real | {"nim-stale"}, {"nimm1"}, real, managed)
    assert all(good.values())
    assert not windc.directory_checks(real | {"nim-stale", "nim-disabled"}, {"nimm1"}, real, managed)["disabled object left out by the agent"]
    assert not windc.directory_checks(real | {"nim-stale"}, {"nimm1", "nim-stale"}, real, managed)["stale object left out of the list"]
    assert not windc.directory_checks(real | {"nim-stale"}, {"nimm1", "nimdc1"}, real, managed)["hosts with an agent aren't listed"]
    assert not windc.directory_checks({"nimdc1", "nim-stale"}, {"nimm1"}, real, managed)["the real computers were read"]


def test_closed_window_is_closed_and_always_is_open_by_the_servers_own_rule():
    for day in range(1, 8):
        for hour in (0, 23):
            when = datetime(2026, 11, day, hour, 30, tzinfo=UTC)
            closed = wincluster.closed_window(when)
            assert remediate.valid_window(closed) and remediate.valid_window(wincluster.ALWAYS)
            assert remediate.window_state(closed, when.replace(tzinfo=None))[0] is False
            assert remediate.window_state(wincluster.ALWAYS, when.replace(tzinfo=None))[0] is True


def test_probe_outage():
    rows = wincluster.parse_probe("100,NIMM1\r\nbad line\n105,DOWN\n110,DOWN\n150,NIMM2\n155,NIMM2\n")
    assert rows[0] == (100, "NIMM1") and len(rows) == 5
    assert wincluster.longest_outage(rows) == 50
    assert wincluster.longest_outage(rows + [(200, "DOWN"), (900, "DOWN")]) == 745  # never came back: counts in full
    assert wincluster.longest_outage([]) == 0 and wincluster.longest_outage([(1, "NIMM1"), (6, "NIMM1")]) == 5


def test_remote_scan_compares_with_the_agent():
    pkg = {"ecosystem": "WinApp", "name": "x", "version": "1", "source": ""}
    a = {"packages": [pkg], "facts": {"config": {"uac_lua": 1}}}
    d = winremote_lab.compare_reports(a, a)
    assert (d["only_agent"], d["only_remote"], d["settings_differ"], d["packages"], d["settings"]) == ([], [], {}, 1, 1)
    d = winremote_lab.compare_reports(a, {"packages": [], "facts": {"config": {"uac_lua": 0}}})
    assert d["only_agent"] == [("WinApp", "x", "1")] and d["settings_differ"] == {"uac_lua": (1, 0)}
    assert winremote_lab.last_json('{"a": 1}\n') == {"a": 1}


def test_gpo_script_runs_once_per_machine():
    s = wingpo.startup_script("http://10.0.2.2:8766", "tok")
    assert s.index("Get-ScheduledTask") < s.index("irm ") and "exit 0" in s and "$env:NIMSTEAD_TOKEN = 'tok'" in s
    assert wingpo.nobody_signed_in("No User exists for *\r\n") and not wingpo.nobody_signed_in(" USERNAME  SESSIONNAME\n administrator  console\n")


def test_footprint_limits():
    assert winfootprint.over_limits({"a": 5}, {"a": 5}) == {}
    assert winfootprint.over_limits({"a": 6}, {"a": 5}) == {"a": 6}
    assert winfootprint.over_limits({}, {"a": 5}) == {"a": None}  # not measured isn't within limits


def test_relay_counts_what_the_client_sends():
    import socket
    import socketserver
    import threading

    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.sendall(self.request.recv(1024) * 2)

    backend = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo)
    threading.Thread(target=backend.serve_forever, daemon=True).start()
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    relay = winfootprint.Relay(port, backend.server_address[1])
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=10) as c:
            c.settimeout(10)
            c.sendall(b"12345")
            got = b""
            while len(got) < 10:
                chunk = c.recv(1024)
                if not chunk:
                    break
                got += chunk
        assert got == b"1234512345" and relay.sent == 5 and relay.received == 10
        relay.reset()
        assert relay.sent == relay.received == 0
    finally:
        relay.shutdown()
        backend.shutdown()


@pytest.mark.skipif(sys.platform != "win32", reason="job objects are Windows only")
def test_meter_counts_a_child_process(tmp_path):
    meter = tmp_path / "meter.py"
    meter.write_text(winfootprint.METER)
    p = subprocess.run([sys.executable, "-I", str(meter), "60", sys.executable, "-I", "-c", "x = bytearray(80 * 2**20); print(len(x))"],
                       capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)
    m = json.loads(p.stdout.strip().splitlines()[-1])
    assert m["rc"] == 0 and m["peak_memory_mb"] >= 80 and m["processes"] >= 2 and m["duration_seconds"] >= 0 and m["cpu_seconds"] >= 0


def test_doctor_lines_parse_the_agents_own_format():
    out = "ok    config: C:\\x\nFAIL  schedule: missing or disabled: Nimstead agent. Fix: Run it\nFAIL  Windows Update: the service wuauserv is disabled. Fix: Run\n2 of 9 checks failed\nlog: C:\\y\n"
    assert winfailures.doctor_lines(out) == {"config": "ok", "schedule": "FAIL", "Windows Update": "FAIL"}


def test_disk_fill_leaves_under_the_agents_limit():
    from test_agent_proxy import agent
    n = winfailures.fill_bytes(40 * 2**30)
    assert (40 * 2**30 - n) // 2**30 == winfailures.LEAVE_GB < agent.WIN_MIN_FREE_GB
    with pytest.raises(ValueError):
        winfailures.fill_bytes(3 * 2**30)


def test_refused_for_disk_means_the_last_step_and_the_only_failure():
    ok = {"step": "job validated", "ok": True, "output": ""}
    disk = {"step": "at least 10 GB free on the system drive", "ok": False, "output": "5 GB free"}
    assert winfailures.refused_for_disk({"outcome": "aborted", "steps": [ok, disk]})
    assert not winfailures.refused_for_disk({"outcome": "aborted", "steps": [{**ok, "ok": False}]})  # refused for something else
    assert not winfailures.refused_for_disk({"outcome": "aborted", "steps": [ok, disk, ok]})  # carried on after it
    assert not winfailures.refused_for_disk({"outcome": "applied", "steps": [ok]})


def test_a_failing_scenario_is_recorded_and_the_rest_still_run(monkeypatch):
    monkeypatch.setattr(winfailures.h, "log", [])
    saves = []

    def boom():
        raise RuntimeError("no")
    r = winfailures.run_all([("a", lambda: {"x": True}), ("b", boom), ("c", lambda: {"y": False})], lambda: saves.append(1))
    assert r["a"]["ok"] and not r["b"]["ok"] and "no" in r["b"]["error"] and not r["c"]["ok"] and len(saves) == 3


def test_exposure_harness_uses_a_curated_listener_and_reads_the_reason():
    assert "grafana" in winconfig.LISTENERS and winconfig.LISTENERS["grafana"] == (winexposure.KEY,)
    assert winexposure.listening_reason({"reasons": ["Fix available", "Listening on the network: grafana on TCP port 3000"]}).endswith("3000")
    assert winexposure.listening_reason({"reasons": ["Fix available"]}) is None and winexposure.listening_reason({}) is None


SCRIPTS = {f"{mod.__name__}.{name}": getattr(mod, name) for mod, names in (
    (winlab, ("LAB_NIC", "FOREST", "REPLICA", "DC_DNS", "JOIN", "KERBEROS", "INSTALL")), (windc, ("PLANT", "OPT_IN", "HEALTH")),
    (wincluster, ("NODE_NET", "UNIQUE_NAT", "FEATURES", "WITNESS", "WITNESS_GRANT", "NEW_CLUSTER", "QUORUM_AND_ROLE", "PROBE", "START_PROBE", "CLUSTER_STATE")),
    (winremote_lab, ("PLANT", "REMOTING_OFF", "REMOTING_ON", "LOW_USER")), (wingpo, ("BUILD_GPO",)),
    (winfailures, ("CHANGED",)), (winexposure, ("ALLOW", "EXPIRED_CERT", "LISTENING"))) for name in names}
SCRIPTS["remote_scan"] = winremote_lab.scan("& 'py' -I 'agent'", "HOST", "tok")
SCRIPTS["gpo_startup"] = wingpo.startup_script("http://x", "tok")


@pytest.mark.skipif(sys.platform != "win32", reason="needs Windows PowerShell's parser")
@pytest.mark.parametrize("name", sorted(SCRIPTS))
def test_each_script_parses_without_running(name):
    script = "$e = $null; [void][Management.Automation.Language.Parser]::ParseInput(($input | Out-String), [ref]$null, [ref]$e); $e | ForEach-Object Message"
    filled = re.sub(r"%[A-Z_]+%", "x", SCRIPTS[name])
    p = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], input=filled, capture_output=True, text=True, check=True, timeout=60)
    assert p.stdout.strip() == "", p.stdout


class StopAtKerberos(Exception):
    pass


def test_a_resumed_build_keeps_finished_machines_and_uses_a_created_one(monkeypatch, tmp_path):
    """A real build stopped at the first member's join after 3 hours: resuming keeps the DC and joins that VM, creating only the third."""
    monkeypatch.setattr(winlab.winvm, "STATE", tmp_path)
    monkeypatch.setattr(winlab, "LAB_FILE", tmp_path / "lab.json")
    monkeypatch.setattr(winlab.h, "log", [])
    plan = winlab.plan_lab(3)
    dc, m1 = {**plan[0], "vm": winvm.PREFIX + "dc", "done": True}, {**plan[1], "vm": winvm.PREFIX + "m1"}
    (tmp_path / "lab.json").write_text(json.dumps({"domain": winlab.DOMAIN, "vms": [dc, m1]}))
    (tmp_path / dc["vm"]).mkdir()
    (tmp_path / dc["vm"] / "creds.json").write_text('{"user": "Administrator", "password": "adm"}')
    (tmp_path / dc["vm"] / "lab-secrets.json").write_text('{"safe_mode": "sm"}')
    done, created = [], []
    monkeypatch.setattr(winlab, "host_memory", lambda: (32000, 12000))
    monkeypatch.setattr(winlab.Peak, "start", lambda self: None)
    monkeypatch.setattr(winlab.Peak, "check", lambda self: self.seen.setdefault(self.phase, {}))
    monkeypatch.setattr(winlab.time, "sleep", lambda s: None)
    monkeypatch.setattr(winlab, "on", lambda v: None)
    monkeypatch.setattr(winlab.winvm, "wait_ready", lambda *a, **k: None)
    monkeypatch.setattr(winlab.winvm, "create", lambda iso, **k: created.append(k["computer"]) or winvm.PREFIX + "m2")
    monkeypatch.setattr(winlab, "lab_net", lambda *a: None)
    monkeypatch.setattr(winlab, "promote_forest", lambda *a: done.append("promote"))
    monkeypatch.setattr(winlab, "join", lambda v, d, admin: done.append((v["computer"], admin)))
    def as_user(*a):
        raise StopAtKerberos  # the joins are what this test is about
    monkeypatch.setattr(winlab, "as_user", as_user)
    with pytest.raises(StopAtKerberos):
        winlab.build("x.iso", resume=True)
    assert created == [plan[2]["computer"]] and done == [(plan[1]["computer"], "adm"), (plan[2]["computer"], "adm")]
    assert all(v.get("done") for v in json.loads((tmp_path / "lab.json").read_text())["vms"])
