"""The VM harness must not hard-reset a Windows that has booted (lost writes zeroed VBoxService.exe on a real VM)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sandbox"))
import winvm  # noqa: E402
from winvm import additions_since_reset, locale_args, os_type  # noqa: E402

REPORT = "00:14:09 VMMDev: Guest Additions information report: Version 7.2.22"
RESET = "00:24:24 Changing the VM state from 'RUNNING' to 'RESETTING'"


def test_booted_only_if_the_additions_reported_after_the_last_reset():
    assert not additions_since_reset(["boot"])
    assert additions_since_reset([REPORT])
    assert not additions_since_reset([REPORT, RESET])
    assert additions_since_reset([REPORT, RESET, REPORT])


def test_wait_ready_restarts_a_booted_windows_cleanly_and_never_hard_resets(monkeypatch):
    import winvm
    calls, clock = [], [0.0]
    monkeypatch.setattr(winvm.time, "time", lambda: clock[0])
    monkeypatch.setattr(winvm.time, "sleep", lambda s: clock.__setitem__(0, clock[0] + s))
    monkeypatch.setattr(winvm, "run", lambda *a, **k: (1, "not ready") if not calls else (0, "ready"))
    monkeypatch.setattr(winvm, "unstick", lambda n: False)
    monkeypatch.setattr(winvm, "os_up", lambda n: True)
    monkeypatch.setattr(winvm, "clean_restart", lambda n: calls.append("restart"))
    monkeypatch.setattr(winvm, "vbox", lambda *a, **k: calls.append("reset"))
    monkeypatch.setattr(winvm, "disk_activity", lambda n: "idle")
    winvm.wait_ready("nimstead-sbx-win-x")
    assert calls == ["restart"] and clock[0] > 20 * 60
    # still applying an update at "Restarting": a busy disk holds the restart back (real Server 2025)
    calls.clear()
    clock[0] = 0.0
    monkeypatch.setattr(winvm, "disk_activity", lambda n: f'c="{int(clock[0]) << 20}"' if clock[0] < 40 * 60 else "idle")
    winvm.wait_ready("nimstead-sbx-win-x")
    assert calls == ["restart"] and clock[0] > 60 * 60


def _clock(monkeypatch, winvm):
    clock = [0.0]
    monkeypatch.setattr(winvm.time, "time", lambda: clock[0])
    monkeypatch.setattr(winvm.time, "sleep", lambda s: clock.__setitem__(0, clock[0] + s))
    monkeypatch.setattr(winvm, "run", lambda *a, **k: (1, ""))
    monkeypatch.setattr(winvm, "unstick", lambda n: False)
    monkeypatch.setattr(winvm, "os_up", lambda n: False)
    return clock


def test_wait_ready_never_resets_a_setup_whose_disk_is_busy(monkeypatch):
    import pytest
    import winvm
    clock, calls = _clock(monkeypatch, winvm), []
    monkeypatch.setattr(winvm, "disk_activity", lambda n: str(clock[0]))
    monkeypatch.setattr(winvm, "vbox", lambda *a, **k: calls.append(a))
    with pytest.raises(RuntimeError):
        winvm.wait_ready("nimstead-sbx-win-x", minutes=60)
    assert calls == []


def test_wait_ready_resets_a_setup_whose_disk_went_idle(monkeypatch):
    import pytest
    import winvm
    clock, calls = _clock(monkeypatch, winvm), []
    monkeypatch.setattr(winvm, "disk_activity", lambda n: "same")
    monkeypatch.setattr(winvm, "vbox", lambda *a, **k: calls.append((a, clock[0])))
    with pytest.raises(RuntimeError):
        winvm.wait_ready("nimstead-sbx-win-x", minutes=30)
    assert calls and calls[0][0][2] == "poweroff" and calls[1][0][0] == "startvm" and calls[0][1] > 12 * 60  # cold: a warm reset hangs the firmware


def test_a_healthy_vm_that_logs_no_guest_os_line_is_not_power_cycled(tmp_path, monkeypatch):
    log = tmp_path / "n" / "n" / "Logs" / "VBox.log"
    log.parent.mkdir(parents=True)
    log.write_text("\n".join(["00:00:01.000000 " + RESET[9:], "00:10:00.000000 " + REPORT[9:]]))
    monkeypatch.setattr(winvm, "STATE", tmp_path)
    monkeypatch.setattr(winvm, "vbox", lambda *a, **k: (_ for _ in ()).throw(AssertionError("power-cycled a healthy VM")))
    assert winvm.unstick("n") is False


def test_only_real_disk_work_counts_as_busy():
    one = 'Counter c="1000" x\nCounter c="%d" y'
    assert winvm.disk_busy(None, one % 0)
    assert not winvm.disk_busy(one % 0, one % (1 << 20))  # idle chatter
    assert winvm.disk_busy(one % 0, one % (64 << 20))  # applying an update


def test_a_localised_iso_installs_in_its_own_language():
    assert locale_args("OS Languages = en-US") == ["--locale=en_US", "--country=GB"]
    assert locale_args("  OS Languages = de-DE") == ["--locale=de_DE", "--country=DE", "--language=de-DE"]
    assert locale_args("no language line") == ["--locale=en_US", "--country=GB"]


def test_the_vm_takes_the_os_type_the_iso_reports():
    assert os_type("    OS TypeId    = Windows2022_64\n    OS Version = 10.0.20348.587") == "Windows2022_64"
    assert os_type("nothing detected") == "Windows2025_64"
