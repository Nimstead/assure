"""The VM harness must not hard-reset a Windows that has booted (lost writes zeroed VBoxService.exe on a real VM)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sandbox"))
from winvm import additions_since_reset  # noqa: E402

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
    monkeypatch.setattr(winvm, "disk_activity", lambda n: str(clock[0]) if clock[0] < 40 * 60 else "idle")
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
    assert calls and calls[0][0][2] == "reset" and calls[0][1] > 12 * 60
