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
    winvm.wait_ready("nimstead-sbx-win-x")
    assert calls == ["restart"] and clock[0] > 20 * 60
