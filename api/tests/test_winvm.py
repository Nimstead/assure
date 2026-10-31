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
