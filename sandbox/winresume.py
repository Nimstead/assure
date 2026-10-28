"""Finish a Windows job left mid-flight (e.g. the harness was interrupted): resume-job until it is final.

Run from api/:  uv run python ../sandbox/winresume.py VM_NAME
Each resume runs as SYSTEM; a pending_reboot result reboots the VM and resumes again. Logs to
sandbox/last_run_windows_resume.json (last_run_windows11_resume.json on a Windows client).
"""

import json
import sys
from pathlib import Path

import wine2e as h  # noqa: E402  (reads VM_NAME from argv)

ROOT = Path(__file__).resolve().parents[1]
OUT = "last_run_windows_resume.json"


def main() -> int:
    h.winvm.wait_ready(h.NAME, minutes=60)
    global OUT
    if "Client" in h.guest(r"(gp 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').InstallationType"):
        OUT = "last_run_windows11_resume.json"
    agent = r'"C:\Program Files\Python313\python.exe" "C:\Program Files\Nimstead\nimstead_agent.py"'
    h.note("resume start", build=h.build(), pending=h.guest(r"Test-Path C:\ProgramData\Nimstead\pending-job.json").strip())
    for i in range(1, 5):
        out = rf"C:\nimtest\resume{i}.json"
        h.as_system(rf"{agent} resume-job > {out} 2>&1", wait_minutes=90, result=out)
        r = json.loads(h.guest(f"Get-Content {out} -Raw").strip().splitlines()[-1])
        h.note(f"resume {i}", outcome=r["outcome"], error=r.get("error"), steps=[s["step"] for s in r["steps"]][-6:])
        if r["outcome"] != "pending_reboot":
            h.note("final", outcome=r["outcome"], build=h.build())
            return 0 if r["outcome"] == "rolled_back" else 1
        h.reboot_and_wait()
        h.note("rebooted", build=h.build())
    return 1


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).parent))
    try:
        rc = main()
    finally:
        (ROOT / "sandbox" / OUT).write_text(json.dumps(h.log, indent=2, default=str))
    sys.exit(rc)
