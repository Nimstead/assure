"""Local privilege-escalation attempts against the installed Windows agent, as a standard (non-admin) user.

Run from api/ on a VM where wine2e.py installed the agent (use --keep):  uv run python ../sandbox/winattack.py VM_NAME
1. On the locked-down folder: a standard user can't create a job-state or outcome file.
2. An install from before the lockdown (inherited ProgramData ACL, simulated by resetting it): the user plants a
   pending job whose service name would run a payload as SYSTEM. The next SYSTEM agent run must remove the file,
   say so, never run the payload, and leave the folder locked.
Logs to sandbox/last_run_windows_attack.json. Destroys the VM on PASS.
"""

import json
import secrets
import sys
from pathlib import Path

import wine2e as h  # noqa: E402  (reads VM_NAME from argv)

ROOT = Path(__file__).resolve().parents[1]
DIR = r"C:\ProgramData\Nimstead"
EVIL = {"job": {"id": "x"}, "phase": "verify", "steps": [], "kb": "5126646", "from": "10.0.26100.1", "to": None, "product": "Windows X",
        "units": ["x' -EA Stop).Status; Set-Content C:\\pwned.txt owned; (Get-Service -Name 'y"], "settle": 0}


def as_user(user, cmd):
    rc, out = h.winvm.run(h.NAME, "$ErrorActionPreference = 'Stop'; " + cmd, user=user, timeout=300)  # 'WROTE' only on success
    return rc, out


def main() -> int:
    h.winvm.wait_ready(h.NAME, minutes=30)
    pw = "Std!" + secrets.token_hex(4)  # <= 14 chars, or net user stops to ask about older clients
    h.guest(f"net user nimuser /delete 2>$null | Out-Null; net user nimuser '{pw}' /add | Out-Null")  # repeatable
    user = {"user": "nimuser", "password": pw}
    is_admin = "nimuser" in h.guest("net localgroup Administrators")
    h.note("standard user created", in_administrators=is_admin)
    assert not is_admin
    planted = json.dumps(EVIL).replace("'", "''")

    # 1) locked folder: creating files must be refused
    rc1, out1 = as_user(user, f"Set-Content -LiteralPath '{DIR}\\pending-job.json' -Value '{planted}'; 'WROTE'")
    rc2, out2 = as_user(user, f"New-Item -ItemType File -Path '{DIR}\\outcomes\\forged.json' -Force | Out-Null; 'WROTE'")
    acl = h.guest(f"icacls '{DIR}'")
    h.note("locked folder: standard user writes", job_state="WROTE" in out1, outcome="WROTE" in out2, acl=acl.strip().splitlines()[:4])
    assert "WROTE" not in out1 and "WROTE" not in out2, (out1[-400:], out2[-400:])

    # 2) an install from before the lockdown: inherited ACL lets users create files; the agent must clean it up
    h.guest(f"icacls '{DIR}' /reset /T /C /Q | Out-Null")
    rc3, out3 = as_user(user, f"Set-Content -LiteralPath '{DIR}\\pending-job.json' -Value '{planted}'; 'WROTE'")
    assert "WROTE" in out3, out3[-400:]
    owner = h.guest(f"(Get-Acl -LiteralPath '{DIR}\\pending-job.json').Owner").strip()
    h.note("old-style folder: user planted a pending job", owner=owner)
    agent = r'"C:\Program Files\Python313\python.exe" -I "C:\Program Files\Nimstead\nimstead_agent.py"'
    h.as_system(rf"{agent} report > C:\nimtest\attack.txt 2>&1", wait_minutes=10)
    out = h.guest(r"Get-Content C:\nimtest\attack.txt -Raw")
    left = h.guest(f"Test-Path -LiteralPath '{DIR}\\pending-job.json'").strip()
    pwned = h.guest(r"Test-Path C:\pwned.txt").strip()
    acl = h.guest(f"icacls '{DIR}'")
    rc4, out4 = as_user(user, f"Set-Content -LiteralPath '{DIR}\\pending-job.json' -Value 'x'; 'WROTE'")
    h.note("SYSTEM agent run", agent_output=out.strip()[-600:], planted_file_still_there=left, payload_ran=pwned,
           acl=acl.strip().splitlines()[:4], user_can_write_again="WROTE" in out4)
    assert "removed" in out and left == "False" and pwned == "False" and "WROTE" not in out4
    assert "BUILTIN\\Users" not in acl and "Users:" not in acl, acl
    h.note("RESULT: PASS")
    return 0


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).parent))
    try:
        rc = main()
    except Exception as e:
        h.note("RESULT: FAIL", error=f"{type(e).__name__}: {e}"[:3000])
        rc = 1
    finally:
        (ROOT / "sandbox" / "last_run_windows_attack.json").write_text(json.dumps(h.log, indent=2, default=str))
    if rc == 0:
        h.winvm.destroy(h.NAME)
        h.note("VM destroyed", name=h.NAME)
    sys.exit(rc)
