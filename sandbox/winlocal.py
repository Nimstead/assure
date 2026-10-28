"""Security round 3: a standard user prepares the agent's folder BEFORE the agent is installed, in a DISPOSABLE Windows VM
(sandbox/winvm.py). Any user may create folders in ProgramData, so the user (nimuser):
1. creates C:\\ProgramData\\Nimstead and grants themselves full control on it (an explicit ACE: `icacls /grant:r` for
   SYSTEM and Administrators alone left it in place, and agent.json, holding the agent key, inherited it);
2. plants a junction in it pointing at another standard user's files (the old lockdown deleted through it as admin).
Then the real install.ps1 runs elevated. PASS: the agent enrolled and reported; nimuser can't read agent.json or write in
the folder; no ACE names nimuser and Administrators own the folder; the junction is gone and the other user's files are
untouched.

Run from api/:  uv run python ../sandbox/winlocal.py VM_NAME
Logs to sandbox/last_run_windows_local.json. Destroys the VM on PASS.
"""

import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import wine2e as h  # noqa: E402  (reads VM_NAME from argv)

ROOT = Path(__file__).resolve().parents[1]
DIR = r"C:\ProgramData\Nimstead"
VICTIM = r"C:\Users\Public\nimvictim"


def as_user(user, cmd):
    return h.winvm.run(h.NAME, "$ErrorActionPreference = 'Stop'; " + cmd, user=user, timeout=300)[1]  # marker printed only on success


def standard_user(name):
    pw = "Std!" + secrets.token_hex(4)  # <= 14 chars, or net user stops to ask about older clients
    h.guest(f"net user {name} /delete 2>$null | Out-Null; net user {name} '{pw}' /add | Out-Null")
    assert name not in h.guest("net localgroup Administrators")
    return {"user": name, "password": pw}


def main() -> int:
    env = {**os.environ, "NIMSTEAD_DB": f"sqlite:///{(h.TMP / 'n.db').as_posix()}", "NIMSTEAD_SECURE_COOKIES": "0",
           "NIMSTEAD_PUBLIC_URL": f"http://10.0.2.2:{h.PORT}", "NIMSTEAD_SIGNING_KEY_FILE": str(h.TMP / "sign.pem"),
           "NIMSTEAD_CHECKPOINT_DIR": str(h.TMP / "cp"), "NIMSTEAD_SECRET_KEY_FILE": str(h.TMP / "secret.key")}
    import httpx
    server = subprocess.Popen([sys.executable, "-m", "uvicorn", "--factory", "nimstead.app:create_app", "--host", "127.0.0.1",
                               "--port", str(h.PORT)], env=env, cwd=ROOT / "api", stdout=open(h.TMP / "api.log", "wb"), stderr=subprocess.STDOUT)
    api = httpx.Client(base_url=f"http://127.0.0.1:{h.PORT}", timeout=60)
    try:
        for _ in range(60):
            try:
                if api.get("/install.ps1").status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(1)
        api.post("/api/auth/signup", json={"email": "win@example.com", "password": "windows-local-password", "org_name": "WinLocal"})
        token = api.post("/api/enroll-tokens", json={"sandbox": True}).json()["token"]

        h.winvm.wait_ready(h.NAME, minutes=150)
        h.note("VM ready", build=h.build())
        attacker, victim = standard_user("nimuser"), standard_user("nimvictim")
        out = as_user(victim, f"New-Item -ItemType Directory -Force '{VICTIM}' | Out-Null; Set-Content '{VICTIM}\\keep.txt' 'not yours'; 'OK'")
        assert "OK" in out, out[-400:]
        out = as_user(attacker, f"""New-Item -ItemType Directory '{DIR}' | Out-Null
            icacls '{DIR}' /grant 'nimuser:(OI)(CI)F' | Out-Null
            cmd /c mklink /J {DIR}\\x {VICTIM} | Out-Null
            'PLANTED'""")
        planted_acl = h.guest(f"icacls '{DIR}'")
        h.note("standard user prepared the folder before install", output=out.strip()[-300:], acl=planted_acl.strip().splitlines()[:5],
               owner=h.guest(f"(Get-Acl -LiteralPath '{DIR}').Owner").strip())
        assert "PLANTED" in out and "nimuser" in planted_acl.lower(), (out[-400:], planted_acl)

        h.guest(rf"""$ErrorActionPreference='Stop'; New-Item -ItemType Directory -Force C:\nimtest | Out-Null
            Invoke-WebRequest -UseBasicParsing https://www.python.org/ftp/python/{h.PY}/python-{h.PY}-amd64.exe -OutFile C:\nimtest\py.exe
            Start-Process C:\nimtest\py.exe -ArgumentList '/quiet InstallAllUsers=1 PrependPath=1 Include_launcher=1' -Wait""", timeout=1800)
        out = h.guest(rf"""$env:Path = 'C:\Program Files\Python313;C:\Program Files\Python313\Scripts;' + $env:Path
            $env:NIMSTEAD_TOKEN = '{token}'
            try {{ irm http://10.0.2.2:{h.PORT}/install.ps1 | iex }} catch {{ "INSTALL FAILED: $_"; exit 1 }}""", timeout=1800, check=False)
        assets = api.get("/api/assets").json()
        h.note("install.ps1 ran elevated", output=out.strip()[-1500:], assets=[(a["hostname"], a["agent_version"]) for a in assets])
        assert len(assets) == 1 and assets[0]["last_seen"], (assets, out[-2000:])

        read = as_user(attacker, f"Get-Content -LiteralPath '{DIR}\\agent.json' -Raw | Out-Null; 'READ'")
        write = as_user(attacker, f"Set-Content -LiteralPath '{DIR}\\pending-job.json' -Value x; 'WROTE'")
        acl = h.guest(f"icacls '{DIR}'")
        owner = h.guest(f"(Get-Acl -LiteralPath '{DIR}').Owner").strip()
        link_left = h.guest(f"Test-Path -LiteralPath '{DIR}\\x'").strip()
        kept = h.guest(f"Get-Content -LiteralPath '{VICTIM}\\keep.txt' -Raw").strip()
        h.note("after install", attacker_read_key="READ" in read, attacker_wrote="WROTE" in write, acl=acl.strip().splitlines()[:5],
               owner=owner, junction_left=link_left, victim_file=kept)
        assert "READ" not in read and "WROTE" not in write, (read[-400:], write[-400:])
        assert "nimuser" not in acl.lower() and "Users:" not in acl and owner == "BUILTIN\\Administrators", (acl, owner)
        assert link_left == "False" and kept == "not yours"
        h.note("RESULT: PASS")
        return 0
    finally:
        server.kill()


if __name__ == "__main__":
    try:
        rc = main()
    except Exception as e:
        h.note("RESULT: FAIL", error=f"{type(e).__name__}: {e}"[:3000])
        rc = 1
    finally:
        (ROOT / "sandbox" / "last_run_windows_local.json").write_text(json.dumps(h.log, indent=2, default=str))
    if rc == 0:
        h.winvm.destroy(h.NAME)
        h.note("VM destroyed", name=h.NAME)
    sys.exit(rc)
