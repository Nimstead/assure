"""Python-free Windows agent (plan T27), in a DISPOSABLE Windows VM (sandbox/winvm.py) that has no Python at all.

The host API serves an agent pinning a test release key and a release signed for it whose runtimes are the real
python.org embeddable zips: first CPython OLD_PY, later NEW_PY. Proves, driven by the installed SYSTEM task alone:
  1. the one-line install.ps1 enrols, reports and schedules on a machine without Python (runtime PSF-signed, hashed);
  2. Windows Update's own missing security updates vs our findings (sandbox/winoracle.py);
  3. a newer agent and a newer runtime are both taken by one task run, the next run changes nothing and removes the
     old runtime folder, and standard users can't write any of it;
  4. a host whose tasks run a system Python moves to the bundled runtime by the task alone;
  5. uninstall --yes leaves no folder, task or key behind.

Run from api/:  uv run python ../sandbox/winnopython.py VM_NAME [--keep]
"""

import base64
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import winoracle  # noqa: E402
import winvm  # noqa: E402
from signin import signup  # noqa: E402  first account + its admin's TOTP sign-in

ROOT = Path(__file__).resolve().parents[1]
NAME = sys.argv[1]
assert NAME.startswith(winvm.PREFIX)
TMP = Path(tempfile.mkdtemp(prefix="nimstead-winnopython-"))
PORT = 8768
OLD_PY, NEW_PY, SYSTEM_PY = "3.15.1", "3.15.2", "3.15.2"
OUT = Path(__file__).with_name("last_run_windows_nopython.json")
AGENT_DIR = r"C:\Program Files\Nimstead"
log: list[dict] = []


def note(step, **kw):
    log.append({"step": step, **kw})
    print(f"[{time.strftime('%H:%M:%S')}] {step}", json.dumps(kw, default=str)[:400] if kw else "", flush=True)


def guest(cmd, timeout=1800, check=True):
    for _ in range(4):  # guest control flakes right after boot
        rc, out = winvm.run(NAME, cmd, timeout=timeout)
        if rc == 0 or not any(s in out for s in ("VERR_", "not ready")) and out.strip():
            break
        time.sleep(15)
        winvm.wait_ready(NAME, minutes=30)
    if check and rc != 0:
        raise RuntimeError(f"guest command failed ({rc}): {cmd[:200]}\n{out[-2000:]}")
    return out


def as_system(cmd, name="NimsteadTest", wait_minutes=60):
    guest("New-Item -ItemType Directory -Force C:\\nimtest | Out-Null; Set-Content -Path C:\\nimtest\\task.cmd -Encoding ascii -Value @'\r\n"
          + cmd + "\r\necho done > C:\\nimtest\\done.txt\r\n'@")
    guest(r"""$ErrorActionPreference='Stop'; Remove-Item C:\nimtest\done.txt -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName NAME -Action (New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c C:\nimtest\task.cmd') -User SYSTEM -RunLevel Highest -Force | Out-Null
        Start-ScheduledTask -TaskName NAME""".replace("NAME", name))
    end = time.time() + wait_minutes * 60
    while time.time() < end:
        if "True" in guest(r"Test-Path C:\nimtest\done.txt", check=False):
            return
        time.sleep(15)
    raise RuntimeError(f"SYSTEM task did not finish in {wait_minutes} min: {cmd}")


def run_task_and_wait(task, minutes=20):
    guest(f"Start-ScheduledTask -TaskName '{task}'")
    end = time.time() + minutes * 60
    time.sleep(10)
    while time.time() < end:
        state, result = guest(f"$t = Get-ScheduledTask -TaskName '{task}'; '{{0}}|{{1}}' -f $t.State, ($t | Get-ScheduledTaskInfo).LastTaskResult").strip().split("|")
        if state != "Running":
            return int(result)
        time.sleep(10)
    raise RuntimeError(f"task {task} still running after {minutes} min")


def task_exe():
    return guest("(Get-ScheduledTask -TaskName 'Nimstead agent').Actions[0].Execute").strip()


def embed(version, arch="amd64") -> bytes:
    f = TMP / f"python-{version}-embed-{arch}.zip"
    if not f.exists():
        with urllib.request.urlopen(f"https://www.python.org/ftp/python/{version}/python-{version}-embed-{arch}.zip", timeout=300) as r:  # noqa: S310
            f.write_bytes(r.read())
    return f.read_bytes()


def main(keep=False) -> int:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    spec = importlib.util.spec_from_file_location("sign_release", ROOT / "scripts" / "sign_release.py")
    sign_release = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sign_release)

    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    src = (ROOT / "agent" / "nimstead_agent.py").read_bytes()
    old_version = re.search(rb'^AGENT_VERSION = "(\d+\.\d+\.\d+)"', src, re.M).group(1).decode()
    new_version = ".".join(old_version.split(".")[:2] + [str(int(old_version.split(".")[2]) + 1)])
    pinned = re.sub(rb"^RELEASE_KEYS = .*$", f'RELEASE_KEYS = ["{pub}"]'.encode(), src, count=1, flags=re.M)
    newer = pinned.replace(f'AGENT_VERSION = "{old_version}"'.encode(), f'AGENT_VERSION = "{new_version}"'.encode(), 1)
    agent_file, release_dir = TMP / "nimstead_agent.py", TMP / "release"
    release_dir.mkdir()

    def publish(agent_bytes, py, tag):
        body = embed(py)
        (release_dir / "python-embed-amd64.zip").write_bytes(body)
        rts = {"amd64": {"version": py, "sha256": hashlib.sha256(body).hexdigest()}}
        manifest = sign_release.release_manifest(tag, "f" * 40, agent_bytes, tag[1:], "preview", rts)
        agent_file.write_bytes(agent_bytes)
        (release_dir / "release.json").write_bytes(manifest)
        (release_dir / "release.json.sig").write_text(base64.b64encode(key.sign(manifest)).decode())
        return rts["amd64"]["sha256"]

    old_sha = publish(pinned, OLD_PY, "v9.9.8")
    env = {**os.environ, "NIMSTEAD_DB": f"sqlite:///{(TMP / 'n.db').as_posix()}", "NIMSTEAD_SECURE_COOKIES": "0",
           "NIMSTEAD_INVENTORY_MIN_SECONDS": "0", "NIMSTEAD_PUBLIC_URL": f"http://10.0.2.2:{PORT}",
           "NIMSTEAD_SIGNING_KEY_FILE": str(TMP / "sign.pem"), "NIMSTEAD_CHECKPOINT_DIR": str(TMP / "cp"),
           "NIMSTEAD_SECRET_KEY_FILE": str(TMP / "secret.key"), "NIMSTEAD_AGENT_FILE": str(agent_file),
           "NIMSTEAD_RELEASE_DIR": str(release_dir), "NIMSTEAD_UPDATE_CHECK": "0", "NIMSTEAD_OPEN_SIGNUP": "1",
           "NIMSTEAD_UPDATE_CHANNEL": "preview"}
    os.environ.update(env)
    import httpx

    from nimstead import feeds
    from nimstead.db import make_sessionmaker
    with make_sessionmaker(env["NIMSTEAD_DB"])() as s:
        note("feeds", msrc=feeds.sync_msrc(s, 3), kev=feeds.sync_kev(s))
    server = subprocess.Popen([sys.executable, "-m", "uvicorn", "--factory", "nimstead.app:create_app", "--host", "127.0.0.1",
                               "--port", str(PORT)], env=env, cwd=ROOT / "api", stdout=open(TMP / "api.log", "wb"), stderr=subprocess.STDOUT)
    api = httpx.Client(base_url=f"http://127.0.0.1:{PORT}", timeout=60)
    try:
        for _ in range(60):
            try:
                if api.get("/install.ps1").status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(1)
        assert api.get("/agent/runtime/amd64.zip").status_code == 200, "server isn't serving the signed runtime"
        signup(api, {"email": "win@example.com", "password": "windows-nopython-password", "org_name": "WinNoPython"})
        token = api.post("/api/enroll-tokens", json={"sandbox": True}).json()["token"]

        winvm.wait_ready(NAME, minutes=120)
        no_py = guest(r"""@((Test-Path 'C:\Program Files\Python*'), [bool](Get-Command py -ErrorAction SilentlyContinue),
            @(Get-ChildItem "$env:LOCALAPPDATA\Programs\Python" -ErrorAction SilentlyContinue).Count) -join ','""").strip()
        note("VM ready, no Python", os=guest("(Get-CimInstance Win32_OperatingSystem).Caption").strip(), python_present=no_py)
        assert no_py == "False,False,0", no_py

        # 1) the documented install, on a machine without Python
        out = guest(rf"""$env:NIMSTEAD_TOKEN = '{token}'; $env:NIMSTEAD_ALLOW_REMEDIATION = '1'
            try {{ irm http://10.0.2.2:{PORT}/install.ps1 | iex }} catch {{ "INSTALL FAILED: $_"; exit 1 }}""", check=False)
        assets = api.get("/api/assets").json()
        assert len(assets) == 1 and assets[0]["agent_version"] == old_version and "Nimstead agent installed." in out, (assets, out[-2000:])
        exe = task_exe()
        assert exe.lower() == rf"{AGENT_DIR}\runtime\{old_sha[:12]}\python.exe".lower(), exe
        assert f"runtime sha256: {old_sha}" in out
        acl = guest(rf"icacls '{AGENT_DIR}\runtime'")
        note("install.ps1 without Python: enrolled, reported, SYSTEM tasks on the bundled runtime", task_runs=exe,
             runtime_sha256=old_sha, facts=assets[0]["facts"], acl=acl.strip().splitlines()[:6])
        assert not re.search(r"BUILTIN\\Users:\((?:OI\)\(CI\))?.*[FMW]", acl), acl  # users may read and run, never write

        # 2) the oracle: Windows Update's missing security updates vs our open findings
        table = winoracle.run(as_system, guest, api.get("/api/findings").json())
        note("oracle: Windows Update vs Nimstead", **table)
        guest("Disable-ScheduledTask -TaskName 'Nimstead jobs' | Out-Null")

        # 3) a newer agent and a newer runtime, taken by the scheduled task alone
        new_sha = publish(newer, NEW_PY, "v9.9.9")
        rc = run_task_and_wait("Nimstead agent")
        exe = task_exe()
        a = api.get("/api/assets").json()[0]
        dirs = guest(rf"(Get-ChildItem '{AGENT_DIR}\runtime' -Directory).Name -join ','").strip()
        assert a["agent_version"] == new_version and exe.lower().endswith(rf"\runtime\{new_sha[:12]}\python.exe"), (rc, a, exe, dirs)
        note("one task run took agent and runtime", task_result=rc, agent=a["agent_version"], task_runs=exe, runtime_dirs=dirs)
        rc = run_task_and_wait("Nimstead agent")
        dirs2 = guest(rf"(Get-ChildItem '{AGENT_DIR}\runtime' -Directory).Name -join ','").strip()
        assert rc == 0 and dirs2 == new_sha[:12] and task_exe() == exe, (rc, dirs2)
        note("next run: nothing to do, old runtime folder removed", task_result=rc, runtime_dirs=dirs2)

        # 4) a host on a system Python (as installed before 0.6.0) moves to the bundled runtime by the task alone
        guest(rf"""$ErrorActionPreference='Stop'
            Invoke-WebRequest -UseBasicParsing https://www.python.org/ftp/python/{SYSTEM_PY}/python-{SYSTEM_PY}-amd64.exe -OutFile C:\nimtest\py.exe
            Start-Process C:\nimtest\py.exe -ArgumentList '/quiet InstallAllUsers=1 PrependPath=0 Include_launcher=0' -Wait""")
        sys_py = guest(r"(Resolve-Path 'C:\Program Files\Python3*\python.exe')[0].Path").strip()
        as_system(rf"""powershell -NoProfile -Command "$c = Get-Content C:\ProgramData\Nimstead\agent.json -Raw | ConvertFrom-Json; $c.PSObject.Properties.Remove('python'); $c | ConvertTo-Json | Set-Content C:\ProgramData\Nimstead\agent.json -Encoding ascii"
"{sys_py}" -I "{AGENT_DIR}\nimstead_agent.py" --insecure-http schedule""")
        assert task_exe().lower() == sys_py.lower(), task_exe()
        guest(rf"Remove-Item -Recurse -Force '{AGENT_DIR}\runtime\{new_sha[:12]}'")
        rc = run_task_and_wait("Nimstead agent")
        exe = task_exe()
        assert exe.lower().endswith(rf"\runtime\{new_sha[:12]}\python.exe"), (rc, exe)
        note("system-Python host moved to the bundled runtime by its own task", was=sys_py, task_result=rc, task_runs=exe)

        # 5) uninstall leaves nothing
        out = guest(rf"& '{exe}' -I '{AGENT_DIR}\nimstead_agent.py' uninstall --yes; Start-Sleep 15; "
                    rf"@((Test-Path '{AGENT_DIR}'), (Test-Path C:\ProgramData\Nimstead), "
                    r"@(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { @('Nimstead agent', 'Nimstead jobs') -contains $_.TaskName }).Count) -join ','")
        left = out.strip().splitlines()[-1]
        assert left == "False,False,0", out[-1500:]
        note("uninstall --yes: no folder, task or key left", output=out.strip().splitlines()[-4:])
        result, code = "PASS", 0
    except Exception as e:
        note("FAILED", error=str(e)[-3000:])
        result, code = "FAIL", 1
    finally:
        server.terminate()
        if not keep and code == 0:
            winvm.destroy(NAME)
            note("VM destroyed", name=NAME)
    OUT.write_text(json.dumps({"result": result, "vm": NAME, "steps": log}, indent=2, default=str) + "\n", encoding="utf-8")
    print(result)
    return code


if __name__ == "__main__":
    sys.exit(main(keep="--keep" in sys.argv))
