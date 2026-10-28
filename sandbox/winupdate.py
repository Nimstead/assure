"""Agent self-update on Windows, driven only by the installed SYSTEM scheduled task, in a DISPOSABLE Windows VM
(sandbox/winvm.py). The VM is destroyed at the end unless --keep.

The host API serves an agent pinning a test release key. After the real install.ps1 (with remediation, so both tasks
exist), the server is given a newer agent, signed for that key, whose SCHEDULE_VERSION is also bumped. Starting the
installed "Nimstead agent" task must then: verify and swap in the new agent, re-register its scheduled tasks while that
very task is running, and finish the run on the new version. A second run must change nothing, and the re-registered
tasks must still be SYSTEM, still have their triggers, and still run.

Run from api/:  uv run python ../sandbox/winupdate.py VM_NAME [--keep]
"""

import base64
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import winvm  # noqa: E402
from signin import signup  # noqa: E402  first account + its admin's TOTP sign-in

ROOT = Path(__file__).resolve().parents[1]
NAME = sys.argv[1]
assert NAME.startswith(winvm.PREFIX)
TMP = Path(tempfile.mkdtemp(prefix="nimstead-winupdate-"))
PORT = 8767
PY = "3.13.17"
OUT = Path(__file__).with_name("last_run_windows_selfupdate.json")
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


def run_task_and_wait(task, minutes=15):
    """Start an installed scheduled task and wait until it has run and stopped; returns its LastTaskResult."""
    guest(f"Start-ScheduledTask -TaskName '{task}'")
    end = time.time() + minutes * 60
    time.sleep(10)
    while time.time() < end:
        st = guest(f"$t = Get-ScheduledTask -TaskName '{task}'; $i = $t | Get-ScheduledTaskInfo; "
                   "'{0}|{1}|{2}' -f $t.State, $i.LastTaskResult, $i.LastRunTime.ToString('o')").strip()
        state, result, _ = st.split("|")
        if state != "Running":
            return int(result)
        time.sleep(10)
    raise RuntimeError(f"task {task} still running after {minutes} min")


def agent_version_in_guest():
    out = guest(f"Select-String -Path '{AGENT_DIR}\\nimstead_agent.py' -Pattern '^AGENT_VERSION = ' | ForEach-Object Line")
    return re.search(r'"([^"]+)"', out).group(1)


def main(keep=False) -> int:
    import importlib.util

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
    sched = int(re.search(rb"^SCHEDULE_VERSION = (\d+)", src, re.M).group(1))
    pinned = re.sub(rb"^RELEASE_KEYS = .*$", f'RELEASE_KEYS = ["{pub}"]'.encode(), src, count=1, flags=re.M)
    newer = pinned.replace(f'AGENT_VERSION = "{old_version}"'.encode(), f'AGENT_VERSION = "{new_version}"'.encode(), 1) \
                  .replace(f"SCHEDULE_VERSION = {sched}".encode(), f"SCHEDULE_VERSION = {sched + 1}".encode(), 1)
    agent_file, release_dir = TMP / "nimstead_agent.py", TMP / "release"
    agent_file.write_bytes(pinned)
    release_dir.mkdir()

    env = {**os.environ, "NIMSTEAD_DB": f"sqlite:///{(TMP / 'n.db').as_posix()}", "NIMSTEAD_SECURE_COOKIES": "0",
           "NIMSTEAD_INVENTORY_MIN_SECONDS": "0", "NIMSTEAD_PUBLIC_URL": f"http://10.0.2.2:{PORT}",
           "NIMSTEAD_SIGNING_KEY_FILE": str(TMP / "sign.pem"), "NIMSTEAD_CHECKPOINT_DIR": str(TMP / "cp"),
           "NIMSTEAD_SECRET_KEY_FILE": str(TMP / "secret.key"), "NIMSTEAD_AGENT_FILE": str(agent_file),
           "NIMSTEAD_RELEASE_DIR": str(release_dir), "NIMSTEAD_UPDATE_CHECK": "0", "NIMSTEAD_OPEN_SIGNUP": "1"}
    import httpx
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
        signup(api, {"email": "win@example.com", "password": "windows-update-password", "org_name": "WinUpdate"})
        token = api.post("/api/enroll-tokens", json={"sandbox": True}).json()["token"]

        winvm.wait_ready(NAME, minutes=120)
        note("VM ready", os=guest("(Get-CimInstance Win32_OperatingSystem).Caption").strip())
        guest(rf"""$ErrorActionPreference='Stop'; New-Item -ItemType Directory -Force C:\nimtest | Out-Null
            Invoke-WebRequest -UseBasicParsing https://www.python.org/ftp/python/{PY}/python-{PY}-amd64.exe -OutFile C:\nimtest\py.exe
            Start-Process C:\nimtest\py.exe -ArgumentList '/quiet InstallAllUsers=1 PrependPath=1 Include_launcher=1' -Wait""", timeout=1800)
        out = guest(rf"""$env:Path = 'C:\Program Files\Python313;C:\Program Files\Python313\Scripts;' + $env:Path
            $env:NIMSTEAD_TOKEN = '{token}'; $env:NIMSTEAD_ALLOW_REMEDIATION = '1'
            try {{ irm http://10.0.2.2:{PORT}/install.ps1 | iex }} catch {{ "INSTALL FAILED: $_"; exit 1 }}
            Get-ScheduledTask -TaskName 'Nimstead*' | ForEach-Object {{ $_.TaskName + ' as ' + $_.Principal.UserId + ': ' + $_.Actions[0].Arguments }}""",
                    check=False)
        assets = api.get("/api/assets").json()
        assert len(assets) == 1 and assets[0]["agent_version"] == old_version and "Nimstead jobs" in out, (assets, out[-2000:])
        note("install.ps1: enrolled and reported, both SYSTEM tasks registered", agent=old_version,
             agent_update=assets[0]["agent_update"], tasks=out.strip().splitlines()[-2:])
        guest("Disable-ScheduledTask -TaskName 'Nimstead jobs' | Out-Null")  # keep the 15-minute poll out of this run

        # publish the newer agent and its signed manifest
        agent_file.write_bytes(newer)
        manifest = sign_release.release_manifest("v9.9.9", "f" * 40, newer, "9.9.9")
        (release_dir / "release.json").write_bytes(manifest)
        (release_dir / "release.json.sig").write_text(base64.b64encode(key.sign(manifest)).decode())
        assert api.get("/api/settings").json()["signed_agent_release"], "server isn't relaying the signed release"
        note("server now relays a newer signed agent", new=new_version, schedule_version=sched + 1)

        rc = run_task_and_wait("Nimstead agent")
        a = api.get("/api/assets").json()[0]
        on_disk = agent_version_in_guest()
        prev = guest(f"Test-Path '{AGENT_DIR}\\nimstead_agent.py.prev'").strip()
        tasks = guest("Get-ScheduledTask -TaskName 'Nimstead*' | ForEach-Object { $tr = ($_.Triggers | ForEach-Object "
                      "{ $_.CimClass.CimClassName + '/' + $_.Repetition.Interval }) -join ','; "
                      "'{0} {1} {2} triggers={3}' -f $_.TaskName, $_.Principal.UserId, $_.State, $tr }")
        cfg = json.loads(guest(r"Get-Content C:\ProgramData\Nimstead\agent.json -Raw"))
        assert rc == 0 and on_disk == new_version and a["agent_version"] == new_version and prev == "True", (rc, on_disk, a, prev)
        assert cfg.get("schedule_version") == sched + 1 and "Nimstead agent SYSTEM" in tasks and "PT6H" in tasks, (cfg.get("schedule_version"), tasks)
        note("the SYSTEM task updated the agent, re-registered its tasks mid-run, and reported on the new version",
             task_result=rc, agent_on_disk=on_disk, reported=a["agent_version"], kept_prev=prev,
             schedule_version=cfg["schedule_version"], tasks=tasks.strip().splitlines())

        rc = run_task_and_wait("Nimstead agent")
        a = api.get("/api/assets").json()[0]
        assert rc == 0 and agent_version_in_guest() == new_version and a["agent_version"] == new_version, (rc, a)
        note("second run of the re-registered task: succeeded, no update, still current", task_result=rc, agent=a["agent_version"])

        guest("Enable-ScheduledTask -TaskName 'Nimstead jobs' | Out-Null")
        rc = run_task_and_wait("Nimstead jobs")
        assert rc == 0, rc
        note("15-minute job poll task (re-registered too) runs as SYSTEM", task_result=rc)
        result, code = "PASS", 0
    except Exception as e:
        note("FAILED", error=str(e)[-3000:])
        result, code = "FAIL", 1
    finally:
        server.terminate()
        if not keep:
            winvm.destroy(NAME)
            note("VM destroyed", name=NAME)
    OUT.write_text(json.dumps({"result": result, "vm": NAME, "steps": log}, indent=2, default=str) + "\n", encoding="utf-8")
    print(result)
    return code


if __name__ == "__main__":
    sys.exit(main(keep="--keep" in sys.argv))
