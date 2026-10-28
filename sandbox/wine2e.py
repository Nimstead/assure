"""Windows end to end in a DISPOSABLE Windows Server 2025 VM (sandbox/winvm.py): real install.ps1, real Windows
Update install of the fixing cumulative update, forced-failure rollback via DISM across reboots, then a clean
update driven entirely by the installed scheduled task.

Run from api/:  uv run python ../sandbox/wine2e.py VM_NAME [--keep]
The API runs on the host at 127.0.0.1:8766 (the VM reaches it as 10.0.2.2 through VirtualBox NAT).
"""

import io
import json
import os
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import winvm  # noqa: E402
from signin import signup  # noqa: E402  first account + its admin's TOTP sign-in

ROOT = Path(__file__).resolve().parents[1]
NAME = sys.argv[1]
assert NAME.startswith(winvm.PREFIX)
TMP = Path(tempfile.mkdtemp(prefix="nimstead-wine2e-"))
PORT = 8766
PY = "3.13.17"
log: list[dict] = []
OUT = "last_run_windows.json"  # last_run_windows11.json once the VM reports Windows 11


def note(step, **kw):
    log.append({"step": step, **kw})
    print(f"[{time.strftime('%H:%M:%S')}] {step}", json.dumps(kw, default=str)[:400] if kw else "", flush=True)


def guest(cmd, timeout=3600, check=True):
    for _ in range(4):  # VirtualBox guest control flakes right after boot (VERR_* from VBoxManage itself)
        rc, out = winvm.run(NAME, cmd, timeout=timeout)
        if rc == 0 or not any(s in out for s in ("VERR_", "not ready")) and out.strip():
            break
        # Windows 11 finishes a cumulative update with a second restart, which can land between two commands (seen
        # for real: empty output, then "Guest Additions are not ready"); wait it out, cold-booting a firmware hang
        time.sleep(15)
        winvm.wait_ready(NAME, minutes=30)
    if check and rc != 0:
        raise RuntimeError(f"guest command failed ({rc}): {cmd[:200]}\n{out[-2000:]}")
    return out


def as_system(cmd, name="NimsteadTest", wait_minutes=120, result=None):
    """Run cmd as SYSTEM through a one-off scheduled task (Windows Update refuses remote/network logons)."""
    # the command goes in a .cmd file: cmd /c inside a task argument mangles quoted "C:\Program Files\..." paths
    guest("Set-Content -Path C:\\nimtest\\task.cmd -Encoding ascii -Value @'\r\n" + cmd + "\r\necho done > C:\\nimtest\\done.txt\r\n'@")
    guest(r"""$ErrorActionPreference='Stop'
        Remove-Item C:\nimtest\done.txt -ErrorAction SilentlyContinue
        $a = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c C:\nimtest\task.cmd'
        Register-ScheduledTask -TaskName NAME -Action $a -User SYSTEM -RunLevel Highest -Force | Out-Null
        Start-ScheduledTask -TaskName NAME""".replace("NAME", name))
    end = time.time() + wait_minutes * 60
    while time.time() < end:
        if "True" in guest(r"Test-Path C:\nimtest\done.txt", check=False):
            return
        # the agent's own result file is authoritative (the task's cmd can be torn down by servicing right after it)
        if result and '"outcome"' in guest(f"Get-Content {result} -Raw -ErrorAction SilentlyContinue", check=False):
            return
        time.sleep(20)
    raise RuntimeError(f"SYSTEM task did not finish in {wait_minutes} min: {cmd}")


def reboot_and_wait():
    guest("shutdown /r /t 5", check=False)
    time.sleep(90)
    winvm.wait_ready(NAME, minutes=90)


def build():
    return guest(r"$k='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'; '10.0.{0}.{1}' -f (gp $k).CurrentBuild, (gp $k).UBR").strip()


def main(keep=False) -> int:
    env = {**os.environ, "NIMSTEAD_DB": f"sqlite:///{(TMP / 'n.db').as_posix()}", "NIMSTEAD_SECURE_COOKIES": "0",
           "NIMSTEAD_INVENTORY_MIN_SECONDS": "0", "NIMSTEAD_PUBLIC_URL": f"http://10.0.2.2:{PORT}",
           "NIMSTEAD_SIGNING_KEY_FILE": str(TMP / "sign.pem"), "NIMSTEAD_CHECKPOINT_DIR": str(TMP / "cp"),
           "NIMSTEAD_SECRET_KEY_FILE": str(TMP / "secret.key")}
    os.environ.update(env)
    import httpx

    from nimstead import feeds
    from nimstead.db import make_sessionmaker
    with make_sessionmaker(env["NIMSTEAD_DB"])() as s:
        for attempt in range(10):  # MSRC rate-limits repeated full syncs (429, no Retry-After); production retries hourly
            try:
                msrc = feeds.sync_msrc(s, 2)
                break
            except httpx.HTTPStatusError as e:
                if e.response.status_code != 429 or attempt == 9:
                    raise
                time.sleep(120)
        note("feeds", msrc=msrc, kev=feeds.sync_kev(s), epss=feeds.sync_epss(s))
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
        signup(api, {"email": "win@example.com", "password": "windows-e2e-password", "org_name": "WinE2E"})
        token = api.post("/api/enroll-tokens", json={"sandbox": True}).json()["token"]

        winvm.wait_ready(NAME, minutes=90)
        start_build = build()
        note("VM ready", build=start_build)
        guest(rf"""$ErrorActionPreference='Stop'; New-Item -ItemType Directory -Force C:\nimtest | Out-Null
            Invoke-WebRequest -UseBasicParsing https://www.python.org/ftp/python/{PY}/python-{PY}-amd64.exe -OutFile C:\nimtest\py.exe
            Start-Process C:\nimtest\py.exe -ArgumentList '/quiet InstallAllUsers=1 PrependPath=1 Include_launcher=1' -Wait""", timeout=1800)
        note("Python installed in VM", version=guest(r"& 'C:\Program Files\Python313\python.exe' --version").strip())

        # 1) the real installer, elevated, with the remediation opt-in
        out = guest(rf"""$env:Path = 'C:\Program Files\Python313;C:\Program Files\Python313\Scripts;' + $env:Path
            $env:NIMSTEAD_TOKEN = '{token}'; $env:NIMSTEAD_ALLOW_REMEDIATION = '1'
            try {{ irm http://10.0.2.2:{PORT}/install.ps1 | iex }} catch {{ "INSTALL FAILED: $_"; exit 1 }}
            (Get-ScheduledTask -TaskName 'Nimstead agent').Triggers | ForEach-Object {{ $_.CimClass.CimClassName }}""", timeout=1800, check=False)
        note("install.ps1 output", output=out[-3000:])
        assets = api.get("/api/assets").json()
        assert len(assets) == 1 and assets[0]["ecosystem"] == "Windows", (assets, out[-2000:])
        a = assets[0]
        if "Windows 11" in a["os_name"]:
            global OUT
            OUT = "last_run_windows11.json"
        summ = api.get("/api/summary").json()
        top = summ["top_actions"][0]
        note("install.ps1 ran elevated: enrolled, reported, task registered", triggers=out.strip().splitlines()[-2:],
             os=a["os_name"], open_by_priority=summ["open_by_priority"], fix=f"{top['package']} -> {top['fixed_version']}")
        product = top["package"]
        guest("Disable-ScheduledTask -TaskName 'Nimstead agent' | Out-Null")  # keep it out of the way for the rollback test

        def plan_and_get_job():
            r = api.post("/api/remediation/jobs", json={"asset_id": a["id"], "ecosystem": "Windows", "package": product})
            assert r.status_code == 201, r.text
            jid = r.json()["id"]
            assert api.post(f"/api/remediation/jobs/{jid}/approve").status_code == 200
            return jid

        cfg = json.loads(guest(r"Get-Content C:\ProgramData\Nimstead\agent.json -Raw"))
        h = {"Authorization": f"Bearer {cfg['agent_key']}"}

        # 2) rollback: real install of the KB, forced failure after the reboot, DISM removal, reboot, original build back
        agent = r'"C:\Program Files\Python313\python.exe" "C:\Program Files\Nimstead\nimstead_agent.py"'
        if "--success-only" not in sys.argv:  # --success-only: rollback already proven on this VM
            jid = plan_and_get_job()
            [job] = api.get("/api/agent/jobs", headers=h).json()
            note("job dispatched", kb=job["packages"][0]["kb"], target=job["packages"][0]["to"])
            guest("Set-Content -Path C:\\nimtest\\job.json -Value '" + json.dumps(job).replace("'", "''") + "' -Encoding ascii")
            as_system(rf"{agent} run-job --yes --fail-after-apply < C:\nimtest\job.json > C:\nimtest\out1.json 2>&1", wait_minutes=150, result=r"C:\nimtest\out1.json")
            r1 = json.loads(guest(r"Get-Content C:\nimtest\out1.json -Raw").strip().splitlines()[-1])
            note("update installed, waiting for reboot", outcome=r1["outcome"], steps=[s["step"] for s in r1["steps"]][-4:])
            assert r1["outcome"] == "pending_reboot", r1
            reboot_and_wait()
            note("rebooted", build=build())
            as_system(rf"{agent} resume-job > C:\nimtest\out2.json 2>&1", wait_minutes=90, result=r"C:\nimtest\out2.json")
            r2 = json.loads(guest(r"Get-Content C:\nimtest\out2.json -Raw").strip().splitlines()[-1])
            note("injected failure -> rollback started", outcome=r2["outcome"], steps=[s["step"] for s in r2["steps"]][-4:])
            assert r2["outcome"] == "pending_reboot", r2
            reboot_and_wait()
            as_system(rf"{agent} resume-job > C:\nimtest\out3.json 2>&1", wait_minutes=60, result=r"C:\nimtest\out3.json")
            r3 = json.loads(guest(r"Get-Content C:\nimtest\out3.json -Raw").strip().splitlines()[-1])
            after = build()
            note("rollback finished", outcome=r3["outcome"], build_now=after, build_before=start_build)
            assert r3["outcome"] == "rolled_back" and after == start_build, r3
            api.post(f"/api/agent/jobs/{jid}/report", json=r3, headers=h)

        # 3) success, driven only by the installed scheduled task: install -> reboot -> startup run resumes -> report
        jid = plan_and_get_job()
        guest("Enable-ScheduledTask -TaskName 'Nimstead agent' | Out-Null; Start-ScheduledTask -TaskName 'Nimstead agent'")
        note("scheduled task started for the real fix")
        end = time.time() + 180 * 60
        status = None
        while time.time() < end:
            try:
                status = next(j for j in api.get("/api/remediation/jobs").json() if j["id"] == jid)["status"]
            except httpx.HTTPError:
                pass
            if status in ("succeeded", "not_fixed", "rolled_back", "rollback_failed", "failed", "aborted"):
                break
            winvm.unstick(NAME)  # the agent's own reboot
            time.sleep(60)
        winvm.wait_ready(NAME, minutes=30)
        final = build()
        f_open = len(api.get("/api/findings").json())
        note("scheduled-task fix finished", status=status, build=final, open_findings=f_open)
        if status != "succeeded":  # the agent's own step log says why
            j = next(j for j in api.get("/api/remediation/jobs").json() if j["id"] == jid)
            note("job steps", error=j.get("error"), steps=[f"{'ok ' if s['ok'] else 'FAIL'} {s['step']}: {s['output'][-200:]}" for s in j.get("steps", [])])
        assert status == "succeeded", status

        z = zipfile.ZipFile(io.BytesIO(api.get("/api/evidence/pack", params={"days": 1}).content))
        from nimstead.verify_pack import verify
        fp = api.get("/api/evidence/public-key").json()["fingerprint_sha256"]
        problems = verify(z.read("pack.json"), z.read("pack.sig").decode(), z.read("public_key.pem"), fp)
        note("evidence pack", problems=problems)
        assert not problems
        note("RESULT: PASS")
        return 0
    except Exception as e:
        note("RESULT: FAIL", error=f"{type(e).__name__}: {e}"[:3000])
        return 1
    finally:
        server.kill()
        passed = any(e["step"] == "RESULT: PASS" for e in log)
        if passed and "--keep" not in sys.argv:  # a failed run keeps the VM for inspection; destroy it with winvm.py destroy
            winvm.destroy(NAME)
            note("VM destroyed", name=NAME)
        elif not passed:
            note("VM kept for inspection", name=NAME, destroy=f"uv run python ../sandbox/winvm.py destroy {NAME}")
        (ROOT / "sandbox" / OUT).write_text(json.dumps(log, indent=2, default=str))


if __name__ == "__main__":
    sys.exit(main())
