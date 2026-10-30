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
log: list[dict] = []
OUT = "last_run_windows.json"  # last_run_windows11.json once the VM reports Windows 11


def note(step, **kw):
    log.append({"step": step, **kw})
    print(f"[{time.strftime('%H:%M:%S')}] {step}", json.dumps(kw, default=str)[:400] if kw else "", flush=True)


def guest(cmd, timeout=3600, check=True):
    for _ in range(4):  # VirtualBox guest control flakes right after boot (VERR_* from VBoxManage itself)
        try:
            rc, out = winvm.run(NAME, cmd, timeout=timeout)
        except subprocess.TimeoutExpired:  # guest control itself can hang (seen: an hour on Test-Path during the Office install)
            rc, out = 1, "timed out"
        if rc == 0 or not any(s in out for s in ("VERR_", "not ready", "timed out", "Error starting guest session")) and out.strip():
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
        if "True" in guest(r"Test-Path C:\nimtest\done.txt", timeout=120, check=False):
            return
        # the agent's own result file is authoritative (the task's cmd can be torn down by servicing right after it)
        if result and '"outcome"' in guest(f"Get-Content {result} -Raw -ErrorAction SilentlyContinue", timeout=120, check=False):
            return
        time.sleep(20)
    raise RuntimeError(f"SYSTEM task did not finish in {wait_minutes} min: {cmd}")


def reboot_and_wait():
    guest("shutdown /r /t 5", check=False)
    time.sleep(90)
    winvm.wait_ready(NAME, minutes=90)
    # servicing can restart once more on its own right after (seen on Server 2025: TrustedInstaller 30 s after boot);
    # ready means the boot time held still for 3 minutes
    boot, stable = None, 0
    while stable < 3:
        time.sleep(60)
        try:
            now = guest("(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString('o')", check=False).strip()
        except Exception:
            now = None
        if not now or now != boot:
            winvm.wait_ready(NAME, minutes=90)
            boot, stable = now, 0
        else:
            stable += 1


def build():
    return guest(r"$k='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'; '10.0.{0}.{1}' -f (gp $k).CurrentBuild, (gp $k).UBR").strip()


def main(keep=False) -> int:
    # --proxy: the server is HTTPS (the agent never sends its key to a plain-http server through a proxy)
    tls = None
    if "--proxy" in sys.argv:
        from hostproxy import server_cert
        tls = server_cert(TMP)
    scheme = "https" if tls else "http"
    env = {**os.environ, "NIMSTEAD_DB": f"sqlite:///{(TMP / 'n.db').as_posix()}", "NIMSTEAD_SECURE_COOKIES": "0",
           "NIMSTEAD_INVENTORY_MIN_SECONDS": "0", "NIMSTEAD_PUBLIC_URL": f"{scheme}://10.0.2.2:{PORT}",
           "NIMSTEAD_SIGNING_KEY_FILE": str(TMP / "sign.pem"), "NIMSTEAD_CHECKPOINT_DIR": str(TMP / "cp"),
           "NIMSTEAD_SECRET_KEY_FILE": str(TMP / "secret.key"), "NIMSTEAD_OPEN_SIGNUP": "1"}
    from testrelease import TestRelease  # install.ps1 brings the signed embeddable runtime (plan T25)
    rel = TestRelease(TMP)
    rel.publish(rel.agent, "3.15.2", "v9.9.8")
    env.update(rel.env())
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
                               "--port", str(PORT), *(["--ssl-certfile", str(tls[0]), "--ssl-keyfile", str(tls[1])] if tls else [])],
                              env=env, cwd=ROOT / "api", stdout=open(TMP / "api.log", "wb"), stderr=subprocess.STDOUT)
    api = httpx.Client(base_url=f"{scheme}://127.0.0.1:{PORT}", timeout=60, verify=str(tls[0]) if tls else True)
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
        guest(r"New-Item -ItemType Directory -Force C:\nimtest | Out-Null")
        px = None
        if "--proxy" in sys.argv:  # plan T44: the only way out is a proxy on this host; everything else is blocked
            from hostproxy import Proxy
            px = Proxy(3128)
            guest("Set-Content -Path C:\\nimtest\\sandbox-cert.pem -Encoding ascii -Value @'\r\n" + tls[0].read_text() + "\r\n'@\r\n"
                  r"Import-Certificate -FilePath C:\nimtest\sandbox-cert.pem -CertStoreLocation Cert:\LocalMachine\Root | Out-Null")
            # only the proxy port is open, so whatever reached the server or the internet went through the proxy
            guest(r"""New-NetFirewallRule -DisplayName 'Nimstead sandbox: proxy only' -Direction Outbound -RemoteAddress 10.0.2.2 -Protocol TCP -RemotePort 3128 -Action Allow | Out-Null
                Set-NetFirewallProfile -All -DefaultOutboundAction Block; netsh winhttp set proxy 10.0.2.2:3128 | Out-Null
                # what an admin sets for Windows Update behind a proxy (docs/install.md): a device-wide proxy, and Delivery
                # Optimization in bypass mode, since on Windows 11 26H2 it went straight to CDN IPs and every download stalled
                $p = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
                New-Item $p -Force | Out-Null; Set-ItemProperty $p ProxySettingsPerUser 0 -Type DWord
                $i = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings'
                Set-ItemProperty $i ProxyEnable 1 -Type DWord; Set-ItemProperty $i ProxyServer '10.0.2.2:3128'
                $d = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'
                New-Item $d -Force | Out-Null; Set-ItemProperty $d DODownloadMode 100 -Type DWord
                Restart-Service DoSvc, wuauserv -Force -ErrorAction SilentlyContinue""")
            direct = {f"{h}:{p}": guest(f"(Test-NetConnection {h} -Port {p} -WarningAction SilentlyContinue).TcpTestSucceeded", check=False).strip()
                      for h, p in (("13.107.4.50", 443), ("10.0.2.2", PORT))}
            note("direct egress blocked, WinHTTP proxy set", direct_tcp=direct)
            assert set(direct.values()) == {"False"}, direct

        # 1) the real installer, elevated, with the remediation opt-in (no Python needed: plan T25)
        out = guest(rf"""$env:NIMSTEAD_TOKEN = '{token}'; $env:NIMSTEAD_ALLOW_REMEDIATION = '1'
            {"$env:NIMSTEAD_PROXY = 'http://10.0.2.2:3128'" if px else ""}
            try {{ irm {"-Proxy http://10.0.2.2:3128 " if px else ""}{scheme}://10.0.2.2:{PORT}/install.ps1 | iex }} catch {{ "INSTALL FAILED: $_"; exit 1 }}
            (Get-ScheduledTask -TaskName 'Nimstead agent').Triggers | ForEach-Object {{ $_.CimClass.CimClassName }}""", timeout=1800, check=False)
        note("install.ps1 output", output=out[-3000:])
        assets = api.get("/api/assets").json()
        assert len(assets) == 1 and assets[0]["ecosystem"] == "Windows", (assets, out[-2000:])
        a = assets[0]
        if "Windows 11" in a["os_name"]:
            global OUT
            OUT = "last_run_windows11.json"
        summ = api.get("/api/summary").json()
        top = next(x for x in summ["top_actions"] if x["ecosystem"] == "Windows")  # the OS update, not app or setting findings
        note("install.ps1 ran elevated: enrolled, reported, task registered", triggers=out.strip().splitlines()[-2:],
             os=a["os_name"], open_by_priority=summ["open_by_priority"], fix=f"{top['package']} -> {top['fixed_version']}")
        product = top["package"]
        # a health unit present on Server Core and Windows 11 alike, so the crash-event check (plan T13) runs for real
        assert api.patch(f"/api/assets/{a['id']}", json={"health_units": ["LanmanServer"]}).status_code == 200
        import winoracle
        table = winoracle.run(as_system, guest, api.get("/api/findings").json())
        note("oracle: Windows Update vs Nimstead", **{k: v for k, v in table.items()})
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
        py = guest(r"(Resolve-Path 'C:\Program Files\Nimstead\runtime\*\python.exe')[0].Path").strip()
        agent = f'"{py}" -I "C:\\Program Files\\Nimstead\\nimstead_agent.py"'
        if "--success-only" not in sys.argv:  # --success-only: rollback already proven on this VM
            # this part drives the job by hand; the agent's own startup run would race it for the same pending job
            guest("Disable-ScheduledTask -TaskName 'Nimstead jobs' | Out-Null")
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
            guest("Enable-ScheduledTask -TaskName 'Nimstead jobs' | Out-Null")

        # 3) success, driven only by the installed scheduled task: install -> reboot -> startup run resumes -> report
        signed_in = "--signed-in" in sys.argv  # plan T41: a workstation user is told and the restart waits for the deadline
        # the install's autologon counts as someone signed in, so every run waits for this deadline, not the default 24 h
        assert api.patch("/api/settings", json={"reboot_deadline_hours": 1}).status_code == 200
        if signed_in:
            guest(r"""$p = 'Nim-user-' + (Get-Random); New-LocalUser nimuser -Password (ConvertTo-SecureString $p -AsPlainText -Force) | Out-Null
                Add-LocalGroupMember Users nimuser  # `net user` stops to ask about passwords over 14 characters
                $k = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
                Set-ItemProperty $k AutoAdminLogon '1'; Set-ItemProperty $k DefaultUserName 'nimuser'; Set-ItemProperty $k DefaultPassword $p""")
            reboot_and_wait()
            for _ in range(30):
                if guest(r"""@(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'").Count""").strip() not in ("", "0"):
                    break
                time.sleep(20)
            explorer = guest(r"""@(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'").Count""").strip()
            note("standard user signed in", explorer=explorer)
            assert explorer not in ("", "0"), "nobody signed in"
        if px:  # a newer signed agent: the task's self-update has to come through the proxy too
            new_agent, new_version = rel.newer()
            rel.publish(new_agent, "3.15.2", "v9.9.9")
        jid = plan_and_get_job()
        dispatched = time.time()
        guest("Enable-ScheduledTask -TaskName 'Nimstead agent' | Out-Null; Start-ScheduledTask -TaskName 'Nimstead agent'")
        note("scheduled task started for the real fix")
        end = time.time() + 180 * 60
        status, deferred, restarted_at = None, None, None
        boot0 = guest("(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('s')").strip()
        while time.time() < end:
            if signed_in and deferred is None:  # installed and waiting: the notice is on screen, no restart yet
                if '"phase": "verify"' in guest(r"Get-Content C:\ProgramData\Nimstead\pending-job.json -Raw -ErrorAction SilentlyContinue", check=False):
                    time.sleep(120)
                    shot = ROOT / "sandbox" / "last_run_windows11_restart_notice.png"
                    try:
                        winvm.vbox("controlvm", NAME, "screenshotpng", str(shot))
                    except RuntimeError:  # a headless VM can refuse it (E_FAIL); the agent's notified_at shows the notice went out
                        shot = None
                    state = guest(r"Get-Content C:\ProgramData\Nimstead\pending-job.json -Raw", check=False)
                    deferred = {"minutes_after_dispatch": round((time.time() - dispatched) / 60), "screenshot": shot and shot.name,
                                "notice_sent": '"notified_at"' in state,
                                "boot_unchanged": guest("(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('s')",
                                                        check=False).strip() == boot0}
                    note("restart deferred for the signed-in user", **deferred)
            if signed_in and restarted_at is None and deferred and guest(
                    "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('s')", check=False).strip() not in ("", boot0):
                restarted_at = round((time.time() - dispatched) / 60)
                note("restarted", minutes_after_dispatch=restarted_at, who=guest(  # the agent, or Windows on its own?
                    "Get-WinEvent -FilterHashtable @{LogName='System'; Id=1074} -MaxEvents 3 | ForEach-Object { \"$($_.TimeCreated.ToUniversalTime().ToString('s')) $($_.Message)\" }", check=False)[-900:])
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
        if px:  # enrol, report, self-update and the fix's Windows Update traffic all went through the proxy
            # TLS end to end, so the proxy sees CONNECTs only; enrol, report and self-update worked with only its port open
            seen = {"server over TLS": any(m == "CONNECT" and t == f"10.0.2.2:{PORT}" for m, t in px.log),
                    "windows update": any(m == "CONNECT" and ("windowsupdate" in t or "microsoft.com" in t or "delivery.mp" in t)
                                          for m, t in px.log)}
            version = guest(r"(Select-String -Path 'C:\Program Files\Nimstead\nimstead_agent.py' -Pattern '^AGENT_VERSION = ').Line").strip()
            note("through the proxy", **seen, agent=version, requests=len(px.log),
                 hosts=sorted({t.split("/")[2] if "://" in t else t for _, t in px.log})[:40])
            assert all(seen.values()) and new_version in version, (seen, version)
        if signed_in:  # deferred while someone was signed in, restarted only once the 1-hour deadline had passed
            assert deferred and deferred["boot_unchanged"] and deferred["notice_sent"] and restarted_at and restarted_at >= 60, (deferred, restarted_at)

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
        mode = "".join(f"_{m}" for m in ("proxy", "signed-in") if f"--{m}" in sys.argv)
        (ROOT / "sandbox" / OUT.replace(".json", mode.replace("-", "_") + ".json")).write_text(json.dumps(log, indent=2, default=str))


if __name__ == "__main__":
    sys.exit(main())
