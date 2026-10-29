"""Agent checks that need a real Windows host (plan T13, T34, T35, T37), in a DISPOSABLE Windows VM (sandbox/winvm.py).

Each check runs the agent's own code as SYSTEM against something planted for it:
  T13  Spooler's process is killed and restarted by its recovery actions: "Running" when sampled, yet the agent's
       crash query (PS_CRASHES, used by WinJob.health) reports the Service Control Manager event.
  T34  a per-user app in the hive of a user who isn't signed in is inventoried (offline_user_apps), the hive is unloaded
       afterwards, and that user then gets their own profile, not a temporary one.
  T35  a log4j-core 2.14.1 jar nested in a fat jar is found by scan_jars with its path.
  T37  an unquoted service path under a user-writable folder and a user-writable service binary are reported by
       windows_host_facts, and the server's winconfig.evaluate turns them into findings.

Run from api/:  uv run python ../sandbox/winchecks.py VM_NAME [--keep]   Writes sandbox/last_run_winchecks.json.
"""

import io
import json
import sys
import zipfile
from pathlib import Path

import wine2e as h  # noqa: E402  (reads VM_NAME from argv)
import winfixes as f  # noqa: E402

from nimstead import winconfig  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def agent_py(code: str, name: str) -> dict:
    """Run `code` (which prints one JSON line) with the agent module imported as `a`, as SYSTEM."""
    h.guest(f"Set-Content -Path C:\\nimtest\\{name}.py -Encoding utf8 -Value @'\r\nimport sys, json\r\nsys.path.insert(0, r'C:\\nimtest')\r\n"
            f"import nimstead_agent as a\r\n{code}\r\n'@")
    out = rf"C:\nimtest\{name}.out"
    h.as_system(rf'"{f.PY}" -I C:\nimtest\{name}.py > {out} 2>&1', wait_minutes=30, result=None)
    text = h.guest(f"Get-Content {out} -Raw").strip()
    return json.loads(text.splitlines()[-1])


def fat_jar() -> Path:
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as z:
        z.writestr("META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties",
                   "groupId=org.apache.logging.log4j\nartifactId=log4j-core\nversion=2.14.1\n")
    p = h.TMP / "app-fat.jar"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("BOOT-INF/lib/log4j-core-2.14.1.jar", inner.getvalue())
        z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
    return p


def main(keep=False) -> int:
    h.winvm.wait_ready(h.NAME, minutes=90)
    h.guest(r"New-Item -ItemType Directory -Force C:\nimtest | Out-Null")
    f.runtime()
    f.copy_in(ROOT / "agent" / "nimstead_agent.py")
    checks = {}

    # T13: a crash the recovery actions hide
    since = int(h.guest("[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()").strip()) - 5
    h.guest("Stop-Process -Name spoolsv -Force; Start-Sleep 90; (Get-Service Spooler).Status")  # recovery restarts it after 60 s
    r = agent_py(f"rc, st = a.ps(a.sh, \"(Get-Service -Name 'Spooler').Status\")\r\n"
                 f"rc2, cr = a.ps(a.sh, a.PS_CRASHES.replace('%SVC%', 'Spooler').replace('%SINCE%', '{since}'))\r\n"
                 "print(json.dumps({'status': st.strip(), 'crashes': cr.strip()}))", "crash")
    h.note("T13 Spooler killed, restarted by recovery", **r)
    checks["T13 crash seen although Running"] = r["status"] == "Running" and "event 7031" in r["crashes"]

    # T34: a signed-out user's per-user app
    # New-LocalUser: `net user` stops to ask about passwords over 14 characters
    h.guest(r"""$p = 'Nim-off-' + (Get-Random); New-LocalUser nimoff -Password (ConvertTo-SecureString $p -AsPlainText -Force) | Out-Null; Add-LocalGroupMember Users nimoff
        $c = New-Object PSCredential('nimoff', (ConvertTo-SecureString $p -AsPlainText -Force))
        Set-Content C:\nimtest\nimoff.txt $p
        Start-Process cmd.exe -ArgumentList '/c echo %USERPROFILE% > C:\Users\Public\nimoff-profile.txt' -Credential $c -LoadUserProfile -Wait
        Start-Sleep 20
        reg load HKU\nimtest C:\Users\nimoff\NTUSER.DAT | Out-Null
        reg add 'HKU\nimtest\Software\Microsoft\Windows\CurrentVersion\Uninstall\NimTestApp' /v DisplayName /d 'WinSCP 6.1.2' /f | Out-Null
        reg add 'HKU\nimtest\Software\Microsoft\Windows\CurrentVersion\Uninstall\NimTestApp' /v DisplayVersion /d '6.1.2' /f | Out-Null
        reg add 'HKU\nimtest\Software\Microsoft\Windows\CurrentVersion\Uninstall\NimTestApp' /v Publisher /d 'Martin Prikryl' /f | Out-Null
        [gc]::Collect(); reg unload HKU\nimtest | Out-Null""")
    r = agent_py("import winreg\r\napps = [p for p in a.offline_user_apps(winreg) if p['name'] == 'WinSCP 6.1.2']\r\n"
                 "print(json.dumps({'apps': apps}))", "hive")
    left = h.guest(r"@(Get-ChildItem Registry::HKEY_USERS | Where-Object { $_.PSChildName -like 'nimstead*' }).Count", check=False).strip()
    h.guest(r"""$p = Get-Content C:\nimtest\nimoff.txt; $c = New-Object PSCredential('nimoff', (ConvertTo-SecureString $p -AsPlainText -Force))
        Start-Process cmd.exe -ArgumentList '/c echo %USERPROFILE% > C:\Users\Public\nimoff-profile.txt' -Credential $c -LoadUserProfile -Wait""")
    profile = h.guest(r"Get-Content C:\Users\Public\nimoff-profile.txt", check=False).strip()
    h.note("T34 signed-out user's app", apps=r["apps"], temporary_hives_left=left, profile_after=profile)
    checks["T34 offline hive read and unloaded, own profile after"] = (
        len(r["apps"]) == 1 and left == "0" and profile.lower().rstrip() == r"c:\users\nimoff")

    # T35: log4j nested in a fat jar
    h.guest(r"New-Item -ItemType Directory -Force 'C:\nimtest\jars\deep dir' | Out-Null")
    f.copy_in(fat_jar())
    h.guest(r"Move-Item -Force C:\nimtest\app-fat.jar 'C:\nimtest\jars\deep dir\app-fat.jar'")
    pkgs, summary = agent_py("print(json.dumps(a.scan_jars([r'C:\\nimtest\\jars']), default=str))", "jars")
    h.note("T35 jar scan", packages=pkgs, summary=summary)
    checks["T35 log4j-core 2.14.1 found with its path"] = (
        any(p["name"].endswith("log4j-core") and p["version"] == "2.14.1" for p in pkgs) and "app-fat.jar" in json.dumps(summary))

    # T37: planted service ACL weaknesses
    h.guest(r"""New-Item -ItemType Directory -Force 'C:\Nim Test\svc dir', 'C:\NimW' | Out-Null
        icacls 'C:\Nim Test' /grant '*S-1-5-32-545:(OI)(CI)M' | Out-Null; icacls 'C:\NimW' /grant '*S-1-5-32-545:(OI)(CI)F' | Out-Null
        Copy-Item C:\Windows\System32\cmd.exe 'C:\Nim Test\svc dir\app.exe'; Copy-Item C:\Windows\System32\cmd.exe C:\NimW\svc.exe
        sc.exe create NimUnq binPath= "C:\Nim Test\svc dir\app.exe" start= demand | Out-Null
        sc.exe create NimWsvc binPath= "C:\NimW\svc.exe" start= demand | Out-Null""")
    r, problem = agent_py("print(json.dumps(a.windows_host_facts(), default=str))", "facts")
    cfg = r.get("config") or {}
    found = winconfig.evaluate(r, "10.0.26100.1")
    ids = sorted({x.get("vuln_id") or x.get("id") for x in found})
    h.note("T37 service ACL checks", problem=problem, unquoted=cfg.get("unquoted_service_paths"), writable=cfg.get("writable_service_binaries"), findings=ids)
    checks["T37 unquoted path and writable binary reported"] = (
        "NimUnq" in (cfg.get("unquoted_service_paths") or []) and "NimWsvc" in (cfg.get("writable_service_binaries") or []))

    ok = all(checks.values())
    h.note("RESULT: " + ("PASS" if ok else "FAIL"), checks=checks)
    (ROOT / "sandbox" / "last_run_winchecks.json").write_text(json.dumps(h.log, indent=2, default=str))
    if not keep:
        h.winvm.destroy(h.NAME)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(keep="--keep" in sys.argv))
