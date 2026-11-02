"""install.ps1 by a GPO startup script (W10), in the lab from sandbox/winlab.py: the machine enrols at boot with nobody signed in.

A GPO linked to an OU holding only the second member carries the startup script. The harness restarts that member and watches only the
server, never touching the VM, until it enrols. The other member, outside the OU, must not enrol, and a second boot must not enrol again.

Note for the owner's docs: this puts an enrolment token where every domain computer and user can read it (SYSVOL).

Run from api/:  uv run python ../sandbox/wingpo.py [--no-reset]   Writes sandbox/last_run_wingpo.json. The lab stays.
"""

import sys
import time

import winlab as lab_  # noqa: E402

h = lab_.h
TASK = "Nimstead agent"
BUILD_GPO = r"""$ErrorActionPreference = 'Stop'
Install-WindowsFeature GPMC | Out-Null
Import-Module GroupPolicy, ActiveDirectory
$d = Get-ADDomain
$ou = New-ADOrganizationalUnit -Name NimGPO -Path $d.DistinguishedName -PassThru
Get-ADComputer %COMPUTER% | Move-ADObject -TargetPath $ou.DistinguishedName
$g = New-GPO -Name NimsteadAgent
New-GPLink -Guid $g.Id -Target $ou.DistinguishedName | Out-Null
Set-GPRegistryValue -Guid $g.Id -Key 'HKLM\Software\Nimstead\Lab' -ValueName gpo -Type DWord -Value 1 | Out-Null  # makes GPT.INI and bumps the version
$root = "C:\Windows\SYSVOL\sysvol\$($d.DNSRoot)\Policies\{$($g.Id)}\Machine\Scripts"
New-Item -ItemType Directory -Force "$root\Startup" | Out-Null
Copy-Item C:\nimtest\nimstead-install.cmd, C:\nimtest\nimstead-install.ps1 "$root\Startup\"
Set-Content "$root\scripts.ini" -Encoding Unicode -Value "[Startup]`r`n0CmdLine=nimstead-install.cmd`r`n0Parameters=`r`n"
# the registry extension (from above) and the scripts extension, ascending by GUID as Windows requires; no cmdlet sets a startup script
Set-ADObject "CN={$($g.Id)},CN=Policies,CN=System,$($d.DistinguishedName)" -Replace @{
  gPCMachineExtensionNames = '[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}][{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}]' }
"""
STARTUP_CMD = r'powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0nimstead-install.ps1" > C:\Windows\Temp\nimstead-gpo.log 2>&1'


def startup_script(server: str, token: str) -> str:
    """Once per machine: it runs at every boot, and an enrolled machine must not enrol again."""
    return (f"if (Get-ScheduledTask -TaskName '{TASK}' -ErrorAction SilentlyContinue) {{ exit 0 }}\r\n"
            f"$env:NIMSTEAD_TOKEN = '{token}'\r\nirm {server}/install.ps1 | iex\r\n")


def nobody_signed_in(quser: str) -> bool:
    return "no user exists" in quser.lower()


def write_guest(path: str, text: str) -> None:
    h.guest(f"Set-Content -Path {path} -Encoding ascii -Value @'\r\n{text}\r\n'@")


def cold_cycle(v: dict) -> None:
    """Off and on with no guest command after the shutdown: nothing here signs in or starts a session."""
    lab_.stop(v)
    lab_.winvm.vbox("startvm", v["vm"], "--type", "headless")


def main() -> int:
    lab = lab_.reset() if "--no-reset" not in sys.argv else lab_.load()
    dc, (other, m, *_) = lab_.by_role(lab)
    api = lab_.Api(msrc=False)

    lab_.on(dc)
    write_guest(r"C:\nimtest\nimstead-install.cmd", STARTUP_CMD)
    write_guest(r"C:\nimtest\nimstead-install.ps1", startup_script(lab_.SERVER, api.token))
    h.guest(BUILD_GPO.replace("%COMPUTER%", m["computer"]), timeout=900)
    h.note("GPO built and linked", ou="NimGPO", computer=m["computer"])

    lab_.on(m)
    h.guest(r"Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' AutoAdminLogon '0'")  # the unattended install's autologon would be someone
    assert lab_.asset_named(api, m["computer"]) is None
    started = time.time()
    cold_cycle(m)
    end, a = time.time() + 40 * 60, None
    while time.time() < end and not (a := lab_.asset_named(api, m["computer"])):
        lab_.winvm.unstick(m["vm"])
        time.sleep(20)
    h.note("enrolled by itself", computer=m["computer"], minutes_after_boot=round((time.time() - started) / 60, 1), asset=a and a["hostname"])
    assert a, f"{m['computer']} didn't enrol in 40 minutes of booting: nothing was run on it, so read C:\\Windows\\Temp\\nimstead-gpo.log there"

    lab_.winvm.wait_ready(m["vm"], minutes=30)
    quser = h.guest("quser 2>&1 | Out-String", check=False)
    principal = h.guest(f"(Get-ScheduledTask -TaskName '{TASK}').Principal.UserId", check=False).strip()
    log = h.guest(r"Get-Content C:\Windows\Temp\nimstead-gpo.log -Raw -ErrorAction SilentlyContinue", check=False)
    h.note("on the member after enrolling", quser=quser.strip()[-200:], task_runs_as=principal, startup_log=log[-400:])
    checks = {"enrolled with nobody signed in": nobody_signed_in(quser), "agent's task runs as SYSTEM": principal == "SYSTEM",
              "the machine outside the OU didn't enrol": lab_.asset_named(api, other["computer"]) is None}

    # the script runs at every boot
    cold_cycle(m)
    lab_.winvm.wait_ready(m["vm"], minutes=30)
    time.sleep(120)
    hosts = [x["hostname"] for x in api.get("/api/assets").json()]
    again = lab_.asset_named(api, m["computer"])
    h.note("after a second boot", hosts=hosts)
    checks["a second boot doesn't enrol again"] = len(hosts) == 1 and again["id"] == a["id"]
    return lab_.conclude(checks)


if __name__ == "__main__":
    sys.exit(lab_.harness(main, "last_run_wingpo.json"))
