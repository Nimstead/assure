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
# "Specify startup policy processing wait time": the member's network took past the default 30 s at boot, so policy ran
# without SYSVOL ("downloaded policies with error") and the startup script never started (real lab, 2026-11-05)
Set-GPRegistryValue -Guid $g.Id -Key 'HKLM\Software\Policies\Microsoft\Windows\System' -ValueName GpNetworkStartTimeoutPolicyValue -Type DWord -Value 120 | Out-Null
# A Group Policy Preferences scheduled task, not a startup script: a startup script runs during early boot, before this host's
# member could reach its DC (NETLOGON failed ~20 s in, four runs, 2026-11-05), so it never started. The member receives the task with
# its policy; at boot it runs as SYSTEM 2 minutes in, once the network is up, with nobody signed in. Action "U" (update), not "R":
# replace deletes and recreates the task at every policy pass, boot included, and a task recreated after boot missed its trigger.
$gpo = "C:\Windows\SYSVOL\sysvol\$($d.DNSRoot)\Policies\{$($g.Id)}\Machine"
New-Item -ItemType Directory -Force "$gpo\Nimstead", "$gpo\Preferences\ScheduledTasks" | Out-Null
Copy-Item C:\nimtest\nimstead-install.ps1 "$gpo\Nimstead\"
$script = "\\$($d.DNSRoot)\SysVol\$($d.DNSRoot)\Policies\{$($g.Id)}\Machine\Nimstead\nimstead-install.ps1"
$uid = "{$([guid]::NewGuid().ToString().ToUpper())}"; $now = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
Set-Content "$gpo\Preferences\ScheduledTasks\ScheduledTasks.xml" -Encoding UTF8 -Value @"
<?xml version="1.0" encoding="utf-8"?>
<ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}"><TaskV2 clsid="{D8896631-B747-47a7-84A6-C155337F3BC8}" name="Nimstead install" image="0" changed="$now" uid="$uid"><Properties action="U" name="Nimstead install" runAs="NT AUTHORITY\System" logonType="S4U"><Task version="1.2"><RegistrationInfo><Author>Nimstead</Author><Description>Installs the Nimstead agent once</Description></RegistrationInfo><Principals><Principal id="Author"><UserId>NT AUTHORITY\System</UserId><LogonType>S4U</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Settings><IdleSettings><Duration>PT10M</Duration><WaitTimeout>PT1H</WaitTimeout><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden><ExecutionTimeLimit>PT1H</ExecutionTimeLimit><Priority>7</Priority></Settings><Triggers><BootTrigger><Enabled>true</Enabled><Delay>PT2M</Delay></BootTrigger></Triggers><Actions Context="Author"><Exec><Command>cmd.exe</Command><Arguments>/c powershell -NoProfile -ExecutionPolicy Bypass -File "$script" &gt;&gt; C:\Windows\Temp\nimstead-gpo.log 2&gt;&amp;1</Arguments></Exec></Actions></Task></Properties></TaskV2></ScheduledTasks>
"@
# the registry extension (from above) and the Preferences scheduled-tasks one, with its tool, ascending by GUID as Windows requires
Set-ADObject "CN={$($g.Id)},CN=Policies,CN=System,$($d.DistinguishedName)" -Replace @{
  gPCMachineExtensionNames = '[{00000000-0000-0000-0000-000000000000}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}][{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}][{AADCED64-746C-4633-A97C-D61349046527}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}]' }
"""


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
    write_guest(r"C:\nimtest\nimstead-install.ps1", startup_script(lab_.SERVER, api.token))
    h.guest(BUILD_GPO.replace("%COMPUTER%", m["computer"]), timeout=900)
    h.note("GPO built and linked", ou="NimGPO", computer=m["computer"])

    lab_.on(m)
    h.guest(r"Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' AutoAdminLogon '0'")  # the unattended install's autologon would be someone
    # a DC just back from its snapshot can't serve SYSVOL yet: the member's boot then "downloaded policies with error" and skipped
    # the GPO (real lab). Wait until the member reads it, as an admin would before restarting machines for it
    end = time.time() + 15 * 60
    while "Nimstead install" not in h.guest("gpupdate /target:computer /force | Out-Null; Get-ScheduledTask -TaskName 'Nimstead install' -ErrorAction SilentlyContinue | ForEach-Object TaskName", timeout=600, check=False):
        assert time.time() < end, f"{m['computer']} still doesn't apply the GPO after 15 minutes"
        time.sleep(30)
    h.note("member applies the GPO", computer=m["computer"])
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
    # install.ps1 enrols first and registers the agent's task after: give it time before reading
    principal = h.guest(f"$e = (Get-Date).AddMinutes(5); while (-not (Get-ScheduledTask -TaskName '{TASK}' -ErrorAction SilentlyContinue) -and (Get-Date) -lt $e) {{ Start-Sleep 10 }}; "
                        f"(Get-ScheduledTask -TaskName '{TASK}').Principal.UserId", check=False, timeout=420).strip()
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
