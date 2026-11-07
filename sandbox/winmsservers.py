"""SharePoint and Exchange collectors on real installs (W11), in the lab from sandbox/winlab.py.

One product per run, on its own member, from Microsoft's own trial media (the owner's go-ahead, 2026-11-06):
  sharepoint  SharePoint Server Subscription Edition, binaries only (prerequisites, then setup with the published trial key, no
              farm): the collector reads Microsoft.SharePoint.dll, which setup lays down without a farm or SQL Server
  exchange    Exchange Server Subscription Edition, the management tools role after /PrepareAD: it installs Bin\\ExSetup.exe and
              the v15\\Setup key the collector reads. A mailbox server isn't tried: it wants more memory than a lab member has
The agent's collector reading is set beside the host's own (the Uninstall entry, and for Exchange the build in its setup key),
and beside the key the server would match MSRC advisories on.

Run from api/:  uv run python ../sandbox/winmsservers.py sharepoint|exchange ISO [--no-reset]
Writes sandbox/last_run_win<product>.json. The lab stays; a later `winlab.py reset` undoes it all, the DC's /PrepareAD included.
"""

import sys
import time

import winfixes as f
import winlab as lab_  # noqa: E402
import winproducts as wp

from nimstead import msproducts  # noqa: E402

h = lab_.h
PRODUCT = next((a for a in sys.argv[1:] if a in ("sharepoint", "exchange")), "")
ISO = next((a for a in sys.argv[1:] if a.lower().endswith(".iso")), "")
MEMORY = 6144
# Published on the Download Center page beside the ISO (details.aspx?id=103599): installs a 180-day trial, not a secret
SP_TRIAL_KEY = "KGN4V-82BMC-H383V-QJVFT-VCHJ7"
MEDIA = r"$m = (Get-PSDrive -PSProvider FileSystem | Where-Object { Test-Path (Join-Path $_.Root '%FILE%') } | Select-Object -First 1).Root"
SIGNED = MEDIA + r"; $s = Get-AuthenticodeSignature (Join-Path $m '%FILE%'); '{0}|{1}' -f $s.Status, $s.SignerCertificate.Subject"
UNINSTALL = r"""Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' | Where-Object { $_.DisplayName -like '%NAME%' } |
  ForEach-Object { '{0}|{1}' -f $_.DisplayName, $_.DisplayVersion }"""
SP_CONFIG = f"""<Configuration>
<Package Id="sts"><Setting Id="LAUNCHEDFROMSETUPSTS" Value="Yes"/></Package>
<Package Id="spswfe"><Setting Id="SETUPCALLED" Value="1"/></Package>
<Logging Type="verbose" Path="C:\\nimtest\\splogs" Template="SharePoint Server Setup(*).log"/>
<PIDKEY Value="{SP_TRIAL_KEY}"/>
<Display Level="none" CompletionNotice="no" AcceptEula="yes"/>
<Setting Id="SERVERROLE" Value="APPLICATION"/>
<Setting Id="USINGUIINSTALLMODE" Value="0"/>
<Setting Id="SETUP_REBOOT" Value="Never"/>
<Setting Id="SETUPTYPE" Value="CLEAN_INSTALL"/>
</Configuration>"""
EX_SETUP = MEDIA.replace("%FILE%", "Setup.exe") + r"; & (Join-Path $m 'Setup.exe') /IAcceptExchangeServerLicenseTerms_DiagnosticDataOFF %ARGS% 2>&1 | Select-Object -Last 25 | Out-String; 'EXIT ' + $LASTEXITCODE"
# Management tools on Windows Server: .NET 4.8 (Server 2025 has 4.8.1), the VC++ 2012 and 2013 runtimes, AD tools for /PrepareAD,
# and IIS 6 metabase compatibility (setup's prerequisite check refused the tools without it, real lab 2026-11-06)
EX_PREREQS = r"""$ErrorActionPreference = 'Stop'
Install-WindowsFeature RSAT-ADDS, Web-Mgmt-Console, Web-Metabase | Out-Null
foreach ($u in 'https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x64.exe',
               'https://aka.ms/highdpimfc2013x64enu') {
  Invoke-WebRequest $u -OutFile C:\nimtest\vcredist.exe -UseBasicParsing
  $s = Get-AuthenticodeSignature C:\nimtest\vcredist.exe
  if ($s.Status -ne 'Valid' -or $s.SignerCertificate.Subject -notlike '*Microsoft Corporation*') { throw "unsigned runtime from $u" }
  Start-Process C:\nimtest\vcredist.exe '/install /quiet /norestart' -Wait
}
'prereqs ok'"""


def media(v: dict, iso: str) -> None:
    """The member off, more memory, the ISO in its DVD drive (where the unattended install's disc was), and on again."""
    lab_.stop(v)
    lab_.winvm.vbox("modifyvm", v["vm"], "--memory", str(MEMORY))
    lab_.winvm.vbox("storageattach", v["vm"], "--storagectl", "SATA", "--port", "1", "--device", "0", "--type", "dvddrive", "--medium", iso)
    lab_.start(v)
    lab_.on(v)
    file = "prerequisiteinstaller.exe" if PRODUCT == "sharepoint" else "Setup.exe"
    signed = h.guest(SIGNED.replace("%FILE%", file)).strip()
    h.note("media in", computer=v["computer"], iso=iso, setup_signature=signed)
    assert signed.startswith("Valid|") and "Microsoft Corporation" in signed, signed


def sharepoint() -> None:
    for attempt in range(6):  # the prerequisite installer asks for a restart between parts: 3010 or 1001, run again after
        rc = h.guest(MEDIA.replace("%FILE%", "prerequisiteinstaller.exe")
                     + r"; (Start-Process (Join-Path $m 'prerequisiteinstaller.exe') '/unattended' -Wait -PassThru).ExitCode", timeout=5400).strip()
        h.note("prerequisites", attempt=attempt + 1, exit_code=rc)
        if rc == "0":
            break
        assert rc in ("3010", "1001"), f"prerequisite installer exit {rc}: read C:\\Users\\Administrator\\AppData\\Local\\Temp\\PrerequisiteInstaller.*.log"
        h.reboot_and_wait()
    else:
        raise AssertionError("prerequisites still asking for restarts after 6 runs")
    h.guest(f"New-Item -ItemType Directory -Force C:\\nimtest\\splogs | Out-Null; Set-Content C:\\nimtest\\spconfig.xml -Encoding ascii -Value @'\r\n{SP_CONFIG}\r\n'@")
    rc = h.guest(MEDIA.replace("%FILE%", "setup.exe") + r"; (Start-Process (Join-Path $m 'setup.exe') '/config C:\nimtest\spconfig.xml /IAcceptTheLicenseTerms' -Wait -PassThru).ExitCode",
                 timeout=7200).strip()
    tail = h.guest(r"Get-ChildItem C:\nimtest\splogs\*.log | Sort-Object LastWriteTime | Select-Object -Last 1 | Get-Content -Tail 8 | Out-String", check=False)
    h.note("SharePoint setup", exit_code=rc, log_tail=tail[-1200:])
    assert rc in ("0", "3010"), f"SharePoint setup exit {rc}"


def as_domain_admin(lab: dict, script: str, minutes=150) -> str:
    """script as the domain's Administrator, by a scheduled task: guest control never started a domain-account session on this
    member (it sat at "starting" with the disk idle, twice, 2026-11-06), and its local Administrator can't act on AD"""
    out = r"C:\nimtest\ex.out"
    h.guest(f"Remove-Item {out} -ErrorAction SilentlyContinue; Set-Content C:\\nimtest\\ex.ps1 -Encoding ascii -Value @'\r\n& {{ {script} }} *> {out}\r\n'@")
    h.guest(r"$a = New-ScheduledTaskAction -Execute powershell.exe -Argument '-NoProfile -ExecutionPolicy Bypass -File C:\nimtest\ex.ps1'; "
            f"Register-ScheduledTask -TaskName NimEx -Action $a -User '{lab_.NETBIOS}\\Administrator' -Password '{lab_.domain_admin(lab)['password']}' "
            "-RunLevel Highest -Force | Out-Null; Start-ScheduledTask NimEx")
    end = time.time() + minutes * 60
    while time.time() < end:
        time.sleep(60)
        text = h.guest(f"Get-Content {out} -Raw -ErrorAction SilentlyContinue", timeout=300, check=False)
        if "EXIT " in text:
            return text
        lab_.winvm.unstick(h.NAME)
    raise AssertionError(f"no result from the task after {minutes} min")


def exchange(lab: dict, v: dict) -> None:
    h.note("Exchange prerequisites", out=h.guest(EX_PREREQS, timeout=1800).strip()[-300:])
    # schema and AD preparation need Schema and Enterprise Admins; the tools read the organisation
    for step, args in (("PrepareAD", "/PrepareAD /OrganizationName:NimLab"), ("management tools", "/Role:ManagementTools")):
        out = as_domain_admin(lab, EX_SETUP.replace("%ARGS%", args))
        h.note(f"Exchange setup {step}", out=out[-1500:])
        assert "EXIT 0" in out, f"Exchange setup {step} failed: read C:\\ExchangeSetupLogs\\ExchangeSetup.log on {v['computer']}"


def host_reading() -> dict:
    """Not through the agent: what Windows' own records say is installed."""
    if PRODUCT == "sharepoint":
        return {"uninstall": h.guest(UNINSTALL.replace("%NAME%", "Microsoft SharePoint Server*"), check=False).strip()}
    return {"uninstall": h.guest(UNINSTALL.replace("%NAME%", "Microsoft Exchange Server*"), check=False).strip(),
            "setup_key": h.guest(r"$k = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup'; "
                                 r"'{0}.{1}.{2}.{3}' -f $k.MsiProductMajor, $k.MsiProductMinor, $k.MsiBuildMajor, $k.MsiBuildMinor", check=False).strip()}


def main() -> int:
    assert PRODUCT and ISO, "usage: winmsservers.py sharepoint|exchange ISO [--no-reset]"
    lab = lab_.reset() if "--no-reset" not in sys.argv else lab_.load()
    _, (m1, m2, *_) = lab_.by_role(lab)
    v = m1 if PRODUCT == "sharepoint" else m2
    media(v, ISO)
    sharepoint() if PRODUCT == "sharepoint" else exchange(lab, v)

    h.guest(r"New-Item -ItemType Directory -Force C:\nimtest | Out-Null")
    f.runtime()
    f.copy_in(f.ROOT / "agent" / "nimstead_agent.py")
    inv = wp.collect()
    name = "SharePoint Server" if PRODUCT == "sharepoint" else "Exchange Server"
    collected = wp.found(inv, name)
    host = host_reading()
    target = msproducts.targets(name, collected[0], inv.get("os_name")) if collected else None
    h.note("collector beside the host", collected=collected, host=host, server_key=target)
    host_versions = {line.split("|")[-1] for line in host["uninstall"].splitlines() if "|" in line} | ({host["setup_key"]} if "setup_key" in host else set())
    checks = {f"the agent reports {name}": len(collected) == 1,
              "its version is the host's own": bool(collected) and collected[0] in host_versions,
              "the server has a key to match advisories on": bool(target and target[0])}
    h.note("CHECK BY HAND: Exchange's Uninstall entry may carry the RTM's display version; the setup key is the installed build")
    return lab_.conclude(checks)


if __name__ == "__main__":
    sys.exit(lab_.harness(main, f"last_run_win{PRODUCT or 'msservers'}.json"))
