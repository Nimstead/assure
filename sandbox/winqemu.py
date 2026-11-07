"""Disposable Windows Server VM on QEMU with Windows' own hypervisor (WHPX), for the OS builds VirtualBox can't boot on
this host (W5: Server 2019 never got past its first boot under VirtualBox's Hyper-V fallback engine, DECISIONS 116).

  uv run python ../sandbox/winqemu.py create ISO [--memory=MB] [--image=N]   # prints the VM name
  uv run python ../sandbox/winqemu.py destroy NAME

A VM made here is driven through winvm.run / wait_ready / unstick / destroy like a VirtualBox one (winvm hands it over),
so wine2e.py runs unchanged. There are no guest additions: a PowerShell runner, installed by setup and started at boot as
the VM's Administrator, polls a relay on the host for commands and posts each one's output back. The VM reaches the host
as 10.0.2.2, as under VirtualBox's NAT. QEMU's Windows build: QEMU_DIR (default Downloads\\qemu-dl\\qemu).
"""

import base64
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path
from xml.sax.saxutils import escape

sys.path.insert(0, str(Path(__file__).parent))
from winvm import PREFIX, STATE  # noqa: E402

QEMU_DIR = Path(os.environ.get("QEMU_DIR", Path(os.environ.get("USERPROFILE", "")) / "Downloads" / "qemu-dl" / "qemu"))
CPU = os.environ.get("QEMU_CPU", "Westmere")  # has what Server 2019+ needs (NX, CX16, LAHF, POPCNT), no xsave
ACCEL = os.environ.get("QEMU_ACCEL", "whpx")  # kernel-irqchip=off froze setup at "Starting services" with both vCPUs spinning
DETACHED = 0x00000008 | 0x00000200  # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP: outlives the harness run that made it

RUNNER = r"""$ErrorActionPreference = 'Continue'
$base = 'http://10.0.2.2:PORT'
while ($true) {
  try {
    $job = Invoke-RestMethod -Uri "$base/next" -TimeoutSec 30 -UseBasicParsing
    if ($job.id) {
      $out = & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $job.cmd 2>&1 | Out-String -Width 4096
      $body = @{ rc = $LASTEXITCODE; out = $out } | ConvertTo-Json -Compress
      Invoke-RestMethod -Uri "$base/result/$($job.id)" -Method Post -Body ([Text.Encoding]::UTF8.GetBytes($body)) -ContentType 'application/json' -UseBasicParsing | Out-Null
      continue
    }
  } catch { }
  Start-Sleep -Seconds 2
}
"""


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def unattend(password: str, image: int, computer: str) -> str:
    """Server setup with no questions: one BIOS partition, the chosen image, UTC, Administrator's password, autologon (as
    VirtualBox's unattended install leaves it, so wine2e's signed-in assumptions hold), then the runner as a startup task."""
    pw = escape(password)
    task = ("powershell -NoProfile -ExecutionPolicy Bypass -Command \"New-Item -ItemType Directory -Force C:\\nimtest | Out-Null; "
            "Copy-Item A:\\runner.ps1 C:\\nimtest\\runner.ps1 -Force; "
            "$a = New-ScheduledTaskAction -Execute powershell.exe -Argument '-NoProfile -ExecutionPolicy Bypass -File C:\\nimtest\\runner.ps1'; "
            "$t = New-ScheduledTaskTrigger -AtStartup; "
            "$s = New-ScheduledTaskSettingsSet -ExecutionTimeLimit 0 -AllowStartIfOnBatteries -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1); "
            f"Register-ScheduledTask -TaskName NimRunner -Action $a -Trigger $t -Settings $s -User Administrator -Password '{password.replace(chr(39), chr(39) * 2)}' -RunLevel Highest -Force; "
            "Start-ScheduledTask -TaskName NimRunner\"")
    return f"""<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
 <settings pass="windowsPE">
  <component name="Microsoft-Windows-International-Core-WinPE" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
   <SetupUILanguage><UILanguage>en-US</UILanguage></SetupUILanguage><InputLocale>en-US</InputLocale><SystemLocale>en-US</SystemLocale><UILanguage>en-US</UILanguage><UserLocale>en-US</UserLocale>
  </component>
  <component name="Microsoft-Windows-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
   <DiskConfiguration><Disk wcm:action="add"><DiskID>0</DiskID><WillWipeDisk>true</WillWipeDisk>
    <CreatePartitions><CreatePartition wcm:action="add"><Order>1</Order><Type>Primary</Type><Extend>true</Extend></CreatePartition></CreatePartitions>
    <ModifyPartitions><ModifyPartition wcm:action="add"><Order>1</Order><PartitionID>1</PartitionID><Format>NTFS</Format><Label>System</Label><Active>true</Active></ModifyPartition></ModifyPartitions>
   </Disk></DiskConfiguration>
   <ImageInstall><OSImage><InstallFrom><MetaData wcm:action="add"><Key>/IMAGE/INDEX</Key><Value>{image}</Value></MetaData></InstallFrom>
    <InstallTo><DiskID>0</DiskID><PartitionID>1</PartitionID></InstallTo></OSImage></ImageInstall>
   <UserData><AcceptEula>true</AcceptEula></UserData>
  </component>
 </settings>
 <settings pass="specialize">
  <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
   <ComputerName>{escape(computer)}</ComputerName><TimeZone>UTC</TimeZone>
  </component>
 </settings>
 <settings pass="oobeSystem">
  <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
   <UserAccounts><AdministratorPassword><Value>{pw}</Value><PlainText>true</PlainText></AdministratorPassword></UserAccounts>
   <AutoLogon><Enabled>true</Enabled><Username>Administrator</Username><Password><Value>{pw}</Value><PlainText>true</PlainText></Password><LogonCount>9999</LogonCount></AutoLogon>
   <OOBE><HideEULAPage>true</HideEULAPage><ProtectYourPC>3</ProtectYourPC><SkipMachineOOBE>true</SkipMachineOOBE><SkipUserOOBE>true</SkipUserOOBE></OOBE>
   <FirstLogonCommands><SynchronousCommand wcm:action="add"><Order>1</Order><CommandLine>{escape(task)}</CommandLine></SynchronousCommand></FirstLogonCommands>
  </component>
 </settings>
</unattend>
"""


def conf(name: str) -> dict:
    return json.loads((STATE / name / "qemu.json").read_text())


def is_qemu(name: str) -> bool:
    return (STATE / name / "qemu.json").exists()


def _alive(pid: int) -> bool:
    out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/NH"], capture_output=True, text=True).stdout
    return str(pid) in out


def start(name: str) -> None:
    """Start (or restart) the VM's QEMU process and its relay if either isn't running."""
    c, folder = conf(name), STATE / name
    if not c.get("relay_pid") or not _alive(c["relay_pid"]):
        c["relay_pid"] = subprocess.Popen([sys.executable, "-I", str(Path(__file__).parent / "qemurelay.py"), str(folder / "q"),
                                           str(c["relay_port"])], creationflags=DETACHED, close_fds=True).pid
    if not c.get("pid") or not _alive(c["pid"]):
        # -cpu max crashed the vCPU at setup's first restart ("failed to get xsave state", "WHPX: Unexpected VP exit code 4");
        # a plain model without xsave/AVX avoids what WHPX won't hand back
        args = [str(QEMU_DIR / "qemu-system-x86_64.exe"), "-accel", ACCEL, "-machine", "pc", "-cpu", CPU, "-smp", "2",
                "-m", str(c["memory"]), "-drive", f"file={folder / 'disk.qcow2'},if=ide,index=0",
                "-drive", f"file={c['iso']},media=cdrom,index=2", "-drive", f"file=fat:floppy:{folder / 'floppy'},if=floppy,format=raw,readonly=on",
                "-nic", "user,model=e1000", "-display", "none", "-qmp", f"tcp:127.0.0.1:{c['qmp_port']},server,nowait",
                "-boot", "order=cd,once=d" if not c.get("installed") else "order=c"]
        c["pid"] = subprocess.Popen(args, creationflags=DETACHED, close_fds=True, stdout=open(folder / "qemu.log", "ab"),
                                    stderr=subprocess.STDOUT).pid
    (folder / "qemu.json").write_text(json.dumps(c))


def create(iso: str, memory: int = 4096, image: int = 1, computer: str = "nimstead-sbx") -> str:
    name = PREFIX + secrets.token_hex(3)
    folder = STATE / name
    (folder / "floppy").mkdir(parents=True)
    (folder / "q").mkdir()
    password = "Nim!" + secrets.token_hex(8)
    (folder / "creds.json").write_text(json.dumps({"user": "Administrator", "password": password}))
    c = {"iso": str(Path(iso).resolve()), "memory": memory, "qmp_port": free_port(), "relay_port": free_port()}
    (folder / "floppy" / "autounattend.xml").write_text(unattend(password, image, computer), encoding="utf-8")
    (folder / "floppy" / "runner.ps1").write_text(RUNNER.replace("PORT", str(c["relay_port"])), encoding="utf-8")
    subprocess.run([str(QEMU_DIR / "qemu-img.exe"), "create", "-f", "qcow2", str(folder / "disk.qcow2"), "80G"], check=True,
                   capture_output=True)
    (folder / "qemu.json").write_text(json.dumps(c))
    start(name)
    print(name)
    return name


def run(name: str, command: str, timeout=3600) -> tuple[int, str]:
    """Queue one PowerShell script for the guest's runner and wait for its result (subprocess.TimeoutExpired if none)."""
    q = STATE / name / "q"
    jid = uuid.uuid4().hex
    encoded = base64.b64encode(("$ProgressPreference = 'SilentlyContinue'\n" + command).encode("utf-16-le")).decode()
    (q / f"{jid}.tmp").write_text(json.dumps({"id": jid, "cmd": encoded}))
    os.replace(q / f"{jid}.tmp", q / f"{jid}.cmd")  # the relay never hands out a half-written job
    end = time.time() + timeout
    while time.time() < end:
        out = q / f"{jid}.out"
        if out.exists():
            r = json.loads(out.read_text(encoding="utf-8"))
            out.unlink()
            return int(r.get("rc") or 0), r.get("out") or ""
        time.sleep(1)
    for p in (q / f"{jid}.cmd", q / f"{jid}.taken"):  # a job nobody picked up must not run later, out of order
        p.unlink(missing_ok=True)
    raise subprocess.TimeoutExpired(command[:80], timeout)


def qmp(name: str, command: str, **arguments) -> dict:
    with socket.create_connection(("127.0.0.1", conf(name)["qmp_port"]), timeout=10) as s:
        f = s.makefile("rw")
        f.readline()
        f.write(json.dumps({"execute": "qmp_capabilities"}) + "\n")
        f.flush()
        f.readline()
        f.write(json.dumps({"execute": command, **({"arguments": arguments} if arguments else {})}) + "\n")
        f.flush()
        return json.loads(f.readline())


def wait_ready(name: str, minutes=90, reset_after=25) -> None:
    """Until the runner answers. Setup reboots on its own; a VM silent for `reset_after` minutes after setup gets one reset."""
    end, last_reset = time.time() + minutes * 60, time.time()
    while time.time() < end:
        start(name)  # a guest shutdown ends the QEMU process: boot it again, as a power button would
        try:
            rc, out = run(name, "'ready'", timeout=60)
            if rc == 0 and "ready" in out:
                c = conf(name)
                if not c.get("installed"):  # from here on boot the disk, never setup again
                    c["installed"] = True
                    (STATE / name / "qemu.json").write_text(json.dumps(c))
                return
        except subprocess.TimeoutExpired:
            pass
        if conf(name).get("installed") and time.time() - last_reset > reset_after * 60:
            try:
                qmp(name, "system_reset")
            except OSError:
                pass
            last_reset = time.time()
    raise RuntimeError(f"{name} not ready after {minutes} min")


def unstick(name: str) -> bool:
    """A Windows restart ends with QEMU still running; only a shutdown ends the process. Restart it if so."""
    c = conf(name)
    if c.get("pid") and not _alive(c["pid"]):
        start(name)
        return True
    return False


def destroy(name: str) -> None:
    assert name.startswith(PREFIX), "refusing to touch a VM that isn't a Nimstead sandbox"
    c = conf(name)
    for pid in (c.get("pid"), c.get("relay_pid")):
        if pid:
            subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True)
    time.sleep(2)
    shutil.rmtree(STATE / name, ignore_errors=True)


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "create":
        opts = dict(a[2:].split("=", 1) for a in sys.argv[3:] if "=" in a)
        create(sys.argv[2], memory=int(opts.get("memory", 4096)), image=int(opts.get("image", 1)))
    elif cmd == "destroy":
        destroy(sys.argv[2])
