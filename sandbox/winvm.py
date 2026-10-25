"""Disposable Windows Server 2025 VM (VirtualBox) for testing Windows install + remediation.

  uv run python ../sandbox/winvm.py create  ISO   # unattended Server Core install, headless; prints the VM name
  uv run python ../sandbox/winvm.py destroy NAME  # power off + delete VM and disks (only nimstead-sbx-win-* names)
  uv run python ../sandbox/winvm.py run NAME 'powershell...'   # run as the VM's Administrator via guest control

Never touches VMs whose names don't start with nimstead-sbx-win-. Credentials are generated per VM and kept in
the VM's own folder (it is disposable).
"""

import base64
import json
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path

VBOX = r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
PREFIX = "nimstead-sbx-win-"
STATE = Path(tempfile.gettempdir()) / "nimstead-sbx-win"


def vbox(*args, check=True, timeout=3600) -> str:
    p = subprocess.run([VBOX, *args], capture_output=True, text=True, timeout=timeout)
    if check and p.returncode != 0:
        raise RuntimeError(f"VBoxManage {' '.join(args[:3])} failed: {p.stdout[-800:]} {p.stderr[-800:]}")
    return p.stdout


def creds(name: str) -> dict:
    return json.loads((STATE / name / "creds.json").read_text())


def create(iso: str) -> str:
    name = PREFIX + secrets.token_hex(3)
    folder = STATE / name
    folder.mkdir(parents=True)
    password = "Nim!" + secrets.token_hex(8)
    (folder / "creds.json").write_text(json.dumps({"user": "Administrator", "password": password}))
    vbox("createvm", "--name", name, "--ostype", "Windows2025_64", "--basefolder", str(folder), "--register")
    vbox("modifyvm", name, "--memory", "4096", "--cpus", "2", "--firmware", "efi", "--nic1", "nat", "--graphicscontroller", "vboxsvga")
    disk = folder / f"{name}.vdi"
    vbox("createmedium", "disk", "--filename", str(disk), "--size", "40960")
    vbox("storagectl", name, "--name", "SATA", "--add", "sata", "--controller", "IntelAhci")
    vbox("storageattach", name, "--storagectl", "SATA", "--port", "0", "--device", "0", "--type", "hdd", "--medium", str(disk))
    additions = str(Path(VBOX).parent / "VBoxGuestAdditions.iso")
    args = ["unattended", "install", name, f"--iso={iso}", "--image-index=1", "--user=Administrator",
            f"--admin-password={password}", f"--password={password}", "--full-user-name=Administrator",
            "--locale=en_US", "--country=GB", "--time-zone=UTC", "--hostname=nimstead-sbx.local",
            "--install-additions", "--start-vm=headless"]
    if Path(additions).exists():
        args.append(f"--additions-iso={additions}")
    vbox(*args)
    print(name)
    return name


def run(name: str, command: str, timeout=3600) -> tuple[int, str]:
    assert name.startswith(PREFIX)
    c = creds(name)
    # guest control re-joins argv without quoting, so send the script base64-encoded (UTF-16LE, as PowerShell expects)
    encoded = base64.b64encode(("$ProgressPreference = 'SilentlyContinue'\n" + command).encode("utf-16-le")).decode()
    p = subprocess.run([VBOX, "guestcontrol", name, "run", "--username", c["user"], "--password", c["password"],
                        "--exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "--wait-stdout", "--wait-stderr",
                        "--", "powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                       capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout + p.stderr


def wait_ready(name: str, minutes=60) -> None:
    """Until guest additions answer and PowerShell runs."""
    end = time.time() + minutes * 60
    while time.time() < end:
        try:
            rc, out = run(name, "'ready'", timeout=60)
            if rc == 0 and "ready" in out:
                return
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        time.sleep(20)
    raise RuntimeError(f"{name} not ready after {minutes} min")


def destroy(name: str) -> None:
    assert name.startswith(PREFIX), "refusing to touch a VM that isn't a Nimstead sandbox"
    vbox("controlvm", name, "poweroff", check=False)
    time.sleep(3)
    vbox("unregistervm", name, "--delete", check=False)


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "create":
        create(sys.argv[2])
    elif cmd == "destroy":
        destroy(sys.argv[2])
    elif cmd == "wait":
        wait_ready(sys.argv[2])
        print("ready")
    elif cmd == "run":
        rc, out = run(sys.argv[2], sys.argv[3])
        print(out)
        sys.exit(rc)
