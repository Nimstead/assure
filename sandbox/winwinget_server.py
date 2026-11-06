"""W23 spike: can Microsoft-signed winget be installed on Windows Server by a hash-pinned, signature-checked path? In a DISPOSABLE
VM (sandbox/winvm.py). Server ships no App Installer, so the agent's winget fixes refuse there with "winget unavailable".

In the guest: download winget-cli's release files (pinned below with the SHA-256 GitHub publishes for each), refuse on any other
hash, refuse unless every package carries a valid Authenticode signature from Microsoft Corporation, then provision them for all
users. Then the agent's own lookup (PS_WINGET, admin-owned WindowsApps only) must find winget.exe, and it must run as SYSTEM.
Nothing here changes the agent: whether it should install winget itself is the decision this run informs.

Run from api/:  uv run python ../sandbox/winwinget_server.py VM_NAME [--keep]   Writes sandbox/last_run_winget_server.json.
Then `winfixes.py VM_NAME` on the same VM is W23's second half (7-Zip old to new as SYSTEM).
"""

import importlib.util
import json
import sys

import wine2e as h  # noqa: E402  (reads VM_NAME from argv)

OUT = h.ROOT / "sandbox" / "last_run_winget_server.json"
TAG = "v1.29.380"  # winget-cli's latest stable on 2026-11-04, the version the Windows 11 VMs run
BASE = f"https://github.com/microsoft/winget-cli/releases/download/{TAG}/"
FILES = {  # name -> SHA-256, from the GitHub release's own digests
    "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle": "65dea9c01ce08ee7b763366b27c0e651f97db857c11ca9b9c301826c10092f2e",
    "DesktopAppInstaller_Dependencies.zip": "ba875afe9d190f61218985ac0292a99d1db710bf93e13c68944ca9d89f0d82d1",
    "e53e159d00e04f729cc2180cffd1c02e_License1.xml": "bcb15118ec47df24e3e6013a7006147c3a15b3a8104ed660fe87c8b4ed01f485",
}
DIR = r"C:\nimwinget"


def main(keep=False) -> int:
    h.winvm.wait_ready(h.NAME, minutes=90)
    os_name = h.guest(r"(gp 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').ProductName + ' ' + (gp 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild").strip()
    h.note("VM ready", os=os_name)
    spec = importlib.util.spec_from_file_location("nimstead_agent", h.ROOT / "agent" / "nimstead_agent.py")
    agent = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(agent)
    h.guest(r"New-Item -ItemType Directory -Force C:\nimtest | Out-Null")
    before = h.guest(agent.PS_WINGET, check=False).strip()
    checks = {"no winget before": not before}
    downloads = "; ".join(f"Invoke-WebRequest -UseBasicParsing '{BASE}{n}' -OutFile '{DIR}\\{n}'" for n in FILES)
    h.guest(f"[Net.ServicePointManager]::SecurityProtocol = 'Tls12'; $ProgressPreference = 'SilentlyContinue'; "
            f"New-Item -ItemType Directory -Force '{DIR}' | Out-Null; {downloads}", timeout=3600)
    got = {n: h.guest(f"(Get-FileHash '{DIR}\\{n}' -Algorithm SHA256).Hash", check=False).strip().lower() for n in FILES}
    checks["every file matches its pinned SHA-256"] = got == FILES
    h.note("downloads", hashes_match=checks["every file matches its pinned SHA-256"])
    if not checks["every file matches its pinned SHA-256"]:
        return finish(checks, keep)
    arch = h.guest(f"""Expand-Archive -Force '{DIR}\\DesktopAppInstaller_Dependencies.zip' '{DIR}\\deps'
        $d = @(Get-ChildItem '{DIR}\\deps' -Recurse -Include *.appx,*.msix | Where-Object {{ $_.FullName -match '\\\\x64\\\\' }})
        $d | ForEach-Object {{ $_.FullName }}""").strip().splitlines()
    sigs = h.guest(f"""@(Get-Item '{DIR}\\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle'; Get-ChildItem '{DIR}\\deps' -Recurse -Include *.appx,*.msix |
        Where-Object {{ $_.FullName -match '\\\\x64\\\\' }}) | ForEach-Object {{ $s = Get-AuthenticodeSignature $_.FullName
        '{{0}}|{{1}}|{{2}}' -f $_.Name, $s.Status, $s.SignerCertificate.Subject }}""").strip().splitlines()
    signed = [line.split("|") for line in sigs]
    checks["dependencies found for x64"] = bool(arch)
    checks["every package Authenticode-valid and signed by Microsoft Corporation"] = bool(signed) and all(
        s[1] == "Valid" and "O=Microsoft Corporation" in s[2] for s in signed)
    h.note("signatures", packages=[(s[0], s[1], s[2][:80]) for s in signed])
    if not checks["every package Authenticode-valid and signed by Microsoft Corporation"]:
        return finish(checks, keep)
    out = h.guest(f"""$deps = @(Get-ChildItem '{DIR}\\deps' -Recurse -Include *.appx,*.msix | Where-Object {{ $_.FullName -match '\\\\x64\\\\' }} | ForEach-Object FullName)
        Add-AppxProvisionedPackage -Online -PackagePath '{DIR}\\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle' -DependencyPackagePath $deps `
          -LicensePath '{DIR}\\e53e159d00e04f729cc2180cffd1c02e_License1.xml' -ErrorAction Stop | Out-String""", timeout=1800, check=False)
    h.note("provisioned", output=out[-600:])
    exe = h.guest(agent.PS_WINGET, check=False).strip()
    checks["the agent's own lookup finds winget.exe"] = bool(exe)
    if exe:
        h.as_system(rf'"{exe}" --version > C:\nimtest\wgv.txt 2>&1', wait_minutes=10)
        res = h.guest(r"Get-Content C:\nimtest\wgv.txt -Raw", check=False)
        h.note("winget as SYSTEM", exe=exe, output=str(res)[-300:])
        checks["winget runs as SYSTEM"] = TAG in str(res)
    return finish(checks, keep)


def finish(checks: dict, keep: bool) -> int:
    ok = all(checks.values())
    h.note("RESULT: " + ("PASS" if ok else "FAIL"), checks=checks)
    OUT.write_text(json.dumps(h.log, indent=2, default=str))
    if ok and not keep:
        h.winvm.destroy(h.NAME)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(keep="--keep" in sys.argv))
