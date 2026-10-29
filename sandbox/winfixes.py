"""Windows app and configuration fixes (plan T21, T38) on a real host, in a DISPOSABLE Windows VM (sandbox/winvm.py).

The agent's own `run-job` runs as SYSTEM with the job a server would send:
  1. winget: refused before anything runs for an unknown product key and for a version not newer than installed;
     7-Zip at an old version upgraded to winget's newest, verified by the agent's fresh inventory and the map;
     on a host without winget: refused with "winget unavailable".
  2. winconfig smb-signing: injected failure after the change -> the value found is put back exactly (read from the
     registry); then applied for real -> the secure value is set and LanmanServer stays running.
  3. --office (client): Microsoft 365 Apps (Word) installed at an older Current-channel build by the Office Deployment
     Tool; injected failure -> back to that build; then updated to the newest build (T17).

Run from api/:  uv run python ../sandbox/winfixes.py VM_NAME [--keep] [--office]   Writes sandbox/last_run_winfixes_<client|server>.json.
"""

import hashlib
import json
import sys
import urllib.request
from pathlib import Path

import wine2e as h  # noqa: E402  (reads VM_NAME from argv)

from nimstead import winapps  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
RT = r"C:\nimtest\rt"
PY, AGENT = RT + r"\python.exe", r"C:\nimtest\nimstead_agent.py"
SMB = r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"


def copy_in(path: Path):
    c = h.winvm.creds(h.NAME)
    h.winvm.vbox("guestcontrol", h.NAME, "copyto", "--username", c["user"], "--password", c["password"],
                 "--target-directory", "C:\\nimtest\\", str(path))


def runtime():
    """The pinned embeddable runtime, hash-checked here before it goes in (the VM may have no Python at all)."""
    pin = json.loads((ROOT / "agent" / "windows-runtime.json").read_text())["runtimes"]["amd64"]
    zp = h.TMP / "rt.zip"
    if not zp.exists():
        urllib.request.urlretrieve(pin["url"], zp)  # noqa: S310 (python.org URL from the pinned file)
    assert hashlib.sha256(zp.read_bytes()).hexdigest() == pin["sha256"], "runtime hash mismatch"
    copy_in(zp)
    h.guest(rf"Remove-Item -Recurse -Force {RT} -ErrorAction SilentlyContinue; Expand-Archive C:\nimtest\rt.zip {RT}")


def job(name, j, fail=False):
    h.guest(f"Set-Content -Path C:\\nimtest\\{name}.json -Encoding ascii -Value '{json.dumps(j)}'")
    out = rf"C:\nimtest\{name}.out"
    h.as_system(rf'"{PY}" -I "{AGENT}" run-job --yes{" --fail-after-apply" if fail else ""} < C:\nimtest\{name}.json > {out} 2>&1',
                wait_minutes=40, result=out)
    r = json.loads(h.guest(f"Get-Content {out} -Raw").strip().splitlines()[-1])
    h.note(name, outcome=r["outcome"], error=r.get("error"), steps=[(s["step"], s["ok"]) for s in r["steps"]])
    return r


def sevenzip():
    rc, out = h.winvm.run(h.NAME, rf'& "{PY}" -I "{AGENT}" collect')
    inv = json.loads(out[out.index("{"):])
    return [hit[1] for p in inv["packages"] if p["ecosystem"] == "WinApp"
            and (hit := winapps.identify(p["name"], p["source"], p["version"])) and hit[0] == "7-zip:7-zip"]


def reg(value):
    out = h.guest(f"(Get-ItemProperty 'Registry::{SMB}' -Name {value} -ErrorAction SilentlyContinue).{value}", check=False)
    return out.strip() or None


C2R_CFG = r"HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration"
ODT = "https://officecdn.microsoft.com/pr/wsus/setup.exe"  # Microsoft's Office Deployment Tool bootstrapper


def office(checks):
    """Microsoft 365 Apps (Word only) installed at an older Current-channel build, then the agent's office job:
    injected failure -> back to the build found; then the real update to the newest build."""
    req = urllib.request.Request("https://clients.config.office.net/releases/v1.0/OfficeReleases",
                                 headers={"User-Agent": "nimstead-sandbox"})  # urllib's default agent gets 403
    with urllib.request.urlopen(req, timeout=60) as r:  # noqa: S310
        feed = json.load(r)
    cur = next(c for c in feed if c["channelId"] == "Current")["officeVersions"]
    new, old = cur[0]["legacyVersion"], cur[2]["legacyVersion"]
    xml = (f'<Configuration><Add OfficeClientEdition="64" Channel="Current" Version="{old}"><Product ID="O365ProPlusRetail">'
           '<Language ID="en-us"/>' + "".join(f'<ExcludeApp ID="{a}"/>' for a in
           ("Access", "Excel", "Groove", "Lync", "OneDrive", "OneNote", "Outlook", "PowerPoint", "Publisher", "Teams"))
           + '</Product></Add><Display Level="None" AcceptEULA="TRUE"/><Updates Enabled="FALSE"/></Configuration>')
    h.guest(rf"""$ErrorActionPreference='Stop'; Invoke-WebRequest '{ODT}' -OutFile C:\nimtest\odt.exe
        if ((Get-AuthenticodeSignature C:\nimtest\odt.exe).SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {{ throw 'ODT not Microsoft-signed' }}
        Set-Content C:\nimtest\office.xml -Encoding utf8 -Value '{xml}'""")
    h.as_system(r"C:\nimtest\odt.exe /configure C:\nimtest\office.xml", wait_minutes=90)
    found = h.guest(f"(Get-ItemProperty '{C2R_CFG}').VersionToReport", check=False).strip()
    h.note("Microsoft 365 Apps installed", build=found, planned_from=old, to=new)
    fix = {"manager": "office", "packages": [{"name": "Microsoft 365 Apps", "from": found, "to": new}], "health_units": []}
    r = job("office-rollback", fix, fail=True)
    back = h.guest(f"(Get-ItemProperty '{C2R_CFG}').VersionToReport").strip()
    checks["office rollback back to the build found"] = found == old and r["outcome"] == "rolled_back" and back == found
    r = job("office-apply", fix)
    now = h.guest(f"(Get-ItemProperty '{C2R_CFG}').VersionToReport").strip()
    h.note("Office build after apply", now=now)
    checks["office updated to the planned build"] = r["outcome"] == "applied" and now == new


def main(keep=False) -> int:
    h.winvm.wait_ready(h.NAME, minutes=90)
    kind = "client" if "Client" in h.guest(r"(gp 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').InstallationType") else "server"
    h.guest(r"New-Item -ItemType Directory -Force C:\nimtest | Out-Null")
    runtime()
    copy_in(ROOT / "agent" / "nimstead_agent.py")
    checks = {}

    # winget: refusals first (nothing may run), then a real upgrade
    r = job("winget-unknown", {"manager": "winget", "packages": [{"name": "evil:app", "from": "1.0", "to": "2.0"}]})
    checks["unknown product refused"] = r["outcome"] == "aborted" and r["error"].startswith("No changes made")
    r = job("winget-downgrade", {"manager": "winget", "packages": [{"name": "7-zip:7-zip", "from": "26.05", "to": "23.01"}]})
    checks["older version refused"] = r["outcome"] == "aborted" and r["error"].startswith("No changes made")
    has_winget = h.winvm.run(h.NAME, "winget --version")[0] == 0
    if has_winget:
        lines = h.guest("winget show --id 7zip.7zip --exact --versions --accept-source-agreements --disable-interactivity").splitlines()
        vs = [v.strip() for v in lines[next(i for i, x in enumerate(lines) if x.startswith("---")) + 1:] if v.strip()]
        newest, old = vs[0], vs[1]
        h.guest("winget uninstall --id 7zip.7zip --exact --silent --disable-interactivity", check=False)  # a rerun finds the newest
        h.guest(f"winget install --id 7zip.7zip --exact --version {old} --silent --accept-package-agreements "
                "--accept-source-agreements --disable-interactivity --scope machine")
        before = sevenzip()
        r = job("winget-upgrade", {"manager": "winget", "packages": [{"name": "7-zip:7-zip", "from": old, "to": newest}]})
        after = sevenzip()
        h.note("7-Zip by inventory", before=before, after=after, planned=[old, newest])
        checks["7-Zip upgraded as SYSTEM, verified by inventory"] = (
            r["outcome"] == "applied" and bool(before) and bool(after) and before != after
            and winapps.appver_parts(after[0]) >= winapps.appver_parts(winapps.identify(f"7-Zip {newest} (x64)", "Igor Pavlov", newest)[1]))
    else:
        r = job("winget-missing", {"manager": "winget", "packages": [{"name": "7-zip:7-zip", "from": "23.01", "to": "26.05"}]})
        checks["no winget: refused with 'winget unavailable'"] = r["outcome"] == "aborted" and "winget unavailable" in r["error"]

    # winconfig: rollback restores exactly what was there, then the real change
    found = reg("RequireSecuritySignature")
    fix = {"manager": "winconfig", "packages": [{"name": "smb-signing"}], "health_units": ["LanmanServer"]}
    r = job("winconfig-rollback", fix, fail=True)
    back = reg("RequireSecuritySignature")
    h.note("SMB signing after rollback", found=found, now=back)
    checks["winconfig rollback restored the value found"] = r["outcome"] == "rolled_back" and back == found
    r = job("winconfig-apply", fix)
    now = reg("RequireSecuritySignature")
    h.note("SMB signing after apply", now=now)
    checks["winconfig applied, LanmanServer running"] = r["outcome"] == "applied" and now == "1"
    if "--office" in sys.argv:
        office(checks)

    ok = all(checks.values())
    h.note("RESULT: " + ("PASS" if ok else "FAIL"), checks=checks, kind=kind)
    (ROOT / "sandbox" / f"last_run_winfixes_{kind}.json").write_text(json.dumps(h.log, indent=2, default=str))
    if not keep:
        h.winvm.destroy(h.NAME)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(keep="--keep" in sys.argv))
