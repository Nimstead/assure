"""W15 proof: a listed vulnerable driver FILE is flagged and an unrelated driver isn't, in a DISPOSABLE Windows VM
(sandbox/winvm.py). The file is copied into System32\\drivers and hashed. It is NEVER loaded: no service is created and
nothing here can start one; the run checks that no driver service points at it, before and after.

The sample comes from LOLDrivers' own repository (RTCore64.sys, pinned below), downloaded INSIDE the guest so it never
touches this host's disk, hash-checked there, and held under a Defender exclusion so it isn't quarantined before the scan.
Needs: a VM from winvm.py with outbound internet; internet on the host for the real feed.

Run from api/:  uv run python ../sandbox/windrivers.py VM_NAME [--keep]   Writes sandbox/last_run_windrivers.json.
"""

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import httpx
import winchecks as c  # noqa: E402
import wine2e as h  # noqa: E402  (reads VM_NAME from argv)
import winfixes as f  # noqa: E402

from nimstead import windrivers  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
SHA = "01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862444af32e87f1fd"
URL = "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/2d8e4f38b36c334d0a32a7324832501d.bin"
LISTED, CONTROL = "nimtest-listed.sys", "nimtest-control.sys"
DRIVERS = r"C:\Windows\System32\drivers"
COLLECT = "pkgs, scan = a.windows_drivers()\r\nprint(json.dumps({'pkgs': pkgs, 'scan': scan}))"


def services_on_it() -> int:
    return int(h.guest(f"@(Get-CimInstance Win32_SystemDriver | Where-Object {{ $_.PathName -match '{LISTED}' }}).Count").strip())


def judged(listed: dict, pkgs: list) -> list[str]:
    return sorted(x["package"] for x in windrivers.findings([SimpleNamespace(**p) for p in pkgs], listed))


def main(keep=False) -> int:
    h.winvm.wait_ready(h.NAME, minutes=90)
    h.guest(r"New-Item -ItemType Directory -Force C:\nimtest, C:\nimdrv | Out-Null")
    f.runtime()
    f.copy_in(ROOT / "agent" / "nimstead_agent.py")
    listed = windrivers.parse(httpx.get(windrivers.URL, follow_redirects=True, timeout=300).raise_for_status().json())
    h.note("feed", hashes=len(listed), sample=listed.get(SHA))
    checks = {"sample is in today's feed": SHA in listed}

    h.guest(rf"""Add-MpPreference -ExclusionPath 'C:\nimdrv', '{DRIVERS}\{LISTED}' -ErrorAction SilentlyContinue
        [Net.ServicePointManager]::SecurityProtocol = 'Tls12'
        Invoke-WebRequest -UseBasicParsing '{URL}' -OutFile C:\nimdrv\sample.bin""")
    got = h.guest(r"(Get-FileHash C:\nimdrv\sample.bin -Algorithm SHA256).Hash").strip().lower()
    h.note("sample downloaded in the guest", sha256=got)
    assert got == SHA, "sample hash mismatch: nothing placed"
    # file only: Copy-Item doesn't register or load anything. The control is an ordinary program under a driver's name
    h.guest(rf"Copy-Item C:\nimdrv\sample.bin '{DRIVERS}\{LISTED}'; Copy-Item C:\Windows\System32\cmd.exe '{DRIVERS}\{CONTROL}'")
    checks["no service points at the file before the scan"] = services_on_it() == 0

    r = c.agent_py(COLLECT, "drivers")
    pkgs, scan = r["pkgs"], r["scan"]
    by_name = {p["name"]: p for p in pkgs}
    loaded = sum(p["source"] == "loaded" for p in pkgs)
    h.note("collector", scan=scan, drivers=len(pkgs), loaded=loaded, listed=by_name.get(LISTED), control=by_name.get(CONTROL))
    hits = judged(listed, pkgs)
    h.note("findings", hits=hits)
    checks["listed file hashed, on disk and not loaded"] = (by_name.get(LISTED) or {}).get("version") == SHA and by_name[LISTED]["source"] == "on disk"
    checks["listed file flagged"] = LISTED in hits
    checks["control file hashed and not flagged"] = CONTROL in by_name and CONTROL not in hits
    checks["some real drivers reported as loaded"] = loaded > 20
    checks["scan complete"] = scan.get("complete") is True
    checks["no service points at the file after the scan"] = services_on_it() == 0

    h.guest(rf"Remove-Item -Force '{DRIVERS}\{LISTED}', '{DRIVERS}\{CONTROL}', C:\nimdrv\sample.bin")
    r = c.agent_py(COLLECT, "drivers2")
    h.note("after removal", scan=r["scan"], hits=judged(listed, r["pkgs"]))
    checks["gone after removal"] = LISTED not in judged(listed, r["pkgs"])

    ok = all(checks.values())
    h.note("RESULT: " + ("PASS" if ok else "FAIL"), checks=checks)
    (ROOT / "sandbox" / "last_run_windrivers.json").write_text(json.dumps(h.log, indent=2, default=str))
    if not keep:
        h.winvm.destroy(h.NAME)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(keep="--keep" in sys.argv))
