"""Curated Windows apps on real installs (plan T31-T33), in a DISPOSABLE Windows VM (sandbox/winvm.py).

For each product: winget installs an old version, the agent's own `collect` reads the registry, and the server-side
map must identify exactly that product and version; then the latest version is installed and must identify again
with a newer version. Writes sandbox/last_run_winapps.json. Products winget can't install at an old version are
recorded as such, never counted as proven.

Run from api/:  uv run python ../sandbox/winapps_e2e.py VM_NAME [--keep]   (the VM needs Python or the bundled runtime)
"""

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import winvm  # noqa: E402

from nimstead import msproducts, winapps  # noqa: E402

NAME = sys.argv[1]
assert NAME.startswith(winvm.PREFIX)
ROOT = Path(__file__).resolve().parents[1]
OUT = Path(__file__).with_name("last_run_winapps.json")
# winget id -> (old version, expected product key)
APPS = {
    "7zip.7zip": ("23.01", "7-zip:7-zip"), "WinSCP.WinSCP": ("6.1.2", "winscp:winscp"),
    "TimKosse.FileZilla.Client": ("3.65.0", "filezilla-project:filezilla_client"),
    "DominikReichl.KeePass": ("2.55", "keepass:keepass"), "Notepad++.Notepad++": ("8.6.2", "notepad-plus-plus:notepad++"),
    "VideoLAN.VLC": ("3.0.18", "videolan:vlc_media_player"), "EclipseAdoptium.Temurin.21.JDK": ("21.0.2.13", "oracle:openjdk"),
    "Microsoft.OpenJDK.17": ("17.0.10.7", "oracle:openjdk"), "Mozilla.Thunderbird": ("115.6.0", "mozilla:thunderbird"),
    "TheDocumentFoundation.LibreOffice": ("7.6.4.1", "libreoffice:libreoffice"), "Opera.Opera": ("106.0.4998.70", "opera:opera_browser"),
    "VivaldiTechnologies.Vivaldi": ("6.5.3206.53", "vivaldi:vivaldi"), "Foxit.FoxitReader": ("2023.3.0.23028", "foxit:pdf_reader"),
    "OpenVPNTechnologies.OpenVPN": ("2.6.8.1", "openvpn:openvpn"), "Oracle.VirtualBox": ("7.0.12", "oracle:vm_virtualbox"),
    "Microsoft.PowerShell": ("7.4.1.0", "PowerShell 7.4"), "Microsoft.VisualStudioCode": ("1.85.0", "Visual Studio Code"),
}
log: list[dict] = []


def note(step, **kw):
    log.append({"step": step, **kw})
    print(f"[{time.strftime('%H:%M:%S')}] {step}", json.dumps(kw, default=str)[:300] if kw else "", flush=True)


def guest(cmd, timeout=1800):
    rc, out = winvm.run(NAME, cmd, timeout=timeout)
    return rc, out


def collect(py, agent):
    rc, out = guest(f"& '{py}' -I '{agent}' collect")
    return json.loads(out[out.index("{"):]) if rc == 0 else {"packages": []}


def found(inv, want):
    for p in inv["packages"]:
        if p["ecosystem"] != "WinApp":
            continue
        hit = winapps.identify(p["name"], p["source"], p["version"]) or msproducts.from_winapp(p["name"], p["source"], p["version"])
        if hit and hit[0] == want:
            return {"display_name": p["name"], "registry_version": p["version"], "identified": list(hit)}
    return None


def main(keep=False) -> int:
    winvm.wait_ready(NAME, minutes=60)
    rc, py = guest(r"(Resolve-Path 'C:\Program Files\Nimstead\runtime\*\python.exe', 'C:\Program Files\Python3*\python.exe' -ErrorAction SilentlyContinue)[0].Path")
    py = py.strip()
    agent = r"C:\nimtest\nimstead_agent.py"
    guest(r"New-Item -ItemType Directory -Force C:\nimtest | Out-Null")
    c = winvm.creds(NAME)  # copyto: the agent source is too long for a command line (WinError 206)
    winvm.vbox("guestcontrol", NAME, "copyto", "--username", c["user"], "--password", c["password"],
               "--target-directory", "C:\\nimtest\\", str(ROOT / "agent" / "nimstead_agent.py"))
    rc, out = guest("winget --version")
    note("VM ready", python=py, winget=out.strip()[-40:])
    results = {}
    for wid, (old, key) in APPS.items():
        rc, out = guest(f"winget install --id {wid} --exact --version {old} --silent --accept-package-agreements "
                        "--accept-source-agreements --disable-interactivity --scope machine", timeout=1800)
        if rc != 0:
            results[wid] = {"proven": False, "why": f"winget couldn't install {old}: {out.strip()[-200:]}"}
            note("not installable", app=wid)
            continue
        before = found(collect(py, agent), key)
        guest(f"winget upgrade --id {wid} --exact --silent --accept-package-agreements --disable-interactivity", timeout=1800)
        after = found(collect(py, agent), key)
        ok = bool(before and after and before["identified"][1] != after["identified"][1])
        results[wid] = {"proven": ok, "old": before, "new": after}
        note("identified on a real install" if ok else "NOT identified as expected", app=wid, old=before, new=after)
    proven = sorted(w for w, r in results.items() if r["proven"])
    OUT.write_text(json.dumps({"result": "PASS" if proven else "FAIL", "vm": NAME, "proven": proven, "apps": results, "steps": log},
                              indent=2, default=str) + "\n", encoding="utf-8")
    if not keep:
        winvm.destroy(NAME)
    return 0 if proven else 1


if __name__ == "__main__":
    sys.exit(main(keep="--keep" in sys.argv))
