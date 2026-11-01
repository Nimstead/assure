"""Curated Windows apps on real installs (plan T31-T33), in a DISPOSABLE Windows VM (sandbox/winvm.py).

For each product: winget installs an old version, the agent's own `collect` reads the registry, and the server-side
map must identify exactly that product and version; then the latest version is installed and must identify again
with a newer version. Writes sandbox/last_run_winapps.json. Products winget can't install at an old version are
recorded as such, never counted as proven.

Run from api/:  uv run python ../sandbox/winapps_e2e.py VM_NAME [--keep]   (the VM needs Python or the bundled runtime)
"""

import json
import subprocess
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
NEW = {  # batch 4 alone with --new: versions below winget's newest on 2026-10-31
    "IrfanSkiljan.IrfanView": ("4.75", "irfanview:irfanview"), "GIMP.GIMP.3": ("3.2.4.0", "gimp:gimp"), "GoLang.Go": ("1.26.7", "golang:go"),
    "PostgreSQL.PostgreSQL.17": ("17.9-1", "postgresql:postgresql"), "MariaDB.Server": ("12.3.3.0", "mariadb:mariadb"),
    "GrafanaLabs.Grafana.OSS": ("13.2.4", "grafana:grafana"), "JetBrains.IntelliJIDEA.Community": ("2025.2.6.1", "jetbrains:intellij_idea"),
    "Anysphere.Cursor": ("3.19.7", "anysphere:cursor"), "calibre.calibre": ("9.16.0", "calibre-ebook:calibre"),
    "TigerVNC.TigerVNC": ("1.16.1", "tigervnc:tigervnc"), "SumatraPDF.SumatraPDF": ("3.6", "sumatrapdfreader:sumatrapdf"),
    "Nextcloud.NextcloudDesktop": ("35.0.0", "nextcloud:desktop"), "NoMachine.NoMachine": ("10.1.7", "nomachine:nomachine"),
    "Greenshot.Greenshot": ("1.3.323", "getgreenshot:greenshot"), "GnuPG.Gpg4win": ("5.1.0", "gpg4win:gpg4win"),
    "qBittorrent.qBittorrent": ("5.2.4", "qbittorrent:qbittorrent"), "Discord.Discord": ("1.0.9265", "discord:discord"),
}
if "--new" in sys.argv:
    APPS, OUT = NEW, OUT.with_name("last_run_winapps_batch4.json")
log: list[dict] = []


def note(step, **kw):
    log.append({"step": step, **kw})
    print(f"[{time.strftime('%H:%M:%S')}] {step}", json.dumps(kw, default=str)[:300] if kw else "", flush=True)


def guest(cmd, timeout=1800):
    try:
        rc, out = winvm.run(NAME, cmd, timeout=timeout)
    except subprocess.TimeoutExpired:  # a hung installer fails that app, not the run
        rc, out = 1, f"timed out after {timeout} s"
    return rc, out


def collect(py, agent):
    rc, out = guest(f"& '{py}' -I '{agent}' collect")
    return json.loads(out[out.index("{"):]) if rc == 0 else {"packages": []}


def found(inv, want):
    """Every install identified as `want` (some products, e.g. JDKs, install a newer version beside the old one)."""
    hits = []
    for p in inv["packages"]:
        if p["ecosystem"] != "WinApp":
            continue
        hit = winapps.identify(p["name"], p["source"], p["version"]) or msproducts.from_winapp(p["name"], p["source"], p["version"])
        if hit and hit[0] == want:
            hits.append({"display_name": p["name"], "registry_version": p["version"], "identified": list(hit)})
    return hits


def older_version(wid):
    """The version just below winget's newest: winget drops old versions, and the one below still has an upgrade."""
    rc, out = guest(f"winget show --id {wid} --exact --versions --accept-source-agreements --disable-interactivity")
    lines = out.splitlines()
    vs = [v.strip() for v in lines[next((i for i, x in enumerate(lines) if x.startswith("---")), len(lines)) + 1:] if v.strip()]
    return vs[1] if rc == 0 and len(vs) > 1 else None


def save(results):
    proven = sorted(w for w, r in results.items() if r["proven"])
    OUT.write_text(json.dumps({"result": "PASS" if proven else "FAIL", "vm": NAME, "proven": proven, "apps": results, "steps": log},
                              indent=2, default=str) + "\n", encoding="utf-8")
    return proven


def main(keep=False) -> int:
    winvm.wait_ready(NAME, minutes=90)
    rc, py = guest(r"(Resolve-Path 'C:\Program Files\Nimstead\runtime\*\python.exe', 'C:\Program Files\Python3*\python.exe' -ErrorAction SilentlyContinue)[0].Path")
    py = py.strip()
    if rc != 0 or not py.endswith("python.exe"):  # a fresh VM has no Python: the pinned runtime the agent ships with
        import winfixes
        guest(r"New-Item -ItemType Directory -Force C:\nimtest | Out-Null")
        winfixes.runtime()
        py = winfixes.PY
    agent = r"C:\nimtest\nimstead_agent.py"
    guest(r"New-Item -ItemType Directory -Force C:\nimtest | Out-Null")
    c = winvm.creds(NAME)  # copyto: the agent source is too long for a command line (WinError 206)
    winvm.vbox("guestcontrol", NAME, "copyto", "--username", c["user"], "--password", c["password"],
               "--target-directory", "C:\\nimtest\\", str(ROOT / "agent" / "nimstead_agent.py"))
    rc, out = guest("winget --version")
    note("VM ready", python=py, winget=out.strip()[-40:])
    assert collect(py, agent)["packages"], "the agent can't read inventory here"  # or every app reads as not identified
    results = {}
    for wid, (old, key) in APPS.items():
        if found(collect(py, agent), key):
            results[wid] = {"proven": False, "why": "already installed before the test (an earlier run): uninstall it to retest"}
            note("already installed", app=wid)
            continue
        install = ("winget install --id {} --exact --version {} --silent --accept-package-agreements "
                   "--accept-source-agreements --disable-interactivity --scope machine")
        rc, out = guest(install.format(wid, old), timeout=1800)
        if rc != 0 and "No version found" in out and (alt := older_version(wid)):
            old = alt  # the pinned old version left winget's repository
            rc, out = guest(install.format(wid, old), timeout=1800)
        if rc != 0 and "No applicable installer" in out:  # per-user only (Cursor, Discord): the agent reads every profile
            rc, out = guest(install.format(wid, old).replace(" --scope machine", ""), timeout=1800)
        if rc != 0:
            results[wid] = {"proven": False, "why": f"winget couldn't install {old}: {out.strip()[-200:]}"}
            note("not installable", app=wid)
            continue
        before = found(collect(py, agent), key)
        guest(f"winget upgrade --id {wid} --exact --silent --accept-package-agreements --disable-interactivity", timeout=1800)
        after = found(collect(py, agent), key)
        old_vs = {h["identified"][1] for h in before}
        ok = bool(before and any(h["identified"][1] not in old_vs for h in after))
        results[wid] = {"proven": ok, "installed": old, "old": before, "new": after}
        note("identified on a real install" if ok else "NOT identified as expected", app=wid, old=before, new=after)
        save(results)  # kept if a later installer hangs the run
    proven = save(results)
    if not keep:
        winvm.destroy(NAME)
    return 0 if proven else 1


if __name__ == "__main__":
    sys.exit(main(keep="--keep" in sys.argv))
