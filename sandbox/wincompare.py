"""W3: the same old Windows VM read by Nimstead and by a commercial scanner, every CVE on one side only classified.

  prepare VM_NAME   old apps onto the VM, our agent's report judged by an in-process server with NVD and MSRC loaded, our findings
                    saved, then the other scanner's installer copied in (signature checked) and its web console port forwarded
                    to https://localhost:18383 on this host. A person runs the installer from the VM's screen (it has no silent
                    mode), signs in to the console (Claude doesn't sign in to other products), scans this machine and exports
                    the vulnerability report as CSV
  compare CSV       each CVE on one side only, to classify by hand: ours missed, theirs wrong, or out of scope

Results stay outside the repo (PRIVATE below): the licence allows the comparison (DECISIONS 111), W3 makes no public claim.
Run from api/:  uv run python ../sandbox/wincompare.py prepare VM_NAME SCANNER_EXE   |   ... compare EXPORT.csv
"""

import csv
import gzip
import json
import os
import re
import sys
import tempfile
from pathlib import Path

PRIVATE = Path(__file__).resolve().parents[2] / "nimstead-private" / "w3"
CVE = re.compile(r"CVE-\d{4}-\d{4,}")


def ours_file() -> Path:
    return PRIVATE / "ours.json"


def cves_in_csv(path: Path) -> dict[str, list[str]]:
    """CVE -> the rows naming it: any column, as exports differ in layout."""
    out: dict[str, list[str]] = {}
    with open(path, encoding="utf-8-sig", newline="") as fh:
        for row in csv.reader(fh):
            line = " | ".join(row)
            for c in set(CVE.findall(line)):
                out.setdefault(c, []).append(line[:300])
    return out


def split(ours: dict[str, list], theirs: dict[str, list]) -> dict:
    a, b = set(ours), set(theirs)
    return {"both": len(a & b), "only_ours": {c: ours[c] for c in sorted(a - b)}, "only_theirs": {c: theirs[c][:2] for c in sorted(b - a)}}


def prepare(name: str, exe: str) -> int:
    sys.argv[1:] = [name]  # winapps_e2e reads the VM from argv
    import winapps_e2e as e
    import winfixes
    from fastapi.testclient import TestClient
    from signin import signup

    from nimstead import feeds
    from nimstead.db import make_sessionmaker

    tmp = Path(tempfile.mkdtemp(prefix="nimstead-sbx-compare-"))
    env = {"NIMSTEAD_DB": f"sqlite:///{(tmp / 'n.db').as_posix()}", "NIMSTEAD_SECURE_COOKIES": "0", "NIMSTEAD_OPEN_SIGNUP": "1",
           "NIMSTEAD_INVENTORY_MIN_SECONDS": "0", "NIMSTEAD_SIGNING_KEY_FILE": str(tmp / "sign.pem"),
           "NIMSTEAD_CHECKPOINT_DIR": str(tmp / "cp"), "NIMSTEAD_SECRET_KEY_FILE": str(tmp / "secret.key")}
    os.environ.update(env)
    from nimstead.app import create_app
    api = TestClient(create_app(env["NIMSTEAD_DB"]))
    with make_sessionmaker(env["NIMSTEAD_DB"])() as s:
        e.note("feeds", msrc=feeds.sync_msrc(s, 12), kev=feeds.sync_kev(s), eol=feeds.sync_eol(s))
        for feed in [*map(str, range(2010, 2027)), "modified"]:
            vulns = [v["cve"] for v in json.loads(gzip.decompress(feeds._get(None, feeds.NVD_URL.format(feed))))["vulnerabilities"]]
            feeds.sync_winapps(s, vulns)
        e.note("NVD loaded for curated apps")
    signup(api, {"email": "win@example.com", "password": "windows-e2e-password", "org_name": "W3"})
    token = api.post("/api/enroll-tokens").json()["token"]
    agent = api.post("/api/agent/enroll", json={"token": token, "hostname": "w3", "ecosystem": "Windows"}).json()

    e.winvm.wait_ready(name, minutes=90)
    # the first W3 VM began a Windows update mid-comparison and sat at 7% for hours (2026-11-07): both scans must see the same machine
    e.guest(r"New-Item -Force 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' | Out-Null; "
            r"Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' NoAutoUpdate 1 -Type DWord; "
            r"Stop-Service wuauserv -Force; Set-Service wuauserv -StartupType Disabled")
    e.guest(r"New-Item -ItemType Directory -Force C:\nimtest | Out-Null")
    winfixes.runtime()
    py, ag = winfixes.PY, r"C:\nimtest\nimstead_agent.py"
    c = e.winvm.creds(name)
    e.winvm.vbox("guestcontrol", name, "copyto", "--username", c["user"], "--password", c["password"],
                 "--target-directory", "C:\\nimtest\\", str(e.ROOT / "agent" / "nimstead_agent.py"))
    install = ("winget install --id {} --exact --version {} --silent --accept-package-agreements "
               "--accept-source-agreements --disable-interactivity --scope machine")
    installed = {}
    for wid, (old, *_) in e.APPS.items():  # round 1's 17 desktop apps at the versions its runs pinned
        rc, out = e.guest(install.format(wid, old), timeout=1800)
        installed[wid] = old if rc == 0 or "already installed" in out.lower() else f"not installed: {out.strip()[-120:]}"
    e.note("old apps", **installed)

    inv = e.collect(py, ag)
    assert inv["packages"], "empty inventory"
    r = api.post("/api/agent/inventory", headers={"Authorization": f"Bearer {agent['agent_key']}"}, json=inv)
    assert r.status_code == 200, r.text
    findings = api.get("/api/findings", params={"limit": 5000}).json()
    assert isinstance(findings, list) and len(findings) < 5000, str(findings)[:300]  # the API's cap: at the cap, some were cut
    ours: dict[str, list] = {}
    for x in findings:
        for cve in set(CVE.findall(x["vuln_id"])) or {x["vuln_id"]}:
            ours.setdefault(cve, []).append([x["ecosystem"], x["package"], x.get("installed_version"), x.get("fixed_version")])
    PRIVATE.mkdir(parents=True, exist_ok=True)
    ours_file().write_text(json.dumps({"os": inv.get("os_name"), "build": (inv.get("facts") or {}).get("build"), "installed": installed,
                                       "findings": ours}, indent=1), encoding="utf-8")
    e.note("our findings saved", cves=len(ours), file=str(ours_file()))

    e.winvm.vbox("guestcontrol", name, "copyto", "--username", c["user"], "--password", c["password"],
                 "--target-directory", "C:\\nimtest\\", exe)
    sig = e.guest(rf"$s = Get-AuthenticodeSignature 'C:\nimtest\{Path(exe).name}'; '{{0}}|{{1}}' -f $s.Status, $s.SignerCertificate.Subject")[1].strip()
    assert sig.startswith("Valid|"), sig
    # an InstallShield setup with no documented silent switch: `/silent` sat at an unseen dialog for 40 minutes (2026-11-06), so a
    # person runs it from the VM's screen
    e.note("scanner installer copied in, signature checked", signature=sig, path=rf"C:\nimtest\{Path(exe).name}")
    e.guest("New-NetFirewallRule -DisplayName 'W3 console' -Direction Inbound -Protocol TCP -LocalPort 8383 -Action Allow | Out-Null")
    e.winvm.vbox("controlvm", name, "natpf1", "w3console,tcp,127.0.0.1,18383,,8383", check=False)
    e.note("NEXT, by a person: open https://localhost:18383, sign in, scan this machine, export the vulnerabilities as CSV, then run compare")
    (PRIVATE / "prepare_log.json").write_text(json.dumps(e.log, indent=1, default=str), encoding="utf-8")
    return 0


def compare(path: str) -> int:
    ours = json.loads(ours_file().read_text(encoding="utf-8"))["findings"]
    result = split({c: v for c, v in ours.items() if CVE.fullmatch(c)}, cves_in_csv(Path(path)))
    (PRIVATE / "compare.json").write_text(json.dumps(result, indent=1), encoding="utf-8")
    print(json.dumps({"both": result["both"], "only_ours": len(result["only_ours"]), "only_theirs": len(result["only_theirs"])}))
    return 0


assert split({"CVE-1": [1], "CVE-2": [2]}, {"CVE-2": ["x"], "CVE-3": ["y"]}) == {"both": 1, "only_ours": {"CVE-1": [1]}, "only_theirs": {"CVE-3": ["y"]}}

if __name__ == "__main__":
    sys.exit(prepare(sys.argv[2], sys.argv[3]) if sys.argv[1] == "prepare" else compare(sys.argv[2]))
