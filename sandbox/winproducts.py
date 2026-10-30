"""Microsoft products and the remaining fix proofs on real installs, in a DISPOSABLE Windows 11 VM (sandbox/winvm.py).

  1. winget: Notepad++ at the version below winget's newest, upgraded by the agent's job as SYSTEM, confirmed by inventory.
  2. winconfig: smb-signing with no injected failure; a watcher stops the health unit (Spooler) as soon as the value
     changes, so the agent's own health check fails and the value found is put back.
  3. Edge, .NET, SQL Server Express, Defender and Microsoft 365 Apps: the agent's `collect` must report the version
     another source on the host reports. The real inventory goes to the server with real MSRC data; an old .NET must
     open findings that close once .NET is updated. Exchange and SharePoint need a domain and aren't tried here.

Run from api/:  uv run python ../sandbox/winproducts.py VM_NAME [--keep]   Writes sandbox/last_run_winproducts.json.
"""

import json
import os
import sys
import time

import wine2e as h  # noqa: E402  (reads VM_NAME from argv)
import winfixes as f
from fastapi.testclient import TestClient
from signin import signup

from nimstead import feeds, winapps  # noqa: E402
from nimstead.app import create_app  # noqa: E402
from nimstead.db import make_sessionmaker  # noqa: E402

WATCH = r"""while ($true) {
  $v = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name RequireSecuritySignature -ErrorAction SilentlyContinue).RequireSecuritySignature
  if ($v -eq 1) { sc.exe stop Spooler | Out-Null; break }
  Start-Sleep -Milliseconds 50
}"""


def versions(wid):
    lines = h.guest(f"winget show --id {wid} --exact --versions --accept-source-agreements --disable-interactivity").splitlines()
    return [v.strip() for v in lines[next(i for i, x in enumerate(lines) if x.startswith("---")) + 1:] if v.strip()]


def install(wid, version=None, timeout=2400):
    pin = f"--version {version} " if version else ""
    return h.guest(f"winget install --id {wid} --exact {pin}--silent --force --accept-package-agreements "
                   "--accept-source-agreements --disable-interactivity --scope machine", timeout=timeout, check=False)


def collect():
    rc, out = h.winvm.run(h.NAME, rf'& "{f.PY}" -I "{f.AGENT}" collect')
    return json.loads(out[out.index("{"):])


def found(inv, name):
    return sorted(p["version"] for p in inv["packages"] if p["name"] == name)


def main(keep=False) -> int:
    h.winvm.wait_ready(h.NAME, minutes=90)
    h.guest(r"New-Item -ItemType Directory -Force C:\nimtest | Out-Null")
    f.runtime()
    f.copy_in(f.ROOT / "agent" / "nimstead_agent.py")
    checks = {}

    # 1) Notepad++
    newest, old = versions("Notepad++.Notepad++")[:2]
    install("Notepad++.Notepad++", old)

    def npp():
        return [hit[1] for p in collect()["packages"] if p["ecosystem"] == "WinApp"
                and (hit := winapps.identify(p["name"], p["source"], p["version"])) and hit[0] == "notepad-plus-plus:notepad++"]
    before = npp()
    r = f.job("winget-notepad", {"manager": "winget", "packages": [{"name": "notepad-plus-plus:notepad++", "from": old, "to": newest}]})
    after = npp()
    h.note("Notepad++ by inventory", before=before, after=after, planned=[old, newest])
    checks["Notepad++ upgraded as SYSTEM, verified by inventory"] = r["outcome"] == "applied" and bool(before) and bool(after) and before != after

    # 2) winconfig: the health check fails on its own
    value = f.reg("RequireSecuritySignature")
    h.guest("Set-Content -Path C:\\nimtest\\watch.ps1 -Encoding ascii -Value @'\r\n" + WATCH + "\r\n'@")
    h.guest(r"""$a = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -File C:\nimtest\watch.ps1'
        Register-ScheduledTask -TaskName NimWatch -Action $a -User SYSTEM -RunLevel Highest -Force | Out-Null; Start-ScheduledTask -TaskName NimWatch""")
    time.sleep(10)
    r = f.job("winconfig-health", {"manager": "winconfig", "packages": [{"name": "smb-signing"}], "health_units": ["Spooler"]})
    back = f.reg("RequireSecuritySignature")
    h.note("SMB signing after the failed health check", found=value, now=back)
    checks["winconfig health check failed by itself, value restored"] = (
        r["outcome"] == "rolled_back" and "injected" not in r["error"] and "Spooler" in r["error"] and back == value)
    h.guest("Start-Service Spooler", check=False)

    # 3) products, judged by the server with real MSRC data
    env = {"NIMSTEAD_DB": f"sqlite:///{(h.TMP / 'p.db').as_posix()}", "NIMSTEAD_SECURE_COOKIES": "0", "NIMSTEAD_OPEN_SIGNUP": "1",
           "NIMSTEAD_INVENTORY_MIN_SECONDS": "0", "NIMSTEAD_SIGNING_KEY_FILE": str(h.TMP / "sign.pem"),
           "NIMSTEAD_CHECKPOINT_DIR": str(h.TMP / "cp"), "NIMSTEAD_SECRET_KEY_FILE": str(h.TMP / "secret.key")}
    os.environ.update(env)
    with make_sessionmaker(env["NIMSTEAD_DB"])() as s:
        h.note("feeds", msrc=feeds.sync_msrc(s, 2))
    api = TestClient(create_app(env["NIMSTEAD_DB"]))
    signup(api, {"email": "win@example.com", "password": "windows-e2e-password", "org_name": "WinProducts"})
    token = api.post("/api/enroll-tokens").json()["token"]
    agent = api.post("/api/agent/enroll", json={"token": token, "hostname": "products", "ecosystem": "Windows"}).json()
    auth = {"Authorization": f"Bearer {agent['agent_key']}"}

    def findings(inv):
        r = api.post("/api/agent/inventory", headers=auth, json=inv)
        assert r.status_code == 200, r.text
        return [x for x in api.get("/api/findings").json() if x["ecosystem"] == "Microsoft"]

    dotnet = "Microsoft.DotNet.Runtime.8"
    dn = versions(dotnet)
    install(dotnet, dn[-1])
    h.note("SQL Server Express install", output=install("Microsoft.SQLServer.2022.Express")[-500:])
    f.office(checks)

    inv = collect()
    open1 = findings(inv)
    runtimes = h.guest(r"& 'C:\Program Files\dotnet\dotnet.exe' --list-runtimes", check=False)
    edge = h.guest(r"(Get-Item 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe').VersionInfo.ProductVersion", check=False).strip()
    sql = h.guest(r"(Get-Item (Get-ChildItem 'C:\Program Files\Microsoft SQL Server' -Recurse -Filter sqlservr.exe)[0].FullName).VersionInfo.ProductVersion", check=False).strip()
    mp = h.guest("Get-MpComputerStatus | Select-Object AMProductVersion, AMEngineVersion | ConvertTo-Json", check=False)
    mp = json.loads(mp) if mp.strip().startswith("{") else {}
    c2r = h.guest(f"(Get-ItemProperty '{f.C2R_CFG}').VersionToReport", check=False).strip()
    reported = {n: found(inv, n) for n in (".NET runtime", "SQL Server", "Defender platform", "Defender engine", "Microsoft 365 Apps")}
    reported["Microsoft Edge"] = [p["version"] for p in inv["packages"] if p["name"] == "Microsoft Edge"]
    h.note("collected vs the host", reported=reported, dotnet_cli=runtimes, edge=edge, sql=sql, defender=mp, office=c2r)
    h.note("Microsoft findings with old .NET", count=len(open1), by_package=sorted({x["package"] for x in open1}))
    net = reported[".NET runtime"]
    checks[".NET version matches dotnet --list-runtimes"] = bool(net) and all(v in runtimes for v in net)
    checks["Edge version matches msedge.exe"] = reported["Microsoft Edge"] == [edge]
    # shortcut: compares build and revision only, sqlservr.exe writes 2022.160.x.y where the registry has 16.0.x.y
    checks["SQL Server version matches sqlservr.exe"] = bool(reported["SQL Server"]) and all(
        v.split(".")[-2:] == sql.split(".")[-2:] for v in reported["SQL Server"])
    checks["Defender versions match Get-MpComputerStatus"] = (
        reported["Defender platform"] == [mp.get("AMProductVersion")] and reported["Defender engine"] == [mp.get("AMEngineVersion")])
    checks["Microsoft 365 Apps version matches Click-to-Run"] = reported["Microsoft 365 Apps"] == [c2r]
    old_net = [x for x in open1 if ".NET" in x["package"]]
    checks["old .NET opens findings"] = bool(old_net)

    install(dotnet, dn[0])
    open2 = findings(collect())
    left = [x for x in open2 if ".NET" in x["package"]]  # /api/findings lists open ones by default
    h.note(".NET updated", before=len(old_net), after=len(left), now=found(collect(), ".NET runtime"), newest=dn[0])
    checks[".NET findings closed by the update"] = bool(old_net) and not left

    ok = all(checks.values())
    h.note("RESULT: " + ("PASS" if ok else "FAIL"), checks=checks)
    (f.ROOT / "sandbox" / "last_run_winproducts.json").write_text(json.dumps(h.log, indent=2, default=str))
    if not keep:
        h.winvm.destroy(h.NAME)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(keep="--keep" in sys.argv))
