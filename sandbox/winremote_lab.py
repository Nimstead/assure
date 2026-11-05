"""Agentless scan across real hosts (W10; DECISIONS 65), in the lab from sandbox/winlab.py. sandbox/winremote.py proved it on one machine.

One member scans the other as a domain admin, by Kerberos, and must read what the agent's own `collect` reads there as SYSTEM. With
remoting off, and as a domain user with no admin right, the scan fails and says so: no asset appears as if clean. Then it reports for real.

Run from api/:  uv run python ../sandbox/winremote_lab.py [--no-reset]   Writes sandbox/last_run_winremote_lab.json. The lab stays.
"""

import json
import sys

import winfixes as f  # noqa: E402
import winlab as lab_  # noqa: E402

h = lab_.h
PLANTED = "7-Zip 23.01 (x64)"  # Server Core has no winget: a row only an Uninstall entry can make, so an app is compared too
PLANT = r"""$k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NimLabApp'
New-Item $k -Force | Out-Null
Set-ItemProperty $k DisplayName '%NAME%'; Set-ItemProperty $k DisplayVersion '23.01'; Set-ItemProperty $k Publisher 'Igor Pavlov'
"""
REMOTING_OFF = "Disable-PSRemoting -Force -WarningAction SilentlyContinue; Stop-Service WinRM -Force; Set-Service WinRM -StartupType Disabled"
REMOTING_ON = "Set-Service WinRM -StartupType Automatic; Start-Service WinRM; Enable-PSRemoting -Force -SkipNetworkProfileCheck | Out-Null"
LOW_USER = r"""$ErrorActionPreference = 'Stop'
New-ADUser nimlow -UserPrincipalName 'nimlow@%DOMAIN%' -Enabled $true -AccountPassword (ConvertTo-SecureString '%SECRET%' -AsPlainText -Force)
"""


def keyset(inv: dict) -> set:
    return {(p["ecosystem"], p["name"], p["version"]) for p in inv["packages"]}


def compare_reports(agent: dict, remote: dict) -> dict:
    a, r = keyset(agent), keyset(remote)
    ca, cr = agent["facts"].get("config") or {}, remote["facts"].get("config") or {}
    return {"only_agent": sorted(a - r), "only_remote": sorted(r - a), "settings_differ": {k: (ca.get(k), cr.get(k)) for k in set(ca) | set(cr) if ca.get(k) != cr.get(k)},
            "packages": len(r), "settings": len(cr)}


def last_json(out: str) -> dict:
    return json.loads(out[out.index("{"):].strip().splitlines()[-1])


def scan(line: str, host: str, token: str) -> str:
    return f"$env:NIMSTEAD_TOKEN = '{token}'; {line} --insecure-http scan-remote --server {lab_.SERVER} {host}; 'agent exit=' + $LASTEXITCODE; exit $LASTEXITCODE"  # guest control doesn't pass the code through (2 reads as 1 or 33)


def main() -> int:
    lab = lab_.reset() if "--no-reset" not in sys.argv else lab_.load()
    dc, (m1, m2, *_) = lab_.by_role(lab)
    admin = lab_.domain_admin(lab)
    api = lab_.Api(msrc=False)
    target = m2["computer"]
    for v in (m1, m2):
        lab_.on(v)
        f.runtime()
        f.copy_in(f.ROOT / "agent" / "nimstead_agent.py")
    line = f"& '{f.PY}' -I '{f.AGENT}'"

    lab_.on(m2)
    h.guest(PLANT.replace("%NAME%", PLANTED))
    h.as_system(rf'"{f.PY}" -I "{f.AGENT}" collect > C:\nimtest\collect.out 2>&1', wait_minutes=20)
    out = h.guest(r"Get-Content C:\nimtest\collect.out -Raw")
    agent = json.loads(out[out.index("{"):])
    rc, out = lab_.as_user(m1, admin, f"{line} scan-remote --print {target}; exit $LASTEXITCODE")
    assert rc == 0, out[-2000:]
    remote = last_json(out)
    d = compare_reports(agent, remote)
    h.note(f"{m1['computer']} scanning {target} vs its own agent", **d)
    checks = {"packages equal the agent's": not d["only_agent"] and not d["only_remote"] and d["packages"] > 0, "settings equal the agent's": not d["settings_differ"] and d["settings"] > 0,
              "an installed app came across": any(n == PLANTED for _, n, _ in keyset(remote))}

    # remoting off: reads as that, and nothing looks clean
    lab_.on(m2)
    h.guest(REMOTING_OFF, check=False)
    rc, out = lab_.as_user(m1, admin, scan(line, target, api.token), check=False)
    h.note("remoting off", rc=rc, output=out[-500:])
    checks["remoting off: fails, naming the host and why"] = "agent exit=2" in out and target.lower() in out.lower() and "remoting" in out.lower()
    checks["remoting off: no asset that could read as clean"] = lab_.asset_named(api, target) is None
    lab_.on(m2)
    h.guest(REMOTING_ON)

    # a domain user with no admin right on the target: the same
    secret = lab_.lab_secrets(lab)["low_user"]
    lab_.on(dc)
    h.guest(LOW_USER.replace("%DOMAIN%", lab_.DOMAIN).replace("%SECRET%", secret))
    low = {"user": f"nimlow@{lab_.DOMAIN}", "password": secret}
    rc, out = lab_.as_user(m1, low, scan(line, target, api.token), check=False)
    h.note("no admin right", rc=rc, output=out[-500:])
    checks["no admin right: fails, saying access was denied"] = "agent exit=2" in out and "denied" in out.lower()
    checks["no admin right: no asset that could read as clean"] = lab_.asset_named(api, target) is None

    # and for real: the same scan, reported
    rc, out = lab_.as_user(m1, admin, scan(line, target, api.token), check=False)
    a = lab_.asset_named(api, target)
    h.note("reported to the server", rc=rc, output=out[-300:], asset=a and a["hostname"])
    checks["a real scan reports the host"] = rc == 0 and a is not None
    return lab_.conclude(checks)


if __name__ == "__main__":
    sys.exit(lab_.harness(main, "last_run_winremote_lab.json"))
