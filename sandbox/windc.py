"""Two domain controllers: AD discovery and one-at-a-time patching (W8), in the lab from sandbox/winlab.py.

The lab's second member is promoted to a second DC. An opted-in DC's agent reads the directory: the real computers are listed, a disabled
object and a stale one are left out, and no credential is stored. Then both DCs get the real OS update through their own scheduled tasks:
never at once, and both healthy afterwards with replication working.

Run from api/:  uv run python ../sandbox/windc.py [--no-reset]   Writes sandbox/last_run_windc.json. The lab stays: `winlab.py reset` or `teardown`.
"""

import json
import secrets
import sys
import time

import winlab as lab_  # noqa: E402
from sqlalchemy import select

from nimstead.db import DirectoryComputer, make_sessionmaker  # noqa: E402

h = lab_.h
PLANT = r"""$ErrorActionPreference = 'Stop'
# lastLogonTimestamp is the SAM's and can't be written (real DC: "owned by the Security Accounts Manager"), so the stale one is a
# computer that never logged on: no timestamp, which the server's 30-day rule leaves out as it does one last seen 90 days ago
New-ADComputer NIM-STALE -Enabled $true
New-ADComputer NIM-DISABLED -Enabled $false
"""
OPT_IN = r"""$ErrorActionPreference = 'Stop'
$p = 'C:\ProgramData\Nimstead\agent.json'; $c = Get-Content $p -Raw | ConvertFrom-Json; $c.ad_discovery = $true
Set-Content $p -Encoding ascii -Value ($c | ConvertTo-Json -Depth 5)
"""
# a sync first: showrepl keeps the failures of attempts made while the other DC was restarting until the next one (real lab)
HEALTH = r"""repadmin /syncall /AdeP | Out-Null
$s = @('NTDS', 'DNS', 'Netlogon', 'KDC') | ForEach-Object { "$((Get-Service $_).Status)" }
$f = @(repadmin /showrepl /csv | ConvertFrom-Csv | Where-Object { [int]$_.'Number of Failures' -ne 0 }).Count
ConvertTo-Json -Compress -InputObject @{ services = @($s); repl_failures = $f }
"""


def dc_healthy(d: dict) -> bool:
    return len(d.get("services", [])) == 4 and set(d["services"]) == {"Running"} and d.get("repl_failures") == 0


def directory_checks(raw: set[str], unmanaged: set[str], real: set[str], managed: set[str]) -> dict:
    """`raw`: what the agent sent. `unmanaged`: what Assets lists. All lower case."""
    return {"the real computers were read": real <= raw, "disabled object left out by the agent": "nim-disabled" not in raw,
            "stale object left out of the list": "nim-stale" in raw and "nim-stale" not in unmanaged,
            "a real computer with no agent is listed": bool((real - managed) & unmanaged), "hosts with an agent aren't listed": not managed & unmanaged}


def health(v: dict) -> dict:
    lab_.on(v)
    return json.loads(h.guest(HEALTH, check=False).strip().splitlines()[-1])


def replicates(src: dict, dst: dict, minutes=10) -> bool:
    """An object made on one DC appears on the other."""
    name = "nimrepl" + secrets.token_hex(3)
    lab_.on(src)
    h.guest(f"New-ADUser {name}; repadmin /syncall /AdeP | Out-Null")
    lab_.on(dst)
    end = time.time() + minutes * 60
    while time.time() < end:
        if name in h.guest(f"(Get-ADUser {name} -Server localhost -ErrorAction Stop).SamAccountName", timeout=120, check=False):
            return True
        time.sleep(30)
    return False


def main() -> int:
    lab = lab_.reset() if "--no-reset" not in sys.argv else lab_.load()
    dc1, [member, dc2, *_] = lab_.by_role(lab)
    api = lab_.Api()
    lab_.promote_replica(dc2, lab_.domain_admin(lab)["password"], lab_.lab_secrets(lab)["safe_mode"])
    checks = {"replication between the DCs before patching": replicates(dc1, dc2)}

    dcs = [dc1, dc2]
    assets = []
    for v in dcs:
        lab_.on(v)
        lab_.install_agent(api.token)
        h.guest("Disable-ScheduledTask -TaskName 'Nimstead jobs' | Out-Null")  # until both jobs are approved
        a = lab_.asset_named(api, v["computer"])
        assert api.patch(f"/api/assets/{a['id']}", json={"health_units": lab_.DC_UNITS}).status_code == 200
        assets.append(a)
    roles = {a["hostname"]: a["facts"].get("domain_role") for a in (lab_.asset_named(api, v["computer"]) for v in dcs)}
    h.note("the DCs as the server sees them", roles=roles)
    checks["both report as domain controllers"] = all(isinstance(r, int) and r >= 4 for r in roles.values())

    # AD discovery: an opted-in DC reads the directory with its own computer account
    lab_.on(dc1)
    h.guest(PLANT)
    h.guest(OPT_IN)
    # an admin names the one host whose directory the server takes (DECISIONS 102): the agent's opt-in alone is refused
    src = lab_.asset_named(api, dc1["computer"])
    assert api.patch(f"/api/assets/{src['id']}", json={"directory_source": True}).status_code == 200
    rc, out = lab_.agent_system("report", "discover")
    h.note("report with AD discovery on", rc=rc, output=out[-400:])
    with make_sessionmaker(api.env["NIMSTEAD_DB"])() as s:
        raw = {c.name for c in s.scalars(select(DirectoryComputer))}
    unmanaged = {c["name"] for c in api.get("/api/directory/unmanaged").json()}
    real, managed = {v["computer"].lower() for v in lab["vms"]}, {v["computer"].lower() for v in dcs}
    h.note("directory", raw=sorted(raw), unmanaged=sorted(unmanaged))
    checks.update(directory_checks(raw, unmanaged, real, managed))
    config = h.guest(r"Get-Content C:\ProgramData\Nimstead\agent.json -Raw")
    cfg = json.loads(config)
    lab_.SECRETS.add(cfg["agent_key"])
    principal = h.guest("(Get-ScheduledTask -TaskName 'Nimstead agent').Principal.UserId").strip()
    checks["no credential stored: the agent's task runs as SYSTEM, with no domain secret in its config"] = (
        principal == "SYSTEM" and lab_.domain_admin(lab)["password"] not in config and not {k for k in cfg if "pass" in k.lower() or "cred" in k.lower()})

    # one at a time
    jids = [lab_.plan_fix(api, a["id"]) for a in assets]
    for v in dcs:
        lab_.on(v)
        h.guest("Enable-ScheduledTask -TaskName 'Nimstead jobs' | Out-Null")
    samples = lab_.drive_jobs(api, jids, dcs)
    jobs = lab_.jobs_by_id(api)
    together = lab_.overlap(samples)
    h.note("both DCs' jobs finished", statuses=[jobs[j]["status"] for j in jids], samples=len(samples), together=together[:5],
           steps=[[s["step"] for s in jobs[j]["steps"]][-5:] for j in jids])
    checks["both jobs succeeded"] = all(jobs[j]["status"] == "succeeded" for j in jids)
    checks["never at once"] = not together and any(any(v == "dispatched" for v in x.values()) for x in samples)
    for v in dcs:
        lab_.wait_ad(v)
    states = {v["computer"]: health(v) for v in dcs}
    h.note("after patching", health=states)
    checks["both healthy"] = all(dc_healthy(d) for d in states.values())
    checks["replication after patching"] = replicates(dc2, dc1)
    return lab_.conclude(checks)


if __name__ == "__main__":
    sys.exit(lab_.harness(main, "last_run_windc.json"))
