"""Attack paths across real hosts (engine track, DECISIONS 112), in the lab from sandbox/winlab.py.

NIMM1 (A) gives an attacker credentials: WDigest keeps passwords in memory and RDP takes sign-ins without network-level
authentication, on an old build with Microsoft's advisories loaded. NIMM2 (B) accepts them: remote UAC filtering off and SMB open.
The domain's Administrator stays signed in on A through a scheduled task that keeps reaching B over SMB, so A's agent sees an
account in B's Administrators group (Domain Admins) and a connection open to B: the edge must read confirmed. Then the task
stops, A restarts and both agents report again: with nobody from B's Administrators signed in on A, the sign-in way must read
unverified (the relay way, which doesn't depend on who's signed in, stays as it was).

Run from api/:  uv run python ../sandbox/winpaths_lab.py [--no-reset]   Writes sandbox/last_run_winpaths_lab.json. The lab stays.
"""

import sys
import time

import winlab as lab_  # noqa: E402

h = lab_.h
A_WEAK = r"""Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' UseLogonCredential 1 -Type DWord
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' fDenyTSConnections 0 -Type DWord
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' UserAuthentication 0 -Type DWord
Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue
'a weak'"""
B_ACCEPTS = r"""Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' LocalAccountTokenFilterPolicy 1 -Type DWord
Enable-NetFirewallRule -DisplayGroup 'File and Printer Sharing' -ErrorAction SilentlyContinue
'b accepts'"""
HOLD = "while ($true) { Get-ChildItem \\\\%B%\\C$ | Out-Null; Start-Sleep 15 }"  # an SMB session to B, kept busy


def report_both(api, hosts) -> dict:
    out = {}
    for v in hosts:
        lab_.on(v)
        rc, text = lab_.agent_system("report", "pathsreport")
        assert rc == 0, text[-1500:]
        a = lab_.asset_named(api, v["computer"])
        assert api.get(f"/api/assets/{a['id']}/scan-report").status_code == 200  # stores the report the fleet view reads
        out[v["computer"]] = a
    return out


def edge(api, ids, a, b) -> dict | None:
    paths = api.get("/api/attack-paths").json()
    return next((e for e in paths["edges"] if e["from"] == ids[a]["id"] and e["to"] == ids[b]["id"]), None)


def facts_of(api, asset_id: str) -> dict:
    """From the server's database: GET /api/assets sends only the facts its list shows (W27)."""
    from nimstead.db import Asset, make_sessionmaker
    with make_sessionmaker(api.env["NIMSTEAD_DB"])() as s:
        f = s.get(Asset, asset_id).facts or {}
    return {k: f.get(k) for k in ("addresses", "peers", "local_admins", "signed_in_sids")}


def main() -> int:
    lab = lab_.reset() if "--no-reset" not in sys.argv else lab_.load()
    _, (m1, m2, *_) = lab_.by_role(lab)
    api = lab_.Api(msrc=True)
    for v in (m1, m2):
        lab_.on(v)
        lab_.install_agent(api.token, remediate=False)
    lab_.on(m1)
    h.note("A gives credentials", out=h.guest(A_WEAK).strip()[-100:])
    lab_.on(m2)
    h.note("B accepts them", out=h.guest(B_ACCEPTS).strip()[-100:])

    admin = lab_.domain_admin(lab)
    lab_.on(m1)
    h.guest(f"Set-Content C:\\nimtest\\hold.ps1 -Encoding ascii -Value '{HOLD.replace('%B%', m2['computer'])}'; "
            r"$a = New-ScheduledTaskAction -Execute powershell.exe -Argument '-NoProfile -ExecutionPolicy Bypass -File C:\nimtest\hold.ps1'; "
            f"Register-ScheduledTask -TaskName NimHold -Action $a -User '{lab_.NETBIOS}\\Administrator' -Password '{admin['password']}' "
            "-RunLevel Highest -Force | Out-Null; Start-ScheduledTask NimHold")
    time.sleep(60)
    ids = report_both(api, (m1, m2))
    held = {"A": facts_of(api, ids[m1["computer"]]["id"]), "B": facts_of(api, ids[m2["computer"]]["id"])}
    e1 = edge(api, ids, m1["computer"], m2["computer"])
    h.note("with the domain's Administrator signed in on A and reaching B", facts=held, edge=e1)

    # stopping the task leaves its logon session (and its credentials in memory) until the machine restarts, and an agent that
    # still lists it is right to: so restart A, and only then is nobody from B's Administrators signed in there
    lab_.on(m1)
    h.guest("Stop-ScheduledTask NimHold; Unregister-ScheduledTask NimHold -Confirm:$false")
    h.reboot_and_wait()
    time.sleep(60)
    ids = report_both(api, (m1, m2))
    after = facts_of(api, ids[m1["computer"]]["id"])
    e2 = edge(api, ids, m1["computer"], m2["computer"])
    h.note("after the task stopped and A restarted", facts_a=after, edge=e2)
    da = next((s for s in (held["B"]["local_admins"] or []) if s.endswith("-512")), None)
    signin = next((w for w in (e2 or {}).get("ways", []) if w["via"] == "CFG:remote-uac"), None)
    return lab_.conclude({
        "B reports its Administrators group, Domain Admins in it": bool(da),
        "A reports the signed-in account's groups, Domain Admins among them": bool(da) and da in (held["A"]["signed_in_sids"] or []),
        "A reports a connection open to B's own address": any(p.rsplit(":", 1)[0] in (held["B"]["addresses"] or []) for p in held["A"]["peers"] or []),
        "the edge A to B reads confirmed": bool(e1) and e1["grade"] == "confirmed",
        # the relay way doesn't depend on who's signed in, so it stays as it was: only the sign-in way falls
        "with nobody from B's Administrators signed in on A, the sign-in way reads unverified":
            after["signed_in_sids"] is not None and da not in after["signed_in_sids"] and bool(signin) and signin["grade"] == "unverified",
    })


if __name__ == "__main__":
    sys.exit(lab_.harness(main, "last_run_winpaths_lab.json"))
