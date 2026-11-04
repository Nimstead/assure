"""A two-node failover cluster (W9), in the lab from sandbox/winlab.py: Failover-Clustering on both members, a file-share witness on the DC,
a clustered web role whose page names the node serving it. A probe on the DC reads that page every 5 seconds throughout, from outside the
cluster. Each node's real OS update then runs from its own scheduled task: drained, patched, resumed, never both at once. The jobs first wait
out a closed maintenance window, which is opened on the same run.

Run from api/:  uv run python ../sandbox/wincluster.py [--no-reset]   Writes sandbox/last_run_wincluster.json. The lab stays: `winlab.py reset` or `teardown`.
"""

import sys
import time
from datetime import UTC, datetime

import winlab as lab_  # noqa: E402

h = lab_.h
CLUSTER, ROLE = "NIMCLUS", "NIMROLE"
CLUSTER_IP, ROLE_IP = f"{lab_.SUBNET}.40", f"{lab_.SUBNET}.50"
MAX_OUTAGE_SECONDS = 90  # the role moves between nodes when one is drained: a short gap there is what a cluster does, a long one isn't
ALWAYS = {"days": [0, 1, 2, 3, 4, 5, 6], "start": "00:00", "hours": 24, "tz": "UTC"}

NODE_NET = r"""$ErrorActionPreference = 'Stop'
$lab = Get-NetIPAddress -IPAddress %IP%
# a cluster's name and role addresses need a network with a gateway; a far worse metric than NAT's, so the internet stays on NAT
New-NetRoute -InterfaceIndex $lab.InterfaceIndex -DestinationPrefix 0.0.0.0/0 -NextHop %GATEWAY% -RouteMetric 9000 | Out-Null
"""
# every VM's NAT address is 10.0.2.15, and a cluster refuses two nodes with one address. The second node moves within NAT's subnet
UNIQUE_NAT = r"""$ErrorActionPreference = 'Stop'
$nat = Get-NetIPAddress -AddressFamily IPv4 | Where-Object IPAddress -like '10.0.2.*'
Set-NetIPInterface -InterfaceIndex $nat.InterfaceIndex -Dhcp Disabled
Remove-NetIPAddress -InterfaceIndex $nat.InterfaceIndex -IPAddress $nat.IPAddress -Confirm:$false
Remove-NetRoute -InterfaceIndex $nat.InterfaceIndex -DestinationPrefix 0.0.0.0/0 -Confirm:$false -ErrorAction SilentlyContinue
New-NetIPAddress -InterfaceIndex $nat.InterfaceIndex -IPAddress 10.0.2.16 -PrefixLength 24 -DefaultGateway 10.0.2.2 -RouteMetric 10 | Out-Null
Start-Sleep 5
(Invoke-WebRequest %SERVER%/api/health -UseBasicParsing -TimeoutSec 30).StatusCode
"""
FEATURES = r"""$ErrorActionPreference = 'Stop'
$r = Install-WindowsFeature Failover-Clustering, Web-Server -IncludeManagementTools
Set-Content C:\inetpub\wwwroot\Default.htm -Encoding ascii -Value $env:COMPUTERNAME
Stop-Service W3SVC; Set-Service W3SVC -StartupType Manual  # the cluster starts it on the node that owns the role
"$($r.RestartNeeded)"
"""
WITNESS = r"""$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force C:\witness | Out-Null
New-SmbShare -Name witness -Path C:\witness -FullAccess 'Domain Admins' | Out-Null
"""
WITNESS_GRANT = r"""$ErrorActionPreference = 'Stop'
Grant-SmbShareAccess -Name witness -AccountName '%NETBIOS%\%CLUSTER%$' -AccessRight Full -Force | Out-Null
icacls C:\witness /grant '%NETBIOS%\%CLUSTER%$:(OI)(CI)F' | Out-Null
"""
NEW_CLUSTER = r"""$ErrorActionPreference = 'Stop'
New-Cluster -Name %CLUSTER% -Node %NODES% -StaticAddress %CLUSTER_IP% -IgnoreNetwork 10.0.2.0/24 -NoStorage -Force | Out-Null
$n = Get-ClusterNetwork | Where-Object Address -eq '10.0.2.0'; if ($n) { $n.Role = 0 }  # the nodes' own way out, not the cluster's
$n = Get-ClusterNetwork | Where-Object Address -eq '%SUBNET%.0'; $n.Role = 3
"""
QUORUM_AND_ROLE = r"""$ErrorActionPreference = 'Stop'
Set-ClusterQuorum -FileShareWitness \\%DC%\witness | Out-Null
Add-ClusterGenericServiceRole -ServiceName W3SVC -Name %ROLE% -StaticAddress %ROLE_IP% | Out-Null
(Get-ClusterGroup %ROLE%).State
(Get-ClusterQuorum).QuorumResource.Name
"""
PROBE = r"""$end = (Get-Date).AddHours(10)
while ((Get-Date) -lt $end -and -not (Test-Path C:\nimtest\probe.stop)) {
  $t = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
  try { $b = (Invoke-WebRequest http://%ROLE_IP%/ -UseBasicParsing -TimeoutSec 4).Content.Trim() } catch { $b = 'DOWN' }
  Add-Content C:\nimtest\probe.csv "$t,$b"
  Start-Sleep 5
}
"""
START_PROBE = r"""$ErrorActionPreference = 'Stop'
$a = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -File C:\nimtest\probe.ps1'
Register-ScheduledTask -TaskName NimsteadProbe -Action $a -User SYSTEM -RunLevel Highest -Force | Out-Null
Start-ScheduledTask -TaskName NimsteadProbe
"""
CLUSTER_STATE = r"""(Get-ClusterNode | ForEach-Object { "$($_.Name)=$($_.State)" }) -join ' '; (Get-ClusterGroup %ROLE%).State; (Get-ClusterGroup %ROLE%).OwnerNode.Name"""


def closed_window(today: datetime) -> dict:
    """A window three days away: closed now, and not about to open during a long run."""
    return {"days": [(today.weekday() + 3) % 7], "start": "00:00", "hours": 1, "tz": "UTC"}


def parse_probe(text: str) -> list[tuple[int, str]]:
    rows = []
    for line in text.splitlines():
        t, _, who = line.strip().partition(",")
        if t.isdigit() and who:
            rows.append((int(t), who))
    return rows


def longest_outage(rows: list[tuple[int, str]]) -> int:
    """Seconds from the last good answer to the next one, or to the last sample: a role that never came back counts in full."""
    worst, last_good = 0, rows[0][0] if rows else 0
    for t, who in rows:
        if who != "DOWN":
            worst, last_good = max(worst, t - last_good), t
    return max(worst, rows[-1][0] - last_good) if rows else 0


def fill(script: str, **kw) -> str:
    for k, v in kw.items():
        script = script.replace(f"%{k}%", v)
    return script


def build_cluster(lab: dict) -> None:
    dc, (n1, n2, *_) = lab_.by_role(lab)
    admin = lab_.domain_admin(lab)
    lab_.on(n2)
    h.note("second node's NAT address moved", health=h.guest(fill(UNIQUE_NAT, SERVER=lab_.SERVER), check=False).strip()[-200:])
    assert "200" in h.guest(f"(Invoke-WebRequest {lab_.SERVER}/api/health -UseBasicParsing -TimeoutSec 30).StatusCode", check=False), (
        "VirtualBox NAT didn't carry a second address in its subnet: this cluster can't have a NAT NIC on both nodes")
    for v in (n1, n2):
        lab_.on(v)
        h.guest(fill(NODE_NET, IP=v["ip"], GATEWAY=dc["ip"]))
        if "Yes" in h.guest(FEATURES, timeout=1800):
            h.reboot_and_wait()
    lab_.on(dc)
    h.guest(WITNESS)
    _, out = lab_.as_user(n1, admin, fill(NEW_CLUSTER, CLUSTER=CLUSTER, NODES=f"{n1['computer']},{n2['computer']}", CLUSTER_IP=CLUSTER_IP, SUBNET=lab_.SUBNET))
    h.note("cluster formed", name=CLUSTER, output=out[-300:])
    lab_.on(dc)
    h.guest(fill(WITNESS_GRANT, NETBIOS=lab_.NETBIOS, CLUSTER=CLUSTER))
    _, out = lab_.as_user(n1, admin, fill(QUORUM_AND_ROLE, DC=dc["computer"], ROLE=ROLE, ROLE_IP=ROLE_IP))
    h.note("witness and role", output=out[-300:])
    assert "Online" in out, out[-1000:]


def main() -> int:
    lab = lab_.reset() if "--no-reset" not in sys.argv else lab_.load()
    dc, (n1, n2, *_) = lab_.by_role(lab)
    nodes = [n1, n2]
    api = lab_.Api()
    build_cluster(lab)

    assets = []
    for v in nodes:  # after the cluster, so the first report already says which cluster this host is in
        lab_.on(v)
        lab_.install_agent(api.token)
        h.guest("Disable-ScheduledTask -TaskName 'Nimstead jobs' | Out-Null")  # until both jobs are approved
        a = lab_.asset_named(api, v["computer"])
        assert api.patch(f"/api/assets/{a['id']}", json={"health_units": ["ClusSvc"], "maintenance_window": closed_window(datetime.now(UTC))}).status_code == 200
        assets.append(a)
    groups = [a["facts"].get("cluster") for a in assets]
    h.note("the nodes as the server sees them", cluster=groups)
    checks = {"both nodes report the cluster": all(str(g).upper() == CLUSTER for g in groups)}

    lab_.on(dc)
    h.guest("Set-Content C:\\nimtest\\probe.ps1 -Encoding ascii -Value @'\r\n" + fill(PROBE, ROLE_IP=ROLE_IP) + "\r\n'@")
    h.guest(START_PROBE)
    time.sleep(30)
    started = parse_probe(h.guest(r"Get-Content C:\nimtest\probe.csv -Raw", check=False))
    h.note("role answering from outside", first=started[:3])
    assert started and started[-1][1] != "DOWN", started[-5:]

    # the maintenance window: approved jobs wait while it's closed
    jids = [lab_.plan_fix(api, a["id"]) for a in assets]
    for v in nodes:
        lab_.on(v)
        h.guest("Enable-ScheduledTask -TaskName 'Nimstead jobs' | Out-Null; Start-ScheduledTask -TaskName 'Nimstead jobs'")
    time.sleep(180)
    waiting = lab_.jobs_by_id(api)
    h.note("window closed: nothing handed out", statuses=[waiting[j]["status"] for j in jids], until=[waiting[j].get("waits_for_window") for j in jids])
    checks["window closed: jobs stayed approved and say when they can start"] = all(waiting[j]["status"] == "approved" and waiting[j].get("waits_for_window") for j in jids)
    for a in assets:
        assert api.patch(f"/api/assets/{a['id']}", json={"maintenance_window": ALWAYS}).status_code == 200
    h.note("window opened")

    samples = lab_.drive_jobs(api, jids, nodes)
    jobs = lab_.jobs_by_id(api)
    together = lab_.overlap(samples)
    steps = [[(s["step"], s["ok"]) for s in jobs[j]["steps"]] for j in jids]
    h.note("both nodes' jobs finished", statuses=[jobs[j]["status"] for j in jids], together=together[:5], last_steps=[x[-5:] for x in steps])
    checks["both jobs succeeded"] = all(jobs[j]["status"] == "succeeded" for j in jids)
    checks["never both nodes at once"] = not together and any(any(v == "dispatched" for v in x.values()) for x in samples)
    checks["each node was drained and resumed"] = all(("cluster node drained", True) in x and ("cluster node resumed", True) in x for x in steps)

    lab_.on(dc)
    h.guest(r"Set-Content C:\nimtest\probe.stop 1")
    time.sleep(10)
    rows = parse_probe(h.guest(r"Get-Content C:\nimtest\probe.csv -Raw"))
    outage, owners = longest_outage(rows), sorted({who for _, who in rows} - {"DOWN"})
    h.note("role from outside, throughout", samples=len(rows), down=sum(who == "DOWN" for _, who in rows), longest_outage_seconds=outage, served_by=owners)
    checks[f"role stayed online from outside (longest gap under {MAX_OUTAGE_SECONDS} s)"] = bool(rows) and outage <= MAX_OUTAGE_SECONDS
    checks["the role really moved between the nodes"] = {n1["computer"], n2["computer"]} <= set(owners)
    _, state = lab_.as_user(n1, lab_.domain_admin(lab), fill(CLUSTER_STATE, ROLE=ROLE))
    h.note("cluster at the end", state=state.strip())
    checks["both nodes up and the role online at the end"] = state.count("=Up") == 2 and "Online" in state
    return lab_.conclude(checks)


if __name__ == "__main__":
    sys.exit(lab_.harness(main, "last_run_wincluster.json"))
