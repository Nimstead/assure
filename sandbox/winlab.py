"""A real Active Directory domain in DISPOSABLE Server Core VMs (W7, the gate for W8-W10). Also the helpers those harnesses share.

  uv run python ../sandbox/winlab.py build ISO [--vms=3] [--memory=2560]   # DC + members, Kerberos remoting member to member,
                                                                           # peak host memory at 2 and 3 VMs, then a snapshot of each VM
  uv run python ../sandbox/winlab.py reset                                 # every VM back to that snapshot
  uv run python ../sandbox/winlab.py teardown                              # destroy the lab, its folders and its secrets

Writes sandbox/last_run_winlab.json. Exit 3 means this host can't hold the lab: that run stopped and removed what it made, and
Phase 2 stops there (W7). The lab's secrets live in its VMs' own folders under winvm.STATE and never in a run file: harness()
scrubs them. The lab file holds names and addresses only.
"""

import atexit
import json
import os
import secrets
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

import httpx
import wine2e as h  # noqa: E402
from signin import signup

from nimstead import feeds  # noqa: E402
from nimstead.db import make_sessionmaker  # noqa: E402

winvm = h.winvm
ROOT = Path(__file__).resolve().parents[1]
DOMAIN, NETBIOS = "nimstead-sbx.test", "NIMSTEAD-SBX"
SUBNET = "10.77.0"
VM_MB, VM_DISK_GB, HOST_RESERVE_MB, HOST_MIN_FREE_MB = 2560, 30, 2048, 512
SNAPSHOT = "joined"
LAB_FILE = winvm.STATE / "lab.json"
SERVER = f"http://10.0.2.2:{h.PORT}"
DC_UNITS = ["NTDS", "DNS", "Netlogon", "KDC"]
DONE = {"succeeded", "not_fixed", "rolled_back", "rollback_failed", "failed", "aborted", "cancelled"}
SECRETS: set[str] = set()  # kept out of every run file by save()

LAB_NIC = r"""$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force C:\nimtest | Out-Null
$lab = Get-NetAdapter | Where-Object { ($_.MacAddress -replace '-', '') -eq '%MAC%' }
$nat = Get-NetAdapter | Where-Object { $_.ifIndex -ne $lab.ifIndex } | Select-Object -First 1
if (-not (Get-NetIPAddress -InterfaceIndex $lab.ifIndex -IPAddress %IP% -ErrorAction SilentlyContinue)) {  # a resumed build runs this again
  New-NetIPAddress -InterfaceIndex $lab.ifIndex -IPAddress %IP% -PrefixLength 24 | Out-Null }
Set-DnsClientServerAddress -InterfaceIndex $lab.ifIndex -ServerAddresses %DNS%
Set-DnsClientServerAddress -InterfaceIndex $nat.ifIndex -ServerAddresses %NATDNS%
# every VM's NAT address is 10.0.2.15: it must never reach the domain's DNS
Set-DnsClient -InterfaceIndex $nat.ifIndex -RegisterThisConnectionsAddress $false
Set-NetIPInterface -InterfaceIndex $lab.ifIndex -InterfaceMetric 5
Set-NetIPInterface -InterfaceIndex $nat.ifIndex -InterfaceMetric 50
# the lab network has no gateway, so Windows calls it public until the domain is seen; the firewall stays on for everything else
if (-not (Get-NetFirewallRule -DisplayName 'Nimstead lab network' -ErrorAction SilentlyContinue)) {
  New-NetFirewallRule -DisplayName 'Nimstead lab network' -Direction Inbound -RemoteAddress %SUBNET%.0/24 -Action Allow | Out-Null }
Enable-PSRemoting -Force -SkipNetworkProfileCheck | Out-Null
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation' RealTimeIsUniversal 1 -Type DWord  # see utc_clock
"""
FOREST = r"""$ErrorActionPreference = 'Stop'
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null
Import-Module ADDSDeployment
$r = Install-ADDSForest -DomainName '%DOMAIN%' -DomainNetbiosName '%NETBIOS%' -InstallDns -NoRebootOnCompletion -Force -WarningAction SilentlyContinue `
  -SafeModeAdministratorPassword (ConvertTo-SecureString '%SAFE%' -AsPlainText -Force)
if ($r.Status -ne 'Success') { throw "$($r.Message)" }
"""
REPLICA = r"""$ErrorActionPreference = 'Stop'
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null
Import-Module ADDSDeployment
$c = New-Object PSCredential('Administrator@%DOMAIN%', (ConvertTo-SecureString '%ADMIN%' -AsPlainText -Force))
$r = Install-ADDSDomainController -DomainName '%DOMAIN%' -InstallDns -Credential $c -NoRebootOnCompletion -Force -WarningAction SilentlyContinue `
  -SafeModeAdministratorPassword (ConvertTo-SecureString '%SAFE%' -AsPlainText -Force)
if ($r.Status -ne 'Success') { throw "$($r.Message)" }
"""
# A DC with a NAT NIC registers 10.0.2.15 for itself, which on any other VM is that VM (Microsoft's fix for a multihomed DC, KB 272294)
DC_DNS = r"""$ErrorActionPreference = 'Stop'
Install-WindowsFeature RSAT-DNS-Server | Out-Null
Get-NetAdapter | ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ServerAddresses %IP% }  # promotion points it at 127.0.0.1, which stops answering next
dnscmd /resetlistenaddresses %IP% | Out-Null
if (@((Get-DnsServerForwarder).IPAddress | ForEach-Object { "$_" }) -notcontains '10.0.2.3') { Add-DnsServerForwarder -IPAddress 10.0.2.3 }
New-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name DnsAvoidRegisterRecords -PropertyType MultiString -Value @('LdapIpAddress', 'GcIpAddress') -Force | Out-Null
Add-DnsServerResourceRecordA -ZoneName '%DOMAIN%' -Name '@' -IPv4Address %IP% -ErrorAction SilentlyContinue
Add-DnsServerResourceRecordA -ZoneName '_msdcs.%DOMAIN%' -Name 'gc' -IPv4Address %IP% -ErrorAction SilentlyContinue
foreach ($z in '%DOMAIN%', '_msdcs.%DOMAIN%') {
  Get-DnsServerResourceRecord -ZoneName $z -RRType A | Where-Object { "$($_.RecordData.IPv4Address)" -like '10.0.2.*' } | Remove-DnsServerResourceRecord -ZoneName $z -Force
}
Restart-Service DNS; Restart-Service Netlogon -Force
"""
JOIN = r"""$ErrorActionPreference = 'Stop'
$c = New-Object PSCredential('Administrator@%DOMAIN%', (ConvertTo-SecureString '%ADMIN%' -AsPlainText -Force))
Add-Computer -DomainName '%DOMAIN%' -Credential $c -Force -WarningAction SilentlyContinue
"""
KERBEROS = r"""$ErrorActionPreference = 'Stop'
Invoke-Command -ComputerName %TARGET%.%DOMAIN% -Authentication Kerberos -ScriptBlock { "$env:COMPUTERNAME|$(whoami)" }
klist
"""
INSTALL = r"""$env:NIMSTEAD_TOKEN = '%TOKEN%'; %REMEDIATE%
try { irm %SERVER%/install.ps1 | iex } catch { "INSTALL FAILED: $_"; exit 1 }"""


class HostShort(Exception):
    """This host can't hold the lab."""


# ---- pure logic -----------------------------------------------------------------------------------------------------

def plan_lab(vms: int) -> list[dict]:
    if vms < 3:
        raise ValueError("member to member remoting needs a DC and two members")
    return [{"role": "dc", "computer": "NIMDC1", "ip": f"{SUBNET}.1"},
            *({"role": "member", "computer": f"NIMM{i}", "ip": f"{SUBNET}.{10 + i}"} for i in range(1, vms))]


def parse_host_mem(text: str) -> tuple[int, int]:
    """(total, free) MB from "TotalVisibleMemorySize FreePhysicalMemory", both KB."""
    total, free = text.split()
    return int(total) // 1024, int(free) // 1024


def host_short(vms: int, memory: int, free_mb: int, disk_gb: int) -> str | None:
    """What this host lacks to start the lab, or None."""
    need_mb, need_gb = vms * memory + HOST_RESERVE_MB, vms * VM_DISK_GB
    if free_mb < need_mb:
        return f"{vms} VMs at {memory} MB plus {HOST_RESERVE_MB} MB for the host need {need_mb} MB of free memory; this host has {free_mb} MB free"
    if disk_gb < need_gb:
        return f"{vms} VMs need about {need_gb} GB of disk; {disk_gb} GB is free"
    return None


def nic2_mac(info: str) -> str:
    """The second NIC's MAC from `showvminfo --machinereadable`: how the guest tells its two adapters apart."""
    return next(line.split('"')[1] for line in info.splitlines() if line.startswith("macaddress2="))


def kerberos_proved(out: str, target: str) -> bool:
    """The remote host answered as the domain's Administrator, and the ticket for its WinRM service is in this session. WinRM asks
    for HTTP/<host>, which Active Directory maps to the computer's HOST/ name by default, so klist lists HOST/ (real lab)."""
    low = out.lower()
    return f"{target}|{NETBIOS}\\administrator".lower() in low and any(f"{s}/{target}.{DOMAIN}".lower() in low for s in ("http", "host"))


def scrub(text: str, known: set[str]) -> str:
    for s in known:
        if s:
            text = text.replace(s, "***")
    return text


def overlap(samples: list[dict]) -> list[dict]:
    """Samples ({"t": seconds, job id: status, ...}) where two jobs of one group were in flight together."""
    return [x for x in samples if sum(v in ("dispatched", "verifying") for k, v in x.items() if k != "t") > 1]


# ---- lab file and VM helpers ----------------------------------------------------------------------------------------

def load() -> dict:
    lab = json.loads(LAB_FILE.read_text())
    SECRETS.add(winvm.creds(lab["vms"][0]["vm"])["password"])
    SECRETS.update(lab_secrets(lab).values())
    return lab


def by_role(lab: dict) -> tuple[dict, list[dict]]:
    return lab["vms"][0], lab["vms"][1:]


def lab_secrets(lab: dict) -> dict:
    return json.loads((winvm.STATE / lab["vms"][0]["vm"] / "lab-secrets.json").read_text())


def on(v: dict) -> dict:
    """h.guest, h.as_system, f.copy_in and the rest act on this VM from now on."""
    h.NAME = v["vm"]
    return v


def domain_admin(lab: dict) -> dict:
    return {"user": f"Administrator@{DOMAIN}", "password": winvm.creds(lab["vms"][0]["vm"])["password"]}


def as_user(v: dict, user: dict, script: str, timeout=1800, check=True) -> tuple[int, str]:
    """As a domain account, so remoting carries its Kerberos identity: guest control's own Administrator is a local one on a member."""
    rc, out = 1, ""
    for _ in range(3):  # guest control flakes right after boot
        rc, out = winvm.run(v["vm"], script, timeout=timeout, user=user)
        if rc == 0 or not any(s in out for s in ("VERR_", "not ready", "Error starting guest session")):
            break
        time.sleep(30)
    if check and rc != 0:
        raise RuntimeError(f"as {user['user']} on {v['computer']} failed ({rc}): {out[-2000:]}")
    return rc, out


def lab_net(v: dict, dns: str, nat_dns: str) -> None:
    on(v)
    mac = nic2_mac(winvm.vbox("showvminfo", v["vm"], "--machinereadable"))
    h.guest(LAB_NIC.replace("%MAC%", mac).replace("%IP%", v["ip"]).replace("%DNS%", dns).replace("%NATDNS%", nat_dns).replace("%SUBNET%", SUBNET))


def wait_ad(v: dict, minutes=20) -> None:
    on(v)
    end = time.time() + minutes * 60
    while time.time() < end:
        if DOMAIN in h.guest("(Get-ADDomain -ErrorAction Stop).DNSRoot", timeout=120, check=False):
            return
        time.sleep(30)
    raise RuntimeError(f"{v['computer']}: Active Directory not answering after {minutes} min")


def dc_dns(v: dict) -> None:
    on(v)
    h.guest(DC_DNS.replace("%IP%", v["ip"]).replace("%DOMAIN%", DOMAIN))


def promote_forest(dc: dict, safe: str) -> None:
    on(dc)
    h.guest(FOREST.replace("%DOMAIN%", DOMAIN).replace("%NETBIOS%", NETBIOS).replace("%SAFE%", safe), timeout=2400)
    h.reboot_and_wait()
    wait_ad(dc)
    dc_dns(dc)
    h.note("forest promoted", dc=dc["computer"], domain=DOMAIN)


def promote_replica(v: dict, admin: str, safe: str) -> None:
    on(v)
    h.guest(REPLICA.replace("%DOMAIN%", DOMAIN).replace("%ADMIN%", admin).replace("%SAFE%", safe), timeout=3600)
    h.reboot_and_wait()
    wait_ad(v)
    dc_dns(v)
    h.note("second domain controller promoted", dc=v["computer"])


def join(v: dict, dc: dict, admin: str) -> None:
    on(v)
    seen = h.guest(f"'{dc['computer']}.{DOMAIN}', '{DOMAIN}' | ForEach-Object {{ (Resolve-DnsName $_ -Type A -DnsOnly -ErrorAction Stop).IPAddress }}", check=False)
    assert dc["ip"] in seen and "10.0.2." not in seen, f"the DC's address as seen from {v['computer']}: {seen[-300:]}"
    h.guest(JOIN.replace("%DOMAIN%", DOMAIN).replace("%ADMIN%", admin), timeout=900)
    h.reboot_and_wait()
    channel = h.guest("Test-ComputerSecureChannel", check=False).strip()
    assert channel == "True", f"{v['computer']} secure channel: {channel[-300:]}"
    h.note("member joined", computer=v["computer"])


def stop(v: dict, wait=600) -> None:
    """Shut Windows down from inside: an ACPI button does nothing at a logon screen on a server. Then hard off if it never gets there."""
    try:
        winvm.run(v["vm"], "shutdown /s /t 5", timeout=120)
    except subprocess.TimeoutExpired:  # going down already
        pass
    end = time.time() + wait
    while time.time() < end and 'VMState="poweroff"' not in winvm.vbox("showvminfo", v["vm"], "--machinereadable", check=False):
        time.sleep(10)
    winvm.vbox("controlvm", v["vm"], "poweroff", check=False)  # no-op once off
    time.sleep(5)


def start(v: dict, minutes=30) -> None:
    winvm.vbox("startvm", v["vm"], "--type", "headless")
    winvm.wait_ready(v["vm"], minutes=minutes)


def reset() -> dict:
    """Every VM back to the snapshot of the joined lab: each harness starts clean, in minutes rather than a rebuild."""
    lab = load()
    dc, members = by_role(lab)
    for v in lab["vms"]:
        winvm.vbox("controlvm", v["vm"], "poweroff", check=False)
    time.sleep(5)
    for v in lab["vms"]:
        winvm.vbox("snapshot", v["vm"], "restore", SNAPSHOT)
    start(dc)
    wait_ad(dc)
    for v in members:
        start(v)
    h.note("lab reset to its snapshot", vms=[v["computer"] for v in lab["vms"]])
    return lab


def utc_clock() -> None:
    """Each boot started 8 hours fast (VirtualBox gives the host's local time, read as Pacific time inside) until Windows corrected it
    seconds later; that was late for NETLOGON, so a member booted without its domain and a startup script never ran (real lab,
    2026-11-05). A UTC hardware clock read as UTC fixes it; this brings a lab built before that into line, snapshot and all."""
    lab = reset()
    dc, members = by_role(lab)
    for v in lab["vms"]:
        on(v)
        h.guest(r"Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation' RealTimeIsUniversal 1 -Type DWord")
    for v in reversed(lab["vms"]):  # the DC goes last and comes back first
        stop(v)
        winvm.vbox("modifyvm", v["vm"], "--rtc-use-utc", "on")
        winvm.vbox("snapshot", v["vm"], "delete", SNAPSHOT)
        winvm.vbox("snapshot", v["vm"], "take", SNAPSHOT)
    start(dc)
    wait_ad(dc)
    for v in members:
        start(v)
    h.note("lab clocks set to UTC and snapshot taken again", vms=[v["computer"] for v in lab["vms"]])


def teardown() -> None:
    lab = json.loads(LAB_FILE.read_text())
    for v in lab["vms"]:
        winvm.destroy(v["vm"])
        shutil.rmtree(winvm.STATE / v["vm"], ignore_errors=True)
    LAB_FILE.unlink()
    print(f"destroyed {[v['vm'] for v in lab['vms']]}")


def host_memory() -> tuple[int, int]:
    p = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                        "$o = Get-CimInstance Win32_OperatingSystem; \"$($o.TotalVisibleMemorySize) $($o.FreePhysicalMemory)\""],
                       capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
    return parse_host_mem(p.stdout)


class Peak(threading.Thread):
    """Peak host memory, sampled from the host's Win32_OperatingSystem, per phase of the run."""

    def __init__(self):
        super().__init__(daemon=True)
        self.phase, self.seen, self.halt = "start", {}, threading.Event()

    def run(self):
        while not self.halt.wait(30):
            self.sample()

    def sample(self):
        try:
            total, free = host_memory()
        except (subprocess.SubprocessError, ValueError):  # one lost sample: the next comes in 30 s
            return
        s = self.seen.setdefault(self.phase, {"total_mb": total, "peak_used_mb": 0, "min_free_mb": free})
        s["peak_used_mb"], s["min_free_mb"] = max(s["peak_used_mb"], total - free), min(s["min_free_mb"], free)

    def check(self):
        self.sample()
        low = min((s["min_free_mb"] for s in self.seen.values()), default=HOST_MIN_FREE_MB)
        if low < HOST_MIN_FREE_MB:
            raise HostShort(f"free host memory fell to {low} MB during '{self.phase}', under the {HOST_MIN_FREE_MB} MB this host needs to stay usable: {self.seen}")


def recheck() -> int:
    """The Kerberos proof again on the built lab, added to its run file (the first real build's check missed the HOST/ ticket)."""
    h.log[:] = json.loads((ROOT / "sandbox" / "last_run_winlab.json").read_text())
    lab = load()
    dc, members = by_role(lab)
    rc, out = as_user(members[0], domain_admin(lab), KERBEROS.replace("%TARGET%", members[1]["computer"]).replace("%DOMAIN%", DOMAIN))
    proved = kerberos_proved(out, members[1]["computer"])
    h.note("Kerberos remoting member to member (rechecked)", source=members[0]["computer"], target=members[1]["computer"], proved=proved, output=out[-1200:])
    measured = {p for e in h.log if e["step"] == "peak host memory" for p in e["phases"]}
    return conclude({"Kerberos remoting member to member": proved, "two VMs measured": "2 VMs running" in measured,
                     "three VMs measured": "3 VMs running" in measured})


def build(iso: str, vms=3, memory=VM_MB, resume=False) -> int:
    """`resume`: carry on with the lab a failed build left: machines it finished are kept, one it had created is used as it is."""
    if LAB_FILE.exists() and not resume:
        raise RuntimeError(f"a lab already exists ({LAB_FILE}): run `winlab.py teardown` first, or `build ISO --resume`")
    lab = json.loads(LAB_FILE.read_text()) if resume else {"domain": DOMAIN, "vms": []}
    have = {v["computer"]: v for v in lab["vms"]}
    peak = Peak()
    total, free = host_memory()
    disk = shutil.disk_usage(winvm.STATE.parent).free // 2**30
    h.note("host before the lab", total_mb=total, free_mb=free, free_disk_gb=disk, vms=vms, vm_mb=memory, resumed=sorted(have))
    if not resume and (why := host_short(vms, memory, free, disk)):
        raise HostShort(why)
    if have:  # the domain's Administrator is every lab VM's own; the DC keeps its safe-mode password in its folder
        dc0 = lab["vms"][0]
        admin, safe = winvm.creds(dc0["vm"])["password"], json.loads((winvm.STATE / dc0["vm"] / "lab-secrets.json").read_text())["safe_mode"]
    else:
        admin, safe = "Nim!" + secrets.token_hex(8), "Nim!" + secrets.token_hex(8)
    SECRETS.update((admin, safe))
    peak.start()
    try:
        for i, v in enumerate(plan_lab(vms)):
            peak.phase = f"{i + 1} VMs running"
            if (v := have.get(v["computer"], v)).get("done"):
                continue
            if not v.get("vm"):
                v["vm"] = winvm.create(iso, memory=memory, lab=True, computer=v["computer"], password=admin)
                lab["vms"].append(v)
                LAB_FILE.write_text(json.dumps(lab, indent=2))  # from the first VM on: teardown can find a half-built lab
            on(v)
            winvm.wait_ready(v["vm"], minutes=90)
            h.note("VM installed", computer=v["computer"], vm=v["vm"], memory=peak.seen.get(peak.phase))
            peak.check()
            if v["role"] == "dc":
                (winvm.STATE / v["vm"] / "lab-secrets.json").write_text(json.dumps({"safe_mode": safe, "low_user": "Nim!" + secrets.token_hex(8)}))
                lab_net(v, v["ip"], "10.0.2.3")  # its own DNS after promotion; the NAT's until then
                promote_forest(v, safe)
            else:
                lab_net(v, lab["vms"][0]["ip"], lab["vms"][0]["ip"])  # all names through the DC, which forwards the rest
                join(v, lab["vms"][0], admin)
            v["done"] = True
            LAB_FILE.write_text(json.dumps(lab, indent=2))
            peak.check()
            if i >= 1:  # a settled machine's memory, not only its install's
                time.sleep(300)
                peak.check()
                h.note(peak.phase, memory=peak.seen[peak.phase])
        dc, members = by_role(lab)
        rc, out = as_user(members[0], domain_admin(lab), KERBEROS.replace("%TARGET%", members[1]["computer"]).replace("%DOMAIN%", DOMAIN))
        proved = kerberos_proved(out, members[1]["computer"])
        h.note("Kerberos remoting member to member", source=members[0]["computer"], target=members[1]["computer"], proved=proved, output=out[-1200:])
        for v in reversed(lab["vms"]):  # the DC goes last and comes back first
            stop(v)
            winvm.vbox("snapshot", v["vm"], "take", SNAPSHOT)
        start(dc)
        wait_ad(dc)
        for v in members:
            start(v)
        peak.check()
    except HostShort:
        if LAB_FILE.exists():
            teardown()
        raise
    finally:
        peak.halt.set()
    checks = {"Kerberos remoting member to member": proved, "two VMs measured": "2 VMs running" in peak.seen, "three VMs measured": "3 VMs running" in peak.seen}
    h.note("peak host memory", phases=peak.seen)
    return conclude(checks)


# ---- shared by the lab harnesses and the single-VM proofs -------------------------------------------------------------

def conclude(checks: dict) -> int:
    ok = all(checks.values())
    h.note("RESULT: " + ("PASS" if ok else "FAIL"), checks=checks)
    return 0 if ok else 1


def save(out: str) -> None:
    (ROOT / "sandbox" / out).write_text(scrub(json.dumps(h.log, indent=2, default=str), SECRETS))


def harness(main, out: str) -> int:
    """Runs one proof; the run file is written and scrubbed however it ends. A failed run keeps its VMs for inspection."""
    rc = 1
    try:
        rc = main()
    except HostShort as e:
        h.note("RESULT: HOST CANNOT HOLD THE LAB", why=str(e), next="stop Phase 2 and say so in STATUS (W7); this run removed what it made")
        rc = 3
    except Exception as e:
        h.note("RESULT: FAIL", error=scrub(f"{type(e).__name__}: {e}", SECRETS)[:3000])
        rc = 1
    save(out)
    return rc


def single_vm() -> None:
    assert h.NAME.startswith(winvm.PREFIX), "usage: ... VM_NAME"
    SECRETS.add(winvm.creds(h.NAME)["password"])
    winvm.wait_ready(h.NAME, minutes=90)
    h.guest(r"New-Item -ItemType Directory -Force C:\nimtest | Out-Null")


class Api:
    """The real server on this host, as wine2e runs it. stop() and start() keep its database (W26's outage)."""

    def __init__(self, msrc=True, port=h.PORT):
        self.port, self.proc = port, None
        tmp = h.TMP
        self.env = {"NIMSTEAD_DB": f"sqlite:///{(tmp / 'n.db').as_posix()}", "NIMSTEAD_SECURE_COOKIES": "0", "NIMSTEAD_INVENTORY_MIN_SECONDS": "0",
                    "NIMSTEAD_PUBLIC_URL": SERVER, "NIMSTEAD_SIGNING_KEY_FILE": str(tmp / "sign.pem"), "NIMSTEAD_CHECKPOINT_DIR": str(tmp / "cp"),
                    "NIMSTEAD_SECRET_KEY_FILE": str(tmp / "secret.key"), "NIMSTEAD_OPEN_SIGNUP": "1"}
        from testrelease import TestRelease  # install.ps1 brings the signed embeddable runtime
        rel = TestRelease(tmp)
        rel.publish(rel.agent, "3.15.2", "v9.9.8")
        self.env.update(rel.env())
        os.environ.update(self.env)
        if msrc:
            with make_sessionmaker(self.env["NIMSTEAD_DB"])() as s:
                for attempt in range(10):  # MSRC rate-limits repeated full syncs (429, no Retry-After)
                    try:
                        h.note("feeds", msrc=feeds.sync_msrc(s, 2))
                        break
                    except httpx.HTTPStatusError as e:
                        if e.response.status_code != 429 or attempt == 9:
                            raise
                        time.sleep(120)
        self.client = httpx.Client(base_url=f"http://127.0.0.1:{port}", timeout=60)
        atexit.register(self.stop)  # on Windows the server outlived every harness run and held its port
        self.start()
        body = {"email": "lab@example.com", "password": "windows-lab-" + secrets.token_hex(8), "org_name": "WinLab"}
        SECRETS.add(body["password"])
        signup(self.client, body)
        self.token = self.client.post("/api/enroll-tokens", json={"sandbox": True}).json()["token"]
        SECRETS.add(self.token)
        assert self.client.patch("/api/settings", json={"reboot_deadline_hours": 1}).status_code == 200

    def start(self):
        self.proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "--factory", "nimstead.app:create_app", "--host", "127.0.0.1", "--port", str(self.port)],
                                     cwd=ROOT / "api", stdin=subprocess.DEVNULL,
                                     stdout=open(h.TMP / "api.log", "ab"), stderr=subprocess.STDOUT)
        for _ in range(60):
            try:
                if self.client.get("/install.ps1").status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(1)
        raise RuntimeError(f"the API didn't start: see {h.TMP / 'api.log'}")

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait(timeout=30)

    def get(self, *a, **k):
        return self.client.get(*a, **k)

    def post(self, *a, **k):
        return self.client.post(*a, **k)

    def patch(self, *a, **k):
        return self.client.patch(*a, **k)


def install_agent(token: str, remediate=True, server=SERVER) -> None:
    """The real installer on the VM h.guest points at, elevated."""
    script = INSTALL.replace("%TOKEN%", token).replace("%SERVER%", server).replace("%REMEDIATE%", "$env:NIMSTEAD_ALLOW_REMEDIATION = '1'" if remediate else "")
    out = h.guest(script, timeout=1800, check=False)
    assert "Nimstead agent installed." in out, out[-2000:]
    h.note("install.ps1 ran", vm=h.NAME)


def py_path() -> str:
    return h.guest(r"(Resolve-Path 'C:\Program Files\Nimstead\runtime\*\python.exe')[0].Path").strip()


def agent_line() -> str:
    return f'"{py_path()}" -I "C:\\Program Files\\Nimstead\\nimstead_agent.py" --insecure-http'


def agent_system(args: str, name="agentrun", minutes=30) -> tuple[int, str]:
    """The installed agent as SYSTEM, as its own scheduled task runs it: (exit code, output)."""
    out, rcf = rf"C:\nimtest\{name}.out", rf"C:\nimtest\{name}.rc"
    h.guest(f"Remove-Item {out}, {rcf} -ErrorAction SilentlyContinue", check=False)
    h.as_system(f"{agent_line()} {args} > {out} 2>&1\r\necho %ERRORLEVEL% > {rcf}", wait_minutes=minutes)
    rc = h.guest(f"Get-Content {rcf} -Raw").strip()
    return int(rc) if rc.isdigit() else 1, h.guest(f"Get-Content {out} -Raw", check=False)


def asset_named(api: Api, computer: str) -> dict | None:
    return next((a for a in api.get("/api/assets").json() if a["hostname"].split(".")[0].lower() == computer.lower()), None)


def plan_fix(api: Api, asset_id: str) -> str:
    """Plan and approve the OS update for one host, as a person does on Home."""
    top = next(x for x in api.get("/api/summary").json()["top_actions"] if x["ecosystem"] == "Windows" and asset_id in x["asset_ids"])
    r = api.post("/api/remediation/jobs", json={"asset_id": asset_id, "ecosystem": "Windows", "package": top["package"]})
    assert r.status_code == 201, r.text
    assert api.post(f"/api/remediation/jobs/{r.json()['id']}/approve").status_code == 200
    return r.json()["id"]


def jobs_by_id(api: Api) -> dict:
    return {j["id"]: j for j in api.get("/api/remediation/jobs").json()}


def drive_jobs(api: Api, jids: list[str], vms: list[dict], minutes=360) -> list[dict]:
    """Until every job is finished, keeping each host's installed task polling. Returns one status sample every 30 s."""
    samples, end, poked = [], time.time() + minutes * 60, 0
    while time.time() < end:
        try:
            jobs = jobs_by_id(api)
        except httpx.HTTPError:
            time.sleep(30)
            continue
        now = {j: jobs[j]["status"] for j in jids}
        if not samples or {k: v for k, v in samples[-1].items() if k != "t"} != now:
            h.note("jobs", **dict(zip([v["computer"] for v in vms], now.values(), strict=True)))
        samples.append({"t": int(time.time()), **now})
        if set(now.values()) <= DONE:
            return samples
        if time.time() - poked > 300:
            poked = time.time()
            for v in vms:
                try:
                    winvm.run(v["vm"], "Start-ScheduledTask -TaskName 'Nimstead jobs'", timeout=60)
                except subprocess.TimeoutExpired:  # mid-restart: its startup run picks the job up
                    pass
                winvm.unstick(v["vm"])
        time.sleep(30)
    raise TimeoutError(f"jobs not finished after {minutes} min: {samples[-1:]}")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    opts = dict(a[2:].split("=", 1) for a in sys.argv[2:] if a.startswith("--") and "=" in a)
    if cmd == "build":
        sys.exit(harness(lambda: build(sys.argv[2], vms=int(opts.get("vms", 3)), memory=int(opts.get("memory", VM_MB)), resume="--resume" in sys.argv),
                         "last_run_winlab.json"))
    elif cmd == "recheck":
        sys.exit(harness(recheck, "last_run_winlab.json"))
    elif cmd == "reset":
        reset()
    elif cmd == "utc-clock":
        utc_clock()
    elif cmd == "teardown":
        teardown()
    else:
        sys.exit(__doc__)
