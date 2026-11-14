"""Devices seen on the fleet's networks with no agent, from each agent's own neighbour table (DECISIONS 128).

Passive: an agent reports addresses its machine already talked to; nothing here sends a packet or starts a job. A host's
key only writes that host's own rows (DECISIONS 27); what a compromised agent can still do here is in DECISIONS 130-131.
Rows not seen for 30 days are dropped.

A host opted in locally to network checks (DECISIONS 129) also sends what its fixed read-only checks observed on devices
it chose itself; record_checks judges those observations with the engine's evaluator and keeps findings on a `device`
asset per MAC.
"""

import base64
import hashlib
import ipaddress
import json
import os
import re
from collections import Counter
from dataclasses import replace
from datetime import timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from nimstead import engine, evidence, external, oui
from nimstead.db import Asset, Finding, Neighbour, now
from nimstead.engine import network

KEEP = timedelta(days=30)
MAX_SEEN, MAX_OWN = 1024, 64
MAX_STORED_PER_HOST = 2048  # rotating IPv6 and randomised MACs would otherwise grow a host's rows for 30 days
MAX_NEIGHBOURS_PER_ORG = 65536  # one org on a shared server stores no more; past it, known rows still refresh
_MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def _ip(v) -> str | None:
    try:
        return str(ipaddress.ip_address(v)) if isinstance(v, str) and len(v) <= 45 else None
    except ValueError:
        return None


def _mac(v) -> str | None:
    return v if isinstance(v, str) and _MAC.match(v) else None


def _list(v) -> list:
    return v if isinstance(v, list) else []


def store(s: Session, asset: Asset, sent) -> None:
    """Record what asset's agent sent as `neighbours` ({"seen": [{ip, mac, interface}], "own": {"ips", "macs"}}).

    Rows that don't fit are dropped, never the inventory; over the caps, the rest is ignored: at most MAX_SEEN a report,
    the newest MAX_STORED_PER_HOST kept per host, no new rows past MAX_NEIGHBOURS_PER_ORG. None (an older agent, or one
    with the table turned off) changes nothing. prune(), from the hourly run, deletes what's 30 days old. No commit."""
    if not isinstance(sent, dict):
        return
    own = sent.get("own") if isinstance(sent.get("own"), dict) else {}
    asset.own_addresses = {"ips": [x for x in map(_ip, _list(own.get("ips"))[:MAX_OWN]) if x],
                           "macs": [x for x in map(_mac, _list(own.get("macs"))[:MAX_OWN]) if x]}
    t = now()
    rows = {}
    for r in _list(sent.get("seen"))[:MAX_SEEN]:
        if isinstance(r, dict) and (ip := _ip(r.get("ip"))) and (mac := _mac(r.get("mac"))):
            rows[ip, mac] = str(r.get("interface") or "")[:64]
    have = {(n.ip, n.mac): n for n in s.scalars(select(Neighbour).where(Neighbour.asset_id == asset.id))}
    room = MAX_NEIGHBOURS_PER_ORG - s.scalar(select(func.count()).select_from(Neighbour).where(Neighbour.org_id == asset.org_id))
    for (ip, mac), interface in rows.items():
        if n := have.get((ip, mac)):
            n.last_seen, n.interface = t, interface
        elif room > 0:
            s.add(Neighbour(asset_id=asset.id, org_id=asset.org_id, ip=ip, mac=mac, interface=interface, first_seen=t, last_seen=t))
            room -= 1
    s.flush()
    old = s.execute(select(Neighbour.ip, Neighbour.mac).where(Neighbour.asset_id == asset.id)
                    .order_by(Neighbour.last_seen.desc(), Neighbour.ip).offset(MAX_STORED_PER_HOST)).all()
    for ip, mac in old:
        s.execute(delete(Neighbour).where(Neighbour.asset_id == asset.id, Neighbour.ip == ip, Neighbour.mac == mac))


def prune(s: Session) -> dict:
    """The hourly run's clean-up for every org: neighbour rows and devices unseen for 30 days go (a device's findings
    with it; the ledger stays). It runs whether or not an org's agents still report. No commit."""
    cutoff = now() - KEEP
    rows = s.execute(delete(Neighbour).where(Neighbour.last_seen < cutoff)).rowcount
    gone = list(s.scalars(select(Asset).where(Asset.kind == "device", Asset.last_seen < cutoff)))
    for d in gone:
        s.execute(delete(Finding).where(Finding.asset_id == d.id))
        s.delete(d)
    return {"neighbours": rows, "devices": len(gone)}


class Fleet:
    """Who the org's own machines are, for telling them from devices (ship review).

    claims: MAC -> the addresses of every host that says that MAC is its own. A claim counts only where the MAC was seen
    at one of those addresses, so a host can't hide a device by naming its MAC alone. fallback: addresses of hosts that
    report no MACs of their own, matched against a device's latest address only, so an address it held last week doesn't
    hide it. Only a host that never sent the table (an agent before 0.7.0, or one with it off) is taken from its `addresses`
    fact (Windows, DECISIONS 112), and no host counts for more than MAX_OWN addresses either way (ship review 2). A fallback
    address hides only the MAC seen there most recently, so it hides one device, however many MACs a host reports at it
    (ship review 3)."""
    def __init__(self, s: Session, org_id: str):
        rows = s.execute(select(Asset.id, Asset.hostname, Asset.own_addresses).where(Asset.org_id == org_id, Asset.kind == "host")).all()
        self.hosts = {aid: hostname for aid, hostname, _ in rows}
        self.claims: dict[str, set[str]] = {}
        self.fallback: set[str] = set()
        older = []
        for aid, _, own in rows:
            ips, macs = set((own or {}).get("ips", [])), (own or {}).get("macs", [])
            for m in macs:
                self.claims.setdefault(m, set()).update(ips)
            if not macs:
                self.fallback |= ips
            if own is None:
                older.append(aid)
        for facts in s.scalars(select(Asset.facts).where(Asset.id.in_(older))) if older else ():
            self.fallback |= {ip for ip in ((facts or {}).get("addresses") or [])[:MAX_OWN] if isinstance(ip, str)}
        self.newest_at: dict[str, str] = {}  # fallback address -> the MAC seen there most recently
        ips = sorted(self.fallback)
        for i in range(0, len(ips), 500):  # in chunks: SQLite allows only so many bound values
            for ip, mac in s.execute(select(Neighbour.ip, Neighbour.mac).where(Neighbour.org_id == org_id, Neighbour.ip.in_(ips[i:i + 500]))
                                     .order_by(Neighbour.last_seen, Neighbour.mac)):
                self.newest_at[ip] = mac

    def owns(self, mac: str, addresses: set[str], latest: str) -> bool:
        """Whether a MAC seen at these addresses (latest the newest) is one of the org's own machines."""
        return bool(self.claims.get(mac, set()) & addresses) or self.newest_at.get(latest) == mac


def unmanaged(s: Session, org_id: str) -> list[dict]:
    """Devices the org's agents saw that are none of its agents (Fleet.owns), one row per MAC: addresses, maker, which
    hosts saw it, first and last seen, and what network checks found on it."""
    fleet = Fleet(s, org_id)
    by_mac: dict[str, dict] = {}
    for aid, ip, mac, first, last in s.execute(select(Neighbour.asset_id, Neighbour.ip, Neighbour.mac, Neighbour.first_seen, Neighbour.last_seen)
                                               .where(Neighbour.org_id == org_id, Neighbour.last_seen >= now() - KEEP)):
        if aid not in fleet.hosts:
            continue
        d = by_mac.setdefault(mac, {"mac": mac, "addresses": set(), "seen_by": set(), "first_seen": first, "last_seen": last, "latest": ip})
        d["addresses"].add(ip)
        d["seen_by"].add(fleet.hosts[aid])
        if last >= d["last_seen"]:
            d["latest"] = ip
        d["first_seen"], d["last_seen"] = min(d["first_seen"], first), max(d["last_seen"], last)
    by_mac = {m: d for m, d in by_mac.items() if not fleet.owns(m, d["addresses"], d.pop("latest"))}
    names = oui.vendors(s)
    views: dict[str, list[Asset]] = {}
    for d in s.scalars(select(Asset).where(Asset.org_id == org_id, Asset.kind == "device")):
        views.setdefault((d.facts or {}).get("mac"), []).append(d)
    open_ids: dict[str, list[str]] = {}
    worst_of: dict[str, str] = {}  # each view's most urgent open priority, so the list can rank a device as it ranks a machine
    ids = [v.id for vs in views.values() for v in vs]
    for aid, vid, prio in s.execute(select(Finding.asset_id, Finding.vuln_id, Finding.priority).where(Finding.org_id == org_id, Finding.status == "open",
                                                                          Finding.asset_id.in_(ids))) if ids else ():
        open_ids.setdefault(aid, []).append(vid)
        if RANK.get(prio, 9) < RANK.get(worst_of.get(aid, ""), 9):
            worst_of[aid] = prio
    return [{**d, "addresses": sorted(d["addresses"], key=lambda a: (":" in a, a)), "seen_by": sorted(d["seen_by"]),
             "vendor": oui.vendor(m, names), "checked": _checked(views.get(m, []), open_ids, worst_of)}
            for m, d in sorted(by_mac.items(), key=lambda kv: kv[1]["last_seen"], reverse=True)]


RANK = {"fix-now": 0, "next": 1, "planned": 2, "low": 3}


def _checked(views: list[Asset], open_ids: dict, worst_of: dict | None = None) -> dict | None:
    """What network checks found on a device, across every machine that checked it (each keeps its own view): when last,
    from which machines, the open findings, and the view with the most to link to. None if no machine checked it."""
    if not views:
        return None
    worst = max(views, key=lambda v: (len(open_ids.get(v.id, [])), v.last_seen))
    return {"asset_id": worst.id, "at": max(v.last_seen for v in views),
            "from": ", ".join(sorted((v.facts or {}).get("checked_from", "") for v in views)),
            "open": sorted({vid for v in views for vid in open_ids.get(v.id, [])}),
            "priority": min((p for v in views if (p := (worst_of or {}).get(v.id))), key=lambda p: RANK[p], default=None)}


# --- network checks from one opted-in agent (DECISIONS 129) ----------------------------------------------------------

RFC1918 = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
MAX_CHECKED = 32
MAX_DEVICES_PER_ORG = 4096  # devices aren't counted against the asset quota, so they have their own cap
MAX_DEVICES_PER_HOST = 256  # one host checks only its own subnets: it can't take the whole org's share (ship review 3)
ECOSYSTEM = "Network"
# On a LAN an open SMB, RDP or database port is normal; these answer without a password or in cleartext by default
INTERNAL_EXPOSED = {f"NIM-EXPOSED-{c}" for c in ("TELNET", "FTP", "VNC", "REDIS", "ELASTICSEARCH", "MONGODB", "MEMCACHED", "DOCKER")}
PORTS = sorted(set(external.SERVICES) | {external.TLS_PORT, 80, *network.BANNER_PORTS})


NO_RESPONSE = (None, None, "", False)
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class _Replay(network.Prober):
    """The prober's checks answered from what the agent recorded, never from the network: each fixed web path's facts as
    the agent judged them, any other path (the prober's own random control) with the agent's control. A fixed path the
    agent didn't record, or recorded in a form the server can't read, got no response. Web findings are named by port,
    so a device that moves address keeps them."""
    def __init__(self, ip: str, http: dict):
        super().__init__(ip, ip)
        self.http, self.web_base = http, "tcp/80 "

    def web_fact(self, port, path, marker, deadline):
        return self.http.get(path if path in {r.path for r in network.WEB_RULES} else "control", NO_RESPONSE)

    def _exchange(self, *a, **k):
        raise RuntimeError("a replay never connects: the server judges what the agent saw")


def _web_fact(v) -> tuple:
    """One web fact the agent sent ([status, marker matched or null, body SHA-256, had content]), or NO_RESPONSE if it
    doesn't have exactly that shape: unread is never an empty page (R4.6)."""
    if not (isinstance(v, list) and len(v) == 4):
        return NO_RESPONSE
    status, hit, digest, content = v
    ok = ((status is None or (type(status) is int and 100 <= status <= 599)) and (hit is None or type(hit) is bool)
          and isinstance(digest, str) and _DIGEST.match(digest) and type(content) is bool)  # 0 == False, but isn't an answer
    return (status, hit, digest, content) if ok else NO_RESPONSE


def _b64(v, limit: int) -> bytes:
    try:
        return base64.b64decode(v or "", validate=True)[:limit] if isinstance(v, str) and len(v) <= limit * 2 else b""
    except ValueError:
        return b""


def _tls(obs) -> dict:
    """external.tls_probe's facts from the agent's certificate. Trust and name aren't judged inside a network: devices
    there are usually self-signed and reached by address, so only expiry and legacy TLS can become findings."""
    from cryptography import x509
    obs = obs if isinstance(obs, dict) else {}
    der = _b64(obs.get("der"), 16384)
    try:
        not_after = x509.load_der_x509_certificate(der).not_valid_after_utc.timestamp() if der else None
    except ValueError:
        not_after = None
    legacy = obs.get("legacy") if type(obs.get("legacy")) is bool else None  # 0 in (True, False) is True (ship review 3)
    if not_after is None:  # lost unless the agent reached a service that wasn't TLS: a cut handshake, or a certificate sent but unreadable
        return {"trusted": None, "error": "no TLS handshake", "not_after": None, "legacy": legacy, "lost": bool(obs.get("der")) or obs.get("lost") is not False}
    return {"trusted": True, "error": None, "not_after": not_after, "legacy": legacy}


def _observe(obs: dict) -> tuple[list, dict]:
    """(verdicts, report) for one device's observations, through the engine's own evaluator."""
    ip, ports = obs["ip"], obs.get("ports") if isinstance(obs.get("ports"), dict) else {}
    endpoints = {}
    for p in PORTS:
        r = ports.get(str(p)) if isinstance(ports.get(str(p)), dict) else {}
        e = network.Endpoint(p, r.get("state") if r.get("state") in ("open", "closed", "filtered") else "filtered")
        if e.state == "open" and p in network.BANNER_PORTS:
            e.banner, e.reflects = _b64(r.get("banner"), 512), r.get("reflects") is True
        endpoints[p] = e
    if endpoints[external.TLS_PORT].state == "open":
        endpoints[external.TLS_PORT].tls = _tls(obs.get("tls"))
    http = obs.get("http") if isinstance(obs.get("http"), dict) else {}
    recorded = {k: _web_fact(http[k]) for k in ("control", *(r.path for r in network.WEB_RULES)) if k in http}
    verdicts = [v for v in network.evaluate(_Replay(ip, recorded), endpoints)
                if not (v.vuln_id or "").startswith("NIM-EXPOSED-") or v.vuln_id in INTERNAL_EXPOSED]
    verdicts = [replace(v, summary=_on_network(v.summary)) if v.summary else v for v in verdicts]
    rep = network.build_report(ip, ip, verdicts, endpoints, [], all(e.state == "filtered" for e in endpoints.values()))
    rep = json.loads(_on_network(json.dumps(rep)))  # the engine's wording is for internet targets: every field, not only summaries
    rep["requests"] = ["GET :80 (a path that can't exist)" if k == "control" else f"GET :80{k}" for k in recorded]
    return verdicts, rep


_WORDING = (("is reachable from the internet.", "answers on your network."), ("not reachable from the internet", "not reachable on your network"),
            ("open to the internet", "open on your network"), ("served to the internet", "served on your network"),
            ("external target ", "device "))


def _on_network(text: str) -> str:
    for internet, lan in _WORDING:
        text = text.replace(internet, lan)
    return text


def record_checks(s: Session, asset: Asset, devices) -> dict:
    """Judge what asset's agent observed on devices it chose (DECISIONS 129) and update each device's findings; no commit.

    A device counts only if it is in this host's own stored neighbour rows (same address and MAC) and in a private IPv4
    range, and isn't one of the org's own machines (it has an agent, so it's judged from that); anything else is dropped
    and counted as refused. So is a MAC this host sees at more than one address (an extender or proxy ARP puts one MAC on
    several devices, and one's evidence mustn't close another's finding; ship review 3), and a new device past this host's
    MAX_DEVICES_PER_HOST or the org's cap. One ledger entry per report lists what each device's check found."""
    s.execute(select(Asset.id).where(Asset.id == asset.id).with_for_update())  # one host's reports one at a time: no device made twice
    rows = list(s.scalars(select(Neighbour).where(Neighbour.asset_id == asset.id)))
    mine = {(n.ip, n.mac) for n in rows}
    newest = max((n.last_seen for n in rows), default=None)  # the latest table only: a DHCP move leaves the old row for 30 days
    addresses_of = Counter(n.mac for n in rows if n.last_seen == newest)
    fleet = Fleet(s, asset.org_id)
    org_devices = list(s.scalars(select(Asset).where(Asset.org_id == asset.org_id, Asset.kind == "device")))
    known = {(d.facts or {}).get("mac"): d for d in org_devices if (d.facts or {}).get("checked_by") == asset.id}  # this host's own views
    names = oui.vendors(s)
    checked = refused = opened = 0
    ledger = []
    for obs in (devices if isinstance(devices, list) else [])[:MAX_CHECKED]:
        ip, mac = (_ip(obs.get("ip")), _mac(obs.get("mac"))) if isinstance(obs, dict) else (None, None)
        if (not ip or not mac or (ip, mac) not in mine or not any(ipaddress.ip_address(ip) in n for n in RFC1918)
                or addresses_of[mac] > 1 or fleet.owns(mac, {ip}, ip)):
            refused += 1
            continue
        device = known.get(mac)
        if device is None:
            if len(org_devices) >= MAX_DEVICES_PER_ORG or len(known) >= MAX_DEVICES_PER_HOST:
                refused += 1
                continue
            device = Asset(org_id=asset.org_id, hostname=ip, kind="device", internet_facing=False,
                           agent_key_hash=hashlib.sha256(os.urandom(32)).hexdigest())  # no agent: no key is ever handed out
            s.add(device)
            s.flush()
            known[mac] = device
            org_devices.append(device)
            evidence.append(s, asset.org_id, "asset_created", device.id, {"by": asset.hostname, "name": "device", "kind": "device"})
        vendor = oui.vendor(mac, names)
        device.hostname, device.os_name = ip, f"{vendor or 'Network device'}, as checked from {asset.hostname}"[:255]  # one view per machine
        device.facts = {"mac": mac, "vendor": vendor, "checked_from": asset.hostname, "checked_by": asset.id}
        verdicts, rep = _observe({**obs, "ip": ip})
        engine.record(s, device, rep, {"address": ip, "mac": mac, "from": asset.hostname})
        seen, _, _ = external.apply(s, device, verdicts, rep, ECOSYSTEM)
        # no address or MAC: they can be personal data, kept on the device row (gone after 30 days), not in the permanent ledger
        ledger.append({"device": device.id, "problems": sorted({v for v, _ in seen}), "requests": rep["requests"]})
        checked += 1
        opened += len(seen)
    if ledger:
        evidence.append(s, asset.org_id, "network_check", asset.id, {"from": asset.hostname, "devices": ledger})
    return {"checked": checked, "refused": refused, "open": opened}
