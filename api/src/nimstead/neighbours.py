"""Devices seen on the fleet's networks with no agent, from each agent's own neighbour table (DECISIONS 128).

Passive: an agent reports addresses its machine already talked to; nothing here sends a packet or starts a job. A host's
key only writes that host's own rows (DECISIONS 27), so a compromised agent can at most add noise to this list. Rows not
seen for 30 days are dropped.

A host opted in locally to network checks (DECISIONS 129) also sends what its fixed read-only checks observed on devices
it chose itself; record_checks judges those observations with the engine's evaluator and keeps findings on a `device`
asset per MAC.
"""

import base64
import hashlib
import ipaddress
import os
import re
from dataclasses import replace
from datetime import timedelta

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from nimstead import engine, evidence, external, oui
from nimstead.db import Asset, Finding, Neighbour, now
from nimstead.engine import network

KEEP = timedelta(days=30)
MAX_SEEN, MAX_OWN = 1024, 64
_MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def _ip(v) -> str | None:
    try:
        return str(ipaddress.ip_address(v)) if isinstance(v, str) and len(v) <= 45 else None
    except ValueError:
        return None


def _mac(v) -> str | None:
    return v if isinstance(v, str) and _MAC.match(v) else None


def store(s: Session, asset: Asset, sent) -> None:
    """Record what asset's agent sent as `neighbours` ({"seen": [{ip, mac, interface}], "own": {"ips", "macs"}}).

    Rows that don't fit are dropped, never the inventory; over the caps, the rest is ignored. None (an older agent, or
    one with the table turned off) changes nothing. The org's rows unseen for 30 days are deleted. No commit."""
    if not isinstance(sent, dict):
        return
    own = sent.get("own") if isinstance(sent.get("own"), dict) else {}
    asset.own_addresses = {"ips": [x for x in map(_ip, (own.get("ips") or [])[:MAX_OWN]) if x],
                           "macs": [x for x in map(_mac, (own.get("macs") or [])[:MAX_OWN]) if x]}
    t = now()
    rows = {}
    for r in (sent.get("seen") if isinstance(sent.get("seen"), list) else [])[:MAX_SEEN]:
        if isinstance(r, dict) and (ip := _ip(r.get("ip"))) and (mac := _mac(r.get("mac"))):
            rows[ip, mac] = str(r.get("interface") or "")[:64]
    have = {(n.ip, n.mac): n for n in s.scalars(select(Neighbour).where(Neighbour.asset_id == asset.id))}
    for (ip, mac), interface in rows.items():
        if n := have.get((ip, mac)):
            n.last_seen, n.interface = t, interface
        else:
            s.add(Neighbour(asset_id=asset.id, org_id=asset.org_id, ip=ip, mac=mac, interface=interface, first_seen=t, last_seen=t))
    s.execute(delete(Neighbour).where(Neighbour.org_id == asset.org_id, Neighbour.last_seen < t - KEEP))
    for d in s.scalars(select(Asset).where(Asset.org_id == asset.org_id, Asset.kind == "device", Asset.last_seen < t - KEEP)):
        s.execute(delete(Finding).where(Finding.asset_id == d.id))  # a device gone a month: its findings go with it, the ledger stays
        s.delete(d)


def _fleet(s: Session, org_id: str) -> tuple[dict, set, set]:
    """(the org's hosts by id, the MACs and the addresses its agents report as their own) - a device is none of these."""
    hosts = {a.id: a for a in s.scalars(select(Asset).where(Asset.org_id == org_id, Asset.kind == "host"))}
    own_macs = {m for a in hosts.values() for m in (a.own_addresses or {}).get("macs", [])}
    own_ips = {ip for a in hosts.values() for ip in (a.own_addresses or {}).get("ips", [])}
    own_ips |= {ip for a in hosts.values() for ip in ((a.facts or {}).get("addresses") or []) if isinstance(ip, str)}  # Windows' own (DECISIONS 112)
    return hosts, own_macs, own_ips


def unmanaged(s: Session, org_id: str) -> list[dict]:
    """Devices the org's agents saw that are none of its agents, one row per MAC: addresses, maker, which hosts saw
    it, first and last seen. Matched by MAC first (DHCP moves addresses), then by any address an agent reports as its own."""
    hosts, own_macs, own_ips = _fleet(s, org_id)
    cutoff = now() - KEEP
    by_mac: dict[str, dict] = {}
    for n in s.scalars(select(Neighbour).where(Neighbour.org_id == org_id, Neighbour.last_seen >= cutoff)):
        if n.mac in own_macs or n.asset_id not in hosts:
            continue
        d = by_mac.setdefault(n.mac, {"mac": n.mac, "addresses": set(), "seen_by": set(), "first_seen": n.first_seen, "last_seen": n.last_seen})
        d["addresses"].add(n.ip)
        d["seen_by"].add(hosts[n.asset_id].hostname)
        d["first_seen"], d["last_seen"] = min(d["first_seen"], n.first_seen), max(d["last_seen"], n.last_seen)
    by_mac = {m: d for m, d in by_mac.items() if not own_ips & d["addresses"]}  # any of its addresses an agent's own: it's that agent
    names = oui.vendors(s)
    devices = {(d.facts or {}).get("mac"): d for d in s.scalars(select(Asset).where(Asset.org_id == org_id, Asset.kind == "device"))}
    open_ids: dict[str, list[str]] = {}
    for aid, vid in s.execute(select(Finding.asset_id, Finding.vuln_id).where(
            Finding.org_id == org_id, Finding.status == "open", Finding.asset_id.in_([d.id for d in devices.values()]))):
        open_ids.setdefault(aid, []).append(vid)
    return [{**d, "addresses": sorted(d["addresses"], key=lambda a: (":" in a, a)), "seen_by": sorted(d["seen_by"]),
             "vendor": oui.vendor(m, names), "checked": _checked(devices.get(m), open_ids)}
            for m, d in sorted(by_mac.items(), key=lambda kv: kv[1]["last_seen"], reverse=True)]


def _checked(device: Asset | None, open_ids: dict) -> dict | None:
    """When and from where this device was last checked, its asset id and its open findings; None if never checked."""
    if device is None:
        return None
    return {"asset_id": device.id, "at": device.last_seen, "from": (device.facts or {}).get("checked_from", ""),
            "open": sorted(open_ids.get(device.id, []))}


# --- network checks from one opted-in agent (DECISIONS 129) ----------------------------------------------------------

RFC1918 = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
MAX_CHECKED = 32
MAX_DEVICES_PER_ORG = 4096  # devices aren't counted against the asset quota, so they have their own cap
ECOSYSTEM = "Network"
# On a LAN an open SMB, RDP or database port is normal; these answer without a password or in cleartext by default
INTERNAL_EXPOSED = {f"NIM-EXPOSED-{c}" for c in ("TELNET", "FTP", "VNC", "REDIS", "ELASTICSEARCH", "MONGODB", "MEMCACHED", "DOCKER")}
PORTS = sorted(set(external.SERVICES) | {external.TLS_PORT, 80, *network.BANNER_PORTS})


class _Replay(network.Prober):
    """The prober's web checks answered from what the agent recorded: each fixed path as recorded, any other path (the
    prober's own random control) with the agent's control. A fixed path the agent didn't record got no response."""
    def __init__(self, ip: str, http: dict):
        super().__init__(ip, ip)
        self.http = http

    def _http_get(self, port, path, deadline):
        fixed = path in {r.path for r in network.WEB_RULES}
        status, body = self.http.get(path if fixed else "control") or [None, b""]  # missing: no response, so it can't close anything
        return status, body


def _b64(v, limit: int) -> bytes:
    try:
        return base64.b64decode(v or "", validate=True)[:limit] if isinstance(v, str) and len(v) <= limit * 2 else b""
    except ValueError:
        return b""


def _tls(obs) -> dict:
    """external.tls_probe's facts from the agent's certificate. Trust and name aren't judged inside a network: devices
    there are usually self-signed and reached by address, so only expiry and legacy TLS can become findings."""
    from cryptography import x509
    der = _b64(obs.get("der"), 16384) if isinstance(obs, dict) else b""
    try:
        not_after = x509.load_der_x509_certificate(der).not_valid_after_utc.timestamp() if der else None
    except ValueError:
        not_after = None
    if not_after is None:  # lost: the agent's handshake was cut or timed out, which isn't evidence of anything
        return {"trusted": None, "error": "no TLS handshake", "not_after": None, "legacy": None, "lost": not isinstance(obs, dict) or obs.get("lost") is not False}
    legacy = obs.get("legacy") if obs.get("legacy") in (True, False) else None
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
    recorded = {k: [v[0] if isinstance(v[0], int) else None, _b64(v[1], 4096)] for k, v in http.items()
                if k in ("control", *(r.path for r in network.WEB_RULES)) and isinstance(v, list) and len(v) == 2}
    verdicts = [v for v in network.evaluate(_Replay(ip, recorded), endpoints)
                if not (v.vuln_id or "").startswith("NIM-EXPOSED-") or v.vuln_id in INTERNAL_EXPOSED]
    verdicts = [replace(v, summary=v.summary.replace("is reachable from the internet.", "answers on your network."))
                if v.summary and v.vuln_id in INTERNAL_EXPOSED else v for v in verdicts]
    rep = network.build_report(ip, ip, verdicts, endpoints, [], all(e.state == "filtered" for e in endpoints.values()))
    rep["requests"] = [f"GET :80{p}" for p in recorded]
    return verdicts, rep


def record_checks(s: Session, asset: Asset, devices) -> dict:
    """Judge what asset's agent observed on devices it chose (DECISIONS 129) and update each device's findings; no commit.

    A device counts only if it is in this host's own stored neighbour rows (same address and MAC) and in a private IPv4
    range, and isn't one of the org's own machines (it has an agent, so it's judged from that); anything else is dropped
    and counted as refused. Each check goes to the ledger with the host that made it."""
    mine = {(n.ip, n.mac) for n in s.scalars(select(Neighbour).where(Neighbour.asset_id == asset.id))}
    _, own_macs, own_ips = _fleet(s, asset.org_id)
    known = {(d.facts or {}).get("mac"): d for d in s.scalars(select(Asset).where(Asset.org_id == asset.org_id, Asset.kind == "device"))}
    names = oui.vendors(s)
    checked = refused = opened = 0
    for obs in (devices if isinstance(devices, list) else [])[:MAX_CHECKED]:
        ip, mac = (_ip(obs.get("ip")), _mac(obs.get("mac"))) if isinstance(obs, dict) else (None, None)
        if (not ip or not mac or (ip, mac) not in mine or not any(ipaddress.ip_address(ip) in n for n in RFC1918)
                or mac in own_macs or ip in own_ips):
            refused += 1
            continue
        device = known.get(mac)
        if device is None:
            if len(known) >= MAX_DEVICES_PER_ORG:
                refused += 1
                continue
            device = Asset(org_id=asset.org_id, hostname=ip, kind="device", internet_facing=False,
                           agent_key_hash=hashlib.sha256(os.urandom(32)).hexdigest())  # no agent: no key is ever handed out
            s.add(device)
            s.flush()
            known[mac] = device
            evidence.append(s, asset.org_id, "asset_created", device.id, {"by": asset.hostname, "name": ip, "kind": "device"})
        vendor = oui.vendor(mac, names)
        device.hostname, device.os_name = ip, vendor or "Network device"
        device.facts = {"mac": mac, "vendor": vendor, "checked_from": asset.hostname}
        verdicts, rep = _observe({**obs, "ip": ip})
        engine.record(s, device, rep, {"address": ip, "mac": mac, "from": asset.hostname})
        seen, _, _ = external.apply(s, device, verdicts, rep, ECOSYSTEM)
        evidence.append(s, asset.org_id, "network_check", device.id, {"from": asset.hostname, "address": ip, "mac": mac,
                                                                      "problems": sorted({v for v, _ in seen}), "requests": rep["requests"]})
        checked += 1
        opened += len(seen)
    return {"checked": checked, "refused": refused, "open": opened}
