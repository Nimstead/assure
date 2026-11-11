"""Devices seen on the fleet's networks with no agent, from each agent's own neighbour table (DECISIONS 128).

Passive: an agent reports addresses its machine already talked to; nothing here sends a packet, opens a finding or
starts a job. A host's key only writes that host's own rows (DECISIONS 27), so a compromised agent can at most add
noise to this list. Rows not seen for 30 days are dropped.
"""

import ipaddress
import re
from datetime import timedelta

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from nimstead import oui
from nimstead.db import Asset, Neighbour, now

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


def unmanaged(s: Session, org_id: str) -> list[dict]:
    """Devices the org's agents saw that are none of its agents, one row per MAC: addresses, maker, which hosts saw
    it, first and last seen. Matched by MAC first (DHCP moves addresses), then by any address an agent reports as its own."""
    hosts = {a.id: a for a in s.scalars(select(Asset).where(Asset.org_id == org_id, Asset.kind == "host"))}
    own_macs = {m for a in hosts.values() for m in (a.own_addresses or {}).get("macs", [])}
    own_ips = {ip for a in hosts.values() for ip in (a.own_addresses or {}).get("ips", [])}
    own_ips |= {ip for a in hosts.values() for ip in ((a.facts or {}).get("addresses") or []) if isinstance(ip, str)}  # Windows' own (DECISIONS 112)
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
    return [{**d, "addresses": sorted(d["addresses"], key=lambda a: (":" in a, a)), "seen_by": sorted(d["seen_by"]), "vendor": oui.vendor(m, names)}
            for m, d in sorted(by_mac.items(), key=lambda kv: kv[1]["last_seen"], reverse=True)]
