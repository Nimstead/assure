"""What runs on a host (tasks/spec-runtime.md Module 2, DECISIONS 161): the agent's latest read of its programs, seven days of
memory of which packages they were seen loading, and each package's state for ranking, filtering and holding a fix open
until the program running the old copy restarts.

A read is a sample taken at each report. A package seen loaded stays "loaded" for seven days from the last read that saw
it, and "listening" for seven days from the last read that saw it loaded by a program listening on a non-loopback address,
so programs coming and going between reports don't flap a finding's rank. "Not loaded" needs a package that ships native
code (only native code is mapped where the agent can see it), complete reads covering the last seven days with no gap over
a day and a half, and none of them seeing it loaded. Everything else is unknown.
"""

import ipaddress
import json
import re
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from nimstead.db import Asset, AssetRuntime, InstalledPackage, now

MEMORY = timedelta(days=7)
GAP = timedelta(hours=36)  # complete reads further apart than this start the seven days again: a missed 6-hourly report,
# or a host scheduled daily, doesn't
STALE = GAP  # a latest complete read older than this concludes nothing new about "not loaded"; as long as GAP, so a host
# reporting daily never drops to unknown between reports (code review)
# Sized to honest hosts, not to the agent's own caps (security audit: a 1 MB body once made a 51 MB row): a busy server runs a
# few hundred programs loading a few thousand packages
PROGRAMS, LOADS, NATIVE, SEEN, REPLACED = 1024, 100_000, 50_000, 5_000, 2_000
BODY_MAX = 4 * 1024 * 1024  # a read larger than this once reduced isn't stored, as facts that don't fit aren't
STATES = ("listening", "loaded", "not_loaded", "restart")
RESTART = "Still open: "  # the held-open reason's prefix, shared with phase 4's (scan._held_open)
_NET_SHOWN, _BY = 4, 3
# what a host may name, in the agent's own character sets: names reach finding reasons, the UI and AI prompts
_NAME = re.compile(r"[A-Za-z0-9._@:+() \\-]{1,100}")
_PKG = re.compile(r"[A-Za-z0-9._+:~@-]{1,128}")
_ADDR = re.compile(r"[0-9A-Fa-f.:\[\]%/a-z-]{1,64}")
# the services an automated fix never restarts: the agent's own RESTART_NEVER, copied (test_runtime checks they're the same)
RESTART_NEVER = re.compile(r"(?:systemd-.*|dbus.*|getty@.*|serial-getty@.*|console-getty|container-getty@.*|user@.*|user-runtime-dir@.*|elogind"
                           r"|(?:gdm|gdm3|kdm|nodm|sddm|wdm|xdm|lightdm|slim|lxdm|display-manager)"
                           r"|network.*|NetworkManager.*|ModemManager|wpa_supplicant.*|iwd|openvpn.*|wg-quick@.*|(?:open|free|libre|strong)swan.*"
                           r"|ifup@.*|ifupdown.*|wicked.*|dhcpcd.*|dhclient.*|connman.*|ovs-vswitchd|ovsdb-server|openvswitch.*|tailscaled|zerotier-one"
                           r"|bird.*|quagga|frr|tinc.*|bluetooth|corosync|pacemaker|sbd|keepalived"
                           r"|docker.*|containerd|crio|podman.*|kubelet|k3s.*|rke2.*|lxcfs|libvirt.*|virtlogd|virtlockd|xendomains"
                           r"|emergency|rescue|cloud-init.*|rc-local|unattended-upgrades|apt-daily.*|auditd|nimstead.*)\.service\Z")
# a kernel's source, or a source with a kernel binary: the engine's running-kernel rule judges these, never runtime (code review)
_KERNEL_SOURCE = re.compile(r"kernel(?:-.*)?|linux(?:-signed.*|-hwe.*|-(?:lts|virt|edge|rpi\d*|aws|azure|gcp|oracle|kvm|lowlatency|raspi|ibm|nvidia)(?:-.*)?)?")
_KERNEL_BINARY = re.compile(r"kernel(?:-.*)?|linux-(?:image|modules|headers|tools|cloud-tools|buildinfo|perf|lts|virt|edge|rpi\d*)(?:-.*)?")


def is_kernel(source: str, binaries: list[str]) -> bool:
    """Whether a source package is a kernel, by its own name or any of its binaries' (linux-image-*, kernel-tools-libs)."""
    return bool(_KERNEL_SOURCE.fullmatch(source or "") or any(_KERNEL_BINARY.fullmatch(b or "") for b in binaries))


def _text(v, n: int) -> str | None:
    return v[:n] if isinstance(v, str) and v else None


def _strs(v, count: int, pattern: re.Pattern) -> list[str]:
    """Up to count distinct strings from list v that the pattern accepts whole, sorted; anything else is dropped."""
    return sorted({x for x in v[:count] if isinstance(x, str) and pattern.fullmatch(x)})[:count] if isinstance(v, list) else []


def valid(raw) -> dict | None:
    """The agent's runtime object reduced to what fits, or None when it isn't one: unknown keys dropped, names in the agent's
    own character sets and lengths, lists bounded, the whole under BODY_MAX, as neighbours.store treats its rows and facts_ok
    its facts. Never raises on any JSON value."""
    if not isinstance(raw, dict) or raw.get("v") != 1 or raw.get("state") not in ("ok", "partial", "failed"):
        return None
    programs, pairs = [], 0
    for p in raw.get("programs")[:PROGRAMS] if isinstance(raw.get("programs"), list) else []:
        if not (isinstance(p, dict) and isinstance(p.get("name"), str) and _NAME.fullmatch(p["name"])):
            continue
        loads = _strs(p.get("loads"), max(0, LOADS - pairs), _PKG)
        pairs += len(loads)
        count, loaded = p.get("count"), set(loads)
        programs.append({"name": p["name"], "unit": p.get("unit") is True, "users": _strs(p.get("users"), 8, _NAME),
                         "count": count if isinstance(count, int) and not isinstance(count, bool) and 0 < count < 1_000_000 else 1,
                         "listen": _strs(p.get("listen"), 32, _ADDR), "loads": loads,
                         "replaced": [x for x in _strs(p.get("replaced"), 5000, _PKG) if x in loaded]})  # a replaced copy is loaded
    other = raw.get("other_roots")
    out = {"state": raw["state"], "problem": _text(raw.get("problem"), 300), "programs": programs, "native": _strs(raw.get("native"), NATIVE, _PKG),
           "other_roots": other if isinstance(other, int) and not isinstance(other, bool) and 0 <= other < 1_000_000 else 0}
    return out if len(json.dumps(out)) <= BODY_MAX else None


def network_address(where: str) -> bool:
    """Whether a listening address ("0.0.0.0:443/tcp", "[::1]:53/udp") is reachable from other machines: anything but loopback.
    An address that doesn't parse counts as reachable (the cautious reading)."""
    host = where.rsplit(":", 1)[0].strip("[]")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return True
    return not (ip.is_loopback or (ip.version == 6 and ip.ipv4_mapped is not None and ip.ipv4_mapped.is_loopback))


def _at(v) -> datetime | None:
    try:
        return datetime.fromisoformat(v) if isinstance(v, str) else None
    except ValueError:
        return None


def store(s: Session, asset: Asset, raw, t: datetime | None = None) -> AssetRuntime | None:
    """Record one read for host asset and update the seven-day memory; returns the row, or None when raw isn't a read (the
    stored row, if any, is then left as it was). A read that isn't complete concludes nothing from what it didn't see: the
    replaced copies of programs it didn't read are kept, and the native list stays the last complete read's. The caller commits."""
    rt = valid(raw)
    if rt is None:
        return None
    t = t or now()
    row = s.get(AssetRuntime, asset.id)
    if row is None:
        row = AssetRuntime(asset_id=asset.id, org_id=asset.org_id, seen={}, since=None, last_complete=None, replaced={}, native=[])
        s.add(row)
    cut, stamp = t - MEMORY, t.isoformat()
    seen = {}
    for pkg, e in (row.seen or {}).items():  # forget what no read has shown for seven days
        at, net = _at(e.get("at")), _at(e.get("net"))
        if at and at > cut:
            seen[pkg] = {**e, **({} if net and net > cut else {"net": None, "net_by": []})}
    for p in rt["programs"]:
        net = [a for a in p["listen"] if network_address(a)]
        for pkg in p["loads"]:
            e = seen.setdefault(pkg, {"net": None, "net_by": []})
            e["at"] = stamp
            e["by"] = sorted({*([] if e.get("read") != stamp else e.get("by", [])), p["name"]})[:_BY]
            e["read"] = stamp
            if net:
                byers = [x for x in (e.get("net_by") or []) if e.get("net") == stamp and x[0] != p["name"]]
                e["net"], e["net_by"] = stamp, sorted([*byers, [p["name"], net[:_NET_SHOWN]]])[:_BY]
    if len(seen) > SEEN:  # an honest host loads a few thousand packages at most
        seen = dict(sorted(seen.items(), key=lambda kv: kv[1]["at"], reverse=True)[:SEEN])
    complete = rt["state"] == "ok"
    if complete:
        if row.last_complete is None or t - row.last_complete > GAP:
            row.since = t
        row.last_complete = t
    before = dict(row.replaced or {})
    replaced: dict[str, dict] = {}  # binary -> its source and the programs running a replaced copy
    for p in rt["programs"]:
        for pkg in p["replaced"]:
            replaced.setdefault(pkg, {"programs": []})["programs"].append(p["name"])
    if not complete:  # a program this read didn't see may still run its old copy (code review): keep what was last seen of it
        read_names = {p["name"] for p in rt["programs"]}
        for b, r in before.items():
            kept = [x for x in r.get("programs", []) if x not in read_names]
            if kept:
                replaced.setdefault(b, {"programs": []})["programs"].extend(kept)
                replaced[b].setdefault("source", r.get("source"))
    if replaced:  # each binary's source: as first recorded (a removed package's rows go with the report), else the inventory's
        fresh = [b for b in replaced if not (before.get(b) or {}).get("source")]
        sources = dict(s.execute(select(InstalledPackage.name, InstalledPackage.source).where(
            InstalledPackage.asset_id == asset.id, InstalledPackage.ecosystem == asset.ecosystem, InstalledPackage.name.in_(fresh))).all()) if fresh else {}
        for b, r in replaced.items():
            r["source"] = (before.get(b) or {}).get("source") or sources.get(b) or b
    replaced = dict(sorted(replaced.items())[:REPLACED])
    row.read_at, row.state, row.problem = t, rt["state"], rt["problem"]
    row.programs, row.seen = rt["programs"], seen
    if complete or not row.native:  # a read cut short may not have reached the lists: keep the last complete read's
        row.native = rt["native"]
    row.replaced = {k: {"source": v["source"], "programs": sorted(set(v["programs"]))[:10]} for k, v in replaced.items()}
    row.replaced_count = len(row.replaced)
    return row


def forget_replaced(s: Session, asset: Asset) -> None:
    """The host stopped reading what runs (opted out): no sighting holds anything any more. The memory ages out as usual."""
    row = s.get(AssetRuntime, asset.id)
    if row is not None and row.replaced_count:
        row.replaced, row.replaced_count = {}, 0


class View:
    """One host's runtime for one rescan or drawer: each package's state and the words for it. Findings on a distribution are
    keyed by source package (openssl) and the agent's lists name binaries (libssl3t64), so each question takes the binaries
    of one source and answers for the most exposed of them."""

    def __init__(self, row: AssetRuntime | None, t: datetime | None = None):
        self.row, self.t = row, t or now()
        self.native = set(row.native or []) if row else set()

    def _one(self, pkg: str) -> str | None:
        row, t = self.row, self.t
        e = (row.seen or {}).get(pkg)
        if e and (net := _at(e.get("net"))) and net > t - MEMORY:
            return "listening"
        if e and (at := _at(e.get("at"))) and at > t - MEMORY:
            return "loaded"
        if pkg in self.native and covered(row, t):
            return "not_loaded"
        return None

    def state(self, binaries: list[str]) -> tuple[str | None, str | None]:
        """(state, binary): listening, loaded or not_loaded for the most exposed of a source's installed binaries, by the module
        docstring's rules, and which binary it is; (None, None) when nothing can be said."""
        if self.row is None:
            return None, None
        best = min(((s, b) for b in binaries if (s := self._one(b))), key=lambda x: STATES.index(x[0]), default=(None, None))
        return best

    def replaced_by(self, binaries: list[str], source: str | None = None) -> list[str]:
        """Programs the latest read saw running a replaced copy of any of these binaries, or of any binary of source (which
        names a removed package's binaries too): a sighting, never inferred."""
        if not self.row or self.row.read_at < self.t - GAP:  # no recent read: no sighting (an agent downgraded, or gone quiet)
            return []
        return sorted({p for b, r in (self.row.replaced or {}).items() if b in binaries or (source and r.get("source") == source)
                       for p in r.get("programs", [])})

    def reason(self, source: str, binary: str | None, state: str | None) -> str | None:
        """The finding reason for a state, in words: the programs, where they listen and when they were read."""
        e = (self.row.seen or {}).get(binary, {}) if self.row and binary else {}
        lib = f"{binary} (from {source}) is loaded" if binary and binary != source else "Loaded"
        if state == "listening":
            parts = [f"{name}, listening on {_and(addrs)}" for name, addrs in e.get("net_by") or []]
            return f"{lib} by {'; '.join(parts) or 'a program listening on the network'} (read {_day(e.get('net'))}; the host firewall isn't read)"
        if state == "loaded":
            by = e.get("by") or ["a running program"]
            return f"{lib} by {_and(by)}, not listening on the network (read {_day(e.get('at'))})"
        if state == "not_loaded":
            return ("Not loaded by any long-running program in 7 days of reads (programs that run briefly, like cron jobs, "
                    "aren't seen): lower priority while it stays that way")
        return None


def restart_reason(programs: list[str], removed: bool) -> str:
    """The held-open reason for a finding whose fix is on disk while programs still run the replaced copy."""
    who, one = _and(programs), len(programs) == 1
    what = "the package is removed" if removed else "the fixed version is installed"
    return f"{RESTART}{what}, but {who} still run{'s' if one else ''} the copy it replaced: restart {'it' if one else 'them'} (or the machine)"


def _and(xs: list[str]) -> str:
    """"a", "a and b", "a, b and c"."""
    xs = list(xs)
    if len(xs) < 2:
        return "".join(xs)
    return ", ".join(xs[:-1]) + " and " + xs[-1]


def covered(row: AssetRuntime | None, t: datetime) -> bool:
    """Whether complete reads cover the last seven days and the latest is recent: what "not loaded" needs."""
    return bool(row and row.since and row.last_complete and row.since <= t - MEMORY and row.last_complete >= t - STALE)


def _day(v) -> str:
    d = _at(v)
    return f"{d.day} {d:%b} {d:%H:%M} UTC" if d else "recently"


def listening(row: AssetRuntime | None, t: datetime | None = None) -> dict[str, list[dict]]:
    """{binary package: [{program, users, listen}]} for each package a program listening beyond loopback was seen loading in
    the last seven days, with the users that program ran as at the latest read (empty when it wasn't in it): what attack
    paths need to say who an attacker becomes by getting in (DECISIONS 167)."""
    if row is None:
        return {}
    t, users = t or now(), {p["name"]: p.get("users") or [] for p in row.programs or [] if isinstance(p, dict) and "name" in p}
    out = {}
    for pkg, e in (row.seen or {}).items():
        if (net := _at(e.get("net"))) and net > t - MEMORY:
            out[pkg] = [{"program": n, "users": users.get(n, []), "listen": addrs} for n, addrs in e.get("net_by") or []]
    return out


def view(s: Session, asset: Asset, t: datetime | None = None) -> View:
    """The host's runtime view; an empty one (every state unknown) for a host without a read, or any other kind of asset."""
    return View(s.get(AssetRuntime, asset.id) if asset.kind == "host" else None, t)


def detail(s: Session, asset: Asset) -> dict | None:
    """The drawer's view of what runs on a host: the latest read's programs (listening first), replaced copies, and how
    much of the seven days is covered; None when the host has never sent a read."""
    row = s.get(AssetRuntime, asset.id) if asset.kind == "host" else None
    if row is None:
        return None
    progs = sorted(row.programs or [], key=lambda p: (not any(network_address(a) for a in p["listen"]), not p["listen"], p["name"]))
    return {"read_at": row.read_at, "state": row.state, "problem": row.problem, "since": row.since,
            "covered": covered(row, now()),
            "programs": [{k: p[k] for k in ("name", "unit", "users", "count", "listen", "replaced")} | {"loads": len(p["loads"])} for p in progs],
            "replaced": row.replaced or {}}


def restarts(programs: list[dict] | None, binaries: list[str]) -> dict[str, list[str]]:
    """What a fix of these binaries would restart, from the latest read's programs (the agent decides again after the change,
    from its own read): "services", the system services loading one, and "left", programs loading one that it won't restart."""
    users = [p for p in programs or [] if set(p["loads"]) & set(binaries)]
    go = sorted(p["name"] for p in users if p["unit"] and not RESTART_NEVER.fullmatch(p["name"]))
    return {"services": go, "left": sorted({p["name"] for p in users} - set(go))}


def held_programs(s: Session, org_id: str, asset_ids: list[str]) -> dict[str, dict]:
    """asset id -> the latest read's binary -> {"source", "programs" running a replaced copy}, for the hosts that have any."""
    return {a: r for a, r in s.execute(select(AssetRuntime.asset_id, AssetRuntime.replaced).where(
        AssetRuntime.org_id == org_id, AssetRuntime.replaced_count > 0, AssetRuntime.asset_id.in_(asset_ids)))}
