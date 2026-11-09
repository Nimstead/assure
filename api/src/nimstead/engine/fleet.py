"""Attack paths across hosts (docs/engine/design-paths.md): which hosts an attacker who gets into one can reach next.

Built from each host's latest stored engine report and its own facts, never by scanning again. An edge A -> B needs three
things, each from evidence: A gives the attacker something (credentials taken on it, or name poisoning on its network), B
accepts it (local administrators over the network, relay because SMB signing isn't required, NTLMv1), and B's own firewall
allows the port that uses it. Inside a domain, a sign-in edge is confirmed only when an account signed in on A is in B's
Administrators group and A was seen with a connection open to B; with no such account it's unverified. Otherwise routing isn't
seen, so no edge is better than reasonable; reuse of a local administrator password can't be seen at all, so an edge resting on
it is unverified and says so (DECISIONS 98, 112).
"""

from collections import deque

from nimstead import winconfig
from nimstead.engine.paths import _grade

# how B lets an attacker in, -> (B's TCP ports that carry it, what it needs from A, how it reads)
ACCEPTS = {"remote-uac": ((445, 5985, 5986), "credentials", "local administrators keep full rights over the network (pass-the-hash)"),
           "smb-signing": ((445,), "poisoning", "SMB signing isn't required, so a relayed sign-in from A's network works"),
           "ntlmv1": ((445,), "credentials", "it accepts NTLMv1, whose responses can be cracked or relayed")}
POISONING = ("CFG:llmnr", "CFG:netbios")
MAX_EDGES = 2_000  # a fleet on Windows' default SMB and LLMNR settings links nearly every pair: past this, say it's cut short
MAX_CHAINS = 50


def _open_ports(facts: dict) -> set[int]:
    rows = facts.get("listening")
    return {r["port"] for r in rows if isinstance(r, dict) and isinstance(r.get("port"), int) and r.get("firewall") in winconfig.FIREWALL_SAYS} \
        if isinstance(rows, list) else set()


def _domain(facts: dict) -> str | None:
    d = facts.get("domain")
    return d.upper() if isinstance(d, str) and d and d.upper() != "WORKGROUP" and isinstance(facts.get("domain_role"), int) and facts["domain_role"] >= 1 else None


def _list(facts: dict, key: str, cap: int) -> set[str] | None:
    """A list fact as a set, or None when the agent couldn't read it (an old agent, a failed read): None is never "empty"."""
    v = facts.get(key)
    return {x for x in v[:cap] if isinstance(x, str) and len(x) <= 200} if isinstance(v, list) else None


def _routed(fa: dict, fb: dict) -> bool:
    """A has a connection open to one of B's own addresses: routing from A to B seen, not assumed (DECISIONS 112)."""
    peers, addrs = _list(fa, "peers", 64), _list(fb, "addresses", 16)
    return bool(peers and addrs and {p.rsplit(":", 1)[0] for p in peers} & addrs)


def _refine(ways: list[dict], base: str, fa: dict, fb: dict) -> list[dict]:
    """One source's ways into B, judged on what A and B said about themselves: whether an account signed in on A is an
    administrator on B (its SIDs and their groups against B's Administrators group), and whether A was seen reaching B."""
    signed, admins, routed = _list(fa, "signed_in_sids", 100), _list(fb, "local_admins", 50), _routed(fa, fb)
    out = []
    for w in ways:
        w = dict(w)
        if w.pop("_domain_creds", False) and signed is not None and admins is not None:
            if signed & admins:
                w["because"] += "; an account signed in on A is in B's Administrators group"
                if routed:
                    w["because"] += ", and A had a connection open to B"
                    w["grade"] = _grade(base, "confirmed")
            else:  # the hash an attacker takes from A doesn't open B as an administrator
                w["because"] = "no account signed in on A when it last reported is in B's Administrators group"
                w["grade"] = "unverified"
        elif routed:
            w["because"] += "; A had a connection open to B"
        out.append(w)
    return sorted(out, key=lambda w: ("unverified", "reasonable", "confirmed").index(w["grade"]), reverse=True)


def build(hosts: list[dict]) -> dict:
    """Return hosts, edges, truncated and chains from stored reports and current facts.

    hosts contains dictionaries with unique id, hostname, facts, os_version, report
    (latest stored engine report or None), and internet_facing. Inputs must follow
    engine model shapes. No scan, database query or input mutation occurs here.
    Edges stop at 2000 and set truncated when a further edge is found. Return up
    to 50 starting-host chains, each with shortest-hop reachability. No separate
    flag signals chain truncation. Malformed fields can raise KeyError, TypeError
    or ValueError. An inferred edge does not prove exploitation or network access."""
    judged = [h for h in hosts if h.get("report") and "attack_paths" in h["report"]]
    gives = {}
    for h in judged:
        steps = {st["stage"]: st for p in h["report"]["attack_paths"] for st in p["steps"]}
        lateral = {w["ref"] for p in h["report"]["attack_paths"] if p.get("then") for w in p["then"]["ways"]}
        net = next((p for p in h["report"]["attack_paths"] if p["kind"] == "network"), None)
        any_path = net or next(iter(h["report"]["attack_paths"]), None)
        gives[h["id"]] = {"credentials": "credentials" in steps, "poisoning": bool(lateral & set(POISONING)), "entry": bool(net),
                          "grade": any_path["grade"] if any_path else None}
    # sources that give the same things from the same domain read the same to every target: judged once per group, not once per
    # host pair (a dense 400-host fleet took 12 s and 200 MB per request before; DECISIONS 101)
    groups: dict[tuple, list[str]] = {}
    for a in judged:
        g = gives[a["id"]]
        if g["grade"]:
            groups.setdefault((g["credentials"], g["poisoning"], g["grade"], _domain(a.get("facts") or {})), []).append(a["id"])
    edges, truncated = [], False
    facts = {h["id"]: h.get("facts") or {} for h in judged}
    for b in judged:
        opened = _open_ports(b.get("facts") or {})
        if not opened:
            continue
        found = {f["package"] for f in winconfig.evaluate(b.get("facts") or {}, b.get("os_version") or "")}
        dom_b = _domain(b.get("facts") or {})
        for (creds, poison, grade, dom), ids in groups.items():
            ways = []
            for check, (ports, needs, how) in ACCEPTS.items():
                port = next((p for p in ports if p in opened), None)
                if check not in found or not (creds if needs == "credentials" else poison) or port is None:
                    continue
                same = bool(dom) and dom == dom_b
                if needs == "credentials":
                    because = f"both are in the domain {dom}" if same else "only if they share a local administrator password, which can't be seen"
                else:  # poisoning on A's network, relayed to B
                    because = "sign-ins on A's network can be captured by name poisoning and relayed" + (f"; both are in the domain {dom}" if same else "")
                ways.append({"via": f"CFG:{check}", "how": how, "port": port, "because": because,
                             "grade": _grade(grade, "reasonable" if same else "unverified"), "_domain_creds": same and needs == "credentials"})
            if not ways:
                continue
            for aid in ids:
                if aid == b["id"]:
                    continue
                if len(edges) >= MAX_EDGES:
                    truncated = True
                    break
                mine = _refine(ways, grade, facts[aid], b.get("facts") or {})
                edges.append({"from": aid, "to": b["id"], "grade": mine[0]["grade"], "ways": mine})
    seen = {h["id"] for h in judged}
    return {"hosts": {h["id"]: {"hostname": h["hostname"], "judged": h["id"] in seen, "entry": gives.get(h["id"], {}).get("entry", False),
                                "internet_facing": bool(h.get("internet_facing")),
                                "paths": [{"kind": p["kind"], "start": p["start"], "grade": p["grade"], "steps": [st["label"] for st in p["steps"]],
                                           "break_at": p["break_at"]} for p in (h["report"] or {}).get("attack_paths", [])] if h["id"] in seen else []}
                      for h in hosts},
            "edges": edges, "truncated": truncated, "chains": _chains(judged, gives, edges)}


def _chains(judged: list[dict], gives: dict, edges: list[dict]) -> list[dict]:
    """From each host with a path from the network (or marked internet-facing with any path), every host reachable, by the fewest hops."""
    nxt: dict[str, list[dict]] = {}
    for e in edges:
        nxt.setdefault(e["from"], []).append(e)
    out = []
    for h in judged:
        if not (gives[h["id"]]["entry"] or (h.get("internet_facing") and gives[h["id"]]["grade"])):
            continue
        seen, q, reach = {h["id"]}, deque([(h["id"], [])]), []
        while q:
            at, hops = q.popleft()
            for e in nxt.get(at, []):
                if e["to"] not in seen:
                    seen.add(e["to"])
                    path = [*hops, e]
                    reach.append({"host": e["to"], "hops": [x["to"] for x in path], "grade": _grade(*(x["grade"] for x in path)),
                                  "fix_on_host": sorted({w["via"] for w in e["ways"]})})
                    q.append((e["to"], path))
        if reach:
            out.append({"start": h["id"], "why_start": "a path from the network" if gives[h["id"]]["entry"] else "marked internet-facing",
                        "reach": reach})
    return sorted(out, key=lambda c: -len(c["reach"]))[:MAX_CHAINS]  # each BFS walks at most MAX_EDGES edges
