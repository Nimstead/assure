"""Attack paths across hosts (docs/engine/design-paths.md): which hosts an attacker who gets into one can reach next.

Built from each host's latest stored engine report and its own facts, never by scanning again. An edge A -> B needs three
things, each from evidence: A gives the attacker something (credentials taken on it, or name poisoning on its network), B
accepts it (local administrators over the network, relay because SMB signing isn't required, NTLMv1), and B's own firewall
allows the port that uses it. Inside a domain, a sign-in edge is confirmed only when an account signed in on A is in B's
Administrators group and A was seen with a connection open to B; with no such account it's unverified. Otherwise routing isn't
seen, so no edge is better than reasonable; reuse of a local administrator password can't be seen at all, so an edge resting on
it is unverified and says so (DECISIONS 98, 112).
"""

import fnmatch
import ipaddress
import re
from collections import defaultdict, deque

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


# ---- SSH key edges (tasks/spec-paths.md Module 4, DECISIONS 168) ----------------------------------------------------
KEY_EDGES_MAX = 50_000  # computed and walked in full; the response lists at most MAX_EDGES of them
ROOT_EQUIVALENT = ("docker", "lxd", "incus-admin", "disk")
_IPISH = re.compile(r"[0-9.*?]+|[0-9A-Fa-f:*?]*:[0-9A-Fa-f:*?]*")


def _addr_match(pattern: str, addrs: list[str]) -> bool | None:
    """sshd's match of one host pattern (CIDR, or an address with * and ? wildcards) against A's own addresses; None for a
    host name, which only DNS could judge and nothing here resolves (DECISIONS 27)."""
    if "/" in pattern:
        try:
            net = ipaddress.ip_network(pattern, strict=False)
        except ValueError:
            return None
        return any(ipaddress.ip_address(a) in net for a in addrs if _is_ip(a))
    if _IPISH.fullmatch(pattern):
        return any(fnmatch.fnmatchcase(a, pattern) for a in addrs)
    return None


def _is_ip(a: str) -> bool:
    try:
        ipaddress.ip_address(a)
        return True
    except ValueError:
        return False


def from_allows(patterns: list[str], addrs: list[str]) -> tuple[bool, str | None]:
    """(allowed, unjudged reason) for an authorized_keys from= list and A's addresses, by sshd's rules: a matching negation
    refuses, otherwise a matching positive allows. A host name can't be judged: when it alone decides, the reason says so."""
    if not patterns:
        return True, None
    allowed, names = False, []
    for p in patterns:
        neg = p.startswith("!")
        m = _addr_match(p[1:] if neg else p, addrs)
        if m is None:
            names.append(p)
        elif m and neg:
            return False, None
        elif m:
            allowed = True
    if names and (allowed and any(n.startswith("!") for n in names) or not allowed and any(not n.startswith("!") for n in names)):
        return True, f"its from= names hosts ({', '.join(names[:3])}) that would need DNS to judge"
    return allowed, None


def _user_allowed(sshd: dict, user: str, groups: list[str], addrs: list[str]) -> tuple[bool, str | None]:
    """Whether sshd lets this account in, by DenyUsers, AllowUsers, DenyGroups, AllowGroups in that order (user@host patterns
    match A's addresses), and for root PermitRootLogin."""
    def hit(pattern: str) -> bool | None:
        u, at, host = pattern.partition("@")
        if not fnmatch.fnmatchcase(user, u):
            return False
        return _addr_match(host, addrs) if at else True
    if any(hit(p) for p in sshd.get("denyusers") or []):
        return False, None
    allow = sshd.get("allowusers") or []
    if allow and not any(hit(p) for p in allow):
        return False, None
    if any(fnmatch.fnmatchcase(g, p) for p in sshd.get("denygroups") or [] for g in groups):
        return False, None
    if (ag := sshd.get("allowgroups") or []) and not any(fnmatch.fnmatchcase(g, p) for p in ag for g in groups):
        return False, None
    if user == "root" and sshd.get("permitrootlogin") == "no":
        return False, None
    return True, None


def _own_reach(report: dict | None) -> dict:
    """What a host's own paths give an attacker: from the network (root, or which users), and whether any account already
    on it can become root (a foothold path that reaches root)."""
    paths = (report or {}).get("attack_paths") or []
    net = next((p for p in paths if p["kind"] == "network"), None)
    entry = None
    if net is not None:
        r = net.get("reaches")
        entry = "root" if r is None or r.get("root") else frozenset(r.get("users") or [])
    return {"entry": entry, "foothold_root": any(p["kind"] == "foothold" and (p.get("reaches") or {}).get("root") for p in paths),
            "grade": net["grade"] if net else next((p["grade"] for p in paths), None)}


def key_edges(hosts: list[dict]) -> tuple[list[dict], bool]:
    """(edges, cut short) from each Linux host's access read: A -> B for a key held on A whose fingerprint B trusts for an
    account sshd lets in, B's sshd listening beyond loopback with keys on and from= allowing A's addresses. Each way says who
    must hold the key on A ("needs": root, or its owner), what B hands over ("gives": root, or the account) and why the grade."""
    acc = {h["id"]: h["access"] for h in hosts if isinstance(h.get("access"), dict)}
    trusted: dict[str, list[tuple[str, dict]]] = defaultdict(list)
    for hid, a in acc.items():
        for t in a.get("trusted") or []:
            trusted[t["fp"]].append((hid, t))
    byid = {h["id"]: h for h in hosts}
    pairs: dict[tuple[str, str], list[dict]] = {}
    cut = False
    for aid, a in acc.items():
        addrs = _list(byid[aid].get("facts") or {}, "addresses", 16) or set()
        for k in a.get("held") or []:
            for bid, t in trusted.get(k["fp"], []):
                if bid == aid:
                    continue
                b, fb = acc[bid], byid[bid].get("facts") or {}
                sshd = b.get("sshd") or {}
                ssh = (byid[bid].get("report") or {}).get("ssh") or {}
                if not sshd.get("installed") or sshd.get("pubkeyauthentication") == "no" or ssh.get("listening") is False:
                    continue
                acct = next((x for x in b.get("accounts") or [] if x["name"] == t["account"]), {"groups": []})
                ok, _ = _user_allowed(sshd, t["account"], acct.get("groups") or [], sorted(addrs))
                allowed, unjudged = from_allows(t.get("from") or [], sorted(addrs))
                if not (ok and allowed):
                    continue
                if t["account"] == "root" and sshd.get("permitrootlogin") == "forced-commands-only" and not t.get("forced"):
                    continue
                routed = _routed(byid[aid].get("facts") or {}, fb)
                grade, because = ("confirmed" if routed else "reasonable"), [
                    f"{byid[bid]['hostname']}'s sshd " + (ssh.get("how") or "is installed; whether it listens beyond loopback isn't read")]
                if ssh.get("listening") is None:
                    grade = "reasonable" if grade == "confirmed" else grade
                if routed:
                    because.append("A had a connection open to B")
                if sshd.get("match"):
                    grade, _ = _grade(grade, "reasonable"), because.append("B's sshd has Match blocks, which can change this per user or address")
                if k.get("passphrase"):
                    grade, _ = "unverified", because.append("the key needs its passphrase")
                if t.get("forced"):
                    grade, _ = "unverified", because.append("B signs this key in only to a forced command")
                elif t.get("restrict"):
                    because.append("restrict: no terminal or forwarding, though commands still run")
                if sshd.get("authorizedkeyscommand"):
                    grade, _ = "unverified", because.append("B also takes keys from a command that isn't read")
                if unjudged:
                    grade, _ = "unverified", because.append(unjudged)
                gives = "root" if t["account"] == "root" or set(acct.get("groups") or []) & set(ROOT_EQUIVALENT) or acct.get("sudo_all") is True else t["account"]
                needs = "root" if k["account"] == "root" else k["account"]
                pairs.setdefault((aid, bid), []).append({
                    "via": f"SSH:{k['fp']}", "key": k["fp"], "path": k["path"], "account": t["account"], "needs": needs, "gives": gives, "port": 22,
                    "how": f"the key {k['path']} on A is trusted for {t['account']} on B", "because": "; ".join(because), "grade": grade})
                if len(pairs) >= KEY_EDGES_MAX:
                    cut = True
                    break
            if cut:
                break
        if cut:
            break
    edges = []
    for (aid, bid), ways in pairs.items():
        ways.sort(key=lambda w: (("unverified", "reasonable", "confirmed").index(w["grade"]), w["gives"] == "root"), reverse=True)
        edges.append({"from": aid, "to": bid, "grade": ways[0]["grade"], "kind": "ssh", "ways": ways})
    return edges, cut


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
        if g["grade"] and not _linux(a):  # a Linux host's credentials are its SSH keys: key edges carry them, never Windows sign-ins
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
    kedges, kcut = key_edges(hosts)
    every = edges + kedges  # chains and choke points walk all of them; the response lists at most MAX_EDGES
    reach = {h["id"]: _own_reach(h.get("report")) for h in judged}
    seen = {h["id"] for h in judged}
    chains = _chains(judged, gives, every, reach)
    shown = edges + kedges[:max(0, MAX_EDGES - len(edges))]
    return {"hosts": {h["id"]: {"hostname": h["hostname"], "judged": h["id"] in seen, "entry": gives.get(h["id"], {}).get("entry", False),
                                "internet_facing": bool(h.get("internet_facing")),
                                "paths": [{"kind": p["kind"], "start": p["start"], "grade": p["grade"], "steps": [st["label"] for st in p["steps"]],
                                           "break_at": p["break_at"], **({"reaches": p["reaches"]} if "reaches" in p else {})}
                                          for p in (h["report"] or {}).get("attack_paths", [])] if h["id"] in seen else []}
                      for h in hosts},
            "edges": shown, "truncated": truncated or kcut or len(shown) < len(every), "chains": chains}


def _linux(h: dict) -> bool:
    return bool(h.get("linux")) or isinstance(h.get("access"), dict)


def _starts(judged: list[dict], gives: dict, reach: dict) -> dict[str, object]:
    """Each host a chain starts from, with what the attacker holds there: "root", or the users its network path reaches."""
    out = {}
    for h in judged:
        g, r = gives[h["id"]], reach[h["id"]]
        if not (g["entry"] or (h.get("internet_facing") and g["grade"])):
            continue
        held = r["entry"] if g["entry"] else frozenset()
        out[h["id"]] = "root" if held == "root" or r["foothold_root"] or not _linux(h) else held
    return out


def _arrive(e: dict, held, reach: dict) -> object | None:
    """What crossing edge e gives on its target, holding `held` ("root" or a set of users) on its source; None when no way
    across can be used from there. A Windows edge gives administrator rights; a key gives what the key's account is on B."""
    ways = [w for w in e["ways"] if "needs" not in w or held == "root" or w["needs"] in held]
    if not ways:
        return None
    got = "root" if any(w.get("gives", "root") == "root" for w in ways) else frozenset(w["gives"] for w in ways)
    return "root" if got == "root" or reach.get(e["to"], {}).get("foothold_root") else got


def _better(new, old) -> bool:
    return old is None or (old != "root" and (new == "root" or not set(new) <= set(old)))


def walk(starts: dict, nxt: dict, reach: dict, skip: frozenset = frozenset()) -> dict[str, tuple]:
    """Every host reachable from the starts by the fewest hops: host -> (what is held there, the edges that led there). An edge
    whose index is in skip is treated as gone (choke points). Holding more on a host already reached walks on from it again."""
    best: dict[str, tuple] = {h: (held, []) for h, held in starts.items()}
    q = deque(best)
    while q:
        at = q.popleft()
        held, hops = best[at]
        for i, e in nxt.get(at, []):
            if i in skip:
                continue
            got = _arrive(e, held, reach)
            if got is None or not _better(got, best.get(e["to"], (None,))[0]):
                continue
            best[e["to"]] = (got, [*hops, i])
            q.append(e["to"])
    return best


def _chains(judged: list[dict], gives: dict, edges: list[dict], reach: dict) -> list[dict]:
    """From each host with a path from the network (or marked internet-facing with any path), every host reachable, by the
    fewest hops, and what the attacker holds there ("root", or which accounts)."""
    nxt: dict[str, list] = defaultdict(list)
    for i, e in enumerate(edges):
        nxt[e["from"]].append((i, e))
    out = []
    for start, held in _starts(judged, gives, reach).items():
        got = walk({start: held}, nxt, reach)
        hosts = [(h, v) for h, v in got.items() if h != start]
        hosts.sort(key=lambda x: (len(x[1][1]), x[0]))
        rows = [{"host": h, "hops": [edges[i]["to"] for i in hops], "grade": _grade(*(edges[i]["grade"] for i in hops)),
                 "fix_on_host": sorted({w["via"] for w in edges[hops[-1]]["ways"]}), "as": "root" if v == "root" else sorted(v)}
                for h, (v, hops) in hosts]
        if rows:
            out.append({"start": start, "why_start": "a path from the network" if gives[start]["entry"] else "marked internet-facing", "reach": rows})
    return sorted(out, key=lambda c: -len(c["reach"]))[:MAX_CHAINS]
