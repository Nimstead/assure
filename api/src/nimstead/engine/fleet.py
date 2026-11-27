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

from nimstead import linconfig, winconfig
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


def _routed(fa: dict, fb: dict, ports: set[str] | None = None) -> bool:
    """A has a connection open to one of B's own addresses (on one of ports, when given): routing from A to B seen, not
    assumed (DECISIONS 112)."""
    peers, addrs = _list(fa, "peers", 64), _list(fb, "addresses", 16)
    return bool(peers and addrs and {p.rsplit(":", 1)[0] for p in peers if ports is None or p.rsplit(":", 1)[-1] in ports} & addrs)


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


def _glob(s: str, pattern: str) -> bool:
    """sshd's wildcard match: * and ? only (fnmatch would also read [...] as a character class)."""
    return fnmatch.fnmatchcase(s, pattern.replace("[", "[[]"))


def _user_allowed(sshd: dict, user: str, uid: int | None, groups: list[str], addrs: list[str]) -> tuple[bool, str | None]:
    """(allowed, unjudged reason): whether sshd lets this account in, by DenyUsers, AllowUsers, DenyGroups, AllowGroups in
    that order (a user@host pattern's host, after its last "@", against A's addresses), and for uid 0 PermitRootLogin. A host
    name in AllowUsers can't be judged without DNS: the account is let in, with the reason."""
    unjudged = None

    def hit(pattern: str) -> bool | None:
        u, at, host = pattern.rpartition("@") if "@" in pattern else (pattern, "", "")
        if not _glob(user, u):
            return False
        return _addr_match(host, addrs) if at else True
    if any(hit(p) for p in sshd.get("denyusers") or []):
        return False, None
    allow = sshd.get("allowusers") or []
    if allow:
        hits = [hit(p) for p in allow]
        if not any(hits):
            if None not in hits:
                return False, None
            unjudged = "B's AllowUsers names hosts that would need DNS to judge"
    if any(_glob(g, p) for p in sshd.get("denygroups") or [] for g in groups):
        return False, None
    if (ag := sshd.get("allowgroups") or []) and not any(_glob(g, p) for p in ag for g in groups):
        return False, None
    if (uid == 0 or (uid is None and user == "root")) and sshd.get("permitrootlogin") == "no":
        return False, None
    return True, unjudged


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
            "other_path": any(p["kind"] != "network" for p in paths),
            "grade": net["grade"] if net else next((p["grade"] for p in paths), None)}


KEY_WAYS_MAX = 50_000  # ways across all key edges: a host trusting one key thousands of times can't make the fleet view crawl
WAYS_SHOWN = 5  # per edge in the response; chains and choke points use them all
_WEAK_TYPES = {"ssh-dss": "ssh-dss keys are off by default since OpenSSH 7.0",
               "sk-ssh-ed25519@openssh.com": "a security-key key also needs its hardware authenticator",
               "sk-ecdsa-sha2-nistp256@openssh.com": "a security-key key also needs its hardware authenticator"}


def key_edges(hosts: list[dict]) -> tuple[list[dict], bool]:
    """(edges, cut short) from each Linux host's access read: A -> B for a key held on A whose fingerprint B trusts for an
    account sshd lets in, B's sshd listening beyond loopback with keys on and from= allowing A's addresses. Each way says who
    must hold the key on A ("needs": root, or its owner), what B hands over ("gives": root, or the account) and why the grade.
    One way per (key, account) per pair, the best; sshd's rules for an account are judged once per target and source address
    set; at most KEY_WAYS_MAX ways in all (security audit: duplicates once made one request take minutes)."""
    acc = {h["id"]: h["access"] for h in hosts if isinstance(h.get("access"), dict)}
    byid = {h["id"]: h for h in hosts}
    trusted: dict[str, list[tuple[str, dict]]] = defaultdict(list)
    for hid, a in acc.items():
        seen = set()
        for t in a.get("trusted") or []:
            if (t["account"], t["fp"]) not in seen:  # the same key trusted twice for one account is one way in
                seen.add((t["account"], t["fp"]))
                trusted[t["fp"]].append((hid, t))
    target = {}
    for bid, b in acc.items():
        sshd = b.get("sshd") or {}
        ssh = (byid[bid].get("report") or {}).get("ssh") or {}
        open_ = sshd.get("installed") and sshd.get("running") is not False and sshd.get("pubkeyauthentication") != "no" and ssh.get("listening") is not False
        target[bid] = (open_, sshd, ssh, {x["name"]: x for x in b.get("accounts") or []})
    facts = {h["id"]: h.get("facts") or {} for h in hosts}
    addrs_of = {hid: tuple(sorted(_list(facts[hid], "addresses", 16) or ())) for hid in acc}
    allowed_memo: dict[tuple, tuple] = {}
    pairs: dict[tuple[str, str], dict[tuple, dict]] = {}
    ways_n, cut = 0, False
    helds = {}
    for aid, a in acc.items():
        held, seen = [], set()
        for k in a.get("held") or []:
            if (k["account"], k["fp"]) not in seen:
                seen.add((k["account"], k["fp"]))
                held.append(k)
        helds[aid] = held
    # sources with the fewest possible ways go first: a host claiming many holders of the fleet's keys can only spend what is
    # left of the budget, never what honest hosts need (security audit: one host's claims erased every real key chain)
    for aid in sorted(acc, key=lambda x: (sum(len(trusted.get(k["fp"], ())) for k in helds[x]), x)):
        addrs, held = addrs_of[aid], helds[aid]
        for k in held:
            for bid, t in trusted.get(k["fp"], []):
                if bid == aid:
                    continue
                open_, sshd, ssh, accounts = target[bid]
                if not open_:
                    continue
                acct = accounts.get(t["account"], {"groups": []})
                memo = (bid, t["account"], addrs)
                if memo not in allowed_memo:
                    allowed_memo[memo] = _user_allowed(sshd, t["account"], acct.get("uid"), acct.get("groups") or [], list(addrs))
                ok, user_unjudged = allowed_memo[memo]
                allowed, from_unjudged = from_allows(t.get("from") or [], list(addrs))
                if not (ok and allowed):
                    continue
                is_root = acct.get("uid") == 0 or ("uid" not in acct and t["account"] == "root")
                if is_root and sshd.get("permitrootlogin") == "forced-commands-only" and not t.get("forced"):
                    continue
                # found by the lab's real ssh: an sshd without PAM (Alpine's prints no UsePAM line) refuses an account locked with
                # "!" (passwd -l), keys too; an account whose shell is nologin or false signs in to no session, so runs nothing
                if sshd.get("usepam") != "yes" and acct.get("password") == "locked" or acct.get("login") is False:
                    continue
                alone = linconfig.key_alone(sshd)
                if alone is None:  # AuthenticationMethods without publickey: no key signs in here
                    continue
                port = next((p for p in sshd.get("port") or [] if p.isdigit()), "22")
                routed = _routed(facts[aid], facts[bid], {port, *(sshd.get("port") or [])})  # to its sshd: a database connection says nothing of SSH
                grade, because = ("confirmed" if routed else "reasonable"), [
                    f"{byid[bid]['hostname']}'s sshd " + (ssh.get("how") or "is installed; whether it listens beyond loopback isn't read")]
                if ssh.get("listening") is None:
                    grade = "reasonable"
                if routed:
                    because.append("A had a connection open to B's sshd")
                for weak, why in ((sshd.get("match"), "B's sshd has Match blocks, which can change this per user or address"),):
                    if weak:
                        grade = _grade(grade, "reasonable")
                        because.append(why)
                for weak, why in ((k.get("passphrase"), "the key needs its passphrase"), (t.get("forced"), "B signs this key in only to a forced command"),
                                  (not alone, "B's sshd asks for another method besides the key (AuthenticationMethods)"),
                                  (sshd.get("forcecommand"), "B's sshd runs one forced command for every sign-in (ForceCommand)"),
                                  (sshd.get("authorizedkeyscommand"), "B also takes keys from a command that isn't read"),
                                  (k.get("type") in _WEAK_TYPES, _WEAK_TYPES.get(k.get("type"), "")), (user_unjudged, user_unjudged), (from_unjudged, from_unjudged),
                                  # a user could plant a file showing someone else's public half: only root's word, or a checked key, is believed
                                  (k["account"] != "root" and not k.get("passphrase") and k.get("checked") is False,
                                   "the key file's private half couldn't be checked against its public half")):
                    if weak:
                        grade = "unverified"
                        because.append(why)
                if t.get("restrict") and not t.get("forced"):
                    because.append("restrict: no terminal or forwarding, though commands still run")
                gives = "root" if is_root or set(acct.get("groups") or []) & set(ROOT_EQUIVALENT) or acct.get("sudo_all") is True else t["account"]
                way = {"via": f"SSH:{k['fp']}", "key": k["fp"], "path": k["path"], "account": t["account"], "needs": "root" if k["account"] == "root" else k["account"],
                       "gives": gives, "port": int(port), "how": f"the key {k['path']} on A is trusted for {t['account']} on B", "because": "; ".join(because), "grade": grade}
                key = (k["fp"], t["account"], way["needs"])
                old = pairs.get((aid, bid), {}).get(key)
                if old is None:
                    if ways_n >= KEY_WAYS_MAX:
                        cut = True
                        continue
                    ways_n += 1
                if old is None or _ORDER.index(grade) > _ORDER.index(old["grade"]):
                    pairs.setdefault((aid, bid), {})[key] = way
    edges = []
    for (aid, bid), ws in pairs.items():
        ways = sorted(ws.values(), key=lambda w: (_ORDER.index(w["grade"]), w["gives"] == "root", w["via"]), reverse=True)
        edges.append({"from": aid, "to": bid, "grade": ways[0]["grade"], "kind": "ssh", "ways": ways})
    return edges, cut


_ORDER = ("unverified", "reasonable", "confirmed")
LIKELY_EPSS = 0.10  # the risk model names a flaw's EPSS from 10%


def _likely(net: dict, epss: dict | None) -> tuple[bool, float | None]:
    """(whether a host's way in from the network starts chains and choke points, the highest EPSS among its flaws) (DECISIONS
    172). It does when any of its ways is a setting, known exploited, or has a flaw with an EPSS of 10% or more or none yet.
    Ways the report didn't keep, or flaws a way didn't list, aren't known, so they count. epss None: not looked up, so all count."""
    step = net["steps"][0]
    if epss is None or step.get("count", 0) > len(step["ways"]):
        return True, None
    top = None
    for w in step["ways"]:
        refs = w.get("refs") or [w["ref"]]
        scores = [epss.get(r) for r in refs]
        if w.get("kev") or len(refs) < w.get("flaws", 1) or any(s is None or s >= LIKELY_EPSS for s in scores):
            return True, None
        top = max(top or 0.0, *scores)
    return False, top


def build(hosts: list[dict]) -> dict:
    """Return hosts, edges, truncated and chains from stored reports and current facts.

    hosts contains dictionaries with unique id, hostname, facts, os_version, report
    (latest stored engine report or None), and internet_facing; optional epss maps the
    host's flaw ids to EPSS (None when unscored), and without it every way in is likely.
    A host whose way in is unlikely keeps its paths but starts no chain. Inputs must follow
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
        likely, top = _likely(net, h.get("epss")) if net else (False, None)
        gives[h["id"]] = {"credentials": "credentials" in steps, "poisoning": bool(lateral & set(POISONING)), "entry": likely,
                          "grade": any_path["grade"] if any_path else None, **({"unlikely": {"epss": top}} if net and not likely else {})}
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
    every = edges + kedges  # chains and choke points walk all of them; the response lists at most MAX_EDGES, WAYS_SHOWN ways each
    reach = {h["id"]: _own_reach(h.get("report")) for h in judged}
    seen = {h["id"] for h in judged}
    g = _Graph(every, reach)
    chains, covered = _chains(judged, gives, g)
    choke = choke_points(judged, gives, g, {h["id"]: h["hostname"] for h in hosts}, truncated or kcut, covered)
    ins = sum(1 for h in judged if gives[h["id"]]["entry"] and h["id"] not in covered and _start_held(h, gives[h["id"]], reach[h["id"]]) is not None)
    shown = [e if len(e["ways"]) <= WAYS_SHOWN else {**e, "ways": e["ways"][:WAYS_SHOWN], "ways_count": len(e["ways"])}
             for e in edges + kedges[:max(0, MAX_EDGES - len(edges))]]
    return {"hosts": {h["id"]: {"hostname": h["hostname"], "judged": h["id"] in seen, "entry": gives.get(h["id"], {}).get("entry", False),
                                "internet_facing": bool(h.get("internet_facing")),
                                **({"unlikely": gives[h["id"]]["unlikely"]} if "unlikely" in gives.get(h["id"], {}) else {}),
                                "paths": [{"kind": p["kind"], "start": p["start"], "grade": p["grade"], "steps": [st["label"] for st in p["steps"]],
                                           "break_at": p["break_at"], **({"reaches": p["reaches"]} if "reaches" in p else {})}
                                          for p in (h["report"] or {}).get("attack_paths", [])] if h["id"] in seen else []}
                      for h in hosts},
            "edges": shown, "truncated": truncated or kcut or len(shown) < len(every), "chains": chains, "choke_points": choke,
            "partial": truncated or kcut or None in covered or ins > MAX_WALKS}


def _linux(h: dict) -> bool:
    return bool(h.get("linux")) or isinstance(h.get("access"), dict)


def _start_held(h: dict, g: dict, r: dict, entry: bool = True):
    """What an attacker holds on a start: its network path's reach, upgraded to root by a foothold path; a Windows start is
    administrator ("root"). With entry False (its way in closed), what it holds as a host marked internet-facing with another
    path, or None when it's no start then. An unlikely way in counts as closed: it makes no start either way (DECISIONS 172)."""
    if entry and g["entry"]:
        held = r["entry"]
    elif h.get("internet_facing") and (r["other_path"] if entry is False or "unlikely" in g else g["grade"]):
        held = frozenset()
    else:
        return None
    return "root" if held == "root" or r["foothold_root"] or not _linux(h) else held


def _starts(judged: list[dict], gives: dict, reach: dict) -> dict[str, object]:
    """Each host a chain starts from, with what the attacker holds there: "root", or the users its network path reaches."""
    out = {}
    for h in judged:
        held = _start_held(h, gives[h["id"]], reach[h["id"]])
        if held is not None:
            out[h["id"]] = held
    return out


class _Graph:
    """Every edge, with what crossing each gives to a holder of root precomputed: walks cross most edges as root, so most
    arrivals are a lookup (code review: 250 walks of 20,000 edges took 5.6 s before)."""

    def __init__(self, edges: list[dict], reach: dict):
        self.edges, self.reach = edges, reach
        self.nxt: dict[str, list[tuple[int, str]]] = defaultdict(list)
        self.as_root = []
        for i, e in enumerate(edges):
            self.nxt[e["from"]].append((i, e["to"]))
            self.as_root.append(_arrive(e, i, "root", reach))


def _arrive(e: dict, i: int, held, reach: dict, gone: frozenset = frozenset()) -> object | None:
    """What crossing edge e (index i) gives on its target, holding `held` ("root" or a set of users) on its source; None when
    no way across can be used from there. A Windows edge gives administrator rights; a key gives what the key's account is on
    B. A way whose (edge, way) index pair is in gone is treated as removed (choke points)."""
    ways = [w for wi, w in enumerate(e["ways"]) if (i, wi) not in gone and ("needs" not in w or held == "root" or w["needs"] in held)]
    if not ways:
        return None
    got = "root" if any(w.get("gives", "root") == "root" for w in ways) else frozenset(w["gives"] for w in ways)
    return "root" if got == "root" or reach.get(e["to"], {}).get("foothold_root") else got


def _merge(new, old):
    """What is held on a host reached again: root dominates, otherwise every account held either way; None when nothing grew."""
    if old is None:
        return new
    if old == "root":
        return None
    if new == "root":
        return "root"
    both = frozenset(old) | frozenset(new)
    return both if both != frozenset(old) else None


def walk(starts: dict, g: _Graph, gone: frozenset = frozenset(), used: set | None = None) -> dict[str, tuple]:
    """Every host reachable from the starts by the fewest hops: host -> (what is held there, the edges that first led there).
    Holding more on a host already reached walks on from it again, since more of its keys are usable. `used` collects every
    edge whose crossing changed what was held somewhere: removing ways on no such edge can't cut anything."""
    gone_edges = {i for i, _ in gone}
    best: dict[str, tuple] = {h: (held, []) for h, held in starts.items()}
    q = deque(best)
    while q:
        at = q.popleft()
        held, hops = best[at]
        for i, to in g.nxt.get(at, ()):
            got = g.as_root[i] if held == "root" and i not in gone_edges else _arrive(g.edges[i], i, held, g.reach, gone)
            if got is None:
                continue
            old = best.get(to)
            merged = _merge(got, old[0] if old else None)
            if merged is None:
                continue
            best[to] = (merged, old[1] if old else [*hops, i])
            if used is not None:
                used.add(i)
            q.append(to)
    return best


def _covers(have, need) -> bool:
    """Whether holding `have` on a host gives at least `need` there ("root", or a set of accounts)."""
    return have == "root" or need != "root" and frozenset(need) <= frozenset(have)


def _chains(judged: list[dict], gives: dict, g: _Graph) -> tuple[list[dict], set]:
    """(chains, covered): from each host with a path from the network (or marked internet-facing with any path), every host
    reachable, by the fewest hops, and what the attacker holds there ("root", or which accounts). A start that an earlier
    start reaches holding at least what its own way in gives is covered: everything it reaches, that one reaches too, so it
    isn't walked and has no chain of its own (code review: a walk per start took 10 s with every host a start)."""
    out, edges, covered, walked = [], g.edges, set(), 0
    starts = _starts(judged, gives, g.reach)
    for start, held in starts.items():
        if start in covered:
            continue
        if walked >= MAX_WALKS:
            covered.add(None)  # None in covered: some starts weren't walked (the response's `partial` says so)
            break
        walked += 1
        got = walk({start: held}, g)
        covered |= {s for s, need in starts.items() if s != start and s in got and _covers(got[s][0], need)}
        hosts = sorted(((h, v) for h, v in got.items() if h != start and v[1]), key=lambda x: (len(x[1][1]), x[0]))
        rows = [{"host": h, "hops": [edges[i]["to"] for i in hops], "grade": _grade(*(edges[i]["grade"] for i in hops)),
                 "fix_on_host": sorted({w["via"] for w in edges[hops[-1]]["ways"]}), "as": "root" if v == "root" else sorted(v)}
                for h, (v, hops) in hosts]
        if rows:
            out.append({"start": start, "why_start": "a path from the network" if gives[start]["entry"] else "marked internet-facing",
                        "reach": rows[:MAX_REACH], **({"reach_count": len(rows)} if len(rows) > MAX_REACH else {})})
    return sorted(out, key=lambda c: -c.get("reach_count", len(c["reach"])))[:MAX_CHAINS], covered


MAX_WALKS = 1_000  # chain walks, and way-in walks, per request: past this the rest aren't walked and `partial` says so
MAX_REACH = 200  # rows per chain, nearest first: 35 chains of 999 made a 10 MB response no page can show (reach_count says how many)


MAX_CANDIDATES = 200  # besides every start's way in; each scored by one walk, and only if it removes a way the walk used
CHOKE_SHOWN = 10


def choke_points(judged: list[dict], gives: dict, g: _Graph, names: dict, truncated: bool = False, covered: frozenset = frozenset()) -> list[dict]:
    """Up to ten single actions that cut the most machines off from every way in, largest first (tasks/spec-paths.md Module
    4, DECISIONS 169): close one start's way in, retire a key everywhere, untrust a key on one machine, or change one setting on
    one machine. Each is scored by walking the graph again without what it removes. Every start's way in is scored; of the
    rest, the 200 on the most ways, and of those only the ones that remove a way the full walk used (removing an unused way
    leaves every host's derivation standing, so it cuts nothing). Closing a start that is also marked internet-facing with
    another path leaves it a start, holding what that path gives. Each carries the best grade among the ways it removes, and
    those resting only on unverified ways come last. Closing that of a start another start reaches holding as
    much (`covered`) cuts nothing, so it isn't walked. When the edge list was cut short, the counts are a lower bound and
    say so."""
    byid = {h["id"]: h for h in judged}
    starts = _starts(judged, gives, g.reach)
    if not starts:
        return []
    used: set[int] = set()
    before = set(walk(starts, g, used=used))
    cands: dict[tuple, dict] = {}
    for i, e in enumerate(g.edges):
        if e["from"] not in before:
            continue  # an edge no chain can cross can't cut anything
        for wi, w in enumerate(e["ways"]):
            if "key" in w:
                c = cands.setdefault(("retire-key", w["key"]), {"ways": set(), "holders": set(), "trusted": set()})
                c["ways"].add((i, wi))
                c["holders"].add((e["from"], w["path"]))
                c["trusted"].add(e["to"])
                cands.setdefault(("untrust-key", w["key"], e["to"], w["account"]), {"ways": set()})["ways"].add((i, wi))
            else:
                cands.setdefault(("setting", w["via"], e["to"]), {"ways": set()})["ways"].add((i, wi))
    ranked = sorted(cands.items(), key=lambda kv: (-len(kv[1]["ways"]), kv[0]))[:MAX_CANDIDATES]
    ins = [h for h in starts if gives[h]["entry"] and h not in covered]
    ranked += [(("way-in", h), {"ways": set()}) for h in ins[:MAX_WALKS]]  # at most one per start, all but past MAX_WALKS
    out = []
    for key, c in ranked:
        if key[0] == "way-in":
            s = {h: v for h, v in starts.items() if h != key[1]}
            alt = _start_held(byid[key[1]], gives[key[1]], g.reach[key[1]], entry=False)
            if alt is not None:
                s[key[1]] = alt
        else:
            if not any(i in used for i, _ in c["ways"]):
                continue
            s = starts
        cut = sorted(before - set(walk(s, g, frozenset(c["ways"]))))
        if cut:
            grade = gives[key[1]]["grade"] if key[0] == "way-in" else max((g.edges[i]["ways"][wi]["grade"] for i, wi in c["ways"]), key=_ORDER.index)
            out.append({"kind": key[0], "action": _action(key, c, names, judged), "cuts": len(cut), "hosts": cut[:50], "ways_removed": len(c["ways"]),
                        "lower_bound": truncated, "ref": key[1], "grade": grade, **({"on": key[2], "account": key[3]} if key[0] == "untrust-key" else {})})
    # resting only on unverified ways (a key that needs its passphrase, a claim a user could plant), it comes after the rest: told
    # to retire a key everywhere on one planted file's word, someone could break real access (security audit)
    out.sort(key=lambda x: (x["grade"] == "unverified", -x["cuts"], ("way-in", "retire-key", "untrust-key", "setting").index(x["kind"]), x["action"]))
    return out[:CHOKE_SHOWN]


def _action(key: tuple, c: dict, names: dict, judged: list[dict]) -> str:
    """A choke point in words: what to do, and where."""
    n = lambda h: names.get(h, h)  # noqa: E731
    if key[0] == "way-in":
        h = next(x for x in judged if x["id"] == key[1])
        net = next((p for p in (h.get("report") or {}).get("attack_paths") or [] if p["kind"] == "network"), None)
        refs = [w["ref"] for w in net["steps"][0]["ways"]] if net else []
        count = net["steps"][0]["count"] if net else 0
        return f"Close {n(key[1])}'s way in" + (": " + ", ".join(refs[:3]) + (f" and {count - 3} more" if count > 3 else "") if refs else "")
    if key[0] == "retire-key":
        held = sorted(f"{p} on {n(h)}" for h, p in c["holders"])
        return (f"Retire the SSH key {key[1][:19]}…: delete it ({'; '.join(held[:3])}{' and more' if len(held) > 3 else ''}) and remove it from "
                f"the authorized_keys of the {len(c['trusted'])} machine{'s' * (len(c['trusted']) != 1)} that trust it")
    if key[0] == "untrust-key":
        return f"Remove the key {key[1][:19]}… from {key[3]}'s authorized_keys on {n(key[2])}"
    return f"Fix {key[1]} on {n(key[2])}"
