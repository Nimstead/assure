"""SSH key edges across Linux hosts (tasks/spec-paths.md Module 4, DECISIONS 168): A -> B only when a key held on A is trusted
on B for an account sshd lets in, graded by sshd's own rules, and chains that know which account the attacker holds."""

import pytest

from nimstead.engine import fleet

K_ROOT, K_DEPLOY, K_OTHER = ("SHA256:" + c * 43 for c in "RDO")
PROHIBIT = {"installed": True, "permitrootlogin": "prohibit-password", "pubkeyauthentication": "yes", "passwordauthentication": "no",
            "kbdinteractiveauthentication": "no", "permitemptypasswords": "no", "strictmodes": "yes", "authorizedkeysfile": [".ssh/authorized_keys"],
            "authorizedkeyscommand": False, "allowusers": [], "denyusers": [], "allowgroups": [], "denygroups": [], "port": ["22"],
            "listenaddress": ["0.0.0.0:22"], "match": False}


def path(kind="network", root=True, users=(), grade="reasonable"):
    return {"kind": kind, "start": "from the network", "grade": grade, "steps": [{"stage": "entry", "label": "Getting in", "ways": [], "count": 1}],
            "then": None, "break_at": {"stage": "entry", "label": "Getting in", "fixes": 1, "refs": []}, "reaches": {"root": root, "users": list(users)}}


def held(fp, account="root", passphrase=False):
    return {"account": account, "path": f"/{'root' if account == 'root' else 'home/' + account}/.ssh/id_ed25519", "type": "ssh-ed25519",
            "fp": fp, "passphrase": passphrase}


def trusts(fp, account="root", frm=(), forced=False, restrict=False):
    return {"account": account, "fp": fp, "type": "ssh-ed25519", "from": list(frm), "forced": forced, "restrict": restrict}


def account(name, uid, groups=(), sudo_all=False):
    return {"name": name, "uid": uid, "groups": sorted({name, *groups}), "login": True, "password": "locked", "sudo_all": sudo_all}


def lhost(hid, addr, keys=(), trusted=(), sshd=PROHIBIT, accounts=None, paths=(), listening=True, peers=None, internet=False):
    return {"id": hid, "hostname": hid, "facts": {"os_id": "debian", "addresses": [addr], **({"peers": peers} if peers is not None else {})},
            "os_version": "", "internet_facing": internet, "linux": True,
            "report": {"attack_paths": list(paths), "ssh": {"listening": listening, "how": f"ssh.service listens on {addr}:22"}},
            "access": {"sshd": sshd, "accounts": accounts or [account("root", 0), account("deploy", 1000)], "held": list(keys), "trusted": list(trusted),
                       "writable": [], "shadow_readable_by": [], "credentials": [], "agent_sockets": 0, "unidentified_keys": 0}}


def edge(out, a="a", b="b"):
    return next((e for e in out["edges"] if (e["from"], e["to"]) == (a, b)), None)


A = lambda **kw: lhost("a", "10.0.0.1", keys=[held(K_ROOT)], paths=[path()], **kw)  # noqa: E731 — a way in, root, root's key


def test_a_key_held_on_a_and_trusted_on_b_is_an_edge_confirmed_when_a_was_seen_reaching_b():
    out = fleet.build([A(), lhost("b", "10.0.0.2", trusted=[trusts(K_ROOT)])])
    e = edge(out)
    assert e["kind"] == "ssh" and e["grade"] == "reasonable"
    w = e["ways"][0]
    assert (w["via"], w["account"], w["needs"], w["gives"], w["port"]) == (f"SSH:{K_ROOT}", "root", "root", "root", 22)
    assert "trusted for root on B" in w["how"] and "ssh.service listens on 10.0.0.2:22" in w["because"]
    assert out["chains"][0]["start"] == "a" and out["chains"][0]["reach"][0] == {"host": "b", "hops": ["b"], "grade": "reasonable",
                                                                                  "fix_on_host": [f"SSH:{K_ROOT}"], "as": "root"}
    seen = fleet.build([A(peers=["10.0.0.2:22"]), lhost("b", "10.0.0.2", trusted=[trusts(K_ROOT)])])
    assert edge(seen)["grade"] == "confirmed" and "A had a connection open to B" in edge(seen)["ways"][0]["because"]


@pytest.mark.parametrize("frm,ok,grade", [
    (["10.0.0.0/24"], True, "reasonable"),
    (["10.0.0.1"], True, "reasonable"),
    (["10.0.0.*"], True, "reasonable"),
    (["192.168.0.0/16"], False, None),
    (["10.0.0.0/24", "!10.0.0.1"], False, None),
    (["!10.0.0.9", "10.0.0.0/24"], True, "reasonable"),
    (["jump.example.com"], True, "unverified"),         # a host name: it would take DNS, never done
    (["10.0.0.0/24", "!*.example.com"], True, "unverified"),
])
def test_from_follows_sshds_rules_against_as_own_addresses(frm, ok, grade):
    e = edge(fleet.build([A(), lhost("b", "10.0.0.2", trusted=[trusts(K_ROOT, frm=frm)])]))
    assert (e is not None) is ok and (e is None or e["grade"] == grade)


@pytest.mark.parametrize("change,want", [  # A was seen connected to B, so an edge with nothing against it is confirmed
    ({}, "confirmed"),
    ({"permitrootlogin": "no"}, None),
    ({"permitrootlogin": "without-password"}, "confirmed"),
    ({"permitrootlogin": "forced-commands-only"}, None),   # this key line has no forced command
    ({"pubkeyauthentication": "no"}, None),
    ({"allowusers": ["deploy"]}, None),
    ({"allowusers": ["root@10.0.0.*"]}, "confirmed"),
    ({"allowusers": ["root@192.168.*"]}, None),
    ({"denyusers": ["ro*"]}, None),
    ({"denygroups": ["root"]}, None),
    ({"allowgroups": ["wheel"]}, None),
    ({"match": True}, "reasonable"),                       # a Match block could say otherwise
    ({"authorizedkeyscommand": True}, "unverified"),
])
def test_b_s_sshd_decides(change, want):
    e = edge(fleet.build([A(peers=["10.0.0.2:22"]), lhost("b", "10.0.0.2", trusted=[trusts(K_ROOT)], sshd={**PROHIBIT, **change})]))
    assert (e["grade"] if e else None) == want


def test_a_passphrase_a_forced_command_and_restrict():
    assert edge(fleet.build([lhost("a", "10.0.0.1", keys=[held(K_ROOT, passphrase=True)], paths=[path()]),
                             lhost("b", "10.0.0.2", trusted=[trusts(K_ROOT)])]))["grade"] == "unverified"
    forced = edge(fleet.build([A(), lhost("b", "10.0.0.2", trusted=[trusts(K_ROOT, forced=True)])]))
    assert forced["grade"] == "unverified" and "forced command" in forced["ways"][0]["because"]
    restricted = edge(fleet.build([A(), lhost("b", "10.0.0.2", trusted=[trusts(K_ROOT, restrict=True)])]))
    assert restricted["grade"] == "reasonable" and "commands still run" in restricted["ways"][0]["because"]


def test_no_edge_when_b_s_sshd_isnt_there_or_doesnt_listen():
    assert edge(fleet.build([A(), lhost("b", "10.0.0.2", trusted=[trusts(K_ROOT)], listening=False)])) is None
    assert edge(fleet.build([A(), lhost("b", "10.0.0.2", trusted=[trusts(K_ROOT)], sshd={"installed": False})])) is None
    assert edge(fleet.build([A(), lhost("b", "10.0.0.2", trusted=[trusts(K_OTHER)])])) is None  # a different key


def test_what_b_hands_over():
    accts = [account("root", 0), account("deploy", 1000, ["docker"]), account("ops", 1001)]
    out = fleet.build([lhost("a", "10.0.0.1", keys=[held(K_DEPLOY, "deploy"), held(K_OTHER, "ops")], paths=[path()]),
                       lhost("b", "10.0.0.2", trusted=[trusts(K_DEPLOY, "deploy"), trusts(K_OTHER, "ops")], accounts=accts)])
    gives = {w["account"]: w["gives"] for w in edge(out)["ways"]}
    assert gives == {"deploy": "root", "ops": "ops"}  # deploy is in docker on B: root at will


def test_chains_know_which_account_the_attacker_holds():
    # a: a way in as www-data only. deploy's key on a opens b, but www-data can't read it: b isn't reached
    a = lhost("a", "10.0.0.1", keys=[held(K_DEPLOY, "deploy")], paths=[path(root=False, users=["www-data"])])
    b = lhost("b", "10.0.0.2", trusted=[trusts(K_DEPLOY, "deploy")])
    assert edge(fleet.build([a, b])) is not None and fleet.build([a, b])["chains"] == []
    # a reaches root: b reached as deploy (no way up there); deploy's own key on b opens c, root's key on b (unreadable to deploy) d
    a = lhost("a", "10.0.0.1", keys=[held(K_DEPLOY, "deploy")], paths=[path()])
    b = lhost("b", "10.0.0.2", keys=[held(K_OTHER, "deploy"), held(K_ROOT)], trusted=[trusts(K_DEPLOY, "deploy")])
    c = lhost("c", "10.0.0.3", trusted=[trusts(K_OTHER)])
    d = lhost("d", "10.0.0.4", trusted=[trusts(K_ROOT)])
    reach = {r["host"]: r for r in fleet.build([a, b, c, d])["chains"][0]["reach"]}
    assert reach["b"]["as"] == ["deploy"] and reach["c"]["hops"] == ["b", "c"] and reach["c"]["as"] == "root" and "d" not in reach
    # with a way up on b that any account can use, root on b reaches d too
    b["report"]["attack_paths"] = [path("foothold")]
    reach = {r["host"]: r for r in fleet.build([a, b, c, d])["chains"][0]["reach"]}
    assert reach["b"]["as"] == "root" and reach["d"]["hops"] == ["b", "d"]


def test_a_host_marked_internet_facing_with_no_way_in_starts_a_chain_only_with_a_way_up():
    a = lhost("a", "10.0.0.1", keys=[held(K_ROOT)], internet=True, paths=[path("foothold")])
    b = lhost("b", "10.0.0.2", trusted=[trusts(K_ROOT)])
    chain = fleet.build([a, b])["chains"][0]
    assert chain["why_start"] == "marked internet-facing" and chain["reach"][0]["as"] == "root"


def test_edges_listed_are_capped_but_chains_walk_them_all(monkeypatch):
    monkeypatch.setattr(fleet, "MAX_EDGES", 2)
    hosts = [A()] + [lhost(f"b{i}", f"10.0.1.{i}", trusted=[trusts(K_ROOT)]) for i in range(5)]
    out = fleet.build(hosts)
    assert len(out["edges"]) == 2 and out["truncated"] and len(out["chains"][0]["reach"]) == 5


def test_a_linux_host_is_never_a_windows_sign_in_source():
    from test_engine_fleet import OPEN_445, host
    win = host("w", {"remote_uac_off": 1}, {"listening": OPEN_445})
    lin = lhost("a", "10.0.0.1", keys=[held(K_ROOT)], paths=[{**path(), "steps": [{"stage": "credentials", "label": "Taking credentials", "ways": [], "count": 1}]}])
    assert edge(fleet.build([lin, win]), "a", "w") is None


def test_the_endpoint_links_two_reporting_hosts_by_their_keys(env):
    from test_access import read as access_read
    from test_api import user
    from test_runtime import doc, host, pkgs, prog
    from test_runtime import read as runtime_read
    c = user(env)
    web, wh = host(c, "web-1")
    db, dh = host(c, "db-1")
    root_listener = {**prog("nginx.service", ["nginx", "libssl3"], ["0.0.0.0:443/tcp"]), "users": ["root"]}
    sshd_prog = prog("ssh.service", ["openssh-server"], ["0.0.0.0:22/tcp"])
    for h, rt, acc, addr in (
            (wh, runtime_read(root_listener), access_read(held=[held(K_ROOT)], trusted=[]), "10.0.0.1"),
            (dh, runtime_read(sshd_prog), access_read(held=[], trusted=[trusts(K_ROOT)]), "10.0.0.2")):
        body = {"os_name": "Debian 12", "ecosystem": "Debian:12", "packages": pkgs(), "agent_version": "0.11.0",
                "collection": {**doc(2), "sources": {**doc(2)["sources"], "access": {"state": "ok", "count": 2}}},
                "facts": {"os_id": "debian", "addresses": [addr], "peers": ["10.0.0.2:22"] if addr == "10.0.0.1" else []},
                "runtime": rt, "access": acc}
        assert c.post("/api/agent/inventory", headers=h, json=body).status_code == 200
    out = c.get("/api/attack-paths").json()
    e = next(x for x in out["edges"] if (x["from"], x["to"]) == (web, db))
    assert e["kind"] == "ssh" and e["grade"] == "confirmed" and e["ways"][0]["gives"] == "root"
    paths = out["hosts"][web]["paths"]
    assert paths and paths[0]["kind"] == "network" and paths[0]["reaches"]["root"] is True
    assert any(ch["start"] == web and ch["reach"][0]["host"] == db for ch in out["chains"])


# ---- choke points ---------------------------------------------------------------------------------------------------

def reached(out):
    """Every host an attacker holds something on, read from the endpoint's own output: starts and chain reaches."""
    return {h for h, v in out["hosts"].items() if v["entry"]} | {r["host"] for c in out["chains"] for r in c["reach"]}


def test_retiring_one_deploy_key_cuts_the_machines_it_alone_opened():
    hosts = [lhost("web-1", "10.0.0.1", keys=[held(K_DEPLOY, "deploy")], paths=[path()]),
             *[lhost(f"app-{i}", f"10.0.0.{10 + i}", trusted=[trusts(K_DEPLOY, "deploy")], accounts=[account("root", 0), account("deploy", 1000, ["docker"])])
               for i in range(3)],
             lhost("db-1", "10.0.0.20", trusted=[trusts(K_DEPLOY, "deploy"), trusts(K_OTHER)], accounts=[account("root", 0), account("deploy", 1000, ["docker"])]),
             lhost("bk-1", "10.0.0.30", keys=[held(K_OTHER)], paths=[path()])]
    choke = fleet.build(hosts)["choke_points"]
    first, key = choke[0], next(c for c in choke if c["kind"] == "retire-key")
    assert (first["kind"], first["ref"], first["cuts"]) == ("way-in", "web-1", 4)  # web-1 itself and the three it alone opens
    assert key["ref"] == K_DEPLOY and key["cuts"] == 3  # db-1 stays reachable through bk-1's key
    assert key["hosts"] == ["app-0", "app-1", "app-2"] and "trust it" in key["action"] and "web-1" in key["action"]
    assert all(not c["lower_bound"] for c in choke)
    assert [c["cuts"] for c in choke] == sorted((c["cuts"] for c in choke), reverse=True)


def test_a_cut_short_graph_says_its_counts_are_a_lower_bound(monkeypatch):
    monkeypatch.setattr(fleet, "KEY_EDGES_MAX", 2)
    hosts = [A()] + [lhost(f"b{i}", f"10.0.1.{i}", trusted=[trusts(K_ROOT)]) for i in range(4)]
    choke = fleet.build(hosts)["choke_points"]
    assert choke and all(c["lower_bound"] for c in choke)


def without(hosts, c):
    """The same fleet with choke point c done for real in its inputs."""
    out = []
    for h in hosts:
        h = {**h, "access": {**h["access"]}, "report": {**h["report"]}}
        if c["kind"] == "retire-key":
            h["access"]["held"] = [k for k in h["access"]["held"] if k["fp"] != c["ref"]]
            h["access"]["trusted"] = [t for t in h["access"]["trusted"] if t["fp"] != c["ref"]]
        elif c["kind"] == "way-in" and h["id"] == c["ref"]:
            h["report"]["attack_paths"] = [p for p in h["report"]["attack_paths"] if p["kind"] != "network"]
        out.append(h)
    return out


@pytest.mark.parametrize("seed", range(40))
def test_choke_point_counts_equal_a_brute_force_recount(seed):
    import random
    rnd = random.Random(seed)  # noqa: S311 — reproducible test graphs
    pool = [("SHA256:" + chr(65 + i) * 43, rnd.choice(["root", "deploy"])) for i in range(6)]
    hosts = []
    for i in range(9):
        paths = []
        if rnd.random() < 0.3:
            paths.append(path(root=rnd.random() < 0.5, users=["deploy"] if rnd.random() < 0.5 else ["www-data"]))
        if rnd.random() < 0.2:
            paths.append(path("foothold"))
        keys = [held(fp, who) for fp, who in rnd.sample(pool, rnd.randint(0, 2))]
        trusted = [trusts(fp, rnd.choice(["root", "deploy"])) for fp, _ in rnd.sample(pool, rnd.randint(0, 3))]
        accts = [account("root", 0), account("deploy", 1000, ["docker"] if rnd.random() < 0.3 else [])]
        hosts.append(lhost(f"h{i}", f"10.0.0.{i + 1}", keys=keys, trusted=trusted, accounts=accts, paths=paths))
    out = fleet.build(hosts)
    before = reached(out)
    for c in out["choke_points"]:
        if c["kind"] == "untrust-key":
            continue  # its target is named in words; retire-key and way-in are recounted exactly
        after = reached(fleet.build(without(hosts, c)))
        assert len(before - after) == c["cuts"], (seed, c)
