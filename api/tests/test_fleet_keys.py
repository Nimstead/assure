"""SSH key edges across Linux hosts (tasks/spec-paths.md Module 4, DECISIONS 168): A -> B only when a key held on A is trusted
on B for an account sshd lets in, graded by sshd's own rules, and chains that know which account the attacker holds."""

import pytest

from nimstead.engine import fleet

K_ROOT, K_DEPLOY, K_OTHER = ("SHA256:" + c * 43 for c in "RDO")
PROHIBIT = {"installed": True, "permitrootlogin": "prohibit-password", "pubkeyauthentication": "yes", "passwordauthentication": "no",
            "kbdinteractiveauthentication": "no", "permitemptypasswords": "no", "strictmodes": "yes", "authorizedkeysfile": [".ssh/authorized_keys"],
            "authorizedkeyscommand": False, "allowusers": [], "denyusers": [], "allowgroups": [], "denygroups": [], "port": ["22"],
            "listenaddress": ["0.0.0.0:22"], "match": False, "usepam": "yes"}


def path(kind="network", root=True, users=(), grade="reasonable"):
    return {"kind": kind, "start": "from the network", "grade": grade, "steps": [{"stage": "entry", "label": "Getting in", "ways": [], "count": 1}],
            "then": None, "break_at": {"stage": "entry", "label": "Getting in", "fixes": 1, "refs": []}, "reaches": {"root": root, "users": list(users)}}


def held(fp, account="root", passphrase=False, checked=True):
    return {"account": account, "path": f"/{'root' if account == 'root' else 'home/' + account}/.ssh/id_ed25519", "type": "ssh-ed25519",
            "fp": fp, "passphrase": passphrase, "checked": checked}


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
    assert edge(seen)["grade"] == "confirmed" and "A had a connection open to B's sshd" in edge(seen)["ways"][0]["because"]
    # code review: a connection to any of B's ports confirmed it, a database's too
    assert edge(fleet.build([A(peers=["10.0.0.2:5432"]), lhost("b", "10.0.0.2", trusted=[trusts(K_ROOT)])]))["grade"] == "reasonable"
    moved = fleet.build([A(peers=["10.0.0.2:2222"]), lhost("b", "10.0.0.2", trusted=[trusts(K_ROOT)], sshd={**PROHIBIT, "port": ["2222"]})])
    assert edge(moved)["grade"] == "confirmed" and edge(moved)["ways"][0]["port"] == 2222


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
    # code review: AuthenticationMethods and ForceCommand weren't read, so a key that can't sign in alone graded confirmed
    ({"authenticationmethods": ["any"]}, "confirmed"),
    ({"authenticationmethods": ["publickey,keyboard-interactive:pam"]}, "unverified"),  # a one-time code too
    ({"authenticationmethods": ["publickey,password", "publickey"]}, "confirmed"),     # either list: the key alone is one
    ({"authenticationmethods": ["password"]}, None),                                    # no key ever signs in
    ({"forcecommand": True}, "unverified"),
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


def two_reporting_hosts(env):
    """web-1, with a way in (nginx as root) and root's key, and db-1, which trusts that key, both reporting through the API."""
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
    return c, web, db


def test_the_endpoint_links_two_reporting_hosts_by_their_keys(env):
    c, web, db = two_reporting_hosts(env)
    out = c.get("/api/attack-paths").json()
    e = next(x for x in out["edges"] if (x["from"], x["to"]) == (web, db))
    assert e["kind"] == "ssh" and e["grade"] == "confirmed" and e["ways"][0]["gives"] == "root"
    paths = out["hosts"][web]["paths"]
    assert paths and paths[0]["kind"] == "network" and paths[0]["reaches"]["root"] is True
    assert any(ch["start"] == web and ch["reach"][0]["host"] == db for ch in out["chains"])
    assert out["flow"]["machines"][db]["route"] == [web, db] and out["flow"]["starts"][web]["reaches"] == 1


def test_the_flow_holds_every_machine_once_each_start_s_reach_in_full_and_what_cuts_it_off(monkeypatch):
    """The Attack paths page (DECISIONS 173) groups the flow, so it holds every machine reached, past the rows a chain lists;
    two ways in reaching the same machines both say so, and a start another reaches says which."""
    monkeypatch.setattr(fleet, "MAX_REACH", 2)
    bs = [f"b{i}" for i in range(5)]
    hosts = [lhost("w1", "10.0.0.1", keys=[held(K_ROOT)], paths=[path()]), lhost("w2", "10.0.0.2", keys=[held(K_ROOT)], paths=[path()]),
             lhost("w3", "10.0.0.3", trusted=[trusts(K_ROOT)], paths=[path()]),
             *[lhost(b, f"10.0.1.{i}", trusted=[trusts(K_ROOT)]) for i, b in enumerate(bs)]]
    out = fleet.build(hosts)
    f = out["flow"]
    assert set(f["machines"]) == {"w1", "w2", "w3", *bs}
    assert len(out["chains"][0]["reach"]) == 2 and out["chains"][0]["reach_count"] == 6  # the chain lists two; the flow holds them all
    for b in bs:
        m = f["machines"][b]
        assert m["route"][0] in ("w1", "w2") and m["route"][-1] == b and (m["via"], m["account"], m["as"]) == ("SSH:" + K_ROOT, "root", "root")
    assert all("route" not in f["machines"][w] and "via" not in f["machines"][w] for w in ("w1", "w2", "w3"))
    assert f["starts"]["w1"] == f["starts"]["w2"] == {"reaches": 6, "through": {"SSH:" + K_ROOT: 6}}
    assert f["starts"]["w3"] == {"covered_by": "w1"}
    key = next(i for i, c in enumerate(out["choke_points"]) if c["kind"] == "retire-key" and c["ref"] == K_ROOT)
    assert out["choke_points"][key]["cuts"] == 5 and all(key in f["machines"][b]["cut_by"] for b in bs)
    assert [(out["choke_points"][i]["kind"], out["choke_points"][i]["ref"]) for i in f["machines"]["w1"]["cut_by"]] == [("way-in", "w1")]  # only its own
    assert not any("_cut" in c for c in out["choke_points"])


# ---- choke points ---------------------------------------------------------------------------------------------------

def reached(out):
    """Every host an attacker holds something on, read from the endpoint's own output: starts (a way in, or marked
    internet-facing with any path) and chain reaches."""
    return ({h for h, v in out["hosts"].items() if v["entry"] or (v["internet_facing"] and v["paths"])}
            | {r["host"] for c in out["chains"] for r in c["reach"]})


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
    assert (key["held_on"], key["trusted_by"], key["accounts"]) == (["web-1"], 4, ["deploy"])  # named without parsing the action
    assert all(not c["lower_bound"] for c in choke)
    assert [c["cuts"] for c in choke] == sorted((c["cuts"] for c in choke), reverse=True)


def test_a_cut_short_graph_says_its_counts_are_a_lower_bound(monkeypatch):
    monkeypatch.setattr(fleet, "KEY_WAYS_MAX", 2)
    hosts = [A()] + [lhost(f"b{i}", f"10.0.1.{i}", trusted=[trusts(K_ROOT)]) for i in range(4)]
    out = fleet.build(hosts)
    assert out["choke_points"] and all(c["lower_bound"] for c in out["choke_points"]) and out["partial"]
    assert not fleet.build(hosts[:2])["partial"]


def test_a_host_claiming_many_holders_cant_spend_what_honest_hosts_need(monkeypatch):
    """Security audit: the key-way budget went first come, first served, so one host listing invented accounts that each
    "hold" the fleet's common key filled it, and the real bastion's chain disappeared."""
    monkeypatch.setattr(fleet, "KEY_WAYS_MAX", 10)
    targets = [lhost(f"b{i}", f"10.0.1.{i}", trusted=[trusts(K_ROOT)]) for i in range(5)]
    liar = lhost("liar", "10.0.2.1", keys=[held(K_ROOT, f"u{i}") for i in range(20)], accounts=[account(f"u{i}", 1000 + i) for i in range(20)])
    for order in ([liar, A(), *targets], [A(), liar, *targets]):
        out = fleet.build(order)
        assert {e["to"] for e in out["edges"] if e["from"] == "a"} == {f"b{i}" for i in range(5)}
        assert out["chains"][0]["start"] == "a" and len(out["chains"][0]["reach"]) == 5 and out["partial"]


def test_past_its_walks_the_view_says_it_is_partial(monkeypatch):
    monkeypatch.setattr(fleet, "MAX_WALKS", 1)
    hosts = [lhost("a1", "10.0.0.1", keys=[held(K_ROOT)], paths=[path()]), lhost("a2", "10.0.0.2", keys=[held(K_DEPLOY)], paths=[path()]),
             lhost("b", "10.0.0.3", trusted=[trusts(K_ROOT), trusts(K_DEPLOY)])]
    out = fleet.build(hosts)
    assert out["partial"] and len(out["chains"]) == 1
    monkeypatch.setattr(fleet, "MAX_WALKS", 2)
    assert not fleet.build(hosts)["partial"] and len(fleet.build(hosts)["chains"]) == 2


def test_a_start_another_start_reaches_as_root_has_no_chain_of_its_own_and_cuts_nothing():
    """Code review: a walk per start took 10 s with every host a start. One reached as root from another reaches nothing more."""
    hosts = [lhost("a", "10.0.0.1", keys=[held(K_ROOT)], paths=[path()]),
             lhost("b", "10.0.0.2", keys=[held(K_DEPLOY)], trusted=[trusts(K_ROOT)], paths=[path()]),
             lhost("c", "10.0.0.3", trusted=[trusts(K_DEPLOY)])]
    out = fleet.build(hosts)
    assert [c["start"] for c in out["chains"]] == ["a"] and [r["host"] for r in out["chains"][0]["reach"]] == ["b", "c"]
    assert not [c for c in out["choke_points"] if c["kind"] == "way-in" and c["ref"] == "b"]
    assert not out["partial"]


def without(hosts, c):
    """The same fleet with choke point c done for real in its inputs."""
    out = []
    for h in hosts:
        h = {**h, "access": {**h["access"]}, "report": {**h["report"]}}
        if c["kind"] == "retire-key":
            h["access"]["held"] = [k for k in h["access"]["held"] if k["fp"] != c["ref"]]
            h["access"]["trusted"] = [t for t in h["access"]["trusted"] if t["fp"] != c["ref"]]
        elif c["kind"] == "untrust-key" and h["id"] == c["on"]:
            h["access"]["trusted"] = [t for t in h["access"]["trusted"] if (t["fp"], t["account"]) != (c["ref"], c["account"])]
        elif c["kind"] == "way-in" and h["id"] == c["ref"]:
            h["report"]["attack_paths"] = [p for p in h["report"]["attack_paths"] if p["kind"] != "network"]
        out.append(h)
    return out


@pytest.mark.parametrize("seed", range(80))
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
        hosts.append(lhost(f"h{i}", f"10.0.0.{i + 1}", keys=keys, trusted=trusted, accounts=accts, paths=paths, internet=rnd.random() < 0.2))
    out = fleet.build(hosts)
    before = reached(out)
    for c in out["choke_points"]:
        after = reached(fleet.build(without(hosts, c)))
        assert len(before - after) == c["cuts"], (seed, c)


def test_an_sshd_that_isnt_running_makes_no_edge():
    stopped = lhost("b", "10.0.0.2", trusted=[trusts(K_ROOT)], sshd={"installed": True, "running": False})
    assert edge(fleet.build([A(), stopped])) is None


def test_without_pam_sshd_refuses_a_locked_account_and_no_shell_runs_nothing():
    # found by the lab's real ssh: Alpine's sshd runs without PAM, and passwd -l's "!" locks keys out too
    locked = [{**account("root", 0), "password": "locked"}, account("deploy", 1000)]
    nopam = {**PROHIBIT, "usepam": "no"}
    assert edge(fleet.build([A(), lhost("b", "10.0.0.2", trusted=[trusts(K_ROOT)], sshd=nopam, accounts=locked)])) is None
    assert edge(fleet.build([A(), lhost("b", "10.0.0.2", trusted=[trusts(K_ROOT)], sshd={**PROHIBIT, "usepam": "yes"}, accounts=locked)])) is not None
    none = [{**account("root", 0), "password": "none"}, account("deploy", 1000)]  # "*": no password, keys still open it
    assert edge(fleet.build([A(), lhost("b", "10.0.0.2", trusted=[trusts(K_ROOT)], sshd=nopam, accounts=none)])) is not None
    svc = [account("root", 0), {**account("www-data", 33), "login": False}]
    assert edge(fleet.build([A(), lhost("b", "10.0.0.2", trusted=[trusts(K_ROOT, "www-data")], accounts=svc)])) is None


def test_an_account_with_nopasswd_sudo_hands_over_root():
    accts = [account("root", 0), account("ops", 1001, sudo_all=True)]
    e = edge(fleet.build([lhost("a", "10.0.0.1", keys=[held(K_OTHER, "ops")], paths=[path()]),
                          lhost("b", "10.0.0.2", trusted=[trusts(K_OTHER, "ops")], accounts=accts)]))
    assert e["ways"][0]["gives"] == "root"


def test_reaching_a_host_twice_with_different_accounts_holds_both():
    # s -> x (root) and s -> b (deploy) leave s first; x -> b (ops) arrives before b is walked: b holds deploy and ops,
    # so deploy's key on b opens c and ops's opens d
    k_x, k_bd, k_bo, k_c, k_d = ("SHA256:" + ch * 43 for ch in "XYZCE")
    s = lhost("s", "10.0.0.1", keys=[held(k_x), held(k_bd, "deploy")], paths=[path()])
    x = lhost("x", "10.0.0.2", keys=[held(k_bo, "ops")], trusted=[trusts(k_x)], accounts=[account("root", 0), account("ops", 1001)])
    b = lhost("b", "10.0.0.3", keys=[held(k_c, "deploy"), held(k_d, "ops")], trusted=[trusts(k_bd, "deploy"), trusts(k_bo, "ops")],
              accounts=[account("root", 0), account("deploy", 1000), account("ops", 1001)])
    c = lhost("c", "10.0.0.4", trusted=[trusts(k_c)])
    d = lhost("d", "10.0.0.5", trusted=[trusts(k_d)])
    reach = {r["host"]: r for r in fleet.build([s, x, b, c, d])["chains"][0]["reach"]}
    assert reach["b"]["as"] == ["deploy", "ops"] and {"c", "d"} <= set(reach)


def test_a_windows_host_never_links_to_itself():
    from test_engine_fleet import OPEN_445, host
    from test_engine_paths import LOCAL, WEAK, rec
    both = host("w", {**WEAK, "remote_uac_off": 1}, {"listening": OPEN_445}, recs=[rec("CVE-2026-1001", LOCAL)])
    assert fleet.build([both])["edges"] == []


# ---- the review round (DECISIONS 170) -------------------------------------------------------------------------------

def test_every_start_s_way_in_is_scored_however_many_other_candidates(monkeypatch):
    monkeypatch.setattr(fleet, "MAX_CANDIDATES", 2)
    keys = ["SHA256:" + f"{i:043d}" for i in range(6)]
    hosts = [lhost("a", "10.0.0.1", keys=[held(k) for k in keys], paths=[path()])] + \
        [lhost(f"b{i}", f"10.0.1.{i}", trusted=[trusts(k)]) for i, k in enumerate(keys)]
    top = fleet.build(hosts)["choke_points"][0]
    assert (top["kind"], top["ref"], top["cuts"]) == ("way-in", "a", 7)


def test_closing_the_way_in_of_a_host_also_marked_internet_facing_leaves_it_a_start():
    a = lhost("a", "10.0.0.1", keys=[held(K_ROOT)], paths=[path(), path("foothold")], internet=True)
    out = fleet.build([a, lhost("b", "10.0.0.2", trusted=[trusts(K_ROOT)])])
    assert not any(c["kind"] == "way-in" for c in out["choke_points"])  # its foothold path still makes it a start, as root


def test_duplicate_keys_make_one_way_and_edges_list_at_most_five():
    dup = [trusts(K_ROOT)] * 1000
    out = fleet.build([lhost("a", "10.0.0.1", keys=[held(K_ROOT)] * 256, paths=[path()]), lhost("b", "10.0.0.2", trusted=dup)])
    assert len(edge(out)["ways"]) == 1
    many = [trusts("SHA256:" + f"{i:043d}") for i in range(8)]
    out = fleet.build([lhost("a", "10.0.0.1", keys=[held("SHA256:" + f"{i:043d}") for i in range(8)], paths=[path()]), lhost("b", "10.0.0.2", trusted=many)])
    assert len(edge(out)["ways"]) == fleet.WAYS_SHOWN and edge(out)["ways_count"] == 8


def test_allowusers_rules_as_sshd_reads_them():
    def g(allow):
        e = edge(fleet.build([A(), lhost("b", "10.0.0.2", trusted=[trusts(K_ROOT)], sshd={**PROHIBIT, "allowusers": allow})]))
        return e and e["grade"]
    assert g(["root@jump.example.com"]) == "unverified"  # a host name: let in, said, never resolved
    assert g(["ro[o]t"]) is None  # sshd has no [...] class: this names no one
    assert g(["deploy@x@10.0.0.*"]) is None and g(["root@x@10.0.0.*"]) is None  # the host is after the last @, the user before it
    renamed = [{**account("toor", 0)}, account("deploy", 1000)]  # uid 0 under another name is root to sshd
    e = edge(fleet.build([A(), lhost("b", "10.0.0.2", trusted=[trusts(K_ROOT, "toor")], sshd={**PROHIBIT, "permitrootlogin": "no"}, accounts=renamed)]))
    assert e is None


def test_a_dsa_or_security_key_link_is_unverified():
    dsa = {**held(K_ROOT), "type": "ssh-dss"}
    e = edge(fleet.build([lhost("a", "10.0.0.1", keys=[dsa], paths=[path()]), lhost("b", "10.0.0.2", trusted=[trusts(K_ROOT)])]))
    assert e["grade"] == "unverified" and "OpenSSH 7.0" in e["ways"][0]["because"]


def test_a_users_unchecked_key_is_unverified_roots_is_believed():
    unchecked = edge(fleet.build([lhost("a", "10.0.0.1", keys=[held(K_DEPLOY, "deploy", checked=False)], paths=[path()]),
                                  lhost("b", "10.0.0.2", trusted=[trusts(K_DEPLOY, "deploy")])]))
    assert unchecked["grade"] == "unverified" and "couldn't be checked" in unchecked["ways"][0]["because"]
    roots = edge(fleet.build([lhost("a", "10.0.0.1", keys=[held(K_ROOT, checked=False)], paths=[path()]),
                              lhost("b", "10.0.0.2", trusted=[trusts(K_ROOT)])]))
    assert roots["grade"] == "reasonable"


def test_a_choke_point_says_its_grade_and_one_resting_on_unverified_ways_comes_last():
    """Security audit: a planted key claim (unverified) could top "Cut these first" with "retire this key everywhere"."""
    planted = lhost("p", "10.0.3.1", keys=[held(K_OTHER, "deploy", checked=False)], paths=[path(root=False, users=["deploy"])])
    many = [lhost(f"m{i}", f"10.0.4.{i}", trusted=[trusts(K_OTHER)]) for i in range(5)]
    few = [lhost(f"f{i}", f"10.0.5.{i}", trusted=[trusts(K_ROOT)]) for i in range(2)]
    choke = fleet.build([A(), planted, *many, *few])["choke_points"]
    keys = [c for c in choke if c["kind"] == "retire-key"]
    assert [(c["ref"], c["grade"], c["cuts"]) for c in keys] == [(K_ROOT, "reasonable", 2), (K_OTHER, "unverified", 5)]
    assert choke.index(keys[0]) < choke.index(keys[1])
    assert all(c["grade"] in ("unverified", "reasonable", "confirmed") for c in choke)


def test_a_target_judged_before_its_ssh_state_was_reported_is_reasonable_at_most():
    """Upgrade path (test review): a stored report from before 0.15 has no ssh object; seen connected, it still can't confirm."""
    b = lhost("b", "10.0.0.2", trusted=[trusts(K_ROOT)])
    b["report"] = {"attack_paths": []}
    e = edge(fleet.build([A(peers=["10.0.0.2:22"]), b]))
    assert e["grade"] == "reasonable" and "whether it listens beyond loopback isn't read" in e["ways"][0]["because"]


def test_a_host_with_an_access_read_but_no_report_yet_is_reached_and_says_so():
    """Mid-ingest (test review): the access row is stored before the host's first report."""
    b = lhost("b", "10.0.0.2", trusted=[trusts(K_ROOT)])
    b["report"] = None
    out = fleet.build([A(), b])
    assert edge(out)["grade"] == "reasonable" and out["hosts"]["b"]["judged"] is False
    assert [r["host"] for r in out["chains"][0]["reach"]] == ["b"]


# ---- likely ways in (DECISIONS 172) ---------------------------------------------------------------------------------

def way(ref="CVE-1", refs=None, kev=False, flaws=1):
    return {"what": f"{ref} in pcre2", "ref": ref, "refs": [ref] if refs is None else refs, "grade": "reasonable", "kev": kev, "flaws": flaws}


def entry(*ways, count=None):
    p = path()
    p["steps"][0] |= {"ways": list(ways), "count": len(ways) if count is None else count}
    return p


def test_a_way_in_with_no_sign_of_exploitation_keeps_its_path_but_starts_nothing():
    a = lhost("a", "10.0.0.1", keys=[held(K_ROOT)], paths=[entry(way("CVE-1", ["CVE-1", "CVE-2"], flaws=2))])
    b = lhost("b", "10.0.0.2", trusted=[trusts(K_ROOT)])
    out = fleet.build([{**h, "epss": {"CVE-1": 0.004, "CVE-2": 0.02}} for h in (a, b)])
    assert out["hosts"]["a"]["entry"] is False and out["hosts"]["a"]["unlikely"] == {"epss": 0.02}
    assert out["hosts"]["a"]["paths"] and edge(out) is not None  # the path and the key link stay; only the chain and the cut go
    assert out["chains"] == [] and out["choke_points"] == []
    assert "unlikely" not in fleet.build([a, b])["hosts"]["a"]  # no EPSS looked up: every way in counts, as before


@pytest.mark.parametrize("ways, scores", [
    ([way(kev=True)], {"CVE-1": 0.004}),  # known exploited
    ([way()], {"CVE-1": 0.10}),  # EPSS at the risk model's 10%
    ([way()], {}),  # no score yet: a new flaw is never discounted
    ([way()], {"CVE-1": None}),
    ([way("CVE-1", ["CVE-1"], flaws=3)], {"CVE-1": 0.004}),  # flaws the way didn't list aren't known
    ([way("CVE-1", [])], {"CVE-1": 0.5}),  # an older report without refs: judged by its ref
    ([way("CFG:ssh-root-password", refs=[])], {}),  # a setting
    ([way(), way("CVE-2")], {"CVE-1": 0.004, "CVE-2": 0.3}),  # one likely way is enough
])
def test_a_way_in_counts_when_any_of_it_could_well_be_used(ways, scores):
    a = lhost("a", "10.0.0.1", keys=[held(K_ROOT)], paths=[entry(*ways)])
    out = fleet.build([{**h, "epss": scores} for h in (a, lhost("b", "10.0.0.2", trusted=[trusts(K_ROOT)]))])
    assert out["hosts"]["a"]["entry"] is True and "unlikely" not in out["hosts"]["a"] and out["chains"][0]["start"] == "a"


def test_ways_the_report_didnt_keep_count():
    a = lhost("a", "10.0.0.1", keys=[held(K_ROOT)], paths=[entry(way(), count=6)])
    out = fleet.build([{**a, "epss": {"CVE-1": 0.004}}, lhost("b", "10.0.0.2", trusted=[trusts(K_ROOT)])])
    assert out["hosts"]["a"]["entry"] is True


def test_an_internet_facing_host_with_an_unlikely_way_in_and_a_way_up_still_starts():
    a = lhost("a", "10.0.0.1", keys=[held(K_ROOT)], paths=[entry(way()), path("foothold")], internet=True)
    out = fleet.build([{**h, "epss": {"CVE-1": 0.004}} for h in (a, lhost("b", "10.0.0.2", trusted=[trusts(K_ROOT)]))])
    assert out["hosts"]["a"]["entry"] is False and out["chains"][0]["why_start"] == "marked internet-facing"


def test_an_internet_facing_host_whose_only_path_is_an_unlikely_way_in_is_no_start():
    a = lhost("a", "10.0.0.1", trusted=[trusts(K_ROOT)], paths=[entry(way())], internet=True)
    b = lhost("b", "10.0.0.2", trusted=[trusts(K_ROOT)])
    c = lhost("c", "10.0.0.3", keys=[held(K_ROOT)], paths=[entry(way("CVE-2"))])
    out = fleet.build([{**h, "epss": {"CVE-1": 0.004, "CVE-2": 0.5}} for h in (a, b, c)])
    retire = next(x for x in out["choke_points"] if x["kind"] == "retire-key")
    assert [ch["start"] for ch in out["chains"]] == ["c"] and retire["hosts"] == ["a", "b"]  # a is reached, so it can be cut off


def test_the_endpoint_reads_each_way_ins_epss(env):
    from sqlalchemy import select
    from sqlalchemy.orm import sessionmaker

    from nimstead.db import Epss, ScanRecord, make_engine
    c, web, db = two_reporting_hosts(env)
    assert c.get("/api/attack-paths").json()["hosts"][web]["entry"] is True  # no EPSS for its flaws: likely
    s = sessionmaker(make_engine(env))()
    report = s.scalars(select(ScanRecord.report).where(ScanRecord.asset_id == web).order_by(ScanRecord.created.desc())).first()
    [w] = next(p for p in report["attack_paths"] if p["kind"] == "network")["steps"][0]["ways"]
    assert w["refs"] and len(w["refs"]) == w["flaws"]
    s.add_all(Epss(cve=r, score=0.003, percentile=0.5) for r in w["refs"])
    s.commit()
    out = c.get("/api/attack-paths").json()
    assert out["hosts"][web]["entry"] is False and out["hosts"][web]["unlikely"] == {"epss": 0.003}
    assert not any(ch["start"] == web for ch in out["chains"])
