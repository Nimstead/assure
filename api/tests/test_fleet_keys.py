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
    assert all(not c["lower_bound"] for c in choke)
    assert [c["cuts"] for c in choke] == sorted((c["cuts"] for c in choke), reverse=True)


def test_a_cut_short_graph_says_its_counts_are_a_lower_bound(monkeypatch):
    monkeypatch.setattr(fleet, "KEY_WAYS_MAX", 2)
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
        hosts.append(lhost(f"h{i}", f"10.0.0.{i + 1}", keys=keys, trusted=trusted, accounts=accts, paths=paths, internet=rnd.random() < 0.2))
    out = fleet.build(hosts)
    before = reached(out)
    for c in out["choke_points"]:
        if c["kind"] == "untrust-key":
            continue  # its target is named in words; retire-key and way-in are recounted exactly
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
