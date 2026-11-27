"""Who can get in and what they hold, as the server stores it (tasks/spec-paths.md Module 1, DECISIONS 165): the agent's
`access` read validated as hostile input, stored one row per host, kept on a failed read, dropped when the host opts out."""

import json

import pytest
from test_runtime import doc, host, pkgs

from nimstead import access
from nimstead.db import AssetAccess, make_sessionmaker

FP = "SHA256:" + "A" * 43
FP2 = "SHA256:" + "B" * 43


def read(state="ok", **kw):
    base = {"v": 1, "state": state, "problem": None,
            "sshd": {"installed": True, "permitrootlogin": "prohibit-password", "pubkeyauthentication": "yes", "passwordauthentication": "no",
                     "kbdinteractiveauthentication": "no", "permitemptypasswords": "no", "strictmodes": "yes", "authorizedkeysfile": [".ssh/authorized_keys"],
                     "authorizedkeyscommand": False, "allowusers": [], "denyusers": [], "allowgroups": [], "denygroups": [], "port": ["22"],
                     "listenaddress": ["0.0.0.0:22"], "match": False, "usepam": "yes",
                     "authenticationmethods": ["any"], "forcecommand": False},
            "accounts": [{"name": "root", "uid": 0, "groups": ["root"], "login": True, "password": "locked", "sudo_all": None},
                         {"name": "www-data", "uid": 33, "groups": ["docker", "www-data"], "login": False, "password": "locked", "sudo_all": False}],
            "writable": [{"path": "/etc/cron.d/backup", "kind": "cron", "by": "everyone", "at": "/etc/cron.d/backup"}],
            "shadow_readable_by": [],
            "held": [{"account": "root", "path": "/root/.ssh/id_ed25519", "type": "ssh-ed25519", "fp": FP, "passphrase": False, "checked": True}],
            "trusted": [{"account": "root", "fp": FP2, "type": "ssh-ed25519", "from": ["10.0.0.0/8"], "forced": False, "restrict": False}],
            "credentials": [{"kind": "keytab", "account": "root", "path": "/etc/krb5.keytab"}], "agent_sockets": 1, "unidentified_keys": 0}
    return {**base, **kw}


def test_a_well_formed_read_is_kept_whole():
    r = read()
    assert access.valid(r) == r


def test_what_doesnt_fit_is_dropped_never_the_read():
    r = read(extra="x", agent_sockets=10**9)
    r["accounts"] += [{"name": "bad name!", "uid": 1}, {"name": "x", "uid": -1}, {"name": "root", "uid": 5}, "junk"]
    r["held"] += [{"account": "nobody", "path": "/x", "type": "ssh-ed25519", "fp": FP, "passphrase": False},       # not a listed account
                  {"account": "root", "path": "/a‮b", "type": "ssh-ed25519", "fp": FP, "passphrase": False},  # bidirectional override
                  {"account": "root", "path": "/a\nb", "type": "ssh-ed25519", "fp": FP, "passphrase": False},      # control character
                  {"account": "root", "path": "/k", "type": "ssh-ed25519", "fp": "MD5:aa:bb", "passphrase": False}]
    r["trusted"] += [{"account": "root", "fp": FP, "type": "ssh-ed25519", "from": ["10.0.0.0/8"], "forced": "yes"},
                     # a from= entry that can't be read could be the negation that refuses: the line is dropped, never widened
                     {"account": "root", "fp": FP, "type": "ssh-ed25519", "from": ["10.0.0.0/8", "!evil host"], "forced": False},
                     {"account": "root", "fp": FP, "type": "ssh-ed25519", "from": ["x" * 200], "forced": False},
                     {"account": "root", "fp": FP, "type": "ssh-ed25519", "from": "10.0.0.0/8", "forced": False}]
    r["writable"] += [{"path": "/etc/x", "kind": "magic", "by": "everyone"}, {"path": "/etc/y", "kind": "cron", "by": "root"}]
    r["sshd"]["permitrootlogin"] = "yes"
    r["sshd"]["allowusers"] = ["deploy", "bad user", 7]
    v = access.valid(r)
    assert [a["name"] for a in v["accounts"]] == ["root", "www-data"]
    assert len(v["held"]) == 1 and len(v["writable"]) == 1
    assert v["trusted"][-1] == {"account": "root", "fp": FP, "type": "ssh-ed25519", "from": ["10.0.0.0/8"], "forced": False, "restrict": False}
    assert v["sshd"]["allowusers"] == ["deploy"] and "extra" not in v and v["agent_sockets"] == 0


def test_lists_are_capped(monkeypatch):
    monkeypatch.setattr(access, "TRUSTED", 3)
    r = read(trusted=[{"account": "root", "fp": FP, "type": "ssh-rsa", "from": [], "forced": False, "restrict": False}] * 10)
    assert len(access.valid(r)["trusted"]) == 3


@pytest.mark.parametrize("raw", [None, [], "x", 3, {}, {"v": 2, "state": "ok"}, {"v": 1, "state": "maybe"}, {"v": 1, "state": "ok", "accounts": "x",
                                 "held": {"a": 1}, "sshd": [1], "trusted": [None, 1, "x"], "shadow_readable_by": "everyone"}])
def test_anything_that_isnt_a_read_is_refused_or_reduced_and_never_raises(raw):
    v = access.valid(raw)
    assert v is None or (v["accounts"] == [] and v["held"] == [] and v["sshd"] is None and v["shadow_readable_by"] is None)


def _paths(v, at=()):
    """Every scalar inside a read, as a path of keys and indexes."""
    if isinstance(v, dict):
        for k, x in v.items():
            yield from _paths(x, (*at, k))
    elif isinstance(v, list) and v and not isinstance(v[0], str):
        for i, x in enumerate(v):
            yield from _paths(x, (*at, i))
    else:
        yield at


@pytest.mark.parametrize("bad", [[], {}, 1, True, None, "x" * 300])
def test_any_field_of_any_shape_never_raises(bad):
    """Test review: a list where a type, kind or setting belonged raised TypeError (an unhashable value tested against a set),
    so the inventory request failed with a 500 and the host lost its whole report."""
    for at in _paths(read()):
        r = json.loads(json.dumps(read()))
        cur = r
        for k in at[:-1]:
            cur = cur[k]
        cur[at[-1]] = bad
        access.valid(r)


def test_an_sshd_that_isnt_installed_and_one_that_wasnt_read_differ():
    assert access.valid(read(sshd={"installed": False}))["sshd"] == {"installed": False}
    assert access.valid(read(sshd=None))["sshd"] is None
    assert access.valid(read(sshd={"installed": True, "permitrootlogin": "maybe"}))["sshd"] is None


def report(c, h, acc=None, off=False, agent="0.11.0"):
    packages = pkgs()
    body = {"os_name": "Debian 12", "ecosystem": "Debian:12", "packages": packages, "agent_version": agent, "collection": doc(len(packages))}
    if acc is not None:
        body["access"] = acc
    if off:
        body["collection"]["sources"]["access"] = {"state": "off", "count": 0}
    r = c.post("/api/agent/inventory", headers=h, json=body)
    assert r.status_code == 200, r.text
    return r.json()


def row(env, asset_id):
    s = make_sessionmaker(env)()
    return s.get(AssetAccess, asset_id)


def test_the_inventory_stores_the_read_keeps_it_through_a_failure_and_forgets_it_on_opt_out(env):
    from test_api import user
    c = user(env)
    aid, h = host(c)
    report(c, h, read())
    r = row(env, aid)
    assert r.state == "ok" and r.data["held"][0]["fp"] == FP and r.data_at is not None
    first = r.data_at
    report(c, h, {"v": 1, "state": "failed", "problem": "not read: OSError: boom"})
    r = row(env, aid)
    assert r.state == "failed" and r.problem.startswith("not read") and r.data["held"][0]["fp"] == FP and r.data_at == first
    report(c, h, read(state="partial", problem="stopped at the 10-second limit", held=[]))
    r = row(env, aid)
    assert r.state == "partial" and r.data["held"] == []  # what a partial read saw counts
    report(c, h, off=True)
    assert row(env, aid) is None


def test_an_agent_moved_back_to_one_that_doesnt_read_access_leaves_nothing_behind(env):
    from test_api import user
    c = user(env)
    aid, h = host(c)
    report(c, h, read())
    assert row(env, aid) is not None
    report(c, h, agent="0.10.0")  # no access object and no access line: it can't read it
    assert row(env, aid) is None


def test_a_body_from_an_older_agent_stores_nothing(env):
    from test_api import user
    c = user(env)
    aid, h = host(c)
    report(c, h, agent="0.10.0")
    assert row(env, aid) is None
    report(c, h, {"v": 1, "state": "ok", "accounts": "not a list"})  # reduced, still stored, carrying nothing usable
    assert json.loads(json.dumps(row(env, aid).data))["accounts"] == []


def test_an_installed_sshd_not_running_is_kept_as_such():
    assert access.valid(read(sshd={"installed": True, "running": False}))["sshd"] == {"installed": True, "running": False}


@pytest.mark.parametrize("bad", ["/a\u0085b", "/a\u009bb", "/a b", "/a b", "/a؜b", "/a​b", "/a‮b", "/a\nb", "x" * 256, ""])
def test_a_path_with_any_control_format_or_separator_character_is_dropped(bad):
    r = read(held=[{"account": "root", "path": bad, "type": "ssh-ed25519", "fp": FP, "passphrase": False}])
    assert access.valid(r)["held"] == []


def test_ordinary_unicode_paths_are_kept():
    r = read(held=[{"account": "root", "path": "/home/zoë/.ssh/id_日本", "type": "ssh-ed25519", "fp": FP, "passphrase": False}])
    assert access.valid(r)["held"][0]["path"] == "/home/zoë/.ssh/id_日本"
