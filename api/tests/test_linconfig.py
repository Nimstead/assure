"""Linux settings that open a stage of an attack path (tasks/spec-paths.md Module 2): each check opens on what the access read
shows, says who it helps, never opens on what wasn't read, and closes only on a complete read."""

import copy

import pytest
from sqlalchemy import select
from test_access import read
from test_api import user
from test_runtime import doc, host, pkgs

from nimstead import linconfig
from nimstead.db import Finding, make_sessionmaker

LISTENING = (True, "sshd.service listens on 0.0.0.0:22")


def account(name, uid, groups=(), login=True, password="locked", sudo_all=False):  # noqa: S107 — a password state, not a password
    return {"name": name, "uid": uid, "groups": sorted({name, *groups}), "login": login, "password": password, "sudo_all": sudo_all}


ROOT = account("root", 0, login=True)
STOCK = {"accounts": [ROOT, account("www-data", 33, login=False)], "writable": []}  # a stock install: nothing planted


def clean_read(**kw):
    return read(**{**STOCK, **kw})


def data(**kw):
    return {k: v for k, v in clean_read(**kw).items() if k not in ("v", "state", "problem")}


def checks(d, listening=LISTENING):
    return {f["package"]: f for f in linconfig.evaluate(d, listening)}


def test_a_stock_read_opens_nothing():
    assert checks(data()) == {}


def test_root_password_sign_in_needs_every_piece():
    d = data(accounts=[{**ROOT, "password": "usable"}])
    d["sshd"] = {**d["sshd"], "permitrootlogin": "yes", "passwordauthentication": "yes"}
    f = checks(d)["ssh-root-password"]
    assert f["vuln_id"] == "CFG:ssh-root-password" and f["risk"].priority == "next" and f["helps"] == ["anyone on the network"]
    assert "0.0.0.0:22" in f["summary"]
    assert "ssh-root-password" not in checks(d, (False, "sshd.service listens only on loopback"))
    assert "ssh-root-password" not in checks(d, None)
    for change in ({"accounts": [ROOT]}, {"sshd": {**d["sshd"], "permitrootlogin": "prohibit-password"}},
                   {"sshd": {**d["sshd"], "passwordauthentication": "no"}}):
        assert "ssh-root-password" not in checks({**d, **change}), change


def test_empty_passwords_need_an_account_with_none():
    d = data(accounts=[ROOT, account("guest", 1001, password="empty")])
    d["sshd"] = {**d["sshd"], "permitemptypasswords": "yes", "passwordauthentication": "yes"}
    f = checks(d)["ssh-empty-passwords"]
    assert f["risk"].priority == "fix-now" and "guest" in f["summary"]
    assert "ssh-empty-passwords" not in checks({**d, "accounts": [ROOT, account("guest", 1001)]})


def test_root_equivalent_groups_and_sudo_say_who_they_help():
    d = data(accounts=[account("root", 0, ["disk"]), account("www-data", 33, ["docker"], login=False), account("deploy", 1000, sudo_all=True),
                       account("ops", 1001, sudo_all=None)])
    c = checks(d)
    assert c["root-equivalent-group"]["helps"] == ["www-data"] and "www-data (docker)" in c["root-equivalent-group"]["summary"]
    assert c["sudo-nopasswd-all"]["helps"] == ["deploy"]  # root's own disk group and an unread sudo open nothing


def test_writable_files_and_shadow():
    d = data(writable=[{"path": "/etc/cron.d/backup", "kind": "cron", "by": "everyone", "at": "/etc/cron.d/backup"},
                       {"path": "/opt/app/bin/app", "kind": "service", "by": "group:deploy", "at": "/opt/app/bin"}],
             shadow_readable_by=["group:adm"], accounts=[ROOT, account("www-data", 33, ["deploy"], login=False), account("syslog", 104, ["adm"], login=False)])
    c = checks(d)
    w = c["writable-root-run"]
    assert w["risk"].priority == "next" and w["helps"] == ["anyone with an account"]
    assert "/opt/app/bin/app (deploy can replace /opt/app/bin)" in w["summary"] and w["version"] == "2 files"
    assert c["shadow-readable"]["helps"] == ["syslog"]  # the group's members, not its name
    only_group = checks(data(writable=[d["writable"][1]], accounts=d["accounts"]))["writable-root-run"]
    assert only_group["risk"].priority == "planned" and only_group["helps"] == ["www-data"]  # a member of deploy


def test_nothing_unread_opens_anything():
    assert linconfig.evaluate(None) == []
    assert checks(data(sshd=None, shadow_readable_by=None, accounts=[], writable=[])) == {}


@pytest.mark.parametrize("programs,sshd,want", [
    ([{"name": "ssh.service", "listen": ["0.0.0.0:22/tcp", "[::]:22/tcp"]}], None, True),
    ([{"name": "sshd.service", "listen": ["127.0.0.1:22/tcp"]}], None, False),
    ([{"name": "nginx.service", "listen": ["0.0.0.0:80/tcp"]}], {"installed": True, "listenaddress": ["0.0.0.0:22"]}, False),  # runs? no
    (None, {"installed": True, "listenaddress": ["0.0.0.0:22", "[::]:22"]}, True),  # no runtime read: the configuration, said so
    (None, {"installed": True, "listenaddress": ["127.0.0.1:22"]}, False),
    (None, {"installed": False}, None),
    (None, None, None),
    ([{"name": "systemd", "listen": ["0.0.0.0:22/tcp"]}], {"installed": True, "port": ["22"]}, True),  # socket activation: systemd holds :22
    ([{"name": "systemd", "listen": ["0.0.0.0:2222/tcp"]}], {"installed": True, "port": ["2222"]}, True),
    ([{"name": "sshd.service", "listen": []}], None, False),
])
def test_whether_sshd_listens_beyond_loopback(programs, sshd, want):
    got = linconfig.ssh_listening(programs, sshd)
    assert (got[0] if got else None) is want
    if programs is None and want:
        assert "whether it runs isn't read" in got[1]


# ---- through the inventory: open, held open while unread, closed on a complete read ---------------------------------

def report(c, h, acc, line_state=None):
    packages = pkgs()
    collection = copy.deepcopy(doc(len(packages)))
    collection["sources"]["access"] = {"state": line_state or (acc or {}).get("state", "off"), "count": 1}
    body = {"os_name": "Debian 12", "ecosystem": "Debian:12", "packages": packages, "agent_version": "0.11.0", "collection": collection}
    if acc is not None:
        body["access"] = acc
    r = c.post("/api/agent/inventory", headers=h, json=body)
    assert r.status_code == 200, r.text


def settings(env, aid, status="open"):
    s = make_sessionmaker(env)()
    return {f.package: f for f in s.scalars(select(Finding).where(Finding.asset_id == aid, Finding.ecosystem == "LinuxConfig", Finding.status == status))}


def test_a_setting_opens_stays_open_while_unread_and_closes_on_a_complete_read(env):
    c = user(env)
    aid, h = host(c)
    docker = read(accounts=[account("root", 0), account("www-data", 33, ["docker"], login=False)])
    report(c, h, docker)
    f = settings(env, aid)["root-equivalent-group"]
    assert f.vuln_id == "CFG:root-equivalent-group" and f.fixed_version is None and "docker" in f.summary
    clean = clean_read()
    report(c, h, {**clean, "state": "partial", "problem": "stopped at the 10-second limit"})
    assert "root-equivalent-group" in settings(env, aid)  # a partial read proves nothing is gone
    report(c, h, None, line_state="off")
    assert "root-equivalent-group" in settings(env, aid)  # nor does turning the read off
    report(c, h, clean)
    assert "root-equivalent-group" not in settings(env, aid) and "root-equivalent-group" in settings(env, aid, "resolved")
