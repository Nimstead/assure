"""Attack paths on one Linux host (tasks/spec-paths.md Module 3, DECISIONS 167): a way in names the user the listening program
runs as, a root listener skips becoming root, a setting helps only the users it names, and credentials depend on whether the
path reached root. Windows paths keep their shape byte for byte."""

import copy

from test_access import read
from test_engine_linux import SSL, deb, lcontent, ldoc, pkg
from test_engine_paths import WEAK, rec
from test_engine_paths import run as windows_run

from nimstead.engine import paths, report
from nimstead.engine.collection import Inventory
from nimstead.engine.content import Content
from nimstead.engine.evaluate import evaluate

REMOTE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
LOCAL = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
FP_ROOT, FP_DEPLOY = "SHA256:" + "R" * 43, "SHA256:" + "D" * 43
SUDO = (pkg("sudo", "1.9.16p2-1"),)


def flaw(cve, src, vector, fixed="9:9"):
    r = deb(cve, src, fixed)
    r["severity"] = [{"type": "CVSS_V3", "score": vector}]
    return r


def account(name, uid, groups=(), login=False, sudo_all=False):
    return {"name": name, "uid": uid, "groups": sorted({name, *groups}), "login": login, "password": "locked", "sudo_all": sudo_all}


def access(accounts=None, held=None, writable=(), state="ok", **kw):
    a = {k: v for k, v in read().items() if k not in ("v", "problem", "trusted")}
    a.update(state=state, accounts=accounts or [account("root", 0, login=True), account("www-data", 33)], writable=list(writable),
             held=held if held is not None else [{"account": "root", "path": "/root/.ssh/id_ed25519", "type": "ssh-ed25519", "fp": FP_ROOT, "passphrase": False}],
             credentials=[], **kw)
    return a


def nginx(user="www-data", addr="10.89.7.11:443/tcp"):
    return {"libssl3t64": [{"program": "nginx.service", "users": [user], "listen": [addr]}]}


def build(*recs, listening=None, acc=None, extra=()):
    inv = Inventory.from_doc(ldoc(*SSL, *SUDO, *extra))
    inv.context = {**({"listening": listening} if listening is not None else {}), **({"access": acc} if acc is not None else {})}
    c = lcontent(*recs)
    return paths.build(inv, c, evaluate(inv, c)), inv, c


def by_kind(p):
    return {x["kind"]: x for x in p}


def test_a_listener_running_as_root_is_root_at_once_and_skips_becoming_root():
    p, inv, c = build(flaw("CVE-2026-0101", "openssl", REMOTE), listening=nginx("root"), acc=access())
    net = by_kind(p)["network"]
    assert [s["stage"] for s in net["steps"]] == ["entry", "credentials"]
    assert net["skipped"]["why"] == "the way in runs as root, so getting in is becoming root"
    assert net["reaches"] == {"root": True, "users": []}
    entry = net["steps"][0]["ways"][0]
    assert "Loaded by nginx.service, listening on 10.89.7.11:443, running as root" in entry["what"] and entry["grade"] == "reasonable"
    assert net["steps"][1]["ways"][0]["ref"] == FP_ROOT and net["then"]["count"] == 1
    assert "Becoming root: not needed" in report.render(report.build(inv, c, evaluate(inv, c)))


def test_www_data_needs_a_way_up_it_can_use():
    docker = access(accounts=[account("root", 0, login=True), account("www-data", 33, ["docker"])])
    p, *_ = build(flaw("CVE-2026-0101", "openssl", REMOTE), listening=nginx(), acc=docker)
    net = by_kind(p)["network"]
    assert [s["stage"] for s in net["steps"]] == ["entry", "escalate", "credentials"]
    assert net["steps"][1]["ways"][0]["ref"] == "CFG:root-equivalent-group" and net["reaches"]["root"] is True
    assert net["steps"][1]["label"] == "Becoming root" and "skipped" not in net
    # deploy's NOPASSWD sudo helps deploy, not www-data: no way up, and www-data holds no key of its own
    sudo = access(accounts=[account("root", 0, login=True), account("www-data", 33), account("deploy", 1000, login=True, sudo_all=True)])
    p, *_ = build(flaw("CVE-2026-0101", "openssl", REMOTE), listening=nginx(), acc=sudo)
    assert "network" not in by_kind(p)


def test_a_local_flaw_any_user_can_use_is_a_way_up_with_its_own_grade():
    p, *_ = build(flaw("CVE-2026-0101", "openssl", REMOTE), flaw("CVE-2025-32463", "sudo", LOCAL), listening=nginx(), acc=access())
    net = by_kind(p)["network"]
    up = net["steps"][1]["ways"][0]
    assert up["ref"] == "CVE-2025-32463" and up["grade"] == "confirmed" and net["grade"] == "reasonable"  # the entry's firewall caveat
    assert by_kind(p)["foothold"]["steps"][0]["ways"][0]["ref"] == "CVE-2025-32463"


def test_without_root_only_the_way_in_users_own_keys_are_taken():
    held = [{"account": "www-data", "path": "/var/www/.ssh/deploy", "type": "ssh-ed25519", "fp": FP_DEPLOY, "passphrase": False},
            {"account": "root", "path": "/root/.ssh/id_ed25519", "type": "ssh-ed25519", "fp": FP_ROOT, "passphrase": True}]
    p, *_ = build(flaw("CVE-2026-0101", "openssl", REMOTE), listening=nginx(), acc=access(held=held))
    net = by_kind(p)["network"]
    assert [w["ref"] for w in net["steps"][1]["ways"]] == [FP_DEPLOY] and net["reaches"] == {"root": False, "users": ["www-data"]}
    # once root, every key, and one with a passphrase is unverified
    p, *_ = build(flaw("CVE-2026-0101", "openssl", REMOTE), listening=nginx("root"), acc=access(held=held))
    ways = {w["ref"]: w for w in by_kind(p)["network"]["steps"][1]["ways"]}
    assert ways[FP_ROOT]["grade"] == "unverified" and "needs its passphrase" in ways[FP_ROOT]["what"] and ways[FP_DEPLOY]["grade"] == "confirmed"


def test_a_remote_flaw_nothing_listening_loaded_is_no_way_in_unless_exploited():
    recs = (flaw("CVE-2026-0101", "openssl", REMOTE), flaw("CVE-2025-32463", "sudo", LOCAL))
    p, *_ = build(*recs, listening={}, acc=access())
    assert "network" not in by_kind(p)
    inv = Inventory.from_doc(ldoc(*SSL, *SUDO))
    inv.context = {"listening": {}, "access": access()}
    c = Content.make({("Debian:13", "openssl"): [recs[0]], ("Debian:13", "sudo"): [recs[1]]}, kev={"CVE-2026-0101"}, feeds={"Debian:13"},
                     universe={"openssl", "sudo"})
    p = paths.build(inv, c, evaluate(inv, c))
    net = by_kind(p)["network"]
    entry = net["steps"][0]["ways"][0]
    assert entry["kev"] and "no listener was seen" in entry["what"] and entry["grade"] == "reasonable"
    assert net["steps"][1]["ways"][0]["ref"] == "CVE-2025-32463"  # who it runs as is unknown: only a way up anyone can use counts


def test_root_password_sign_in_is_a_way_in_as_root():
    acc = access(accounts=[{**account("root", 0, login=True), "password": "usable"}])
    acc["sshd"] = {**acc["sshd"], "permitrootlogin": "yes", "passwordauthentication": "yes"}
    p, *_ = build(listening={"openssh-server": [{"program": "ssh.service", "users": ["root"], "listen": ["0.0.0.0:22/tcp"]}]}, acc=acc)
    net = by_kind(p)["network"]
    assert net["steps"][0]["ways"][0]["ref"] == "CFG:ssh-root-password" and net["reaches"]["root"] and "skipped" in net


def test_a_partial_access_read_grades_its_steps_unverified():
    p, *_ = build(flaw("CVE-2026-0101", "openssl", REMOTE), listening=nginx("root"), acc=access(state="partial"))
    assert by_kind(p)["network"]["grade"] == "unverified"


def test_no_context_means_no_linux_path_and_windows_is_unchanged():
    p, *_ = build(flaw("CVE-2026-0101", "openssl", REMOTE), flaw("CVE-2025-32463", "sudo", LOCAL))
    assert p == []  # nothing listening seen, no key known: nothing chains
    w, _ = windows_run(rec("CVE-2026-1001", "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"), config=WEAK)
    assert all("reaches" not in x and "skipped" not in x for x in w)


def test_the_context_rides_in_the_document_only_when_there_is_one():
    inv = Inventory.from_doc(ldoc(*SSL))
    bare = copy.deepcopy(inv.to_doc())
    assert "context" not in bare
    inv.context = {"listening": {}}
    assert inv.to_doc()["context"] == {"listening": {}} and inv.sha256() != Inventory.from_doc(ldoc(*SSL)).sha256()
