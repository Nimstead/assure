"""The agent reads what runs (tasks/spec-runtime.md Module 1, DECISIONS 161): each program's loaded files, the copies replaced
since it started and its listening sockets, matched to packages by the package manager's own file lists.

Fixtures are real /proc text recorded on disposable WSL distros (Debian 13 and AlmaLinux 9 with systemd, Alpine 3.21 with
OpenRC) running nginx, sshd and PostgreSQL, after a library upgrade with nginx still running; `oracle.json` holds each
distribution's own answer (dpkg -S, rpm -qf, apk info --who-owns) for the files nginx mapped, and `*-ss.txt` is `ss -H
-ltnup` from the same moment."""

import importlib.util
import json
import os
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("nimstead_agent", Path(__file__).parents[2] / "agent" / "nimstead_agent.py")
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)

FIX = Path(__file__).parent / "fixtures" / "proc"
ORACLE = json.loads((FIX / "oracle.json").read_text())
POSIX = pytest.mark.skipif(os.name == "nt", reason="the fake /proc tree needs symbolic links")
DISTROS = ("debian13", "alma9", "alpine321")


def fx(name):
    return (FIX / name).read_text(encoding="utf-8")


# ---- maps -----------------------------------------------------------------------------------------------------------

def test_maps_of_a_real_nginx_after_a_libc_upgrade_on_debian():
    mapped, replaced = agent.parse_maps(fx("debian13-nginx-maps.txt"))
    assert {"/usr/sbin/nginx", "/usr/lib/x86_64-linux-gnu/libssl.so.3", "/usr/lib/x86_64-linux-gnu/libcrypto.so.3"} <= mapped
    assert {"/usr/lib/x86_64-linux-gnu/libc.so.6", "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"} <= replaced
    assert not any(p.startswith("[") or p.endswith("(deleted)") for p in mapped | replaced)
    assert "/usr/lib/x86_64-linux-gnu/libc.so.6" not in mapped  # the copy it runs is the replaced one


@pytest.mark.parametrize("tag", DISTROS)
def test_every_file_the_distribution_says_nginx_mapped_is_read(tag):
    mapped, replaced = agent.parse_maps(fx(f"{tag}-nginx-maps.txt"))
    want = {p.removesuffix(" (deleted)") for p in ORACLE[tag]["oracle"]} - {"/usr/sbin/nginx"}  # the executable comes from exe
    assert want == (mapped | replaced) - {"/usr/sbin/nginx"}
    assert {p.removesuffix(" (deleted)") for p in ORACLE[tag]["oracle"] if p.endswith(" (deleted)")} == replaced


def test_maps_lines_that_are_not_files_are_skipped_and_rpm_temporaries_are_the_file_they_replaced():
    text = "\n".join([
        "55d0-55d1 r--p 00000000 08:30 14065   /usr/sbin/nginx",
        "7f00-7f01 rw-p 00000000 00:00 0 ",  # anonymous
        "7f01-7f02 rw-p 00000000 00:00 0   [heap]",
        "7f02-7f03 r--p 00000000 00:00 0   [vvar]",
        "7f03-7f04 r-xp 00000000 08:30 4161   /usr/lib64/libcrypto.so.3.5.9;6745a1b2 (deleted)",
        "7f04-7f05 r--p 00000000 00:2a 99   /usr/lib64/libssl.so.3.5.9",  # btrfs and overlayfs files sit on 00: devices too
        "7f05-7f06 r--p 00000000 08:30 77   /srv/a name with spaces",
        "7f06-7f07 r--p 00000000 08:30 78   /srv/new\\012line (deleted)",  # the kernel writes a newline as \012
        "garbage",
    ])
    mapped, replaced = agent.parse_maps(text)
    assert mapped == {"/usr/sbin/nginx", "/usr/lib64/libssl.so.3.5.9", "/srv/a name with spaces"}
    assert replaced == {"/usr/lib64/libcrypto.so.3.5.9", "/srv/new\\012line"}


# ---- cgroups --------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize(("tag", "unit"), [("debian13", "nginx.service"), ("alma9", "nginx.service"), ("alpine321", None)])
def test_units_from_real_cgroups(tag, unit):
    assert agent.parse_cgroup_unit(fx(f"{tag}-nginx-cgroup.txt")) == unit  # Alpine runs OpenRC: "0::/non-systemd"


@pytest.mark.parametrize(("text", "unit"), [
    ("0::/system.slice/system-postgresql.slice/postgresql@17-main.service", "postgresql@17-main.service"),
    ("0::/system.slice/systemd-udevd.service/udev", "systemd-udevd.service"),  # a service's own sub-cgroup is the service
    ("0::/init.scope", None),
    ("0::/user.slice/user-1000.slice/session-3.scope", None),
    ("0::/user.slice/user-1000.slice/user@1000.service/app.slice/mine.service", None),  # a user names these
    ("0::/system.slice/docker-0123abcd.scope", None),
    ("12:pids:/system.slice/cron.service\n1:name=systemd:/system.slice/cron.service\n0::/", "cron.service"),  # v1, hybrid
    ("1:name=systemd:/system.slice/ssh.service", "ssh.service"),
    ("0::/system.slice/evil‮ecivres.service", None),
    ("0::/system.slice/a b.service", None),
    ("0::/system.slice/" + "a" * 300 + ".service", None),
    ("", None),
])
def test_unit_rules(text, unit):
    assert agent.parse_cgroup_unit(text) == unit


# ---- listening sockets ------------------------------------------------------------------------------------------------

def ss_addresses(text):
    out = set()
    for ln in text.splitlines():
        f = ln.split()
        if len(f) >= 5 and f[1] in ("LISTEN", "UNCONN"):
            host, port = f[4].rsplit(":", 1)
            host = host.split("%")[0]  # ss writes an interface scope; /proc doesn't
            out.add(f"{host}:{port}/{f[0]}")
    return out


@pytest.mark.parametrize("tag", DISTROS)
def test_listening_sockets_equal_ss(tag):
    ours = {where for t in ("tcp", "tcp6", "udp", "udp6") for where, _ in agent.parse_net(fx(f"{tag}-net-{t}.txt"), t)}
    assert ours == ss_addresses(fx(f"{tag}-ss.txt")) and "0.0.0.0:80/tcp" in ours and "[::]:80/tcp" in ours


@pytest.mark.parametrize("tag", DISTROS)
def test_nginx_sockets_are_its_listeners(tag):
    by_inode = {inode: where for t in ("tcp", "tcp6") for where, inode in agent.parse_net(fx(f"{tag}-net-{t}.txt"), t)}
    assert {by_inode[i] for i in ORACLE[tag]["nginx_sockets"] if i in by_inode} == {"0.0.0.0:80/tcp", "[::]:80/tcp"}


def test_net_rows_that_are_not_listening_or_dont_parse_are_skipped():
    head = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
    rows = ["   0: 0100007F:1538 00000000:0000 0A 00000000:00000000 00:00000000 00000000   111        0 101 1",
            "   1: 0100007F:1538 0100007F:A1B2 01 00000000:00000000 00:00000000 00000000   111        0 102 1",  # established
            "   2: ZZZZ:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 103 1",
            "   3: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 0 1",
            "   4: 00000000:0000 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 104 1",
            "short"]
    assert agent.parse_net(head + "\n".join(rows), "tcp") == [("127.0.0.1:5432/tcp", 101)]
    udp = head + "  9: 00000000:0044 0A00000B:0035 07 00000000:00000000 00:00000000 00000000 0 0 105 2\n"  # a connected UDP socket
    assert agent.parse_net(udp, "udp") == []


# ---- package file lists -------------------------------------------------------------------------------------------------

@POSIX  # a colon in a Windows file name opens an alternate data stream
def test_dpkg_lists_drop_the_architecture(tmp_path):
    info = tmp_path / "info"
    info.mkdir()
    (info / "libssl3t64:amd64.list").write_text("/.\n/usr\n/usr/lib/x86_64-linux-gnu/libssl.so.3\n")
    (info / "nginx.list").write_text("/usr/sbin/nginx\n")
    (info / "nginx.md5sums").write_text("x  usr/sbin/nginx\n")
    got = list(agent.package_files(which=lambda n: n == "dpkg-query", dpkg_info=str(info), apk_db=str(tmp_path / "none")))
    assert ("libssl3t64", "/usr/lib/x86_64-linux-gnu/libssl.so.3") in got and ("nginx", "/usr/sbin/nginx") in got
    assert all(not p.endswith("md5sums") for _, p in got)


def test_apk_database_and_rpm_lists(tmp_path):
    db = tmp_path / "installed"
    db.write_text("P:musl\nV:1.2.5-r12\nF:lib\nR:ld-musl-x86_64.so.1\n\nP:nginx\nF:usr/sbin\nR:nginx\nF:var/lib/nginx\n\nP:empty\n")
    assert list(agent.package_files(apk_db=str(db))) == [("musl", "/lib/ld-musl-x86_64.so.1"), ("nginx", "/usr/sbin/nginx")]
    out = "glibc\t/usr/lib64/libc.so.6\nopenssl-libs\t/usr/lib64/libssl.so.3\nfilesystem\t(none)\n"
    seen = []
    got = list(agent.package_files(query=lambda cmd: (seen.append(cmd), (0, out, ""))[1], which=lambda n: n == "rpm",
                                   apk_db=str(tmp_path / "none")))
    assert seen == [agent.RPM_FILES] and got == [("glibc", "/usr/lib64/libc.so.6"), ("openssl-libs", "/usr/lib64/libssl.so.3")]
    with pytest.raises(agent.AgentError):
        list(agent.package_files(query=lambda cmd: (1, "", "error: rpmdb open failed"), which=lambda n: n == "rpm", apk_db=str(tmp_path / "none")))
    with pytest.raises(agent.AgentError):
        list(agent.package_files(which=lambda n: False, apk_db=str(tmp_path / "none")))


def test_owners_match_merged_usr_and_only_wanted_paths():
    files = [("libc6", "/lib/x86_64-linux-gnu/libc.so.6"), ("libc6", "/usr/share/doc/libc6/copyright"),
             ("nginx", "/usr/sbin/nginx"), ("python3-requests", "/usr/lib/python3/dist-packages/requests/api.py"),
             ("coreutils", "/usr/bin/ls"), ("tzdata", "/usr/share/zoneinfo/UTC"), ("scripts", "/usr/bin/a-script")]
    owners, native, problem = agent.runtime_owners({"/usr/lib/x86_64-linux-gnu/libc.so.6", "/usr/sbin/nginx", "/srv/x"}, files,
                                                   is_elf=lambda p: p in ("/usr/sbin/nginx", "/usr/bin/ls"))
    assert owners == {"/usr/lib/x86_64-linux-gnu/libc.so.6": {"libc6"}, "/usr/sbin/nginx": {"nginx"}} and problem is None
    assert native == {"libc6", "nginx", "coreutils"}  # python3-requests, tzdata and a shell script can't be said "not loaded"


def test_owners_stop_at_their_budgets_with_the_same_words(monkeypatch):
    monkeypatch.setattr(agent, "RUNTIME_PATHS", 3)
    files = [("a", f"/usr/lib/lib{i}.so") for i in range(10)]
    _, native, problem = agent.runtime_owners(set(), files)
    assert problem == "stopped at its file-list budget (3 paths)" and native == {"a"}
    monkeypatch.setattr(agent, "RUNTIME_PATHS", 2_000_000)
    _, _, problem = agent.runtime_owners(set(), (("a", f"/x/{i}") for i in range(10_000)), late=lambda: True)
    assert problem == f"stopped at its time budget ({agent.RUNTIME_SECONDS} s)"

    def broken():
        yield "a", "/usr/lib/liba.so"
        raise OSError(13, "Permission denied")
    owners, native, problem = agent.runtime_owners({"/usr/lib/liba.so"}, broken())
    assert problem == "the package manager's file list couldn't be read: Permission denied" and owners == {"/usr/lib/liba.so": {"a"}}


def test_a_renamed_library_is_named_by_its_shorter_names():
    assert agent._so_names("/usr/lib/libz.so.1.3.1") == ["/usr/lib/libz.so.1.3", "/usr/lib/libz.so.1"]
    assert agent._so_names("/usr/lib64/libcrypto.so.3.5.9") == ["/usr/lib64/libcrypto.so.3.5", "/usr/lib64/libcrypto.so.3"]
    assert agent._so_names("/usr/lib/libssl.so.3") == [] and agent._so_names("/usr/sbin/nginx") == []


def test_is_elf_reads_regular_files_only(tmp_path):
    (tmp_path / "bin").write_bytes(b"\x7fELF\x02\x01")
    (tmp_path / "script").write_text("#!/bin/sh\n")
    assert agent._is_elf(str(tmp_path / "bin")) and not agent._is_elf(str(tmp_path / "script"))
    assert not agent._is_elf(str(tmp_path / "missing")) and not agent._is_elf(str(tmp_path))


# ---- the pass, on a fake /proc --------------------------------------------------------------------------------------------

SECRET = "hunter2-do-not-send"


def fake_proc(tmp_path, procs, tables="debian13"):
    """A /proc tree: self, and per pid its files and links. root links say which filesystem the process sees, and ns/mnt
    links which mount namespace: the host's (default), a container's ("container": True, another root and namespace), a
    chroot's ("chroot": the host's namespace, another root) or one of its own over the host's root ("own_ns": a systemd
    sandbox or a user's unshare)."""
    proc, host, other = tmp_path / "proc", tmp_path / "host-root", tmp_path / "container-root"
    host.mkdir()
    other.mkdir()
    (tmp_path / "ns").mkdir()
    for n in ("host", "container", "own"):
        (tmp_path / "ns" / n).write_text(n)
    (proc / "self" / "ns").mkdir(parents=True)
    os.symlink(host, proc / "self" / "root")
    os.symlink(tmp_path / "ns" / "host", proc / "self" / "ns" / "mnt")
    (proc / "net").mkdir()
    for t in ("tcp", "tcp6", "udp", "udp6"):
        (proc / "net" / t).write_text(fx(f"{tables}-net-{t}.txt"))
    for pid, p in procs.items():
        d = proc / str(pid)
        (d / "fd").mkdir(parents=True)
        (d / "ns").mkdir()
        os.symlink(other if p.get("container") or p.get("chroot") else host, d / "root")
        os.symlink(tmp_path / "ns" / ("container" if p.get("container") else "own" if p.get("own_ns") else "host"), d / "ns" / "mnt")
        if p.get("exe"):
            os.symlink(p["exe"], d / "exe")
        (d / "maps").write_text(p.get("maps", ""))
        (d / "cgroup").write_text(p.get("cgroup", "0::/user.slice/user-0.slice/session-1.scope"))
        (d / "comm").write_text(p.get("comm", "x") + "\n")
        (d / "status").write_text(f"Name:\tx\nUid:\t{p.get('uid', 0)}\t{p.get('uid', 0)}\t0\t0\n")
        (d / "cmdline").write_bytes(p.get("cmdline", b""))
        (d / "environ").write_bytes(f"PGPASSWORD={SECRET}\0".encode())
        for i, target in enumerate(p.get("fds", [])):
            os.symlink(target, d / "fd" / str(i))
    return proc


DEB_FILES = [("nginx", "/usr/sbin/nginx"), ("libssl3t64", "/usr/lib/x86_64-linux-gnu/libssl.so.3"),
             ("libssl3t64", "/usr/lib/x86_64-linux-gnu/libcrypto.so.3"), ("libc6", "/lib/x86_64-linux-gnu/libc.so.6"),
             ("libc6", "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"), ("libpcre2-8-0", "/usr/lib/x86_64-linux-gnu/libpcre2-8.so.0.14.0"),
             ("zlib1g", "/usr/lib/x86_64-linux-gnu/libz.so.1.3.1"), ("libzstd1", "/usr/lib/x86_64-linux-gnu/libzstd.so.1.5.7"),
             ("libcrypt1", "/usr/lib/x86_64-linux-gnu/libcrypt.so.1.1.0"), ("python3.13-minimal", "/usr/bin/python3.13"),
             ("unattended-upgrades", "/usr/bin/unattended-upgrade"), ("bash", "/usr/bin/bash"), ("libfoo1", "/usr/lib/libfoo.so.1")]


def nginx(**kw):
    return {"exe": "/usr/sbin/nginx", "maps": fx("debian13-nginx-maps.txt"), "cgroup": fx("debian13-nginx-cgroup.txt"),
            "comm": "nginx", "uid": 33, "fds": ["/dev/null", *(f"socket:[{i}]" for i in ORACLE["debian13"]["nginx_sockets"])], **kw}


def read(proc, files=DEB_FILES, **kw):
    return agent.runtime_read(str(proc), files=iter(files), euid=kw.pop("euid", 0), user_of=lambda u: {0: "root", 33: "www-data"}.get(u, str(u)),
                              own_pid=kw.pop("own_pid", 1), **kw)


@POSIX
def test_a_host_read_whole(tmp_path):
    proc = fake_proc(tmp_path, {
        10: nginx(uid=0), 11: nginx(), 12: nginx(),
        20: {"exe": "/usr/bin/python3.13", "comm": "unattended-upgr", "cgroup": "0::/system.slice/unattended-upgrades.service",
             "cmdline": b"/usr/bin/python3\0/usr/bin/unattended-upgrade\0--password=" + SECRET.encode() + b"\0"},
        30: {"comm": "kworker/0:1"},  # a kernel thread: no exe
        40: {"exe": "/usr/sbin/nginx", "container": True, "comm": "nginx"},
        50: {"exe": "/usr/bin/bash", "comm": "ba\nsh‮!", "uid": 1000},
        60: {"exe": "/opt/nimstead/python3", "cgroup": "0::/system.slice/nimstead-agent.service", "comm": "python3"},
    })
    rt = read(proc)
    assert rt["state"] == "ok" and "problem" not in rt and rt["other_roots"] == 1
    progs = {p["name"]: p for p in rt["programs"]}
    assert set(progs) == {"nginx.service", "unattended-upgrades.service", "ba?sh??"}  # the agent's own unit is left out
    ng = progs["nginx.service"]
    assert ng["unit"] and ng["count"] == 3 and ng["users"] == ["root", "www-data"]
    assert ng["listen"] == ["0.0.0.0:80/tcp", "[::]:80/tcp"]
    assert {"nginx", "libssl3t64", "libc6", "libpcre2-8-0", "zlib1g", "libzstd1", "libcrypt1"} <= set(ng["loads"])
    assert ng["replaced"] == ["libc6"]  # the libc upgrade ran while nginx was up (real maps)
    assert progs["unattended-upgrades.service"]["loads"] == ["python3.13-minimal", "unattended-upgrades"]
    assert not progs["ba?sh??"]["unit"] and progs["ba?sh??"]["users"] == ["1000"]
    assert "libfoo1" in rt["native"] and "unattended-upgrades" not in rt["native"]
    body = json.dumps(rt)
    assert SECRET not in body and "--password" not in body and "/usr/bin/unattended-upgrade" not in body  # matched here, never sent


@POSIX
def test_a_renamed_library_still_names_its_package(tmp_path):
    maps = "7f-80 r-xp 00000000 08:30 345   /usr/lib/libz.so.1.3.1 (deleted)\n"
    proc = fake_proc(tmp_path, {10: {"exe": "/usr/sbin/nginx", "maps": maps, "comm": "nginx"}}, tables="alpine321")
    rt = read(proc, files=[("nginx", "/usr/sbin/nginx"), ("zlib", "/usr/lib/libz.so.1"), ("zlib", "/usr/lib/libz.so.1.3.2")])
    assert rt["programs"][0]["replaced"] == ["zlib"] and rt["programs"][0]["loads"] == ["nginx", "zlib"]


@POSIX
def test_partial_reads_say_why_in_the_same_words(tmp_path, monkeypatch):
    proc = fake_proc(tmp_path, {10: nginx(), 11: nginx(), 12: nginx()})
    rt = read(proc, euid=1000)
    assert rt["state"] == "partial" and rt["problem"] == "not run as root: other users' programs can't be read"
    monkeypatch.setattr(agent, "RUNTIME_PROCESSES", 2)
    rt = read(proc)
    assert rt["problem"] == "stopped at its process budget (2 processes)" and rt["programs"][0]["count"] == 2
    monkeypatch.setattr(agent, "RUNTIME_PROCESSES", 4096)
    ticks = iter(range(0, 1000, 15))
    rt = read(proc, clock=lambda: next(ticks))
    assert rt["state"] == "partial" and rt["problem"].startswith(f"stopped at its time budget ({agent.RUNTIME_SECONDS} s)")
    monkeypatch.setattr(agent, "RUNTIME_MAPS_MAX", 200)
    rt = read(proc)
    assert "a program's memory map was larger than 0 MB" in rt["problem"]  # cut at a line, still read
    monkeypatch.setattr(agent, "RUNTIME_MAPS_MAX", 4 * 1024 * 1024)
    monkeypatch.setattr(agent, "RUNTIME_LOADS", 3)
    rt = read(proc)
    assert len(rt["programs"][0]["loads"]) == 3 and "stopped at its size budget" in rt["problem"]


@POSIX
def test_a_process_that_exits_mid_read_is_skipped(tmp_path):
    proc = fake_proc(tmp_path, {10: nginx(), 11: nginx()})
    os.remove(proc / "11" / "maps")
    rt = read(proc)
    assert rt["state"] == "ok" and rt["programs"][0]["count"] == 1


@POSIX
def test_unreadable_proc_fails_cleanly(tmp_path):
    rt = agent.runtime_read(str(tmp_path / "nothing"), files=iter([]), euid=0)
    assert rt["state"] == "failed" and rt["programs"] == [] and rt["problem"].startswith(str(tmp_path / "nothing"))


def test_safe_runtime_never_raises():
    def boom():
        raise RuntimeError("bad")
    rt = agent.safe_runtime(boom)
    assert rt["state"] == "failed" and rt["problem"] == "not read: RuntimeError: bad" and rt["programs"] == []


@POSIX
def test_inventory_carries_runtime_unless_the_host_opts_out(monkeypatch):
    monkeypatch.setattr(agent, "safe_runtime", lambda: {"v": 1, "state": "partial", "problem": "x", "programs": [{"name": "a"}],
                                                        "native": [], "other_roots": 0})
    inv = agent.with_runtime({"collection": {"v": 1, "sources": {}}}, {})
    assert inv["runtime"]["programs"] == [{"name": "a"}]
    assert inv["collection"]["sources"]["runtime"] == {"state": "partial", "count": 1, "error": "x"}
    inv = agent.with_runtime({"collection": {"v": 1, "sources": {}}}, {"runtime": False})
    assert "runtime" not in inv and inv["collection"]["sources"]["runtime"] == {"state": "off", "count": 0}



# ---- the review round (DECISIONS 164) -------------------------------------------------------------------------------------------

@POSIX
def test_a_chrooted_daemon_is_read_and_a_users_own_namespace_isnt(tmp_path):
    # named -t chroots after loading the host's libraries: its maps name host paths (security audit). A user's unshare keeps the
    # host's root but mounts what it likes over it: not believed unless it's a system service, which systemd sandboxes
    proc = fake_proc(tmp_path, {
        10: nginx(chroot=True, cgroup="0::/system.slice/named.service", comm="named"),
        11: nginx(own_ns=True, cgroup="0::/user.slice/user-1000.slice/session-2.scope", comm="faker", uid=1000),
        12: nginx(own_ns=True),  # nginx.service under systemd's PrivateTmp
        13: nginx(container=True, comm="nginx"),
    })
    rt = read(proc)
    names = {p["name"] for p in rt["programs"]}
    assert names == {"named.service", "nginx.service"} and rt["other_roots"] == 2 and rt["state"] == "ok"


@POSIX
def test_a_process_named_like_a_service_is_its_own_entry(tmp_path):
    proc = fake_proc(tmp_path, {10: nginx(), 11: {"exe": "/usr/bin/python3.13", "comm": "nginx.service", "uid": 1000,
                                                  "maps": "7f-80 r-xp 00000000 08:30 1629   /usr/lib/x86_64-linux-gnu/libc.so.6 (deleted)\n"}})
    rt = read(proc)
    entries = sorted((p["name"], p["unit"], tuple(p["replaced"])) for p in rt["programs"])
    assert entries == [("nginx.service", False, ("libc6",)), ("nginx.service", True, ("libc6",))]  # the real one's own (libc upgraded)


@POSIX
def test_the_process_budget_counts_programs_not_kernel_threads(tmp_path, monkeypatch):
    proc = fake_proc(tmp_path, {1: {"comm": "kthreadd"}, 2: {"comm": "kworker"}, 10: nginx(), 11: nginx()})
    monkeypatch.setattr(agent, "RUNTIME_PROCESSES", 2)
    rt = read(proc)
    assert rt["state"] == "ok" and rt["programs"][0]["count"] == 2


@POSIX
def test_one_descriptor_budget_for_the_whole_pass(tmp_path, monkeypatch):
    proc = fake_proc(tmp_path, {10: nginx(), 11: nginx(), 12: nginx()})
    monkeypatch.setattr(agent, "RUNTIME_FDS_TOTAL", 4)
    rt = read(proc)
    assert rt["problem"] == "stopped at its descriptor budget (4 descriptors in all)" and rt["programs"][0]["loads"]  # files still matched


@POSIX
def test_a_budget_is_said_once(tmp_path):
    proc = fake_proc(tmp_path, {10: nginx(), 11: nginx()})
    ticks = iter(range(0, 10_000, 30))
    rt = read(proc, clock=lambda: next(ticks))
    assert rt["problem"].count("time budget") == 1
