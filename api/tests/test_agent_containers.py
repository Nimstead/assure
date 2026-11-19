"""The agent reads running containers (tasks/plan-containers.md C1-C2): package databases parsed exactly as each container's
own package manager reports them, through a root that a hostile image can't steer out of (DECISIONS 138).

Fixtures are real files copied out of real images (debian:11, alpine:3.18, almalinux:9, distroless/base-debian12) with the
answer each image's own dpkg-query, apk or rpm gave; the rpm database is a few real header rows of almalinux:9's."""

import importlib.util
import json
import os
import sqlite3
import stat
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("nimstead_agent", Path(__file__).parents[2] / "agent" / "nimstead_agent.py")
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)

FIX = Path(__file__).parent / "fixtures" / "containers"
POSIX = pytest.mark.skipif(not hasattr(os, "O_PATH"), reason="Linux only: the agent reads containers through /proc and O_PATH")


def rows(pkgs):
    return sorted((p["name"], p["version"], p["source"], p.get("source_version")) for p in pkgs)


# ---- parsers, from real files ------------------------------------------------------------------------------------

def test_dpkg_status_equals_dpkg_query_in_the_same_image():
    ours = agent.parse_dpkg_status((FIX / "debian11-dpkg-status").read_text(encoding="utf-8"))
    truth = agent.parse_dpkg((FIX / "debian11-dpkg-query.txt").read_text(encoding="utf-8"))
    assert len(ours) == 96 and rows(ours) == rows(truth)
    libc = next(p for p in ours if p["name"] == "libc6")
    assert libc["source"] == "glibc" and "source_version" not in libc  # the Source field without a version: the binary's own


def test_dpkg_status_keeps_only_installed_stanzas_and_reads_source_versions():
    text = ("Package: bsdutils\nStatus: install ok installed\nVersion: 1:2.36.1-8+deb11u1\nSource: util-linux (2.36.1-8+deb11u1)\n"
            "Description: x\n continuation: not a field\n\n"
            "Package: gone\nStatus: deinstall ok config-files\nVersion: 1.0\n\n"
            "Package: half\nStatus: install ok half-installed\nVersion: 1.0\n\n"
            "Package: man-db\nStatus: install ok triggers-pending\nVersion: 2.9.4-2\n\n"
            "Package: held\nStatus: hold ok installed\nVersion: 3\n\nPackage: nover\nStatus: install ok installed\n")
    assert agent.parse_dpkg_status(text) == [
        {"name": "bsdutils", "version": "1:2.36.1-8+deb11u1", "source": "util-linux", "source_version": "2.36.1-8+deb11u1"},
        {"name": "man-db", "version": "2.9.4-2", "source": "man-db"},
        {"name": "held", "version": "3", "source": "held"}]


def test_distroless_status_d_entries_have_no_status_line():
    d = FIX / "distroless-status.d"
    got = [p for f in sorted(d.iterdir()) if not f.name.endswith(".md5sums")
           for p in agent.parse_dpkg_status(f.read_text(encoding="utf-8"), require_status=False)]
    assert rows(got) == [("base-files", "12.4+deb12u15", "base-files", None), ("libc6", "2.36-9+deb12u14", "glibc", None),
                         ("libssl3", "3.0.20-1~deb12u2", "openssl", None)]
    assert agent.parse_dpkg_status((d / "libssl3").read_text(encoding="utf-8")) == []  # the host's status file always has Status


def test_apk_database_equals_apk_info():
    pkgs = agent.parse_apk((FIX / "alpine318-apk-installed").read_text(encoding="utf-8"))
    assert sorted(f"{p['name']}-{p['version']}" for p in pkgs) == sorted((FIX / "alpine318-apk-info.txt").read_text().split())


def test_rpm_sqlite_equals_rpm_qa_in_the_same_image():
    ours = agent.parse_rpm_sqlite((FIX / "almalinux9-rpmdb-sample.sqlite").read_bytes())
    truth = agent.parse_rpm((FIX / "almalinux9-rpm-qa.txt").read_text())
    assert len(ours) == 6 and rows(ours) == rows(truth)
    assert ("openssl-libs", "1:3.5.9-1.el9_9", "openssl", None) in rows(ours)  # epoch kept, source from SOURCERPM


def header(tags):
    """An rpm header blob: (tag, type, value) entries, strings NUL-terminated, INT32 big-endian."""
    index, data = b"", b""
    for tag, typ, value in tags:
        index += b"".join(int(x).to_bytes(4, "big") for x in (tag, typ, len(data), 1))
        data += (value.encode() + b"\0") if typ == 6 else int(value).to_bytes(4, "big")
    return len(tags).to_bytes(4, "big") + len(data).to_bytes(4, "big") + index + data


def test_rpm_header_parser_checks_every_offset():
    good = header([(1000, 6, "zlib"), (1001, 6, "1.2.11"), (1002, 6, "40.el9"), (1003, 4, 2), (1044, 6, "zlib-1.2.11-40.el9.src.rpm")])
    assert agent.parse_rpm_header(good) == ("zlib", "2:1.2.11-40.el9", "zlib-1.2.11-40.el9.src.rpm")
    assert agent.parse_rpm_header(good[:-3]) is None  # data shorter than declared
    assert agent.parse_rpm_header(b"\xff\xff\xff\xff" + good[4:]) is None  # absurd index count
    assert agent.parse_rpm_header(b"") is None
    assert agent.parse_rpm_header(header([(1000, 6, "x"), (1001, 6, "1")])) is None  # no release
    unterminated = bytearray(good)
    unterminated[-1:] = b"X"
    assert agent.parse_rpm_header(bytes(unterminated)) is None


def test_rpm_sqlite_refuses_what_isnt_an_rpm_database(tmp_path):
    with pytest.raises(agent.ContainerReadError, match="not a database|file is not"):
        agent.parse_rpm_sqlite(b"not sqlite at all" * 100)
    p = tmp_path / "x.sqlite"
    con = sqlite3.connect(p)
    con.execute("CREATE VIEW Packages AS SELECT 1 AS blob")
    con.commit()
    con.close()
    with pytest.raises(agent.ContainerReadError, match="isn't laid out as rpm's database"):  # a view is no table
        agent.parse_rpm_sqlite(p.read_bytes())


# ---- the container root, as hostile input ------------------------------------------------------------------------

@pytest.fixture
def root(tmp_path):
    """A fake container root at tmp/root, and a "host" file beside it that nothing may reach."""
    r = tmp_path / "root"
    (r / "etc").mkdir(parents=True)
    (r / "usr/lib").mkdir(parents=True)
    (r / "var/lib/dpkg").mkdir(parents=True)
    (tmp_path / "host-secret").write_text("Package: stolen\nStatus: install ok installed\nVersion: 1\n")
    (r / "usr/lib/os-release").write_bytes((FIX / "debian11-os-release").read_bytes())
    os.symlink("../usr/lib/os-release", r / "etc/os-release")  # as Debian ships it
    cr = agent.ContainerRoot.of_dir(str(r))
    yield r, cr
    cr.close()


@POSIX
def test_relative_links_resolve_inside_the_root(root):
    r, cr = root
    assert agent.parse_os_release(cr.read("/etc/os-release").decode())["ID"] == "debian"
    assert cr.read("/etc/../etc/./os-release") == cr.read("/usr/lib/os-release")


@POSIX
def test_no_link_or_dotdot_leaves_the_root(root):
    r, cr = root
    status = r / "var/lib/dpkg/status"
    for target in ("../../../../host-secret", "/../host-secret", str(r.parent / "host-secret"), "/etc/hostname"):
        if status.is_symlink():
            status.unlink()
        os.symlink(target, status)
        with pytest.raises(FileNotFoundError):  # resolved inside the root, where none of these exist
            cr.read("/var/lib/dpkg/status")
    with pytest.raises(FileNotFoundError):
        cr.read("/../../host-secret")
    os.symlink("/", r / "var/lib/up")  # a directory link to "/" is the container's root
    assert cr.read("/var/lib/up/usr/lib/os-release") == cr.read("/usr/lib/os-release")


@POSIX
def test_link_loops_and_files_on_the_way_are_refused(root):
    r, cr = root
    os.symlink("b", r / "etc/a")
    os.symlink("a", r / "etc/b")
    with pytest.raises(agent.ContainerReadError, match="too many links"):
        cr.read("/etc/a")
    with pytest.raises(agent.ContainerReadError, match="not a directory"):
        cr.read("/etc/os-release/x")


@POSIX
def test_fifo_device_and_oversized_files_are_never_read(root):
    r, cr = root
    os.mkfifo(r / "var/lib/dpkg/status")
    with pytest.raises(agent.ContainerReadError, match="not a regular file"):  # and doesn't block: a FIFO is never opened
        cr.read("/var/lib/dpkg/status")
    os.unlink(r / "var/lib/dpkg/status")
    os.symlink("/dev/zero", r / "var/lib/dpkg/status")  # inside the root there's no /dev/zero; a host path is never reached
    with pytest.raises(FileNotFoundError):
        cr.read("/var/lib/dpkg/status")
    os.unlink(r / "var/lib/dpkg/status")
    (r / "var/lib/dpkg/status").write_bytes(b"x" * 4096)
    with pytest.raises(agent.ContainerReadError, match="larger than"):
        cr.read("/var/lib/dpkg/status", limit=1024)
    assert stat.S_ISDIR(os.fstat(cr.fd).st_mode)


@POSIX
def test_read_container_reports_what_it_read(root):
    r, cr = root
    (r / "var/lib/dpkg/status").write_bytes((FIX / "debian11-dpkg-status").read_bytes())
    got = agent.read_container(cr)
    assert got["ecosystem"] == "Debian:11" and got["os_name"].startswith("Debian GNU/Linux 11")
    assert got["collection"] == {"v": 1, "sources": {"os_release": {"state": "ok", "count": 1}, "package_db": {"state": "ok", "count": 96}}}
    assert len(got["packages"]) == 96 and "kernel_release" not in got["facts"]


@POSIX
def test_read_container_says_why_nothing_was_assessed(tmp_path):
    r = tmp_path / "busybox"
    (r / "bin").mkdir(parents=True)
    cr = agent.ContainerRoot.of_dir(str(r))
    got = agent.read_container(cr)
    assert got["ecosystem"] == "" and "os_unmatched" in got["facts"]
    assert got["collection"]["sources"]["package_db"] == {"state": "failed", "count": 0,
                                                          "error": "no package database found (apk, dpkg or rpm SQLite)"}
    (r / "var/lib/rpm").mkdir(parents=True)
    (r / "var/lib/rpm/Packages").write_bytes(b"\0" * 64)  # Berkeley DB, as ubi8 and Rocky 8 ship
    assert agent.read_container(cr)["collection"]["sources"]["package_db"]["error"] == "rpm's Berkeley DB format isn't read yet"
    (r / "var/lib/rpm/Packages").unlink()
    (r / "var/lib/rpm/rpmdb.sqlite").write_bytes((FIX / "almalinux9-rpmdb-sample.sqlite").read_bytes())
    assert agent.read_container(cr)["collection"]["sources"]["package_db"] == {"state": "ok", "count": 6}
    cr.close()


@POSIX
def test_distroless_root_is_read_from_status_d(tmp_path):
    r = tmp_path / "distroless"
    (r / "etc").mkdir(parents=True)
    (r / "etc/os-release").write_bytes((FIX / "distroless-os-release").read_bytes())
    (r / "var/lib/dpkg").mkdir(parents=True)
    os.symlink(str(FIX / "distroless-status.d"), r / "var/lib/dpkg/status.d")  # an absolute link: resolved in the root, so missing
    cr = agent.ContainerRoot.of_dir(str(r))
    assert agent.read_container(cr)["collection"]["sources"]["package_db"]["state"] == "failed"
    os.unlink(r / "var/lib/dpkg/status.d")
    (r / "var/lib/dpkg/status.d").mkdir()
    for f in (FIX / "distroless-status.d").iterdir():
        (r / "var/lib/dpkg/status.d" / f.name).write_bytes(f.read_bytes())
    got = agent.read_container(cr)
    assert got["ecosystem"] == "Debian:12" and [p["name"] for p in got["packages"]] == ["base-files", "libc6", "libssl3"]
    cr.close()


@POSIX
def test_a_pid_in_the_agents_own_namespace_is_not_a_container():
    with pytest.raises(agent.ContainerReadError, match="isn't that container any more"):
        agent.ContainerRoot.of_pid(os.getpid())
    own = os.stat("/proc/self/ns/mnt").st_ino
    cr = agent.ContainerRoot.of_pid(os.getpid(), own_ns=own + 1)  # as if the agent lived elsewhere: our root is taken
    assert cr.exists("/proc") or cr.exists("/etc")
    cr.close()


# ---- discovery and the report (C2), from real docker/podman output -------------------------------------------------

LEGACY, WEB1, WEB2 = "da60fb4b41ac67a9d7b04a24e3cc76a5b062cfa0ae93d376afda3a8907b65e47", "fa2d307274fcf7340246bccf00846081e8580bc7a18cfee67dc1170cdc98c780", "edaa930d4c13cce80ebeaaf77ba70bd3a9f5205b26656f58a38071977689ecbb"
POD1 = "84fcd62abc1bc05c3cf5303607a6e5ae49d4eff582e529285a621a7ca8c3155a"
ALPINE_ID, DEBIAN_ID = "802c91d5298192c0f3a08101aeb5f9ade2992e22c9e27fa8b88eab82602550d0", "d89d848cffea21f345166115b8db117797b081ad20f705706d7e7ce5d3449e78"
DOCKER_INSPECT = json.dumps([  # docker 26.1.5 inspect --type container, trimmed to the fields read
    {"Id": LEGACY, "State": {"Status": "running", "Running": True, "Pid": 7375}, "Image": f"sha256:{DEBIAN_ID}", "Name": "/legacy", "Config": {"Image": "debian:11"}},
    {"Id": WEB2, "State": {"Status": "running", "Running": True, "Pid": 7299}, "Image": f"sha256:{ALPINE_ID}", "Name": "/web2", "Config": {"Image": "alpine:3.18"}},
    {"Id": WEB1, "State": {"Status": "running", "Running": True, "Pid": 7223}, "Image": f"sha256:{ALPINE_ID}", "Name": "/web1", "Config": {"Image": "alpine:3.18"}}])
PODMAN_INSPECT = json.dumps([  # podman 5.4.2: the bare image id, and ImageName
    {"Id": POD1, "Image": ALPINE_ID, "ImageName": "docker.io/library/alpine:3.18", "Name": "pod1",
     "State": {"Status": "running", "Running": True, "Pid": 7504}, "Config": {"Image": "docker.io/library/alpine:3.18"}}])


def cli(answers):
    """A fake _query answering (runtime, verb) with (rc, out, err), recording every command."""
    calls = []

    def query(cmd, timeout=600):
        calls.append(cmd)
        return answers[(cmd[0], cmd[1])]
    query.calls = calls
    return query


def test_list_containers_from_real_docker_and_podman_output():
    q = cli({("docker", "ps"): (0, f"{LEGACY}\n{WEB2}\n{WEB1}\n", ""), ("docker", "inspect"): (0, DOCKER_INSPECT, "")})
    found, problem, ids = agent.list_containers("docker", q)
    assert problem is None and q.calls[1] == ["docker", "inspect", "--type", "container", LEGACY, WEB2, WEB1] and ids == [LEGACY, WEB2, WEB1]
    assert found[0] == {"id": LEGACY, "name": "legacy", "runtime": "docker", "pid": 7375, "image_id": f"sha256:{DEBIAN_ID}", "ref": "debian:11"}
    q = cli({("podman", "ps"): (0, POD1 + "\n", ""), ("podman", "inspect"): (0, PODMAN_INSPECT, "")})
    found, problem, ids = agent.list_containers("podman", q)
    assert problem is None and found == [{"id": POD1, "name": "pod1", "runtime": "podman", "pid": 7504,
                                          "image_id": f"sha256:{ALPINE_ID}", "ref": "docker.io/library/alpine:3.18"}]


def test_list_containers_never_calls_a_failure_complete():
    found, problem, ids = agent.list_containers("docker", cli({("docker", "ps"): (1, "", "Cannot connect to the Docker daemon at unix:///var/run/docker.sock\n")}))
    assert found == [] and problem == "docker ps exited 1: Cannot connect to the Docker daemon at unix:///var/run/docker.sock"
    found, problem, ids = agent.list_containers("docker", cli({("docker", "ps"): (0, f"{LEGACY}\n", ""), ("docker", "inspect"): (0, "[{not json", "")}))
    assert found == [] and problem == "docker inspect: unreadable output"
    broken = json.dumps([{"Id": LEGACY, "State": {"Running": True, "Pid": 0}, "Image": "sha256:" + DEBIAN_ID}])
    found, problem, ids = agent.list_containers("docker", cli({("docker", "ps"): (0, f"{LEGACY}\n", ""), ("docker", "inspect"): (0, broken, "")}))
    assert found == [] and "without its id, PID or image" in problem
    stopped = json.dumps([{"Id": LEGACY, "State": {"Running": False, "Pid": 0}, "Image": "sha256:" + DEBIAN_ID}])  # stopped since ps
    found, problem, ids = agent.list_containers("docker", cli({("docker", "ps"): (0, f"{LEGACY}\n", ""), ("docker", "inspect"): (0, stopped, "")}))
    assert found == [] and problem is None
    found, problem, ids = agent.list_containers("docker", cli({("docker", "ps"): (0, "$(rm -rf /)\n", "")}))
    assert found == [] and problem == "1 unreadable container ids" and ids is None  # never passed on to inspect, and proves nothing


class FakeRoot:
    def __init__(self, pid):
        self.pid = pid

    def close(self):
        pass


def image_of(pid):
    """What read_container would return for each fake PID: alpine for the replicas, debian for legacy."""
    alpine = {"os_name": "Alpine Linux v3.18", "ecosystem": "Alpine:v3.18", "facts": {"os_id": "alpine", "os_version_id": "3.18.12"},
              "collection": {"v": 1, "sources": {"os_release": {"state": "ok", "count": 1}, "package_db": {"state": "ok", "count": 1}}},
              "packages": [{"name": "musl", "version": "1.2.4-r3", "source": "musl"}]}
    debian = dict(alpine, os_name="Debian GNU/Linux 11 (bullseye)", ecosystem="Debian:11", packages=[{"name": "libc6", "version": "2.31-13+deb11u11", "source": "glibc"}])
    return debian if pid == 7375 else alpine


def both_runtimes():
    return cli({("docker", "ps"): (0, f"{LEGACY}\n{WEB2}\n{WEB1}\n", ""), ("docker", "inspect"): (0, DOCKER_INSPECT, ""),
                ("podman", "ps"): (0, POD1 + "\n", ""), ("podman", "inspect"): (0, PODMAN_INSPECT, "")})


def report(q, which=lambda n: n in ("docker", "podman"), **kw):
    kw.setdefault("root_of", lambda pid, own, cid: FakeRoot(pid))
    kw.setdefault("read", lambda root: image_of(root.pid))
    return agent.containers(q, which, euid=0, **kw)


@POSIX
def test_replicas_of_one_image_are_read_and_sent_once():
    body = report(both_runtimes())
    assert body["complete"] is True and body["error"] is None and body["line"] == {"state": "ok", "count": 4}
    assert body["runtimes"] == {"docker": {"state": "ok", "count": 3}, "podman": {"state": "ok", "count": 1}}
    alpine, debian = sorted(body["images"], key=lambda i: i["ecosystem"])
    assert alpine["image_id"] == f"sha256:{ALPINE_ID}" and sorted(c["name"] for c in alpine["containers"]) == ["pod1", "web1", "web2"]
    assert {c["runtime"] for c in alpine["containers"]} == {"docker", "podman"}
    assert debian["ref"] == "debian:11" and debian["packages"] == [{"name": "libc6", "version": "2.31-13+deb11u11", "source": "glibc"}]
    assert "pid" not in json.dumps(body["images"])  # PIDs stay on the host


@POSIX
def test_a_changed_replica_is_its_own_entry():
    def read(root):
        got = image_of(root.pid)
        return dict(got, packages=[*got["packages"], {"name": "curl", "version": "8.9.1-r1", "source": "curl"}]) if root.pid == 7504 else got
    body = report(both_runtimes(), read=read)
    assert len(body["images"]) == 3 and sum(i["image_id"] == f"sha256:{ALPINE_ID}" for i in body["images"]) == 2


@POSIX
def test_a_runtime_failure_or_a_vanished_container_makes_the_report_partial():
    q = cli({("docker", "ps"): (0, f"{LEGACY}\n", ""), ("docker", "inspect"): (0, json.dumps(json.loads(DOCKER_INSPECT)[:1]), ""),
             ("podman", "ps"): (125, "", "Error: database is locked\n")})
    body = report(q)
    assert body["complete"] is False and body["runtimes"]["podman"]["state"] == "failed" and len(body["images"]) == 1
    assert body["line"]["state"] == "partial" and "podman: podman ps exited 125: Error: database is locked" in body["error"]

    def gone(pid, own, cid):
        if pid == 7299:
            raise agent.ContainerReadError("the process isn't in a container of its own any more")
        return FakeRoot(pid)
    body = report(both_runtimes(), root_of=gone)
    assert body["complete"] is False and "container web2 stopped before it was read" in body["error"]
    assert sum(len(i["containers"]) for i in body["images"]) == 3


@POSIX
def test_budgets_end_the_pass_early_and_say_so(monkeypatch):
    ticks = iter(range(0, 1000, 100))
    body = report(both_runtimes(), clock=lambda: next(ticks))  # the second container starts after the 120 s budget
    assert body["complete"] is False and "containers not read: the pass reached its time budget" in body["error"]
    monkeypatch.setattr(agent, "CONTAINER_MAX", 2)
    body = report(both_runtimes())
    assert body["complete"] is False and "2 more containers than one report reads (2)" in body["error"]


def test_not_root_no_runtime_and_kubernetes_are_said():
    body = agent.containers(cli({}), lambda n: None, euid=1000)
    assert body["complete"] is False and body["line"]["state"] == "failed" and "isn't running as root" in body["error"]
    body = agent.containers(cli({}), lambda n: None, euid=0)
    assert body == {"v": 1, "complete": True, "runtimes": {}, "listed": {}, "images": [], "error": None, "line": {"state": "ok", "count": 0}}
    body = agent.containers(cli({}), lambda n: n == "crictl", euid=0)
    assert body["complete"] is True and body["line"]["state"] == "failed"  # nothing listed from Docker or Podman to take as stopped
    assert body["error"] == "crictl: Kubernetes (CRI) containers aren't read yet"


def test_enrol_records_the_local_opt_out(monkeypatch, tmp_path):
    saved = {}
    monkeypatch.setattr(agent, "collect", lambda: {"os_name": "Debian GNU/Linux 13", "ecosystem": "Debian:13"})
    monkeypatch.setattr(agent, "post", lambda *a, **k: {"agent_key": "nma_x", "asset_id": "a1"})
    monkeypatch.setattr(agent, "save_config", lambda cfg: saved.update(cfg) or "agent.json")
    monkeypatch.setattr(agent, "use_proxy", lambda proxy: None)
    monkeypatch.setenv("NIMSTEAD_TOKEN", "t")
    agent._main(["enroll", "--server", "https://s", "--no-containers"])
    assert saved["containers"] is False
    agent._main(["enroll", "--server", "https://s"])
    assert saved["containers"] is True


# ---- security and code review (DECISIONS 143) ------------------------------------------------------------------------

def rpmdb(tmp_path, ddl, rows=1):
    p = tmp_path / "rpmdb.sqlite"
    con = sqlite3.connect(p)
    con.execute(ddl)
    for _ in range(rows):
        con.execute("INSERT INTO Packages (hnum) VALUES (NULL)")
    con.commit()
    con.close()
    return p.read_bytes()


def test_an_rpm_database_not_laid_out_as_rpms_is_never_queried(tmp_path):
    # a generated column would build a gigabyte blob per row on one SELECT: refused from the schema, before any row is read
    raw = rpmdb(tmp_path, "CREATE TABLE Packages(hnum INTEGER PRIMARY KEY, blob BLOB GENERATED ALWAYS AS (zeroblob(999999999)) VIRTUAL)")
    with pytest.raises(agent.ContainerReadError, match="isn't laid out as rpm's database"):
        agent.parse_rpm_sqlite(raw)
    (tmp_path / "rpmdb.sqlite").unlink()
    raw = rpmdb(tmp_path, "CREATE TABLE Packages(hnum INTEGER PRIMARY KEY, blob BLOB, extra TEXT)")
    with pytest.raises(agent.ContainerReadError, match="isn't laid out"):
        agent.parse_rpm_sqlite(raw)
    real = (FIX / "almalinux9-rpmdb-sample.sqlite").read_bytes()
    with pytest.raises(agent.ContainerReadError, match="more than 3 packages"):
        agent.parse_rpm_sqlite(real, max_rows=3)
    assert len(agent.parse_rpm_sqlite(real)) == 6  # rpm's own layout still reads


class TreeRoot:
    """A container root held in memory, for the package-database logic on any platform."""
    def __init__(self, files):
        self.files = files

    def exists(self, path):
        return path in self.files or any(k.startswith(path + "/") for k in self.files)

    def read(self, path, limit=agent.CONTAINER_READ_MAX):
        if path not in self.files:
            raise FileNotFoundError(path)
        return self.files[path]

    def listdir(self, path):
        return sorted(k[len(path) + 1:] for k in self.files if k.startswith(path + "/"))


def test_package_databases_past_the_cap_are_refused_before_they_are_parsed(monkeypatch):
    monkeypatch.setattr(agent, "CONTAINER_MAX_PACKAGES", 3)
    tiny = "".join(f"P:p{i}\nV:1\n\n" for i in range(4)).encode()
    pkgs, line = agent.container_package_db(TreeRoot({agent.APK_DB: tiny}))
    assert pkgs == [] and line["state"] == "failed" and "more than 3 packages" in line["error"]
    status = "".join(f"Package: p{i}\nStatus: install ok installed\nVersion: 1\n\n" for i in range(4)).encode()
    assert agent.container_package_db(TreeRoot({agent.DPKG_STATUS: status}))[1]["state"] == "failed"
    many = {f"{agent.DPKG_STATUS_D}/p{i}": f"Package: p{i}\nVersion: 1\n".encode() for i in range(4)}
    assert "more than 3 packages" in agent.container_package_db(TreeRoot(many))[1]["error"]
    three = {f"{agent.DPKG_STATUS_D}/p{i}": f"Package: p{i}\nVersion: 1\n".encode() for i in range(3)}
    assert agent.container_package_db(TreeRoot(three))[1] == {"state": "ok", "count": 3}


def test_status_d_entries_are_capped_together_too(monkeypatch):
    monkeypatch.setattr(agent, "CONTAINER_READ_MAX", 100)
    files = {f"{agent.DPKG_STATUS_D}/p{i}": (f"Package: p{i}\nVersion: 1\n" + "x" * 40).encode() for i in range(3)}
    assert "MB in all" in agent.container_package_db(TreeRoot(files))[1]["error"]


@POSIX
def test_each_runtimes_whole_listing_is_sent_even_past_the_read_budget(monkeypatch):
    monkeypatch.setattr(agent, "CONTAINER_MAX", 1)
    body = report(both_runtimes())
    assert body["listed"] == {"docker": [LEGACY, WEB2, WEB1], "podman": [POD1]}  # every running container, though one was read
    assert body["complete"] is False and sum(len(i["containers"]) for i in body["images"]) == 1
    q = cli({("docker", "ps"): (0, f"{LEGACY}\n", ""), ("docker", "inspect"): (0, json.dumps(json.loads(DOCKER_INSPECT)[:1]), ""),
             ("podman", "ps"): (125, "", "Error: database is locked\n")})
    assert report(q)["listed"] == {"docker": [LEGACY]}  # a runtime that didn't answer proves nothing


@POSIX
def test_an_image_that_would_overrun_the_body_budget_is_left_out_whole(monkeypatch):
    monkeypatch.setattr(agent, "CONTAINER_BODY_MAX", 900)

    def read(root):
        got = image_of(root.pid)
        return dict(got, packages=got["packages"] * (40 if root.pid == 7375 else 1))  # debian's entry alone is past the budget
    body = report(both_runtimes(), read=read)
    assert [i["ecosystem"] for i in body["images"]] == ["Alpine:v3.18"] and "legacy not sent: the report reached its size budget" in body["error"]
    assert body["listed"]["docker"] == [LEGACY, WEB2, WEB1]  # still listed as running: its row isn't taken as stopped


def test_an_unexpected_error_in_the_container_pass_never_costs_the_inventory():
    def boom():
        raise RuntimeError("something nobody expected")
    body = agent.safe_containers(boom)
    assert body["line"] == {"state": "failed", "count": 0, "error": "containers not read: RuntimeError: something nobody expected"}
    assert body["images"] == [] and body["listed"] == {} and body["complete"] is False


@POSIX
def test_a_path_that_crosses_into_another_mount_is_refused(root, monkeypatch):
    r, cr = root
    real = agent._mount_id
    usr = os.open(str(r / "usr"), os.O_PATH)
    usr_ino = os.fstat(usr).st_ino
    os.close(usr)
    monkeypatch.setattr(agent, "_mount_id", lambda fd: "elsewhere" if os.fstat(fd).st_ino == usr_ino else real(fd))  # /usr as a mount
    with pytest.raises(agent.ContainerReadError, match="crosses into another mount"):
        cr.read("/usr/lib/os-release")
    with pytest.raises(agent.ContainerReadError, match="crosses into another mount"):
        cr.read("/etc/os-release")  # a link into it too


@POSIX
def test_a_reused_pid_that_isnt_the_listed_container_is_refused():
    own = os.stat("/proc/self/ns/mnt").st_ino
    with pytest.raises(agent.ContainerReadError, match="isn't that container any more"):
        agent.ContainerRoot.of_pid(os.getpid(), own_ns=own + 1, container_id="f" * 64)  # our cgroup doesn't name it
    with open("/proc/self/cgroup") as f:
        mine = f.read().strip().rsplit("/", 1)[-1] or "0::"
    agent.ContainerRoot.of_pid(os.getpid(), own_ns=own + 1, container_id=mine).close()
