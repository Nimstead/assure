"""Applications inside containers and Kubernetes nodes (tasks/spec-workloads.md, DECISIONS 155-158).

The walk and the readers run on temporary trees taken as a container's root (ContainerRoot.of_dir), so every hostile case
is a real file on a real filesystem; crictl's output is what real containerd 2.4 and CRI-O 1.32 printed for a container
created through the CRI as the kubelet creates one (api/tests/fixtures/cri, recorded 2026-11-21)."""

import importlib.util
import io
import json
import os
import time
import zipfile
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("nimstead_agent", Path(__file__).parents[2] / "agent" / "nimstead_agent.py")
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)

CRI = Path(__file__).parent / "fixtures" / "cri"
POSIX = pytest.mark.skipif(not hasattr(os, "O_PATH"), reason="Linux only: the agent reads containers through /proc and O_PATH")
NOBODY_OWNS = (lambda p: False), None


def budget(seconds=60, entries=200_000):
    b = agent._Budget(seconds, entries)
    b.deep = b.unread = 0
    return b


def write(path: Path, data: str | bytes = ""):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode())
    return path


def jar(path: Path, coords, nested=None, mode=zipfile.ZIP_DEFLATED):
    """A jar with pom.properties for each (group, artifact, version), and nested jars {name: bytes}."""
    path.parent.mkdir(parents=True, exist_ok=True)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", mode) as z:
        for g, a, v in coords:
            z.writestr(f"META-INF/maven/{g}/{a}/pom.properties", f"groupId={g}\nartifactId={a}\nversion={v}\n")
        for name, data in (nested or {}).items():
            z.writestr(name, data, compress_type=zipfile.ZIP_STORED)  # Spring Boot stores its nested jars
    path.write_bytes(buf.getvalue())
    return buf.getvalue()


def uvarint(n):
    out = b""
    while n >= 0x80:
        out += bytes([(n & 0x7F) | 0x80])
        n >>= 7
    return out + bytes([n])


START, END = b"0w\xaf\x0c\x92t\x08\x02A\xe1\xc1\x07\xe6\xd6\x18\xe6", b"\xf92C1\x86\x18 r\x00\x82B\x10A\x16\xd8\xf2"  # Go's sentinels


def buildinfo(version="go1.22.3", modinfo="", inline=True):
    """A .go.buildinfo section as Go 1.18+ writes it (flags bit 2: strings inline, varint-prefixed)."""
    head = agent.GO_MAGIC + bytes([8, 2 if inline else 0]) + b"\0" * 16
    mod = (START + modinfo.encode() + END) if modinfo else b""
    return head + uvarint(len(version)) + version.encode() + uvarint(len(mod)) + mod


BASE = 0x400000  # each section is loaded at BASE + its file offset


def elf(sections: dict[str, bytes], pad=4096) -> bytes:
    """A little-endian ELF64 file holding the named sections, laid out in order after the header and the section name
    table, each loaded at BASE + its offset."""
    names = b"\0.shstrtab\0" + b"".join(n.encode() + b"\0" for n in sections)
    blobs, off = [], 64
    layout = [(".shstrtab", 1, names)]
    pos = 1 + len(".shstrtab") + 1
    for n, data in sections.items():
        layout.append((n, pos, data))
        pos += len(n) + 1
    body = b""
    for _, name_off, data in layout:
        blobs.append((name_off, off + len(body), len(data)))
        body += data
    shoff = 64 + len(body)
    table = b"\0" * 64 + b"".join(no.to_bytes(4, "little") + (1).to_bytes(4, "little") + b"\0" * 8 + (BASE + o).to_bytes(8, "little")
                                  + o.to_bytes(8, "little") + s.to_bytes(8, "little") + b"\0" * 24 for no, o, s in blobs)
    header = (b"\x7fELF\x02\x01\x01" + b"\0" * 9 + (2).to_bytes(2, "little") + (0x3E).to_bytes(2, "little") + (1).to_bytes(4, "little")
              + b"\0" * 16 + shoff.to_bytes(8, "little") + b"\0" * 4 + (64).to_bytes(2, "little") + b"\0" * 4
              + (64).to_bytes(2, "little") + (len(blobs) + 1).to_bytes(2, "little") + (1).to_bytes(2, "little"))
    assert len(header) == 64
    data = header + body + table
    return data + b"\0" * max(0, pad - len(data))


def executable(path: Path, data: bytes):
    write(path, data)
    path.chmod(0o755)
    return path


def apps_of(tmp_path, owned=NOBODY_OWNS, b=None):
    root = agent.ContainerRoot.of_dir(str(tmp_path))
    try:
        return agent.container_apps(root, b or budget(), owned)
    finally:
        root.close()


def rows(got):
    return sorted((r["ecosystem"], r["name"], r["version"], r["source"]) for r in got)


# ---- the walk -----------------------------------------------------------------------------------------------------

@POSIX
def test_walk_lists_every_folder_top_down_and_follows_no_link(tmp_path):
    write(tmp_path / "app" / "a.txt")
    write(tmp_path / "app" / "lib" / "b.txt")
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    write(outside / "secret.jar")
    (tmp_path / "app" / "out").symlink_to(outside)            # absolute, out of the root
    (tmp_path / "app" / "up").symlink_to("../../..")          # climbing
    (tmp_path / "app" / "loop").symlink_to(".")               # a loop
    root = agent.ContainerRoot.of_dir(str(tmp_path))
    try:
        seen = {p: files for p, _, files in root.walk(budget())}
    finally:
        root.close()
    assert list(seen) == ["/", "/app", "/app/lib"]
    assert seen["/app"] == ["a.txt", "loop", "out", "up"]  # links are listed as names, never entered
    assert seen["/app/lib"] == ["b.txt"]


@POSIX
def test_walk_never_enters_another_mount():
    root = agent.ContainerRoot.of_dir("/")  # /proc and /sys are their own mounts on every Linux
    try:
        paths = [p for p, _, _ in root.walk(budget(), depth=1)]
    finally:
        root.close()
    assert "/etc" in paths or "/usr" in paths
    assert "/proc" not in paths and "/sys" not in paths


@POSIX
def test_walk_counts_folders_past_its_depth_and_stops_at_its_entry_budget(tmp_path):
    deep = tmp_path
    for i in range(6):
        deep = deep / f"d{i}"
    write(deep / "x")
    b = budget()
    root = agent.ContainerRoot.of_dir(str(tmp_path))
    try:
        paths = [p for p, _, _ in root.walk(b, depth=3)]
        assert paths == ["/", "/d0", "/d0/d1", "/d0/d1/d2"] and b.deep == 1 and not b.stopped
        for i in range(50):
            write(tmp_path / "wide" / f"f{i}")
        b = budget(entries=20)
        list(root.walk(b))
        assert b.stopped and "budget" in b.stopped
    finally:
        root.close()


@POSIX
def test_open_file_opens_only_regular_files(tmp_path):
    write(tmp_path / "ok", "x")
    os.mkfifo(tmp_path / "fifo")
    (tmp_path / "link").symlink_to("ok")
    write(tmp_path / "big", b"x" * 2048)
    root = agent.ContainerRoot.of_dir(str(tmp_path))
    try:
        fd = root.open_file(root.fd, "ok")
        assert os.read(fd, 10) == b"x"
        os.close(fd)
        t = time.monotonic()
        assert root.open_file(root.fd, "fifo") is None and time.monotonic() - t < 1  # never opened, so never blocks
        assert root.open_file(root.fd, "link") is None and root.open_file(root.fd, "missing") is None
        with pytest.raises(agent.ContainerReadError, match="larger than"):
            root.open_file(root.fd, "big", 1024)
    finally:
        root.close()


# ---- Python, npm, Java ------------------------------------------------------------------------------------------

@POSIX
def test_python_packages_in_site_packages_anywhere(tmp_path):
    sp = tmp_path / "usr/local/lib/python3.12/site-packages"
    write(sp / "Django-4.2.1.dist-info" / "METADATA", "Metadata-Version: 2.1\nName: Django\nVersion: 4.2.1\n\nlong text\nName: no\n")
    write(sp / "six-1.16.0.egg-info" / "PKG-INFO", "Name: six\nVersion: 1.16.0\n")
    write(sp / "old.egg-info", "Name: old_pkg\nVersion: 0.1\n")  # an egg-info can be a file
    write(tmp_path / "opt/venv/lib/python3.12/site-packages/urllib3-1.26.5.dist-info/METADATA", "Name: urllib3\nVersion: 1.26.5\n")
    write(tmp_path / "src/tests/data/fake-9.9.dist-info/METADATA", "Name: fake\nVersion: 9.9\n")  # test data, not in site-packages
    write(sp / "broken-1.0.dist-info" / "RECORD", "")  # no METADATA: unread, said
    got, lines = apps_of(tmp_path)
    assert rows(got) == [
        ("PyPI", "django", "4.2.1", "/usr/local/lib/python3.12/site-packages/Django-4.2.1.dist-info"),
        ("PyPI", "old-pkg", "0.1", "/usr/local/lib/python3.12/site-packages/old.egg-info"),
        ("PyPI", "six", "1.16.0", "/usr/local/lib/python3.12/site-packages/six-1.16.0.egg-info"),
        ("PyPI", "urllib3", "1.26.5", "/opt/venv/lib/python3.12/site-packages/urllib3-1.26.5.dist-info")]
    assert lines["python_packages"] == {"state": "partial", "count": 4, "error": "1 installs' metadata couldn't be read"}
    assert lines["npm_packages"] == lines["java_archives"] == lines["go_modules"] == {"state": "ok", "count": 0}


@POSIX
def test_npm_packages_scoped_and_nested(tmp_path):
    nm = tmp_path / "usr/src/app/node_modules"
    write(nm / "lodash/package.json", json.dumps({"name": "lodash", "version": "4.17.20"}))
    write(nm / "@babel/core/package.json", json.dumps({"name": "@babel/core", "version": "7.20.0"}))
    write(nm / "express/node_modules/qs/package.json", json.dumps({"name": "qs", "version": "6.5.2"}))
    write(nm / ".bin/thing/package.json", json.dumps({"name": "thing", "version": "1.0.0"}))  # .bin isn't a package
    write(nm / ".pnpm/minimist@1.2.0/node_modules/minimist/package.json", json.dumps({"name": "minimist", "version": "1.2.0"}))
    write(tmp_path / "usr/src/app/package.json", json.dumps({"name": "my-app", "version": "1.0.0"}))  # the app itself
    write(nm / "huge/package.json", "{" + " " * (agent.MAX_PACKAGE_JSON + 10) + "}")
    os.makedirs(nm / "fifo")
    os.mkfifo(nm / "fifo/package.json")
    t = time.monotonic()
    got, lines = apps_of(tmp_path)
    assert time.monotonic() - t < 10
    assert [(e, n, v) for e, n, v, _ in rows(got)] == [("npm", "@babel/core", "7.20.0"), ("npm", "lodash", "4.17.20"),
                                                        ("npm", "minimist", "1.2.0"), ("npm", "qs", "6.5.2")]
    assert ("npm", "qs", "6.5.2", "/usr/src/app/node_modules/express/node_modules/qs") in rows(got)
    assert lines["npm_packages"]["state"] == "partial" and lines["npm_packages"]["count"] == 4  # huge and the FIFO: unread


@POSIX
def test_java_archives_with_nested_jars(tmp_path):
    jar(tmp_path / "opt/app/lib/log4j-core-2.14.1.jar", [("org.apache.logging.log4j", "log4j-core", "2.14.1")])
    inner = jar(tmp_path / "scratch/inner.jar", [("com.fasterxml.jackson.core", "jackson-databind", "2.9.10")])
    jar(tmp_path / "app/app.jar", [("com.example", "app", "1.0.0")], {"BOOT-INF/lib/jackson-databind-2.9.10.jar": inner})
    got, lines = apps_of(tmp_path)
    assert ("Maven", "com.fasterxml.jackson.core:jackson-databind", "2.9.10",
            "/app/app.jar!/BOOT-INF/lib/jackson-databind-2.9.10.jar") in rows(got)
    assert ("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1", "/opt/app/lib/log4j-core-2.14.1.jar") in rows(got)
    assert ("Maven", "com.example:app", "1.0.0", "/app/app.jar") in rows(got)
    assert lines["java_archives"] == {"state": "ok", "count": 4}  # the scratch copy of the inner jar counts as its own location


@POSIX
def test_jenkins_plugins_inside_a_war_are_read_two_levels_deep(tmp_path):
    """jenkins.war carries its detached plugins as .hpi files, each a jar of jars (found on the real run); a running Jenkins
    keeps its plugins as .jpi files. Two levels are read; a third isn't."""
    deepest = jar(tmp_path / "scratch/d.jar", [("too", "deep", "1.0")])
    lib = jar(tmp_path / "scratch/sshd-core.jar", [("org.apache.sshd", "sshd-core", "1.7.0")], {"inner/d.jar": deepest})
    hpi = jar(tmp_path / "scratch/sshd.hpi", [("org.jenkins-ci.modules", "sshd", "3.1")], {"WEB-INF/lib/sshd-core-1.7.0.jar": lib})
    jar(tmp_path / "usr/share/jenkins/jenkins.war", [("org.jenkins-ci.main", "jenkins-war", "2.319.1")], {"WEB-INF/detached-plugins/sshd.hpi": hpi})
    jar(tmp_path / "var/jenkins_home/plugins/git.jpi", [("org.jenkins-ci.plugins", "git", "4.0")])
    for f in ("d.jar", "sshd-core.jar", "sshd.hpi"):
        (tmp_path / "scratch" / f).unlink()
    got, _ = apps_of(tmp_path)
    names = {r["name"]: r["source"] for r in got}
    assert names["org.apache.sshd:sshd-core"] == "/usr/share/jenkins/jenkins.war!/WEB-INF/detached-plugins/sshd.hpi!/WEB-INF/lib/sshd-core-1.7.0.jar"
    assert "org.jenkins-ci.modules:sshd" in names and "org.jenkins-ci.plugins:git" in names and "too:deep" not in names


@POSIX
def test_hostile_jars_read_nothing_and_finish(tmp_path):
    os.mkfifo(tmp_path / "evil.jar")
    with open(tmp_path / "sparse.jar", "wb") as f:  # 200 MB of nothing, no end record
        f.truncate(200 * 1024 * 1024)
    big = io.BytesIO()
    with zipfile.ZipFile(big, "w", zipfile.ZIP_DEFLATED) as z:  # a pom.properties declaring 10 MB: past the 64 KB cap, never read
        z.writestr("META-INF/maven/g/a/pom.properties", b"version=1\n" + b"\0" * (10 * 1024 * 1024))
    write(tmp_path / "bomb.jar", big.getvalue())
    eocd = b"PK\x05\x06" + b"\0" * 6 + (1).to_bytes(2, "little") + (agent.ZIP_MAX_DIRECTORY + 1).to_bytes(4, "little") + b"\0" * 6
    write(tmp_path / "huge-directory.jar", b"PK\x03\x04" + b"\0" * 100 + eocd)
    t = time.monotonic()
    got, lines = apps_of(tmp_path)
    assert time.monotonic() - t < 10
    assert got == []
    assert lines["java_archives"]["state"] == "failed" and "2 installs' metadata couldn't be read" in lines["java_archives"]["error"]  # sparse, huge directory


@POSIX
def test_a_jar_whose_central_directory_is_past_the_cap_is_never_parsed(tmp_path, monkeypatch):
    jar(tmp_path / "app/ok.jar", [("g", "a", "1.0")])
    assert [r["name"] for r in apps_of(tmp_path)[0]] == ["g:a"]
    monkeypatch.setattr(agent, "ZIP_MAX_DIRECTORY", 10)  # a real directory is ~100 bytes: past the cap, refused before zipfile reads it
    got, lines = apps_of(tmp_path)
    assert got == [] and lines["java_archives"] == {"state": "failed", "count": 0, "error": "1 installs' metadata couldn't be read"}


def test_zip_too_big_reads_the_end_record_only():
    small = io.BytesIO()
    with zipfile.ZipFile(small, "w") as z:
        z.writestr("a", "b")
    assert agent._zip_too_big(small, len(small.getvalue())) is False
    assert agent._zip_too_big(io.BytesIO(b"not a zip"), 9) is False  # zipfile refuses it itself


# ---- Go ---------------------------------------------------------------------------------------------------------

MODINFO = ("path\tgithub.com/coredns/coredns\nmod\tgithub.com/coredns/coredns\t(devel)\t\n"
           "dep\tgolang.org/x/net\tv0.17.0\th1:abc=\n"
           "dep\tgithub.com/miekg/dns\tv1.1.50\th1:def=\n=>\tgithub.com/coredns/dns\tv1.1.51\th1:ghi=\n"
           "dep\texample.com/local\tv0.0.0\t\n=>\t../local\t\t\n"
           "dep\tgoogle.golang.org/grpc\tv1.56.3-0.20230101000000-abcdefabcdef\th1:x=\nbuild\t-compiler=gc\n")


def test_go_buildinfo_parses_deps_replacements_and_the_toolchain():
    assert agent.parse_go_buildinfo(buildinfo("go1.22.3", MODINFO)) == ("1.22.3", [
        ("golang.org/x/net", "0.17.0"), ("github.com/coredns/dns", "1.1.51"), ("google.golang.org/grpc", "1.56.3-0.20230101000000-abcdefabcdef")])
    assert agent.parse_go_buildinfo(buildinfo("go1.21rc2 X:boringcrypto", ""))[0] == "1.21.0-rc.2"
    assert agent.parse_go_buildinfo(buildinfo("go1.20", ""))[0] == "1.20.0"
    assert agent.parse_go_buildinfo(buildinfo("devel go1.23-abc", ""))[0] is None
    assert agent.parse_go_buildinfo(buildinfo(inline=False)) is None  # pre-1.18: pointers into the binary
    assert agent.parse_go_buildinfo(buildinfo()[:40]) is None  # cut short
    assert agent.parse_go_buildinfo(agent.GO_MAGIC + b"\x08\x02" + b"\0" * 16 + b"\xff" * 12) is None  # a varint that never ends


def test_go_buildinfo_section_is_found_in_an_elf_and_offsets_are_checked():
    data = elf({".text": b"\x90" * 64, ".go.buildinfo": buildinfo("go1.22.3", MODINFO)})
    assert agent.go_buildinfo_section(io.BytesIO(data), len(data))[0].startswith(agent.GO_MAGIC)
    assert agent.go_buildinfo_section(io.BytesIO(elf({".text": b"\x90"})), 4096) is None  # a C binary
    assert agent.go_buildinfo_section(io.BytesIO(b"#!/bin/sh\n" * 200), 2000) is None
    bad = bytearray(data)
    bad[0x28:0x30] = (10 ** 9).to_bytes(8, "little")  # section table past the end of the file
    assert agent.go_buildinfo_section(io.BytesIO(bytes(bad)), len(bad)) is None


def old_go_elf(version="go1.16.15", modinfo=MODINFO):
    """A Go binary as Go before 1.18 wrote it: .go.buildinfo holds two pointers, each to a string header (data, length) in .data."""
    names = b"\0.shstrtab\0.data\0.go.buildinfo\0"
    addr = BASE + 64 + len(names)  # .data comes right after the header and the name table
    v, m = version.encode(), START + modinfo.encode() + END
    data = b"".join(x.to_bytes(8, "little") for x in (addr + 32, len(v), addr + 32 + len(v), len(m))) + v + m
    return elf({".data": data, ".go.buildinfo": agent.GO_MAGIC + bytes([8, 0]) + addr.to_bytes(8, "little") + (addr + 16).to_bytes(8, "little")})


def test_go_before_1_18_is_read_through_its_pointers():
    x = old_go_elf()
    assert agent.parse_go_buildinfo(*agent.go_buildinfo_section(io.BytesIO(x), len(x))) == ("1.16.15", [
        ("golang.org/x/net", "0.17.0"), ("github.com/coredns/dns", "1.1.51"), ("google.golang.org/grpc", "1.56.3-0.20230101000000-abcdefabcdef")])
    assert agent.parse_go_buildinfo(agent.GO_MAGIC + bytes([8, 0]) + b"\0" * 16, lambda a, n: b"") is None  # pointers to nowhere
    lying = agent.GO_MAGIC + bytes([8, 0]) + BASE.to_bytes(8, "little") * 2  # a header claiming a gigabyte string is refused unread
    assert agent.parse_go_buildinfo(lying, lambda a, n: BASE.to_bytes(8, "little") + (10 ** 9).to_bytes(8, "little") if n == 16 else b"") is None


@POSIX
def test_go_binaries_are_read_only_when_executable(tmp_path):
    bi = elf({".go.buildinfo": buildinfo("go1.22.3", MODINFO)})
    executable(tmp_path / "usr/local/bin/coredns", bi)
    write(tmp_path / "srv/not-exec", bi)  # no exec bit: not a program
    executable(tmp_path / "usr/local/bin/old-go", elf({".go.buildinfo": buildinfo(inline=False)}))  # pointers that resolve to nothing
    executable(tmp_path / "usr/local/bin/git-lfs", old_go_elf("go1.15.15", "path\tgithub.com/git-lfs/git-lfs\nmod\tgithub.com/git-lfs/git-lfs\t(devel)\t\n"
                                                                  "dep\tgithub.com/git-lfs/gitobj/v2\tv2.0.2\th1:x=\n"))
    executable(tmp_path / "usr/local/bin/c-prog", elf({".text": b"\x90" * 64}))
    got, lines = apps_of(tmp_path)
    assert rows(got) == sorted([("Go", n, v, "/usr/local/bin/coredns") for n, v in [
        ("golang.org/x/net", "0.17.0"), ("github.com/coredns/dns", "1.1.51"), ("google.golang.org/grpc", "1.56.3-0.20230101000000-abcdefabcdef"),
        ("stdlib", "1.22.3")]] + [("Go", "github.com/git-lfs/gitobj/v2", "2.0.2", "/usr/local/bin/git-lfs"), ("Go", "stdlib", "1.15.15", "/usr/local/bin/git-lfs")])
    assert lines["go_modules"] == {"state": "partial", "count": 6, "error": "1 installs' metadata couldn't be read"}


# ---- what the image's package manager installed --------------------------------------------------------------------

@POSIX
def test_dpkg_owned_files_are_left_to_the_os_list(tmp_path):
    write(tmp_path / "var/lib/dpkg/status", "")
    write(tmp_path / "var/lib/dpkg/info/python3-requests.list",
          "/.\n/usr\n/usr/lib/python3/dist-packages/requests-2.28.1.egg-info\n/usr/lib/python3/dist-packages/requests-2.28.1.egg-info/PKG-INFO\n")
    write(tmp_path / "var/lib/dpkg/info/golang-thing.list", "/bin/thing\n")  # merged /usr: lives at /usr/bin/thing
    write(tmp_path / "usr/lib/python3/dist-packages/requests-2.28.1.egg-info/PKG-INFO", "Name: requests\nVersion: 2.28.1\n")
    write(tmp_path / "usr/local/lib/python3.11/dist-packages/flask-2.0.0.dist-info/METADATA", "Name: Flask\nVersion: 2.0.0\n")
    executable(tmp_path / "usr/bin/thing", elf({".go.buildinfo": buildinfo("go1.19.1", MODINFO)}))
    root = agent.ContainerRoot.of_dir(str(tmp_path))
    try:
        owned = agent.container_owned(root)
        got, _ = agent.container_apps(root, budget(), owned)
    finally:
        root.close()
    assert owned[1] is None
    assert [(e, n, v) for e, n, v, _ in rows(got)] == [("PyPI", "flask", "2.0.0")]


@POSIX
def test_apk_and_rpm_owned_files(tmp_path):
    write(tmp_path / "lib/apk/db/installed", "P:py3-requests\nV:2.31.0-r0\nF:usr/lib/python3.11/site-packages/requests-2.31.0.dist-info\n"
                                             "R:METADATA\nF:usr/lib/python3.11/site-packages\nR:x.py\n")
    write(tmp_path / "usr/lib/python3.11/site-packages/requests-2.31.0.dist-info/METADATA", "Name: requests\nVersion: 2.31.0\n")
    write(tmp_path / "usr/lib/python3.11/site-packages/jinja2-3.0.0.dist-info/METADATA", "Name: Jinja2\nVersion: 3.0.0\n")
    got, _ = apps_of(tmp_path, owned=None)
    assert [(e, n, v) for e, n, v, _ in rows(got)] == [("PyPI", "jinja2", "3.0.0")]
    rpm = tmp_path / "rpm"
    write(rpm / "var/lib/rpm/rpmdb.sqlite", b"")
    write(rpm / "usr/lib/python3.9/site-packages/dnf-4.0.dist-info/METADATA", "Name: dnf\nVersion: 4.0\n")
    write(rpm / "usr/local/lib/python3.9/site-packages/pyyaml-5.3.dist-info/METADATA", "Name: PyYAML\nVersion: 5.3\n")
    executable(rpm / "usr/bin/podman", elf({".go.buildinfo": buildinfo("go1.21.1", MODINFO)}))
    got, _ = apps_of(rpm, owned=None)
    assert [(e, n, v) for e, n, v, _ in rows(got)] == [("PyPI", "pyyaml", "5.3")]


@POSIX
def test_an_unreadable_file_list_is_said_on_every_line(tmp_path):
    write(tmp_path / "var/lib/dpkg/info/big.list", "x")
    write(tmp_path / "var/lib/dpkg/info/fifo.list")
    os.remove(tmp_path / "var/lib/dpkg/info/fifo.list")
    os.mkfifo(tmp_path / "var/lib/dpkg/info/fifo.list")
    write(tmp_path / "usr/local/lib/python3.12/site-packages/a-1.dist-info/METADATA", "Name: a\nVersion: 1\n")
    got, lines = apps_of(tmp_path, owned=None)
    assert len(got) == 1
    assert lines["python_packages"]["state"] == "partial" and "file list couldn't be read" in lines["python_packages"]["error"]
    assert lines["npm_packages"]["state"] == "failed"  # nothing found and the list unread: absence proves nothing


@POSIX
def test_walk_budget_makes_every_line_partial(tmp_path):
    for i in range(30):
        write(tmp_path / f"usr/local/lib/python3.12/site-packages/p{i}-1.dist-info/METADATA", f"Name: p{i}\nVersion: 1\n")
    got, lines = apps_of(tmp_path, b=budget(entries=40))
    assert 0 < len(got) < 30
    assert all(line["state"] in ("partial", "failed") and "budget" in line["error"] for line in lines.values())


# ---- containers(): one walk per image, the opt-out ------------------------------------------------------------------

def _docker_query(images):
    """A fake docker CLI: ps lists the containers, inspect describes them."""
    def q(cmd, timeout=600):
        if cmd[:2] == ["docker", "ps"]:
            return 0, "".join(c["Id"] + "\n" for c in images), ""
        if cmd[:2] == ["docker", "inspect"]:
            return 0, json.dumps(images), ""
        return 1, "", "no"
    return q


def _ctr(cid, image, pid):
    return {"Id": cid * 64, "Name": f"/c{cid}", "State": {"Running": True, "Pid": pid}, "Image": "sha256:" + image * 64, "Config": {"Image": "app:1"}}


@POSIX
def test_containers_send_apps_and_lines_and_walk_each_image_once(tmp_path):
    write(tmp_path / "etc/os-release", "ID=debian\nVERSION_ID=\"12\"\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n")
    write(tmp_path / "var/lib/dpkg/status", "Package: base-files\nStatus: install ok installed\nVersion: 12.4\n")
    write(tmp_path / "app/node_modules/lodash/package.json", json.dumps({"name": "lodash", "version": "4.17.20"}))
    walks = []

    def read_apps(root, b):
        walks.append(1)
        return agent.container_apps(root, b, NOBODY_OWNS)
    which = lambda name, path=None: "/usr/bin/docker" if name == "docker" else None  # noqa: E731
    root_of = lambda pid, own, cid: agent.ContainerRoot.of_dir(str(tmp_path))  # noqa: E731
    body = agent.containers(_docker_query([_ctr("a", "1", 10), _ctr("b", "1", 11)]), which, root_of, euid=0, read_apps=read_apps)
    assert len(walks) == 1 and len(body["images"]) == 1
    img = body["images"][0]
    assert [c["name"] for c in img["containers"]] == ["ca", "cb"]
    assert img["apps"] == [{"ecosystem": "npm", "name": "lodash", "version": "4.17.20", "source": "/app/node_modules/lodash"}]
    assert img["collection"]["sources"]["npm_packages"] == {"state": "ok", "count": 1}
    assert set(img["collection"]["sources"]) == {"os_release", "package_db", "python_packages", "npm_packages", "java_archives", "go_modules"}
    off = agent.containers(_docker_query([_ctr("a", "1", 10)]), which, root_of, euid=0, apps=False)["images"][0]
    assert off["apps"] == [] and off["collection"]["sources"]["go_modules"] == {"state": "off", "count": 0}


# ---- crictl --------------------------------------------------------------------------------------------------------

def _cri_query(runtime, fail=()):
    """crictl as recorded on a real node: version, ps, inspect and images for one runtime (containerd or crio)."""
    def q(cmd, timeout=600):
        what = cmd[1]
        if what in fail:
            return 1, "", f"time=x level=fatal msg=\"{what} failed\""
        name = {"version": "version-{}.txt", "ps": "ps-{}.txt", "inspect": "inspect-{}.json", "images": "images-{}.json"}[what]
        return 0, (CRI / name.format(runtime)).read_text(), ""
    return q


@pytest.mark.parametrize("runtime,name,cid,pid", [
    ("containerd", "containerd", "6ab25ec0186e6ac6fe2fe38abb8d29e3b56ca321cbbd67ff387f56591dcc84ac", 700),
    ("crio", "cri-o", "500df4314994c34f74b57c299438a2c2a150674472fdc2ae7f7b599222d1f5c6", 825)])
def test_crictl_listing_from_real_containerd_and_cri_o(runtime, name, cid, pid):
    rt, found, problem, ids = agent.list_cri(_cri_query(runtime))
    assert (rt, problem, ids) == (name, None, [cid])
    ns, pod = ("payments", "api-7d9f4-x2k") if runtime == "containerd" else ("billing", "worker-5c6d-q8r")
    # both name the image by tag and registry digest; `crictl images` gives the config digest Docker and Podman use
    assert found == [{"id": cid, "name": f"{ns}/{pod}/app", "runtime": name, "pid": pid,
                      "image_id": "sha256:78976a69c067520ef8be34cde307ef9f6fea6dcefa50edb57039773d241ca0db",
                      "ref": "docker.io/library/python:3.12-slim"}]


def test_crictl_failures_are_problems_and_prove_nothing():
    assert agent.list_cri(_cri_query("containerd", fail=("version",)))[0::2] == (None, 'crictl version exited 1: time=x level=fatal msg="version failed"')
    rt, found, problem, ids = agent.list_cri(_cri_query("containerd", fail=("ps",)))
    assert (rt, found, ids) == ("containerd", [], None) and "crictl ps exited 1" in problem
    rt, found, problem, ids = agent.list_cri(_cri_query("containerd", fail=("images",)))
    assert found == [] and ids and "without its id, PID or image" in problem and "crictl images exited 1" in problem
    docker = lambda cmd, timeout=600: (0, "RuntimeName:  docker\n", "")  # noqa: E731
    assert agent.list_cri(docker)[:3] == (None, [], "crictl talks to docker, whose containers aren't read through crictl")


@POSIX
def test_crictl_takes_part_in_the_pass_and_in_completeness(tmp_path):
    which = lambda name, path=None: "/usr/bin/crictl" if name == "crictl" else None  # noqa: E731
    reads = []

    def root_of(pid, own, cid):
        reads.append((pid, cid))
        raise agent.ContainerReadError("gone")
    body = agent.containers(_cri_query("containerd"), which, root_of, euid=0)
    assert body["listed"] == {"docker": [], "podman": [], "containerd": ["6ab25ec0186e6ac6fe2fe38abb8d29e3b56ca321cbbd67ff387f56591dcc84ac"]}
    assert reads == [(700, "6ab25ec0186e6ac6fe2fe38abb8d29e3b56ca321cbbd67ff387f56591dcc84ac")]
    assert body["runtimes"]["containerd"] == {"state": "ok", "count": 1} and body["complete"] is False  # it stopped before it was read
    failing = agent.containers(_cri_query("containerd", fail=("ps",)), which, root_of, euid=0)
    assert "containerd" not in failing["listed"] and failing["runtimes"]["containerd"]["state"] == "failed"


def test_no_crictl_and_no_runtime_anywhere_lists_none():
    body = agent.containers(lambda *a, **k: (1, "", ""), lambda name, path=None: None, euid=0)
    assert body["listed"] == {"docker": [], "podman": [], "containerd": [], "cri-o": []}
    kept = agent.containers(lambda *a, **k: (1, "", ""), lambda name, path=None: "/usr/bin/containerd" if name == "containerd" else None, euid=0)
    assert "containerd" not in kept["listed"] and kept["listed"]["cri-o"] == []  # containerd is installed: its pods may still run


# ---- security audit (DECISIONS 160) --------------------------------------------------------------------------------

@POSIX
def test_the_budget_holds_while_files_are_read_not_only_while_folders_are_listed(tmp_path, monkeypatch):
    first = jar(tmp_path / "lib/a0.jar", [("g", "a", "1.0")])
    for i in range(1, 50):  # hard links in a real image: no disk, one listing, and each name parsed again
        os.link(tmp_path / "lib/a0.jar", tmp_path / f"lib/a{i}.jar")
    assert first
    real = agent._poms

    def slow(*a, **k):
        time.sleep(0.1)
        return real(*a, **k)
    monkeypatch.setattr(agent, "_poms", slow)
    t = time.monotonic()
    got, lines = apps_of(tmp_path, b=budget(seconds=1))
    assert time.monotonic() - t < 3
    assert lines["java_archives"]["state"] == "partial" and "budget" in lines["java_archives"]["error"]


def test_the_zip_guard_reads_the_end_record_zipfile_will_use():
    cap = agent.ZIP_MAX_DIRECTORY
    # a comment-free end record whose own offset field holds the end signature: a backwards search stops there
    eocd = b"PK\x05\x06" + b"\0" * 6 + (1).to_bytes(2, "little") + (cap + 1).to_bytes(4, "little") + b"PK\x05\x06" + b"\0\0"
    data = b"\0" * 100 + eocd
    assert agent._zip_too_big(io.BytesIO(data), len(data)) is True
    # a zip64 locator before a small classic record: zipfile takes the zip64 directory size (a consistent one: Python 3.14
    # refuses a zip64 record whose directory doesn't end where the record starts, and then refuses the whole file itself)
    rec64 = (b"PK\x06\x06" + (44).to_bytes(8, "little") + b"\0" * 4 + b"\0" * 8 + (1).to_bytes(8, "little") + (1).to_bytes(8, "little")
             + (cap + 1).to_bytes(8, "little") + (0).to_bytes(8, "little"))
    loc = b"PK\x06\x07" + b"\0" * 4 + (cap + 1).to_bytes(8, "little") + (1).to_bytes(4, "little")
    classic = b"PK\x05\x06" + b"\0" * 6 + (1).to_bytes(2, "little") + (46).to_bytes(4, "little") + (0).to_bytes(4, "little") + b"\0\0"
    data = b"\0" * (cap + 1) + rec64 + loc + classic
    assert agent._zip_too_big(io.BytesIO(data), len(data)) is True


def test_a_location_that_isnt_utf8_is_sent_with_a_replacement_character():
    assert agent._where("/srv/site-packages/\udcff-1.0.dist-info") == "/srv/site-packages/�-1.0.dist-info"
    json.dumps(agent._where("/a/\udcff"), ensure_ascii=False).encode("utf-8")  # encodable: the server can store it


@POSIX
def test_a_huge_file_list_is_said_not_held_in_memory(tmp_path, monkeypatch):
    monkeypatch.setattr(agent, "CONTAINER_OWNED_MAX", 10)
    write(tmp_path / "lib/apk/db/installed", "P:x\nV:1\n" + "".join(f"F:bin/{i}\nR:f\n" for i in range(20)))
    write(tmp_path / "usr/local/lib/python3.12/site-packages/a-1.dist-info/METADATA", "Name: a\nVersion: 1\n")
    got, lines = apps_of(tmp_path, owned=None)
    assert len(got) == 1 and "file list couldn't be read" in lines["python_packages"]["error"] and "more than 10" in lines["python_packages"]["error"]


@POSIX
def test_a_huge_dpkg_file_list_is_said_too(tmp_path, monkeypatch):
    monkeypatch.setattr(agent, "CONTAINER_OWNED_MAX", 10)
    write(tmp_path / "var/lib/dpkg/info/big.list", "".join(f"/usr/share/doc/x/{i}\n" for i in range(20)))
    write(tmp_path / "usr/local/lib/python3.12/site-packages/a-1.dist-info/METADATA", "Name: a\nVersion: 1\n")
    _, lines = apps_of(tmp_path, owned=None)
    assert "more than 10 paths" in lines["python_packages"]["error"]


def test_a_jars_pom_entries_stop_at_the_budget():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for i in range(50):
            z.writestr(f"META-INF/maven/g/a{i}/pom.properties", f"groupId=g\nartifactId=a{i}\nversion=1\n")
    out, asked = {}, []

    def late():
        asked.append(1)
        return len(asked) > 3
    with zipfile.ZipFile(buf) as z:
        agent._poms(z, "/app.jar", out, late)
    assert len(out) == 3  # asked before each entry; the fourth is past the budget


@POSIX
def test_a_file_on_another_mount_is_never_opened():
    root = agent.ContainerRoot.of_dir("/")
    proc = os.open("/proc", os.O_PATH | os.O_DIRECTORY)
    try:
        assert root.open_file(proc, "version") is None  # procfs: a mount of its own, as a bind-mounted file is
    finally:
        os.close(proc)
        root.close()


@POSIX
def test_a_jar_past_the_size_cap_is_one_unread_jar_and_the_walk_goes_on(tmp_path, monkeypatch):
    jar(tmp_path / "a/big.jar", [("g", "big", "1.0")])
    write(tmp_path / "b/site-packages/later-1.dist-info/METADATA", "Name: later\nVersion: 1\n")
    monkeypatch.setattr(agent, "CONTAINER_JAR_MAX", 10)
    got, lines = apps_of(tmp_path)
    assert [r["name"] for r in got] == ["later"]
    assert lines["java_archives"] == {"state": "failed", "count": 0, "error": "1 installs' metadata couldn't be read"}


# ---- code review (DECISIONS 160) -----------------------------------------------------------------------------------

def test_one_container_gone_between_ps_and_inspect_costs_only_itself():
    """cri-tools' inspect stops at the first id it can't describe and prints nothing: the rest are asked one at a time."""
    one = json.loads((CRI / "inspect-containerd.json").read_text())
    ids = ["a" * 64, "b" * 64, "c" * 64]
    described = {i: {**one, "status": {**one["status"], "id": i}} for i in (ids[0], ids[2])}
    calls = []

    def q(cmd, timeout=600):
        calls.append(cmd)
        if cmd[1] == "version":
            return 0, (CRI / "version-containerd.txt").read_text(), ""
        if cmd[1] == "ps":
            return 0, "\n".join(ids) + "\n", ""
        if cmd[1] == "images":
            return 0, (CRI / "images-containerd.json").read_text(), ""
        if cmd[1] == "inspect" and len(cmd) > 5:  # all at once: one gone, so crictl answers nothing
            return 1, "", f'level=fatal msg="getting the status of the container {ids[1]}: rpc error: code = NotFound desc = an error occurred when try to find container"'
        cid = cmd[-1]
        return (0, json.dumps(described[cid]), "") if cid in described else (1, "", "rpc error: code = NotFound desc = not found")
    rt, found, problem, listing = agent.list_cri(q)
    assert [c["id"] for c in found] == [ids[0], ids[2]] and problem is None and listing == ids
    assert sum(c[1] == "inspect" for c in calls) == 4  # once for all (which printed nothing), then once each


def test_the_image_id_comes_from_the_running_images_digest_before_a_tag_that_moved():
    images = json.loads((CRI / "images-containerd.json").read_text())
    moved = {"id": "sha256:" + "9" * 64, "repoTags": ["docker.io/library/python:3.12-slim"], "repoDigests": []}  # the tag, re-pulled
    for im in images["images"]:
        if "docker.io/library/python:3.12-slim" in im["repoTags"]:
            im["repoTags"] = []  # the image the container started from keeps only its digest
    images["images"].insert(0, moved)
    q = _cri_query("containerd")

    def query(cmd, timeout=600):
        return (0, json.dumps(images), "") if cmd[1] == "images" else q(cmd, timeout)
    _, found, _, _ = agent.list_cri(query)
    assert found[0]["image_id"] == "sha256:78976a69c067520ef8be34cde307ef9f6fea6dcefa50edb57039773d241ca0db"


@POSIX
def test_an_image_cut_short_says_so_in_the_same_words_each_time(tmp_path):
    for i in range(30):
        write(tmp_path / f"usr/local/lib/python3.12/site-packages/p{i}-1.dist-info/METADATA", f"Name: p{i}\nVersion: 1\n")
    first, again = apps_of(tmp_path, b=budget(entries=40))[1], apps_of(tmp_path, b=budget(entries=40))[1]
    assert first == again and first["python_packages"]["error"] == "stopped at its 200,000-entry budget" or "budget" in first["python_packages"]["error"]
    assert not any(ch.isdigit() for ch in budget_text(apps_of(tmp_path, b=budget(seconds=0))[1]))


def budget_text(lines):
    return lines["python_packages"]["error"]
