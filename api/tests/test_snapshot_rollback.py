"""Snapshot rollback for apk and dnf against simulated hosts (real proof: sandbox/sbx.py on Alpine and AlmaLinux)."""

from pathlib import Path

from test_agent_remediate import agent

OLD, NEW = "3.1.4-r0", "3.1.7-r1"


def apk_db(version, extra_file=False):
    files = "R:libcrypto.so.3\n" + ("R:new-plugin.so\n" if extra_file else "")
    return (f"P:busybox\nV:1.36.1-r20\nF:bin\nR:busybox\n\n"
            f"P:libcrypto3\nV:{version}\no:openssl\nF:usr/lib\n{files}\n")


class FakeApk:
    def __init__(self, root, break_health=False, extra_pkg=None):
        self.root, self.break_health, self.extra_pkg = Path(root), break_health, extra_pkg
        (self.root / "lib/apk/db").mkdir(parents=True)
        (self.root / "lib/apk/db/installed").write_text(apk_db(OLD))
        (self.root / "lib/apk/db/scripts.tar").write_bytes(b"old scripts")
        (self.root / "etc/apk").mkdir(parents=True)
        (self.root / "etc/apk/world").write_text("busybox\n")
        (self.root / "usr/lib").mkdir(parents=True)
        (self.root / "usr/lib/libcrypto.so.3").write_text("old library")
        self.healthy, self.log = True, []

    def __call__(self, cmd, cwd=None):
        self.log.append(cmd)
        match cmd:
            case ["apk", "version", "-t", a, b]:
                from nimstead.versions import apk_cmp
                return 0, {1: ">", 0: "=", -1: "<"}[apk_cmp(a, b)]
            case ["apk", "--version"] | ["apk", "update"]:
                return 0, "ok"
            case ["systemctl", "show", "-p", "NRestarts", "--value", _]:
                return 0, "0"
            case ["systemctl", "is-active", *_]:
                broken = self.break_health and (self.root / "usr/lib/libcrypto.so.3").read_text() == "new library"
                return (3, "") if broken or not self.healthy else (0, "")
            case ["apk", "add", "-s", "--upgrade", *_]:
                extra = f"\n(2/2) Upgrading {self.extra_pkg} (1 -> 2)" if self.extra_pkg else ""
                return 0, f"(1/1) Upgrading libcrypto3 ({OLD} -> {NEW}){extra}\nOK: 10 MiB in 20 packages"
            case ["apk", "add", "--upgrade", *specs]:
                (self.root / "lib/apk/db/installed").write_text(apk_db(NEW, extra_file=True))
                (self.root / "lib/apk/db/scripts.tar").write_bytes(b"new scripts")
                (self.root / "usr/lib/libcrypto.so.3").write_text("new library")
                self.new_ino = (self.root / "usr/lib/libcrypto.so.3").stat().st_ino
                (self.root / "usr/lib/new-plugin.so").write_text("added by upgrade")
                with open(self.root / "etc/apk/world", "a") as f:
                    f.write("\n".join(specs) + "\n")  # what real `apk add` does to dependencies
                return 0, "OK"
        raise AssertionError(cmd)


JOB = {"id": "a1", "manager": "apk", "health_units": ["app.service"], "settle_seconds": 0,
       "packages": [{"name": "libcrypto3", "from": OLD}]}


def run(tmp_path, host, job=JOB):
    return agent.Job(job, run=host, rollback_root=str(tmp_path / "rb"), root=str(host.root)).execute()


def test_apk_upgrade_keeps_world_file_unchanged(tmp_path):
    h = FakeApk(tmp_path / "root")
    outcome, _, err = run(tmp_path, h)
    assert outcome == "applied" and err is None
    assert (h.root / "etc/apk/world").read_text() == "busybox\n"  # no accidental pins / world entries


def test_apk_failure_restores_files_and_database_exactly(tmp_path):
    h = FakeApk(tmp_path / "root", break_health=True)
    before_db = (h.root / "lib/apk/db/installed").read_text()
    outcome, steps, err = run(tmp_path, h)
    assert outcome == "rolled_back", err
    assert (h.root / "lib/apk/db/installed").read_text() == before_db
    assert (h.root / "lib/apk/db/scripts.tar").read_bytes() == b"old scripts"
    assert (h.root / "usr/lib/libcrypto.so.3").read_text() == "old library"
    # a new file, not the new one rewritten in place: that fails on a running binary and crashes processes mapping a library
    assert (h.root / "usr/lib/libcrypto.so.3").stat().st_ino != h.new_ino
    assert not list(h.root.rglob("*.nimstead-restore"))
    assert not (h.root / "usr/lib/new-plugin.so").exists()  # file introduced by the new version removed
    assert [s["step"] for s in steps if s["step"].startswith("versions restored")]


def test_apk_unplanned_package_in_transaction_refused(tmp_path):
    h = FakeApk(tmp_path / "root", extra_pkg="musl")
    outcome, _, err = run(tmp_path, h)
    assert outcome == "aborted" and "would also change: musl" in err
    assert (h.root / "usr/lib/libcrypto.so.3").read_text() == "old library"


def test_tampered_snapshot_refused(tmp_path):
    h = FakeApk(tmp_path / "root", break_health=True)
    j = agent.Job(JOB, run=h, rollback_root=str(tmp_path / "rb"), root=str(h.root))
    real_apply = j.apply

    def apply_then_tamper():
        real_apply()
        Path(j.artefacts[0][0]).write_bytes(b"evil")

    j.apply = apply_then_tamper
    outcome, _, err = j.execute()
    assert outcome == "rollback_failed" and "ROLLBACK FAILED" in err
    assert (h.root / "usr/lib/libcrypto.so.3").read_text() == "new library"  # nothing restored from a bad archive


def test_apk_owned_paths():
    assert agent.apk_owned(apk_db(OLD), {"libcrypto3"}) == ["/usr/lib", "/usr/lib/libcrypto.so.3"]


DNF_PLAN = """Last metadata expiration check: 0:00:05 ago.
Dependencies resolved.
================================================================================
 Package               Arch      Version                  Repository      Size
================================================================================
Upgrading:
 openssl               x86_64    1:3.2.2-6.el9_5.1        baseos         1.4 M
 openssl-libs          x86_64    1:3.2.2-6.el9_5.1        baseos         2.2 M
Installing dependencies:
 crypto-policies-x     noarch    20250128-1.el9           baseos          10 k

Transaction Summary
================================================================================
Upgrade  2 Packages
Operation aborted.
"""


def test_dnf_transaction_parser():
    assert agent.dnf_touched(DNF_PLAN) == {"openssl", "openssl-libs", "crypto-policies-x"}


class NoUpgradeApk(FakeApk):
    def __call__(self, cmd, cwd=None):
        return (0, "OK: 10 MiB in 20 packages") if cmd[:3] == ["apk", "add", "-s"] else super().__call__(cmd, cwd)


def test_apk_with_no_upgrade_on_offer_aborts_before_any_change(tmp_path):
    h = NoUpgradeApk(tmp_path / "root")
    outcome, _, err = run(tmp_path, h)
    assert outcome == "aborted" and "offers no upgrade for: libcrypto3" in err
    assert (h.root / "usr/lib/libcrypto.so.3").read_text() == "old library"


def test_dnf_with_nothing_to_do_is_refused_in_the_dry_run(tmp_path):
    job = {**JOB, "manager": "dnf", "packages": [{"name": "openssl", "from": "1:3.2.2-1.el9"}]}
    for out in ("Dependencies resolved.\nNothing to do.\nComplete!\n",  # dnf4: no plan printed at all
                "Dependencies resolved.\n\nTransaction Summary\n====\n\nOperation aborted.\n"):  # a summary of nothing
        j = agent.Job(job, run=lambda cmd, cwd=None, out=out: (1, out), rollback_root=str(tmp_path / "rb"), root=str(tmp_path))
        try:
            j.simulate()
            raise AssertionError("dry run passed")
        except agent.StepFailed as e:
            assert "simulate upgrade failed" in str(e) or "offers no upgrade for: openssl" in str(e)


def test_a_hardlinked_pair_restores_as_new_files_never_in_place(tmp_path):
    """Review: before Python 3.13 tarfile wrote a hardlink member whose path existed into that path's inode: the ETXTBSY
    write the new-inode restore removes. Both paths come back as one new file; no temp copy is left beside them."""
    import os
    import tarfile
    src = tmp_path / "src" / "usr" / "bin"
    src.mkdir(parents=True)
    (src / "perl").write_text("old perl")
    os.link(src / "perl", src / "perl5.36")
    with tarfile.open(tmp_path / "rb.tar", "w") as tar:
        for n in ("perl", "perl5.36"):
            tar.add(src / n, arcname=f"usr/bin/{n}", recursive=False)
    root = tmp_path / "root" / "usr" / "bin"
    root.mkdir(parents=True)
    (root / "perl").write_text("new perl")
    os.link(root / "perl", root / "perl5.36")  # the upgraded pair, which a running process may hold
    running = (root / "perl").stat().st_ino
    with tarfile.open(tmp_path / "rb.tar") as tar:
        members = tar.getmembers()
        assert [m.islnk() for m in members] == [False, True]
        for m in members:
            agent._restore_beside(tar, m, str(tmp_path / "root"), {})
    assert (root / "perl").read_text() == (root / "perl5.36").read_text() == "old perl"
    assert (root / "perl").stat().st_ino == (root / "perl5.36").stat().st_ino != running
    assert not list(root.glob("*.nimstead-restore"))
