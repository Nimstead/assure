"""zypper remediation with snapper rollback against a simulated openSUSE host (real proof: sandbox/suse.py)."""

from test_agent_remediate import agent

OLD, NEW = "0:3.5.0-160000.3.1", "0:3.5.0-160000.4.1"


def xml_summary(*names, removed=()):
    up = "".join(f'<solvable type="package" name="{n}" edition="3.5.0-160000.4.1" arch="x86_64"/>' for n in names)
    rm = "".join(f'<solvable type="package" name="{n}"/>' for n in removed)
    return (f'<?xml version="1.0"?><stream><message type="info">Loading repository data...</message><install-summary>'
            f'<to-upgrade>{up}</to-upgrade>' + (f"<to-remove>{rm}</to-remove>" if rm else "") + "</install-summary></stream>")


class FakeSuse:
    def __init__(self, extra=(), breaks=False, snapper=True):
        self.installed = {"openssl-3": OLD, "libopenssl3": OLD}
        self.extra, self.breaks, self.snapper = list(extra), breaks, snapper
        self.snaps, self.config = [], "original"  # config = a file a %post script edits, outside the package
        self.log = []

    def __call__(self, cmd, cwd=None):
        self.log.append(cmd)
        match cmd:
            case ["zypper", "--version"]:
                return 0, "zypper 1.14"
            case ["zypper", "--non-interactive", "refresh"]:
                return 0, ""
            case ["rpm", "-q", "--qf", _, name]:
                return (0, self.installed[name]) if name in self.installed else (1, "not installed")
            case ["systemctl", "is-active", "--quiet", _]:
                return (3, "") if self.breaks and self.installed["openssl-3"] == NEW else (0, "")
            case ["zypper", "--non-interactive", "--xmlout", "install", "--dry-run", *specs]:
                return 0, xml_summary(*specs, *self.extra)
            case ["snapper", "-c", "root", "list", "--columns", "number"]:
                return (0, "0\n1") if self.snapper else (1, "Unknown config.")
            case ["snapper", "-c", "root", "create", "--type", "pre", *_]:
                self.snaps.append(("pre", dict(self.installed), self.config))
                return 0, str(len(self.snaps))
            case ["snapper", "-c", "root", "create", "--type", "post", *_]:
                self.snaps.append(("post", dict(self.installed), self.config))
                return 0, str(len(self.snaps))
            case ["zypper", "--non-interactive", "install", "--no-recommends", *specs]:
                for s in specs:
                    self.installed[s.split("=")[0]] = NEW
                self.config = "edited by %post script"
                return 0, "done"
            case ["snapper", "-c", "root", "undochange", rng]:
                pre = int(rng.split("..")[0])
                _, self.installed, self.config = self.snaps[pre - 1][0], dict(self.snaps[pre - 1][1]), self.snaps[pre - 1][2]
                return 0, "create:0 modify:12 delete:3"
        raise AssertionError(cmd)


JOB = {"id": "z1", "manager": "zypper", "health_units": ["sshd.service"], "settle_seconds": 0,
       "packages": [{"name": "openssl-3", "from": OLD}, {"name": "libopenssl3", "from": OLD}]}


def run(tmp_path, h, job=JOB):
    return agent.Job(job, run=h, rollback_root=str(tmp_path / "rb")).execute()


def test_zypper_upgrade_with_snapper_pre_post(tmp_path):
    h = FakeSuse()
    outcome, steps, err = run(tmp_path, h)
    assert outcome == "applied" and err is None
    assert [k for k, *_ in h.snaps] == ["pre", "post"]


def test_snapper_undo_reverts_script_side_effects_too(tmp_path):
    h = FakeSuse(breaks=True)
    outcome, steps, err = run(tmp_path, h)
    assert outcome == "rolled_back", err
    assert h.installed["openssl-3"] == OLD
    assert h.config == "original"  # the %post edit outside the package's files is undone as well
    assert any(c[:4] == ["snapper", "-c", "root", "undochange"] for c in h.log)


def test_zypper_scope_check_refuses_unplanned_changes(tmp_path):
    h = FakeSuse(extra=["glibc"])
    outcome, _, err = run(tmp_path, h)
    assert outcome == "aborted" and "would also change: glibc" in err and h.snaps == []


def test_zypper_xml_parser():
    assert agent.zypper_touched(xml_summary("a", "b", removed=["c"])) == {"a", "b", "c"}


def test_without_snapper_falls_back_to_file_snapshot(tmp_path, monkeypatch):
    h = FakeSuse(snapper=False)
    j = agent.Job(JOB, run=h, rollback_root=str(tmp_path / "rb"))
    called = {}
    monkeypatch.setattr(j, "owned_paths", lambda: called.setdefault("owned", set()))
    monkeypatch.setattr(j, "path", lambda p: str(tmp_path / "root" / p.lstrip("/")))
    (tmp_path / "root/var/lib/rpm").mkdir(parents=True)
    (tmp_path / "root/var/lib/rpm/rpmdb.sqlite").write_text("db")
    j.save_rollback()
    assert "owned" in called and j.db_backups and not getattr(j, "snap_pre", None)


def test_suse_ecosystems():
    osr = 'ID="opensuse-leap"\nVERSION_ID="16.0"\n'
    assert agent.ecosystem_from_os_release(osr) == "openSUSE:Leap 16.0"
    assert agent.ecosystem_from_os_release('ID="sles"\nVERSION_ID="15.6"\n') == "SUSE:Linux Enterprise Server 15 SP6"
    assert agent.ecosystem_from_os_release('ID="opensuse-tumbleweed"\nVERSION_ID="20261024"\n') == "openSUSE:Tumbleweed"
