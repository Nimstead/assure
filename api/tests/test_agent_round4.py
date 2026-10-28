"""Security round 4, agent side (tasks/plan-0.4-security.md A2-A5): fixes never downgrade, rollback copies don't fill the
disk, signed channels, strict regexes, capped responses, and the installers."""

from pathlib import Path

import pytest
from test_agent_remediate import JOB, NEW, OLD, FakeApt, agent, fill_cache, job_kw, run
from test_agent_update import FakeServer, host, pub, run_update, signed  # noqa: F401  host is a fixture
from test_snapshot_rollback import JOB as APK_JOB
from test_snapshot_rollback import FakeApk
from test_snapshot_rollback import run as run_apk

# --- A2: never downgrade ---------------------------------------------------------------------------------------------

def test_pinned_older_version_is_refused_before_any_change(tmp_path):
    job = {**JOB, "packages": [{**p, "to": "3.0.9-1~deb12u1"} for p in JOB["packages"]]}  # older than installed
    h = FakeApt(tmp_path, OLD, NEW)
    outcome, steps, err = run(tmp_path, h, job)
    assert outcome == "aborted" and "not newer: libssl3 3.0.9-1~deb12u1" in err
    assert not any(c[:2] == ["apt-get", "install"] for c in h.log) and h.installed == OLD


def test_apk_pinned_downgrade_and_dry_run_downgrade_are_refused(tmp_path):
    h = FakeApk(tmp_path / "a")
    older = {**APK_JOB, "packages": [{**APK_JOB["packages"][0], "to": "3.0.0-r0"}]}
    outcome, _, err = run_apk(tmp_path, h, older)
    assert outcome == "aborted" and "not newer: libcrypto3 3.0.0-r0" in err
    assert not any(c[:3] == ["apk", "add", "--upgrade"] for c in h.log)

    class Downgrading(FakeApk):
        def __call__(self, cmd, cwd=None):
            if cmd[:3] == ["apk", "add", "-s"]:
                return 0, "(1/1) Downgrading libcrypto3 (3.3.2-r0 -> 3.3.1-r0)\nOK"
            return super().__call__(cmd, cwd)
    h = Downgrading(tmp_path / "b")
    outcome, _, err = run_apk(tmp_path, h)
    assert outcome == "aborted" and "would downgrade: libcrypto3" in err


def test_dnf_and_zypper_downgrade_sections_are_found():
    from test_snapshot_rollback import DNF_PLAN
    from test_zypper import xml_summary
    plan = DNF_PLAN.replace("Upgrading:", "Downgrading:")
    assert agent.dnf_touched(plan, ("Downgrading",)) == {"openssl", "openssl-libs"}
    assert agent.dnf_touched(DNF_PLAN, ("Downgrading",)) == set()
    xml = xml_summary("openssl").replace("to-upgrade", "to-downgrade")
    assert agent.zypper_touched(xml, ("to-downgrade",)) == {"openssl"} and agent.zypper_touched(xml_summary("openssl"), ("to-downgrade",)) == set()


# --- A3: rollback copies -----------------------------------------------------------------------------------------------

def test_no_change_without_room_for_the_rollback_copy(tmp_path, monkeypatch):
    monkeypatch.setattr(agent, "MIN_FREE_BYTES", 1 << 62)
    h = FakeApt(tmp_path, OLD, NEW)
    outcome, _, err = run(tmp_path, h)
    assert outcome == "aborted" and "MiB free" in err and h.installed == OLD


@pytest.mark.parametrize(("kw", "outcome", "kept"), [({}, "applied", False), ({"break_unit_on_upgrade": True}, "rolled_back", False),
                                                     ({"break_unit_on_upgrade": True, "dpkg_i_fails": True}, "rollback_failed", True)])
def test_rollback_copy_is_removed_once_the_outcome_is_saved(tmp_path, monkeypatch, kw, outcome, kept):
    fill_cache(tmp_path)
    h = FakeApt(tmp_path, OLD, NEW, **kw)
    sent = []
    monkeypatch.setattr(agent, "post", lambda server, path, body, *a, **k: [JOB] if path == "/api/agent/jobs" else sent.append(body) or {})
    agent.run_jobs("https://x", "k", False, run=h, outcome_dir=str(tmp_path / "outcomes"), **job_kw(tmp_path))
    assert [b["outcome"] for b in sent] == [outcome]
    assert (tmp_path / "rb" / "j1").exists() == kept  # a failed rollback keeps its copy for whoever repairs the host


def test_a_reused_job_id_cannot_delete_a_kept_rollback_copy(tmp_path):
    kept = tmp_path / "rb" / "j1"  # left by an earlier job's failed rollback, for whoever repairs the host
    kept.mkdir(parents=True)
    (kept / "files.tar").write_text("the only copy")
    h = FakeApt(tmp_path, OLD, NEW)
    job = agent.Job(JOB, run=h, **job_kw(tmp_path))
    outcome, _, err = job.execute()
    job.discard_rollback(outcome)
    assert outcome == "aborted" and "rollback copy kept from an earlier job" in err and h.installed == OLD
    assert (kept / "files.tar").read_text() == "the only copy"


# --- A4: signed channels -----------------------------------------------------------------------------------------------

@pytest.mark.parametrize(("release", "mine", "ok"), [
    ("stable", "stable", True), ("beta", "stable", False), ("preview", "stable", False), (None, "stable", False),
    ("beta", "beta", True), ("stable", "beta", True), ("preview", "beta", False),
    ("preview", "preview", True), ("preview", None, True),  # enrolled before channels: everything, as before
])
def test_channel_matrix(release, mine, ok):
    assert agent.channel_ok({"channel": release} if release else {}, {"channel": mine} if mine else {}) is ok


def test_stable_host_skips_a_preview_build_the_server_relays(host, monkeypatch):  # noqa: F811  the imported fixture
    path, k = host
    old = path.read_bytes()
    new, manifest, sig = signed(k, old, "9.0.0")  # sign_release defaults to preview
    cfg = {"server": "https://nimstead.example", "agent_key": "nma_x", "channel": "stable"}
    v, why = run_update(monkeypatch, path, k, FakeServer(k, new, manifest, sig), cfg=cfg)
    assert v is None and "signed for preview" in why and path.read_bytes() == old
    assert run_update(monkeypatch, path, k, FakeServer(k, new, manifest, sig), cfg={**cfg, "channel": "preview"})[0] == "9.0.0"
    assert pub(k)


def test_enrol_records_the_channel(monkeypatch):
    saved = {}
    monkeypatch.setattr(agent, "collect", lambda: {"os_name": "x", "ecosystem": "Debian:13", "packages": []})
    monkeypatch.setattr(agent, "post", lambda *a, **kw: {"asset_id": "a1", "agent_key": "nma_k", "channel": "preview"})
    monkeypatch.setattr(agent, "save_config", lambda cfg: saved.update(cfg) or "cfg")
    assert agent.main(["enroll", "--server", "https://n.example", "--token", "t", "--channel", "beta"]) == 0
    assert saved["channel"] == "beta"  # from the installer's flag, never the server's answer
    with pytest.raises(SystemExit):
        agent.main(["enroll", "--server", "https://n.example", "--token", "t", "--channel", "nightly"])


# --- A5: strict regexes, capped responses ---------------------------------------------------------------------------

def test_a_trailing_newline_never_passes_validation(tmp_path):
    for bad in ({**JOB, "packages": [{"name": "openssl\n", "from": OLD["openssl"]}]},
                {**JOB, "packages": [{"name": "openssl", "from": OLD["openssl"] + "\n"}]},
                {**JOB, "health_units": ["nginx.service\n"]}):
        h = FakeApt(tmp_path, OLD, NEW)
        assert run(tmp_path, h, bad)[0] == "aborted" and h.log == []
    assert not agent.SAFE_KB.match("5034441\n") and agent.SAFE_KB.match("5034441")
    assert not agent.ROLLUP_NAME.match("Package_for_RollupFix~31bf3856ad364e35~amd64~~26100.1.1\n")


def test_json_responses_are_capped(monkeypatch):
    class Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n=-1):
            return b"[" + b"0," * (agent.MAX_AGENT_BYTES // 2) + b"0]"
    monkeypatch.setattr(agent._opener, "open", lambda req, timeout=None: Resp())
    with pytest.raises(agent.AgentError, match="larger than"):
        agent.post("https://x", "/api/agent/jobs", None, False, "k")


# --- installers --------------------------------------------------------------------------------------------------------

def test_installers_pass_the_channel_and_check_the_trusted_folder_properly(env, monkeypatch):
    from fastapi.testclient import TestClient

    from nimstead.app import create_app
    monkeypatch.setenv("NIMSTEAD_UPDATE_CHANNEL", "beta")
    monkeypatch.setenv("NIMSTEAD_PUBLIC_URL", "https://nim.example")
    c = TestClient(create_app(env))
    sh, ps1 = c.get("/install.sh").text, c.get("/install.ps1").text
    assert 'CHANNEL="beta"' in sh and '--channel "$CHANNEL"' in sh and "__CHANNEL__" not in sh
    assert '--proto "$PROTO" --proto-redir "$PROTO"' in sh and 'PROTO="=https"' in sh and "agent sha256" in sh
    assert '$Channel = "beta"' in ps1 and "--channel $Channel" in ps1
    assert "$_.TrimEnd('\\') + '\\'" in ps1  # without the backslash, C:\Program Files Evil\python.exe would pass
    assert Path(agent.__file__).name == "nimstead_agent.py"
