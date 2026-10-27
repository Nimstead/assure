"""Agent executor against a simulated apt host (real-host runs happen only in disposable sandboxes)."""

import importlib.util
import json
import os
from pathlib import Path

spec = importlib.util.spec_from_file_location("nimstead_agent", Path(__file__).parents[2] / "agent" / "nimstead_agent.py")
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)


class FakeApt:
    def __init__(self, tmp, installed, candidate, downloadable=True, break_unit_on_upgrade=False, dpkg_i_fails=False,
                 also_upgrades=(), clean_cache_on_upgrade=False, crash_loop_on_upgrade=False):
        self.tmp, self.installed, self.candidate = tmp, dict(installed), candidate
        self.downloadable, self.break_unit, self.dpkg_i_fails = downloadable, break_unit_on_upgrade, dpkg_i_fails
        self.also, self.clean_cache = list(also_upgrades), clean_cache_on_upgrade
        self.units_ok, self.log = True, []
        self.crash_loop, self.restart_n = crash_loop_on_upgrade, 0  # systemd restarting a dying service: is-active can still say active

    def __call__(self, cmd, cwd=None):
        self.log.append(cmd)
        match cmd:
            case [_, "--version"]:
                return 0, "1.0"
            case ["dpkg-query", "-s", _]:
                return 1, "not in this fake"  # repack path covered by test_repack_*
            case ["dpkg-query", "-W", "-f=${Architecture}", _]:
                return 0, "amd64"
            case ["dpkg-query", "-W", _, name]:
                return (0, self.installed[name]) if name in self.installed else (1, "not installed")
            case ["systemctl", "is-active", *_]:
                return (0, "") if self.units_ok else (3, "inactive")
            case ["systemctl", "show", "-p", "NRestarts", "--value", _]:
                return 0, str(self.restart_n)
            case ["apt-get", "update"]:
                return 0, "ok"
            case ["apt-get", "-s", "install", "--only-upgrade", "--no-remove", *specs]:
                names = [s.split("=")[0] for s in specs] + self.also
                return 0, "\n".join(f"Inst {n} [old] (new Debian:12/stable [amd64])" for n in names) + "\nConf x"
            case ["apt-get", "download", spec_]:
                if not self.downloadable:
                    return 100, "E: Can't find a source to download version"
                name, ver = spec_.split("=")
                Path(cwd, f"{name}_{ver.replace(':', '%3a')}_amd64.deb").write_text(f"{name} {ver}")
                return 0, ""
            case ["apt-get", "install", "-y", "--only-upgrade", "--no-remove", "-o", _, *specs]:
                for s in specs:
                    n, _, pin = s.partition("=")
                    self.installed[n] = pin or self.candidate[n]
                if self.break_unit:
                    self.units_ok = False
                if self.crash_loop:
                    self.restart_n += 5
                if self.clean_cache:  # e.g. Debian docker-clean hook
                    for f in Path(self.tmp, "cache").glob("*.deb"):
                        f.unlink()
                return 0, "upgraded"
            case ["dpkg", "--audit"]:
                return 0, ""
            case ["dpkg", "-i", *files]:
                if self.dpkg_i_fails:
                    return 1, "dpkg: error processing archive"
                for f in files:
                    name, ver = Path(f).read_text().split(" ")
                    self.installed[name] = ver
                self.units_ok = True
                return 0, ""
        raise AssertionError(f"unexpected command {cmd}")


JOB = {"id": "j1", "manager": "apt", "health_units": ["nginx.service"], "settle_seconds": 0,
       "packages": [{"name": "libssl3", "from": "3.0.11-1~deb12u1"}, {"name": "openssl", "from": "3.0.11-1~deb12u1"}]}
NEW = {"libssl3": "3.0.17-1~deb12u2", "openssl": "3.0.17-1~deb12u2"}
OLD = {"libssl3": "3.0.11-1~deb12u1", "openssl": "3.0.11-1~deb12u1"}


def job_kw(tmp_path):
    return {"rollback_root": str(tmp_path / "rb"), "apt_cache": str(tmp_path / "cache")}


def run(tmp_path, host, job=JOB):
    return agent.Job(job, run=host, **job_kw(tmp_path)).execute()


def fill_cache(tmp_path):
    cache = tmp_path / "cache"
    cache.mkdir(exist_ok=True)
    for n, v in OLD.items():
        (cache / f"{n}_{v}_amd64.deb").write_text(f"{n} {v}")


def test_success_saves_rollback_first(tmp_path):
    h = FakeApt(tmp_path, OLD, NEW)
    outcome, steps, err = run(tmp_path, h)
    assert outcome == "applied" and err is None
    assert h.installed == NEW
    first_change = next(i for i, c in enumerate(h.log) if c[:3] == ["apt-get", "install", "-y"])
    last_download = max(i for i, c in enumerate(h.log) if c[:2] == ["apt-get", "download"])
    assert last_download < first_change  # rollback artefacts exist before anything changes
    assert len(os.listdir(tmp_path / "rb" / "j1")) == 2
    assert any("sha256" in s["output"] for s in steps)


def test_failed_health_check_rolls_back(tmp_path):
    h = FakeApt(tmp_path, OLD, NEW, break_unit_on_upgrade=True)
    outcome, steps, err = run(tmp_path, h)
    assert outcome == "rolled_back" and err.endswith("nginx.service active after change failed: service is inactive")
    assert h.installed == OLD and h.units_ok
    assert steps[-1]["step"] == "nginx.service active after rollback"


def test_crash_looping_service_rolls_back_even_when_sampled_active(tmp_path):
    h = FakeApt(tmp_path, OLD, NEW, crash_loop_on_upgrade=True)  # is-active says active, but systemd keeps restarting it
    outcome, steps, err = run(tmp_path, h)
    assert outcome == "rolled_back" and err.endswith("nginx.service active after change failed: service is active, restarted 5 times since the change")
    assert h.installed == OLD
    assert steps[-1]["step"] == "nginx.service active after rollback" and steps[-1]["ok"]


def test_transaction_touching_unplanned_packages_is_refused(tmp_path):
    h = FakeApt(tmp_path, OLD, NEW, also_upgrades=["libc6"])
    outcome, _, err = run(tmp_path, h)
    assert outcome == "aborted" and "would also change: libc6" in err
    assert h.installed == OLD


def test_rollback_survives_cache_cleaned_during_upgrade(tmp_path):
    fill_cache(tmp_path)
    h = FakeApt(tmp_path, OLD, NEW, downloadable=False, break_unit_on_upgrade=True, clean_cache_on_upgrade=True)
    outcome, _, _ = run(tmp_path, h)
    assert outcome == "rolled_back" and h.installed == OLD  # copies in our own dir were used


def test_tampered_rollback_artefact_is_detected(tmp_path):
    h = FakeApt(tmp_path, OLD, NEW, break_unit_on_upgrade=True)
    j = agent.Job(JOB, run=h, **job_kw(tmp_path))
    real_apply = j.apply

    def apply_then_tamper():
        real_apply()
        Path(j.artefacts[0][0]).write_text("libssl3 9.9.9-evil")

    j.apply = apply_then_tamper
    outcome, steps, err = j.execute()
    assert outcome == "rollback_failed" and err.startswith("ROLLBACK FAILED")
    assert not any(c[:2] == ["dpkg", "-i"] for c in h.log)  # never installs an unverified package


def test_pinned_version_installed(tmp_path):
    job = {**JOB, "packages": [{**p, "to": "3.0.15-1~deb12u1"} for p in JOB["packages"]]}
    h = FakeApt(tmp_path, OLD, NEW)
    assert run(tmp_path, h, job)[0] == "applied"
    assert h.installed == {"libssl3": "3.0.15-1~deb12u1", "openssl": "3.0.15-1~deb12u1"}


def test_no_rollback_package_means_no_change(tmp_path):
    h = FakeApt(tmp_path, OLD, NEW, downloadable=False)
    outcome, _, err = run(tmp_path, h)
    assert outcome == "aborted" and err.startswith("No changes made")
    assert h.installed == OLD
    assert not any(c[:3] == ["apt-get", "install", "-y"] for c in h.log)


def test_cached_deb_used_without_download(tmp_path):
    fill_cache(tmp_path)
    h = FakeApt(tmp_path, OLD, NEW, downloadable=False)
    assert run(tmp_path, h)[0] == "applied"


def test_drift_aborts(tmp_path):
    h = FakeApt(tmp_path, {**OLD, "openssl": "3.0.15-1~deb12u1"}, NEW)
    outcome, _, err = run(tmp_path, h)
    assert outcome == "aborted" and "drifted: openssl" in err


def test_unhealthy_before_change_aborts(tmp_path):
    h = FakeApt(tmp_path, OLD, NEW)
    h.units_ok = False
    assert run(tmp_path, h)[0] == "aborted"
    assert h.installed == OLD


def test_rollback_failure_is_loud(tmp_path):
    h = FakeApt(tmp_path, OLD, NEW, break_unit_on_upgrade=True, dpkg_i_fails=True)
    outcome, _, err = run(tmp_path, h)
    assert outcome == "rollback_failed" and err.startswith("ROLLBACK FAILED")


def test_hostile_job_rejected_before_any_command(tmp_path):
    for bad in ({**JOB, "packages": [{"name": "x; rm -rf /", "from": "1"}]},
                {**JOB, "packages": [{"name": "openssl", "from": "$(id)"}]},
                {**JOB, "packages": [{"name": "openssl", "from": "1", "to": "-o APT::x"}]},
                {**JOB, "manager": "bash"},
                {**JOB, "manager": "yum"},
                {**JOB, "health_units": ["--now"]},
                {**JOB, "packages": []}):
        h = FakeApt(tmp_path, OLD, NEW)
        outcome, _, _ = run(tmp_path, h, bad)
        assert outcome == "aborted" and h.log == []


def test_outcomes_persist_and_retry_when_report_fails(tmp_path, monkeypatch):
    calls, fail = [], {"on": True}

    def fake_post(server, path, body, insecure, key=None):
        calls.append(path)
        if path == "/api/agent/jobs":
            return [JOB] if len([c for c in calls if c == path]) == 1 else []
        if fail["on"]:
            raise agent.AgentError("request to x failed: timed out")
        return {}

    monkeypatch.setattr(agent, "post", fake_post)
    h = FakeApt(tmp_path, OLD, NEW)
    out = tmp_path / "outcomes"
    assert agent.run_jobs("https://x", "k", False, run=h, outcome_dir=str(out), **job_kw(tmp_path)) == (1, False)
    saved = json.loads((out / "j1.json").read_text())
    assert saved["report"]["outcome"] == "applied" and saved["report"]["versions"] == NEW

    fail["on"] = False  # next run: the unsent outcome is delivered, nothing re-executed
    assert agent.run_jobs("https://x", "k", False, run=h, outcome_dir=str(out), **job_kw(tmp_path)) == (0, False)
    assert not list(out.glob("*.json")) and calls.count("/api/agent/jobs/j1/report") == 2


def test_remediate_requires_local_opt_in(tmp_path, monkeypatch, capsys):
    cfg = tmp_path / "agent.json"
    cfg.write_text('{"server": "https://x", "agent_key": "k"}')
    monkeypatch.setattr(agent, "config_path", lambda: str(cfg))
    assert agent.main(["remediate"]) == 1
    assert "not enabled" in capsys.readouterr().err


def test_redirects_are_not_followed():
    assert agent._NoRedirect().redirect_request(None, None, 302, "Found", {}, "http://evil") is None
