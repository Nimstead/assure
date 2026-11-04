"""The Windows agent keeps its bundled Python current from signed releases (plan T26), with fakes for the server,
PowerShell's signature check and the scheduler. Real proof: sandbox/winupdate.py."""

import hashlib
import io
import zipfile

import pytest
from test_agent_remediate import agent


def runtime_zip(files=None):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        for n, data in (files or {"python.exe": b"MZ", "python315.zip": b"PK"}).items():
            z.writestr(n, data)
    return b.getvalue()


@pytest.fixture
def host(tmp_path, monkeypatch):
    body = runtime_zip()
    state = {"body": body, "signed": "0", "smoke": None, "scheduled": [], "fetched": 0}
    root = tmp_path / "runtime"
    old = root / "aaaaaaaaaaaa"
    old.mkdir(parents=True)
    (old / "python.exe").write_bytes(b"MZ")

    def post(server, path, body_, insecure, key=None, raw=False, limit=None):
        assert path == "/agent/runtime/amd64.zip" and raw and limit == agent.MAX_RUNTIME_BYTES
        state["fetched"] += 1
        return state["body"]
    monkeypatch.setattr(agent, "post", post)
    monkeypatch.setattr(agent, "schedule", lambda cfg, run=None: state["scheduled"].append(cfg["python"]))
    monkeypatch.setattr(agent, "WIN_STATE", str(tmp_path / "pending-job.json"))
    monkeypatch.setattr(agent.platform, "python_version", lambda: "3.15.1")
    rel = {"runtimes": {"amd64": {"version": "3.15.2", "sha256": hashlib.sha256(body).hexdigest()}}}

    def go(exe=None, rel_=None):
        return agent.runtime_update({"server": "https://s"}, rel_ or rel, False, run=lambda cmd: (0, state["signed"]),
                                    root=str(root), executable=exe or str(old / "python.exe"),
                                    smoke=lambda path, py: state["smoke"], machine="AMD64")
    return go, state, root, old, rel


def test_switches_to_the_signed_runtime_and_reschedules(host):
    go, state, root, old, rel = host
    assert go() is None
    new = root / rel["runtimes"]["amd64"]["sha256"][:12]
    assert (new / "python.exe").exists() and state["scheduled"] == [str(new / "python.exe")]
    assert old.exists()  # the running runtime is never removed during the run
    assert go(exe=str(new / "python.exe")) is None and not old.exists()  # next run, from the new one: old folder gone
    assert state["fetched"] == 1


@pytest.mark.parametrize("breakage,why", [
    (lambda s: s.update(body=b"tampered"), "doesn't match the signed release"),
    (lambda s: s.update(signed="2"), "isn't signed by the Python Software Foundation"),
    (lambda s: s.update(smoke="collect returned no packages"), "agent failed on runtime 3.15.2"),
    (lambda s: s.update(body=runtime_zip({"../evil.exe": b"x"})), "doesn't match"),
])
def test_any_failure_keeps_the_runtime_and_tasks_as_they_were(host, breakage, why):
    go, state, root, old, rel = host
    breakage(state)
    problem = go()
    assert problem and why in problem
    assert not state["scheduled"] and [p.name for p in root.iterdir()] == [old.name]


def test_unsafe_archive_paths_are_refused(host):
    go, state, root, old, _ = host
    state["body"] = runtime_zip({r"..\..\evil.exe": b"x", "python.exe": b"MZ"})
    rel = {"runtimes": {"amd64": {"version": "3.15.2", "sha256": hashlib.sha256(state["body"]).hexdigest()}}}
    assert "unsafe paths" in go(rel_=rel) and [p.name for p in root.iterdir()] == [old.name]


def test_never_to_an_older_python_but_a_system_python_moves_to_the_bundled_one(host, tmp_path):
    go, state, root, old, rel = host
    older = {"runtimes": {"amd64": {**rel["runtimes"]["amd64"], "version": "3.14.9"}}}
    assert "older than the Python 3.15.1" in go(rel_=older) and state["fetched"] == 0
    system = tmp_path / "Python315" / "python.exe"  # installed before the bundled runtime existed
    assert go(exe=str(system), rel_=older) is None and state["scheduled"]


def test_nothing_while_a_windows_job_waits_for_its_restart(host, tmp_path):
    go, state, *_ = host
    (tmp_path / "pending-job.json").write_text("{}")
    assert go() is None and state["fetched"] == 0


def test_a_replayed_older_release_never_changes_the_runtime(monkeypatch):
    """Security review: runtime_update ran before the agent anti-rollback check."""
    calls = []
    monkeypatch.setattr(agent, "runtime_update", lambda *a, **k: calls.append(1))
    old = {"agent_version": "0.0.1", "agent_sha256": "a" * 64, "version": "0.0.1", "commit": "f" * 40, "channel": "stable",
           "runtimes": {"amd64": {"version": "3.14.0", "sha256": "b" * 64}}}
    monkeypatch.setattr(agent, "post", lambda *a, **k: {"release": "x", "sig": "y"})
    monkeypatch.setattr(agent, "verify_release", lambda m, s, keys=None: old)
    assert agent.self_update({"server": "https://s", "agent_key": "k", "channel": "stable"}, False) == (None, None)
    assert not calls
