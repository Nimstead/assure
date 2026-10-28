"""Signed agent self-update (DECISIONS 31): release signing, the agent's update step, and what the server relays and shows."""

import base64
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi.testclient import TestClient
from test_agent_remediate import agent
from test_api import INV, enrol, user

ROOT = Path(__file__).parents[2]
spec = importlib.util.spec_from_file_location("sign_release", ROOT / "scripts" / "sign_release.py")
sign_release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sign_release)

COMMIT = "a" * 40


def pub(k):
    return k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def pin(k):
    """The shipped agent with only k pinned, as a test release key."""
    return re.sub(rb"^RELEASE_KEYS = .*$", f'RELEASE_KEYS = ["{pub(k)}"]'.encode(), (ROOT / "agent" / "nimstead_agent.py").read_bytes(), count=1, flags=re.M)


def signed(k, agent_bytes, agent_version=None, version="0.3.0"):
    if agent_version:
        agent_bytes = agent_bytes.replace(f'AGENT_VERSION = "{agent.AGENT_VERSION}"'.encode(), f'AGENT_VERSION = "{agent_version}"'.encode())
    manifest = sign_release.release_manifest(f"v{version}", COMMIT, agent_bytes, version)
    return agent_bytes, manifest, base64.b64encode(k.sign(manifest)).decode()


# --- release signing ----------------------------------------------------------------------------------------------

def test_manifest_binds_version_agent_hash_and_commit():
    body = (ROOT / "agent" / "nimstead_agent.py").read_bytes()
    rel = json.loads(sign_release.release_manifest("v0.3.0", COMMIT, body, "0.3.0"))
    assert rel == {"version": "0.3.0", "agent_version": agent.AGENT_VERSION, "agent_sha256": hashlib.sha256(body).hexdigest(), "commit": COMMIT,
                   "channel": "preview"}  # a tag push is preview until promoted
    assert json.loads(sign_release.release_manifest("v0.3.0", COMMIT, body, "0.3.0", "stable"))["channel"] == "stable"
    with pytest.raises(SystemExit, match="channel"):
        sign_release.release_manifest("v0.3.0", COMMIT, body, "0.3.0", "nightly")
    for tag, commit, version in [("v0.3.1", COMMIT, "0.3.0"), ("0.3.0", COMMIT, "0.3.0"), ("v0.3.0", "abc", "0.3.0")]:
        with pytest.raises(SystemExit):
            sign_release.release_manifest(tag, commit, body, version)


def test_keygen_refuses_the_repository_and_writes_a_usable_key(tmp_path, capsys):
    with pytest.raises(SystemExit):
        sign_release.main(["keygen", str(ROOT / "keys")])
    sign_release.main(["keygen", str(tmp_path)])
    out = capsys.readouterr().out
    public = out.rsplit(": ", 1)[1].strip()
    key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(next(tmp_path.glob("release-*.key")).read_text()))
    assert pub(key) == public


def test_sign_refuses_a_key_the_agent_does_not_pin(tmp_path, monkeypatch):
    k = Ed25519PrivateKey.generate()
    monkeypatch.setenv("NIMSTEAD_RELEASE_KEY", base64.b64encode(k.private_bytes_raw()).decode())
    version = sign_release.tomllib.loads((ROOT / "api" / "pyproject.toml").read_text())["project"]["version"]
    with pytest.raises(SystemExit, match="pinned"):
        sign_release.main(["sign", "--tag", f"v{version}", "--commit", COMMIT, "--out", str(tmp_path)])


def test_agent_verifies_what_ci_signs_and_nothing_else(tmp_path):
    k, other = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    _, manifest, sig = signed(k, b'AGENT_VERSION = "0.9.0"\n')
    assert agent.verify_release(manifest, sig, [pub(other), pub(k)])["agent_version"] == "0.9.0"  # backup key order doesn't matter
    for m, sg, keys in [(manifest, sig, [pub(other)]), (manifest + b" ", sig, [pub(k)]), (manifest, "not base64!", [pub(k)]), (manifest, sig, [])]:
        with pytest.raises(agent.AgentError):
            agent.verify_release(m, sg, keys)
    (tmp_path / "r.json").write_bytes(manifest)
    (tmp_path / "r.sig").write_text(sig)
    assert agent.main(["verify-release", str(tmp_path / "r.json"), str(tmp_path / "r.sig")]) == 1  # shipped agent pins no test key


# --- the agent's update step --------------------------------------------------------------------------------------

class FakeServer:
    def __init__(self, k, agent_bytes, manifest, sig, paused=False):
        self.body, self.manifest = agent_bytes, {"paused": paused, "release": manifest.decode(), "sig": sig}
        self.k = k

    def __call__(self, server, path, body, insecure_http, key=None, raw=False):
        if path == "/api/agent/manifest":
            return self.manifest
        assert path == "/agent/nimstead_agent.py" and raw and key is None  # the agent key is never sent for the download
        return self.body


@pytest.fixture
def host(tmp_path, monkeypatch):
    """An installed agent file plus a signing key the agent under test pins."""
    path = tmp_path / "nimstead_agent.py"
    path.write_bytes((ROOT / "agent" / "nimstead_agent.py").read_bytes())
    k = Ed25519PrivateKey.generate()
    return path, k


CFG = {"server": "https://nimstead.example", "agent_key": "nma_x"}


def run_update(monkeypatch, path, k, server, smoke=lambda p: None, cfg=CFG):
    monkeypatch.setattr(agent, "post", server)
    return agent.self_update(cfg, False, path=str(path), keys=[pub(k)], smoke=smoke, memo=str(path) + ".failed.json")


def test_newer_signed_release_replaces_the_agent_and_keeps_the_old_one(host, monkeypatch):
    path, k = host
    old = path.read_bytes()
    new, manifest, sig = signed(k, old, "9.0.0")
    assert run_update(monkeypatch, path, k, FakeServer(k, new, manifest, sig)) == ("9.0.0", None)
    assert path.read_bytes() == new and Path(str(path) + ".prev").read_bytes() == old
    assert not Path(str(path) + ".new").exists()


@pytest.mark.parametrize("version", [agent.AGENT_VERSION, "0.1.3", "0.0.9"])
def test_same_or_older_signed_release_is_ignored(host, monkeypatch, version):
    path, k = host
    old = path.read_bytes()
    body, manifest, sig = signed(k, old, version)
    assert run_update(monkeypatch, path, k, FakeServer(k, body, manifest, sig)) == (None, None)  # anti-rollback
    assert path.read_bytes() == old


def test_forged_tampered_or_broken_releases_leave_the_agent_untouched(host, monkeypatch):
    path, k = host
    old = path.read_bytes()
    new, manifest, sig = signed(k, old, "9.0.0")
    forger = Ed25519PrivateKey.generate()  # e.g. a compromised server signing its own agent
    _, _, forged_sig = signed(forger, old, "9.0.0")
    cases = [
        (FakeServer(k, new, manifest, forged_sig), lambda p: None, "pinned release key"),
        (FakeServer(k, new + b"# backdoor\n", manifest, sig), lambda p: None, "doesn't match the signed release"),
        (FakeServer(k, new, manifest, sig), lambda p: "SyntaxError", "failed its self-test"),
    ]
    for server, smoke, why in cases:
        version, error = run_update(monkeypatch, path, k, server, smoke)
        assert version is None and why in error
        assert path.read_bytes() == old and not Path(str(path) + ".new").exists()


def test_paused_opted_out_or_no_release_does_nothing(host, monkeypatch):
    path, k = host
    new, manifest, sig = signed(k, path.read_bytes(), "9.0.0")
    assert run_update(monkeypatch, path, k, FakeServer(k, new, manifest, sig, paused=True)) == (None, None)
    assert run_update(monkeypatch, path, k, FakeServer(k, new, manifest, sig), cfg={**CFG, "auto_update": False}) == (None, None)
    unsigned = FakeServer(k, new, manifest, sig)
    unsigned.manifest = {"paused": False}  # dev server: no signed release
    assert run_update(monkeypatch, path, k, unsigned) == (None, None)


def test_server_errors_are_reported_not_raised(host, monkeypatch):
    path, k = host

    def down(*a, **kw):
        raise agent.AgentError("request to https://nimstead.example failed: timed out")
    version, error = run_update(monkeypatch, path, k, down)
    assert version is None and "timed out" in error


def test_real_smoke_test_runs_the_new_file(tmp_path):
    bad = tmp_path / "bad.py"
    bad.write_text("this is not python\n")
    assert agent._smoke_test(str(bad))
    empty = tmp_path / "empty.py"
    empty.write_text('import json\nprint(json.dumps({"packages": []}))\n')
    assert agent._smoke_test(str(empty)) == "collect returned no packages"
    good = tmp_path / "good.py"
    good.write_text('import json\nprint(json.dumps({"packages": [{"name": "x"}]}))\n')
    assert agent._smoke_test(str(good)) is None


def test_updated_agent_reruns_the_command_with_the_new_file(monkeypatch, tmp_path):
    cfg = tmp_path / "agent.json"
    cfg.write_text(json.dumps(CFG))
    monkeypatch.setattr(agent, "config_path", lambda: str(cfg))
    monkeypatch.setattr(agent, "run_lock", type("L", (), {"__enter__": lambda s: s, "__exit__": lambda s, *a: None}))
    monkeypatch.setattr(agent, "self_update", lambda c, i: ("9.0.0", None))
    calls = []
    monkeypatch.setattr(agent.subprocess, "call", lambda argv: calls.append(argv) or 0)
    assert agent.main(["report"]) == 0
    assert calls == [[sys.executable, *(["-I"] if sys.flags.isolated else []), str(Path(agent.__file__).resolve()), "--no-self-update", "report"]]


def test_inventory_says_whether_this_agent_can_update(monkeypatch):
    monkeypatch.setattr(agent, "collect", lambda: {"packages": []})
    monkeypatch.setattr(agent, "RELEASE_KEYS", [])
    assert agent.inventory({})["auto_update"] is None  # can't: no pinned keys, so the server asks for a reinstall
    monkeypatch.setattr(agent, "RELEASE_KEYS", ["00" * 32])
    assert agent.inventory({})["auto_update"] is True and agent.inventory({"auto_update": False})["auto_update"] is False


# --- what the server relays and shows -----------------------------------------------------------------------------

@pytest.fixture
def release(tmp_path, monkeypatch):
    """A server shipping an agent that pins k, with a signed release for it in RELEASE_DIR."""
    import nimstead.app as appmod
    k = Ed25519PrivateKey.generate()
    body = pin(k)
    agent_file = tmp_path / "served_agent.py"
    agent_file.write_bytes(body)
    rel_dir = tmp_path / "release"
    rel_dir.mkdir()
    _, manifest, sig = signed(k, body)
    (rel_dir / "release.json").write_bytes(manifest)
    (rel_dir / "release.json.sig").write_text(sig + "\n")
    monkeypatch.setattr(appmod, "AGENT_FILE", agent_file)
    monkeypatch.setattr(appmod, "RELEASE_DIR", rel_dir)
    appmod.latest_agent_version.cache_clear()
    yield rel_dir, manifest, sig
    appmod.latest_agent_version.cache_clear()


def test_manifest_relays_the_signed_release_and_the_org_pause(env, release):
    rel_dir, manifest, sig = release
    c = user(env)
    h = {"Authorization": f"Bearer {enrol(c)['agent_key']}"}
    assert TestClient(c.app).get("/api/agent/manifest").status_code == 401
    m = c.get("/api/agent/manifest", headers=h).json()
    assert m == {"paused": False, "release": manifest.decode(), "sig": sig}
    assert c.patch("/api/settings", json={"agent_updates_paused": True}).json()["agent_updates_paused"]
    assert c.get("/api/agent/manifest", headers=h).json()["paused"] is True
    entries = c.get("/api/evidence/ledger").json()["entries"]
    assert any(e["kind"] == "policy_changed" and "agent_updates_paused" in json.dumps(e) for e in entries)


def test_manifest_withheld_unless_signed_by_a_pinned_key_for_the_served_agent(env, release, tmp_path):
    import nimstead.app as appmod
    rel_dir, manifest, sig = release
    c = user(env)
    h = {"Authorization": f"Bearer {enrol(c)['agent_key']}"}
    (rel_dir / "release.json.sig").write_text(signed(Ed25519PrivateKey.generate(), b'AGENT_VERSION = "0.1.0"\n')[2])
    assert c.get("/api/agent/manifest", headers=h).json() == {"paused": False}
    (rel_dir / "release.json.sig").write_text(sig)
    appmod.AGENT_FILE.write_bytes(appmod.AGENT_FILE.read_bytes() + b"\n# changed after signing\n")
    assert c.get("/api/agent/manifest", headers=h).json() == {"paused": False}
    assert c.get("/api/settings").json()["signed_agent_release"] is False


def test_assets_say_what_happens_to_each_agent(env, release):
    import nimstead.app as appmod
    latest = appmod.latest_agent_version()
    c = user(env)
    h = {"Authorization": f"Bearer {enrol(c)['agent_key']}"}
    status = lambda: c.get("/api/assets").json()[0]["agent_update"]  # noqa: E731
    report = lambda **kw: c.post("/api/agent/inventory", json={**INV, **kw}, headers=h)  # noqa: E731
    report()
    assert status() == "reinstall"  # agent too old to update itself
    report(agent_version="0.1.9", auto_update=True)
    assert status() == "updating"
    report(agent_version="0.1.9", auto_update=True, update_error="self-update failed: new agent failed its self-test")
    assert status() == "failed" and "self-test" in c.get("/api/assets").json()[0]["agent_update_error"]
    report(agent_version="0.1.9", auto_update=False)
    assert status() == "off"
    c.patch("/api/settings", json={"agent_updates_paused": True})
    report(agent_version="0.1.9", auto_update=True)
    assert status() == "paused"
    report(agent_version=latest, auto_update=True)
    assert status() == "current" and c.get("/api/assets").json()[0]["agent_update_error"] is None
    (release[0] / "release.json").unlink()
    report(agent_version="0.1.9", auto_update=True)
    assert status() == "reinstall"  # server has no signed release to hand out


# --- hosts that stop reporting ----------------------------------------------------------------------------------------

def test_silent_host_flagged_and_alerted_once_per_outage(env, monkeypatch, tmp_path):
    from datetime import timedelta

    from sqlalchemy.orm import sessionmaker

    from nimstead import notify
    from nimstead.db import Asset, make_engine, now
    c = user(env)
    h = {"Authorization": f"Bearer {enrol(c)['agent_key']}"}
    c.post("/api/agent/inventory", json=INV, headers=h)
    sent = []
    monkeypatch.setattr(notify, "notify", lambda s, org_id, kind, text, urgent=False: sent.append((kind, text)))
    s = sessionmaker(make_engine(env))()
    state = tmp_path / "monitor.json"
    assert notify.alert_silent_hosts(s, state) == 0 and not c.get("/api/assets").json()[0]["not_reporting"]
    s.query(Asset).update({Asset.last_seen: now() - timedelta(hours=15)})
    s.commit()
    assert notify.alert_silent_hosts(s, state) == 1 and notify.alert_silent_hosts(s, state) == 0  # once, not every hour
    assert sent[0][0] == "host_not_reporting" and "1 machine stopped reporting: web-1 (15 h)" in sent[0][1]
    assert c.get("/api/assets").json()[0]["not_reporting"] and c.get("/api/summary").json()["hosts_not_reporting"] == 1
    c.post("/api/agent/inventory", json=INV, headers=h)  # back: flag and marker cleared
    assert not c.get("/api/assets").json()[0]["not_reporting"] and c.get("/api/summary").json()["hosts_not_reporting"] == 0
    s.query(Asset).update({Asset.last_seen: now() - timedelta(hours=15)})
    s.commit()
    assert notify.alert_silent_hosts(s, state) == 1  # a new outage alerts again
    s.close()


def test_summary_counts_agents_that_cannot_update(env, release):
    c = user(env)
    h = {"Authorization": f"Bearer {enrol(c)['agent_key']}"}
    c.post("/api/agent/inventory", json=INV, headers=h)  # agent too old to say: reinstall
    assert c.get("/api/summary").json()["agents_need_attention"] == 1
    c.post("/api/agent/inventory", json={**INV, "agent_version": "0.1.9", "auto_update": True}, headers=h)
    assert c.get("/api/summary").json()["agents_need_attention"] == 0  # will update itself


def test_real_update_over_http_with_the_real_self_test(tmp_path):
    """No fakes inside the agent: a local HTTP server, the agent's own HTTP client, a real `collect` of this machine by
    the new file (read-only), and the real file swap, all in a temp folder."""
    import http.server
    import threading
    k = Ed25519PrivateKey.generate()
    installed = pin(k)
    path = tmp_path / "nimstead_agent.py"
    path.write_bytes(installed)
    new, manifest, sig = signed(k, installed, "9.0.0")
    routes = {"/api/agent/manifest": json.dumps({"paused": False, "release": manifest.decode(), "sig": sig}).encode(),
              "/agent/nimstead_agent.py": new}

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = routes.get(self.path)
            self.send_response(200 if body else 404)
            self.end_headers()
            self.wfile.write(body or b"")

        def log_message(self, *a):
            pass
    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        cfg = {"server": f"http://127.0.0.1:{srv.server_port}", "agent_key": "nma_x"}
        assert agent.self_update(cfg, True, path=str(path), keys=[pub(k)], memo=str(tmp_path / "failed.json")) == ("9.0.0", None)
        assert path.read_bytes() == new and Path(str(path) + ".prev").read_bytes() == installed
        new2 = new.replace(b'AGENT_VERSION = "9.0.0"', b'AGENT_VERSION = "9.1.0"').replace(
            b"def collect():", b"def collect():\n    raise SystemExit(3)\n\n\ndef _unused():")
        manifest2 = sign_release.release_manifest("v0.3.0", COMMIT, new2, "0.3.0")  # validly signed, but broken on this host
        sig2 = base64.b64encode(k.sign(manifest2)).decode()
        routes["/api/agent/manifest"] = json.dumps({"paused": False, "release": manifest2.decode(), "sig": sig2}).encode()
        routes["/agent/nimstead_agent.py"] = new2
        monkey_version = agent.AGENT_VERSION
        agent.AGENT_VERSION = "9.0.0"
        try:
            version, error = agent.self_update(cfg, True, path=str(path), keys=[pub(k)], memo=str(tmp_path / "failed.json"))
        finally:
            agent.AGENT_VERSION = monkey_version
        assert version is None and "failed its self-test" in error and path.read_bytes() == new  # kept the working one
    finally:
        srv.shutdown()


def test_failed_release_is_not_retried_for_a_day_and_bad_manifests_never_crash(host, monkeypatch):
    path, k = host
    new, manifest, sig = signed(k, path.read_bytes(), "9.0.0")
    tries = []
    assert "failed its self-test" in run_update(monkeypatch, path, k, FakeServer(k, new, manifest, sig), lambda p: tries.append(p) or "boom")[1]
    version, error = run_update(monkeypatch, path, k, FakeServer(k, new, manifest, sig), lambda p: tries.append(p) or "boom")
    assert version is None and "last 24 hours" in error and len(tries) == 1  # no second download + self-test
    for bad in (["not", "an", "object"], "text", None):
        version, error = run_update(monkeypatch, path, k, lambda *a, bad=bad, **kw: bad)
        assert version is None and "not a JSON object" in error


def test_enrol_keeps_local_choices_whatever_the_server_answers(monkeypatch, tmp_path):
    saved = {}
    monkeypatch.setattr(agent, "collect", lambda: {"os_name": "x", "ecosystem": "Debian:13", "packages": []})
    monkeypatch.setattr(agent, "post", lambda *a, **kw: {"asset_id": "a1", "agent_key": "nma_k", "allow_remediation": True,
                                                         "auto_update": True, "server": "http://evil.example", "schedule_version": 99})
    monkeypatch.setattr(agent, "save_config", lambda cfg: saved.update(cfg) or "cfg")
    assert agent.main(["enroll", "--server", "https://nimstead.example", "--token", "t", "--no-auto-update"]) == 0
    assert saved == {"asset_id": "a1", "agent_key": "nma_k", "server": "https://nimstead.example", "allow_remediation": False, "auto_update": False}


def test_no_not_reporting_storm_after_the_server_itself_was_down(env, monkeypatch, tmp_path):
    import json as _json
    from datetime import timedelta

    from sqlalchemy.orm import sessionmaker

    from nimstead import notify
    from nimstead.db import Asset, make_engine, now
    c = user(env)
    enrol(c)
    sent = []
    monkeypatch.setattr(notify, "notify", lambda s, org_id, kind, text, urgent=False: sent.append(kind))
    s = sessionmaker(make_engine(env))()
    s.query(Asset).update({Asset.last_seen: now() - timedelta(hours=20)})
    s.commit()
    state = tmp_path / "monitor.json"
    state.write_text(_json.dumps({"last_check": (now() - timedelta(hours=20)).isoformat(), "grace_until": None}))  # server down 20 h
    assert notify.alert_silent_hosts(s, state) == 0 and sent == []  # hosts get a report cycle to catch up
    assert notify.alert_silent_hosts(s, state) == 0  # hourly runs inside the grace stay quiet
    st = _json.loads(state.read_text())
    state.write_text(_json.dumps({**st, "grace_until": (now() - timedelta(minutes=1)).isoformat()}))  # grace over
    assert notify.alert_silent_hosts(s, state) == 1 and sent == ["host_not_reporting"]  # still silent: now it alerts
    s.close()
