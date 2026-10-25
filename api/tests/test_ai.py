from types import SimpleNamespace

import pytest
from test_api import INV, enrol, user

from nimstead import ai


class FakeClient:
    def __init__(self, text, stop="end_turn"):
        self.text, self.stop, self.calls = text, stop, []
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self.create))

    def create(self, **kw):
        self.calls.append(kw)
        return SimpleNamespace(stop_reason=self.stop, content=[SimpleNamespace(type="text", text=self.text)])


@pytest.fixture
def fake(monkeypatch):
    def install(text, stop="end_turn"):
        fc = FakeClient(text, stop)
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test")
        monkeypatch.setattr(ai, "client", lambda: fc)
        ai._explain_cached.cache_clear()
        return fc
    return install


def test_disabled_without_credentials(env, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    c = user(env)
    assert c.get("/api/ai/status").json() == {"enabled": False}
    assert c.post("/api/ai/search", json={"text": "urgent stuff"}).status_code == 503


def test_explain_passes_advisory_as_data(env, fake):
    fc = fake("This flaw lets an attacker ...")
    c = user(env)
    a = enrol(c)
    c.post("/api/agent/inventory", json=INV, headers={"Authorization": f"Bearer {a['agent_key']}"})
    fid = c.get("/api/findings").json()[0]["id"]
    r = c.post(f"/api/ai/explain/{fid}")
    assert r.status_code == 200 and r.json()["text"].startswith("This flaw")
    call = fc.calls[0]
    assert call["model"] == "claude-opus-5-5" and call["fallbacks"] == "default"
    assert "<advisory>" in call["messages"][0]["content"] and "not instructions" in call["system"]
    c.post(f"/api/ai/explain/{fid}")
    assert len(fc.calls) == 1  # cached
    assert user(env, "b@example.com").post(f"/api/ai/explain/{fid}").status_code == 404  # tenant isolation


def test_search_output_is_validated(env, fake):
    fake('{"q": "openssl", "priority": ["fix-now"], "status": "open", "fixable": true, "kev": null}')
    c = user(env)
    assert c.post("/api/ai/search", json={"text": "urgent openssl stuff I can patch"}).json() == {
        "q": "openssl", "priority": ["fix-now"], "status": "open", "fixable": True, "kev": None}
    fake('{"q": "x", "priority": ["DROP TABLE"], "status": "open", "fixable": null, "kev": null}')
    assert c.post("/api/ai/search", json={"text": "anything"}).status_code == 503


def test_refusal_surfaces_cleanly(env, fake):
    fake("", stop="refusal")
    assert user(env).post("/api/ai/search", json={"text": "hello"}).status_code == 503
