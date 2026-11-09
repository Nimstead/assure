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


def test_auth_token_also_enables_ai_and_disable_switch_wins(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "test-token")
    monkeypatch.delenv("NIMSTEAD_AI", raising=False)
    assert ai.enabled()
    monkeypatch.setenv("NIMSTEAD_AI", "0")
    assert not ai.enabled()


def test_search_local_defaults_extra_keys_and_input_limit(fake):
    fc = fake('{"q": "openssl", "ignored": "not retained"}')
    assert ai.parse_search("x" * 600).model_dump() == {
        "q": "openssl", "priority": [], "status": "open", "fixable": None, "kev": None}
    assert fc.calls[0]["messages"][0]["content"] == "x" * 500


def test_explanation_selects_fields_without_redacting_values(fake):
    fc = fake("Provider answer")
    finding = {"vuln_id": "CVE-2099-99999", "package": "package-with-host-context",
               "installed_version": "1", "fixed_version": None, "kev": False,
               "epss": None, "cvss": None, "priority": "low",
               "reasons": ["context-host-name"], "hostname": "excluded-host-name", "summary": "a" * 1600}
    assert ai.explain(finding) == "Provider answer"
    request = fc.calls[0]["messages"][0]["content"]
    assert "excluded-host-name" not in request and "context-host-name" in request
    assert "a" * 1500 in request and "a" * 1501 not in request
    assert "no fix available yet" in request
