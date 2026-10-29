"""Agent proxy support (plan T44): --proxy at enrol, else the WinHTTP proxy; TLS stays end to end."""

import pytest
from test_agent_remediate import agent


@pytest.fixture(autouse=True)
def reset(monkeypatch):
    monkeypatch.setattr(agent, "_proxy", None)
    monkeypatch.setattr(agent, "_opener", agent._opener)


@pytest.mark.parametrize("out,want", [
    ("Current WinHTTP proxy settings:\r\n\r\n    Direct access (no proxy server).\r\n", None),
    ("Current WinHTTP proxy settings:\r\n\r\n    Proxy Server(s) :  proxy.corp:8080\r\n    Bypass List     :  (none)\r\n", "http://proxy.corp:8080"),
    ("    Proxy Server(s) :  http=p1:80;https=p2:8443\r\n", "http://p2:8443"),
    ("    Proxy Server(s) :  http=p1:80\r\n", None),
])
def test_winhttp_proxy(out, want):
    assert agent.winhttp_proxy(lambda cmd: (0, out)) == want


def test_explicit_proxy_wins_and_is_validated(monkeypatch):
    monkeypatch.setattr(agent.os, "name", "posix")
    assert agent.use_proxy(None) is None and agent._proxy is None
    assert agent.use_proxy("http://proxy.corp:3128") == "http://proxy.corp:3128"
    handlers = [type(h).__name__ for h in agent._opener.handlers]
    assert "ProxyHandler" in handlers and "_NoRedirect" in handlers
    with pytest.raises(agent.AgentError, match="proxy must be"):
        agent.use_proxy("http://proxy.corp:3128/$(calc)")


def test_plain_http_server_refused_through_a_proxy(monkeypatch):
    monkeypatch.setattr(agent.os, "name", "posix")
    agent.use_proxy("http://proxy.corp:3128")
    with pytest.raises(agent.AgentError, match="plain-http server through a proxy"):
        agent.post("http://10.0.2.2:8000", "/api/agent/manifest", None, True, "key")
