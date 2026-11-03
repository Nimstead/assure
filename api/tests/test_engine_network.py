"""The engine's network-service slice: a remote prober producing verdicts with evidence, grades, negative controls, a
catch-all suppression, budgets and safe mode (spec sections 10, 14; T22, T23, T25, T26, T8). Scope is proven before any
packet (tested in test_external.py, which gates external.scan through the same external.prove_scope)."""

import re
import socketserver
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from nimstead import external
from nimstead.engine import network as net
from nimstead.engine.model import Grade, Outcome
from nimstead.engine.network import Budget, Endpoint, Prober


def endpoints(overrides=None) -> dict[int, Endpoint]:
    base = {p: Endpoint(p, "closed") for p in sorted(set(external.SERVICES) | {external.TLS_PORT, 80, *net.BANNER_PORTS})}
    base.update(overrides or {})
    return base


def by_id(verdicts):
    return {v.vuln_id or v.check: v for v in verdicts}


def test_exposed_port_states_are_verdicts_never_silence():
    eps = endpoints({6379: Endpoint(6379, "open"), 445: Endpoint(445, "closed"), 21: Endpoint(21, "filtered")})
    v = by_id(net._exposed(eps))
    assert v["NIM-EXPOSED-REDIS"].outcome == Outcome.VULNERABLE and v["NIM-EXPOSED-REDIS"].grade == Grade.REASONABLE
    assert v["NIM-EXPOSED-SMB"].outcome == Outcome.NOT_VULNERABLE  # refused = positive evidence nothing listens
    assert v["NIM-EXPOSED-FTP"].outcome == Outcome.NOT_RUN and v["NIM-EXPOSED-FTP"].reason == "port-filtered"  # a drop is never clean
    assert all(x.grade != Grade.CONFIRMED for x in net._exposed(eps))  # no remote check is ever confirmed


def test_exposed_matches_external_scan_finding_ids():
    """The vulnerable verdict reuses external.scan's own finding, so the two can't drift (parity by construction)."""
    v = by_id(net._exposed(endpoints({6379: Endpoint(6379, "open")})))["NIM-EXPOSED-REDIS"]
    f = external.exposed_finding(6379)
    assert v.product == f["package"] and v.cvss == f["cvss"] and f["summary"] in v.summary


def test_tls_verdicts_cover_expired_healthy_closed_and_filtered():
    now = time.time()
    expired = {"trusted": False, "error": "certificate has expired", "not_after": now - 86400 * 3, "legacy": False}
    v = by_id(net._tls(endpoints({443: Endpoint(443, "open", tls=expired)}), "www.example.com"))
    assert v["NIM-TLS-EXPIRED"].outcome == Outcome.VULNERABLE and v["NIM-TLS-EXPIRED"].grade == Grade.REASONABLE

    healthy = {"trusted": True, "error": None, "not_after": now + 86400 * 90, "legacy": False}
    assert net._tls(endpoints({443: Endpoint(443, "open", tls=healthy)}), "h")[0].outcome == Outcome.NOT_VULNERABLE
    assert net._tls(endpoints({443: Endpoint(443, "closed")}), "h")[0].outcome == Outcome.NOT_APPLICABLE  # no HTTPS at all
    f = net._tls(endpoints({443: Endpoint(443, "filtered")}), "h")[0]
    assert f.outcome == Outcome.NOT_RUN and f.reason == "port-filtered"


def test_version_rule_vsftpd_backdoor():
    vuln = net._versions(endpoints({21: Endpoint(21, "open", banner=b"220 (vsFTPd 2.3.4)\r\n")}))
    assert by_id(vuln)["CVE-2011-2523"].outcome == Outcome.VULNERABLE
    assert by_id(vuln)["CVE-2011-2523"].grade == Grade.UNVERIFIED  # a banner is weak, never confirmed
    fixed = net._versions(endpoints({21: Endpoint(21, "open", banner=b"220 (vsFTPd 2.3.5)\r\n")}))
    assert by_id(fixed)["CVE-2011-2523"].outcome == Outcome.NOT_VULNERABLE


def test_openssh_backport_is_declined_not_guessed():
    tagged = net._versions(endpoints({22: Endpoint(22, "open", banner=b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n")}))
    assert by_id(tagged)["CVE-2024-6387"].outcome == Outcome.UNDETERMINED and by_id(tagged)["CVE-2024-6387"].reason == "backported"
    bare = net._versions(endpoints({2222: Endpoint(2222, "open", banner=b"SSH-2.0-OpenSSH_9.6p1\r\n")}))  # also on a non-standard port
    assert by_id(bare)["CVE-2024-6387"].outcome == Outcome.VULNERABLE
    patched = net._versions(endpoints({22: Endpoint(22, "open", banner=b"SSH-2.0-OpenSSH_9.9p1\r\n")}))
    assert by_id(patched)["CVE-2024-6387"].outcome == Outcome.NOT_VULNERABLE


def test_catch_all_port_suppresses_product_results_and_says_why():
    """T23: a port that answers a nonsense probe (reflects=True) yields no product/version verdict, only a stated suppression."""
    v = net._versions(endpoints({21: Endpoint(21, "open", banner=b"220 (vsFTPd 2.3.4)\r\n", reflects=True)}))
    assert len(v) == 1 and v[0].outcome == Outcome.UNDETERMINED and v[0].reason == "catch-all"
    assert "CVE-2011-2523" not in by_id(v)


class _Prober(Prober):
    def __init__(self, **kw):
        super().__init__("www.example.com", "203.0.113.9", **kw)


def test_web_negative_control_blocks_soft_404(monkeypatch):
    """T22: a site that answers success for a path that can't exist produces no web-path findings."""
    p = _Prober()
    monkeypatch.setattr(p, "_http_get", lambda port, path, deadline: (200, b"<h1>welcome</h1>"))
    eps = endpoints({80: Endpoint(80, "open")})
    assert all(v.outcome == Outcome.UNDETERMINED and v.reason == "soft-404" for v in net._web(p, eps))


def test_web_fires_only_with_marker_and_a_clean_control(monkeypatch):
    p = _Prober()
    pages = {"/.git/config": (200, b"[core]\n\trepositoryformatversion = 0\n"), "/.env": (404, b"not found")}
    monkeypatch.setattr(p, "_http_get", lambda port, path, deadline: pages.get(path, (404, b"missing")))
    v = by_id(net._web(p, endpoints({80: Endpoint(80, "open")})))
    assert v["NIM-WEB-GIT"].outcome == Outcome.VULNERABLE and v["NIM-WEB-GIT"].grade == Grade.REASONABLE
    assert v["NIM-WEB-ENV"].outcome == Outcome.NOT_VULNERABLE  # served path, but the marker is absent


def test_safe_mode_cannot_be_bypassed_by_content(monkeypatch):
    disruptive = net.WebRule("NIM-WEB-DANGER", "/drop", re.compile(b"x"), 9.0, "test", safety=net.Safety.DISRUPTIVE)
    monkeypatch.setattr(net, "WEB_RULES", (disruptive,))
    eps = endpoints({80: Endpoint(80, "open")})
    blocked = net._web(_Prober(safe_mode=True), eps)
    assert blocked[0].outcome == Outcome.NOT_RUN and blocked[0].reason == "safe-mode"  # never probed in safe mode


def test_parity_lists_engine_only_checks_and_flags_a_gap():
    vuln = net._exposed(endpoints({6379: Endpoint(6379, "open")})) + net._versions(endpoints({21: Endpoint(21, "open", banner=b"220 (vsFTPd 2.3.4)\r\n")}))
    good = net.parity(vuln, {"NIM-EXPOSED-REDIS"})
    assert good["ok"] and good["agree"] == ["NIM-EXPOSED-REDIS"] and good["explained"][0]["id"] == "CVE-2011-2523"
    gap = net.parity(vuln, {"NIM-EXPOSED-REDIS", "NIM-TLS-EXPIRED"})  # scan opened one the engine didn't
    assert not gap["ok"] and gap["unexplained"][0]["id"] == "NIM-TLS-EXPIRED"


# --- real local sockets: budgets the engine enforces ----------------------

class _Echo(socketserver.StreamRequestHandler):
    def handle(self):
        _CONC.enter()
        try:
            time.sleep(0.2)
            self.request.recv(64)
            self.request.sendall(b"ok\r\n")
        finally:
            _CONC.leave()


class _Counter:
    def __init__(self):
        self.now = self.max = 0
        self.lock = threading.Lock()

    def enter(self):
        with self.lock:
            self.now += 1
            self.max = max(self.max, self.now)

    def leave(self):
        with self.lock:
            self.now -= 1


_CONC = _Counter()


def test_per_endpoint_concurrency_is_never_exceeded():
    """T26: with a per-endpoint limit of one, the target never sees two connections to it at once."""
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _Echo)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    p = Prober("h", "127.0.0.1", Budget(per_host=6, per_endpoint=1, deadline=5))
    with ThreadPoolExecutor(max_workers=6) as pool:
        list(pool.map(lambda _: p._exchange(port, b"hi\r\n", deadline=time.monotonic() + 4), range(6)))
    srv.shutdown()
    assert _CONC.max == 1, _CONC.max


def test_a_check_past_its_deadline_is_timed_out_and_the_scan_continues(monkeypatch):
    """T8/R2.4: an endpoint whose work overruns the deadline yields not-run timed-out, and the other ports still report."""
    slow = {6379}

    def connect_state(ip, port, timeout):
        if port in slow:
            time.sleep(0.2)
            return "open"
        return "closed" if port == 445 else "filtered"

    monkeypatch.setattr(external, "connect_state", connect_state)
    monkeypatch.setattr(external, "tls_probe", lambda *a, **k: {"trusted": True, "error": None, "not_after": None, "legacy": None})
    p = Prober("h", "127.0.0.1", Budget(per_host=8, per_endpoint=1, deadline=0.05, connect=0.05))
    eps = p.observe()
    assert eps[6379].timed_out
    v = by_id(net._exposed(eps))
    assert v["NIM-EXPOSED-REDIS"].outcome == Outcome.NOT_RUN and v["NIM-EXPOSED-REDIS"].reason == "timed-out"
    assert v["NIM-EXPOSED-SMB"].outcome == Outcome.NOT_VULNERABLE  # a different port still reached a verdict


def test_report_renders_in_the_engine_format():
    from nimstead.engine import report
    eps = endpoints({6379: Endpoint(6379, "open"), 443: Endpoint(443, "open", tls={"trusted": True, "error": None, "not_after": None, "legacy": None})})
    verdicts = net._exposed(eps) + net._tls(eps, "www.example.com")
    r = net.build_report("www.example.com", "203.0.113.9", verdicts, eps, [], False)
    text = report.render(r)
    assert "VULNERABLE" in r["headline"]["text"] and "Redis" in text and "Coverage" in text
    assert r["content_version"].startswith("net.")
