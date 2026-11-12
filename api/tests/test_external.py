"""External (outside-in) scanning: only hosts the org proves it owns, only public addresses, findings open and close."""

import time

import pytest
from fastapi.testclient import TestClient

from nimstead import external, netguard
from nimstead.app import create_app
from nimstead.engine import network as net
from nimstead.engine.network import Endpoint

PUBLIC = [(2, 1, 6, "", ("93.184.216.34", 443))]


class DNS:
    def __init__(self):
        self.records: dict[str, list[str]] = {}
        self.served: set[tuple[str, str]] = set()  # (address, value) pairs the "server at that address" serves

    def __call__(self, name):
        return self.records.get(name, [])


@pytest.fixture
def world(env, monkeypatch):
    dns = DNS()
    monkeypatch.setattr(netguard.socket, "getaddrinfo", lambda *a, **k: PUBLIC)
    monkeypatch.setattr(external, "address_proven", lambda ip, host, value, **k: (ip, value) in dns.served)
    c = TestClient(create_app(env, dns_lookup=dns))
    c.post("/api/auth/signup", json={"email": "admin@example.com", "password": "correct horse battery", "org_name": "Ex"})
    return c, dns


def add(c, dns, host="www.example.com", prove=True):
    t = c.post("/api/targets", json={"hostname": host}).json()
    if prove:
        dns.records[t["txt_name"]] = [t["txt_value"]]
        dns.served.add((PUBLIC[0][4][0], t["txt_value"]))
    return t


DAY = 86400
GOOD_TLS = {"trusted": True, "error": None, "legacy": False}
EXPIRED = {"trusted": False, "error": "certificate has expired", "legacy": False}


def fake_net(monkeypatch, open_ports=(), tls=None, filtered=()):
    """What the engine's prober sees: every port refused unless open or filtered; tls = 443's handshake facts (open)."""
    eps = {p: Endpoint(p, "open" if p in open_ports else "filtered" if p in filtered else "closed")
           for p in sorted(set(external.SERVICES) | {external.TLS_PORT, 80, *net.BANNER_PORTS})}
    if tls is not None:
        days = -3 if tls is EXPIRED else 90
        eps[external.TLS_PORT] = Endpoint(external.TLS_PORT, "open", tls={"not_after": time.time() + days * DAY, **tls})
    monkeypatch.setattr(net.Prober, "observe", lambda self: eps)


def no_probe(monkeypatch, why):
    monkeypatch.setattr(net.Prober, "observe", lambda self: pytest.fail(why))


def test_unverified_target_is_never_scanned(world, monkeypatch):
    c, dns = world
    probes = []
    monkeypatch.setattr(net.Prober, "observe", lambda self: probes.append(self) or {})
    t = add(c, dns, prove=False)
    assert t["verified"] is False and t["txt_name"] == "_nimstead-verify.www.example.com"
    r = c.post(f"/api/targets/{t['id']}/scan")
    assert r.status_code == 409 and "Prove you own" in r.json()["detail"]
    assert c.post(f"/api/targets/{t['id']}/verify").status_code == 409  # no TXT record yet
    assert probes == []  # not a single packet sent


def test_verified_scan_opens_and_resolves_findings_with_evidence(world, monkeypatch):
    c, dns = world
    t = add(c, dns)
    assert c.post(f"/api/targets/{t['id']}/verify").json()["verified"] is True
    fake_net(monkeypatch, open_ports={6379}, tls=EXPIRED)
    r = c.post(f"/api/targets/{t['id']}/scan").json()
    assert r["open"] == 2 and r["address"] == "93.184.216.34"
    f = {x["vuln_id"]: x for x in c.get("/api/findings").json()}
    assert set(f) == {"NIM-EXPOSED-REDIS", "NIM-TLS-EXPIRED"} and f["NIM-EXPOSED-REDIS"]["priority"] == "fix-now"
    assert any("abused automatically" in why for why in f["NIM-EXPOSED-REDIS"]["reasons"])

    fake_net(monkeypatch, tls=EXPIRED)  # Redis now refuses connections
    assert c.post(f"/api/targets/{t['id']}/scan").json() == {"address": "93.184.216.34", "open": 1, "resolved": 1, "still_open": 0, "skipped": []}
    kinds = [e["kind"] for e in c.get("/api/evidence/ledger").json()["entries"]]
    assert {"external_target_verified", "external_scan", "finding_opened", "finding_resolved"} <= set(kinds)


def test_scan_counters_include_accepted_and_omitted_checks_can_resolve_them(world, monkeypatch):
    c, dns = world
    t = add(c, dns)
    c.post(f"/api/targets/{t['id']}/verify")
    fake_net(monkeypatch, tls=EXPIRED)
    c.post(f"/api/targets/{t['id']}/scan")
    finding = c.get("/api/findings").json()[0]
    assert c.post(f"/api/findings/{finding['id']}/accept", json={"reason": "Test compensating control", "days": 30}).status_code == 200
    assert c.post(f"/api/targets/{t['id']}/scan").json()["open"] == 1
    assert not c.get("/api/findings").json()
    fake_net(monkeypatch, tls={**GOOD_TLS, "legacy": None})  # renewed; this scanner can't offer TLS 1.0/1.1
    r = c.post(f"/api/targets/{t['id']}/scan").json()
    assert r["open"] == 0 and r["resolved"] == 1 and r["skipped"] == [external.LEGACY_SKIP]
    assert c.get("/api/findings", params={"status": "resolved"}).json()[0]["id"] == finding["id"]


def test_a_legacy_tls_finding_stays_open_when_this_scan_couldnt_test_legacy_tls(world, monkeypatch):
    c, dns = world
    t = add(c, dns)
    c.post(f"/api/targets/{t['id']}/verify")
    fake_net(monkeypatch, tls={**GOOD_TLS, "legacy": True})
    c.post(f"/api/targets/{t['id']}/scan")
    fake_net(monkeypatch, tls={**GOOD_TLS, "legacy": None})
    r = c.post(f"/api/targets/{t['id']}/scan").json()
    assert r["resolved"] == 0 and [f["vuln_id"] for f in c.get("/api/findings").json()] == ["NIM-TLS-LEGACY"]
    fake_net(monkeypatch, tls=GOOD_TLS)  # tested, and not accepted any more
    assert c.post(f"/api/targets/{t['id']}/scan").json()["resolved"] == 1


def test_a_finding_closes_on_a_refused_port_never_on_a_dropped_one(world, monkeypatch):
    c, dns = world
    t = add(c, dns)
    c.post(f"/api/targets/{t['id']}/verify")
    fake_net(monkeypatch, open_ports={3389, 6379}, tls=EXPIRED)
    c.post(f"/api/targets/{t['id']}/scan")
    fake_net(monkeypatch, filtered={3389}, tls=EXPIRED)  # RDP firewalled (dropped), Redis gone (refused)
    r = c.post(f"/api/targets/{t['id']}/scan").json()
    assert r["resolved"] == 1 and r["still_open"] == 1
    f = {x["vuln_id"]: x for x in c.get("/api/findings").json()}
    assert set(f) == {"NIM-EXPOSED-RDP", "NIM-TLS-EXPIRED"}
    assert any(why.startswith("Still open: ") and "drop" in why for why in f["NIM-EXPOSED-RDP"]["reasons"])
    c.patch(f"/api/assets/{t['id']}", json={"criticality": "high"})  # a re-score keeps the scan's word on why it's open
    rdp = next(x for x in c.get("/api/findings").json() if x["vuln_id"] == "NIM-EXPOSED-RDP")
    assert sum(why.startswith("Still open: ") for why in rdp["reasons"]) == 1
    fake_net(monkeypatch, tls=EXPIRED)  # now refused: evidence that nothing listens
    assert c.post(f"/api/targets/{t['id']}/scan").json()["resolved"] == 1


def test_a_target_that_stops_answering_closes_nothing(world, monkeypatch):
    c, dns = world
    t = add(c, dns)
    c.post(f"/api/targets/{t['id']}/verify")
    fake_net(monkeypatch, open_ports={6379}, tls=EXPIRED)
    c.post(f"/api/targets/{t['id']}/scan")
    every = set(external.SERVICES) | {external.TLS_PORT, 80, *net.BANNER_PORTS}
    fake_net(monkeypatch, filtered=every)
    r = c.post(f"/api/targets/{t['id']}/scan").json()
    assert r["resolved"] == 0 and r["still_open"] == 2
    assert c.get(f"/api/assets/{t['id']}/scan-report").json()["headline"]["status"] == "not-assessed"


def test_tls_findings_close_when_nothing_listens_on_443(world, monkeypatch):
    c, dns = world
    t = add(c, dns)
    c.post(f"/api/targets/{t['id']}/verify")
    fake_net(monkeypatch, tls=EXPIRED)
    c.post(f"/api/targets/{t['id']}/scan")
    fake_net(monkeypatch)  # 443 refused: no HTTPS left to be wrong
    assert c.post(f"/api/targets/{t['id']}/scan").json()["resolved"] == 1


def web(monkeypatch, pages):
    """Port 80's answers by path; any other path gets a real 404. Returns the paths requested."""
    asked = []

    def get(self, port, path, deadline):
        asked.append(path)
        return pages.get(path, (404, b"not found"))
    monkeypatch.setattr(net.Prober, "_http_get", get)
    return asked


def test_an_exposed_git_config_opens_a_finding_and_every_request_is_in_the_ledger(world, monkeypatch):
    c, dns = world
    t = add(c, dns)
    c.post(f"/api/targets/{t['id']}/verify")
    fake_net(monkeypatch, open_ports={80})
    asked = web(monkeypatch, {"/.git/config": (200, b"[core]\n\trepositoryformatversion = 0\n")})
    c.post(f"/api/targets/{t['id']}/scan")
    f = {x["vuln_id"]: x for x in c.get("/api/findings").json()}
    assert set(f) == {"NIM-WEB-GIT"} and f["NIM-WEB-GIT"]["package"] == "http://www.example.com/.git/config"
    scan = next(e for e in c.get("/api/evidence/ledger").json()["entries"] if e["kind"] == "external_scan")
    assert scan["data"]["requests"] == [f"GET :80{p}" for p in asked] and "/.git/config" in asked
    web(monkeypatch, {"/.git/config": (404, b"gone")})
    assert c.post(f"/api/targets/{t['id']}/scan").json()["resolved"] == 1  # a real 404 after a clean control is evidence


def test_a_soft_404_site_opens_no_web_finding_and_closes_none(world, monkeypatch):
    c, dns = world
    t = add(c, dns)
    c.post(f"/api/targets/{t['id']}/verify")
    fake_net(monkeypatch, open_ports={80})
    web(monkeypatch, {"/.env": (200, b"DB_PASSWORD=hunter2\n")})
    c.post(f"/api/targets/{t['id']}/scan")
    assert [x["vuln_id"] for x in c.get("/api/findings").json()] == ["NIM-WEB-ENV"]
    monkeypatch.setattr(net.Prober, "_http_get", lambda self, port, path, deadline: (200, b"<h1>welcome</h1>"))  # 200 for everything
    r = c.post(f"/api/targets/{t['id']}/scan").json()
    assert r["resolved"] == 0 and r["still_open"] == 1 and [x["vuln_id"] for x in c.get("/api/findings").json()] == ["NIM-WEB-ENV"]


def banner(monkeypatch, greetings, reflects=()):
    """Open banner ports and their greetings; ports in reflects echo a nonsense probe back (a catch-all)."""
    eps = {p: Endpoint(p, "closed") for p in sorted(set(external.SERVICES) | {external.TLS_PORT, 80, *net.BANNER_PORTS})}
    for p, g in greetings.items():
        eps[p] = Endpoint(p, "open", banner=g, reflects=p in reflects)
    monkeypatch.setattr(net.Prober, "observe", lambda self: eps)


def test_a_vulnerable_banner_opens_an_unverified_finding_ranked_below_firmer_evidence(world, monkeypatch):
    c, dns = world
    t = add(c, dns)
    c.post(f"/api/targets/{t['id']}/verify")
    banner(monkeypatch, {2222: b"220 (vsFTPd 2.3.4)\r\n", 2121: b"220 (vsFTPd 2.3.4)\r\n"})
    c.post(f"/api/targets/{t['id']}/scan")
    f = c.get("/api/findings").json()
    assert sorted((x["vuln_id"], x["package"]) for x in f) == [("CVE-2011-2523", "tcp/2121 vsftpd"), ("CVE-2011-2523", "tcp/2222 vsftpd")]
    assert f[0]["installed_version"] == "2.3.4" and f[0]["fixed_version"] == "2.3.5"
    assert any("banner" in why and "agent" in why for why in f[0]["reasons"])
    bscore = f[0]["score"]
    fake_net(monkeypatch, open_ports={23})  # Telnet: CVSS 9.0 exposed, firm evidence
    c.post(f"/api/targets/{t['id']}/scan")
    telnet = next(x for x in c.get("/api/findings").json() if x["vuln_id"] == "NIM-EXPOSED-TELNET")
    assert telnet["score"] > bscore  # 9.8 from a banner still ranks below 9.0 read directly
    assert c.get("/api/findings", params={"status": "resolved"}).json()  # both FTP ports refused now: evidence it's gone


def test_banners_that_echo_or_carry_a_distro_tag_open_nothing(world, monkeypatch):
    c, dns = world
    t = add(c, dns)
    c.post(f"/api/targets/{t['id']}/verify")
    banner(monkeypatch, {2121: b"220 (vsFTPd 2.3.4)\r\n", 22: b"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3\r\n"}, reflects={2121})
    c.post(f"/api/targets/{t['id']}/scan")
    assert c.get("/api/findings").json() == []


def test_a_banner_finding_stays_open_while_its_port_drops_and_closes_on_an_upgrade(world, monkeypatch):
    c, dns = world
    t = add(c, dns)
    c.post(f"/api/targets/{t['id']}/verify")
    banner(monkeypatch, {22: b"SSH-2.0-OpenSSH_9.6p1\r\n"})
    c.post(f"/api/targets/{t['id']}/scan")
    assert [x["vuln_id"] for x in c.get("/api/findings").json()] == ["CVE-2024-6387"]
    fake_net(monkeypatch, filtered={22})
    assert c.post(f"/api/targets/{t['id']}/scan").json()["still_open"] == 1
    banner(monkeypatch, {22: b"SSH-2.0-OpenSSH_9.8p1\r\n"})
    assert c.post(f"/api/targets/{t['id']}/scan").json()["resolved"] == 1


def test_ownership_is_rechecked_before_every_scan(world, monkeypatch):
    c, dns = world
    t = add(c, dns)
    c.post(f"/api/targets/{t['id']}/verify")
    dns.records.clear()  # record removed, or the domain changed hands
    no_probe(monkeypatch, "scanned a host no longer proven")
    r = c.post(f"/api/targets/{t['id']}/scan")
    assert r.status_code == 409 and "gone" in r.json()["detail"]
    assert next(a for a in c.get("/api/assets").json() if a["id"] == t["id"])["verified"] is False


def test_names_that_resolve_to_private_addresses_are_refused(world, monkeypatch):
    c, dns = world
    t = add(c, dns, "intranet.example.com")
    c.post(f"/api/targets/{t['id']}/verify")
    monkeypatch.setattr(netguard.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("10.0.0.7", 443))])
    no_probe(monkeypatch, "scanned a private address")
    r = c.post(f"/api/targets/{t['id']}/scan")
    assert r.status_code == 409 and "private" in r.json()["detail"]


@pytest.mark.parametrize("host", ["10.0.0.1", "localhost", "intranet", "-bad.example.com", "a" * 300 + ".com", "x.example.com/path"])
def test_only_public_dns_names_can_be_targets(world, host):
    c, _ = world
    assert c.post("/api/targets", json={"hostname": host}).status_code == 422


def test_another_orgs_claim_neither_blocks_nor_reveals_a_host(world, env):
    """Each org proves ownership with its own TXT token, so a squatter's unverified row can't lock the real owner out,
    and adding a host never tells you whether another tenant monitors it."""
    c, dns = world
    other = TestClient(c.app)
    other.post("/api/auth/signup", json={"email": "x@other.example", "password": "correct horse battery", "org_name": "Other"})
    assert other.post("/api/targets", json={"hostname": "www.example.com"}).status_code == 201  # squatter goes first
    t = add(c, dns)  # the real owner can still add it...
    assert c.post(f"/api/targets/{t['id']}/verify").json()["verified"]  # ...and prove it with its own token
    r = c.post("/api/targets", json={"hostname": "www.example.com"})
    assert r.status_code == 409 and "organisation" not in r.json()["detail"]  # a duplicate within the org is still refused


def test_manual_scans_are_rate_limited_per_org(world, monkeypatch):
    c, dns = world
    t = add(c, dns)
    c.post(f"/api/targets/{t['id']}/verify")
    fake_net(monkeypatch)
    codes = [c.post(f"/api/targets/{t['id']}/scan").status_code for _ in range(11)]
    assert codes[:10] == [200] * 10 and codes[10] == 429


def test_context_rescore_never_closes_external_findings(world, monkeypatch):
    c, dns = world
    t = add(c, dns)
    c.post(f"/api/targets/{t['id']}/verify")
    fake_net(monkeypatch, open_ports={6379})
    c.post(f"/api/targets/{t['id']}/scan")
    before = c.get("/api/findings").json()[0]["score"]
    c.patch(f"/api/assets/{t['id']}", json={"criticality": "low"})  # triggers rescan(): must only re-score
    after = c.get("/api/findings").json()
    assert len(after) == 1 and after[0]["score"] < before


def test_tls_facts_classify_into_findings():
    now = time.time()
    for probe, want in (({"trusted": True, "error": None, "not_after": now + DAY * 90, "legacy": False}, set()),
                        ({"trusted": True, "error": None, "not_after": now + DAY * 5, "legacy": False}, {"NIM-TLS-EXPIRING"}),
                        ({"trusted": False, "error": "certificate has expired", "not_after": now - DAY * 3, "legacy": False}, {"NIM-TLS-EXPIRED"}),
                        ({"trusted": False, "error": "Hostname mismatch, certificate is not valid for 'x'", "not_after": now + DAY * 90,
                          "legacy": True}, {"NIM-TLS-NAME", "NIM-TLS-LEGACY"}),
                        ({"trusted": False, "error": "self-signed certificate", "not_after": now + DAY * 90, "legacy": None},
                         {"NIM-TLS-UNTRUSTED"})):
        found, skipped = external.tls_findings("www.example.com", probe)
        assert {f["id"] for f in found} == want
        assert bool(skipped) == (probe["legacy"] is None)  # an untested check is said, never silently passed


def test_a_scan_stores_the_engine_report_for_the_target(world, monkeypatch, env):
    c, dns = world
    t = add(c, dns)
    c.post(f"/api/targets/{t['id']}/verify")
    assert c.get(f"/api/assets/{t['id']}/scan-report").status_code == 404  # not scanned yet: nothing probed by reading
    fake_net(monkeypatch, open_ports={6379}, filtered={3389}, tls=EXPIRED)
    c.post(f"/api/targets/{t['id']}/scan")
    no_probe(monkeypatch, "reading the report probed the host")
    rep = c.get(f"/api/assets/{t['id']}/scan-report").json()
    assert rep["host"] == "www.example.com" and rep["headline"]["status"] == "vulnerable"
    assert {g["vulnerabilities"][0]["id"] for g in rep["vulnerable"]} == {"NIM-EXPOSED-REDIS", "NIM-TLS-EXPIRED"}
    assert any("dropped rather than refused" in s for s in rep["coverage"]["statements"])
    other = TestClient(create_app(env, dns_lookup=dns))
    other.post("/api/auth/signup", json={"email": "b@example.org", "password": "correct horse battery", "org_name": "B"})
    assert other.get(f"/api/assets/{t['id']}/scan-report").status_code == 404


def test_a_name_pointed_at_someone_elses_server_is_never_scanned(world, monkeypatch):
    """The tenant controls the DNS name (TXT proof passes) but the A record points at a third party's IP, which of course
    doesn't serve the tenant's token: refused at verification and before every scan, with no probe sent."""
    c, dns = world
    t = add(c, dns)
    dns.served.clear()  # the address the name resolves to isn't the tenant's
    no_probe(monkeypatch, "probed an address nobody proved")
    r = c.post(f"/api/targets/{t['id']}/verify")
    assert r.status_code == 409 and "/.well-known/nimstead-verify.txt" in r.json()["detail"]
    dns.served.add(("93.184.216.34", t["txt_value"]))
    assert c.post(f"/api/targets/{t['id']}/verify").json()["verified"]
    monkeypatch.setattr(netguard.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("1.1.1.1", 443))])  # re-pointed
    r = c.post(f"/api/targets/{t['id']}/scan")
    assert r.status_code == 409 and "1.1.1.1" in r.json()["detail"]
    assert "external_scan_refused" in [e["kind"] for e in c.get("/api/evidence/ledger").json()["entries"]]


def test_address_proof_reads_the_value_from_that_exact_address():
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    seen = []

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append((self.path, self.headers["Host"]))
            ok = self.path == external.PROOF_PATH
            self.send_response(200 if ok else 404)
            self.end_headers()
            self.wfile.write(b"nimstead-verify=abc\n" if ok else b"nimstead-verify=abc")

        def log_message(self, *a):
            pass
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = [(srv.server_address[1], False)]
    try:
        assert external.address_proven("127.0.0.1", "www.example.com", "nimstead-verify=abc", ports=port)
        assert not external.address_proven("127.0.0.1", "www.example.com", "nimstead-verify=other", ports=port)
        assert seen[0] == (external.PROOF_PATH, "www.example.com")  # asked for the target's name, at the checked address
    finally:
        srv.shutdown()
    assert not external.address_proven("127.0.0.1", "www.example.com", "nimstead-verify=abc", ports=port, timeout=1)  # nothing listening


def test_a_tls_handshake_that_times_out_keeps_tls_findings_open(world, monkeypatch):
    """Prove-It: 443 accepted the connection but the handshake was cut off. That is no evidence the certificate was fixed."""
    c, dns = world
    t = add(c, dns)
    c.post(f"/api/targets/{t['id']}/verify")
    fake_net(monkeypatch, tls=EXPIRED)
    c.post(f"/api/targets/{t['id']}/scan")
    lost = {"trusted": None, "error": "no TLS handshake: _ssl.c:1011: The handshake operation timed out", "not_after": None, "legacy": None, "lost": True}
    eps_tls = Endpoint(external.TLS_PORT, "open", tls=lost)
    fake_net(monkeypatch)
    real = net.Prober.observe
    monkeypatch.setattr(net.Prober, "observe", lambda self: {**real(self), external.TLS_PORT: eps_tls})
    r = c.post(f"/api/targets/{t['id']}/scan").json()
    assert r["resolved"] == 0 and [f["vuln_id"] for f in c.get("/api/findings").json()] == ["NIM-TLS-EXPIRED"]


def test_tls_probe_says_lost_for_a_cut_connection_and_not_tls_for_a_plain_service():
    import socket as so
    import threading as th
    srv = so.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    port = srv.getsockname()[1]

    def serve():
        for reply in (None, b"HTTP/1.1 400 Bad Request\r\n\r\n"):
            conn, _ = srv.accept()
            if reply:
                conn.recv(65536)  # all of the ClientHello: closing with unread bytes would send a reset, which reads as "lost"
                conn.sendall(reply)
                conn.shutdown(so.SHUT_WR)
            conn.close()  # the first: closed mid-handshake, nothing sent
    th.Thread(target=serve, daemon=True).start()
    cut = external.tls_probe("127.0.0.1", "www.example.com", port=port, timeout=3)
    plain = external.tls_probe("127.0.0.1", "www.example.com", port=port, timeout=3)
    srv.close()
    assert cut["trusted"] is None and cut.get("lost") is True
    assert plain["trusted"] is None and not plain.get("lost")
