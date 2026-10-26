"""External (outside-in) scanning: only hosts the org proves it owns, only public addresses, findings open and close."""

import time

import pytest
from fastapi.testclient import TestClient

from nimstead import external, netguard
from nimstead.app import create_app

PUBLIC = [(2, 1, 6, "", ("93.184.216.34", 443))]


class DNS:
    def __init__(self):
        self.records: dict[str, list[str]] = {}

    def __call__(self, name):
        return self.records.get(name, [])


@pytest.fixture
def world(env, monkeypatch):
    dns = DNS()
    monkeypatch.setattr(netguard.socket, "getaddrinfo", lambda *a, **k: PUBLIC)
    c = TestClient(create_app(env, dns_lookup=dns))
    c.post("/api/auth/signup", json={"email": "admin@example.com", "password": "correct horse battery", "org_name": "Ex"})
    return c, dns


def add(c, dns, host="www.example.com", prove=True):
    t = c.post("/api/targets", json={"hostname": host}).json()
    if prove:
        dns.records[t["txt_name"]] = [t["txt_value"]]
    return t


def fake_checks(problems):
    return lambda host, ip: ([{"id": p, "package": "tcp/6379 Redis" if "REDIS" in p else "tcp/443 TLS", "cvss": 9.8,
                               "likelihood": external.likelihood_of(p), "summary": p} for p in problems], [])


def test_unverified_target_is_never_scanned(world, monkeypatch):
    c, dns = world
    probes = []
    monkeypatch.setattr(external, "checks", lambda *a: probes.append(a) or ([], []))
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
    monkeypatch.setattr(external, "checks", fake_checks(["NIM-EXPOSED-REDIS", "NIM-TLS-EXPIRED"]))
    r = c.post(f"/api/targets/{t['id']}/scan").json()
    assert r["open"] == 2 and r["address"] == "93.184.216.34"
    f = {x["vuln_id"]: x for x in c.get("/api/findings").json()}
    assert set(f) == {"NIM-EXPOSED-REDIS", "NIM-TLS-EXPIRED"} and f["NIM-EXPOSED-REDIS"]["priority"] == "fix-now"
    assert any("abused automatically" in why for why in f["NIM-EXPOSED-REDIS"]["reasons"])

    monkeypatch.setattr(external, "checks", fake_checks(["NIM-TLS-EXPIRED"]))  # Redis firewalled
    assert c.post(f"/api/targets/{t['id']}/scan").json() == {"address": "93.184.216.34", "open": 1, "resolved": 1, "skipped": []}
    kinds = [e["kind"] for e in c.get("/api/evidence/ledger").json()["entries"]]
    assert {"external_target_verified", "external_scan", "finding_opened", "finding_resolved"} <= set(kinds)


def test_ownership_is_rechecked_before_every_scan(world, monkeypatch):
    c, dns = world
    t = add(c, dns)
    c.post(f"/api/targets/{t['id']}/verify")
    dns.records.clear()  # record removed, or the domain changed hands
    monkeypatch.setattr(external, "checks", lambda *a: pytest.fail("scanned a host no longer proven"))
    r = c.post(f"/api/targets/{t['id']}/scan")
    assert r.status_code == 409 and "gone" in r.json()["detail"]
    assert next(a for a in c.get("/api/assets").json() if a["id"] == t["id"])["verified"] is False


def test_names_that_resolve_to_private_addresses_are_refused(world, monkeypatch):
    c, dns = world
    t = add(c, dns, "intranet.example.com")
    c.post(f"/api/targets/{t['id']}/verify")
    monkeypatch.setattr(netguard.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("10.0.0.7", 443))])
    monkeypatch.setattr(external, "checks", lambda *a: pytest.fail("scanned a private address"))
    r = c.post(f"/api/targets/{t['id']}/scan")
    assert r.status_code == 409 and "private" in r.json()["detail"]


@pytest.mark.parametrize("host", ["10.0.0.1", "localhost", "intranet", "-bad.example.com", "a" * 300 + ".com", "x.example.com/path"])
def test_only_public_dns_names_can_be_targets(world, host):
    c, _ = world
    assert c.post("/api/targets", json={"hostname": host}).status_code == 422


def test_one_org_per_host_and_admin_only(world, env):
    c, dns = world
    add(c, dns)
    other = TestClient(c.app)
    other.post("/api/auth/signup", json={"email": "x@other.example", "password": "correct horse battery", "org_name": "Other"})
    assert other.post("/api/targets", json={"hostname": "www.example.com"}).status_code == 409


def test_context_rescore_never_closes_external_findings(world, monkeypatch):
    c, dns = world
    t = add(c, dns)
    c.post(f"/api/targets/{t['id']}/verify")
    monkeypatch.setattr(external, "checks", fake_checks(["NIM-EXPOSED-REDIS"]))
    c.post(f"/api/targets/{t['id']}/scan")
    before = c.get("/api/findings").json()[0]["score"]
    c.patch(f"/api/assets/{t['id']}", json={"criticality": "low"})  # triggers rescan(): must only re-score
    after = c.get("/api/findings").json()
    assert len(after) == 1 and after[0]["score"] < before


def test_checks_classify_ports_and_tls(monkeypatch):
    monkeypatch.setattr(external, "port_open", lambda ip, port, timeout=3.0: port in (6379, 443))
    now = time.time()
    for probe, want in (({"trusted": True, "error": None, "not_after": now + 86400 * 90, "legacy": False}, set()),
                        ({"trusted": True, "error": None, "not_after": now + 86400 * 5, "legacy": False}, {"NIM-TLS-EXPIRING"}),
                        ({"trusted": False, "error": "certificate has expired", "not_after": now - 86400 * 3, "legacy": False},
                         {"NIM-TLS-EXPIRED"}),
                        ({"trusted": False, "error": "Hostname mismatch, certificate is not valid for 'x'", "not_after": now + 86400 * 90,
                          "legacy": True}, {"NIM-TLS-NAME", "NIM-TLS-LEGACY"}),
                        ({"trusted": False, "error": "self-signed certificate", "not_after": now + 86400 * 90, "legacy": None},
                         {"NIM-TLS-UNTRUSTED"})):
        monkeypatch.setattr(external, "tls_probe", lambda ip, host, p=probe: p)
        found, skipped = external.checks("www.example.com", "93.184.216.34")
        assert {f["id"] for f in found} == {"NIM-EXPOSED-REDIS"} | want
        assert bool(skipped) == (probe["legacy"] is None)  # an untested check is said, never silently passed
