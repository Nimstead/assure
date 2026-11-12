"""Network checks judged on the server (tasks/plan-network.md N10-N11, DECISIONS 129): only devices in the reporting host's
own neighbour rows on private ranges, through the engine's evaluator, as findings on a device asset that close on evidence."""

import base64
import datetime as dt
import hashlib
from datetime import timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from sqlalchemy import select
from test_api import user
from test_neighbours import agent, report, row

from nimstead import external
from nimstead.db import Asset, make_sessionmaker, now
from nimstead.engine import network as net

PORTS = sorted(set(external.SERVICES) | {external.TLS_PORT, 80, *net.BANNER_PORTS})
CAMERA = ("192.168.1.64", "bc:ba:c2:11:22:33")


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def obs(ip=CAMERA[0], mac=CAMERA[1], open_=(), filtered=(), banners=None, tls=None, http=None):
    ports = {str(p): {"state": "open" if p in open_ else "filtered" if p in filtered else "closed"} for p in PORTS}
    for p, b in (banners or {}).items():
        ports[str(p)].update(state="open", banner=b64(b), reflects=False)
    return {"ip": ip, "mac": mac, "ports": ports, "tls": tls, "http": http}


def page(status, body: bytes, path: str | None = None) -> list:
    """What the agent sends for one web request: status, whether the path's marker matched (None for the control), the
    body's SHA-256 and whether it had any content. Never the body itself (DECISIONS 129)."""
    rule = next((r for r in net.WEB_RULES if r.path == path), None)
    return [status, bool(rule.marker.search(body)) if rule else None, hashlib.sha256(body).hexdigest(), bool(body.strip())]


def cert(days: int) -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "camera")])
    t = dt.datetime.now(dt.UTC)
    c = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1)
         .not_valid_before(t - timedelta(days=400)).not_valid_after(t + timedelta(days=days)).sign(key, hashes.SHA256()))
    return b64(c.public_bytes(Encoding.DER))


def setup(env):
    c = user(env)
    h = agent(c, "web-1")
    report(c, h, [row(*CAMERA), row("192.168.1.65", "bc:ba:c2:11:22:34"), row("8.8.8.8", "02:00:00:00:00:08")],
           own={"ips": ["192.168.1.20"], "macs": ["52:54:00:00:00:20"]})
    return c, h


def send(c, h, devices):
    r = c.post("/api/agent/network-checks", headers=h, json={"devices": devices})
    assert r.status_code == 200, r.text
    return r.json()


def test_an_unauthenticated_redis_on_a_device_opens_a_finding_on_that_device(env):
    c, h = setup(env)
    out = send(c, h, [obs(open_={6379, 445, 3389})])  # SMB and RDP open on a LAN: normal, not findings
    assert out == {"checked": 1, "refused": 0, "open": 1}
    f = c.get("/api/findings").json()
    assert [(x["vuln_id"], x["ecosystem"], x["hostname"]) for x in f] == [("NIM-EXPOSED-REDIS", "Network", "192.168.1.64")]
    assert "answers on your network" in f[0]["summary"] and "internet" not in f[0]["summary"]
    rows = c.get("/api/network/unmanaged").json()
    camera = next(d for d in rows if d["mac"] == CAMERA[1])
    assert camera["checked"]["from"] == "web-1" and camera["checked"]["open"] == ["NIM-EXPOSED-REDIS"]
    assert next(d for d in rows if d["mac"] == "bc:ba:c2:11:22:34")["checked"] is None
    assert c.get(f"/api/assets/{camera['checked']['asset_id']}/scan-report").json()["headline"]["status"] == "vulnerable"
    assert "network_check" in [e["kind"] for e in c.get("/api/evidence/ledger").json()["entries"]]


def test_internal_findings_rank_below_the_same_exposure_on_the_internet(env):
    c, h = setup(env)
    send(c, h, [obs(open_={6379})])
    internal = c.get("/api/findings").json()[0]
    from nimstead import risk
    outside = risk.score(kev=False, epss=None, cvss=9.8, internet_facing=True, likelihood=external.OPEN_BY_DEFAULT_LIKELIHOOD[0])
    assert "Internet-facing asset" not in internal["reasons"] and internal["score"] < outside.score


def test_only_its_own_neighbours_on_private_ranges_count(env):
    c, h = setup(env)
    other = agent(c, "db-1")
    report(c, other, [row("10.9.9.9", "02:00:00:00:09:09")])
    out = send(c, h, [obs("192.168.1.99", "bc:ba:c2:00:00:99", open_={23}),  # not in web-1's table
                      obs("8.8.8.8", "02:00:00:00:00:08", open_={23}),  # in its table, but public
                      obs("10.9.9.9", "02:00:00:00:09:09", open_={23}),  # another host's neighbour
                      obs(CAMERA[0], "bc:ba:c2:11:22:99", open_={23}),  # right address, wrong MAC
                      "nonsense", {"ip": 5}])
    assert out == {"checked": 0, "refused": 6, "open": 0}
    assert c.get("/api/findings").json() == []


def test_a_dropped_port_keeps_it_open_and_a_refused_one_closes_it(env):
    c, h = setup(env)
    send(c, h, [obs(open_={23})])
    assert send(c, h, [obs(filtered={23})])["open"] == 0
    f = c.get("/api/findings").json()
    assert [x["vuln_id"] for x in f] == ["NIM-EXPOSED-TELNET"] and any(w.startswith("Still open: ") for w in f[0]["reasons"])
    send(c, h, [obs()])
    assert c.get("/api/findings").json() == []


def test_expired_certificates_and_banners_count_self_signed_ones_do_not(env):
    c, h = setup(env)
    send(c, h, [obs(open_={443}, banners={21: b"220 (vsFTPd 2.3.4)\r\n"}, tls={"der": cert(-10), "legacy": False})])
    ids = sorted(x["vuln_id"] for x in c.get("/api/findings").json())
    assert ids == ["CVE-2011-2523", "NIM-EXPOSED-FTP", "NIM-TLS-EXPIRED"]  # self-signed, reached by address: no untrusted or name finding


def test_web_paths_use_the_agents_negative_control(env):
    c, h = setup(env)
    git = b"[core]\n\trepositoryformatversion = 0\n"
    send(c, h, [obs(open_={80}, http={"control": page(404, b"no"), "/.git/config": page(200, git, "/.git/config"), "/.env": page(404, b"no", "/.env")})])
    assert [x["vuln_id"] for x in c.get("/api/findings").json()] == ["NIM-WEB-GIT"]
    send(c, h, [obs(CAMERA[0], CAMERA[1], open_={80}, http={"control": page(200, b"<h1>hi</h1>"), "/.git/config": page(200, b"<h1>hi</h1>", "/.git/config"),
                                                          "/.env": page(200, b"<h1>hi</h1>", "/.env")})])
    assert [x["vuln_id"] for x in c.get("/api/findings").json()] == ["NIM-WEB-GIT"]  # soft-404 now: undetermined, still open


def test_devices_stay_out_of_the_asset_quota_and_go_after_30_days(env, monkeypatch):
    from nimstead import app as appmod
    c, h = setup(env)
    send(c, h, [obs(open_={6379})])
    monkeypatch.setattr(appmod, "MAX_ASSETS_PER_ORG", 2)  # web-1 and the next machine: the device doesn't count
    token = c.post("/api/enroll-tokens").json()["token"]
    assert c.post("/api/agent/enroll", json={"token": token, "hostname": "db-1", "ecosystem": "Debian:13"}).status_code == 201
    s = make_sessionmaker(env)()
    d = s.scalar(select(Asset).where(Asset.kind == "device"))
    d.last_seen = now() - timedelta(days=31)
    s.commit()
    report(c, h, [row("192.168.1.65", "bc:ba:c2:11:22:34")])
    assert make_sessionmaker(env)().scalar(select(Asset).where(Asset.kind == "device")) is None
    assert c.get("/api/findings").json() == []


def test_at_most_four_reports_an_hour_per_host(env):
    c, h = setup(env)
    codes = [c.post("/api/agent/network-checks", headers=h, json={"devices": []}).status_code for _ in range(5)]
    assert codes == [200] * 4 + [429]
    assert c.post("/api/agent/network-checks", headers=h, json={"devices": [obs()] * 33}).status_code == 422


def test_a_web_path_missing_from_the_report_keeps_its_finding_open(env):
    """Prove-It: the agent's report lacks /.env this time. Silence is not evidence the file is gone."""
    c, h = setup(env)
    env_body = b"DB_PASSWORD=hunter2\n"
    send(c, h, [obs(open_={80}, http={"control": page(404, b"no"), "/.git/config": page(404, b"no", "/.git/config"), "/.env": page(200, env_body, "/.env")})])
    assert [x["vuln_id"] for x in c.get("/api/findings").json()] == ["NIM-WEB-ENV"]
    send(c, h, [obs(open_={80}, http={"control": page(404, b"no"), "/.git/config": page(404, b"no", "/.git/config")})])
    assert [x["vuln_id"] for x in c.get("/api/findings").json()] == ["NIM-WEB-ENV"]


def test_a_tls_read_the_agent_lost_keeps_tls_findings_open(env):
    """Prove-It: 443 open, but the agent's handshake failed this run (no certificate, lost). Not evidence of a renewal."""
    c, h = setup(env)
    send(c, h, [obs(open_={443}, tls={"der": cert(-10), "legacy": False})])
    assert [x["vuln_id"] for x in c.get("/api/findings").json()] == ["NIM-TLS-EXPIRED"]
    send(c, h, [obs(open_={443}, tls={"der": None, "legacy": None, "lost": True})])
    assert [x["vuln_id"] for x in c.get("/api/findings").json()] == ["NIM-TLS-EXPIRED"]


def test_a_neighbour_that_is_one_of_the_orgs_own_machines_never_becomes_a_device(env):
    """Prove-It: web-1 checked db-1, which has an agent. It must not appear twice, once as a device with its own findings."""
    c = user(env)
    web, db = agent(c, "web-1"), agent(c, "db-1")
    report(c, web, [row("192.168.1.11", "52:54:00:00:00:11")], own={"ips": ["192.168.1.10"], "macs": ["52:54:00:00:00:10"]})
    report(c, db, [], own={"ips": ["192.168.1.11"], "macs": ["52:54:00:00:00:11"]})
    out = send(c, web, [obs("192.168.1.11", "52:54:00:00:00:11", open_={6379})])
    assert out["checked"] == 0 and out["refused"] == 1
    assert c.get("/api/findings").json() == [] and make_sessionmaker(env)().scalar(select(Asset).where(Asset.kind == "device")) is None


def test_a_certificate_too_big_to_read_keeps_tls_findings_open(env):
    """Prove-It (review 2): the server can't read a certificate past its size cap; unread is not renewed."""
    c, h = setup(env)
    send(c, h, [obs(open_={443}, tls={"der": cert(-10), "legacy": False, "lost": False})])
    huge = b64(b"\x30\x82" + bytes(40_000))  # a 40 KB "certificate": over the cap, and unparseable if cut
    send(c, h, [obs(open_={443}, tls={"der": huge, "legacy": False, "lost": False})])
    assert [x["vuln_id"] for x in c.get("/api/findings").json()] == ["NIM-TLS-EXPIRED"]


def test_a_device_that_speaks_only_tls_1_0_opens_the_legacy_finding(env):
    """Prove-It (review 1, devices): the agent's handshake was refused (lost) but TLS 1.0 completed."""
    c, h = setup(env)
    send(c, h, [obs(open_={443}, tls={"der": None, "legacy": True, "lost": True})])
    assert [x["vuln_id"] for x in c.get("/api/findings").json()] == ["NIM-TLS-LEGACY"]


def test_a_malformed_web_entry_keeps_its_finding_open(env):
    """Prove-It (ship review): an entry the server can't read was treated as an empty 200 and closed the finding."""
    c, h = setup(env)
    env_body = b"DB_PASSWORD=hunter2\n"
    send(c, h, [obs(open_={80}, http={"control": page(404, b"no"), "/.git/config": page(404, b"no", "/.git/config"), "/.env": page(200, env_body, "/.env")})])
    for bad in ([200, "yes", "zz", True], [200, False], [200, False, "0" * 64, True, "extra"]):  # three more: the hourly limit is four
        send(c, h, [obs(open_={80}, http={"control": page(404, b"no"), "/.git/config": page(404, b"no", "/.git/config"), "/.env": bad})])
        assert [x["vuln_id"] for x in c.get("/api/findings").json()] == ["NIM-WEB-ENV"], bad


def test_a_device_that_moves_address_keeps_one_web_finding(env):
    """Prove-It (ship review): the web finding was keyed by the device's IP, so a DHCP move opened a second one."""
    c, h = setup(env)
    git = b"[core]\n"
    exposed = {"control": page(404, b"no"), "/.git/config": page(200, git, "/.git/config"), "/.env": page(404, b"no", "/.env")}
    send(c, h, [obs(open_={80}, http=exposed)])
    report(c, h, [row("192.168.1.70", CAMERA[1])])
    send(c, h, [obs("192.168.1.70", CAMERA[1], open_={80}, http=exposed)])
    f = c.get("/api/findings").json()
    assert [(x["vuln_id"], x["hostname"]) for x in f] == [("NIM-WEB-GIT", "192.168.1.70")]


def test_judging_a_device_never_opens_a_connection(env, monkeypatch):
    """The server replays what the agent saw; a future rule must not make it connect to an address an agent named."""
    import socket
    c, h = setup(env)
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: pytest.fail(f"server connected to {a}"))
    send(c, h, [obs(open_={80, 443, 6379}, banners={21: b"220 (vsFTPd 2.3.4)\r\n"}, tls={"der": cert(-5), "legacy": True, "lost": False},
                    http={"control": page(404, b"no"), "/.git/config": page(200, b"[core]", "/.git/config"), "/.env": page(404, b"no", "/.env")})])
    assert len(c.get("/api/findings").json()) == 6
    from nimstead.neighbours import _Replay
    with pytest.raises(RuntimeError):
        _Replay("192.168.1.64", {})._exchange(80)


def test_one_machines_view_never_closes_what_another_machine_found(env):
    """Prove-It (ship review): db-1 is behind a firewall rule that refuses Telnet; web-1 sees it open. db-1's report closed
    web-1's finding, and every run flipped it. A compromised host could close real findings the same way."""
    c, web = setup(env)
    db = agent(c, "db-1")
    report(c, db, [row(*CAMERA)], own={"ips": ["192.168.1.21"], "macs": ["52:54:00:00:00:21"]})
    send(c, web, [obs(open_={23})])
    send(c, db, [obs()])  # every port refused from db-1
    f = c.get("/api/findings").json()
    assert [x["vuln_id"] for x in f] == ["NIM-EXPOSED-TELNET"]
    camera = next(d for d in c.get("/api/network/unmanaged").json() if d["mac"] == CAMERA[1])
    assert camera["checked"]["open"] == ["NIM-EXPOSED-TELNET"] and camera["checked"]["from"] == "db-1, web-1"


def test_claiming_a_devices_mac_without_its_address_hides_nothing(env):
    """Prove-It (ship review): a host that listed the camera's MAC as its own hid it and made every check on it refused."""
    c, web = setup(env)
    liar = agent(c, "liar-1")
    report(c, liar, [], own={"ips": ["192.168.1.30"], "macs": [CAMERA[1]]})
    assert CAMERA[1] in [d["mac"] for d in c.get("/api/network/unmanaged").json()]
    assert send(c, web, [obs(open_={23})])["checked"] == 1


def test_an_address_a_device_used_to_have_doesnt_hide_it(env):
    """Prove-It (ship review): a phone held .77 last week; a managed laptop has .77 now. The phone vanished for 30 days."""
    from nimstead.db import Neighbour
    c = user(env)
    web = agent(c, "web-1")
    report(c, web, [row("192.168.1.77", "02:aa:00:00:00:77")])
    s = make_sessionmaker(env)()
    for n in s.scalars(select(Neighbour)):
        n.last_seen = n.first_seen = now() - timedelta(days=7)
    s.commit()
    report(c, web, [row("192.168.1.78", "02:aa:00:00:00:77")])  # the phone moved
    report(c, agent(c, "laptop-1", "Windows"), [], facts={"addresses": ["192.168.1.77"]})  # an older agent: its address from facts
    assert [d["mac"] for d in c.get("/api/network/unmanaged").json()] == ["02:aa:00:00:00:77"]


def test_a_malformed_own_field_never_fails_the_inventory(env):
    c = user(env)
    h = agent(c, "web-1")
    for own in ({"ips": {}, "macs": 5}, {"ips": "10.0.0.1"}, []):
        r = c.post("/api/agent/inventory", headers=h, json={"os_name": "x", "ecosystem": "Debian:13", "packages": [], "neighbours": {"seen": [], "own": own}})
        assert r.status_code == 200, own


def test_the_ledger_keeps_no_device_address_or_mac(env):
    """Ship review: MACs can be personal data; the device row (deleted after 30 days) holds them, the permanent ledger doesn't."""
    c, h = setup(env)
    send(c, h, [obs(open_={23})])
    entries = c.get("/api/evidence/ledger").json()["entries"]
    text = str([e["data"] for e in entries if e["kind"] in ("network_check", "asset_created", "finding_opened") and e["data"].get("kind") != "host"])
    assert CAMERA[1] not in text and CAMERA[0] not in text
