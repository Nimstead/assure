"""Network checks judged on the server (tasks/plan-network.md N10-N11, DECISIONS 129): only devices in the reporting host's
own neighbour rows on private ranges, through the engine's evaluator, as findings on a device asset that close on evidence."""

import base64
import datetime as dt
from datetime import timedelta

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
    send(c, h, [obs(open_={80}, http={"control": [404, b64(b"no")], "/.git/config": [200, b64(git)], "/.env": [404, b64(b"no")]})])
    assert [x["vuln_id"] for x in c.get("/api/findings").json()] == ["NIM-WEB-GIT"]
    send(c, h, [obs(CAMERA[0], CAMERA[1], open_={80}, http={"control": [200, b64(b"<h1>hi</h1>")], "/.git/config": [200, b64(b"<h1>hi</h1>")],
                                                          "/.env": [200, b64(b"<h1>hi</h1>")]})])
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
