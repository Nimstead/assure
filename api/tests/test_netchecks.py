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

from nimstead import external, neighbours
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
    neighbours.prune(s)  # the hourly run's step: devices gone a month go, with their findings
    s.commit()
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
    report(c, agent(c, "laptop-1", "Windows"), None, facts={"addresses": ["192.168.1.77"]})  # an older agent: its address from facts
    assert [d["mac"] for d in c.get("/api/network/unmanaged").json()] == ["02:aa:00:00:00:77"]


def test_a_current_agent_with_no_macs_cant_hide_devices_through_its_facts(env):
    """Prove-It (ship review 2): a 0.7.0 host sending no MACs and 250 `addresses` hid a whole /24 and blocked others' checks."""
    c, web = setup(env)
    liar = agent(c, "liar-1")
    report(c, liar, [], own={"ips": [], "macs": []}, facts={"addresses": [f"192.168.1.{i}" for i in range(1, 251)]})
    assert CAMERA[1] in [d["mac"] for d in c.get("/api/network/unmanaged").json()]
    assert send(c, web, [obs(open_={23})])["checked"] == 1


def test_an_older_agents_addresses_count_only_up_to_a_hosts_own_cap(env):
    """The fallback for agents before 0.7.0 trusts their `addresses` fact, but no more of it than a host's own addresses."""
    from nimstead.db import Asset
    c, web = setup(env)
    report(c, agent(c, "old-1", "Windows"), None, facts={"addresses": [f"10.9.{i // 250}.{i % 250}" for i in range(300)] + [CAMERA[0]]})
    assert CAMERA[1] in [d["mac"] for d in c.get("/api/network/unmanaged").json()]
    s = make_sessionmaker(env)()
    assert len(neighbours.Fleet(s, s.scalar(select(Asset.org_id))).fallback) == neighbours.MAX_OWN


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


def test_network_check_reports_are_limited_per_org(env, monkeypatch):
    """Ship review: the per-host limit alone let one org with thousands of hosts send 20,000 reports an hour."""
    from nimstead import app as appmod
    monkeypatch.setattr(appmod, "ORG_NETCHECKS_MAX_PER_HOUR", 2)
    c, web = setup(env)
    db = agent(c, "db-1")
    codes = [c.post("/api/agent/network-checks", headers=h, json={"devices": []}).status_code for h in (web, db, db)]
    assert codes == [200, 200, 429]


def test_devices_stay_out_of_asset_counts_and_attack_paths(env):
    """Ship review: a device counted as an asset on Home and appeared as a host in attack paths."""
    c, h = setup(env)
    send(c, h, [obs(open_={23})])
    assert c.get("/api/summary").json()["assets"] == 1
    assert [x["hostname"] for x in c.get("/api/attack-paths").json()["hosts"].values()] == ["web-1"]


def test_device_findings_explain_themselves_as_on_your_network(env):
    """Ship review: a device's reasons said "reachable from the internet" and "fetched by automated crawlers"."""
    c, h = setup(env)
    send(c, h, [obs(open_={23, 80}, http={"control": page(404, b"no"), "/.git/config": page(200, b"[core]", "/.git/config"),
                                          "/.env": page(404, b"no", "/.env")})])
    c.patch(f"/api/assets/{c.get('/api/findings').json()[0]['asset_id']}", json={"criticality": "high"})  # a re-score writes reasons too
    for f in c.get("/api/findings").json():
        text = " ".join([f["summary"], *f["reasons"]]).lower()
        assert "internet" not in text and "crawler" not in text, f
        assert "network" in text


def test_a_device_finding_that_comes_back_is_reopened_not_duplicated(env):
    c, h = setup(env)
    send(c, h, [obs(open_={23})])
    first = c.get("/api/findings").json()[0]["id"]
    send(c, h, [obs()])
    send(c, h, [obs(open_={23})])
    f = c.get("/api/findings").json()
    assert [x["id"] for x in f] == [first]
    assert "finding_reopened" in [e["kind"] for e in c.get("/api/evidence/ledger").json()["entries"]]


def test_the_device_cap_refuses_new_devices_past_it(env, monkeypatch):
    monkeypatch.setattr(neighbours, "MAX_DEVICES_PER_ORG", 1)
    c, h = setup(env)
    out = send(c, h, [obs(), obs("192.168.1.65", "bc:ba:c2:11:22:34")])
    assert out["checked"] == 1 and out["refused"] == 1


def test_ipv6_devices_are_never_checked(env):
    c, h = setup(env)
    report(c, h, [row("fd00::5", "02:00:00:00:00:05"), row("fe80::5", "02:00:00:00:00:05")])
    assert send(c, h, [obs("fd00::5", "02:00:00:00:00:05", open_={23}), obs("fe80::5", "02:00:00:00:00:05", open_={23})])["refused"] == 2


def test_a_devices_report_says_on_your_network_never_the_internet(env):
    """Ship review 2: only the summary was reworded; "open to the internet" and "external target" stayed in the report."""
    c, h = setup(env)
    git = page(200, b"[core]\n\trepositoryformatversion = 0\n", "/.git/config")
    send(c, h, [obs(open_={23, 80}, http={"control": page(404, b"nope"), "/.git/config": git})])
    aid = next(d for d in c.get("/api/network/unmanaged").json() if d["mac"] == CAMERA[1])["checked"]["asset_id"]
    text = c.get(f"/api/assets/{aid}/scan-report").text
    assert "NIM-WEB-GIT" in text and "internet" not in text.lower() and "external target" not in text


def test_deleting_a_device_keeps_its_address_out_of_the_ledger(env):
    c, h = setup(env)
    send(c, h, [obs(open_={23})])
    aid = next(d for d in c.get("/api/network/unmanaged").json() if d["mac"] == CAMERA[1])["checked"]["asset_id"]
    assert c.delete(f"/api/assets/{aid}").status_code == 204
    entry = next(e for e in c.get("/api/evidence/ledger").json()["entries"] if e["kind"] == "asset_deleted")
    assert entry["data"]["hostname"] == "device" and CAMERA[0] not in str(entry["data"])


def test_deleting_a_host_takes_its_device_views_with_it_not_anyone_elses(env):
    """Ship review 2: a deleted host's views kept their findings open for 30 days, checked from a machine that's gone."""
    c, web = setup(env)
    db = agent(c, "db-1")
    report(c, db, [row(*CAMERA)], own={"ips": ["192.168.1.21"], "macs": ["52:54:00:00:00:21"]})
    send(c, web, [obs(open_={23})])
    send(c, db, [obs(open_={6379})])
    web_id = next(a["id"] for a in c.get("/api/assets").json() if a["hostname"] == "web-1")
    assert c.delete(f"/api/assets/{web_id}").status_code == 204
    assert sorted(f["vuln_id"] for f in c.get("/api/findings").json()) == ["NIM-EXPOSED-REDIS"]


def test_a_device_that_later_gets_an_agent_keeps_its_old_views_until_they_age_out(env):
    """Decided (ship review 2): views stay until the 30-day prune. Deleting them on a claim would let one host erase what
    another machine found; checking the device stops, as it's judged from its own agent now."""
    c, web = setup(env)
    send(c, web, [obs(open_={23})])
    report(c, agent(c, "camera-1"), [], own={"ips": [CAMERA[0]], "macs": [CAMERA[1]]})
    assert send(c, web, [obs(open_={23})])["refused"] == 1
    assert [f["vuln_id"] for f in c.get("/api/findings").json()] == ["NIM-EXPOSED-TELNET"]


# --- ship review 2: coverage the test engineer asked for ---------------------------------------------------------------

def age(env, days, **where):
    s = make_sessionmaker(env)()
    for a in s.scalars(select(Asset).filter_by(**where)):
        a.last_seen = now() - timedelta(days=days)
    s.commit()


def test_the_hourly_prune_never_touches_hosts_or_external_targets_and_keeps_the_ledger(env):
    """A wrong filter would delete every silent host and its history each hour."""
    c, h = setup(env)
    send(c, h, [obs(open_={23})])
    s = make_sessionmaker(env)()
    org = s.scalar(select(Asset.org_id))
    s.add(Asset(org_id=org, hostname="shop.example.com", kind="external", agent_key_hash="x" * 64))
    s.commit()
    age(env, 400, kind="host")
    age(env, 400, kind="external")
    before = len(c.get("/api/evidence/ledger").json()["entries"])
    s = make_sessionmaker(env)()
    assert neighbours.prune(s)["devices"] == 0
    s.commit()
    assert {a.kind for a in s.scalars(select(Asset))} == {"host", "external", "device"}
    assert len(c.get("/api/evidence/ledger").json()["entries"]) == before


def test_a_device_checked_29_days_ago_stays_and_31_goes(env):
    c, h = setup(env)
    send(c, h, [obs(open_={23})])
    age(env, 29, kind="device")
    s = make_sessionmaker(env)()
    assert neighbours.prune(s)["devices"] == 0
    s.commit()
    age(env, 31, kind="device")
    assert neighbours.prune(s)["devices"] == 1


def test_a_known_device_is_still_checked_at_the_cap_and_the_cap_counts_each_machines_view(env, monkeypatch):
    """At the cap only new views are refused, or known devices' findings would freeze. The cap counts views (one per
    machine that checks a device), so N machines checking one camera use N: bounded storage, not a device count."""
    monkeypatch.setattr(neighbours, "MAX_DEVICES_PER_ORG", 1)
    c, web = setup(env)
    send(c, web, [obs(open_={23})])
    assert send(c, web, [obs(open_=())]) == {"checked": 1, "refused": 0, "open": 0}  # and the finding closed on it
    assert send(c, web, [obs(ip="192.168.1.65", mac="bc:ba:c2:11:22:34")])["refused"] == 1
    db = agent(c, "db-1")
    report(c, db, [row(*CAMERA)], own={"ips": ["192.168.1.21"], "macs": ["52:54:00:00:00:21"]})
    assert send(c, db, [obs(open_={23})])["refused"] == 1


def test_a_port_that_echoes_whatever_its_sent_neither_opens_nor_closes_a_banner_cve(env):
    c, h = setup(env)
    echo = obs(banners={21: b"220 (vsFTPd 2.3.4)\r\n"})
    echo["ports"]["21"]["reflects"] = True
    send(c, h, [echo])
    assert [f["vuln_id"] for f in c.get("/api/findings").json() if f["vuln_id"].startswith("CVE-")] == []  # a catch-all repeats our words: no product is proven
    send(c, h, [obs(banners={21: b"220 (vsFTPd 2.3.4)\r\n"})])
    assert [f["vuln_id"] for f in c.get("/api/findings").json() if f["vuln_id"].startswith("CVE-")] == ["CVE-2011-2523"]
    send(c, h, [echo])
    assert [f["vuln_id"] for f in c.get("/api/findings").json() if f["vuln_id"].startswith("CVE-")] == ["CVE-2011-2523"]  # no proof it's gone either


def test_a_report_missing_ports_or_a_device_thats_off_keeps_findings_open(env):
    """A truncated or older report, or every port dropped (device off), proves nothing closed (R4.6)."""
    c, h = setup(env)
    send(c, h, [obs(open_={23})])
    send(c, h, [{"ip": CAMERA[0], "mac": CAMERA[1], "ports": {}}])
    send(c, h, [{"ip": CAMERA[0], "mac": CAMERA[1]}])
    send(c, h, [obs(filtered=set(PORTS))])
    assert [f["vuln_id"] for f in c.get("/api/findings").json()] == ["NIM-EXPOSED-TELNET"]


def test_another_org_can_neither_check_hide_nor_read_this_orgs_devices(env, monkeypatch):
    from fastapi.testclient import TestClient

    from nimstead.app import create_app
    monkeypatch.setattr(neighbours, "MAX_DEVICES_PER_ORG", 1)
    c, web = setup(env)
    send(c, web, [obs(open_={23})])  # org A is at its device cap
    b = TestClient(create_app(env))
    assert b.post("/api/auth/signup", json={"email": "b@example.org", "password": "correct horse battery", "org_name": "B"}).status_code == 201
    bh = agent(b, "b-web")
    report(b, bh, [row("192.168.1.99", "02:bb:00:00:00:99")], own={"ips": [CAMERA[0]], "macs": [CAMERA[1]]})  # B claims A's camera
    assert send(b, bh, [obs()])["refused"] == 1  # A's camera isn't in B's table
    assert send(b, bh, [obs(ip="192.168.1.99", mac="02:bb:00:00:00:99")])["checked"] == 1  # A's cap isn't B's
    assert CAMERA[1] in [d["mac"] for d in c.get("/api/network/unmanaged").json()]
    aid = next(d for d in c.get("/api/network/unmanaged").json() if d["mac"] == CAMERA[1])["checked"]["asset_id"]
    assert b.get(f"/api/assets/{aid}/scan-report").status_code == 404


@pytest.mark.skipif(not __import__("conftest").PG, reason="SQLite ignores row locks; the race is Postgres-only")
def test_one_host_posting_twice_at_once_makes_one_view_of_a_device(env, monkeypatch):
    import threading
    import time
    vendors = neighbours.oui.vendors
    monkeypatch.setattr(neighbours.oui, "vendors", lambda s: (time.sleep(0.5), vendors(s))[1])  # both past the read, without the lock
    c, h = setup(env)
    gate, codes = threading.Barrier(2), []

    def post():
        gate.wait()
        codes.append(c.post("/api/agent/network-checks", headers=h, json={"devices": [obs(open_={23})]}).status_code)
    threads = [threading.Thread(target=post) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    s = make_sessionmaker(env)()
    assert codes == [200, 200] and len(list(s.scalars(select(Asset).where(Asset.kind == "device")))) == 1


# --- ship review 3 -----------------------------------------------------------------------------------------------------

def open_ids(c):
    return sorted(f["vuln_id"] for f in c.get("/api/findings").json())


@pytest.mark.parametrize("whole,cut,cve", [(b"220 (vsFTPd 2.3.4)\r\n", b"220 (vsFTPd 2.3.4", "CVE-2011-2523"),
                                            (b"220 ProFTPD 1.3.5 Server ready.\r\n", b"220 ProFTPD 1.3", "CVE-2015-3306")])
def test_a_greeting_cut_off_mid_line_or_mid_version_keeps_a_banner_cve_open(env, whole, cut, cve):
    """Prove-It (ship review 3): "220 (vsFTPd 2.3.4" counted as a greeting naming something else, and "ProFTPD 1.3" as a
    version that isn't 1.3.5; both closed the CVE on a read the agent cut short."""
    c, h = setup(env)
    send(c, h, [obs(banners={21: whole})])
    assert cve in open_ids(c)
    send(c, h, [obs(banners={21: cut})])
    assert cve in open_ids(c)
    send(c, h, [obs(banners={21: b"220 Microsoft FTP Service\r\n"})])  # a whole greeting naming something else closes it
    assert cve not in open_ids(c)


def test_one_mac_at_two_addresses_is_never_judged_on_the_other_devices_evidence(env):
    """Prove-It (ship review 3): a Wi-Fi extender puts its own MAC on every client behind it; Redis open on .50 opened a
    finding and .51 refusing the port closed it."""
    c = user(env)
    h = agent(c, "web-1")
    mac = "bc:ba:c2:11:22:33"
    report(c, h, [row("192.168.1.50", mac), row("192.168.1.51", mac)], own={"ips": ["192.168.1.20"], "macs": ["52:54:00:00:00:20"]})
    assert send(c, h, [obs("192.168.1.50", mac, open_={6379})])["refused"] == 1
    assert open_ids(c) == []
    report(c, h, [row("192.168.1.50", mac)], own={"ips": ["192.168.1.20"], "macs": ["52:54:00:00:00:20"]})  # one address in the latest table
    assert send(c, h, [obs("192.168.1.50", mac, open_={6379})])["checked"] == 1
    assert open_ids(c) == ["NIM-EXPOSED-REDIS"]


def test_a_web_path_found_without_its_control_answering_opens_nothing(env):
    """Prove-It (ship review 3): with no answer to the path that can't exist, the soft-404 check was skipped and the hit
    opened NIM-WEB-GIT (R10.3)."""
    c, h = setup(env)
    send(c, h, [obs(open_={80}, http={"/.git/config": page(200, b"[core]\n", "/.git/config"), "/.env": page(404, b"no", "/.env")})])
    assert open_ids(c) == []
    send(c, h, [obs(open_={80}, http={"control": page(404, b"no"), "/.git/config": page(200, b"[core]\n", "/.git/config"),
                                      "/.env": page(404, b"no", "/.env")})])
    assert open_ids(c) == ["NIM-WEB-GIT"]
    send(c, h, [obs(open_={80}, http={"/.git/config": page(404, b"no", "/.git/config"), "/.env": page(404, b"no", "/.env")})])
    assert open_ids(c) == ["NIM-WEB-GIT"]  # nor closes it


def test_a_version_too_long_to_be_real_is_never_judged_or_stored(env):
    """Prove-It (ship review 3): a 400-digit OpenSSH version opened a finding whose version overflowed its 255-character
    column, so PostgreSQL refused the whole report."""
    c, h = setup(env)
    send(c, h, [obs(banners={22: b"SSH-2.0-OpenSSH_8." + b"6" * 400 + b"\r\n", 21: b"220 (vsFTPd " + b"2" * 300 + b")\r\n"})])
    assert [v for v in open_ids(c) if v.startswith("CVE-")] == []
    assert all(len(f["installed_version"] or "") <= 255 for f in c.get("/api/findings").json())


def test_a_long_host_name_and_maker_still_fit_the_device_name(env, monkeypatch):
    """Prove-It (ship review 3): maker plus "as checked from" plus a long host name passed 255 characters."""
    monkeypatch.setattr(neighbours.oui, "vendor", lambda mac, names: "M" * 120)
    c = user(env)
    h = agent(c, "h" * 250)
    report(c, h, [row(*CAMERA)], own={"ips": ["192.168.1.20"], "macs": ["52:54:00:00:00:20"]})
    send(c, h, [obs(open_={23})])
    s = make_sessionmaker(env)()
    assert [len(d.os_name) <= 255 for d in s.scalars(select(Asset).where(Asset.kind == "device"))] == [True]


def test_a_host_claiming_one_address_hides_at_most_one_device_there(env):
    """Prove-It (ship review 3): a host with no MACs of its own that reported 200 MACs at its one address hid all 200."""
    c = user(env)
    honest, evil = agent(c, "honest"), agent(c, "evil")
    victims = [row(f"192.168.1.{i}", f"bc:ba:c2:00:00:{i:02x}") for i in range(2, 202)]
    report(c, honest, victims, own={"ips": ["192.168.1.1"], "macs": ["52:54:00:00:00:01"]})
    report(c, evil, [row("192.168.1.250", v["mac"]) for v in victims], own={"ips": ["192.168.1.250"], "macs": []})
    assert len(c.get("/api/network/unmanaged").json()) == 199


def test_one_host_can_fill_only_its_own_share_of_the_device_cap(env, monkeypatch):
    """Ship review 3: one compromised host filled the org's whole device cap and no other host could add a device."""
    monkeypatch.setattr(neighbours, "MAX_DEVICES_PER_HOST", 1, raising=False)
    c, web = setup(env)
    assert send(c, web, [obs(open_={23}), obs("192.168.1.65", "bc:ba:c2:11:22:34")]) == {"checked": 1, "refused": 1, "open": 1}
    assert send(c, web, [obs(open_={23})])["checked"] == 1  # its known device still is
    db = agent(c, "db-1")
    report(c, db, [row("192.168.1.65", "bc:ba:c2:11:22:34")], own={"ips": ["192.168.1.21"], "macs": ["52:54:00:00:00:21"]})
    assert send(c, db, [obs("192.168.1.65", "bc:ba:c2:11:22:34")])["checked"] == 1


def test_only_true_or_false_count_as_a_tls_or_web_answer(env):
    """Prove-It (ship review 3): 0 is in (True, False), so legacy: 0 closed NIM-TLS-LEGACY."""
    c, h = setup(env)
    send(c, h, [obs(open_={443}, tls={"der": cert(300), "legacy": True, "lost": False})])
    send(c, h, [obs(open_={443}, tls={"der": cert(300), "legacy": 0, "lost": False})])
    assert open_ids(c) == ["NIM-TLS-LEGACY"]
    digest = hashlib.sha256(b"x").hexdigest()
    assert neighbours._web_fact([200, 1, digest, True]) == neighbours.NO_RESPONSE
    assert neighbours._web_fact([200, True, digest, 1]) == neighbours.NO_RESPONSE


def test_one_ledger_entry_per_report_not_per_device(env):
    """Ship review 3: one entry per device per report let a host write thousands of permanent rows a day."""
    c, h = setup(env)
    send(c, h, [obs(open_={23}), obs("192.168.1.65", "bc:ba:c2:11:22:34")])
    entries = [e for e in c.get("/api/evidence/ledger").json()["entries"] if e["kind"] == "network_check"]
    assert len(entries) == 1 and sorted(d["problems"] for d in entries[0]["data"]["devices"]) == [[], ["NIM-EXPOSED-TELNET"]]


def test_443_open_with_no_tls_facts_keeps_tls_findings_open(env):
    c, h = setup(env)
    send(c, h, [obs(open_={443}, tls={"der": cert(-10), "legacy": False})])
    assert open_ids(c) == ["NIM-TLS-EXPIRED"]
    send(c, h, [obs(open_={443})])  # tls missing: a truncated or older report
    assert open_ids(c) == ["NIM-TLS-EXPIRED"]


def test_legacy_tls_on_a_device_closes_only_on_a_refusal(env):
    c, h = setup(env)
    send(c, h, [obs(open_={443}, tls={"der": cert(300), "legacy": True, "lost": False})])
    send(c, h, [obs(open_={443}, tls={"der": cert(300), "legacy": None, "lost": False})])
    assert open_ids(c) == ["NIM-TLS-LEGACY"]
    send(c, h, [obs(open_={443}, tls={"der": cert(300), "legacy": False, "lost": False})])
    assert open_ids(c) == []


def test_a_known_neighbour_still_refreshes_at_the_org_cap(env, monkeypatch):
    from nimstead.db import Neighbour
    monkeypatch.setattr(neighbours, "MAX_NEIGHBOURS_PER_ORG", 1)
    c = user(env)
    h = agent(c, "web-1")
    report(c, h, [row("192.168.1.5", "02:00:00:00:00:05")])
    s = make_sessionmaker(env)()
    for n in s.scalars(select(Neighbour)):
        n.last_seen = now() - timedelta(days=20)
    s.commit()
    report(c, h, [row("192.168.1.5", "02:00:00:00:00:05"), row("192.168.1.6", "02:00:00:00:00:06")])
    rows = make_sessionmaker(env)().scalars(select(Neighbour)).all()
    assert len(rows) == 1 and now() - rows[0].last_seen < timedelta(minutes=5)


def test_the_device_list_has_an_org_wide_limit_too(env, monkeypatch):
    from fastapi.testclient import TestClient

    from nimstead import app as appmod
    from nimstead.app import create_app
    monkeypatch.setattr(appmod, "UNMANAGED_ORG_MAX_PER_HOUR", 2)
    c = user(env)
    tok = c.post("/api/tokens", json={"name": "ro"}).json()["token"]
    ro = TestClient(create_app(env))
    assert c.get("/api/network/unmanaged").status_code == 200
    assert ro.get("/api/network/unmanaged", headers={"Authorization": f"Bearer {tok}"}).status_code == 200
    assert c.get("/api/network/unmanaged").status_code == 429


def test_the_device_list_links_to_the_view_with_findings(env):
    c, web = setup(env)
    db = agent(c, "db-1")
    report(c, db, [row(*CAMERA)], own={"ips": ["192.168.1.21"], "macs": ["52:54:00:00:00:21"]})
    send(c, web, [obs(open_={23})])
    send(c, db, [obs()])
    cam = next(d for d in c.get("/api/network/unmanaged").json() if d["mac"] == CAMERA[1])
    assert cam["checked"]["asset_id"] == c.get("/api/findings").json()[0]["asset_id"]


def test_a_device_at_an_older_agents_address_is_refused(env):
    c, h = setup(env)
    old = agent(c, "old-win")
    report(c, old, None, facts={"addresses": [CAMERA[0]]})  # an agent before 0.7.0 at the camera's address
    assert send(c, h, [obs(open_={23})])["refused"] == 1


def test_deleting_a_host_removes_its_neighbour_rows(env):
    from nimstead.db import Neighbour
    c, h = setup(env)
    hid = next(a["id"] for a in c.get("/api/assets").json() if a["hostname"] == "web-1")
    assert c.delete(f"/api/assets/{hid}").status_code in (200, 204)
    assert make_sessionmaker(env)().scalars(select(Neighbour)).all() == []
