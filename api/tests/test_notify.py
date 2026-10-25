"""Failure alerts: triggers, batching, SSRF refusal, recorded failures, and an unaffected request path."""

import json
import time

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import update
from sqlalchemy.orm import sessionmaker
from test_api import INV
from test_remediate import add_host, plan, setup

from nimstead import netguard, notify
from nimstead.app import create_app
from nimstead.db import Asset, Kev, RemediationJob, make_engine, now
from nimstead.scan import rescan

HOOK = "https://hooks.slack.com/services/T000/B000/XXXX"


@pytest.fixture
def sent(monkeypatch):
    """Webhook posts captured by a mock transport; DNS resolves to a public address unless a test overrides it."""
    class Posts(list):
        behaviour = {"fn": lambda req: httpx.Response(200)}

    posts = Posts()

    def handler(req):
        posts.append((str(req.url), json.loads(req.content)))
        return posts.behaviour["fn"](req)

    monkeypatch.setattr(notify, "http_client", httpx.Client(transport=httpx.MockTransport(handler)))
    monkeypatch.setattr(netguard.socket, "getaddrinfo", lambda host, *a, **k: [(2, 1, 6, "", ("93.184.216.34", 443))])
    return posts


def configured(env, fmt="slack"):
    c = setup(env)
    r = c.put("/api/settings/notifications", json={"webhook_url": HOOK, "webhook_format": fmt})
    assert r.status_code == 200, r.text
    return c


def dispatched_job(c):
    aid, h = add_host(c)
    jid = plan(c, aid).json()["id"]
    c.post(f"/api/remediation/jobs/{jid}/approve")
    c.get("/api/agent/jobs", headers=h)
    return aid, h, jid


def report(c, h, jid, outcome, error=None):
    r = c.post(f"/api/agent/jobs/{jid}/report", json={"outcome": outcome, "error": error}, headers=h)
    notify.flush()
    return r


@pytest.mark.parametrize("outcome,urgent", [("rolled_back", False), ("rollback_failed", True), ("aborted", False)])
def test_agent_failure_outcomes_alert(env, sent, outcome, urgent):
    c = configured(env)
    _, h, jid = dispatched_job(c)
    assert report(c, h, jid, outcome, "nginx.service inactive").status_code == 200
    assert len(sent) == 1
    url, body = sent[0]
    assert url == HOOK and list(body) == ["text"]  # Slack-compatible
    assert f"Remediation {outcome}" in body["text"] and "nginx.service inactive" in body["text"] and "sbx-1" in body["text"]
    assert body["text"].startswith("URGENT: ") == urgent


def test_success_and_applied_do_not_alert_but_not_fixed_does(env, sent):
    c = configured(env)
    _, h, jid = dispatched_job(c)
    report(c, h, jid, "applied")
    assert sent == []  # verifying isn't a failure
    c.post("/api/agent/inventory", json={"ecosystem": "Debian:12", "packages": [
        {"ecosystem": "Debian:12", "name": "openssl", "version": "3.0.11-1~deb12u1", "source": "openssl"}]}, headers=h)  # still vulnerable
    notify.flush()
    assert len(sent) == 1 and "not_fixed" in sent[0][1]["text"]


def test_timed_out_job_alerts_as_failed(env, sent):
    c = configured(env)
    _, _, jid = dispatched_job(c)
    s = sessionmaker(make_engine(env))()
    s.execute(update(RemediationJob).values(updated=now().replace(year=2020)))
    s.commit()
    c.get("/api/remediation/jobs")  # sweep
    notify.flush()
    assert len(sent) == 1 and "Remediation failed" in sent[0][1]["text"]


def test_generic_json_format(env, sent):
    c = configured(env, fmt="json")
    _, h, jid = dispatched_job(c)
    report(c, h, jid, "rollback_failed")
    assert sent[0][1] == {"kind": "remediation_rollback_failed", "urgent": True, "source": "nimstead", "text": sent[0][1]["text"]}


def test_new_fix_now_findings_are_batched_one_message_per_inventory(env, sent):
    c = setup(env)
    a = c.post("/api/enroll-tokens").json()["token"]
    agent = c.post("/api/agent/enroll", json={"token": a, "hostname": "web-1", "ecosystem": "Debian:12"}).json()
    h = {"Authorization": f"Bearer {agent['agent_key']}"}
    c.put("/api/settings/notifications", json={"webhook_url": HOOK})
    assert c.post("/api/agent/inventory", json=INV, headers=h).status_code == 200
    notify.flush()
    assert len(sent) == 1 and "fix-now" in sent[0][1]["text"] and "web-1" in sent[0][1]["text"]  # the fixture's KEV on requests
    first = sent[0][1]["text"]
    c.post("/api/agent/inventory", json=INV, headers=h)  # same findings again: nothing new
    notify.flush()
    assert len(sent) == 1

    # three more CVEs turn KEV at once (a feed update): still a single message, not three
    s = sessionmaker(make_engine(env))()
    targets = [f["vuln_id"] for f in c.get("/api/findings").json() if not f["kev"]][:3]
    s.add_all(Kev(cve=v, date_added="2026-10-25") for v in targets)
    s.commit()
    rescan(s, s.get(Asset, agent["asset_id"]), inventory_received=False)
    notify.flush()
    assert len(sent) == 2 and "3 new fix-now findings" in sent[1][1]["text"] and all(v in sent[1][1]["text"] for v in targets)
    assert sent[1][1]["text"] != first


def test_nothing_sent_when_unconfigured(env, sent):
    c = setup(env)
    _, h, jid = dispatched_job(c)
    report(c, h, jid, "rolled_back")
    assert sent == []


@pytest.mark.parametrize("url", ["http://hooks.example.com/x", "https://127.0.0.1/x", "https://169.254.169.254/latest", "https://[::1]/x",
                                 "https://10.0.0.5/x", "https://user:pw@hooks.example.com/x"])
def test_unsafe_webhook_urls_are_refused_at_configuration(env, sent, url):
    c = setup(env)
    assert c.put("/api/settings/notifications", json={"webhook_url": url}).status_code == 422


def test_hostname_resolving_to_private_address_is_refused_at_delivery(env, sent, monkeypatch):
    c = configured(env)
    monkeypatch.setattr(netguard.socket, "getaddrinfo", lambda host, *a, **k: [(2, 1, 6, "", ("10.1.2.3", 443))])  # rebinding / internal name
    _, h, jid = dispatched_job(c)
    assert report(c, h, jid, "rolled_back").status_code == 200
    assert sent == []  # never connected
    n = c.get("/api/settings/notifications").json()
    assert n["last_delivery_failed"] and "private or non-public" in n["recent"][0]["error"]


def test_failed_delivery_is_recorded_visible_and_recovers(env, sent):
    c = configured(env)
    sent.behaviour["fn"] = lambda req: httpx.Response(500)
    _, h, jid = dispatched_job(c)
    report(c, h, jid, "rolled_back")
    n = c.get("/api/settings/notifications").json()
    assert n["last_delivery_failed"] is True
    assert n["recent"][0]["ok"] is False and "500" in n["recent"][0]["error"] and n["recent"][0]["channel"] == "webhook"
    assert HOOK not in str(n) and n["webhook_host"] == "hooks.slack.com"  # secret URL never echoed back
    sent.behaviour["fn"] = lambda req: httpx.Response(200)
    assert c.post("/api/settings/notifications/test").status_code == 202
    notify.flush()
    assert c.get("/api/settings/notifications").json()["last_delivery_failed"] is False


def test_request_path_unaffected_by_broken_or_slow_webhook(env, sent):
    c = configured(env)
    _, h, jid = dispatched_job(c)

    def boom(req):
        time.sleep(0.6)
        raise httpx.ConnectError("unreachable")

    sent.behaviour["fn"] = boom
    t = time.monotonic()
    r = c.post(f"/api/agent/jobs/{jid}/report", json={"outcome": "rolled_back"}, headers=h)
    assert r.status_code == 200 and r.json()["status"] == "rolled_back"
    assert time.monotonic() - t < 0.5  # delivery happens off the request path
    notify.flush()
    assert c.get("/api/settings/notifications").json()["last_delivery_failed"] is True


class FakeSMTP:
    sent: list = []
    fail = False

    def __init__(self, host, port, **kw):
        self.host, self.port = host, port

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def ehlo(self):
        pass

    def has_extn(self, name):
        return False

    def login(self, user, pw):
        FakeSMTP.sent.append(("login", user, pw))

    def send_message(self, m):
        if FakeSMTP.fail:
            raise OSError("smtp down")
        FakeSMTP.sent.append(m)


def test_email_channel(env, sent, monkeypatch):
    monkeypatch.setenv("NIMSTEAD_SMTP_URL", "smtp://bot:pw@mail.example.com:587")
    monkeypatch.setenv("NIMSTEAD_SMTP_FROM", "nimstead@example.com")
    monkeypatch.setattr(notify.smtplib, "SMTP", FakeSMTP)
    FakeSMTP.sent, FakeSMTP.fail = [], False
    c = setup(env)
    assert c.put("/api/settings/notifications", json={"emails": ["Ops@Example.com", "sec@example.com"]}).json()["email_available"]
    _, h, jid = dispatched_job(c)
    report(c, h, jid, "rollback_failed", "x")
    msgs = [m for m in FakeSMTP.sent if not isinstance(m, tuple)]
    assert len(msgs) == 1 and msgs[0]["To"] == "ops@example.com, sec@example.com" and msgs[0]["Subject"].startswith("[URGENT] Nimstead:")
    assert ("login", "bot", "pw") in FakeSMTP.sent and sent == []  # no webhook configured

    FakeSMTP.fail = True  # SMTP outage: recorded, request path fine
    aid, h2 = add_host(c, "sbx-2")
    jid2 = plan(c, aid).json()["id"]
    c.post(f"/api/remediation/jobs/{jid2}/approve")
    c.get("/api/agent/jobs", headers=h2)
    assert report(c, h2, jid2, "aborted").status_code == 200
    n = c.get("/api/settings/notifications").json()
    assert n["last_delivery_failed"] and n["recent"][0]["channel"] == "email" and "smtp down" in n["recent"][0]["error"]


def test_email_ignored_without_smtp_env(env, sent, monkeypatch):
    monkeypatch.delenv("NIMSTEAD_SMTP_URL", raising=False)
    c = setup(env)
    assert c.put("/api/settings/notifications", json={"emails": ["ops@example.com"]}).json()["email_available"] is False
    _, h, jid = dispatched_job(c)
    report(c, h, jid, "rolled_back")
    assert c.get("/api/settings/notifications").json()["recent"] == []


def test_settings_are_per_org_and_need_login(env, sent):
    c = configured(env)
    other = TestClient(create_app(env))
    other.post("/api/auth/signup", json={"email": "b@example.com", "password": "correct horse battery", "org_name": "B"})
    assert other.get("/api/settings/notifications").json()["webhook_set"] is False
    _, h, jid = dispatched_job(c)
    report(c, h, jid, "rolled_back")
    assert other.get("/api/settings/notifications").json()["recent"] == []
    assert TestClient(c.app).get("/api/settings/notifications").status_code == 401


def test_failed_alert_is_retried_with_its_text_and_gives_up_after_three_attempts(env, sent):
    from sqlalchemy import select

    from nimstead.db import Notification
    c = configured(env)
    sent.behaviour["fn"] = lambda req: httpx.Response(503)
    _, h, jid = dispatched_job(c)
    report(c, h, jid, "rollback_failed", "disk full")
    s = sessionmaker(make_engine(env))()
    for _ in range(4):  # hourly feed runs
        notify.retry_failed(s)
        notify.flush()
    rows = s.scalars(select(Notification).order_by(Notification.id)).all()
    assert [r.attempt for r in rows] == [1, 2, 3]  # stops at MAX_ATTEMPTS
    texts = {p["text"] for _, p in sent}
    assert len(texts) == 1 and "URGENT" in texts.pop()  # same message each time
    sent.behaviour["fn"] = lambda req: httpx.Response(200)
    assert notify.retry_failed(s) == 0  # nothing left to retry once exhausted
