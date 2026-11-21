"""Tickets (DECISIONS 150-153): one ticket per (project, owner, fix), opened, kept current, closed only when none of its
findings is open (saying why each machine left), reopened on a regression or a hand close; against stateful fakes of
Jira and GitLab (tests/trackers.py)."""

import json
import re
import socket
from datetime import timedelta

import httpx
import pytest
from sqlalchemy import select
from test_api import user
from trackers import FakeGitLab, FakeJira, client_for

from nimstead import evidence, netguard, sso, tickets
from nimstead.db import (
    Asset,
    Container,
    Finding,
    InstalledPackage,
    LedgerEntry,
    Org,
    Ticket,
    TicketSettings,
    make_sessionmaker,
    new_id,
    now,
)

LIVE = ("@all", "[x|", "https://evil", "<b>", "/close", "![i]")  # what would act if it escaped a block (~ is legal in the link's URL)
HOSTILE = "evil``` @all [x|https://evil.example] {noformat} <b>\n/close #1 ~~~ ![i](https://evil.example/p.png)"


@pytest.fixture
def org(env):
    c = user(env)
    s = make_sessionmaker(env)()
    yield c, s, s.scalar(select(Org.id))
    s.close()


def machine(s, org_id, name, owner=None, kind="host", eco="Debian:12"):
    a = Asset(org_id=org_id, hostname=name, owner=owner, kind=kind, ecosystem=eco, agent_key_hash=new_id() + new_id())
    s.add(a)
    s.flush()
    return a


def finding(s, a, vuln="CVE-2024-0001", package="openssl", priority="fix-now", fixed="3.0.15-1~deb12u1", version="3.0.11-1~deb12u2",
            kev=False, score=80, eco=None):
    f = Finding(org_id=a.org_id, asset_id=a.id, ecosystem=eco or a.ecosystem, package=package, installed_version=version, vuln_id=vuln,
                advisory_ids=[vuln], fixed_version=fixed, priority=priority, score=score, kev=kev, reasons=[], status="open")
    s.add(f)
    s.flush()
    return f


def setup(s, org_id, kind="jira", **kw):
    site = "https://acme.atlassian.net" if kind == "jira" else "https://gitlab.example.com"
    base = {"kind": kind, "site": site, "user": "bot@example.com" if kind == "jira" else "", "token": sso.seal("tok" if kind == "jira" else "glpat-tok"),
            "default_project": "OPS" if kind == "jira" else "platform/ops", "routes": [], "min_priority": "fix-now", "enabled": True}
    cfg = TicketSettings(org_id=org_id, **(base | kw))
    s.add(cfg)
    s.commit()
    return cfg


def run(s, org_id, fake):
    return tickets.sync(s, org_id, http=client_for(fake))


def ledger(s, kind):
    return [e.data for e in s.scalars(select(LedgerEntry).where(LedgerEntry.kind == kind).order_by(LedgerEntry.seq))]


def resolve(s, *fs, version=None):
    for f in fs:
        f.status, f.resolved_at = "resolved", now()
        if version:
            s.add(InstalledPackage(asset_id=f.asset_id, ecosystem=f.ecosystem, name=f.package, version=version))
    s.commit()


# --- operator-named private hosts --------------------------------------------------------------------------------------

def test_only_a_host_the_operator_named_may_be_private_and_never_link_local(monkeypatch):
    answers = {"jira.corp.example": "10.0.0.5", "jira.corp.example.evil.test": "10.0.0.6", "meta.corp.example": "169.254.169.254"}
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, *a, **k: [(0, 0, 0, "", (answers[host], 443))])
    monkeypatch.delenv("NIMSTEAD_ALLOW_PRIVATE_TARGETS", raising=False)
    monkeypatch.delenv("NIMSTEAD_ALLOW_PRIVATE_HOSTS", raising=False)
    with pytest.raises(ValueError):
        netguard.check_public_url("https://jira.corp.example/", named_ok=True)
    monkeypatch.setenv("NIMSTEAD_ALLOW_PRIVATE_HOSTS", " Jira.Corp.Example. , meta.corp.example")
    assert netguard.check_public_url("https://jira.corp.example/rest", named_ok=True) == ["10.0.0.5"]
    for url, ok in (("https://jira.corp.example/", False),  # outside-in scans never pass named_ok
                    ("https://jira.corp.example.evil.test/", True), ("https://meta.corp.example/", True)):
        with pytest.raises(ValueError):
            netguard.check_public_url(url, named_ok=ok)


# --- which tickets should be open ----------------------------------------------------------------------------------------

def test_one_ticket_per_fix_and_team_not_per_cve(org):
    _, s, oid = org
    for n in range(3):
        a = machine(s, oid, f"db-{n}", owner="Payments")
        for v in range(5):
            finding(s, a, f"CVE-2024-{v:04d}", fixed="3.0.14-1~deb12u1" if v else "3.0.15-1~deb12u1")
    cfg = setup(s, oid, routes=[{"owner": "payments", "project": "PAY"}])
    want, skipped = tickets.desired(s, oid, cfg)
    assert not skipped and len(want) == 1
    (g,) = want.values()
    assert (g["project"], g["findings"], len(g["machines"]), len(g["vulns"])) == ("PAY", 15, 3, 5)
    assert tickets.title(g, tickets.Style()) == "Upgrade openssl to 3.0.15-1~deb12u1 on 3 machines (Payments)"  # the highest fix clears them all


def test_owners_route_to_projects_else_the_default_else_they_are_counted_not_sent(org):
    _, s, oid = org
    for name, owner in (("pay-1", "Payments"), ("plat-1", "Platform"), ("orphan-1", None)):
        finding(s, machine(s, oid, name, owner))
    cfg = setup(s, oid, routes=[{"owner": "PAYMENTS", "project": "PAY"}])
    want, _ = tickets.desired(s, oid, cfg)
    assert sorted((g["project"], g["owner"] or "") for g in want.values()) == [("OPS", ""), ("OPS", "Platform"), ("PAY", "Payments")]
    cfg.default_project = ""
    want, skipped = tickets.desired(s, oid, cfg)
    assert [g["owner"] for g in want.values()] == ["Payments"] and skipped == {"Platform": 1, "": 1}


def test_only_findings_at_or_above_the_threshold_and_open_ones(org):
    _, s, oid = org
    a = machine(s, oid, "web-1")
    finding(s, a, "CVE-1", priority="fix-now")
    finding(s, a, "CVE-2", package="curl", priority="next")
    finding(s, a, "CVE-3", package="zlib", priority="low")
    gone = finding(s, a, "CVE-4", package="bash")
    resolve(s, gone)
    cfg = setup(s, oid)
    assert [g["action"]["package"] for g in tickets.desired(s, oid, cfg)[0].values()] == ["openssl"]
    cfg.min_priority = "next"
    assert sorted(g["action"]["package"] for g in tickets.desired(s, oid, cfg)[0].values()) == ["curl", "openssl"]
    cfg.min_priority = "low"
    assert len(tickets.desired(s, oid, cfg)[0]) == 3


def test_an_images_findings_are_one_rebuild_ticket_for_the_team_that_builds_it(org):
    _, s, oid = org
    img = machine(s, oid, "registry.example/pay/api:1.4", owner="Payments", kind="image")
    host = machine(s, oid, "node-1", owner="Platform")
    s.add(Container(asset_id=host.id, container_id="c1", image_asset_id=img.id, org_id=oid))
    finding(s, img, "CVE-1", package="openssl")
    finding(s, img, "CVE-2", package="zlib", fixed="1:1.3")
    cfg = setup(s, oid)
    (g,) = tickets.desired(s, oid, cfg)[0].values()
    assert g["action"] == {"kind": "image", "asset_id": img.id} and g["hosts"] == ["node-1"]
    assert tickets.title(g, tickets.Style()) == "Rebuild image registry.example/pay/api:1.4 (2 findings) (Payments)"
    b = tickets.body(g, cfg, tickets.Style())
    assert "openssl 3.0.15-1~deb12u1" in b and "zlib 1:1.3" in b and "node-1" in b


def test_a_ticket_says_priority_due_date_fix_machines_cves_and_links_back(org, monkeypatch):
    monkeypatch.setenv("NIMSTEAD_PUBLIC_URL", "https://nimstead.example/")
    _, s, oid = org
    a = machine(s, oid, "db-1", owner="Pay ments")
    f = finding(s, a, kev=True)
    f.first_seen = now() - timedelta(days=60)  # past fix-now's default deadline: overdue
    cfg = setup(s, oid)
    (g,) = tickets.desired(s, oid, cfg)[0].values()
    p = tickets.payload(g, cfg, tickets.Style())
    assert p["due"] == (f.first_seen + timedelta(days=evidence.SLA_DAYS["fix-now"])).date().isoformat()
    assert p["labels"] == ["nimstead", "nimstead-fix-now", f"nimstead-{g['fingerprint']}"]
    assert "Priority: Fix now, known exploited (CISA KEV). Due " in p["body"] and "(overdue)" in p["body"]
    assert "db-1  3.0.11-1~deb12u2" in p["body"] and "CVE-2024-0001" in p["body"]
    assert "[Open these findings in Nimstead|https://nimstead.example/findings?q=openssl&eco=Debian%3A12&priority=fix-now&owner=Pay%20ments]" in p["body"]


def test_a_hostile_package_name_stays_inert_in_jira_and_gitlab(org, monkeypatch):
    monkeypatch.setenv("NIMSTEAD_PUBLIC_URL", "https://nimstead.example")
    _, s, oid = org
    finding(s, machine(s, oid, "web-1"), package=HOSTILE, fixed=None)
    cfg = setup(s, oid)
    (g,) = tickets.desired(s, oid, cfg)[0].values()
    jira = tickets.payload(g, cfg, tickets.Style())
    outside = jira["body"].split("{noformat}")[::2]  # even pieces are outside the no-markup blocks
    assert jira["body"].count("{noformat}") % 2 == 0 and not any(m in x for m in LIVE for x in outside)
    assert "\n" not in jira["title"] and "{no-format}" in jira["body"]
    gl = tickets.payload(g, cfg, tickets.MarkdownStyle())
    fences = re.findall(r"^(`{3,})$", gl["body"], re.M)
    inside, fence = [], None
    for line in gl["body"].split("\n"):
        if fence and line == fence:
            fence = None
        elif not fence and re.fullmatch(r"`{3,}", line):
            fence = line
        elif fence:
            inside.append(line)
            assert line.startswith("  ")  # no line inside starts a quick action
        else:
            assert not any(m in line for m in LIVE) and not line.startswith(("/", "~~~"))
    assert fences and max(map(len, fences)) > 3 and any("evil" in x for x in inside)  # a fence a ``` inside can't close
    assert gl["title"].count("`") == 2 and "\n" not in gl["title"]


# --- the lifecycle ------------------------------------------------------------------------------------------------------

def test_opened_once_kept_current_closed_on_evidence_and_reopened_on_a_regression(org):
    _, s, oid = org
    fake = FakeJira(done_name="Shipped")
    a, b = machine(s, oid, "db-1", "Payments"), machine(s, oid, "db-2", "Payments")
    fa, fb = finding(s, a), finding(s, b)
    setup(s, oid, routes=[{"owner": "Payments", "project": "PAY"}])
    r = run(s, oid, fake)
    assert r["opened"] == 1 and list(fake.issues) == ["PAY-1"]
    i = fake.issues["PAY-1"]
    assert i["summary"] == "Upgrade openssl to 3.0.15-1~deb12u1 on 2 machines (Payments)" and i["duedate"] and "nimstead" in i["labels"]
    assert ledger(s, "ticket_opened")[0] | {"action": None} == {"key": "PAY-1", "project": "PAY", "owner": "Payments", "action": None,
                                                                "findings": 2, "machines": 2, "link": "https://acme.atlassian.net/browse/PAY-1"}
    fake.calls.clear()
    assert run(s, oid, fake)["opened"] == 0 and fake.writes == []  # nothing changed: nothing written

    resolve(s, fa, version="3.0.15-1~deb12u1")
    assert run(s, oid, fake)["updated"] == 1
    assert i["summary"].endswith("on 1 machine (Payments)")
    assert "db-1  fixed" in i["comments"][-1] and "3.0.15-1~deb12u1 in the machine's inventory" in i["comments"][-1]

    resolve(s, fb, version="3.0.15-1~deb12u1")
    assert run(s, oid, fake)["closed"] == 1 and fake.status("PAY-1") == "done"
    assert "closing it" in i["comments"][-1] and "db-2  fixed" in i["comments"][-1]
    assert ledger(s, "ticket_closed")[-1]["why"] == {"fixed": 1}

    fb.status, fb.resolved_at = "open", None  # the fix regressed
    s.commit()
    assert run(s, oid, fake)["reopened"] == 1 and fake.status("PAY-1") == "new"
    assert "open again" in i["comments"][-1] and "db-2" in i["comments"][-1]
    assert ledger(s, "ticket_reopened")[-1]["reason"] == "regression" and len(fake.issues) == 1


def test_a_ticket_closed_by_hand_while_findings_are_open_is_reopened_with_the_evidence(org):
    _, s, oid = org
    fake = FakeJira()
    finding(s, machine(s, oid, "db-1"))
    setup(s, oid)
    run(s, oid, fake)
    fake.close_by_hand("OPS-1")
    assert run(s, oid, fake)["reopened"] == 1 and fake.status("OPS-1") == "new"
    assert "closed in the tracker while findings are still open" in fake.issues["OPS-1"]["comments"][-1]
    assert "accept the risk in Nimstead" in fake.issues["OPS-1"]["comments"][-1]
    assert ledger(s, "ticket_reopened")[-1]["reason"] == "closed_in_tracker"


def test_a_ticket_deleted_in_the_tracker_is_opened_afresh(org):
    _, s, oid = org
    fake = FakeJira()
    finding(s, machine(s, oid, "db-1"))
    setup(s, oid)
    run(s, oid, fake)
    del fake.issues["OPS-1"]
    assert run(s, oid, fake)["opened"] == 1 and list(fake.issues) == ["OPS-2"]
    assert s.scalar(select(Ticket.key)) == "OPS-2"


def test_a_create_that_reached_the_tracker_before_a_crash_is_found_by_its_label_not_repeated(org):
    _, s, oid = org
    fake = FakeJira()
    finding(s, machine(s, oid, "db-1"))
    cfg = setup(s, oid)
    (g,) = tickets.desired(s, oid, cfg)[0].values()
    s.add(Ticket(org_id=oid, fingerprint=g["fingerprint"], owner=None, action=g["action"], project="OPS"))  # the row, no key
    s.commit()
    fake.issues["OPS-7"] = {"project": "OPS", "summary": "x", "description": "", "labels": [f"nimstead-{g['fingerprint']}"],
                            "duedate": None, "status": "new", "comments": []}
    assert run(s, oid, fake)["opened"] == 1 and list(fake.issues) == ["OPS-7"]
    assert s.scalar(select(Ticket.key)) == "OPS-7" and fake.issues["OPS-7"]["summary"].startswith("Upgrade openssl")


def test_accepting_the_risk_closes_a_ticket_and_a_new_owner_moves_a_machine(org):
    _, s, oid = org
    fake = FakeJira()
    a, b = machine(s, oid, "db-1", "Payments"), machine(s, oid, "db-2", "Payments")
    fa, _ = finding(s, a), finding(s, b)
    setup(s, oid, routes=[{"owner": "Payments", "project": "PAY"}, {"owner": "Platform", "project": "SEC"}])
    run(s, oid, fake)
    b.owner = "Platform"
    s.commit()
    r = run(s, oid, fake)
    assert (r["opened"], r["updated"]) == (1, 1) and "db-2  now owned by Platform" in fake.issues["PAY-1"]["comments"][-1]
    assert fake.issues["SEC-2"]["summary"].endswith("on 1 machine (Platform)")
    fa.status, fa.accepted_until = "accepted", now() + timedelta(days=30)
    s.commit()
    assert run(s, oid, fake)["closed"] == 1
    assert "db-1  risk accepted in Nimstead until" in fake.issues["PAY-1"]["comments"][-1]
    assert ledger(s, "ticket_closed")[-1]["why"] == {"accepted": 1}


def test_at_most_max_writes_per_sync_most_urgent_first_and_the_rest_wait(org, monkeypatch):
    monkeypatch.setattr(tickets, "MAX_WRITES", 2)
    _, s, oid = org
    a = machine(s, oid, "web-1")
    for n, pkg in enumerate(("bash", "curl", "zlib", "perl")):
        finding(s, a, f"CVE-{n}", package=pkg, score=50 + n)
    finding(s, a, "CVE-9", package="glibc", score=10, kev=True)
    setup(s, oid)
    fake = FakeJira()
    r = run(s, oid, fake)
    assert (r["opened"], r["waiting"]) == (2, 3)
    assert [i["summary"].split()[1] for i in fake.issues.values()] == ["glibc", "perl"]  # KEV first, then worst score
    assert run(s, oid, fake)["waiting"] == 1 and len(fake.issues) == 4


def test_one_failing_project_costs_only_its_tickets_and_a_down_tracker_stops_the_sync(org, monkeypatch):
    _, s, oid = org
    finding(s, machine(s, oid, "pay-1", "Payments"))
    finding(s, machine(s, oid, "ops-1"))
    setup(s, oid, routes=[{"owner": "Payments", "project": "PAY"}])
    fake = FakeJira(projects=("PAY",))  # OPS doesn't exist
    r = run(s, oid, fake)
    assert (r["opened"], r["failed"]) == (1, 1) and "OPS" in s.get(TicketSettings, oid).last_sync["errors"][0]["error"]
    assert s.scalar(select(Ticket.error).where(Ticket.project == "OPS"))

    def down(req):
        raise httpx.ConnectError("connection refused")
    for n in range(8):
        finding(s, machine(s, oid, f"x-{n}", "Payments"), f"CVE-{n}", package=f"pkg{n}")
    r = tickets.sync(s, oid, http=httpx.Client(transport=httpx.MockTransport(down)))
    assert r["failed"] == tickets.MAX_FAILURES_IN_A_ROW and r["waiting"] > 0


def test_a_sync_already_running_is_left_alone_until_its_claim_is_stale(org):
    _, s, oid = org
    finding(s, machine(s, oid, "db-1"))
    cfg = setup(s, oid)
    cfg.sync_started = now() - timedelta(minutes=5)
    s.commit()
    fake = FakeJira()
    assert run(s, oid, fake) == {"skipped": True} and fake.calls == []
    cfg.sync_started = now() - timedelta(minutes=16)
    s.commit()
    assert run(s, oid, fake)["opened"] == 1 and s.get(TicketSettings, oid).sync_started is None


def test_nothing_is_sent_while_ticketing_is_off(org):
    _, s, oid = org
    finding(s, machine(s, oid, "db-1"))
    setup(s, oid, enabled=False)
    fake = FakeJira()
    assert run(s, oid, fake) == {"skipped": True} and fake.calls == []
    assert tickets.preview(s, oid, s.get(TicketSettings, oid))["open"][0]["title"].startswith("Upgrade openssl")
    assert fake.calls == []


def test_jira_data_center_bearer_search_and_a_screen_without_a_due_date(org):
    _, s, oid = org
    finding(s, machine(s, oid, "db-1"))
    cfg = setup(s, oid, user="", site="https://jira.acme.example")
    (g,) = tickets.desired(s, oid, cfg)[0].values()
    s.add(Ticket(org_id=oid, fingerprint=g["fingerprint"], owner=None, action=g["action"], project="OPS"))
    s.commit()
    fake = FakeJira(cloud=False, due_on_screen=False)
    assert run(s, oid, fake)["opened"] == 1  # searched /search (no /search/jql), then created without the due date
    assert ("GET", "/rest/api/2/search") in fake.calls and fake.issues["OPS-1"]["duedate"] is None


def test_replies_are_validated_and_links_are_never_taken_from_them(org):
    _, s, oid = org
    finding(s, machine(s, oid, "db-1"))
    setup(s, oid)
    fake = FakeJira()
    fake.override[r"^/rest/api/2/issue$"] = {"key": "javascript:alert(1)"}
    r = run(s, oid, fake)
    assert r["failed"] == 1 and s.scalar(select(Ticket.key)) is None
    fake.override = {r"^/rest/api/2/issue$": b"x" * (netguard.MAX_REPLY_BYTES + 1)}
    assert "larger than" in str(run(s, oid, fake)["errors"])

    def redirect(req):
        return httpx.Response(302, headers={"location": "https://evil.example/"})
    r = tickets.sync(s, oid, http=httpx.Client(transport=httpx.MockTransport(redirect)))
    assert "redirected" in r["errors"][0]["error"]


def test_the_gitlab_lifecycle_with_links_built_from_the_site(org):
    _, s, oid = org
    fake = FakeGitLab()
    a = machine(s, oid, "web-1", "Payments")
    f = finding(s, a)
    setup(s, oid, kind="gitlab", routes=[{"owner": "Payments", "project": "payments/app"}])
    assert run(s, oid, fake)["opened"] == 1
    issue = fake.issues[("payments/app", 1)]
    assert issue["title"] == "Upgrade `openssl` to `3.0.15-1~deb12u1` on 1 machine (Payments)" and issue["due_date"]
    assert ledger(s, "ticket_opened")[0]["link"] == "https://gitlab.example.com/payments/app/-/issues/1"
    idx = tickets.links(s, oid)
    assert tickets.ticket_for(idx, "payments", tickets.action_of("host", a.id, "Debian:12", "openssl")) == {
        "key": "#1", "url": "https://gitlab.example.com/payments/app/-/issues/1", "state": "open", "project": "payments/app"}
    fake.close_by_hand("payments/app", 1)
    assert run(s, oid, fake)["reopened"] == 1 and issue["state"] == "opened" and "closed in the tracker" in issue["notes"][-1]
    resolve(s, f, version="3.0.15-1~deb12u1")
    assert run(s, oid, fake)["closed"] == 1 and issue["state"] == "closed" and "web-1  fixed" in issue["notes"][-1]


def test_test_connection_says_what_it_found_in_words(org, monkeypatch):
    _, s, oid = org
    cfg = setup(s, oid, routes=[{"owner": "Payments", "project": "PAY"}])
    fake = FakeJira()
    monkeypatch.setattr(tickets, "http_client", client_for(fake))
    assert tickets.test_connection(cfg) == "Signed in to Jira as Nimstead bot; projects OPS, PAY found."
    cfg.routes = [{"owner": "Payments", "project": "NOPE"}]
    with pytest.raises(tickets.TrackerError, match="project NOPE wasn't found"):
        tickets.test_connection(cfg)
    cfg.token = sso.seal("wrong")
    with pytest.raises(tickets.TrackerError, match="HTTP 401: You are not authenticated"):
        tickets.test_connection(cfg)


def test_the_hourly_run_isolates_each_org(org, monkeypatch):
    _, s, oid = org
    finding(s, machine(s, oid, "db-1"))
    setup(s, oid)
    calls = []
    real = tickets.sync

    def flaky(sess, org_id, http=None):
        calls.append(org_id)
        raise RuntimeError("boom")
    monkeypatch.setattr(tickets, "sync", flaky)
    assert tickets.sync_all(s) == {"orgs_failed": 1} and calls == [oid]
    monkeypatch.setattr(tickets, "sync", lambda sess, org_id: real(sess, org_id, http=client_for(FakeJira())))
    assert tickets.sync_all(s)["opened"] == 1


# --- the API -----------------------------------------------------------------------------------------------------------

CFG = {"kind": "jira", "site": "https://acme.atlassian.net/", "user": "bot@example.com", "token": "tok", "default_project": "ops",
       "routes": [{"owner": "payments", "project": "pay"}], "min_priority": "fix-now", "enabled": False}


def member(env, c):
    from fastapi.testclient import TestClient

    from nimstead.app import ph
    from nimstead.db import User
    s = make_sessionmaker(env)()
    s.add(User(org_id=s.scalar(select(Org.id)), email="staff@example.com", password_hash=ph.hash("correct horse battery"), admin=False))
    s.commit()
    staff = TestClient(c.app)
    assert staff.post("/api/auth/login", json={"email": "staff@example.com", "password": "correct horse battery"}).status_code == 200
    return staff


def test_settings_keep_the_token_write_only_validate_and_are_recorded(org, env):
    c, s, oid = org
    machine(s, oid, "pay-1", "Payments")
    s.commit()
    r = c.put("/api/settings/tickets", json=CFG | {"token": None, "enabled": True})
    assert r.status_code == 422 and "Save a token" in r.json()["detail"]
    got = c.put("/api/settings/tickets", json=CFG).json()
    assert got["token_set"] and '"tok"' not in json.dumps(got) and got["site"] == "https://acme.atlassian.net"
    assert (got["default_project"], got["routes"], got["owners"]) == ("OPS", [{"owner": "Payments", "project": "PAY"}], ["Payments"])
    assert c.get("/api/settings/tickets").json() == got
    stored = make_sessionmaker(env)().get(TicketSettings, oid)
    assert stored.token != "tok" and sso.unseal(stored.token) == "tok"
    assert c.put("/api/settings/tickets", json=CFG | {"token": None}).json()["token_set"]  # omitted: kept
    logged = ledger(s, "tickets_configured")
    assert logged[0]["token"] == "[redacted]" and logged[0]["token_changed"] and not logged[1]["token_changed"]
    assert "tok" not in json.dumps([e.get("token") for e in logged]).replace("[redacted]", "")
    for patch, msg in (({"site": "http://acme.atlassian.net"}, "Site URL"), ({"site": "https://u:p@acme.atlassian.net"}, "Site URL"),
                       ({"site": "https://acme.atlassian.net/?x=1"}, "no query"), ({"default_project": "not a key"}, "Jira project key"),
                       ({"kind": "gitlab", "user": "", "token": "t"}, "GitLab project path"), ({"kind": "gitlab"}, "leave the email empty"),
                       ({"user": "not-an-email"}, "Email"), ({"routes": [{"owner": "Payments", "project": "PAY"}, {"owner": "PAYMENTS", "project": "OPS"}]}, "two routes"),
                       ({"site": "https://other.atlassian.net", "token": None}, "its own token")):
        r = c.put("/api/settings/tickets", json=CFG | {"token": None} | patch)
        assert r.status_code == 422 and msg in r.json()["detail"], (patch, r.text)


def test_a_new_site_needs_a_new_token_and_forgets_the_old_trackers_tickets(org):
    c, s, oid = org
    c.put("/api/settings/tickets", json=CFG)
    s.add(Ticket(org_id=oid, fingerprint="a" * 12, owner=None, action={}, project="OPS", key="OPS-1"))
    s.commit()
    r = c.put("/api/settings/tickets", json=CFG | {"kind": "gitlab", "site": "https://gitlab.example.com", "user": "", "token": "glpat",
                                                  "default_project": "platform/ops", "routes": []})
    assert r.status_code == 200 and r.json()["open_by_project"] == {}
    assert s.scalar(select(Ticket.id)) is None and ledger(s, "tickets_configured")[-1]["forgot_tickets"] == 1


def test_test_preview_and_sync_now_write_only_when_switched_on(org, monkeypatch):
    c, s, oid = org
    finding(s, machine(s, oid, "pay-1", "Payments"))
    finding(s, machine(s, oid, "web-1"), package="curl", fixed="8.14")
    s.commit()
    fake = FakeJira()
    monkeypatch.setattr(tickets, "http_client", client_for(fake))
    assert c.post("/api/settings/tickets/test").status_code == 409  # nothing saved yet
    c.put("/api/settings/tickets", json=CFG)
    assert c.post("/api/settings/tickets/test").json() == {"ok": True, "message": "Signed in to Jira as Nimstead bot; projects OPS, PAY found."}
    p = c.get("/api/settings/tickets/preview").json()
    assert sorted((t["project"], t["title"]) for t in p["open"]) == [
        ("OPS", "Upgrade curl to 8.14 on 1 machine"), ("PAY", "Upgrade openssl to 3.0.15-1~deb12u1 on 1 machine (Payments)")]
    assert (p["tickets"], p["findings"], p["skipped"]) == (2, 2, []) and fake.writes == []
    assert c.post("/api/settings/tickets/sync").status_code == 409  # off
    c.put("/api/settings/tickets", json=CFG | {"token": None, "enabled": True})
    assert c.post("/api/settings/tickets/sync").status_code == 202  # runs after the response (the test client waits for it)
    got = c.get("/api/settings/tickets").json()
    assert got["last_sync"]["opened"] == 2 and got["open_by_project"] == {"OPS": 1, "PAY": 1} and len(fake.issues) == 2
    for _ in range(4):
        c.post("/api/settings/tickets/test")
    assert c.post("/api/settings/tickets/test").status_code == 200 and c.post("/api/settings/tickets/test").status_code == 429


def test_only_admins_change_ticketing_and_members_and_read_only_tokens_see_the_links(org, env, monkeypatch):
    from test_api import INV
    c, s, oid = org
    token = c.post("/api/enroll-tokens", json={"owner": "Payments"}).json()["token"]
    a = c.post("/api/agent/enroll", json={"token": token, "hostname": "pay-1", "os_name": "Debian 12", "ecosystem": "Debian:12"}).json()
    h = {"Authorization": f"Bearer {a['agent_key']}"}
    c.post("/api/agent/inventory", json=INV, headers=h)
    fake = FakeJira()
    monkeypatch.setattr(tickets, "http_client", client_for(fake))
    c.put("/api/settings/tickets", json=CFG | {"enabled": True})
    c.post("/api/settings/tickets/sync")
    staff = member(env, c)
    ro = {"Authorization": "Bearer " + c.post("/api/tokens", json={"name": "ro"}).json()["token"]}
    for method, path in (("get", ""), ("put", ""), ("post", "/test"), ("get", "/preview"), ("post", "/sync")):
        kw = {"json": CFG} if method == "put" else {}
        assert getattr(staff, method)(f"/api/settings/tickets{path}", **kw).status_code == 403
        assert getattr(c, method)(f"/api/settings/tickets{path}", headers=ro, **kw).status_code in (401, 403)
    top = next(f for f in c.get("/api/findings", headers=ro).json() if f["package"] == "requests")
    link = c.get(f"/api/findings/{top['id']}", headers=ro).json()["ticket"]
    assert link == {"key": "PAY-1", "url": "https://acme.atlassian.net/browse/PAY-1", "state": "open", "project": "PAY"}
    assert next(x for x in staff.get("/api/summary").json()["top_actions"] if x["package"] == "requests")["tickets"] == [link]
    assert "fix-now" in fake.issues["PAY-1"]["labels"][1]
    # the fix lands: the machine's own inventory closes the ticket, naming the version it now has
    inv2 = {**INV, "packages": INV["packages"][:2] + [{"ecosystem": "PyPI", "name": "requests", "version": "2.32.4"}]}
    c.post("/api/agent/inventory", json=inv2, headers=h)
    c.post("/api/settings/tickets/sync")
    assert fake.status("PAY-1") == "done" and "pay-1  fixed" in fake.issues["PAY-1"]["comments"][-1]
    assert "2.32.4 in the machine's inventory" in fake.issues["PAY-1"]["comments"][-1]
    other = user(env, "b@example.com")
    assert other.get("/api/settings/tickets").json()["open_by_project"] == {} and not other.get("/api/settings/tickets").json()["token_set"]
