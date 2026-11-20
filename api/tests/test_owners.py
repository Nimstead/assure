"""Owners (DECISIONS 145): one team per asset, set in the drawer, in bulk or by the enrolment token, reused case-insensitively,
recorded in the ledger, and filterable on findings and in their CSV."""

import csv
import io

from sqlalchemy import select
from test_api import INV, user
from test_containers import IMG, entry, host, images, send

from nimstead.db import LedgerEntry, make_sessionmaker


def enrol_as(c, hostname, owner=None):
    token = c.post("/api/enroll-tokens", json={"owner": owner} if owner is not None else None).json()
    a = c.post("/api/agent/enroll", json={"token": token["token"], "hostname": hostname, "os_name": "Debian 12", "ecosystem": "Debian:12"}).json()
    c.post("/api/agent/inventory", json=INV, headers={"Authorization": f"Bearer {a['agent_key']}"})
    return token, a["asset_id"]


def test_an_enrolment_tokens_owner_is_every_enrolled_machines_owner(env):
    c = user(env)
    token, aid = enrol_as(c, "pay-1", "  Payments   team ")
    assert token["owner"] == "Payments team"
    assert next(t for t in c.get("/api/enroll-tokens").json() if t["id"] == token["id"])["owner"] == "Payments team"
    assert next(a for a in c.get("/api/assets").json() if a["id"] == aid)["owner"] == "Payments team"
    _, other = enrol_as(c, "web-1")
    assert next(a for a in c.get("/api/assets").json() if a["id"] == other)["owner"] is None


def test_an_owner_is_reused_in_any_case_cleared_when_empty_and_recorded(env):
    c = user(env)
    _, a = enrol_as(c, "pay-1", "Payments")
    _, b = enrol_as(c, "web-1")
    before = {r["id"]: r["score"] for r in c.get("/api/findings", params={"asset_id": b}).json()}
    r = c.patch(f"/api/assets/{b}", json={"owner": "payments"})
    assert r.status_code == 200 and r.json()["owner"] == "Payments"  # one team, never two spellings
    assert {r["id"]: r["score"] for r in c.get("/api/findings", params={"asset_id": b}).json()} == before
    assert c.patch(f"/api/assets/{a}", json={"owner": "   "}).json()["owner"] is None
    for bad in ("x" * 101, "Pay\nments", "Pay\x00"):
        assert c.patch(f"/api/assets/{a}", json={"owner": bad}).status_code == 422
    s = make_sessionmaker(env)()
    logged = [e.data for e in s.scalars(select(LedgerEntry).where(LedgerEntry.kind == "asset_context_changed").order_by(LedgerEntry.seq))]
    assert [d["owner"] for d in logged] == ["Payments", None]


def test_findings_filter_by_owner_and_the_csv_names_it(env):
    c = user(env)
    _, a = enrol_as(c, "pay-1", "Payments")
    _, b = enrol_as(c, "web-1")
    every = c.get("/api/findings").json()
    pay = c.get("/api/findings", params={"owner": "Payments"}).json()
    none = c.get("/api/findings", params={"owner": ""}).json()
    assert pay and none and {r["asset_id"] for r in pay} == {a} and {r["asset_id"] for r in none} == {b}
    assert len(pay) + len(none) == len(every)
    assert c.get("/api/findings/count", params={"owner": "Payments"}).json()["total"] == len(pay)
    assert sum(g["findings"] for g in c.get("/api/findings/groups", params={"owner": ""}).json()) == len(none)
    rows = list(csv.DictReader(io.StringIO(c.get("/api/findings.csv").text)))
    assert {r["hostname"]: r["owner"] for r in rows} == {"pay-1": "Payments", "web-1": ""}
    assert c.get(f"/api/findings/{pay[0]['id']}").json()["owner"] == "Payments"


def test_only_an_admin_sets_an_owner_and_an_image_takes_one(env):
    c = user(env)
    _, h = host(c, "docker-1")
    send(c, h, [entry()])
    s, (img,) = images(env)
    assert img.facts["image_id"] == IMG
    assert c.patch(f"/api/assets/{img.id}", json={"criticality": "high"}).status_code == 409
    assert c.patch(f"/api/assets/{img.id}", json={"owner": "Platform"}).json()["owner"] == "Platform"
    token = c.post("/api/tokens", json={"name": "ro"}).json()["token"]
    ro = {"Authorization": f"Bearer {token}"}
    assert c.patch(f"/api/assets/{img.id}", json={"owner": "Data"}, headers=ro).status_code in (401, 403)
    assert c.post("/api/enroll-tokens", json={"owner": "Data"}, headers=ro).status_code in (401, 403)
    assert next(a for a in c.get("/api/assets", headers=ro).json() if a["id"] == img.id)["owner"] == "Platform"


def test_an_owner_named_only_on_a_token_is_reused_too(env):
    c = user(env)
    c.post("/api/enroll-tokens", json={"owner": "Data Platform"})  # no machine has joined with it yet
    _, a = enrol_as(c, "web-1")
    assert c.patch(f"/api/assets/{a}", json={"owner": "data   platform"}).json()["owner"] == "Data Platform"
    assert c.post("/api/enroll-tokens", json={"owner": "DATA PLATFORM"}).json()["owner"] == "Data Platform"
