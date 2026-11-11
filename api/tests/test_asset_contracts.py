"""Published asset response contracts and inventory replacement boundaries."""

import json
from pathlib import Path

from sqlalchemy import select
from test_api import INV, enrol, user

from nimstead.db import Asset, InstalledPackage, LedgerEntry, RemediationJob, make_sessionmaker

SCHEMAS = json.loads((Path(__file__).parents[2] / "docs/reference/openapi.json").read_text())["components"]["schemas"]


def fields_match(name, row):
    """Check actual fields against the published closed contract."""
    schema = SCHEMAS[name]
    assert set(schema["required"]) <= row.keys() <= schema["properties"].keys()
    assert schema["additionalProperties"] is False


def test_asset_variants_and_patch_context(env):
    c = user(env)
    e = enrol(c)
    fields_match("AgentEnrolment", e)
    assert enrol(c)["asset_id"] != e["asset_id"]
    h = {"Authorization": "Bearer " + e["agent_key"]}
    fields_match("InventoryResult", c.post("/api/agent/inventory", headers=h, json=INV).json())
    fields_match("CreatedApplication", c.post("/api/assets", json={"name": "fixture-app"}).json())
    target = c.post("/api/targets", json={"hostname": "fixture.example.com"}).json()
    fields_match("ExternalAsset", target)
    assert not target["verified"] and target["verified_at"] is None
    with make_sessionmaker(env)() as s:
        s.add(InstalledPackage(asset_id=e["asset_id"], ecosystem="WinApp", name="unmapped fixture", version="1", origin="agent"))
        s.commit()
    rows = c.get("/api/assets").json()
    for row in rows:
        fields_match({"host": "HostAsset", "application": "ApplicationAsset", "external": "ExternalAsset"}[row["kind"]], row)
    host = next(row for row in rows if row["id"] == e["asset_id"])
    assert host["open_by_priority"] and host["apps"] == {"assessed": 0, "inventory_only": 1}
    patched = c.patch(f"/api/assets/{e['asset_id']}", json={}).json()
    fields_match("HostAsset", patched)
    assert patched["open_by_priority"] == {} and "apps" not in patched
    coverage = c.get("/api/coverage").json()
    fields_match("ApplicationCoverage", coverage)
    assert coverage["not_assessed"] == [{"name": "unmapped fixture", "publisher": None, "hosts": 1}]


def test_partial_inventory_and_missing_facts_retain_prior_data(env):
    c = user(env)
    e = enrol(c)
    h = {"Authorization": "Bearer " + e["agent_key"]}
    assert c.post("/api/agent/inventory", headers=h, json={**INV, "facts": {"pending_reboot": True}}).status_code == 200
    partial = {"packages": [], "facts": {"too_long": "x" * 501}, "collection": {
        "v": 1, "sources": {"package_db": {"state": "partial", "count": 1}}}}
    assert c.post("/api/agent/inventory", headers=h, json=partial).status_code == 200
    with make_sessionmaker(env)() as s:
        a = s.get(Asset, e["asset_id"])
        assert a.facts == {"pending_reboot": True}
        assert a.collection["sources"]["host_facts"]["state"] == "failed"
        assert len(s.scalars(select(InstalledPackage).where(InstalledPackage.asset_id == a.id)).all()) == len(INV["packages"])
    assert c.post("/api/agent/inventory", headers=h, json={"packages": [], "collection": None}).status_code == 200  # an agent too old to send one
    with make_sessionmaker(env)() as s:
        a = s.get(Asset, e["asset_id"])
        assert a.facts == {"pending_reboot": True} and a.collection is None
        assert not s.scalars(select(InstalledPackage).where(InstalledPackage.asset_id == a.id)).all()


def test_summary_fields_and_deleted_asset_ledger(env):
    c = user(env)
    e = enrol(c)
    assert c.post("/api/agent/inventory", headers={"Authorization": "Bearer " + e["agent_key"]}, json=INV).status_code == 200
    with make_sessionmaker(env)() as s:
        a = s.get(Asset, e["asset_id"])
        s.add(RemediationJob(org_id=a.org_id, asset_id=a.id, status="aborted", manager="apt", action_key="Debian:12|openssl",
                             packages=[], finding_ids=[], summary="fixture attempt", created_by="fixture", error="fixture"))
        s.commit()
    summary = c.get("/api/summary").json()
    fields_match("FleetSummary", summary)
    assert summary["top_actions"] and summary["attention"]
    for action in summary["top_actions"]:
        fields_match("SummaryAction", action)
    for job in summary["attention"]:
        fields_match("RemediationJob", job)
    assert c.delete(f"/api/assets/{e['asset_id']}").status_code == 204
    with make_sessionmaker(env)() as s:
        assert s.get(Asset, e["asset_id"]) is None
        assert s.scalar(select(LedgerEntry).where(LedgerEntry.subject == e["asset_id"], LedgerEntry.kind == "asset_deleted"))


def test_sbom_bearer_precedence_and_host_last_seen(env):
    c = user(env)
    e = enrol(c)
    body = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}
    path = f"/api/assets/{e['asset_id']}/sbom"
    assert c.post(path, headers={"Authorization": "Bearer wrong"}, json=body).status_code == 401
    with make_sessionmaker(env)() as s:
        a = s.get(Asset, e["asset_id"])
        old_seen = a.last_seen
    assert c.post(path, json=body).status_code == 200
    with make_sessionmaker(env)() as s:
        assert s.get(Asset, e["asset_id"]).last_seen > old_seen
