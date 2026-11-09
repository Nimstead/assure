"""Finding and database reference contracts exercised through actual API/storage paths."""

import csv
import io
import json
import re
from pathlib import Path

import pytest
from sqlalchemy import delete, select, text
from sqlalchemy.exc import IntegrityError
from test_api import INV, enrol, user

from nimstead.db import Advisory, Asset, Base, Finding, InstalledPackage, Org, make_sessionmaker
from nimstead.scan import rescan

REFERENCE = Path(__file__).resolve().parents[2] / "docs" / "reference"


def _host(env):
    c = user(env)
    a = enrol(c)
    headers = {"Authorization": f"Bearer {a['agent_key']}"}
    assert c.post("/api/agent/inventory", json=INV, headers=headers).status_code == 200
    return c, a, headers


def test_finding_response_fields_match_reference_and_exported_schemas(env):
    c, _, _ = _host(env)
    schemas = json.loads((REFERENCE / "openapi.json").read_text())["components"]["schemas"]
    documented = set(re.findall(r"`([a-z][a-z0-9_]*)`", (REFERENCE / "findings.md").read_text()))
    full = c.get("/api/findings").json()
    compact = c.get("/api/findings", params={"view": "list"}).json()
    detail = c.get(f"/api/findings/{full[0]['id']}").json()
    groups = c.get("/api/findings/groups").json()
    assert full and compact and groups
    for name, rows in (("FindingRow", full), ("FindingCompact", compact), ("FindingDetail", [detail]), ("FindingGroup", groups)):
        fields = set(schemas[name]["properties"])
        assert fields == set(schemas[name]["required"]) and fields <= documented
        assert not schemas[name]["additionalProperties"]
        assert all(set(row) == fields for row in rows)
    assert c.get("/api/findings/count").json() == {"total": len(full)}
    assert all(len(row["reasons"]) <= 1 for row in compact)
    assert "accepted_until" not in detail
    assert detail["due"] is not None


def test_false_overdue_is_no_filter_and_grouping_ignores_true(env):
    c, _, _ = _host(env)
    total = c.get("/api/findings/count").json()
    assert total["total"] > 0
    assert c.get("/api/findings/count", params={"overdue": False}).json() == total
    assert c.get("/api/findings/count", params={"overdue": True}).json() == {"total": 0}
    assert c.get("/api/findings/groups", params={"overdue": True}).json() == c.get("/api/findings/groups").json()
    assert c.get("/api/findings/count", params={"q": "%"}).json() == total


def test_single_acceptance_can_follow_resolution_and_revoke_retains_timestamp(env):
    c, _, h = _host(env)
    changed = {**INV, "packages": INV["packages"][:2] + [{"ecosystem": "PyPI", "name": "requests", "version": "2.32.4"}]}
    assert c.post("/api/agent/inventory", json=changed, headers=h).status_code == 200
    resolved = c.get("/api/findings", params={"status": "resolved"}).json()[0]
    assert resolved["resolved_at"]
    fid = resolved["id"]
    accepted = c.post(f"/api/findings/{fid}/accept", json={"reason": "Documented acceptance contract", "days": 30}).json()
    assert accepted["status"] == "accepted" and accepted["resolved_at"] == resolved["resolved_at"]
    revoked = c.post(f"/api/findings/{fid}/revoke-acceptance", json={"reason": "Reassess this result"}).json()
    assert revoked["status"] == "open" and revoked["resolved_at"] == resolved["resolved_at"]
    assert revoked["due"] is None and c.get(f"/api/findings/{fid}").json()["due"] is not None


def test_rescan_can_resolve_from_feed_absence_and_commits_caller_changes(env):
    c, a, _ = _host(env)
    factory = make_sessionmaker(env)
    with factory() as s:
        asset = s.get(Asset, a["asset_id"])
        oid = asset.org_id
        s.get(Org, oid).name = "Caller change committed by rescan"
        s.execute(delete(Advisory).where(Advisory.ecosystem == "PyPI", Advisory.package == "requests"))
        result = rescan(s, asset, inventory_received=False)
        assert result["resolved"] > 0
    with factory() as s:
        assert s.get(Org, oid).name == "Caller change committed by rescan"
        assert s.scalar(select(InstalledPackage).where(InstalledPackage.asset_id == asset.id, InstalledPackage.name == "requests"))
    assert any(f["package"] == "requests" for f in c.get("/api/findings", params={"status": "resolved"}).json())
    factory.kw["bind"].dispose()


def test_csv_columns_match_reference(env):
    c, _, _ = _host(env)
    factory = make_sessionmaker(env)
    with factory() as s:
        s.scalar(select(Finding)).summary = "=SUM(1,2)"
        s.commit()
    r = c.get("/api/findings.csv")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert "nimstead-findings-open.csv" in r.headers["content-disposition"]
    rows = list(csv.reader(io.StringIO(r.text)))
    expected = ["hostname", "package", "installed_version", "fixed_version", "vuln_id", "priority", "score", "cvss", "epss",
                "kev", "status", "first_seen", "last_seen", "resolved_at", "summary"]
    assert rows[0] == expected and len(rows) > 1
    assert any(row[-1] == "'=SUM(1,2)" for row in rows[1:])
    assert all(" " in row[11] for row in rows[1:])
    reference = (REFERENCE / "findings.md").read_text()
    assert all(f"`{name}`" in reference for name in expected)
    factory.kw["bind"].dispose()


def test_sqlite_factory_defaults_json_tracking_and_explicit_commit():
    factory = make_sessionmaker("sqlite://")
    engine = factory.kw["bind"]
    try:
        with factory() as s:
            org = Org(name="Original")
            assert org.id is None and org.created is None
            s.add(org)
            s.commit()
            oid = org.id
            assert org.created.tzinfo is None
            org.sla_days["next"] = 1
            s.commit()
            s.expire(org, ["sla_days"])
            assert org.sla_days == {}
            org.sla_days = {"next": 2}
            s.commit()
            org.name = "Uncommitted"
        with factory() as s:
            assert s.get(Org, oid).name == "Original"
            assert s.get(Org, oid).sla_days == {"next": 2}
            assert s.scalar(text("PRAGMA foreign_keys")) == 1
            s.add(InstalledPackage(asset_id="absent", ecosystem="PyPI", name="test", version="1"))
            with pytest.raises(IntegrityError):
                s.flush()
            s.rollback()
        reference = (REFERENCE / "database.md").read_text()
        assert all(f"`{mapper.class_.__name__}`" in reference for mapper in Base.registry.mappers)
    finally:
        engine.dispose()
