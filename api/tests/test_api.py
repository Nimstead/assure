import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from nimstead.app import create_app
from nimstead.db import Advisory, Kev, make_engine
from nimstead.match import normalize_ecosystem

FIX = Path(__file__).parent / "fixtures" / "osv"


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("NIMSTEAD_SECURE_COOKIES", "0")
    url = f"sqlite:///{tmp_path}/t.db"
    s = sessionmaker(make_engine(url))()
    for f in ("Debian_12__openssl.json", "PyPI__requests.json"):
        d = json.loads((FIX / f).read_text())
        for r in d["records"]:
            s.merge(Advisory(id=r["id"], ecosystem=normalize_ecosystem(d["ecosystem"]), package=d["name"], record=r))
    s.add(Kev(cve="CVE-2024-35195", date_added="2024-06-01"))  # pretend-KEV to test the override
    s.commit()
    import nimstead.app as appmod
    monkeypatch.setattr(appmod, "SECURE_COOKIES", False)
    return url


def user(url, email="a@example.com"):
    c = TestClient(create_app(url))
    r = c.post("/api/auth/signup", json={"email": email, "password": "correct horse battery", "org_name": "Acme"})
    assert r.status_code == 201, r.text
    return c


def enrol(c):
    token = c.post("/api/enroll-tokens").json()["token"]
    r = c.post("/api/agent/enroll", json={"token": token, "hostname": "web-1", "os_name": "Debian 12", "ecosystem": "Debian:12"})
    assert r.status_code == 201
    return r.json()


INV = {"ecosystem": "Debian:12", "packages": [
    {"ecosystem": "Debian:12", "name": "libssl3", "version": "3.0.11-1~deb12u2", "source": "openssl"},
    {"ecosystem": "Debian:12", "name": "openssl", "version": "3.0.11-1~deb12u2", "source": "openssl"},
    {"ecosystem": "PyPI", "name": "requests", "version": "2.31.0"},
]}


def test_end_to_end_findings_and_resolution(env):
    c = user(env)
    agent = enrol(c)
    h = {"Authorization": f"Bearer {agent['agent_key']}"}
    r = c.post("/api/agent/inventory", json=INV, headers=h)
    assert r.status_code == 200, r.text
    first = r.json()["open"]
    assert first > 10

    findings = c.get("/api/findings").json()
    assert len(findings) == first  # libssl3 + openssl binaries collapse onto one source package
    assert findings == sorted(findings, key=lambda f: -f["score"])
    top = findings[0]
    assert top["vuln_id"] == "CVE-2024-35195" and top["kev"] and top["priority"] == "fix-now"

    s = c.get("/api/summary").json()
    assert s["assets"] == 1 and s["top_actions"][0]["package"] == "requests"

    # upgrade requests -> its findings resolve with a timestamp (patch evidence)
    inv2 = {**INV, "packages": INV["packages"][:2] + [{"ecosystem": "PyPI", "name": "requests", "version": "2.32.4"}]}
    r = c.post("/api/agent/inventory", json=inv2, headers=h).json()
    assert r["resolved"] >= 1
    resolved = c.get("/api/findings", params={"status": "resolved"}).json()
    assert any(f["package"] == "requests" and f["resolved_at"] for f in resolved)


def test_context_changes_score(env):
    c = user(env)
    a = enrol(c)
    c.post("/api/agent/inventory", json=INV, headers={"Authorization": f"Bearer {a['agent_key']}"})
    before = {f["id"]: f["score"] for f in c.get("/api/findings").json()}
    c.patch(f"/api/assets/{a['asset_id']}", json={"internet_facing": True, "criticality": "critical"})
    after = {f["id"]: f["score"] for f in c.get("/api/findings").json()}
    assert all(after[k] >= before[k] for k in before) and after != before


def test_tenant_isolation(env):
    a, b = user(env, "a@example.com"), user(env, "b@example.com")
    agent = enrol(a)
    a.post("/api/agent/inventory", json=INV, headers={"Authorization": f"Bearer {agent['agent_key']}"})
    fid = a.get("/api/findings").json()[0]["id"]
    assert b.get("/api/findings").json() == []
    assert b.get("/api/assets").json() == []
    assert b.get(f"/api/findings/{fid}").status_code == 404
    assert b.patch(f"/api/assets/{agent['asset_id']}", json={"criticality": "low"}).status_code == 404


def test_only_enrolled_assets_can_report(env):
    c = TestClient(create_app(env))
    assert c.post("/api/agent/enroll", json={"token": "nme_forged", "hostname": "x"}).status_code == 403
    assert c.post("/api/agent/inventory", json=INV, headers={"Authorization": "Bearer nma_forged"}).status_code == 401
    assert c.post("/api/agent/inventory", json=INV).status_code == 401


def test_auth(env):
    c = user(env)
    assert c.get("/api/me").json()["org"] == "Acme"
    c.post("/api/auth/logout")
    assert c.get("/api/me").status_code == 401
    assert c.post("/api/auth/login", json={"email": "a@example.com", "password": "wrong password!"}).status_code == 401
    assert c.post("/api/auth/login", json={"email": "a@example.com", "password": "correct horse battery"}).status_code == 200
    assert c.post("/api/auth/signup", json={"email": "a@example.com", "password": "correct horse battery", "org_name": "X"}).status_code == 409
    assert c.post("/api/auth/signup", json={"email": "z@example.com", "password": "short", "org_name": "X"}).status_code == 422
