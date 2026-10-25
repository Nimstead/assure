from pathlib import Path

from fastapi.testclient import TestClient

from nimstead.app import create_app

FIX = Path(__file__).parent / "fixtures" / "osv"


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


def test_install_script_and_agent_served(env):
    c = TestClient(create_app(env))
    r = c.get("/install.sh")
    assert r.status_code == 200 and 'SERVER="http://testserver"' in r.text and "__SERVER__" not in r.text
    assert c.get("/install.sh", headers={"Host": "evil$(id)"}).status_code == 400
    assert b"def collect" in c.get("/agent/nimstead_agent.py").content


def test_feed_update_rescans_existing_assets(env):
    from sqlalchemy.orm import sessionmaker

    from nimstead.db import Asset, Kev, make_engine
    from nimstead.scan import rescan

    c = user(env)
    a = enrol(c)
    c.post("/api/agent/inventory", json=INV, headers={"Authorization": f"Bearer {a['agent_key']}"})
    target = next(f for f in c.get("/api/findings").json() if not f["kev"] and f["fixed_version"])
    s = sessionmaker(make_engine(env))()
    s.add(Kev(cve=target["vuln_id"], date_added="2026-10-25"))  # newly exploited, no new agent report
    s.commit()
    rescan(s, s.get(Asset, a["asset_id"]), inventory_received=False)
    assert c.get(f"/api/findings/{target['id']}").json()["priority"] == "fix-now"


def test_enrol_tokens_expire_and_revoke(env):
    from sqlalchemy import update
    from sqlalchemy.orm import sessionmaker

    from nimstead.db import EnrollToken, make_engine, now

    c = user(env)
    t1 = c.post("/api/enroll-tokens").json()
    c.delete(f"/api/enroll-tokens/{t1['id']}")
    assert c.post("/api/agent/enroll", json={"token": t1["token"], "hostname": "x"}).status_code == 403
    t2 = c.post("/api/enroll-tokens").json()
    s = sessionmaker(make_engine(env))()
    s.execute(update(EnrollToken).values(expires=now()))
    s.commit()
    assert c.post("/api/agent/enroll", json={"token": t2["token"], "hostname": "x"}).status_code == 403
    assert {t["revoked"] for t in c.get("/api/enroll-tokens").json()} == {True, False}
    assert user(env, "b@example.com").delete(f"/api/enroll-tokens/{t2['id']}").status_code == 404  # other tenant


def test_asset_delete(env):
    c = user(env)
    a = enrol(c)
    c.post("/api/agent/inventory", json=INV, headers={"Authorization": f"Bearer {a['agent_key']}"})
    assert user(env, "b@example.com").delete(f"/api/assets/{a['asset_id']}").status_code == 404
    assert c.delete(f"/api/assets/{a['asset_id']}").status_code == 204
    assert c.get("/api/assets").json() == [] and c.get("/api/findings").json() == []
    assert c.post("/api/agent/inventory", json=INV, headers={"Authorization": f"Bearer {a['agent_key']}"}).status_code == 401


def test_request_guards(env):
    c = user(env)
    assert c.post("/api/enroll-tokens", headers={"Origin": "https://evil.example"}).status_code == 403
    assert c.post("/api/enroll-tokens", headers={"Origin": "http://testserver"}).status_code == 201
    assert c.post("/api/agent/inventory", content=b"x", headers={"Content-Length": str(11 * 1024 * 1024)}).status_code == 413
    assert c.get("/api/findings", params={"limit": -1}).status_code == 422


def test_login_throttled_after_repeated_failures(env):
    c = user(env)
    bad = {"email": "a@example.com", "password": "wrong password!"}
    assert [c.post("/api/auth/login", json=bad).status_code for _ in range(10)] == [401] * 10
    assert c.post("/api/auth/login", json=bad).status_code == 429
    assert c.post("/api/auth/login", json={**bad, "password": "correct horse battery"}).status_code == 429


def test_serves_web_ui_with_spa_fallback(env, tmp_path, monkeypatch):
    import nimstead.app as appmod
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<div id=root></div>")
    (dist / "assets" / "app.js").write_text("console.log(1)")
    monkeypatch.setattr(appmod, "WEB_DIST", dist)
    c = TestClient(create_app(env))
    assert c.get("/").text == "<div id=root></div>"
    assert c.get("/findings?f=abc").text == "<div id=root></div>"  # client-side route
    assert c.get("/assets/app.js").text == "console.log(1)"
    assert c.get("/api/nope").status_code == 404
    assert c.get("/install.sh").status_code == 200  # real routes still win
