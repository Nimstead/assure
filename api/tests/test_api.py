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
    assert 'TOKEN="${NIMSTEAD_TOKEN:-}"' in r.text  # the token comes from the environment: argv is visible to every local user
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



def test_one_attacker_cannot_lock_out_the_account_everywhere(env):
    c = user(env)
    attacker = TestClient(c.app, client=("203.0.113.9", 4444))
    bad = {"email": "a@example.com", "password": "wrong password!"}
    assert [attacker.post("/api/auth/login", json=bad).status_code for _ in range(11)][-1] == 429
    owner = TestClient(c.app, client=("198.51.100.7", 5555))  # the real admin, elsewhere (e.g. break-glass while SSO is down)
    assert owner.post("/api/auth/login", json={**bad, "password": "correct horse battery"}).status_code == 200


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


def test_inventory_rate_limited_per_asset(env, monkeypatch):
    import nimstead.app as appmod
    monkeypatch.setattr(appmod, "INVENTORY_MIN_SECONDS", 3600)
    c = user(env)
    h = {"Authorization": f"Bearer {enrol(c)['agent_key']}"}
    assert c.post("/api/agent/inventory", json=INV, headers=h).status_code == 200
    assert c.post("/api/agent/inventory", json=INV, headers=h).status_code == 429
    h2 = {"Authorization": f"Bearer {enrol(c)['agent_key']}"}  # other assets unaffected
    assert c.post("/api/agent/inventory", json=INV, headers=h2).status_code == 200


def test_windows_installer_served_and_parses(env, tmp_path):
    import shutil
    import subprocess
    c = TestClient(create_app(env))
    r = c.get("/install.ps1")
    assert r.status_code == 200 and '$Server = "http://testserver"' in r.text
    assert c.get("/install.ps1", headers={"Host": "evil$(calc)"}).status_code == 400
    if shutil.which("powershell"):  # syntax check with the real PowerShell parser
        f = tmp_path / "i.ps1"
        f.write_text(r.text)
        cmd = ("$e=$null; [void][System.Management.Automation.Language.Parser]::ParseFile('" + str(f) +
               "',[ref]$null,[ref]$e); $e.Count")
        assert subprocess.run(["powershell", "-NoProfile", "-Command", cmd], capture_output=True, text=True).stdout.strip() == "0"


def test_non_admins_can_read_but_not_change_remediation_or_assets(env):
    from sqlalchemy import select
    from sqlalchemy.orm import sessionmaker

    from nimstead.app import create_app, ph
    from nimstead.db import User, make_engine
    app = create_app(env)
    admin = TestClient(app)
    admin.post("/api/auth/signup", json={"email": "owner@example.com", "password": "correct horse battery", "org_name": "O"})
    s = sessionmaker(make_engine(env))()
    org_id = s.scalar(select(User.org_id).where(User.email == "owner@example.com"))
    s.add(User(org_id=org_id, email="staff@example.com", password_hash=ph.hash("correct horse battery"), admin=False))  # e.g. SSO-created
    s.commit()
    staff = TestClient(app)
    assert staff.post("/api/auth/login", json={"email": "staff@example.com", "password": "correct horse battery"}).status_code == 200
    for method, path, body in (("post", "/api/enroll-tokens", {}), ("delete", "/api/enroll-tokens/x", None),
                               ("delete", "/api/assets/x", None), ("patch", "/api/assets/x", {"ring": 0}),
                               ("post", "/api/assets", {"name": "app"}), ("post", "/api/findings/x/accept", {"reason": "r", "days": 30}),
                               ("post", "/api/remediation/jobs", {"asset_id": "x", "ecosystem": "Debian:12", "package": "p"}),
                               ("post", "/api/remediation/jobs/x/approve", None), ("patch", "/api/settings", {"remediation_mode": "auto"}),
                               ("post", "/api/assets/x/sbom", {})):  # replacing an SBOM resolves findings and writes evidence
        r = getattr(staff, method)(path, **({"json": body} if body is not None else {}))
        assert r.status_code == 403, (method, path, r.status_code)
    for path in ("/api/summary", "/api/findings", "/api/assets", "/api/remediation/jobs", "/api/settings"):
        assert staff.get(path).status_code == 200, path


def test_agent_version_flags_outdated_agents(env):
    from nimstead.app import latest_agent_version
    latest = latest_agent_version()
    assert latest  # read from the agent file the server hands out
    c = user(env)
    h = {"Authorization": f"Bearer {enrol(c)['agent_key']}"}
    asset = lambda: c.get("/api/assets").json()[0]  # noqa: E731
    c.post("/api/agent/inventory", json=INV, headers=h)  # agent too old to report a version
    assert asset()["agent_version"] == "" and asset()["agent_outdated"]
    c.post("/api/agent/inventory", json={**INV, "agent_version": latest}, headers=h)
    assert asset()["agent_version"] == latest and not asset()["agent_outdated"]


def test_signup_is_rate_limited_per_address(env):
    c = TestClient(create_app(env))
    codes = [c.post("/api/auth/signup", json={"email": f"u{i}@example.com", "password": "correct horse battery",
                                              "org_name": "X"}).status_code for i in range(11)]
    assert codes == [201] * 10 + [429]  # signup has to say whether an email is taken, so probing stays slow


def test_distributed_guessing_cannot_lock_the_owner_out(env):
    from sqlalchemy.orm import sessionmaker

    from nimstead.db import AuthFailure, make_engine
    c = user(env, "admin@example.com")
    c.post("/api/auth/logout")
    s = sessionmaker(make_engine(env))()
    s.add_all(AuthFailure(key="email:admin@example.com") for _ in range(100))  # the email-wide cap, reached from elsewhere
    s.commit()
    good = {"email": "admin@example.com", "password": "correct horse battery"}
    assert c.post("/api/auth/login", json=good).json()["mfa"] == "setup"  # from an address with no failures: let through
    s.add(AuthFailure(key="ip:testclient"))
    s.commit()
    assert c.post("/api/auth/login", json=good).status_code == 429  # an address that has been guessing is stopped


def test_ipv6_clients_are_throttled_by_their_64():
    from types import SimpleNamespace

    from nimstead.app import client_key
    key = lambda ip: client_key(SimpleNamespace(client=SimpleNamespace(host=ip)))  # noqa: E731
    assert key("2001:db8:1:2::1") == key("2001:db8:1:2:ffff::9") == "2001:db8:1:2::/64"
    assert key("2001:db8:1:3::1") != key("2001:db8:1:2::1") and key("203.0.113.7") == "203.0.113.7"


def test_signup_never_says_whether_an_email_has_an_account(env, monkeypatch):
    """Default mode: the first account sets the server up; after that the response is the same for a new address and a
    taken one, and the next step goes to the address itself."""
    from test_notify import FakeSMTP

    from nimstead import notify
    monkeypatch.delenv("NIMSTEAD_OPEN_SIGNUP")
    c = TestClient(create_app(env))
    body = lambda e: {"email": e, "password": "correct horse battery", "org_name": "Acme"}  # noqa: E731
    assert c.post("/api/auth/signup", json=body("first@example.com")).status_code == 201  # empty server: instant
    c.post("/api/auth/logout")
    taken, new = c.post("/api/auth/signup", json=body("first@example.com")), c.post("/api/auth/signup", json=body("new@example.com"))
    assert taken.status_code == new.status_code == 403 and taken.json() == new.json()  # no email set up: same refusal

    monkeypatch.setenv("NIMSTEAD_SMTP_URL", "smtp://mail.example.com:587")
    monkeypatch.setenv("NIMSTEAD_SMTP_FROM", "nimstead@example.com")
    monkeypatch.setattr(notify.smtplib, "SMTP", FakeSMTP)
    FakeSMTP.sent, FakeSMTP.fail, FakeSMTP.tls = [], False, True
    taken, new = c.post("/api/auth/signup", json=body("first@example.com")), c.post("/api/auth/signup", json=body("new@example.com"))
    assert taken.status_code == new.status_code == 202
    assert {k: v for k, v in taken.json().items() if k != "email"} == {k: v for k, v in new.json().items() if k != "email"}
    assert "set-cookie" not in taken.headers and "set-cookie" not in new.headers
    notify.flush()
    mails = {m["To"]: m.get_content() for m in FakeSMTP.sent if not isinstance(m, tuple)}
    assert "already has one" in mails["first@example.com"] and "/signin" in mails["first@example.com"]
    link = next(ln for ln in mails["new@example.com"].splitlines() if "/api/auth/signup/confirm?" in ln)
    browser = TestClient(c.app)
    assert browser.get(link).status_code == 200 and browser.get("/api/me").status_code == 401  # opening it isn't enough
    assert browser.post(link, data={"password": "short"}).status_code == 422  # still usable after a bad password
    r = browser.post(link, data={"password": "chosen by the owner"}, follow_redirects=False)
    assert r.status_code == 303 and browser.get("/api/me").json()["email"] == "new@example.com"
    assert TestClient(c.app).post(link, data={"password": "chosen by the owner"}).status_code == 404  # single use


def mfa_login(c, email, password="correct horse battery"):  # noqa: S107  the test password
    """Sign in as a password user, enrolling TOTP first if the server asks (admins must). Returns the final answer."""
    import time

    from nimstead import mfa
    body = {"email": email, "password": password}
    r = c.post("/api/auth/login", json=body)
    if r.status_code == 200 and r.json().get("mfa") == "setup":
        d = r.json()
        r = c.post("/api/auth/login", json={**body, "setup": d["setup"], "code": mfa.code(d["secret"], int(time.time() // 30))})
        r.secret = d["secret"]
    return r
