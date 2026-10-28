"""Security round 4 (tasks/plan-0.4-security.md): sign-up pre-hijack, body cap, quotas, AI budget, headers, ledger gaps,
user management, MFA, password change/reset, API tokens, CSV export."""

import time

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker
from test_api import INV, enrol, mfa_login, user
from test_notify import FakeSMTP

from nimstead import mfa, notify
from nimstead.app import create_app
from nimstead.db import LedgerEntry, User, WebSession, make_engine

PW = "correct horse battery"


def now_code(secret: str, offset: int = 0) -> str:
    return mfa.code(secret, int(time.time() // 30) + offset)


@pytest.fixture
def mail(monkeypatch):
    monkeypatch.setenv("NIMSTEAD_SMTP_URL", "smtp://mail.example.com:587")
    monkeypatch.setenv("NIMSTEAD_SMTP_FROM", "nimstead@example.com")
    monkeypatch.setattr(notify.smtplib, "SMTP", FakeSMTP)
    FakeSMTP.sent, FakeSMTP.fail, FakeSMTP.tls = [], False, True

    def inbox(to: str) -> str:
        notify.flush()
        return [m.get_content() for m in FakeSMTP.sent if not isinstance(m, tuple) and m["To"] == to][-1]
    return inbox


def link_in(text: str) -> str:
    return next(ln for ln in text.splitlines() if "/api/auth/signup/confirm?" in ln)


def kinds(env) -> list[str]:
    return [e.kind for e in sessionmaker(make_engine(env))().scalars(select(LedgerEntry))]


# --- S1: emailed sign-up never carries the requester's password ---------------------------------------------------

def test_attacker_cannot_preset_the_password_of_an_address_they_dont_own(env, monkeypatch, mail):
    monkeypatch.delenv("NIMSTEAD_OPEN_SIGNUP")
    c = TestClient(create_app(env))
    assert c.post("/api/auth/signup", json={"email": "owner@example.com", "password": PW, "org_name": "Op"}).status_code == 201
    attacker = TestClient(c.app)
    r = attacker.post("/api/auth/signup", json={"email": "victim@corp.com", "password": "attacker knows this", "org_name": "Corp"})
    assert r.status_code == 202
    first = link_in(mail("victim@corp.com"))
    attacker.post("/api/auth/signup", json={"email": "victim@corp.com", "org_name": "Corp"})  # a newer link replaces it
    second = link_in(mail("victim@corp.com"))
    victim = TestClient(c.app)
    assert victim.get(first).status_code == 404
    assert "type=password" in victim.get(second).text
    assert victim.post(second, data={"password": "the victim's own pass"}, follow_redirects=False).status_code == 303
    assert victim.get("/api/me").json()["email"] == "victim@corp.com"
    assert TestClient(c.app).post("/api/auth/login", json={"email": "victim@corp.com", "password": "attacker knows this"}).status_code == 401
    assert mfa_login(TestClient(c.app), "victim@corp.com", "the victim's own pass").status_code == 200


# --- S2: chunked bodies are capped too ------------------------------------------------------------------------------

def test_chunked_body_over_the_cap_is_refused_before_any_handler(env):
    c = TestClient(create_app(env))
    big = b" " * (10 * 1024 * 1024 + 1)
    r = c.post("/api/auth/login", content=(x for x in (big[:6_000_000], big[6_000_000:])), headers={"content-type": "application/json"})
    assert r.status_code == 413
    assert c.post("/api/auth/login", content=b" " * (10 * 1024 * 1024 + 1)).status_code == 413  # with content-length


# --- S3: per-tenant quotas -------------------------------------------------------------------------------------------

def test_asset_cap_per_org(env, monkeypatch):
    import nimstead.app as appmod
    monkeypatch.setattr(appmod, "MAX_ASSETS_PER_ORG", 2)
    c = user(env)
    enrol(c), enrol(c)
    token = c.post("/api/enroll-tokens").json()["token"]
    r = c.post("/api/agent/enroll", json={"token": token, "hostname": "h3"})
    assert r.status_code == 403 and "limit of 2 assets" in r.json()["detail"]
    assert c.post("/api/assets", json={"name": "app"}).status_code == 403
    assert c.post("/api/targets", json={"hostname": "www.example.com"}).status_code == 403
    other = user(env, "b@example.com")  # another org is unaffected
    assert enrol(other)["agent_key"]


def test_enrolments_per_token_and_inventories_per_org_are_rate_limited(env, monkeypatch):
    import nimstead.app as appmod
    monkeypatch.setattr(appmod, "ENROLL_MAX_PER_TOKEN_HOUR", 2)
    monkeypatch.setattr(appmod, "ORG_INVENTORY_MAX_PER_HOUR", 2)
    c = user(env)
    token = c.post("/api/enroll-tokens").json()["token"]
    codes = [c.post("/api/agent/enroll", json={"token": token, "hostname": f"h{i}"}).status_code for i in range(3)]
    assert codes == [201, 201, 429]
    keys = [r.json()["agent_key"] for r in (c.post("/api/agent/enroll", json={"token": c.post("/api/enroll-tokens").json()["token"],
                                                                               "hostname": f"x{i}"}) for i in range(2))]
    sent = [c.post("/api/agent/inventory", json=INV, headers={"Authorization": f"Bearer {k}"}).status_code for k in keys + keys[:1]]
    assert sent == [200, 200, 429]  # each host is within its own limit; the org isn't


# --- S4: AI budget and cache -----------------------------------------------------------------------------------------

def test_ai_is_rate_limited_per_user_and_cached_across_hosts(env, monkeypatch):
    import nimstead.app as appmod
    from nimstead import ai
    calls = []
    monkeypatch.setattr(ai, "enabled", lambda: True)
    monkeypatch.setattr(ai, "_call", lambda *a, **k: calls.append(a) or '{"priority": ["fix-now"]}')
    ai._explain_cached.cache_clear()
    monkeypatch.setattr(appmod, "AI_MAX_PER_USER_HOUR", 3)
    c = user(env)
    for _ in range(2):
        c.post("/api/agent/inventory", json=INV, headers={"Authorization": f"Bearer {enrol(c)['agent_key']}"})
    f = c.get("/api/findings").json()
    same = [x for x in f if x["vuln_id"] == f[0]["vuln_id"] and x["package"] == f[0]["package"]]
    assert len({x["hostname"] for x in same}) == 1 or len(same) == 2
    a, b = same[:2] if len(same) > 1 else (same[0], same[0])
    assert c.post(f"/api/ai/explain/{a['id']}").status_code == 200
    assert c.post(f"/api/ai/explain/{b['id']}").status_code == 200
    assert len(calls) == 1  # same advisory and context on another host: one model call
    assert c.post("/api/ai/search", json={"text": "kev on web"}).status_code == 200
    assert c.post("/api/ai/search", json={"text": "kev on web"}).status_code == 429


# --- S6: security headers --------------------------------------------------------------------------------------------

def test_security_headers(env, monkeypatch):
    import nimstead.app as appmod
    monkeypatch.setattr(appmod, "SECURE_COOKIES", True)
    h = TestClient(create_app(env)).get("/api/health").headers
    assert h["x-content-type-options"] == "nosniff" and h["x-frame-options"] == "DENY" and h["referrer-policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in h["content-security-policy"] and "max-age=" in h["strict-transport-security"]
    assert "content-security-policy" not in TestClient(create_app(env)).get("/api/docs").headers  # Swagger UI's CDN


def test_csp_allows_the_spas_inline_theme_script_by_hash(tmp_path):
    import base64
    import hashlib

    from nimstead.app import csp
    js = "try { document.documentElement.dataset.theme = 'dark'; } catch (e) {}"
    (tmp_path / "index.html").write_text(f"<html><script>{js}</script><script type=module src=/assets/x.js></script>")
    assert f"'sha256-{base64.b64encode(hashlib.sha256(js.encode()).digest()).decode()}'" in csp(tmp_path / "index.html")
    assert "script-src 'self';" in csp(tmp_path / "missing.html")


# --- S7: ledger --------------------------------------------------------------------------------------------------------

def test_enrolment_org_creation_and_password_login_are_ledgered(env):
    c = user(env)
    a = enrol(c)
    mfa_login(TestClient(c.app), "a@example.com")
    k = kinds(env)
    assert {"org_created", "asset_enrolled", "mfa_enrolled", "password_login"} <= set(k)
    token_id = c.get("/api/enroll-tokens").json()[0]["id"]
    s = sessionmaker(make_engine(env))()
    e = s.scalar(select(LedgerEntry).where(LedgerEntry.kind == "asset_enrolled"))
    assert e.data["token"] == token_id and e.subject == a["asset_id"]


# --- I2: TOTP --------------------------------------------------------------------------------------------------------

def test_totp_matches_rfc6238_vectors():
    import base64
    import hashlib
    sha1, sha256 = base64.b32encode(b"12345678901234567890").decode(), base64.b32encode(b"12345678901234567890123456789012").decode()
    for t, want in ((59, "94287082"), (1111111109, "07081804"), (1234567890, "89005924"), (20000000000, "65353130")):
        assert mfa.code(sha1, t // 30, digits=8) == want
    assert mfa.code(sha256, 59 // 30, digits=8, digest=hashlib.sha256) == "46119246"
    s = mfa.new_secret()
    assert mfa.verify(s, mfa.code(s, 1000), 0, at=1000 * 30) == 1000
    assert mfa.verify(s, mfa.code(s, 1000), 1000, at=1000 * 30) is None  # used once
    assert mfa.verify(s, mfa.code(s, 997), 0, at=1000 * 30) is None  # too old
    assert mfa.verify(s, "12345", 0) is None and mfa.verify(s, "abcdef", 0) is None


def test_admin_password_sign_in_needs_mfa(env):
    c = user(env)
    c.post("/api/auth/logout")
    pw = {"email": "a@example.com", "password": PW}
    r = c.post("/api/auth/login", json=pw).json()
    assert r["mfa"] == "setup" and r["uri"].startswith("otpauth://totp/") and c.get("/api/me").status_code == 401
    assert c.post("/api/auth/login", json={**pw, "setup": r["setup"], "code": "000000"}).status_code == 401
    other = user(env, "b@example.com")  # someone else's setup blob doesn't enrol this account
    blob = other.post("/api/me/mfa/setup").json()
    assert c.post("/api/auth/login", json={**pw, "setup": blob["setup"], "code": now_code(blob["secret"])}).status_code == 401
    done = c.post("/api/auth/login", json={**pw, "setup": r["setup"], "code": now_code(r["secret"])})
    assert done.status_code == 200 and len(done.json()["recovery_codes"]) == 10
    codes = done.json()["recovery_codes"]
    assert c.get("/api/me").json()["mfa"] is True
    c.post("/api/auth/logout")
    assert c.post("/api/auth/login", json=pw).json() == {"mfa": "required"} and c.get("/api/me").status_code == 401
    assert c.post("/api/auth/login", json={**pw, "code": now_code(r["secret"])}).status_code == 401  # the setup code was step N
    assert c.post("/api/auth/login", json={**pw, "code": now_code(r["secret"], 1)}).status_code == 200
    c.post("/api/auth/logout")
    assert c.post("/api/auth/login", json={**pw, "code": codes[0]}).status_code == 200  # recovery code
    c.post("/api/auth/logout")
    assert c.post("/api/auth/login", json={**pw, "code": codes[0]}).status_code == 401  # spent
    assert c.post("/api/auth/login", json={**pw, "code": codes[1].upper()}).json()["email"] == "a@example.com"
    assert c.get("/api/me").json()["recovery_codes_left"] == 8
    assert "mfa_recovery_code_used" in kinds(env)


def test_wrong_codes_count_toward_the_sign_in_throttle(env):
    c = user(env)
    r = mfa_login(TestClient(c.app), "a@example.com")
    assert r.status_code == 200
    pw = {"email": "a@example.com", "password": PW, "code": "000000"}
    assert [c.post("/api/auth/login", json=pw).status_code for _ in range(11)][-1] == 429


def test_non_admins_may_enrol_and_replacing_needs_the_old_authenticator(env):
    c = user(env)
    s = c.post("/api/me/mfa/setup").json()
    assert c.post("/api/me/mfa", json={"setup": s["setup"], "code": "000000"}).status_code == 422
    assert c.post("/api/me/mfa", json={"setup": s["setup"], "code": now_code(s["secret"])}).status_code == 200
    s2 = c.post("/api/me/mfa/setup").json()
    assert c.post("/api/me/mfa", json={"setup": s2["setup"], "code": now_code(s2["secret"])}).status_code == 403
    r = c.post("/api/me/mfa", json={"setup": s2["setup"], "code": now_code(s2["secret"]), "current_code": now_code(s["secret"], 1)})
    assert r.status_code == 200


# --- I3: password change and reset -----------------------------------------------------------------------------------

def test_password_change_needs_current_password_and_code_and_signs_out_other_devices(env):
    c = user(env)
    laptop = TestClient(c.app)
    secret = mfa_login(laptop, "a@example.com").secret
    body = {"current": PW, "new": "a brand new passphrase"}
    assert c.post("/api/me/password", json={**body, "current": "wrong wrong wrong"}).status_code == 403
    assert c.post("/api/me/password", json=body).status_code == 403  # no code
    assert c.post("/api/me/password", json={**body, "code": now_code(secret, 1)}).status_code == 204
    assert c.get("/api/me").status_code == 200 and laptop.get("/api/me").status_code == 401
    assert "password_changed" in kinds(env)


def test_password_reset_by_email(env, monkeypatch, mail):
    c = user(env)
    secret = mfa_login(TestClient(c.app), "a@example.com").secret
    anon = TestClient(c.app)
    known, unknown = anon.post("/api/auth/password/reset", json={"email": "a@example.com"}), \
        anon.post("/api/auth/password/reset", json={"email": "nobody@example.com"})
    assert known.status_code == unknown.status_code == 202
    assert {k: v for k, v in known.json().items() if k != "email"} == {k: v for k, v in unknown.json().items() if k != "email"}
    link = link_in(mail("a@example.com"))
    assert "within 1 hour" in mail("a@example.com")
    r = anon.post(link, data={"password": "my new long password"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/signin?reset=1" and anon.get("/api/me").status_code == 401
    assert c.get("/api/me").status_code == 401  # every session ended
    assert anon.post(link, data={"password": "my new long password"}).status_code == 404  # single use
    pw = {"email": "a@example.com", "password": "my new long password"}
    assert anon.post("/api/auth/login", json=pw).json() == {"mfa": "required"}  # the code is still needed
    assert anon.post("/api/auth/login", json={**pw, "code": now_code(secret, 1)}).status_code == 200


def test_reset_and_invite_need_smtp(env):
    c = user(env)
    assert TestClient(c.app).post("/api/auth/password/reset", json={"email": "a@example.com"}).status_code == 403
    assert c.post("/api/users/invite", json={"email": "x@example.com"}).status_code == 403


# --- I1: user management -----------------------------------------------------------------------------------------------

def test_invite_promote_demote_and_remove(env, mail):
    admin = user(env)
    assert admin.post("/api/users/invite", json={"email": "bob@example.com"}).status_code == 202
    bob = TestClient(admin.app)
    page = bob.get(link_in(mail("bob@example.com")))
    assert "Join Acme on Nimstead" in page.text
    assert bob.post(link_in(mail("bob@example.com")), data={"password": "bob's own password"}, follow_redirects=False).status_code == 303
    assert bob.get("/api/me").json() | {"admin": "?"} == bob.get("/api/me").json() | {"admin": "?"} and not bob.get("/api/me").json()["admin"]
    assert bob.get("/api/users").status_code == 403
    users = {u["email"]: u for u in admin.get("/api/users").json()}
    assert set(users) == {"a@example.com", "bob@example.com"}
    me_id, bob_id = users["a@example.com"]["id"], users["bob@example.com"]["id"]
    assert admin.patch(f"/api/users/{me_id}", json={"admin": False}).status_code == 409  # last admin
    assert admin.delete(f"/api/users/{me_id}").status_code == 409
    assert admin.patch(f"/api/users/{bob_id}", json={"admin": True}).json()["admin"] is True
    assert bob.get("/api/users").status_code == 200
    assert admin.delete(f"/api/users/{bob_id}").status_code == 204
    assert bob.get("/api/me").status_code == 401  # signed out at once
    assert {"user_invited", "user_joined", "user_role_changed", "user_removed"} <= set(kinds(env))
    stranger = user(env, "s@example.com")  # another org can't see or touch these users
    assert stranger.patch(f"/api/users/{me_id}", json={"admin": False}).status_code == 404
    assert stranger.delete(f"/api/users/{me_id}").status_code == 404


def test_invite_answers_the_same_for_taken_addresses(env, mail):
    admin = user(env)
    user(env, "taken@example.com")
    a, b = admin.post("/api/users/invite", json={"email": "taken@example.com"}), admin.post("/api/users/invite", json={"email": "new@example.com"})
    assert a.status_code == b.status_code == 202
    assert "already has one" in mail("taken@example.com")


def test_idle_sessions_expire_and_sign_out_everywhere(env):
    c = user(env)
    other = TestClient(c.app)
    mfa_login(other, "a@example.com")
    s = sessionmaker(make_engine(env))()
    from datetime import timedelta

    from nimstead.db import now
    for ws in s.scalars(select(WebSession)):
        ws.last_used = now() - timedelta(hours=13)
    s.commit()
    assert c.get("/api/me").status_code == 401
    secret = mfa_login(TestClient(c.app), "a@example.com")  # enrolled already: needs the code path
    assert secret.json() == {"mfa": "required"}
    s.execute(WebSession.__table__.update().values(last_used=now()))
    s.commit()
    assert other.post("/api/me/sessions/revoke").status_code == 204
    assert other.get("/api/me").status_code == 401 and c.get("/api/me").status_code == 401


# --- I4: API tokens ----------------------------------------------------------------------------------------------------

def test_api_tokens_are_read_only_and_scoped_to_their_org(env):
    c = user(env)
    c.post("/api/agent/inventory", json=INV, headers={"Authorization": f"Bearer {enrol(c)['agent_key']}"})
    other = user(env, "b@example.com")
    enrol(other)
    t = c.post("/api/tokens", json={"name": "jira sync"}).json()
    bot = TestClient(c.app)
    h = {"Authorization": f"Bearer {t['token']}"}
    assert len(bot.get("/api/findings", headers=h).json()) > 0
    assert [a["hostname"] for a in bot.get("/api/assets", headers=h).json()] == ["web-1"]  # own org only
    assert bot.get("/api/findings.csv", headers=h).status_code == 200
    assert bot.post("/api/enroll-tokens", headers=h).status_code == 403  # read-only
    assert bot.get("/api/users", headers=h).status_code == 403  # admin pages need a person
    assert bot.get("/api/settings/sso", headers=h).status_code == 403
    assert bot.post("/api/ai/search", headers=h, json={"text": "x"}).status_code == 403
    listed = c.get("/api/tokens").json()
    assert listed[0]["name"] == "jira sync" and "token" not in listed[0] and listed[0]["last_used"]
    assert c.delete(f"/api/tokens/{t['id']}").status_code == 204
    assert bot.get("/api/findings", headers=h).status_code == 401
    assert c.delete("/api/tokens/____________").status_code == 404  # LIKE wildcards don't match
    assert {"api_token_created", "api_token_revoked"} <= set(kinds(env))


def test_api_token_ends_with_its_admin(env, mail):
    admin = user(env)
    admin.post("/api/users/invite", json={"email": "bob@example.com"})
    bob = TestClient(admin.app)
    bob.post(link_in(mail("bob@example.com")), data={"password": "bob's own password"})
    bob_id = next(u["id"] for u in admin.get("/api/users").json() if u["email"] == "bob@example.com")
    admin.patch(f"/api/users/{bob_id}", json={"admin": True})
    t = bob.post("/api/tokens", json={"name": "bob's script", "days": None}).json()
    h = {"Authorization": f"Bearer {t['token']}"}
    assert t["expires"] is None and TestClient(admin.app).get("/api/findings", headers=h).status_code == 200
    admin.patch(f"/api/users/{bob_id}", json={"admin": False})
    assert TestClient(admin.app).get("/api/findings", headers=h).status_code == 401


def test_expired_api_token(env):
    from datetime import timedelta

    from nimstead.db import ApiToken, now
    c = user(env)
    t = c.post("/api/tokens", json={"name": "old", "days": 1}).json()
    s = sessionmaker(make_engine(env))()
    s.execute(ApiToken.__table__.update().values(expires=now() - timedelta(seconds=1)))
    s.commit()
    assert TestClient(c.app).get("/api/findings", headers={"Authorization": f"Bearer {t['token']}"}).status_code == 401


# --- I5: CSV export ----------------------------------------------------------------------------------------------------

def test_csv_export_escapes_formulas(env):
    import csv
    import io
    c = user(env)
    inv = {**INV, "packages": INV["packages"] + [{"ecosystem": "PyPI", "name": "=HYPERLINK(\"http://x\")", "version": "1"}]}
    c.post("/api/agent/inventory", json=inv, headers={"Authorization": f"Bearer {enrol(c)['agent_key']}"})
    r = c.get("/api/findings.csv", params={"kev": True})
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    rows = list(csv.reader(io.StringIO(r.text)))
    assert rows[0][:2] == ["hostname", "package"] and all(row[0] == "web-1" for row in rows[1:]) and len(rows) > 1
    assert all(not cell.startswith(("=", "+", "-", "@")) for row in rows for cell in row)
    assert not TestClient(c.app).get("/api/findings.csv").status_code == 200  # signed in only


def test_users_table_has_no_password_material_in_json(env):
    c = user(env)
    assert set(c.get("/api/users").json()[0]) == {"id", "email", "admin", "origin", "mfa", "created"}
    assert sessionmaker(make_engine(env))().scalar(select(User.recovery_codes)) == []
