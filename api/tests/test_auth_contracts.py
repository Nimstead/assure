"""Account response fields and state transitions promised by the public reference."""

import json
import secrets
import time
from datetime import timedelta
from pathlib import Path

from fastapi.testclient import TestClient
from test_api import user
from test_asset_contracts import fields_match
from test_sso import DNS, FakeIdP, make

from nimstead import mfa
from nimstead.app import sha
from nimstead.db import PendingSignup, User, make_sessionmaker, now

SCHEMAS = json.loads((Path(__file__).parents[2] / "docs/reference/openapi.json").read_text())["components"]["schemas"]


def test_login_branches_metadata_and_mfa_replacement_preserve_access(env):
    admin = user(env)
    fields_match("CurrentIdentity", admin.get("/api/me").json())
    assert admin.get("/api/me", headers={"Authorization": "Bearer nmt_invalid"}).status_code == 401
    assert admin.get("/api/me", headers={"Authorization": "Bearer unrelated"}).status_code == 200
    browser = TestClient(admin.app)
    body = {"email": "a@example.com", "password": "correct horse battery"}
    proposal = browser.post("/api/auth/login", json=body)
    assert proposal.status_code == 200 and proposal.json()["mfa"] == "setup"
    assert "set-cookie" not in proposal.headers and browser.get("/api/me").status_code == 401
    setup = proposal.json()
    assert set(setup) == set(SCHEMAS["PasswordLogin"]["oneOf"][2]["required"])
    finished = browser.post("/api/auth/login", json={**body, "setup": setup["setup"], "code": mfa.code(setup["secret"], int(time.time() // 30))})
    assert finished.status_code == 200
    answer = finished.json()
    assert set(answer) == {"email", "recovery_codes"}
    assert TestClient(admin.app).post("/api/auth/login", json=body).json() == {"mfa": "required"}
    fields_match("CurrentIdentity", browser.get("/api/me").json())
    rows = browser.get("/api/users").json()
    for row in rows:
        fields_match("UserRecord", row)
    same_role = browser.patch(f"/api/users/{rows[0]['id']}ignored-suffix", json={"admin": True})
    assert same_role.status_code == 200 and same_role.json()["id"] == rows[0]["id"]
    token = browser.post("/api/tokens", json={"name": "fixture", "code": answer["recovery_codes"][0]}).json()
    fields_match("CreatedApiToken", token)
    headers = {"Authorization": "Bearer " + token["token"]}
    assert browser.get("/api/me", headers=headers).status_code == 200
    for row in browser.get("/api/tokens").json():
        fields_match("ApiTokenMetadata", row)
        assert "token" not in row
    enrol = browser.post("/api/enroll-tokens").json()
    fields_match("CreatedEnrolmentToken", enrol)
    for row in browser.get("/api/enroll-tokens").json():
        fields_match("EnrolmentTokenMetadata", row)
    replacement = browser.post("/api/me/mfa/setup").json()
    fields_match("AuthenticatorSetup", replacement)
    response = browser.post("/api/me/mfa", json={"setup": replacement["setup"],
        "code": mfa.code(replacement["secret"], int(time.time() // 30)), "current_code": answer["recovery_codes"][1]})
    assert response.status_code == 200
    fields_match("RecoveryCodes", response.json())
    assert browser.get("/api/me", headers=headers).status_code == 200
    assert browser.get("/api/me").status_code == 200
    assert browser.post("/api/me/sessions/revoke").status_code == 204
    assert browser.get("/api/me").status_code == 401
    assert admin.get("/api/me").status_code == 401
    assert browser.get("/api/me", headers=headers).status_code == 401


def test_invitation_confirmation_establishes_member_session(env):
    admin = user(env)
    token = secrets.token_urlsafe(32)
    with make_sessionmaker(env)() as s:
        owner = s.query(User).filter_by(email="a@example.com").one()
        s.add(PendingSignup(token_hash=sha(token), email="member@example.com", purpose="invite", org_name="Acme",
                            org_id=owner.org_id, expires=now() + timedelta(hours=1)))
        s.commit()
    browser = TestClient(admin.app)
    path = f"/api/auth/signup/confirm?token={token}"
    assert browser.get(path).status_code == 200
    assert browser.get("/api/me").status_code == 401
    assert browser.post(path, data={"password": "short"}).status_code == 422
    joined = browser.post(path, data={"password": "fixture member password"}, follow_redirects=False)
    assert joined.status_code == 303 and joined.headers["location"] == "/"
    identity = browser.get("/api/me").json()
    fields_match("CurrentIdentity", identity)
    assert identity["email"] == "member@example.com" and not identity["admin"]
    assert browser.get(path).status_code == 404


def test_sso_verification_is_stored_and_empty_default_issuer_disables(env):
    app, admin = make(env, FakeIdP())
    settings = admin.get("/api/settings/sso").json()
    fields_match("SSOSettings", settings)
    assert settings["domain_checks"] and all(row["verified"] for row in settings["domain_checks"])
    DNS.clear()
    verified = admin.post("/api/settings/sso/verify").json()
    assert all(row["verified"] for row in verified["domain_checks"])
    response = admin.put("/api/settings/sso", json={"client_id": "omitted-issuer-fixture"})
    assert response.status_code == 200
    disabled = response.json()
    fields_match("SSOSettings", disabled)
    assert disabled["issuer"] == "" and disabled["domains"] == [] and not disabled["client_secret_set"]
