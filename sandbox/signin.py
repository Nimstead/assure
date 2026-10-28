"""Sign up the first account and sign in as its admin, as a person would since 0.4.0: sign-up gives no session, and an
admin's first sign-in sets up TOTP (DECISIONS 35). For harnesses that drive the API in-process or over HTTP."""

import time

from nimstead import mfa


def signup(c, body):
    """POST /api/auth/signup with body, then sign in with a code. Returns the sign-up response; c holds the session."""
    r = c.post("/api/auth/signup", json=body)
    creds = {"email": body["email"], "password": body["password"]}
    d = c.post("/api/auth/login", json=creds).json()
    if d.get("mfa") == "setup":
        d = c.post("/api/auth/login", json={**creds, "setup": d["setup"], "code": mfa.code(d["secret"], int(time.time() // 30))}).json()
    assert d.get("email") == body["email"], d
    return r
