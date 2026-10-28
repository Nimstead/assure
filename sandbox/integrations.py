"""SSO, DNS domain verification and failure alerts against REAL services in a DISPOSABLE WSL distro.

Run from api/:  uv run python ../sandbox/integrations.py [--keep]
The distro (nimstead-sbx-int-<random>) runs:
  - Keycloak (real OIDC provider) over HTTPS, realm "nimstead" with user jane@corp.example.com
  - dnsmasq serving the _nimstead-verify TXT record for corp.example.com (TCP, port 5353)
  - aiosmtpd as the SMTP server (port 2525), writing a Maildir
  - a small HTTPS webhook receiver (port 9443)
TLS uses a throwaway CA generated inside the VM. Nimstead runs in-process with NIMSTEAD_ALLOW_PRIVATE_TARGETS=1
(the dev switch that lets it reach these private addresses). The distro is always unregistered at the end.
"""

import html
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

PREFIX = "nimstead-sbx-"
NAME = PREFIX + "int-" + secrets.token_hex(3)
TMP = Path(tempfile.mkdtemp(prefix="nimstead-sbx-int-"))
KEYCLOAK = "26.8.1"
CLIENT_SECRET = secrets.token_hex(16)
JANE_PASSWORD = "Jane-" + secrets.token_hex(6)
CA = TMP / "ca.pem"
ROOT = Path(__file__).resolve().parents[1]
log: list[dict] = []


def note(step, **kw):
    log.append({"step": step, **kw})
    print(f"[{time.strftime('%H:%M:%S')}] {step}", json.dumps(kw)[:300] if kw else "", flush=True)


def vm(script: str, check=True) -> str:
    assert NAME.startswith(PREFIX)
    p = subprocess.run(["wsl", "-d", NAME, "-u", "root", "--", "sh", "-s"], input=script.encode(), capture_output=True, timeout=1800)
    if check and p.returncode != 0:
        raise RuntimeError(f"{script[:300]}\n{p.stdout.decode(errors='replace')[-1500:]}\n{p.stderr.decode(errors='replace')[-1500:]}")
    return p.stdout.decode(errors="replace")


REALM = {
    "realm": "nimstead", "enabled": True, "sslRequired": "external",
    "clients": [{"clientId": "nimstead", "enabled": True, "publicClient": False, "secret": CLIENT_SECRET,
                 "redirectUris": ["http://testserver/*"], "standardFlowEnabled": True, "directAccessGrantsEnabled": False,
                 "attributes": {"pkce.code.challenge.method": "S256"}}],
    "users": [{"username": "jane", "email": "jane@corp.example.com", "emailVerified": True, "enabled": True,
               "firstName": "Jane", "lastName": "Doe",
               "credentials": [{"type": "password", "value": JANE_PASSWORD, "temporary": False}]}],
}

HOOK_SERVER = r'''
import http.server, json, ssl
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("content-length", 0)))
        with open("/opt/int/hooks.jsonl", "ab") as f:
            f.write(body + b"\n")
        self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
s = http.server.HTTPServer(("0.0.0.0", 9443), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain("/opt/int/tls/server.pem", "/opt/int/tls/server.key")
s.socket = ctx.wrap_socket(s.socket, server_side=True)
s.serve_forever()
'''


# Each long-running service lives in its own wsl session held open by this script: WSL tears down
# processes left behind when the session that started them exits.
SERVICES = {
    "keycloak": "cd /opt/int && JAVA_OPTS_APPEND=-Djava.net.preferIPv4Stack=true exec kc/bin/kc.sh start-dev --http-host=0.0.0.0 --import-realm --http-enabled=false --https-port=8443 "
                "--https-certificate-file=/opt/int/tls/server.pem --https-certificate-key-file=/opt/int/tls/server.key "
                "--hostname=https://127.0.0.1:8443",
    "smtp": "exec python3 -m aiosmtpd -n -l 0.0.0.0:2525 -c aiosmtpd.handlers.Mailbox /opt/int/maildir",
    "hook": "exec python3 /opt/int/hook.py",
}
running: dict[str, subprocess.Popen] = {}


def start_service(name: str, cmd: str):
    logf = open(TMP / f"{name}.log", "ab")
    running[name] = subprocess.Popen(["wsl", "-d", NAME, "-u", "root", "--", "sh", "-c", cmd], stdout=logf, stderr=logf)


def stop_service(name: str):
    p = running.pop(name, None)
    if p:
        p.kill()
        vm({"dns": "pkill dnsmasq", "hook": "pkill -f hook.py", "smtp": "pkill -f aiosmtpd", "keycloak": "pkill -f keycloak"}[name], check=False)


def build_vm():
    note("creating integration VM", name=NAME)
    r = subprocess.run(["wsl", "--install", "Debian", "--name", NAME, "--location", str(TMP / "d"), "--no-launch"],
                       capture_output=True, timeout=1800)
    if r.returncode != 0:
        raise RuntimeError((r.stdout + r.stderr).decode("utf-16-le", errors="replace"))
    keepalive = subprocess.Popen(["wsl", "-d", NAME, "-u", "root", "--", "sleep", "infinity"])
    vm("apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "
       "openjdk-21-jre-headless dnsmasq-base python3-aiosmtpd openssl curl ca-certificates >/dev/null")
    vm("""set -e
        mkdir -p /opt/int/tls /opt/int/maildir/tmp /opt/int/maildir/new /opt/int/maildir/cur && cd /opt/int/tls
        openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=Nimstead test CA" -keyout ca.key -out ca.pem \
          -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
          -addext "subjectKeyIdentifier=hash" 2>/dev/null
        openssl req -newkey rsa:2048 -nodes -subj "/CN=127.0.0.1" -keyout server.key -out server.csr 2>/dev/null
        printf 'subjectAltName=IP:127.0.0.1,DNS:localhost\\nbasicConstraints=CA:FALSE\\nkeyUsage=critical,digitalSignature,keyEncipherment\\nextendedKeyUsage=serverAuth\\nauthorityKeyIdentifier=keyid\\n' > san.ext
        openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -extfile san.ext -out server.pem 2>/dev/null
        chmod 644 server.key
    """)
    CA.write_text(vm("cat /opt/int/tls/ca.pem"))
    note("test CA created")
    vm(f"""set -e
        cd /opt/int && curl -fsSL -o kc.tgz https://github.com/keycloak/keycloak/releases/download/{KEYCLOAK}/keycloak-{KEYCLOAK}.tar.gz
        tar xzf kc.tgz && mv keycloak-{KEYCLOAK} kc && mkdir -p kc/data/import
    """)
    vm("cat > /opt/int/kc/data/import/realm.json <<'EOF'\n" + json.dumps(REALM) + "\nEOF")
    vm("cat > /opt/int/hook.py <<'EOF'\n" + HOOK_SERVER + "\nEOF")
    for name, cmd in SERVICES.items():
        start_service(name, cmd)
    for _ in range(90):  # Keycloak takes a while on first start
        if "200" in vm("curl -s -o /dev/null -w '%{http_code}' --cacert /opt/int/tls/ca.pem "
                       "https://127.0.0.1:8443/realms/nimstead/.well-known/openid-configuration", check=False):
            break
        time.sleep(2)
    else:
        raise RuntimeError("Keycloak did not start:\n" + vm("tail -40 /opt/int/kc.log", check=False))
    note("Keycloak, SMTP and webhook receiver up")
    return keepalive


def serve_txt(name: str, value: str):
    vm(f"""printf 'port=5353\nno-resolv\nno-hosts\nlisten-address=0.0.0.0\nbind-interfaces\ntxt-record={name},"{value}"\n' > /opt/int/dnsmasq.conf""")
    stop_service("dns")
    start_service("dns", "dnsmasq -k -C /opt/int/dnsmasq.conf")
    time.sleep(1)


def main(keep=False) -> int:
    keepalive = None
    try:
        keepalive = build_vm()
        os.environ.update({
            "NIMSTEAD_SECURE_COOKIES": "0", "NIMSTEAD_ALLOW_PRIVATE_TARGETS": "1", "SSL_CERT_FILE": str(CA),
            "NIMSTEAD_DNS_SERVER": "127.0.0.1:5353", "NIMSTEAD_SMTP_URL": "smtp://127.0.0.1:2525",
            "NIMSTEAD_SMTP_FROM": "nimstead@corp.example.com", "NIMSTEAD_SIGNING_KEY_FILE": str(TMP / "sign.pem"),
            "NIMSTEAD_SECRET_KEY_FILE": str(TMP / "secret.key"), "NIMSTEAD_CHECKPOINT_DIR": str(TMP / "cp"),
        })
        import httpx
        from fastapi.testclient import TestClient
        from signin import signup  # first account + its admin's TOTP sign-in

        from nimstead import notify
        from nimstead.app import create_app

        app = create_app(f"sqlite:///{(TMP / 'n.db').as_posix()}")
        admin = TestClient(app)
        assert signup(admin, {"email": "admin@corp.example.com", "password": "admin-password-123", "org_name": "Corp"}).status_code == 201
        issuer = "https://127.0.0.1:8443/realms/nimstead"
        r = admin.put("/api/settings/sso", json={"issuer": issuer, "client_id": "nimstead", "client_secret": CLIENT_SECRET,
                                                 "domains": ["corp.example.com"]})
        assert r.status_code == 200, r.text
        chk = r.json()["domain_checks"][0]

        # 1) DNS: not verified until the record exists, verified once a real DNS server serves it
        assert not admin.post("/api/settings/sso/verify").json()["domain_checks"][0]["verified"]
        serve_txt(chk["txt_name"], "nimstead-verify=wrong-value")
        assert not admin.post("/api/settings/sso/verify").json()["domain_checks"][0]["verified"]
        serve_txt(chk["txt_name"], chk["txt_value"])
        assert admin.post("/api/settings/sso/verify").json()["domain_checks"][0]["verified"]
        note("DNS TXT domain verification via real dnsmasq", wrong_value_refused=True, verified=True)

        # 2) SSO: real browser-style login against Keycloak
        def login(password):
            browser = TestClient(app)
            start = browser.post("/api/auth/sso/start", data={"email": "jane@corp.example.com"}, follow_redirects=False)
            assert start.status_code == 303 and start.headers["location"].startswith(issuer), start.headers.get("location")
            with httpx.Client(verify=str(CA), follow_redirects=True) as kc:
                page = kc.get(start.headers["location"])
                action = html.unescape(re.search(r'<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"', page.text).group(1))
                resp = kc.post(action, data={"username": "jane", "password": password}, follow_redirects=False)
            loc = resp.headers.get("location", "")
            if not loc.startswith("http://testserver/api/auth/sso/callback"):
                return browser, None
            cb = browser.get(loc.removeprefix("http://testserver"), follow_redirects=False)
            return browser, cb

        _, cb = login("wrong-password")
        assert cb is None
        browser, cb = login(JANE_PASSWORD)
        assert cb.status_code == 303 and cb.headers["location"] == "/", (cb.status_code, cb.headers.get("location"))
        me = browser.get("/api/me").json()
        assert me["email"] == "jane@corp.example.com" and not me.get("admin")
        replay = browser.get(cb.request.url.raw_path.decode(), follow_redirects=False)  # same code+state again
        assert "sso_error=state" in replay.headers.get("location", "")
        note("OIDC login via real Keycloak", user=me["email"], wrong_password_refused=True, replay_refused=True)

        # 3) Alerts: real HTTPS webhook and real SMTP
        r = admin.put("/api/settings/notifications", json={"webhook_url": "https://127.0.0.1:9443/hook", "webhook_format": "slack",
                                                           "emails": ["secops@corp.example.com"]})
        assert r.status_code == 200, r.text
        notify.flush()  # the confirmation email went out; confirm the way the recipient's button does
        from sqlalchemy import select
        from sqlalchemy.orm import sessionmaker

        from nimstead.db import Org, make_engine
        org_id = sessionmaker(make_engine(f"sqlite:///{(TMP / 'n.db').as_posix()}"))().scalar(select(Org.id))
        q = {"org": org_id, "email": "secops@corp.example.com", "token": notify.confirm_token(org_id, "secops@corp.example.com")}
        assert "Confirmed" in TestClient(app).post("/api/notify/confirm", params=q).text
        assert admin.post("/api/settings/notifications/test").status_code == 202
        notify.flush()
        time.sleep(1)
        hooks = [json.loads(ln) for ln in vm("cat /opt/int/hooks.jsonl", check=False).splitlines() if ln.strip()]
        mails = vm("cat /opt/int/maildir/new/* 2>/dev/null", check=False)
        recent = admin.get("/api/settings/notifications").json()["recent"]
        assert hooks and "text" in hooks[-1], hooks
        assert "secops@corp.example.com" in mails and "Nimstead" in mails, mails[:500]
        assert all(x["ok"] for x in recent[:2]), recent[:2]
        note("alerts delivered to real webhook + SMTP", webhook=hooks[-1]["text"][:80], email="received")

        stop_service("hook")  # receiver down -> failure must be recorded, then retried
        admin.post("/api/settings/notifications/test")
        notify.flush()
        n = admin.get("/api/settings/notifications").json()
        assert n["last_delivery_failed"] is True
        start_service("hook", SERVICES["hook"])
        time.sleep(1)
        from sqlalchemy.orm import sessionmaker

        from nimstead.db import make_engine
        notify.retry_failed(sessionmaker(make_engine(f"sqlite:///{(TMP / 'n.db').as_posix()}"))())
        notify.flush()
        assert admin.get("/api/settings/notifications").json()["last_delivery_failed"] is False
        note("dead webhook recorded as failed, then delivered on retry")
        note("RESULT: PASS")
        return 0
    except Exception as e:
        note("RESULT: FAIL", error=f"{type(e).__name__}: {e}"[:2000])
        return 1
    finally:
        for name in list(running):
            running.pop(name).kill()
        if keepalive:
            keepalive.kill()
        if not keep:
            subprocess.run(["wsl", "--unregister", NAME], capture_output=True)
            note("VM destroyed", name=NAME)
        (ROOT / "sandbox" / "last_run_integrations.json").write_text(json.dumps(log, indent=2, default=str))
        if not keep:
            shutil.rmtree(TMP, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main(keep="--keep" in sys.argv))
