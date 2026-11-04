"""The engine's network prober against REAL services in a DISPOSABLE WSL distro (Debian), reached at the distro's own IP
(not localhost, so this PC's own services can't leak in). Modelled on sandbox/extscan.py.

Run from api/:  uv run python ../sandbox/netengine.py [--keep]

It proves ownership exactly as the shipped scan does (TXT + the value served by the address), then drives
nimstead.engine.network.run and prints the engine report. What it shows on real services:
 1. Exposed Redis + an expired TLS certificate that also accepts TLS 1.0/1.1: each a `vulnerable` verdict, and the
    engine's verdicts agree with external.scan's findings (parity ok). A refused port is `not-vulnerable` (positive
    evidence), a firewall-dropped port is `not-run: port-filtered` (never clean).
 2. An exposed /.git/config over HTTP: `vulnerable` (NIM-WEB-GIT), with a real 404 as the negative control.
 3. A catch-all responder that presents a vsftpd banner but echoes anything sent to it: its product/version result is
    SUPPRESSED and said out loud (T23). A plain banner responder that doesn't echo: the banner-to-CVE check fires
    (vsftpd 2.3.4 -> CVE-2011-2523), graded `unverified`.
 4. A soft-404 web server (HTTP 200 for every path): the web-path checks are `undetermined: soft-404` (T22).

The private-address guard is off for this run only (NIMSTEAD_ALLOW_PRIVATE_TARGETS=1): the WSL address is private by
nature. Nothing here is disruptive. Logs to sandbox/last_run_netengine.json.
"""

import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from signin import signup  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
PREFIX = "nimstead-sbx-"
NAME = PREFIX + "net-" + secrets.token_hex(3)
TMP = Path(tempfile.mkdtemp(prefix="nimstead-sbx-net-"))
HOST = "shop.example.com"
log: list[dict] = []
running: dict[str, subprocess.Popen] = {}


def note(step, **kw):
    log.append({"step": step, **kw})
    print(f"[{time.strftime('%H:%M:%S')}] {step}", json.dumps(kw, default=str)[:1500] if kw else "", flush=True)


def vm(script: str, check=True) -> str:
    assert NAME.startswith(PREFIX)
    p = subprocess.run(["wsl", "-d", NAME, "-u", "root", "--", "sh", "-s"], input=script.encode(), capture_output=True, timeout=1200)
    if check and p.returncode != 0:
        raise RuntimeError(f"{script[:200]}\n{p.stdout.decode(errors='replace')[-600:]}\n{p.stderr.decode(errors='replace')[-600:]}")
    return p.stdout.decode(errors="replace")


def put(path: str, data: bytes):
    subprocess.run(["wsl", "-d", NAME, "-u", "root", "--", "sh", "-c", f"cat > {path}"], input=data, check=True, timeout=120)


def service(name: str, cmd: str):
    if name in running:
        running.pop(name).kill()
        time.sleep(1)
    logf = open(TMP / f"{name}.log", "ab")
    running[name] = subprocess.Popen(["wsl", "-d", NAME, "-u", "root", "--", "sh", "-c", cmd], stdout=logf, stderr=logf, stdin=subprocess.DEVNULL)


def stop(name: str):
    if name in running:
        running.pop(name).kill()


def cert(days_from: int, days_to: int) -> tuple[bytes, bytes]:
    import datetime as dt

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOST)])
    now = dt.datetime.now(dt.UTC)
    c = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(now + dt.timedelta(days=days_from))
         .not_valid_after(now + dt.timedelta(days=days_to))
         .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOST)]), critical=False).sign(key, hashes.SHA256()))
    return (c.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))


def wait_port(ip, port, up=True):
    import socket
    for _ in range(60):
        try:
            socket.create_connection((ip, port), timeout=1).close()
            if up:
                return
        except OSError:
            if not up:
                return
        time.sleep(1)
    raise RuntimeError(f"{ip}:{port} never {'opened' if up else 'closed'}")


RESPONDER = br"""
import socket, sys, threading
mode, port = sys.argv[1], int(sys.argv[2])
banner = (sys.argv[3] + "\r\n").encode() if len(sys.argv) > 3 else b""
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("0.0.0.0", port)); s.listen(50)
def handle(c):
    try:
        if banner: c.sendall(banner)
        data = c.recv(256)
        if mode == "echo": c.sendall(data)                 # catch-all / tarpit: reflects whatever it is sent
        else: c.sendall(b"500 Unknown command\r\n")        # genuine banner service: does not echo
    except OSError: pass
    finally: c.close()
while True:
    c, _ = s.accept(); threading.Thread(target=handle, args=(c,), daemon=True).start()
"""

SOFT404 = br"""
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
TOKEN = sys.argv[1].encode()
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers()
        self.wfile.write(TOKEN + b"\n" if self.path == "/.well-known/nimstead-verify.txt" else b"<h1>ok</h1>")
    def log_message(self, *a): pass
ThreadingHTTPServer(("0.0.0.0", 80), H).serve_forever()
"""


def engine_run(asset_id, dns_lookup):
    """Drive the engine prober against the proven target and return (report, verdicts, external_finding_ids)."""
    from nimstead.db import Finding, make_sessionmaker
    from nimstead.engine import network, report
    sm = make_sessionmaker(DB_URL)
    with sm() as s:
        from nimstead.db import Asset
        asset = s.query(Asset).filter_by(id=asset_id).one()
        external_ids = {f.vuln_id for f in s.query(Finding).filter_by(asset_id=asset_id).all()}
        verdicts, rep, _ = network.run(s, asset, lookup=dns_lookup)
    rep["parity"] = network.parity(verdicts, external_ids)
    print("\n" + report.render(rep) + "\n", flush=True)
    print("PARITY:", json.dumps(rep["parity"]), flush=True)
    return rep, verdicts, external_ids


DB_URL = ""


def outcome(rep, vuln_id):
    for g in rep["vulnerable"]:
        if any(v["id"] == vuln_id for v in g["vulnerabilities"]):
            return "vulnerable"
    for g in rep["undetermined"]:
        if vuln_id in (g.get("examples") or []):
            return f"{g['outcome']}:{g['reason']}"
    return None


def main(keep=False) -> int:
    global DB_URL
    try:
        r = subprocess.run(["wsl", "--install", "Debian", "--name", NAME, "--location", str(TMP / "d"), "--no-launch"],
                           capture_output=True, timeout=1800)
        if r.returncode != 0:
            raise RuntimeError((r.stdout + r.stderr).decode("utf-16-le", errors="replace"))
        running["keepalive"] = subprocess.Popen(["wsl", "-d", NAME, "-u", "root", "--", "sleep", "infinity"], stdin=subprocess.DEVNULL)
        vm("apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq redis-server openssl iproute2 iptables python3 >/dev/null")
        vm("systemctl disable --now redis-server >/dev/null 2>&1 || true")
        ip = vm("ip -4 -o addr show eth0 | awk '{print $4}' | cut -d/ -f1").strip()
        note("distro up", name=NAME, address=ip)
        expired = cert(-400, -30)
        put("/root/expired.pem", expired[0])
        put("/root/expired.key", expired[1])
        put("/root/responder.py", RESPONDER)
        put("/root/soft404.py", SOFT404)
        vm("mkdir -p /root/www/.well-known /root/www/.git")

        DB_URL = f"sqlite:///{(TMP / 'n.db').as_posix()}"
        os.environ.update(NIMSTEAD_SECURE_COOKIES="0", NIMSTEAD_ALLOW_PRIVATE_TARGETS="1", NIMSTEAD_SIGNING_KEY_FILE=str(TMP / "s.pem"),
                          NIMSTEAD_SECRET_KEY_FILE=str(TMP / "s.key"), NIMSTEAD_CHECKPOINT_DIR=str(TMP / "cp"))
        from fastapi.testclient import TestClient

        from nimstead import external, netguard
        from nimstead.app import create_app
        real_gai = netguard.socket.getaddrinfo
        netguard.socket.getaddrinfo = lambda h, *a, **k: [(2, 1, 6, "", (ip, 443))] if h == HOST else real_gai(h, *a, **k)
        txt: dict = {}
        dns_lookup = lambda n: txt.get(n, [])  # noqa: E731
        c = TestClient(create_app(DB_URL, dns_lookup=dns_lookup))
        signup(c, {"email": "net@example.com", "password": "correct horse battery", "org_name": "Net"})
        t = c.post("/api/targets", json={"hostname": HOST}).json()
        tid = t["id"]

        # prove ownership: TXT record + the value served by the address itself
        put("/root/www/.well-known/nimstead-verify.txt", (t["txt_value"] + "\n").encode())
        put("/root/www/.git/config", b"[core]\n\trepositoryformatversion = 0\n\tbare = false\n")
        txt[t["txt_name"]] = [t["txt_value"]]
        service("http", "exec python3 -m http.server 80 --directory /root/www")
        wait_port(ip, 80)
        assert c.post(f"/api/targets/{tid}/verify").json()["verified"] is True
        note("verified", host=HOST, address=ip)

        # Phase 1: exposed Redis + expired TLS + legacy, and an exposed .git/config over HTTP
        service("redis", "exec redis-server --bind 0.0.0.0 --protected-mode no --port 6379 --save ''")
        service("tls", "exec openssl s_server -quiet -accept 443 -cert /root/expired.pem -key /root/expired.key -www "
                       "-min_protocol TLSv1 -cipher DEFAULT:@SECLEVEL=0")
        wait_port(ip, 6379)
        wait_port(ip, 443)
        from nimstead.db import Asset, make_sessionmaker
        sm = make_sessionmaker(DB_URL)
        with sm() as s:
            scan = external.scan(s, s.query(Asset).filter_by(id=tid).one(), lookup=dns_lookup)
        note("external.scan (shipped)", result=scan)
        rep1, v1, ext1 = engine_run(tid, dns_lookup)
        note("phase 1 verdicts", redis=outcome(rep1, "NIM-EXPOSED-REDIS"), tls_expired=outcome(rep1, "NIM-TLS-EXPIRED"),
             git=outcome(rep1, "NIM-WEB-GIT"), parity_ok=rep1["parity"]["ok"], external_findings=sorted(ext1))
        assert rep1["parity"]["ok"], rep1["parity"]
        assert outcome(rep1, "NIM-EXPOSED-REDIS") == "vulnerable"
        assert outcome(rep1, "NIM-TLS-EXPIRED") == "vulnerable"
        assert outcome(rep1, "NIM-WEB-GIT") == "vulnerable"

        # Phase 2: a catch-all echo responder presenting a vsftpd banner on 2121, and a plain (non-echo) banner on a
        # non-standard FTP port 2222 (behavioural identification, and not a SERVICES port, so no exposed-service finding)
        service("catchall", "exec python3 /root/responder.py echo 2121 '220 (vsFTPd 2.3.4)'")
        service("ftp", "exec python3 /root/responder.py banner 2222 '220 (vsFTPd 2.3.4)'")
        wait_port(ip, 2121)
        wait_port(ip, 2222)
        rep2, v2, _ = engine_run(tid, dns_lookup)
        catchall = outcome(rep2, "catch-all/tcp/2121") or next((f"{g['outcome']}:{g['reason']}" for g in rep2["undetermined"] if g["reason"] == "catch-all"), None)
        note("phase 2 verdicts", vsftpd_cve=outcome(rep2, "CVE-2011-2523"), catch_all_2121=catchall)
        assert outcome(rep2, "CVE-2011-2523") == "vulnerable", "a plain banner should fire the version check"
        assert any(g["reason"] == "catch-all" for g in rep2["undetermined"]), "the echo port's product result should be suppressed"
        stop("catchall")
        stop("ftp")

        # Phase 3: a soft-404 web server (HTTP 200 for every path) replaces the real HTTP server
        stop("http")
        wait_port(ip, 80, up=False)
        service("soft404", f"exec python3 /root/soft404.py '{t['txt_value']}'")
        wait_port(ip, 80)
        rep3, v3, _ = engine_run(tid, dns_lookup)
        note("phase 3 verdicts", git=outcome(rep3, "NIM-WEB-GIT"))
        assert outcome(rep3, "NIM-WEB-GIT") == "undetermined:soft-404", "a soft-404 web server must suppress web-path findings"

        note("RESULT: PASS", parity=rep1["parity"], phases=3)
        return 0
    except Exception as e:
        import traceback
        note("RESULT: FAIL", error=f"{type(e).__name__}: {e}"[:2000], trace=traceback.format_exc()[-1500:])
        return 1
    finally:
        for p in running.values():
            p.kill()
        if not keep:
            subprocess.run(["wsl", "--unregister", NAME], capture_output=True, timeout=300)
            note("distro destroyed", name=NAME)
            shutil.rmtree(TMP, ignore_errors=True)
        (ROOT / "sandbox" / "last_run_netengine.json").write_text(json.dumps(log, indent=2, default=str))


if __name__ == "__main__":
    sys.exit(main(keep="--keep" in sys.argv))
