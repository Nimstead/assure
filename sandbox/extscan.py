"""External scanning against REAL services in a DISPOSABLE WSL distro (Debian): an unauthenticated Redis and an
OpenSSL TLS server, reached at the distro's own IP (not localhost, so this PC's own services can't leak in).

Run from api/:  uv run python ../sandbox/extscan.py [--keep]
1. No TXT record: the scan is refused and nothing is probed. TXT record but the address doesn't serve the value at
   /.well-known/nimstead-verify.txt: verification is refused. Once a real HTTP server there serves it: verified.
2. Redis exposed + TLS server with an EXPIRED certificate that also accepts TLS 1.0/1.1: each must be found.
3. Redis stopped, TLS restarted with a valid self-signed certificate, TLS 1.2+ only: the earlier findings must
   close and "untrusted certificate" must open.
The private-address guard is switched off for this run only (NIMSTEAD_ALLOW_PRIVATE_TARGETS=1): the WSL address is
private by nature. Logs to sandbox/last_run_extscan.json.
"""

import datetime as dt
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from signin import signup  # noqa: E402  first account + its admin's TOTP sign-in

ROOT = Path(__file__).resolve().parents[1]
PREFIX = "nimstead-sbx-"
NAME = PREFIX + "ext-" + secrets.token_hex(3)
TMP = Path(tempfile.mkdtemp(prefix="nimstead-sbx-ext-"))
HOST = "shop.example.com"
log: list[dict] = []
running: dict[str, subprocess.Popen] = {}


def note(step, **kw):
    log.append({"step": step, **kw})
    print(f"[{time.strftime('%H:%M:%S')}] {step}", json.dumps(kw, default=str)[:500] if kw else "", flush=True)


def vm(script: str, input_path: str | None = None, check=True) -> str:
    assert NAME.startswith(PREFIX)
    p = subprocess.run(["wsl", "-d", NAME, "-u", "root", "--", "sh", "-s"], input=script.encode(), capture_output=True, timeout=1200)
    if check and p.returncode != 0:
        raise RuntimeError(f"{script[:300]}\n{p.stdout.decode(errors='replace')[-800:]}\n{p.stderr.decode(errors='replace')[-800:]}")
    return p.stdout.decode(errors="replace")


def put(path: str, data: bytes):
    subprocess.run(["wsl", "-d", NAME, "-u", "root", "--", "sh", "-c", f"cat > {path}"], input=data, check=True)


def service(name: str, cmd: str):
    if name in running:
        running.pop(name).kill()
        vm(f"pkill -f '{cmd.split()[0]}' || true", check=False)
        time.sleep(1)
    logf = open(TMP / f"{name}.log", "ab")
    running[name] = subprocess.Popen(["wsl", "-d", NAME, "-u", "root", "--", "sh", "-c", cmd], stdout=logf, stderr=logf)


def cert(days_from: int, days_to: int) -> tuple[bytes, bytes]:
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


def main(keep=False) -> int:
    try:
        r = subprocess.run(["wsl", "--install", "Debian", "--name", NAME, "--location", str(TMP / "d"), "--no-launch"],
                           capture_output=True, timeout=1800)
        if r.returncode != 0:
            raise RuntimeError((r.stdout + r.stderr).decode("utf-16-le", errors="replace"))
        running["keepalive"] = subprocess.Popen(["wsl", "-d", NAME, "-u", "root", "--", "sleep", "infinity"])
        vm("apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq redis-server openssl iproute2 python3 >/dev/null")
        vm("systemctl disable --now redis-server >/dev/null 2>&1 || true")  # the package starts its own, bound to localhost
        ip = vm("ip -4 -o addr show eth0 | awk '{print $4}' | cut -d/ -f1").strip()
        versions = vm("redis-server --version | cut -d' ' -f3; openssl version").split()
        note("distro up", name=NAME, address=ip, redis=versions[0], openssl=" ".join(versions[1:3]))
        expired = cert(-400, -30)
        valid = cert(-1, 365)
        put("/root/expired.pem", expired[0])
        put("/root/expired.key", expired[1])
        put("/root/valid.pem", valid[0])
        put("/root/valid.key", valid[1])

        os.environ.update(NIMSTEAD_SECURE_COOKIES="0", NIMSTEAD_ALLOW_PRIVATE_TARGETS="1", NIMSTEAD_SIGNING_KEY_FILE=str(TMP / "s.pem"),
                          NIMSTEAD_SECRET_KEY_FILE=str(TMP / "s.key"), NIMSTEAD_CHECKPOINT_DIR=str(TMP / "cp"))
        from fastapi.testclient import TestClient

        from nimstead import external, netguard
        from nimstead.app import create_app
        real_gai = netguard.socket.getaddrinfo
        netguard.socket.getaddrinfo = lambda h, *a, **k: [(2, 1, 6, "", (ip, 443))] if h == HOST else real_gai(h, *a, **k)
        txt = {}
        c = TestClient(create_app(f"sqlite:///{(TMP / 'n.db').as_posix()}", dns_lookup=lambda n: txt.get(n, [])))
        signup(c, {"email": "ext@example.com", "password": "correct horse battery", "org_name": "Ext"})
        t = c.post("/api/targets", json={"hostname": HOST}).json()

        # 1) not proven: refused, nothing probed
        probes = []
        real_checks = external.checks
        external.checks = lambda *a: probes.append(a) or real_checks(*a)
        r1 = c.post(f"/api/targets/{t['id']}/scan")
        note("unverified target", status=r1.status_code, detail=r1.json().get("detail"), probes_sent=len(probes))
        assert r1.status_code == 409 and not probes
        txt[t["txt_name"]] = [t["txt_value"]]
        r = c.post(f"/api/targets/{t['id']}/verify")  # the name is ours, but nothing at the address says so yet
        note("TXT only, no address proof", status=r.status_code, detail=r.json().get("detail"))
        assert r.status_code == 409 and external.PROOF_PATH in r.json()["detail"]
        vm(f"mkdir -p /root/www/.well-known && printf '%s\\n' '{t['txt_value']}' > /root/www/.well-known/nimstead-verify.txt")
        service("http", "exec python3 -m http.server 80 --directory /root/www")
        wait_port(ip, 80)
        assert c.post(f"/api/targets/{t['id']}/verify").json()["verified"] is True
        note("verified: TXT record and the value served by the address itself")

        # 2) exposed Redis + expired certificate + legacy TLS accepted
        service("redis", "exec redis-server --bind 0.0.0.0 --protected-mode no --port 6379 --save ''")
        service("tls", "exec openssl s_server -quiet -accept 443 -cert /root/expired.pem -key /root/expired.key -www "
                       "-min_protocol TLSv1 -cipher DEFAULT:@SECLEVEL=0")
        wait_port(ip, 6379)
        wait_port(ip, 443)
        r2 = c.post(f"/api/targets/{t['id']}/scan").json()
        f2 = {f["vuln_id"]: f["priority"] for f in c.get("/api/findings").json()}
        note("scan 1: Redis open, expired cert, TLS 1.0 on", result=r2, findings=f2)
        assert {"NIM-EXPOSED-REDIS", "NIM-TLS-EXPIRED"} <= set(f2), f2
        assert ("NIM-TLS-LEGACY" in f2) or r2["skipped"], "legacy TLS neither found nor reported as unchecked"
        assert f2["NIM-EXPOSED-REDIS"] == "fix-now"

        # 3) fixed: Redis gone, valid (self-signed) cert, TLS 1.2+ only
        running.pop("redis").kill()
        vm("pkill redis-server || true", check=False)
        wait_port(ip, 6379, up=False)
        service("tls", "exec openssl s_server -quiet -accept 443 -cert /root/valid.pem -key /root/valid.key -www -min_protocol TLSv1.2")
        wait_port(ip, 443)
        r3 = c.post(f"/api/targets/{t['id']}/scan").json()
        f3 = {f["vuln_id"] for f in c.get("/api/findings").json()}
        resolved = {f["vuln_id"] for f in c.get("/api/findings", params={"status": "resolved"}).json()}
        note("scan 2: Redis closed, valid self-signed cert, TLS 1.2+", result=r3, open=sorted(f3), resolved=sorted(resolved))
        assert f3 == {"NIM-TLS-UNTRUSTED"}, f3
        assert {"NIM-EXPOSED-REDIS", "NIM-TLS-EXPIRED"} <= resolved
        note("RESULT: PASS", legacy_tls_checked=not r2["skipped"])
        return 0
    except Exception as e:
        note("RESULT: FAIL", error=f"{type(e).__name__}: {e}"[:2000])
        return 1
    finally:
        for p in running.values():
            p.kill()
        if not keep:
            subprocess.run(["wsl", "--unregister", NAME], capture_output=True)
            note("distro destroyed", name=NAME)
            shutil.rmtree(TMP, ignore_errors=True)
        (ROOT / "sandbox" / "last_run_extscan.json").write_text(json.dumps(log, indent=2, default=str))


if __name__ == "__main__":
    sys.exit(main(keep="--keep" in sys.argv))
