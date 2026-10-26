"""Production key storage against REAL services in a DISPOSABLE WSL distro: HashiCorp Vault (transit) and an S3
server with object lock (Versity S3 gateway; MinIO's open-source server is archived).

Run from api/:  uv run python ../sandbox/keystore.py [--keep]
Proves: evidence packs are signed by Vault and verify offline; SSO secrets are Vault-encrypted; ledger checkpoints
land in S3 under COMPLIANCE object lock and cannot be deleted or overwritten; a consistent ledger rewrite is still
caught via those checkpoints. No key files are created locally.
"""

import io
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

PREFIX = "nimstead-sbx-"
NAME = PREFIX + "keys-" + secrets.token_hex(3)
TMP = Path(tempfile.mkdtemp(prefix="nimstead-sbx-keys-"))
ROOT = Path(__file__).resolve().parents[1]
VAULT, VERSITY = "2.1.1", "1.8.0"
S3_KEY, S3_SECRET = "nimstead", secrets.token_hex(12)
log: list[dict] = []
running: dict[str, subprocess.Popen] = {}


def note(step, **kw):
    log.append({"step": step, **kw})
    print(f"[{time.strftime('%H:%M:%S')}] {step}", json.dumps(kw, default=str)[:400] if kw else "", flush=True)


def vm(script: str, check=True) -> str:
    assert NAME.startswith(PREFIX)
    p = subprocess.run(["wsl", "-d", NAME, "-u", "root", "--", "sh", "-s"], input=script.encode(), capture_output=True, timeout=1800)
    if check and p.returncode != 0:
        raise RuntimeError(f"{script[:300]}\n{p.stdout.decode(errors='replace')[-1500:]}\n{p.stderr.decode(errors='replace')[-1500:]}")
    return p.stdout.decode(errors="replace")


def service(name: str, cmd: str):
    logf = open(TMP / f"{name}.log", "ab")
    running[name] = subprocess.Popen(["wsl", "-d", NAME, "-u", "root", "--", "sh", "-c", cmd], stdout=logf, stderr=logf)


def build():
    note("creating VM", name=NAME)
    r = subprocess.run(["wsl", "--install", "Debian", "--name", NAME, "--location", str(TMP / "d"), "--no-launch"],
                       capture_output=True, timeout=1800)
    if r.returncode != 0:
        raise RuntimeError((r.stdout + r.stderr).decode("utf-16-le", errors="replace"))
    running["keepalive"] = subprocess.Popen(["wsl", "-d", NAME, "-u", "root", "--", "sleep", "infinity"])
    vm("apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl unzip ca-certificates >/dev/null")
    vm(f"""set -e; mkdir -p /opt/k && cd /opt/k
        curl -fsSLO https://releases.hashicorp.com/vault/{VAULT}/vault_{VAULT}_linux_amd64.zip
        curl -fsSLO https://releases.hashicorp.com/vault/{VAULT}/vault_{VAULT}_SHA256SUMS
        grep linux_amd64.zip vault_{VAULT}_SHA256SUMS | sha256sum -c - && unzip -q vault_{VAULT}_linux_amd64.zip
        curl -fsSLO https://github.com/versity/versitygw/releases/download/v{VERSITY}/versitygw_{VERSITY}_linux_amd64.deb
        curl -fsSLO https://github.com/versity/versitygw/releases/download/v{VERSITY}/checksums.txt
        grep "versitygw_{VERSITY}_linux_amd64.deb" checksums.txt | sha256sum -c - && dpkg -i versitygw_{VERSITY}_linux_amd64.deb >/dev/null
        mkdir -p /opt/k/s3data /opt/k/s3vers""")
    note("binaries downloaded and checksum-verified", vault=VAULT, versitygw=VERSITY)
    service("vault", "cd /opt/k && exec ./vault server -dev -dev-root-token-id=root -dev-listen-address=0.0.0.0:8200")
    # explicit IPv4: Go turns 0.0.0.0 into a dual-stack socket, which WSL does not forward to Windows
    service("s3", f"exec versitygw --access {S3_KEY} --secret {S3_SECRET} --port 127.0.0.1:7070 "
                  "posix --versioning-dir /opt/k/s3vers /opt/k/s3data")
    for _ in range(60):
        if "200" in vm("curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8200/v1/sys/health", check=False):
            break
        time.sleep(1)
    vm("cd /opt/k && VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root ./vault secrets enable transit")
    import httpx  # WSL forwards new listeners to Windows' localhost after a short delay: wait from this side too
    for url in ("http://127.0.0.1:8200/v1/sys/health", "http://127.0.0.1:7070/"):
        for _ in range(90):
            try:
                httpx.get(url, timeout=2)
                break
            except httpx.HTTPError:
                time.sleep(1)
        else:
            raise RuntimeError(f"{url} not reachable from Windows")
    note("Vault (transit) and S3 gateway up, reachable from the host")


def main(keep=False) -> int:
    try:
        build()
        os.environ.update({
            "NIMSTEAD_SECURE_COOKIES": "0", "NIMSTEAD_INVENTORY_MIN_SECONDS": "0",
            "NIMSTEAD_VAULT_ADDR": "http://127.0.0.1:8200", "NIMSTEAD_VAULT_TOKEN": "root",
            "NIMSTEAD_CHECKPOINT_S3": "s3://nimstead-checkpoints/prod", "NIMSTEAD_S3_ENDPOINT": "http://127.0.0.1:7070",
            "AWS_ACCESS_KEY_ID": S3_KEY, "AWS_SECRET_ACCESS_KEY": S3_SECRET, "AWS_DEFAULT_REGION": "us-east-1",
            "NIMSTEAD_SIGNING_KEY_FILE": str(TMP / "must-not-exist.pem"), "NIMSTEAD_SECRET_KEY_FILE": str(TMP / "must-not-exist.key"),
        })
        import boto3
        s3 = boto3.client("s3", endpoint_url="http://127.0.0.1:7070")
        s3.create_bucket(Bucket="nimstead-checkpoints", ObjectLockEnabledForBucket=True)
        note("bucket created with object lock",
             config=s3.get_object_lock_configuration(Bucket="nimstead-checkpoints").get("ObjectLockConfiguration"))

        from fastapi.testclient import TestClient
        from sqlalchemy import select
        from sqlalchemy.orm import sessionmaker

        from nimstead import evidence, sso
        from nimstead.app import create_app
        from nimstead.db import Advisory, LedgerEntry, make_engine
        from nimstead.match import normalize_ecosystem
        from nimstead.verify_pack import entry_hash, verify

        db = f"sqlite:///{(TMP / 'n.db').as_posix()}"
        app = create_app(db)
        s = sessionmaker(make_engine(db))()
        fx = json.loads((ROOT / "api/tests/fixtures/osv/Debian_12__openssl.json").read_text())
        for rec in fx["records"]:
            s.merge(Advisory(id=rec["id"], ecosystem=normalize_ecosystem(fx["ecosystem"]), package=fx["name"], record=rec))
        s.commit()
        c = TestClient(app)
        c.post("/api/auth/signup", json={"email": "k@example.com", "password": "keystore-test-pass", "org_name": "K"})
        token = c.post("/api/enroll-tokens").json()["token"]
        a = c.post("/api/agent/enroll", json={"token": token, "hostname": "h", "ecosystem": "Debian:12"}).json()
        c.post("/api/agent/inventory", headers={"Authorization": f"Bearer {a['agent_key']}"}, json={"ecosystem": "Debian:12", "packages": [
            {"ecosystem": "Debian:12", "name": "libssl3", "version": "3.0.11-1~deb12u1", "source": "openssl"}]})

        # 1) evidence pack signed by Vault, verifies offline against the Vault key's fingerprint
        z = zipfile.ZipFile(io.BytesIO(c.get("/api/evidence/pack").content))
        fp = c.get("/api/evidence/public-key").json()["fingerprint_sha256"]
        problems = verify(z.read("pack.json"), z.read("pack.sig").decode(), z.read("public_key.pem"), fp)
        assert problems == [], problems
        assert not (TMP / "must-not-exist.pem").exists()
        note("evidence pack signed in Vault verifies offline", fingerprint=fp[:16], local_key_file=False)

        # 2) checkpoint in S3 under COMPLIANCE lock: delete and overwrite must be refused
        objs = s3.list_object_versions(Bucket="nimstead-checkpoints", Prefix="prod/").get("Versions", [])
        assert objs, "no checkpoint object written"
        o = objs[0]
        ret = s3.get_object_retention(Bucket="nimstead-checkpoints", Key=o["Key"], VersionId=o["VersionId"])["Retention"]
        refused = []
        for attempt in ("delete", "shorten"):
            try:
                if attempt == "delete":
                    s3.delete_object(Bucket="nimstead-checkpoints", Key=o["Key"], VersionId=o["VersionId"])
                else:
                    s3.put_object_retention(Bucket="nimstead-checkpoints", Key=o["Key"], VersionId=o["VersionId"],
                                            Retention={"Mode": "COMPLIANCE", "RetainUntilDate": "2026-10-27T00:00:00Z"})
                refused.append((attempt, False))
            except Exception as e:
                refused.append((attempt, type(e).__name__ + ": " + str(e)[:80]))
        assert all(r[1] for r in refused), refused
        note("checkpoint is write-once", key=o["Key"], mode=ret["Mode"], until=str(ret["RetainUntilDate"])[:10], refused=refused)

        # 3) a consistent rewrite of the ledger is caught via the S3 checkpoint
        org_id = s.scalar(select(LedgerEntry.org_id))
        rows = s.scalars(select(LedgerEntry).where(LedgerEntry.org_id == org_id).order_by(LedgerEntry.seq)).all()
        prev = None
        for e in rows:
            if e.seq >= 2:
                if e.seq == 2:
                    e.data = {**e.data, "tampered": True}
                e.prev_hash = prev
                e.hash = entry_hash(evidence.entry_dict(e))
            prev = e.hash
        s.commit()
        problems = evidence.verify_chain(s, org_id)
        assert any("rewritten" in p for p in problems), problems
        note("consistent ledger rewrite detected via S3 checkpoint", problems=problems[:2])

        # 4) SSO secret encrypted by Vault; domain tokens are Vault HMACs
        sealed = sso.seal("idp-client-secret")
        assert sealed.startswith("vault:v1:") and sso.unseal(sealed) == "idp-client-secret"
        assert sso.domain_token(org_id, "corp.example.com") == sso.domain_token(org_id, "corp.example.com")
        assert not (TMP / "must-not-exist.key").exists()
        note("SSO secret sealed by Vault, domain tokens via Vault HMAC", sealed_prefix=sealed[:9])
        note("RESULT: PASS")
        return 0
    except Exception as e:
        note("RESULT: FAIL", error=f"{type(e).__name__}: {e}"[:2000])
        return 1
    finally:
        for p in running.values():
            p.kill()
        if not keep:
            subprocess.run(["wsl", "--unregister", NAME], capture_output=True)
            note("VM destroyed", name=NAME)
        (ROOT / "sandbox" / "last_run_keystore.json").write_text(json.dumps(log, indent=2, default=str))
        if not keep:
            shutil.rmtree(TMP, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main(keep="--keep" in sys.argv))
