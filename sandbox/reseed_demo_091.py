"""Make the 0.9.1 demo tell the truth (tasks/plan-design-ceiling.md, Theme 8).

Reviewers kept reporting the demo's own shortcuts as product bugs: machines named *-prod-* marked as test machines,
and a curl rollout written straight into the database, so its "Fixed and verified" jobs had no ledger trail and
Evidence disagreed with Remediation. This script:

1. undoes those direct writes (the inserted curl jobs, and the findings they resolved by hand);
2. gives machines roles that match their names: *-dev-* and *-staging-* are test machines, *-prod-* is not;
3. drives a real curl rollout through the product's own API: plan, approve, the agent fetching and reporting
   the job, and an inventory that proves the upgrade, so verify(), the ledger and Evidence all agree.

Only the agent keys of the machines it drives are set directly (standing in for re-enrolment); everything that
the UI shows about the rollout comes from the API. Run from api/ with the demo env:
    set -a; . demo/demo-091.env; set +a; .venv/Scripts/python.exe ../sandbox/reseed_demo_091.py
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import sqlite3
import struct
import sys
import time
from pathlib import Path

from fastapi.testclient import TestClient

from nimstead.app import create_app

sys.path.insert(0, str(Path(__file__).parent))
import agentdoc  # noqa: E402  # the document a current agent sends with its inventory: the engine judges nothing without it

DB = os.environ["NIMSTEAD_DB"]
path = DB.removeprefix("sqlite:///")
# NIMSTEAD_DB is also what a real server reads: refuse anything but a demo database, since this rewrites jobs and roles
if "demo" not in Path(path).name:
    sys.exit(f"refusing: {path} is not a demo database (its file name must contain 'demo')")
if not Path(path + ".before-reseed").exists():  # keep the first backup: a rerun starts from the same state
    shutil.copyfile(path, path + ".before-reseed")
shutil.copyfile(path + ".before-reseed", path)
here = Path(path).parent

# 1. undo the direct writes
c = sqlite3.connect(path)
jobs = c.execute("select id, status, finding_ids from remediation_job where action_key like '%|curl'").fetchall()
reopened = 0
for _, status, fids in jobs:
    if status == "succeeded":
        for fid in json.loads(fids or "[]"):
            reopened += c.execute("update finding set status='open', resolved_at=null where id=? and status='resolved'", (fid,)).rowcount
c.execute("delete from remediation_job where action_key like '%|curl'")
# 2. roles that match names
c.execute("update asset set sandbox = (hostname like '%-dev-%' or hostname like '%-staging-%') where kind='host'")
c.commit()
print(f"removed {len(jobs)} inserted curl jobs, reopened {reopened} findings; roles follow names")

# the machines the rollout runs on: Ubuntu 24.04 test machines with open curl findings, canary ring first
rows = c.execute("""select a.id, a.hostname, a.ring from asset a where a.kind='host' and a.sandbox=1 and a.ecosystem='Ubuntu:24.04'
                    and exists (select 1 from finding f where f.asset_id=a.id and f.package='curl' and f.status='open')
                    order by a.ring, a.hostname""").fetchall()
canary = [r for r in rows if r[2] == 0][:2]
broad = [r for r in rows if r[2] != 0][:6]
keys = {}
for aid, _host, _ in canary + broad:
    k = secrets.token_urlsafe(32)
    keys[aid] = k
    c.execute("update asset set agent_key_hash=? where id=?", (hashlib.sha256(k.encode()).hexdigest(), aid))
c.commit()
print("canary:", [h for _, h, _ in canary], "broad:", [h for _, h, _ in broad])


def totp(secret: str) -> str:
    key = base64.b32decode(secret)
    h = hmac.new(key, struct.pack(">Q", int(time.time()) // 30), hashlib.sha1).digest()
    o = h[-1] & 15
    return f"{(struct.unpack('>I', h[o:o + 4])[0] & 0x7FFFFFFF) % 1000000:06d}"


login = (here / "login.txt").read_text()
email = re.search(r"email: (\S+)", login)[1]
password = re.search(r"password: (\S+)", login)[1]
secret = re.search(r"totp setup key[^:]*: (\S+)", login)[1]
api = TestClient(create_app(DB))
r = api.post("/api/auth/login", json={"email": email, "password": password, "code": totp(secret)})
if r.status_code != 200:  # a code used in this 30 s window is refused: wait for the next
    time.sleep(31 - time.time() % 30)
    r = api.post("/api/auth/login", json={"email": email, "password": password, "code": totp(secret)})
assert r.status_code == 200, r.text


def agent(aid):
    return {"Authorization": f"Bearer {keys[aid]}"}


def inventory(aid, upgrade_to=None):
    """The machine's own package list, with curl (and its libraries) at upgrade_to when given."""
    pk = c.execute("select ecosystem, name, version, source, source_version from installed_package where asset_id=?", (aid,)).fetchall()
    eco = c.execute("select ecosystem from asset where id=?", (aid,)).fetchone()[0]
    out = []
    for e, name, version, source, sv in pk:
        is_curl = (source or name) == "curl"
        p = {"ecosystem": e, "name": name, "version": upgrade_to if (upgrade_to and is_curl) else version}
        if source:
            p["source"] = source
        if sv and not (upgrade_to and is_curl):
            p["source_version"] = sv
        out.append(p)
    return agentdoc.with_document({"ecosystem": eco, "os_name": "Ubuntu 24.04.5 LTS", "packages": out})


def plan(aid):
    r = api.post("/api/remediation/jobs", json={"asset_id": aid, "ecosystem": "Ubuntu:24.04", "package": "curl"})
    assert r.status_code == 201, r.text
    return r.json()


# 3a. canary: planned, approved, fetched, applied, proven by the next inventory
for aid, host, _ in canary:
    j = plan(aid)
    target = max(p["to"] for p in j["packages"] if p.get("to")) if any(p.get("to") for p in j["packages"]) else None
    assert api.post(f"/api/remediation/jobs/{j['id']}/approve", json={"forward_only": False}).status_code == 200
    assert [x["id"] for x in api.get("/api/agent/jobs", headers=agent(aid)).json()] == [j["id"]]
    api.post(f"/api/agent/jobs/{j['id']}/report", headers=agent(aid), json={"outcome": "applied", "steps": [
        {"step": "snapshot curl, libcurl4t64, libcurl3t64-gnutls", "ok": True},
        {"step": "dry run: only the planned packages change", "ok": True},
        {"step": "apt-get install --only-upgrade curl", "ok": True}]})
    version = target or c.execute("select max(fixed_version) from finding where asset_id=? and package='curl'", (aid,)).fetchone()[0]
    api.post("/api/agent/inventory", headers=agent(aid), json=inventory(aid, version))
    status = next(x for x in api.get("/api/remediation/jobs").json() if x["id"] == j["id"])["status"]
    print(f"canary {host}: {status}")

# 3b. broad: two approved and running, the rest waiting for approval
for i, (aid, host, _) in enumerate(broad):
    j = plan(aid)
    if i < 2:
        api.post(f"/api/remediation/jobs/{j['id']}/approve", json={"forward_only": False})
        if i == 0:
            api.get("/api/agent/jobs", headers=agent(aid))  # picked up: running
    print(f"broad {host}: {'approved' if i < 2 else 'planned'}")
print("done; backup at", path + ".before-reseed")
