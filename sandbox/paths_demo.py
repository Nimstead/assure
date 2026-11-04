"""Seed a local server for looking at attack paths in the browser: two hosts through the real agent API.

Host "de-ltsc" sends the real German Windows 10 inventory a VM reported (taken from that run's database); "srv-files" is
synthetic: local administrators keep full rights over the network and SMB is allowed through its firewall. Both are in
the WORKGROUP, so the edge between them is unverified, as it should be.

  uv run python ../sandbox/paths_demo.py http://127.0.0.1:8002 paths-demo.db
Writes the test account it creates to paths-demo.seed.json beside the database (git-ignored, local only).
"""

import json
import secrets
import sqlite3
import sys
from pathlib import Path

import httpx


def main(base: str, db: str) -> int:
    c = sqlite3.connect(db)
    facts, os_name = c.execute("select facts, os_name from asset order by first_seen limit 1").fetchone()
    aid = c.execute("select id from asset order by first_seen limit 1").fetchone()[0]
    pkgs = [{"ecosystem": e, "name": n, "version": v, "source": s} for e, n, v, s in
            c.execute("select ecosystem, name, version, source from installed_package where asset_id = ?", (aid,))]
    collection = json.loads(c.execute("select collection from asset where id = ?", (aid,)).fetchone()[0])
    facts = json.loads(facts)
    account = {"email": f"paths-{secrets.token_hex(3)}@example.com", "password": secrets.token_urlsafe(18), "org_name": "Paths demo"}
    seed = Path(db).with_suffix(".seed.json")
    seed.write_text(json.dumps(account))
    api = httpx.Client(base_url=base, headers={"Origin": base})
    assert api.post("/api/auth/signup", json=account).status_code == 201
    server = {**facts, "config": {"remote_uac_off": 1, "smb_signing_required": True}, "listening": [{"port": 445, "process": "System", "firewall": "allowed"}]}
    for host, f, p in (("de-ltsc", facts, pkgs), ("srv-files", server, [p for p in pkgs if p["ecosystem"] == "Windows"])):
        token = api.post("/api/enroll-tokens").json()["token"]
        key = api.post("/api/agent/enroll", json={"token": token, "hostname": host, "ecosystem": "Windows"}).json()["agent_key"]
        r = api.post("/api/agent/inventory", headers={"Authorization": f"Bearer {key}"},
                     json={"hostname": host, "os_name": os_name, "ecosystem": "Windows", "agent_version": "0.5.0", "facts": f,
                           "collection": collection, "packages": p})
        assert r.status_code == 200, r.text
    out = api.get("/api/attack-paths").json()
    print(json.dumps({"hosts": {v["hostname"]: [p["kind"] for p in v["paths"]] for v in out["hosts"].values()},
                      "edges": [(out["hosts"][e["from"]]["hostname"], out["hosts"][e["to"]]["hostname"], e["grade"]) for e in out["edges"]]}))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
