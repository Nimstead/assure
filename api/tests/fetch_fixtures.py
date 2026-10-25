"""Refresh OSV oracle fixtures: `uv run python tests/fetch_fixtures.py`.

For each package we store every OSV record for it plus OSV's own answer
(advisory ids) for a few installed versions. test_match.py asserts our
local matcher agrees with OSV exactly — an accuracy check against the
reference implementation on real data.
"""

import json
from pathlib import Path

import httpx

CASES = [
    ("Debian:12", "openssl", ["3.0.11-1~deb12u2", "3.0.15-1~deb12u1", "3.0.17-1~deb12u2"]),
    ("Debian:12", "glibc", ["2.36-9+deb12u3", "2.36-9+deb12u10"]),
    ("Ubuntu:22.04:LTS", "curl", ["7.81.0-1ubuntu1.13", "7.81.0-1ubuntu1.20"]),
    ("Alpine:v3.18", "openssl", ["3.1.4-r0", "3.1.7-r1"]),
    ("Rocky Linux:9", "openssl", ["1:3.0.7-24.el9", "1:3.2.2-6.el9_5"]),
    ("PyPI", "requests", ["2.19.0", "2.31.0", "2.32.4"]),
    ("npm", "lodash", ["4.17.15", "4.17.21"]),
]

OUT = Path(__file__).parent / "fixtures" / "osv"


def query(client: httpx.Client, body: dict) -> list[dict]:
    vulns, token = [], None
    while True:
        r = client.post("https://api.osv.dev/v1/query", json={**body, **({"page_token": token} if token else {})})
        r.raise_for_status()
        d = r.json()
        vulns += d.get("vulns", [])
        token = d.get("next_page_token")
        if not token:
            return vulns


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    with httpx.Client(timeout=60) as c:
        for eco, name, versions in CASES:
            pkg = {"name": name, "ecosystem": eco}
            records = query(c, {"package": pkg})
            keep = ("id", "aliases", "upstream", "withdrawn", "summary", "severity")
            slim = [
                {**{k: r[k] for k in keep if k in r},
                 "affected": [a for a in r.get("affected", []) if a.get("package", {}).get("name") == name]}
                for r in records
            ]
            oracle = {v: sorted(x["id"] for x in query(c, {"package": pkg, "version": v})) for v in versions}
            fname = f"{eco.replace(':', '_').replace(' ', '_')}__{name}.json"
            (OUT / fname).write_text(json.dumps({"ecosystem": eco, "name": name, "records": slim, "oracle": oracle}))
            print(fname, len(records), {v: len(ids) for v, ids in oracle.items()})


if __name__ == "__main__":
    main()
