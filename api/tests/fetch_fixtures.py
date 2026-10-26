"""Refresh OSV oracle fixtures: `uv run python tests/fetch_fixtures.py [FILTER...]`.

With filters, only cases whose "ecosystem/name" contains one of them are fetched (e.g. `Maven NuGet rack`);
without, all are refreshed.

For each package we store every OSV record for it plus OSV's own answer
(advisory ids) for a few installed versions. test_match.py asserts our
local matcher agrees with OSV exactly — an accuracy check against the
reference implementation on real data.
"""

import json
import re
import sys
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
    ("Maven", "org.apache.logging.log4j:log4j-core", ["2.14.1", "2.17.0", "2.17.1", "2.3.2"]),
    ("Maven", "com.fasterxml.jackson.core:jackson-databind", ["2.9.10", "2.13.4.2"]),
    ("NuGet", "Newtonsoft.Json", ["12.0.3", "13.0.1"]),
    ("NuGet", "System.Text.Encodings.Web", ["4.7.1", "5.0.1"]),
    ("RubyGems", "rack", ["2.2.3", "2.2.8", "3.0.0.beta1"]),
    ("RubyGems", "nokogiri", ["1.13.9", "1.16.5"]),
    ("Packagist", "laravel/framework", ["8.0.0", "9.52.0", "10.48.29"]),
    ("Packagist", "symfony/http-kernel", ["4.4.0", "5.4.20", "6.4.0"]),
    ("Packagist", "guzzlehttp/guzzle", ["6.5.7", "7.4.4"]),
    ("Hex", "plug", ["1.10.0", "1.14.0"]),
    ("Hex", "phoenix", ["1.5.0", "1.6.14"]),
    ("Pub", "http", ["0.12.2", "0.13.3", "1.2.0"]),
    ("Pub", "archive", ["3.3.0", "3.3.8", "3.6.1"]),
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


def main(filters: list[str]) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    with httpx.Client(timeout=60) as c:
        for eco, name, versions in CASES:
            if filters and not any(f in f"{eco}/{name}" for f in filters):
                continue
            pkg = {"name": name, "ecosystem": eco}
            records = query(c, {"package": pkg})
            keep = ("id", "aliases", "upstream", "withdrawn", "summary", "severity")
            slim = [
                {**{k: r[k] for k in keep if k in r},
                 "affected": [a for a in r.get("affected", []) if a.get("package", {}).get("name") == name]}
                for r in records
            ]
            oracle = {v: sorted(x["id"] for x in query(c, {"package": pkg, "version": v})) for v in versions}
            fname = re.sub(r"[^A-Za-z0-9._-]", "_", f"{eco}__{name}") + ".json"
            (OUT / fname).write_text(json.dumps({"ecosystem": eco, "name": name, "records": slim, "oracle": oracle}))
            print(fname, len(records), {v: len(ids) for v, ids in oracle.items()})


if __name__ == "__main__":
    main(sys.argv[1:])
