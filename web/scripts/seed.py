"""Dev only: load the OSV test fixtures (+ one fake KEV entry) into ./nimstead.db so the UI has findings.

    cd api && uv run python ../web/scripts/seed.py
"""
import json
from pathlib import Path

from sqlalchemy.orm import sessionmaker

from nimstead.db import Advisory, Kev, make_engine
from nimstead.match import normalize_ecosystem

fixtures = Path(__file__).resolve().parents[2] / "api" / "tests" / "fixtures" / "osv"
s = sessionmaker(make_engine())()
for f in fixtures.glob("*.json"):
    d = json.loads(f.read_text())
    if "records" not in d:
        continue
    for r in d["records"]:
        s.merge(Advisory(id=r["id"], ecosystem=normalize_ecosystem(d["ecosystem"]), package=d["name"], record=r))
s.merge(Kev(cve="CVE-2024-35195", date_added="2024-06-01"))
s.commit()
print("seeded")
