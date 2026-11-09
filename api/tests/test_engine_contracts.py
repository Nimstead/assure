"""Source-backed reference checks for collection, report and fleet formats."""

from pathlib import Path

from test_engine import BUILD
from test_engine_apps import REQUESTS, pypi, sbom_inv
from test_engine_fleet import OPEN_445, host
from test_engine_paths import LOCAL, WEAK, rec, run

from nimstead.engine import fleet, report
from nimstead.engine.collection import Inventory, valid_document
from nimstead.engine.content import Content
from nimstead.engine.evaluate import evaluate
from nimstead.engine.model import REASONS

REFERENCE = Path(__file__).resolve().parents[2] / "docs" / "reference"


def _fields_documented(text, *rows):
    for row in rows:
        for field in row:
            assert f"`{field}`" in text, f"Undocumented response field: {field}"


def test_scan_reference_covers_emitted_fields_and_reason_codes():
    _, r = run(rec("CVE-2026-1001", LOCAL), rec("CVE-2026-1002", LOCAL, fixed=BUILD), config=WEAK,
               sources={"microsoft_products": {"state": "failed", "count": 0}})
    text = (REFERENCE / "scan-report.md").read_text()
    _fields_documented(text, r, r["headline"], r["coverage"], r["coverage"]["applications"])
    _fields_documented(text, *r["vulnerable"], *r["undetermined"], *r["not_vulnerable"])
    _fields_documented(text, *r["coverage"]["sources"], *r["coverage"]["families"].values())
    assert r["vulnerable"] and r["attack_paths"] and r["undetermined"] and r["not_vulnerable"]
    for group in r["vulnerable"]:
        _fields_documented(text, *group["vulnerabilities"])
    for path in r["attack_paths"]:
        _fields_documented(text, path, path["break_at"], *path["steps"])
        for step in path["steps"]:
            _fields_documented(text, *step["ways"])
        if path["then"]:
            _fields_documented(text, path["then"], *path["then"]["ways"])
    outcomes = (REFERENCE / "scan-outcomes.md").read_text()
    assert all(f"`{reason}`" in outcomes for reason in REASONS)


def test_application_report_fields_are_in_the_reference():
    c = Content.make({("PyPI", "requests"): [REQUESTS]}, feeds={"PyPI"})
    inv = sbom_inv(pypi("requests", "2.19.1"))
    r = report.build(inv, c, evaluate(inv, c))
    assert r["applications"]
    _fields_documented((REFERENCE / "scan-report.md").read_text(), *r["applications"])


def test_fleet_reference_covers_emitted_fields():
    a = host("a", WEAK, recs=[rec("CVE-2026-1001", LOCAL)])
    b = host("b", {"remote_uac_off": 1}, {"listening": OPEN_445})
    r = fleet.build([a, b])
    text = (REFERENCE / "fleet-paths.md").read_text()
    assert r["edges"] and r["chains"]
    _fields_documented(text, r, *r["hosts"].values(), *r["edges"], *r["chains"])
    for h in r["hosts"].values():
        _fields_documented(text, *h["paths"])
    for edge in r["edges"]:
        _fields_documented(text, *edge["ways"])
    for chain in r["chains"]:
        _fields_documented(text, *chain["reach"])


def test_collection_validation_accepts_root_extras_but_closes_source_entries():
    d = {"v": True, "sources": {"package_db": {"state": "ok", "count": 1}}, "extra": "retained"}
    assert valid_document(d)
    d["v"] = 1.0
    assert valid_document(d)
    d["sources"]["package_db"]["extra"] = 1
    assert not valid_document(d)


def test_agent_document_loader_is_not_an_application_round_trip():
    original = Inventory(kind="application", received=False, sbom={"components": 0})
    loaded = Inventory.from_doc(original.to_doc())
    assert loaded.kind == "host" and loaded.sbom is None and loaded.received


