"""Source-backed Windows settings and baseline reference contracts."""

import ast
import json
import re
from datetime import date
from pathlib import Path

from test_api import user
from test_winbaseline import enrol_host

from nimstead import winbaseline, winconfig

REFERENCE = Path(__file__).resolve().parents[2] / "docs" / "reference"


def test_baseline_api_fields_match_reference_and_schema(env):
    c = user(env)
    aid = enrol_host(c, "baseline-contract")
    detail = c.get(f"/api/baselines/{aid}").json()
    fleet = c.get("/api/baselines").json()
    assert detail["rules"] and fleet["hosts"] and fleet["baselines"]
    schemas = json.loads((REFERENCE / "openapi.json").read_text())["components"]["schemas"]
    reference = (REFERENCE / "windows-checks.md").read_text()
    for name, rows in (("BaselineDetail", [detail]), ("BaselineRule", detail["rules"]),
                       ("BaselineHostSummary", fleet["hosts"]), ("BaselineAggregate", fleet["baselines"])):
        fields = set(schemas[name]["properties"])
        assert fields == set(schemas[name]["required"])
        assert all(set(row) == fields for row in rows)
        assert all(f"`{field}`" in reference for field in fields)
    assert detail["pass"] + detail["fail"] + detail["not_assessed"] + detail["not_applicable"] == detail["automated"]
    assert detail["manual"] > 0
    empty = winbaseline.evaluate("Windows 11 Pro", {})
    assert empty["not_assessed"] == empty["automated"]


def test_configuration_default_rules_can_report_missing_values():
    rows = winconfig.evaluate({"config": {}, "installation_type": "Server", "domain_role": 5}, "10.0.17763.1")
    assert {r["package"] for r in rows} == {"speculative-execution", "ldap-signing", "ldap-channel-binding"}
    assert all(not ({"score", "priority", "reasons"} & r.keys()) for r in rows)


def test_certificate_checks_require_a_config_dictionary():
    facts = {"machine_certs": [{"private_key": True, "subject": "test", "not_after": "2000-01-01"}]}
    assert winconfig.evaluate(facts, today=date(2026, 11, 9)) == []
    rows = winconfig.evaluate({**facts, "config": {}}, today=date(2026, 11, 9))
    assert [r["package"] for r in rows] == ["machine-cert-expired"]


def test_reference_names_static_configuration_input_keys():
    tree = ast.parse(Path(winconfig.__file__).read_text())
    keys = {n.args[0].value for n in ast.walk(tree)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "get"
            and isinstance(n.func.value, ast.Name) and n.func.value.id in {"facts", "c", "d", "pp", "r", "x", "cert"}
            and n.args and isinstance(n.args[0], ast.Constant) and isinstance(n.args[0].value, str)}
    reference = (REFERENCE / "windows-checks.md").read_text()
    assert all(re.search(r"\b" + re.escape(key) + r"\b", reference) for key in keys)
