"""Jira contract check (tasks/spec-tickets.md; DECISIONS 150, 154): every REST v2 call `tickets.Jira` makes, checked against
Atlassian's published OpenAPI spec for the Jira Cloud platform. The path and method exist, each query parameter and body
property Nimstead sends is declared, and each response field it reads is in the response schema. Data Center serves the
same v2 paths (its own /search is covered by the tests' model, not this spec).

Run from api/:  uv run python ../sandbox/jira_contract.py
Downloads the spec (public, no account) and writes sandbox/last_run_jira_contract.json: PASS only if nothing is missing.
"""

import json
import sys
import time
from pathlib import Path

import httpx

SPEC = "https://developer.atlassian.com/cloud/jira/platform/swagger.v3.json"  # REST API v2, in OpenAPI 3 form
OUT = Path(__file__).with_name("last_run_jira_contract.json")
CALLS = [  # method, path, query parameters sent, body properties sent, response fields read (dotted, [] = array items)
    ("get", "/rest/api/2/myself", [], [], ["displayName", "name", "emailAddress"]),
    ("get", "/rest/api/2/project/{projectIdOrKey}", [], [], ["name", "issueTypes.[].id", "issueTypes.[].name", "issueTypes.[].subtask"]),
    ("post", "/rest/api/2/issue", [], ["fields"], ["key"]),
    ("put", "/rest/api/2/issue/{issueIdOrKey}", [], ["fields", "update"], []),
    ("post", "/rest/api/2/issue/{issueIdOrKey}/comment", [], ["body"], []),
    ("get", "/rest/api/2/issue/{issueIdOrKey}", ["fields"], [], ["key", "fields"]),
    ("get", "/rest/api/2/issue/{issueIdOrKey}/transitions", ["expand"], [],
     ["transitions.[].id", "transitions.[].to.statusCategory.key", "transitions.[].fields"]),
    ("post", "/rest/api/2/issue/{issueIdOrKey}/transitions", [], ["transition", "transition.id", "fields"], []),
    ("get", "/rest/api/2/search/jql", ["jql", "fields", "maxResults"], [], ["issues.[].id", "issues.[].key"]),
]


def check(spec: dict) -> list[str]:
    """Every way the spec disagrees with CALLS."""
    schemas = spec["components"]["schemas"]

    def resolve(s, depth=0):
        while isinstance(s, dict) and "$ref" in s:
            s = schemas[s["$ref"].rsplit("/", 1)[1]]
        if isinstance(s, dict) and "allOf" in s and depth < 5:
            return {"properties": {k: v for part in s["allOf"] for k, v in resolve(part, depth + 1).get("properties", {}).items()}}
        return s or {}

    def prop(s, path):
        for step in path.split("."):
            s = resolve(s)
            if step == "[]":
                s = s.get("items")
            elif step in (s.get("properties") or {}):
                s = s["properties"][step]
            else:
                return None
        return resolve(s)

    problems = []
    for method, path, query, body, reads in CALLS:
        op, name = spec["paths"].get(path, {}).get(method), f"{method.upper()} {path}"
        if not op:
            problems.append(f"{name}: not in the spec")
            continue
        declared = {p["name"] for p in map(resolve, op.get("parameters", [])) if p.get("in") == "query"}
        problems += [f"{name}: query parameter {q} not declared" for q in query if q not in declared]
        sent = resolve(next(iter(((op.get("requestBody") or {}).get("content") or {}).values()), {}).get("schema"))
        problems += [f"{name}: body property {b} not declared" for b in body if prop(sent, b) is None]
        ok = next((r for code, r in op.get("responses", {}).items() if code.startswith("2")), None)
        got = resolve(next(iter((resolve(ok).get("content") or {}).values()), {}).get("schema")) if ok else {}
        problems += [f"{name}: response field {f} not in the schema" for f in reads if prop(got, f) is None]
    return problems


def main() -> int:
    spec = httpx.get(SPEC, timeout=60, follow_redirects=True).raise_for_status().json()
    problems = check(spec)
    OUT.write_text(json.dumps({"result": "FAIL" if problems else "PASS", "problems": problems, "calls": len(CALLS), "spec": SPEC,
                               "spec_version": spec["info"].get("version"), "when": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}, indent=1))
    print("RESULT:", "PASS" if not problems else f"FAIL {problems}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
