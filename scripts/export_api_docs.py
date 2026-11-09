"""Export API lookup material from FastAPI; run in the locked API environment.

python scripts/export_api_docs.py writes the schema and endpoint catalog.
python scripts/export_api_docs.py --check refuses stale generated documentation.
Only an in-memory SQLite database is created. No provider or feed requests are made.
"""

import argparse
import json
from pathlib import Path

import httpx
from fastapi.routing import APIRoute

from nimstead.app import MAX_BODY, SESSION_COOKIE, create_app
from nimstead.sbom import MAX_COMPONENTS, MAX_DEPTH, SPDX_VERSIONS, SPEC_VERSIONS

ROOT = Path(__file__).resolve().parents[1]
SPECIAL_AUTH = {
    "/api/agent/enroll": "Enrolment token in JSON body",
    "/api/assets/{asset_id}/sbom": "Asset upload/agent key or admin session",
    "/api/auth/sso/callback": "SSO flow cookie and provider response",
    "/api/notify/confirm": "Confirmation token",
    "/api/auth/signup/confirm": "Signup confirmation token",
}


def render() -> dict[str, str]:
    """Return generated repository paths mapped to UTF-8 document contents.

    Build the current FastAPI app with an in-memory database and caller-owned HTTP client.
    The catalog reflects typed parameters and named authentication dependencies. Routes that
    authenticate inside their body use explicit labels. Schema-generation errors propagate.
    """
    with httpx.Client() as client:
        app = create_app("sqlite://", oidc_http=client)
        schema = app.openapi()
    schema["servers"] = [{"url": "/", "description": "The Assure server you operate"}]
    schema["components"]["securitySchemes"] = {
        "SessionCookie": {"type": "apiKey", "in": "cookie", "name": SESSION_COOKIE,
                          "description": "Browser session. Role and two-step requirements depend on the operation."},
        "ReadToken": {"type": "http", "scheme": "bearer", "bearerFormat": "nmt_",
                      "description": "Organisation token; only accepted on eligible GET/HEAD operations."},
        "AgentToken": {"type": "http", "scheme": "bearer", "bearerFormat": "nma_",
                       "description": "Asset-specific agent key."},
        "UploadToken": {"type": "http", "scheme": "bearer", "bearerFormat": "nmu_",
                        "description": "Upload token for the asset named by the request."},
    }
    finding_fields = {name: {"type": "string"} for name in (
        "id", "asset_id", "hostname", "ecosystem", "package", "installed_version", "vuln_id", "summary", "priority", "status", "first_seen", "last_seen")}
    finding_fields |= {name: {"type": ["string", "null"]} for name in ("fixed_version", "rule_evidence", "resolved_at", "due")}
    finding_fields |= {name: {"type": "boolean"} for name in ("setting_fix", "plannable", "kev")}
    finding_fields |= {name: {"type": ["number", "null"]} for name in ("cvss", "epss")}
    finding_fields |= {name: {"type": "array", "items": {"type": "string"}} for name in ("advisory_ids", "reasons")}
    finding_fields["score"] = {"type": "integer"}
    compact_fields = {name: finding_fields[name] for name in (
        "id", "asset_id", "hostname", "ecosystem", "package", "installed_version", "fixed_version", "vuln_id", "kev", "score", "priority", "reasons")}
    detail_fields = {**finding_fields, "package_fix": {"type": ["object", "null"], "properties": {
        "version": {"type": "string"}, "open": {"type": "integer", "minimum": 0}}, "required": ["version", "open"], "additionalProperties": False}}
    group_fields = {name: {"type": "string"} for name in ("key", "priority", "package", "vuln_id")}
    group_fields |= {name: {"type": "integer", "minimum": 0} for name in ("findings", "hosts", "score", "packages", "vulns")}
    group_fields |= {"kev": {"type": "boolean"}, "fixed_version": {"type": ["string", "null"]}, "ecosystem": {"type": ["string", "null"]}}
    for name, fields in (("FindingRow", finding_fields), ("FindingCompact", compact_fields), ("FindingDetail", detail_fields), ("FindingGroup", group_fields)):
        schema["components"]["schemas"][name] = {"type": "object", "properties": fields, "required": list(fields), "additionalProperties": False}
    lines = ["# HTTP endpoint catalog", "",
             "Use the [OpenAPI JSON](openapi.json) for typed parameters, request models, defaults, and declared response schemas.", "",
             "The export adds server/authentication metadata and selected contracts: findings, CSV, SBOM, external-scan counters, agent manifest and distribution files. Other definitions come from the app.", "",
             "Authentication labels describe entry requirements. Organisation ownership, roles, origin checks, quotas, "
             "and operation-specific state checks still apply. See [HTTP API reference](http-api.md).", "",
             "Empty response schemas do not define a stable response contract. Inspect the linked handler and its tests "
             "for returned dictionary fields. Error responses in OpenAPI are not an exhaustive list of runtime failures.", "",
             "## Operations", "",
             "| Method | Path | Authentication | Purpose |",
             "| --- | --- | --- | --- |"]
    count = 0
    for route in sorted((r for r in app.routes if isinstance(r, APIRoute) and r.include_in_schema), key=lambda r: r.path):
        dependencies = {d.call.__name__ for d in route.dependant.dependencies}
        for method in sorted(route.methods):
            operation = schema["paths"][route.path][method.lower()]
            if "admin_user" in dependencies:
                auth = "Admin browser session"
            elif "signed_in" in dependencies:
                auth = "Browser session; no API token"
            elif "current_agent" in dependencies:
                auth = "Asset agent key"
            elif "current_user" in dependencies:
                auth = "Session or read-only API token" if method in {"GET", "HEAD"} else "Browser session"
            else:
                auth = SPECIAL_AUTH.get(route.path, "No user-session dependency")
            if "admin_user" in dependencies or "signed_in" in dependencies:
                operation["security"] = [{"SessionCookie": []}]
            elif "current_agent" in dependencies:
                operation["security"] = [{"AgentToken": []}]
            elif "current_user" in dependencies:
                operation["security"] = [{"SessionCookie": []}]
                if method in {"GET", "HEAD"}:
                    operation["security"].append({"ReadToken": []})
            elif route.path == "/api/assets/{asset_id}/sbom":
                operation["security"] = [{"SessionCookie": []}, {"AgentToken": []}, {"UploadToken": []}]
            else:
                # Body tokens and SSO cookies are described separately; no HTTP auth scheme represents them.
                operation["security"] = []
            operation["x-authentication"] = auth
            finding_schema = None
            if route.path == "/api/findings":
                finding_schema = {"anyOf": [{"type": "array", "items": {"$ref": f"#/components/schemas/{row}"}}
                                            for row in ("FindingRow", "FindingCompact")]}
            elif route.path == "/api/findings/{finding_id}":
                finding_schema = {"$ref": "#/components/schemas/FindingDetail"}
            elif route.path in {"/api/findings/{finding_id}/accept", "/api/findings/{finding_id}/revoke-acceptance"}:
                finding_schema = {"$ref": "#/components/schemas/FindingRow"}
            elif route.path == "/api/findings/groups":
                finding_schema = {"type": "array", "items": {"$ref": "#/components/schemas/FindingGroup"}}
            elif route.path in {"/api/findings/count", "/api/findings/accept", "/api/findings/accept-many"}:
                names = ["total"] if route.path.endswith("/count") else ["accepted", "skipped"] if route.path.endswith("accept-many") else ["accepted"]
                finding_schema = {"type": "object", "properties": {n: {"type": "integer", "minimum": 0} for n in names},
                                  "required": names, "additionalProperties": False}
            if finding_schema:
                operation["responses"]["200"] = {"description": "Finding result; see findings.md for row variants, filters and state semantics.",
                                                 "content": {"application/json": {"schema": finding_schema}}}
            if route.path == "/api/findings.csv":
                operation["responses"]["200"] = {"description": "CSV attachment in the documented column order, without list pagination.",
                                                 "content": {"text/csv": {"schema": {"type": "string"}}},
                                                 "headers": {"Content-Disposition": {"schema": {"type": "string"},
                                                                                     "description": "attachment; filename=nimstead-findings-STATUS.csv"}}}
            media = {"/install.sh": "text/x-shellscript", "/install.ps1": "text/plain",
                     "/agent/nimstead_agent.py": "text/x-python", "/agent/runtime/{arch}.zip": "application/zip"}.get(route.path)
            if media:
                body_schema = {"type": "string", **({"format": "binary"} if media == "application/zip" else {})}
                operation["responses"]["200"] = {"description": "Distribution file bytes; see the platform-update reference for verification and availability.",
                                                 "content": {media: {"schema": body_schema}}}
            if route.path == "/api/agent/manifest":
                fields = {"paused": {"type": "boolean", "description": "Unsigned organisation pause flag."},
                          "release": {"type": "string", "description": "Exact signed manifest JSON as text, not a nested JSON object."},
                          "sig": {"type": "string", "description": "Base64 signature over release bytes."}}
                operation["responses"]["200"] = {"description": "Pause flag with optional paired manifest/signature strings.",
                                                 "content": {"application/json": {"schema": {"type": "object", "properties": fields,
                                                                                          "required": ["paused"], "additionalProperties": False,
                                                                                          "dependentRequired": {"release": ["sig"], "sig": ["release"]}}}}}
            if route.path == "/api/assets/{asset_id}/sbom":
                operation["requestBody"] = {
                    "required": True,
                    "description": "Raw CycloneDX or SPDX JSON, not multipart. Parser limits apply; this is not the complete upstream SBOM schema.",
                    "content": {"application/json": {"schema": {"type": "object"}}},
                    "x-parser-limits": {"body_bytes": MAX_BODY, "components": MAX_COMPONENTS, "cyclonedx_component_depth": MAX_DEPTH,
                                        "cyclonedx_versions": sorted(SPEC_VERSIONS), "spdx_versions": sorted(SPDX_VERSIONS)},
                }
                counts = {name: {"type": "integer", "minimum": 0}
                          for name in ("components", "mapped", "unique_packages", "open", "resolved")}
                counts["skipped"] = {"type": "object", "required": ["no_purl", "unsupported_or_invalid_purl"],
                                     "properties": {name: {"type": "integer", "minimum": 0}
                                                    for name in ("no_purl", "unsupported_or_invalid_purl")},
                                     "additionalProperties": False}
                operation["responses"]["200"] = {"description": "Inventory mapping and rescan counts; see the SBOM reference for count semantics.",
                                                 "content": {"application/json": {"schema": {"type": "object", "properties": counts,
                                                                                          "required": list(counts), "additionalProperties": False}}}}
            if route.path == "/api/targets/{target_id}/scan":
                fields = {"address": {"type": "string", "description": "Pinned IP selected by the scope check."},
                          "open": {"type": "integer", "minimum": 0, "description": "Unique observed issue IDs, including accepted findings."},
                          "resolved": {"type": "integer", "minimum": 0, "description": "Previously open/accepted findings newly resolved by absence."},
                          "skipped": {"type": "array", "items": {"type": "string"}, "description": "Reported scanner limitations; not every missing observation."}}
                operation["responses"]["200"] = {"description": "External scan counters; see external-scans.md for observation and resolution limits.",
                                                 "content": {"application/json": {"schema": {"type": "object", "properties": fields,
                                                                                          "required": list(fields), "additionalProperties": False}}}}
            summary = operation.get("description", operation.get("summary", "")).split("\n", 1)[0].replace("|", "\\|")
            source = f"../../api/src/nimstead/app.py#L{route.endpoint.__code__.co_firstlineno}"
            lines.append(f"| `{method}` | [`{route.path}`]({source}) | {auth} | {summary} |")
            count += 1
    lines += ["", f"The schema contains {count} operations and {len(schema['components']['schemas'])} schema definitions.", "",
              "## Routes outside the schema", "",
              "- `GET /api/health`: unauthenticated deployment health; HTTP200 when database and migration checks pass, otherwise503.",
              "- `GET /.well-known/security.txt`: public security contact policy.",
              "- Static web assets and the web application's fallback route are not API contracts.", "",
              "## Refresh this reference", "",
              "From the repository root with the locked API environment available:", "",
              "```bash", "(cd api && uv run python ../scripts/export_api_docs.py)", "```", "",
              "CI checks freshness with `--check`. Compare the schema served by your installed release before integration.", ""]
    return {"docs/reference/openapi.json": json.dumps(schema, indent=2, sort_keys=True) + "\n",
            "docs/reference/api-endpoints.md": "\n".join(lines).replace("HTTP200", "HTTP 200").replace("otherwise503", "otherwise 503")}


def main() -> int:
    """Write API reference outputs, or return 1 for stale files when --check is selected.

    Argument, app/schema, and file errors propagate. The command never deploys the app.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    stale = []
    for name, content in render().items():
        path = ROOT / name
        if args.check:
            if not path.exists() or path.read_text() != content:
                stale.append(name)
        else:
            path.write_text(content)
    for name in stale:
        print(f"Stale API documentation: {name}")
    return int(bool(stale))


if __name__ == "__main__":
    raise SystemExit(main())
