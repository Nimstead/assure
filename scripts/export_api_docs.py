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
    """Return two generated repository paths mapped to document text strings.

    Build the current FastAPI app with an in-memory database and caller-owned HTTP client.
    The catalog reflects typed parameters and named authentication dependencies. Routes that
    authenticate inside their body use explicit labels. Only included APIRoute objects enter
    the sorted catalog. Authentication inference uses direct dependency function names.
    Add selected manually maintained response schemas, security metadata and parser limits.
    This does not execute endpoint bodies, validate responses or run a schema linter.
    JSON output sorts keys. Catalog summaries use the description's first line and source
    links use endpoint code line numbers. No output files or directories are written here.
    App initialization reads configuration/static context and creates temporary SQLite tables.
    HTTP client closure occurs before catalog assembly. App/schema/attribute errors propagate.
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
    rule_fields = {name: {"type": "string"} for name in ("id", "v", "severity", "status", "setting", "expected", "found", "note")}
    baseline_fields = {name: {"type": "string"} for name in ("baseline_id", "name", "version", "date")}
    baseline_fields |= {name: {"type": "integer", "minimum": 0} for name in ("automated", "manual", "pass", "fail", "not_assessed", "not_applicable")}
    baseline_detail = {**baseline_fields, "asset_id": {"type": "string"}, "hostname": {"type": "string"},
                       "rules": {"type": "array", "items": {"$ref": "#/components/schemas/BaselineRule"}}}
    baseline_summary = {**baseline_fields, **{name: {"type": "string"} for name in ("asset_id", "hostname", "last_seen")}}
    baseline_aggregate = {name: baseline_fields[name] for name in baseline_fields if name != "date"}
    baseline_aggregate["hosts"] = {"type": "integer", "minimum": 0}
    notification_fields = {name: {"type": "boolean"} for name in ("webhook_set", "email_available", "last_delivery_failed")}
    notification_fields |= {"webhook_host": {"type": ["string", "null"]}, "webhook_format": {"type": "string"}}
    notification_fields |= {name: {"type": "array", "items": {"type": "string"}} for name in ("emails", "emails_confirmed")}
    delivery_fields = {name: {"type": "string"} for name in ("ts", "kind", "channel")}
    delivery_fields |= {name: {"type": "boolean"} for name in ("urgent", "ok")}
    delivery_fields["error"] = {"type": ["string", "null"]}
    notification_fields["recent"] = {"type": "array", "maxItems": 5, "items": {"type": "object", "properties": delivery_fields,
                                                                            "required": list(delivery_fields), "additionalProperties": False}}
    for name, fields in (("BaselineRule", rule_fields), ("BaselineDetail", baseline_detail), ("BaselineHostSummary", baseline_summary),
                         ("BaselineAggregate", baseline_aggregate), ("NotificationSettings", notification_fields)):
        schema["components"]["schemas"][name] = {"type": "object", "properties": fields, "required": list(fields), "additionalProperties": False}
    job_fields = {name: {"type": "string"} for name in (
        "id", "asset_id", "hostname", "status", "manager", "action_key", "summary", "created_by", "created", "updated")}
    job_fields |= {name: {"type": ["string", "null"]} for name in ("approved_by", "error")}
    job_fields |= {"packages": {"type": "array", "items": {"type": "object"}},
                   "finding_ids": {"type": "array", "items": {"type": "string"}}, "forward_only": {"type": "boolean"},
                   "steps": {"type": "array", "items": {"type": "object", "properties": {
                       "step": {"type": "string"}, "ok": {"type": "boolean"}, "output": {"type": "string"}},
                       "required": ["step", "ok", "output"], "additionalProperties": False}},
                   "result_versions": {"type": ["object", "null"], "additionalProperties": {"type": "string"}}}
    agent_job = {name: job_fields[name] for name in ("id", "manager", "packages")}
    agent_job |= {"health_units": {"type": "array", "items": {"type": "string"}}, "reboot_by": {"type": "string"}}
    update_host = {name: {"type": "string"} for name in ("asset_id", "hostname", "build", "why")}
    update_host |= {"ring": {"type": "integer"}, "notes": {"type": "array", "items": {"type": "string"}},
                    "job": {"type": ["object", "null"], "properties": {name: {"type": "string"} for name in ("id", "status")},
                            "required": ["id", "status"], "additionalProperties": False}}
    update_fields = {name: {"type": "string"} for name in ("kb", "product", "title", "build")}
    update_fields |= {name: {"type": ["string", "null"]} for name in ("released", "plan_note")}
    update_fields |= {name: {"type": "integer", "minimum": 0} for name in ("hosts", "fixed")}
    settings = {"remediation_mode": {"type": "string"}, "canary_soak_hours": {"type": "integer"},
                "reboot_deadline_hours": {"type": "integer"}, "maintenance_window": {"type": ["object", "null"]},
                "sla_days": {"type": "object", "additionalProperties": {"type": "integer"}}, "platform": {"type": "object"}}
    settings |= {name: {"type": "boolean"} for name in ("agent_updates_paused", "signed_agent_release", "production_remediation_allowed")}
    for name, fields in (("RemediationJob", job_fields), ("WindowsUpdateHost", update_host),
                         ("WindowsUpdateSummary", update_fields), ("OrganisationSettings", settings)):
        schema["components"]["schemas"][name] = {"type": "object", "properties": fields, "required": list(fields), "additionalProperties": False}
    schema["components"]["schemas"]["RemediationJobListItem"] = {
        "type": "object", "properties": {**job_fields, "waits_for_window": {"type": ["string", "null"]}},
        "required": list(job_fields), "additionalProperties": False}
    schema["components"]["schemas"]["AgentJobPlan"] = {
        "type": "object", "properties": agent_job, "required": ["id", "manager", "packages", "health_units"], "additionalProperties": False}
    update_detail = {**update_fields, "missing": {"type": "array", "items": {"$ref": "#/components/schemas/WindowsUpdateHost"}},
                     "plan_asset_ids": {"type": "array", "items": {"type": "string"}}}
    schema["components"]["schemas"]["WindowsUpdateDetail"] = {
        "type": "object", "properties": update_detail, "required": list(update_detail), "additionalProperties": False}
    lines = ["# HTTP endpoint catalog", "",
             "Use the [OpenAPI JSON](openapi.json) for typed parameters, request models, defaults, and declared response schemas.", "",
             "The export adds server/authentication metadata and selected contracts: findings, remediation, policy, Windows updates, baselines, notifications, CSV, SBOM, external-scan counters, agent manifest and distribution files. Other definitions come from the app.", "",
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
            remediation_schema = None
            response_status = "200"
            if route.path == "/api/remediation/jobs":
                if method == "GET":
                    remediation_schema = {"type": "array", "maxItems": 500, "items": {"$ref": "#/components/schemas/RemediationJobListItem"}}
                else:
                    remediation_schema, response_status = {"$ref": "#/components/schemas/RemediationJob"}, "201"
            elif route.path in {"/api/remediation/jobs/{job_id}/approve", "/api/remediation/jobs/{job_id}/cancel"}:
                remediation_schema = {"$ref": "#/components/schemas/RemediationJob"}
            elif route.path == "/api/remediation/jobs/batch":
                response_status = "201"
                remediation_schema = {"type": "object", "required": ["jobs", "errors"], "additionalProperties": False, "properties": {
                    "jobs": {"type": "array", "items": {"$ref": "#/components/schemas/RemediationJob"}},
                    "errors": {"type": "array", "items": {"type": "object", "required": ["asset_id", "error"], "additionalProperties": False,
                                                         "properties": {name: {"type": "string"} for name in ("asset_id", "error")}}}}}
            elif route.path == "/api/agent/jobs":
                remediation_schema = {"type": "array", "items": {"$ref": "#/components/schemas/AgentJobPlan"}}
            elif route.path == "/api/agent/jobs/{job_id}/report":
                remediation_schema = {"type": "object", "required": ["status"], "additionalProperties": False,
                                      "properties": {"status": {"type": "string"}}}
            elif route.path == "/api/windows-updates":
                remediation_schema = {"type": "array", "items": {"$ref": "#/components/schemas/WindowsUpdateSummary"}}
            elif route.path == "/api/windows-updates/{kb}":
                remediation_schema = {"$ref": "#/components/schemas/WindowsUpdateDetail"}
            elif route.path == "/api/settings":
                remediation_schema = {"$ref": "#/components/schemas/OrganisationSettings"}
            if remediation_schema:
                operation["responses"][response_status] = {
                    "description": "Recorded policy/plan result; see remediation-jobs.md for state, verification and commit boundaries.",
                    "content": {"application/json": {"schema": remediation_schema}}}
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
            if route.path in {"/api/settings/notifications", "/api/baselines/{asset_id}"}:
                response_type = "NotificationSettings" if route.path.startswith("/api/settings") else "BaselineDetail"
                operation["responses"]["200"] = {"description": "Stored configuration/result fields; see the corresponding reference for limits.",
                                                 "content": {"application/json": {"schema": {"$ref": f"#/components/schemas/{response_type}"}}}}
            if route.path == "/api/baselines":
                fields = {"baselines": {"type": "array", "items": {"$ref": "#/components/schemas/BaselineAggregate"}},
                          "hosts": {"type": "array", "items": {"$ref": "#/components/schemas/BaselineHostSummary"}},
                          "no_baseline": {"type": "integer", "minimum": 0}}
                operation["responses"]["200"] = {"description": "Baseline summaries and aggregated stored-host outcomes, not conformance certification.",
                                                 "content": {"application/json": {"schema": {"type": "object", "properties": fields,
                                                                                          "required": list(fields), "additionalProperties": False}}}}
            if route.path == "/api/settings/notifications/test":
                operation["responses"]["202"] = {"description": "Request acknowledged; does not establish durable enqueue or delivery.",
                                                 "content": {"application/json": {"schema": {"type": "object", "required": ["queued"],
                                                                                          "properties": {"queued": {"type": "boolean", "const": True}},
                                                                                          "additionalProperties": False}}}}
            if route.path == "/api/notify/confirm":
                for status, description in (("200", "Consent form or confirmation HTML."), ("404", "Invalid confirmation link HTML.")):
                    operation["responses"][status] = {"description": description, "content": {"text/html": {"schema": {"type": "string"}}}}
            if route.path == "/api/baselines.csv":
                operation["responses"]["200"] = {"description": "CSV attachment with automated and explicit manual rule rows.",
                                                 "content": {"text/csv": {"schema": {"type": "string"}}}}
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

    Read --check from CLI arguments. Check mode compares exact text, prints stale paths
    and performs no writes. Missing outputs are stale. Return 0 when no outputs are stale.
    Write mode overwrites the schema then catalog and returns 0 after both writes.
    Parent directories must exist. Writes are not atomic. Earlier output can remain changed
    after a later failure. argparse uses SystemExit for invalid arguments. App/schema and
    filesystem errors propagate. The command neither deploys the app nor invokes endpoints.
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
