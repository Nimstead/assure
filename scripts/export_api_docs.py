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
    schema["info"]["license"] = {"name": "FSL-1.1-ALv2", "url": "https://github.com/Nimstead/assure/blob/main/LICENSE.md"}
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
    asset_fields = {name: {"type": "string"} for name in ("id", "hostname", "os_name", "ecosystem", "kind", "criticality", "first_seen", "last_seen")}
    asset_fields |= {name: {"type": "boolean"} for name in ("internet_facing", "directory_source", "sandbox")}
    asset_fields |= {"ring": {"type": "integer"}, "health_units": {"type": "array", "items": {"type": "string"}},
                     "open_by_priority": {"type": "object", "additionalProperties": {"type": "integer", "minimum": 0}}}
    app_counts = {"type": "object", "properties": {name: {"type": "integer", "minimum": 0} for name in ("assessed", "inventory_only")},
                  "required": ["assessed", "inventory_only"], "additionalProperties": False}
    host_fields = {name: {"type": "string"} for name in ("agent_version", "agent_update")}
    host_fields |= {name: {"type": "boolean"} for name in ("agent_outdated", "not_reporting")}
    host_fields |= {"agent_update_error": {"type": ["string", "null"]}, "facts": {"type": "object"},
                    "maintenance_window": {"type": ["object", "null"]}}
    external_fields = {name: {"type": "string"} for name in ("txt_name", "txt_value", "proof_path")}
    external_fields |= {"verified": {"type": "boolean"}, "verified_at": {"type": ["string", "null"]}}
    for name, kind, extra in (("HostAsset", "host", host_fields), ("ApplicationAsset", "application", {}),
                               ("ExternalAsset", "external", external_fields)):
        fields = {**asset_fields, **extra, "kind": {"const": kind, "type": "string"}, "apps": app_counts}
        schema["components"]["schemas"][name] = {"type": "object", "properties": fields,
                                                   "required": [*asset_fields, *extra], "additionalProperties": False}
    schema["components"]["schemas"]["AssetRow"] = {"oneOf": [{"$ref": f"#/components/schemas/{name}"}
                                                                            for name in ("HostAsset", "ApplicationAsset", "ExternalAsset")]}
    created_fields = {**schema["components"]["schemas"]["ApplicationAsset"]["properties"], "upload_token": {"type": "string"}}
    schema["components"]["schemas"]["CreatedApplication"] = {"type": "object", "properties": created_fields,
                                                               "required": [*asset_fields, "upload_token"], "additionalProperties": False}
    coverage_fields = {name: {"type": "integer", "minimum": 0} for name in ("assessed", "inventory_only")}
    coverage_fields["not_assessed"] = {"type": "array", "maxItems": 200, "items": {"type": "object", "properties": {
        "name": {"type": "string"}, "publisher": {"type": ["string", "null"]}, "hosts": {"type": "integer", "minimum": 0}},
        "required": ["name", "publisher", "hosts"], "additionalProperties": False}}
    action_fields = {name: {"type": "string"} for name in ("ecosystem", "package")}
    action_fields |= {name: {"type": ["string", "null"]} for name in ("fixed_version", "summary", "fix")}
    action_fields |= {name: {"type": "array", "items": {"type": "string"}} for name in ("hosts", "asset_ids", "busy_asset_ids", "vulns")}
    action_fields |= {name: {"type": "boolean"} for name in ("kev", "plannable", "person_only", "forward_only")}
    action_fields["max_score"] = {"type": "integer"}
    for name, fields in (("job", {"id": {"type": "string"}, "status": {"type": "string"}}),
                         ("last_attempt", {"id": {"type": "string"}, "status": {"type": "string"}, "error": {"type": ["string", "null"]}})):
        action_fields[name] = {"type": ["object", "null"], "properties": fields, "required": list(fields), "additionalProperties": False}
    summary_fields = {name: {"type": "integer", "minimum": 0} for name in ("assets", "hosts_not_reporting", "agents_need_attention", "devices_with_issues")}
    summary_fields |= {"open_by_priority": asset_fields["open_by_priority"],
                       "top_actions": {"type": "array", "maxItems": 10, "items": {"$ref": "#/components/schemas/SummaryAction"}},
                       "attention": {"type": "array", "maxItems": 20, "items": {"$ref": "#/components/schemas/RemediationJob"}}}
    for name, fields in (("ApplicationCoverage", coverage_fields), ("SummaryAction", action_fields), ("FleetSummary", summary_fields),
                         ("AgentEnrolment", {"asset_id": {"type": "string"}, "agent_key": {"type": "string"}}),
                         ("InventoryResult", {name: {"type": "integer", "minimum": 0} for name in ("open", "resolved")})):
        schema["components"]["schemas"][name] = {"type": "object", "properties": fields, "required": list(fields), "additionalProperties": False}
    user_fields = {name: {"type": "string"} for name in ("id", "email", "origin", "created")}
    user_fields |= {name: {"type": "boolean"} for name in ("admin", "mfa")}
    me_fields = {name: {"type": "string"} for name in ("email", "org", "origin")}
    me_fields |= {"admin": {"type": "boolean"}, "mfa": {"type": "boolean"}, "recovery_codes_left": {"type": "integer", "minimum": 0}}
    setup_fields = {name: {"type": "string"} for name in ("setup", "secret", "uri")}
    recovery_field = {"type": "array", "items": {"type": "string"}}
    enrol_fields = {name: {"type": ["string", "null"] if name == "expires" else "string"} for name in ("id", "created", "expires")}
    enrol_fields |= {"revoked": {"type": "boolean"}, "sandbox": {"type": "boolean"}}
    token_fields = {name: {"type": "string"} for name in ("id", "name", "created_by", "created")}
    token_fields |= {name: {"type": ["string", "null"]} for name in ("expires", "last_used")}
    domain_fields = {name: {"type": "string"} for name in ("domain", "txt_name", "txt_value")}
    domain_fields["verified"] = {"type": "boolean"}
    sso_fields = {name: {"type": "string"} for name in ("issuer", "client_id", "redirect_uri")}
    sso_fields |= {"client_secret_set": {"type": "boolean"}, "required": {"type": "boolean"},
                   "domains": {"type": "array", "items": {"type": "string"}},
                   "domain_checks": {"type": "array", "items": {"type": "object", "properties": domain_fields,
                                                                 "required": list(domain_fields), "additionalProperties": False}}}
    for name, fields in (("UserRecord", user_fields), ("CurrentIdentity", me_fields), ("AuthenticatorSetup", setup_fields),
                         ("RecoveryCodes", {"recovery_codes": recovery_field}), ("EnrolmentTokenMetadata", enrol_fields),
                         ("ApiTokenMetadata", token_fields), ("SSOSettings", sso_fields), ("AuthenticationError", {"detail": {"type": "string"}}),
                         ("CreatedEnrolmentToken", {name: {"type": "string"} for name in ("id", "token", "expires")}),
                         ("CreatedApiToken", {name: {"type": "string"} for name in ("id", "token", "name", "expires")})):
        schema["components"]["schemas"][name] = {"type": "object", "properties": fields, "required": list(fields), "additionalProperties": False}
    login_success = {"type": "object", "properties": {"email": {"type": "string"}, "recovery_codes": recovery_field},
                     "required": ["email"], "additionalProperties": False}
    schema["components"]["schemas"]["PasswordLogin"] = {"oneOf": [login_success,
        {"type": "object", "properties": {"mfa": {"const": "required"}}, "required": ["mfa"], "additionalProperties": False},
        {"type": "object", "properties": {**setup_fields, "mfa": {"const": "setup"}},
         "required": ["mfa", *setup_fields], "additionalProperties": False}]}
    schema["components"]["schemas"]["SignupCreated"] = {"type": "object", "properties": {
        "email": {"type": "string"}, "org": {"type": "string"}, "next": {"const": "signin"}},
        "required": ["email", "org"], "additionalProperties": False}
    def record(name, properties, optional=()):
        """Register a closed response object, except explicitly optional field names."""
        schema["components"]["schemas"][name] = {"type": "object", "properties": properties,
                                                   "required": [k for k in properties if k not in optional], "additionalProperties": False}
        return {"$ref": f"#/components/schemas/{name}"}

    string = {"type": "string"}
    nullable_text = {"type": ["string", "null"]}
    integer = {"type": "integer"}
    boolean = {"type": "boolean"}
    number_or_null = {"type": ["number", "null"]}
    strings = {"type": "array", "items": string}
    counts = {"type": "object", "additionalProperties": integer}
    record("HttpError", {"detail": string})
    record("AIStatus", {"enabled": boolean})
    record("AIExplanation", {"text": string, "model": string})
    from nimstead.ai import SearchFilter
    search_filter = SearchFilter.model_json_schema()
    search_filter.update(required=list(search_filter["properties"]), additionalProperties=False)
    schema["components"]["schemas"]["AISearchFilter"] = search_filter
    record("DirectoryReceipt", {"computers": integer})
    record("UnmanagedComputer", {**{k: string for k in ("domain", "name", "os", "os_version", "last_logon")}, "end_of_support": nullable_text})
    checked = record("DeviceCheck", {**{k: string for k in ("asset_id", "at", "from")}, "open": strings})
    record("UnmanagedDevice", {**{k: string for k in ("mac", "vendor", "first_seen", "last_seen")}, "addresses": strings, "seen_by": strings,
                               "checked": {"anyOf": [checked, {"type": "null"}]}})
    entry = record("LedgerEntry", {**{k: string for k in ("ts", "kind", "subject", "prev_hash", "hash")},
                                    "seq": integer, "data": {"type": "object", "description": "Event-specific ledger payload."}})
    record("LedgerPage", {"problems": strings, "entries": {"type": "array", "items": entry}, "total": integer})
    record("EvidencePublicKey", {k: string for k in ("pem", "fingerprint_sha256", "verifier_sha256")})
    finding = record("EvidenceFinding", {**{k: string for k in ("vuln_id", "package", "host", "priority", "status", "first_seen")},
        "cvss": number_or_null, "kev": boolean, "resolved_at": nullable_text, "days_open": {"type": "number"}, "sla_days": integer, "within_sla": boolean})
    control = record("EvidenceControl", {**{k: string for k in ("framework", "control", "requirement", "status", "evidence")},
                                        "exceptions": integer}, optional=("exceptions",))
    metric_names = ("resolved", "resolved_within_sla", "overdue_open", "ce_in_scope_resolved", "ce_in_scope_resolved_in_14d",
                    "ce_in_scope_overdue", "critical_overdue_30d", "findings_without_ledger_record", "assets", "assets_reporting",
                    "assets_silent_now", "changes", "changes_authorised", "changes_self_approved", "forward_only_changes", "sla_changes")
    metrics = record("EvidenceMetrics", {**{k: integer for k in metric_names}, "mttr_days": number_or_null})
    asset = record("EvidenceAsset", {k: string for k in ("hostname", "os", "last_seen")})
    change = record("EvidenceForwardChange", {**{k: string for k in ("job", "host", "summary", "status", "updated")}, "approved_by": nullable_text})
    policy = record("EvidencePolicyChange", {"ts": string, "by": nullable_text, "sla_days": counts})
    report_fields = {**{k: string for k in ("format", "organisation", "organisation_id", "organisation_created", "generated_at", "basis")},
        "verified_domains": strings, "period": {"type": "object", "properties": {"from": string, "to": string},
                                                "required": ["from", "to"], "additionalProperties": False},
        "sla_days": counts, "sla_changes": {"type": "array", "items": policy}, "metrics": metrics,
        "controls": {"type": "array", "items": control}, "forward_only_changes": {"type": "array", "items": change},
        "assets": {"type": "array", "items": asset}, "findings": {"type": "array", "items": finding},
        "ledger": {"type": "object", "properties": {"entries": integer, "head_hash": string},
                   "required": ["entries", "head_hash"], "additionalProperties": False}}
    record("EvidenceReport", report_fields, optional=("assets", "findings"))
    checkpoint = record("EvidenceCheckpoint", {**{k: string for k in ("org_id", "hash", "ts", "sig")}, "seq": integer})
    pack_fields = {**report_fields, "ledger": {"type": "object", "properties": {
        "entries": {"type": "array", "items": entry}, "head_hash": string,
        "chain_head": {"type": "object", "properties": {"seq": integer, "hash": string}, "required": ["seq", "hash"], "additionalProperties": False},
        "checkpoints": {"type": "array", "items": checkpoint}}, "required": ["entries", "head_hash", "chain_head", "checkpoints"], "additionalProperties": False}}
    record("EvidencePackDocument", pack_fields)
    way = record("HostPathWay", {"what": string, "ref": string, "grade": nullable_text, "kev": boolean, "flaws": integer}, optional=("flaws",))
    step = record("HostPathStep", {"stage": string, "label": string, "ways": {"type": "array", "items": way}, "count": integer})
    break_at = record("HostPathBreak", {"stage": string, "label": string, "fixes": integer, "refs": strings})
    continuation = {"type": ["object", "null"], "properties": {"label": string, "ways": {"type": "array", "items": way}, "count": integer},
                    "required": ["label", "ways", "count"], "additionalProperties": False}
    path = record("HostAttackPath", {"kind": string, "start": string, "grade": nullable_text,
        "steps": {"type": "array", "items": step}, "then": continuation, "break_at": break_at})
    vulnerability = record("ReportVulnerability", {"id": string, "kev": boolean, "cvss": number_or_null,
        **{k: nullable_text for k in ("cvss_source", "fixed", "kb", "summary", "vendor_status")}})
    vulnerable = record("VulnerableInstall", {**{k: string for k in ("family", "product", "expected", "action")},
        **{k: nullable_text for k in ("instance", "grade", "version", "observed", "source", "kernel", "raise_confidence")},
        **{k: integer for k in ("fixed_after_restart", "count", "no_fix", "no_fix_planned", "known_exploited")},
        "pending_reboot": boolean, "worst_cvss": number_or_null, "vulnerabilities": {"type": "array", "items": vulnerability}})
    incomplete = record("IncompleteChecks", {**{k: string for k in ("outcome", "reason", "why", "what_to_do")},
        "blocked_by": nullable_text, "source_said": nullable_text, "count": integer, "examples": strings})
    not_vulnerable = record("NonVulnerableInstall", {"family": string, "product": string, "instance": nullable_text, "grade": nullable_text, "checks": integer})
    application = record("ApplicationInstall", {"ecosystem": string, "product": string, "instance": string, "grade": nullable_text, "outcomes": counts})
    source = record("ReportSource", {**{k: string for k in ("name", "label", "state")}, "count": integer, "error": nullable_text})
    family = record("ReportFamily", {"label": string, "attempted": integer, "determined": integer, "outcomes": counts})
    app_coverage = record("ReportApplications", {**{k: integer for k in ("installs", "judged", "vulnerable", "no_advisory", "left_to_package_manager", "sbom_components_not_assessed")},
                                                "not_looked_for": strings})
    coverage = record("ReportCoverage", {"sources": {"type": "array", "items": source}, "families": {"type": "object", "additionalProperties": family},
                                         "applications": app_coverage, "statements": strings})
    headline = record("ReportHeadline", {"status": string, "text": string})
    record("ScanReport", {**{k: string for k in ("host", "kind", "os", "agent_version", "engine_version", "content_version", "inventory_sha256", "verdicts_sha256")},
        "headline": headline,
        "inventory_read_at": nullable_text, "vulnerable": {"type": "array", "items": vulnerable}, "undetermined": {"type": "array", "items": incomplete},
        "not_vulnerable": {"type": "array", "items": not_vulnerable}, "not_applicable": integer,
        "applications": {"type": "array", "items": application}, "attack_paths": {"type": "array", "items": path}, "coverage": coverage})
    compact_path = record("FleetHostPath", {"kind": string, "start": string, "grade": nullable_text, "steps": strings, "break_at": break_at})
    host = record("FleetHost", {"hostname": string, "judged": boolean, "entry": boolean, "internet_facing": boolean, "paths": {"type": "array", "items": compact_path}})
    fleet_way = record("FleetWay", {**{k: string for k in ("via", "how", "because", "grade")}, "port": integer})
    edge = record("FleetEdge", {"from": string, "to": string, "grade": string, "ways": {"type": "array", "items": fleet_way}})
    reach = record("FleetReach", {"host": string, "hops": strings, "grade": string, "fix_on_host": strings})
    chain = record("FleetChain", {"start": string, "why_start": string, "reach": {"type": "array", "items": reach}})
    record("FleetPaths", {"hosts": {"type": "object", "additionalProperties": host}, "edges": {"type": "array", "maxItems": 2000, "items": edge},
                          "truncated": boolean, "chains": {"type": "array", "maxItems": 50, "items": chain}})
    lines = ["# HTTP endpoint catalog", "",
             "Use the [OpenAPI JSON](openapi.json) for typed parameters, request models, defaults, and declared response schemas.", "",
             "The export adds server/authentication metadata and response contracts for account/authentication, assets, inventory, fleet summary/paths, findings, remediation, policy, Windows updates, baselines, notifications, AI, directory, scan reports, evidence, CSV, SBOM, agent manifests and distribution files. Request definitions come from the app.", "",
             "Authentication labels describe entry requirements. Organisation ownership, roles, origin checks, quotas, "
             "and operation-specific state checks still apply. See [HTTP API reference](http-api.md).", "",
             "The export defines success payloads and selected shared errors. Inspect the linked handler and its tests "
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
            if dependencies & {"admin_user", "signed_in", "current_agent", "current_user"}:
                operation["responses"].setdefault("401", {"description": "Missing, expired or invalid credential.",
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/AuthenticationError"}}}})
            if dependencies & {"admin_user", "signed_in"} or ("current_user" in dependencies and method not in {"GET", "HEAD"}):
                operation["responses"].setdefault("403", {"description": "Role, browser-session or local MFA requirement refused the operation.",
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/AuthenticationError"}}}})
            account_response = None
            account_status = "200"
            account_name = {"/api/me": "CurrentIdentity", "/api/auth/login": "PasswordLogin", "/api/me/mfa/setup": "AuthenticatorSetup",
                            "/api/me/mfa": "RecoveryCodes", "/api/settings/sso": "SSOSettings", "/api/settings/sso/verify": "SSOSettings"}.get(route.path)
            if account_name:
                account_response = {"$ref": f"#/components/schemas/{account_name}"}
            elif route.path in {"/api/users", "/api/enroll-tokens", "/api/tokens"}:
                if method == "GET":
                    account_name = {"/api/users": "UserRecord", "/api/enroll-tokens": "EnrolmentTokenMetadata", "/api/tokens": "ApiTokenMetadata"}[route.path]
                    account_response = {"type": "array", "items": {"$ref": f"#/components/schemas/{account_name}"}}
                elif method == "POST":
                    account_name = {"/api/enroll-tokens": "CreatedEnrolmentToken", "/api/tokens": "CreatedApiToken"}.get(route.path)
                    if account_name:
                        account_response, account_status = {"$ref": f"#/components/schemas/{account_name}"}, "201"
            elif route.path == "/api/users/{user_id}" and method == "PATCH":
                account_response = {"$ref": "#/components/schemas/UserRecord"}
            if account_response:
                operation["responses"][account_status] = {"description": "Account contract; see authentication.md for branch and persistence semantics.",
                    "content": {"application/json": {"schema": account_response}}}
            if route.path == "/api/auth/signup":
                operation["responses"]["201"] = {"description": "First account or development signup. A session exists only in open-signup mode.",
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/SignupCreated"}}}}
            if route.path in {"/api/auth/signup", "/api/auth/password/reset", "/api/users/invite"}:
                fields = {"status": {"const": "invited" if route.path == "/api/users/invite" else "check_email"}, "email": {"type": "string"}}
                operation["responses"]["202"] = {"description": "Acknowledged account-mail request, not proof of delivery.",
                    "content": {"application/json": {"schema": {"type": "object", "properties": fields,
                                                               "required": list(fields), "additionalProperties": False}}}}
            if route.path in {"/api/auth/sso/start", "/api/auth/sso/callback"}:
                operation["responses"].pop("200", None)
                operation["responses"]["303"] = {"description": "Provider, home or sign-in error redirect. See authentication.md.",
                    "headers": {"Location": {"schema": {"type": "string"}}}}
            if route.path == "/api/auth/signup/confirm" and method == "POST":
                operation["responses"]["303"] = {"description": "Signup/reset redirects to sign-in. Successful invitation can establish a member session.",
                    "headers": {"Location": {"schema": {"type": "string"}}}}
            operation["responses"].setdefault("413", {"description": "Declared request body exceeds the shared limit, or a consumed stream crosses it.",
                "content": {"application/json": {"schema": {"$ref": "#/components/schemas/HttpError"}}}})
            if method not in {"GET", "HEAD", "OPTIONS"}:
                operation["responses"].setdefault("403", {"description": "An Origin-bearing write failed the shared origin check.",
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/HttpError"}}}})
            report_name = {"/api/ai/status": "AIStatus", "/api/ai/explain/{finding_id}": "AIExplanation", "/api/ai/search": "AISearchFilter",
                "/api/agent/directory": "DirectoryReceipt", "/api/evidence/ledger": "LedgerPage", "/api/evidence/public-key": "EvidencePublicKey",
                "/api/evidence/report": "EvidenceReport", "/api/assets/{asset_id}/scan-report": "ScanReport", "/api/attack-paths": "FleetPaths"}.get(route.path)
            if report_name:
                operation["responses"]["200"] = {"description": "Source-backed response fields. Consult the matching reference for observation, integrity and persistence limits.",
                    "content": {"application/json": {"schema": {"$ref": f"#/components/schemas/{report_name}"}}}}
            if route.path == "/api/directory/unmanaged":
                operation["responses"]["200"] = {"description": "Stored unmatched directory rows, or CSV only when format=csv.", "content": {
                    "application/json": {"schema": {"type": "array", "items": {"$ref": "#/components/schemas/UnmanagedComputer"}}},
                    "text/csv": {"schema": {"type": "string"}}}}
            if route.path == "/api/network/unmanaged":
                operation["responses"]["200"] = {"description": "Devices in agents' own neighbour tables that are none of the organisation's agents, or CSV only when format=csv.", "content": {
                    "application/json": {"schema": {"type": "array", "items": {"$ref": "#/components/schemas/UnmanagedDevice"}}},
                    "text/csv": {"schema": {"type": "string"}}}}
            if route.path == "/api/evidence/pack":
                operation["responses"]["200"] = {"description": "Signed ZIP containing pack.json matching EvidencePackDocument, plus signature/key/instructions.",
                    "x-pack-json-schema": {"$ref": "#/components/schemas/EvidencePackDocument"},
                    "content": {"application/zip": {"schema": {"type": "string", "format": "binary"}}},
                    "headers": {"Content-Disposition": {"schema": {"type": "string"}}}}
            if route.path == "/api/evidence/verify.py":
                operation["responses"]["200"] = {"description": "Offline verifier source bytes.", "content": {"text/x-python": {"schema": {"type": "string"}}}}
            if route.path in {"/install.sh", "/install.ps1"}:
                operation["responses"]["400"] = {"description": "Unsafe public-origin text cannot be embedded into the installer.",
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/HttpError"}}}}
            if route.path == "/agent/runtime/{arch}.zip":
                operation["responses"]["404"] = {"description": "Unsupported, unavailable or mismatched signed runtime.",
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/HttpError"}}}}
            if route.path == "/api/auth/signup/confirm":
                for status in ("200", "404"):
                    operation["responses"][status] = {"description": "Password-selection form or invalid-link HTML.",
                        "content": {"text/html": {"schema": {"type": "string"}}}}
                if method == "POST":
                    operation["responses"].pop("200", None)
                    for status in ("409", "422"):
                        operation["responses"][status] = {"description": "Account/link state conflict or invalid password HTML.",
                            "content": {"text/html": {"schema": {"type": "string"}}}}
            asset_response = None
            asset_status = "200"
            if route.path == "/api/assets":
                if method == "GET":
                    asset_response = {"type": "array", "items": {"$ref": "#/components/schemas/AssetRow"}}
                else:
                    asset_response, asset_status = {"$ref": "#/components/schemas/CreatedApplication"}, "201"
            elif route.path == "/api/assets/{asset_id}" and method == "PATCH":
                asset_response = {"$ref": "#/components/schemas/AssetRow"}
            elif route.path == "/api/targets" or route.path == "/api/targets/{target_id}/verify":
                asset_response = {"$ref": "#/components/schemas/ExternalAsset"}
                asset_status = "201" if route.path == "/api/targets" else "200"
            elif route.path in {"/api/coverage", "/api/summary", "/api/agent/enroll", "/api/agent/inventory"}:
                response_name = {"/api/coverage": "ApplicationCoverage", "/api/summary": "FleetSummary",
                                 "/api/agent/enroll": "AgentEnrolment", "/api/agent/inventory": "InventoryResult"}[route.path]
                asset_response = {"$ref": f"#/components/schemas/{response_name}"}
                asset_status = "201" if route.path == "/api/agent/enroll" else "200"
            if asset_response:
                operation["responses"][asset_status] = {"description": "Asset/inventory contract; see assets-api.md for state and count semantics.",
                                                       "content": {"application/json": {"schema": asset_response}}}
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
