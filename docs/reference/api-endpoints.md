# HTTP endpoint catalog

Use the [OpenAPI JSON](openapi.json) for typed parameters, request models, defaults, and declared response schemas.

The export adds server and authentication metadata to FastAPI’s schema. Request and response definitions come from the app.

Authentication labels describe entry requirements. Organisation ownership, roles, origin checks, quotas, and operation-specific state checks still apply. See [HTTP API reference](http-api.md).

Empty response schemas do not define a stable response contract. Inspect the linked handler and its tests for returned dictionary fields. Error responses in OpenAPI are not an exhaustive list of runtime failures.

## Operations

| Method | Path | Authentication | Purpose |
| --- | --- | --- | --- |
| `GET` | [`/agent/nimstead_agent.py`](../../api/src/nimstead/app.py#L384) | No user-session dependency | Return the Python agent source served by this checkout. |
| `GET` | [`/agent/runtime/{arch}.zip`](../../api/src/nimstead/app.py#L389) | No user-session dependency | The Windows agent's bundled Python, only as the signed release names it (plan decision 9). |
| `POST` | [`/api/agent/directory`](../../api/src/nimstead/app.py#L1022) | Asset agent key | Computer objects an opted-in agent read from its domain (plan T43); replaces that domain's list for the org. |
| `POST` | [`/api/agent/enroll`](../../api/src/nimstead/app.py#L892) | Enrolment token in JSON body | Exchange an enrolment token for a new asset ID and asset-specific agent key. |
| `POST` | [`/api/agent/inventory`](../../api/src/nimstead/app.py#L969) | Asset agent key | Replace this agent's inventory, rescan the asset, and return scan results. |
| `GET` | [`/api/agent/jobs`](../../api/src/nimstead/app.py#L1141) | Asset agent key | Dispatch eligible approved jobs to this agent and return their execution plans. |
| `POST` | [`/api/agent/jobs/{job_id}/report`](../../api/src/nimstead/app.py#L1161) | Asset agent key | Record an outcome for a job owned by this agent and return its resulting status. |
| `GET` | [`/api/agent/manifest`](../../api/src/nimstead/app.py#L1133) | Asset agent key | Return the organisation's update pause flag and any valid signed release for the served agent. |
| `POST` | [`/api/ai/explain/{finding_id}`](../../api/src/nimstead/app.py#L2230) | Browser session | Return an AI explanation and model name for an owned finding, subject to AI usage quotas. |
| `POST` | [`/api/ai/search`](../../api/src/nimstead/app.py#L2248) | Browser session | Return a validated findings filter from the submitted natural-language text, subject to AI usage quotas. |
| `GET` | [`/api/ai/status`](../../api/src/nimstead/app.py#L2217) | Session or read-only API token | Return whether the optional AI service is configured and enabled. |
| `GET` | [`/api/assets`](../../api/src/nimstead/app.py#L1206) | Session or read-only API token | Return organisation assets with finding counts, agent status, and application coverage. |
| `POST` | [`/api/assets`](../../api/src/nimstead/app.py#L1388) | Admin browser session | Create an application asset and return its asset record plus a one-time upload_token. |
| `DELETE` | [`/api/assets/{asset_id}`](../../api/src/nimstead/app.py#L1239) | Admin browser session | Delete an organisation-owned asset and its associated rows; append the deletion to the ledger. |
| `PATCH` | [`/api/assets/{asset_id}`](../../api/src/nimstead/app.py#L1282) | Admin browser session | Update an owned asset's editable context, ring, health checks, or maintenance settings. |
| `POST` | [`/api/assets/{asset_id}/sbom`](../../api/src/nimstead/app.py#L1403) | Asset upload/agent key or admin session | Replace this asset's SBOM packages and return mapping counts and scan results. |
| `GET` | [`/api/assets/{asset_id}/scan-report`](../../api/src/nimstead/app.py#L1251) | Session or read-only API token | Every check's verdict on this host's stored inventory (nimstead/engine). Findings still open and close through rescan. |
| `GET` | [`/api/attack-paths`](../../api/src/nimstead/app.py#L1256) | Session or read-only API token | Which hosts an attacker who gets into one can reach next, from each host's latest stored scan report (engine/fleet.py). |
| `POST` | [`/api/auth/login`](../../api/src/nimstead/app.py#L542) | No user-session dependency | Authenticate a password user and complete or request two-step sign-in. |
| `POST` | [`/api/auth/logout`](../../api/src/nimstead/app.py#L616) | No user-session dependency | Delete the current server-side session, clear its browser cookie, and return no content. |
| `POST` | [`/api/auth/password/reset`](../../api/src/nimstead/app.py#L490) | No user-session dependency | Same answer whether or not the address has an account; the link goes to the address itself. |
| `POST` | [`/api/auth/signup`](../../api/src/nimstead/app.py#L451) | No user-session dependency | Create the first organisation account or send a later signup confirmation email. |
| `GET` | [`/api/auth/signup/confirm`](../../api/src/nimstead/app.py#L2149) | Signup confirmation token | Return the password-selection form for a valid signup, invitation, or reset token; otherwise HTML 404. |
| `POST` | [`/api/auth/signup/confirm`](../../api/src/nimstead/app.py#L2157) | Signup confirmation token | Consume a confirmation form and choose a password for signup, invitation, or password reset. |
| `GET` | [`/api/auth/sso/callback`](../../api/src/nimstead/app.py#L1921) | SSO flow cookie and provider response | Validate the pending SSO flow and provider identity, then establish a session. |
| `POST` | [`/api/auth/sso/start`](../../api/src/nimstead/app.py#L1890) | No user-session dependency | Read the SSO start form and begin the configured organisation's authorisation-code flow. |
| `GET` | [`/api/baselines`](../../api/src/nimstead/app.py#L1066) | Session or read-only API token | How Windows hosts compare with the automated part of a baseline (DECISIONS 75). A reference, never a conformance result. |
| `GET` | [`/api/baselines.csv`](../../api/src/nimstead/app.py#L1084) | Session or read-only API token | Stream the organisation's baseline results as spreadsheet-safe CSV. |
| `GET` | [`/api/baselines/{asset_id}`](../../api/src/nimstead/app.py#L1117) | Session or read-only API token | Return the Windows baseline evaluation for an organisation-owned host. |
| `GET` | [`/api/coverage`](../../api/src/nimstead/app.py#L1224) | Session or read-only API token | How much of the fleet's Windows software is checked at all, so a clean result can't be misread. |
| `GET` | [`/api/directory/unmanaged`](../../api/src/nimstead/app.py#L1042) | Session or read-only API token | Enabled computers seen in their domain in the last 30 days that have no enrolled agent (plan T43). |
| `POST` | [`/api/enroll-tokens`](../../api/src/nimstead/app.py#L712) | Admin browser session | Create an expiring enrolment token and return its secret once, with ID and expiry. |
| `GET` | [`/api/enroll-tokens`](../../api/src/nimstead/app.py#L725) | Session or read-only API token | Return enrolment-token metadata for this organisation without token secrets. |
| `DELETE` | [`/api/enroll-tokens/{token_id}`](../../api/src/nimstead/app.py#L734) | Admin browser session | Revoke the enrolment token identified by its displayed hash prefix; return no content. |
| `GET` | [`/api/evidence/ledger`](../../api/src/nimstead/app.py#L2273) | Session or read-only API token | Return recent ledger entries, matching total, and integrity problems for the organisation. |
| `GET` | [`/api/evidence/pack`](../../api/src/nimstead/app.py#L2316) | Session or read-only API token | Return a signed ZIP evidence pack for the requested trailing days. |
| `GET` | [`/api/evidence/public-key`](../../api/src/nimstead/app.py#L2290) | No user-session dependency | Publish this out of band (website, contract, auditor email); auditors verify packs against it, not the copy in the zip. |
| `GET` | [`/api/evidence/report`](../../api/src/nimstead/app.py#L2301) | Session or read-only API token | Return the evidence report for the requested trailing days. |
| `GET` | [`/api/evidence/verify.py`](../../api/src/nimstead/app.py#L2296) | No user-session dependency | The offline verifier, published here (and by hash next to the key) rather than inside the pack it checks. |
| `GET` | [`/api/findings`](../../api/src/nimstead/app.py#L1486) | Session or read-only API token | Return an array of organisation findings matching the query filters. |
| `GET` | [`/api/findings.csv`](../../api/src/nimstead/app.py#L1537) | Session or read-only API token | Stream all matching findings as CSV, escaping spreadsheet formula prefixes. |
| `POST` | [`/api/findings/accept`](../../api/src/nimstead/app.py#L1646) | Admin browser session | One decision for one vulnerability on every host it's open on now (each recorded; new hosts aren't covered). |
| `POST` | [`/api/findings/accept-many`](../../api/src/nimstead/app.py#L1660) | Admin browser session | One reason for a selection of findings (each recorded on its own); ones already closed or not yours are skipped. |
| `GET` | [`/api/findings/count`](../../api/src/nimstead/app.py#L1503) | Session or read-only API token | How many match, so a capped list can say how many it isn't showing. |
| `GET` | [`/api/findings/groups`](../../api/src/nimstead/app.py#L1512) | Session or read-only API token | One row per vulnerability or package across the fleet, worst first (the overdue filter isn't applied here). |
| `GET` | [`/api/findings/{finding_id}`](../../api/src/nimstead/app.py#L1597) | Session or read-only API token | Return an owned finding with full detail, package context, and its remediation deadline. |
| `POST` | [`/api/findings/{finding_id}/accept`](../../api/src/nimstead/app.py#L1621) | Admin browser session | Record time-limited risk acceptance with a reason and return the updated finding. |
| `POST` | [`/api/findings/{finding_id}/revoke-acceptance`](../../api/src/nimstead/app.py#L1672) | Admin browser session | Reopen an accepted finding with a recorded reason and return its updated detail. |
| `GET` | [`/api/me`](../../api/src/nimstead/app.py#L624) | Session or read-only API token | Return the current user email, organisation, admin role, login origin, and MFA status. |
| `POST` | [`/api/me/mfa`](../../api/src/nimstead/app.py#L690) | Browser session; no API token | Confirm or replace the authenticator and return newly generated one-time recovery codes. |
| `POST` | [`/api/me/mfa/setup`](../../api/src/nimstead/app.py#L673) | Browser session; no API token | Return a temporary encrypted setup token, secret, and authenticator URI for a password user. |
| `POST` | [`/api/me/password`](../../api/src/nimstead/app.py#L648) | Browser session; no API token | Change a password after verifying the current password and required authenticator code. |
| `POST` | [`/api/me/sessions/revoke`](../../api/src/nimstead/app.py#L632) | Browser session; no API token | Revoke all sessions for the current user, clear this cookie, and return no content. |
| `GET` | [`/api/notify/confirm`](../../api/src/nimstead/app.py#L2106) | Confirmation token | Return the email-alert consent form for a valid confirmation link, otherwise HTML 404. |
| `POST` | [`/api/notify/confirm`](../../api/src/nimstead/app.py#L2115) | Confirmation token | Confirm the linked email recipient and return HTML confirmation, or HTML 404 for an invalid link. |
| `POST` | [`/api/remediation/jobs`](../../api/src/nimstead/app.py#L1708) | Admin browser session | Plan a package fix on an owned asset and return the job without executing it. |
| `GET` | [`/api/remediation/jobs`](../../api/src/nimstead/app.py#L1744) | Session or read-only API token | Return up to 500 recent jobs, optionally filtered by comma-separated status names. |
| `POST` | [`/api/remediation/jobs/batch`](../../api/src/nimstead/app.py#L1729) | Admin browser session | One fix on many machines in one request ("plan the rest"): each plan is its own commit, so one refusal keeps the others. |
| `POST` | [`/api/remediation/jobs/{job_id}/approve`](../../api/src/nimstead/app.py#L1791) | Admin browser session | Approve a planned job and return its detail. |
| `POST` | [`/api/remediation/jobs/{job_id}/cancel`](../../api/src/nimstead/app.py#L1811) | Admin browser session | Cancel a job when its current state permits cancellation; return the updated job. |
| `GET` | [`/api/settings`](../../api/src/nimstead/app.py#L1837) | Session or read-only API token | Return organisation policy, deadlines, agent update status, and server release status. |
| `PATCH` | [`/api/settings`](../../api/src/nimstead/app.py#L1849) | Admin browser session | Update organisation policy, record the decision, and return current settings. |
| `GET` | [`/api/settings/notifications`](../../api/src/nimstead/app.py#L2053) | Admin browser session | Return webhook/email configuration, confirmation state, and recent notification outcomes. |
| `PUT` | [`/api/settings/notifications`](../../api/src/nimstead/app.py#L2060) | Admin browser session | Save notification settings and request confirmation for newly added email recipients. |
| `POST` | [`/api/settings/notifications/test`](../../api/src/nimstead/app.py#L2202) | Admin browser session | Queue a test notification for the organisation and return queued=true with HTTP 202. |
| `GET` | [`/api/settings/sso`](../../api/src/nimstead/app.py#L1991) | Admin browser session | Return SSO configuration with domain-verification instructions, without exposing its stored secret. |
| `PUT` | [`/api/settings/sso`](../../api/src/nimstead/app.py#L1998) | Admin browser session | Validate and save SSO configuration and return the current domain-verification state. |
| `POST` | [`/api/settings/sso/verify`](../../api/src/nimstead/app.py#L1978) | Admin browser session | Check each pending domain's DNS TXT record; only verified domains route SSO sign-ins. |
| `GET` | [`/api/summary`](../../api/src/nimstead/app.py#L2362) | Session or read-only API token | Return fleet counts, priority totals, recommended upgrades, and jobs needing attention. |
| `POST` | [`/api/targets`](../../api/src/nimstead/app.py#L1316) | Admin browser session | Create an external target for a public DNS hostname and return its asset record. |
| `POST` | [`/api/targets/{target_id}/scan`](../../api/src/nimstead/app.py#L1367) | Admin browser session | Recheck ownership, scan the external target, and return its findings result. |
| `POST` | [`/api/targets/{target_id}/verify`](../../api/src/nimstead/app.py#L1343) | Admin browser session | Verify DNS and address ownership for an external target and return its asset record. |
| `POST` | [`/api/tokens`](../../api/src/nimstead/app.py#L837) | Admin browser session | Create a read-only organisation API token and return its secret once. |
| `GET` | [`/api/tokens`](../../api/src/nimstead/app.py#L860) | Admin browser session | Return organisation API-token metadata and creator emails without token secrets. |
| `DELETE` | [`/api/tokens/{token_id}`](../../api/src/nimstead/app.py#L870) | Admin browser session | Delete the API token identified by its displayed hash prefix; return no content. |
| `GET` | [`/api/users`](../../api/src/nimstead/app.py#L764) | Admin browser session | Return organisation member records ordered by email. |
| `POST` | [`/api/users/invite`](../../api/src/nimstead/app.py#L815) | Admin browser session | Same answer whether or not the address already has an account (anywhere): the address owner gets the next step. |
| `PATCH` | [`/api/users/{user_id}`](../../api/src/nimstead/app.py#L774) | Admin browser session | Change an organisation member's admin role while preserving at least one admin. |
| `DELETE` | [`/api/users/{user_id}`](../../api/src/nimstead/app.py#L794) | Admin browser session | Remove an organisation member and their access while preserving at least one admin. |
| `GET` | [`/api/windows-updates`](../../api/src/nimstead/app.py#L1766) | Session or read-only API token | Return Windows update groups across this organisation without the per-host detail lists. |
| `GET` | [`/api/windows-updates/{kb}`](../../api/src/nimstead/app.py#L1774) | Session or read-only API token | Return host-level detail for a Windows KB and exact product query. |
| `GET` | [`/install.ps1`](../../api/src/nimstead/app.py#L372) | No user-session dependency | Return the PowerShell installer with this server URL and release channel substituted. |
| `GET` | [`/install.sh`](../../api/src/nimstead/app.py#L360) | No user-session dependency | Return the Linux installer with this server URL and release channel substituted. |

The schema contains 83 operations and 31 schema definitions.

## Routes outside the schema

- `GET /api/health`: unauthenticated deployment health; HTTP 200 when database and migration checks pass, otherwise 503.
- `GET /.well-known/security.txt`: public security contact policy.
- Static web assets and the web application's fallback route are not API contracts.

## Refresh this reference

From the repository root with the locked API environment available:

```bash
(cd api && uv run python ../scripts/export_api_docs.py)
```

CI checks freshness with `--check`. Compare the schema served by your installed release before integration.
