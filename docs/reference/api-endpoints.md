# HTTP endpoint catalog

Use the [OpenAPI JSON](openapi.json) for typed parameters, request models, defaults, and declared response schemas.

The export adds server/authentication metadata and selected contracts: account/authentication, assets, inventory, fleet summary, findings, remediation, policy, Windows updates, baselines, notifications, CSV, SBOM, external-scan counters, agent manifest and distribution files. Other definitions come from the app.

Authentication labels describe entry requirements. Organisation ownership, roles, origin checks, quotas, and operation-specific state checks still apply. See [HTTP API reference](http-api.md).

Empty response schemas do not define a stable response contract. Inspect the linked handler and its tests for returned dictionary fields. Error responses in OpenAPI are not an exhaustive list of runtime failures.

## Operations

| Method | Path | Authentication | Purpose |
| --- | --- | --- | --- |
| `GET` | [`/agent/nimstead_agent.py`](../../api/src/nimstead/app.py#L429) | No user-session dependency | Return the Python agent source served by this checkout. |
| `GET` | [`/agent/runtime/{arch}.zip`](../../api/src/nimstead/app.py#L434) | No user-session dependency | Return application/zip runtime bytes for arch: amd64, arm64 or win32. |
| `POST` | [`/api/agent/directory`](../../api/src/nimstead/app.py#L1176) | Asset agent key | Replace the organisation's entire stored directory list with this agent's body. |
| `POST` | [`/api/agent/enroll`](../../api/src/nimstead/app.py#L1024) | Enrolment token in JSON body | Create a new host asset and return asset_id plus its one-time agent_key. |
| `POST` | [`/api/agent/inventory`](../../api/src/nimstead/app.py#L1117) | Asset agent key | Update stored host metadata, rescan and return open/resolved counts. |
| `GET` | [`/api/agent/jobs`](../../api/src/nimstead/app.py#L1328) | Asset agent key | Dispatch eligible approved jobs to this agent and return their execution plans. |
| `POST` | [`/api/agent/jobs/{job_id}/report`](../../api/src/nimstead/app.py#L1349) | Asset agent key | Record an outcome for a job owned by this agent and return its resulting status. |
| `GET` | [`/api/agent/manifest`](../../api/src/nimstead/app.py#L1316) | Asset agent key | Return the organisation's update pause flag and any valid signed release for the served agent. |
| `POST` | [`/api/ai/explain/{finding_id}`](../../api/src/nimstead/app.py#L2642) | Browser session | Return an AI explanation and model name for an owned finding, subject to AI usage quotas. |
| `POST` | [`/api/ai/search`](../../api/src/nimstead/app.py#L2660) | Browser session | Return a validated findings filter from the submitted natural-language text, subject to AI usage quotas. |
| `GET` | [`/api/ai/status`](../../api/src/nimstead/app.py#L2629) | Session or read-only API token | Return whether the optional AI service is configured and enabled. |
| `GET` | [`/api/assets`](../../api/src/nimstead/app.py#L1404) | Session or read-only API token | Return organisation assets with finding counts, agent status, and application coverage. |
| `POST` | [`/api/assets`](../../api/src/nimstead/app.py#L1632) | Admin browser session | Create an application asset and return its record plus upload_token. |
| `DELETE` | [`/api/assets/{asset_id}`](../../api/src/nimstead/app.py#L1450) | Admin browser session | Delete an owned asset and its findings, packages, jobs and scan records. |
| `PATCH` | [`/api/assets/{asset_id}`](../../api/src/nimstead/app.py#L1506) | Admin browser session | Update owned asset context, rescan and return an asset record. |
| `POST` | [`/api/assets/{asset_id}/sbom`](../../api/src/nimstead/app.py#L1651) | Asset upload/agent key or admin session | Read raw CycloneDX/SPDX JSON and return parser plus rescan counts. |
| `GET` | [`/api/assets/{asset_id}/scan-report`](../../api/src/nimstead/app.py#L1466) | Session or read-only API token | Return the grouped engine report for asset_id's stored inventory. |
| `GET` | [`/api/attack-paths`](../../api/src/nimstead/app.py#L1475) | Session or read-only API token | Return organisation fleet paths from latest stored reports and current host facts. |
| `POST` | [`/api/auth/login`](../../api/src/nimstead/app.py#L640) | No user-session dependency | Return a password-login branch, creating a session only after required MFA. |
| `POST` | [`/api/auth/logout`](../../api/src/nimstead/app.py#L719) | No user-session dependency | Return 204 after deleting the cookie-selected session when present. |
| `POST` | [`/api/auth/password/reset`](../../api/src/nimstead/app.py#L563) | No user-session dependency | Return 202 status=check_email/email for a reset request. |
| `POST` | [`/api/auth/signup`](../../api/src/nimstead/app.py#L519) | No user-session dependency | Create a first/development admin or acknowledge an email signup request. |
| `GET` | [`/api/auth/signup/confirm`](../../api/src/nimstead/app.py#L2543) | Signup confirmation token | Return password-selection HTML for a valid link, otherwise HTML 404. |
| `POST` | [`/api/auth/signup/confirm`](../../api/src/nimstead/app.py#L2554) | Signup confirmation token | Parse the first form password and complete the query token's account link. |
| `GET` | [`/api/auth/sso/callback`](../../api/src/nimstead/app.py#L2272) | SSO flow cookie and provider response | Consume a pending flow and return a success or sign-in error redirect. |
| `POST` | [`/api/auth/sso/start`](../../api/src/nimstead/app.py#L2232) | No user-session dependency | Parse URL-encoded email/org from a POST and return an SSO redirect. |
| `GET` | [`/api/baselines`](../../api/src/nimstead/app.py#L1235) | Session or read-only API token | Return baselines/hosts/no_baseline for the caller's stored Windows host facts. |
| `GET` | [`/api/baselines.csv`](../../api/src/nimstead/app.py#L1258) | Session or read-only API token | Stream the organisation's baseline results as spreadsheet-safe CSV. |
| `GET` | [`/api/baselines/{asset_id}`](../../api/src/nimstead/app.py#L1296) | Session or read-only API token | Return the Windows baseline evaluation for an organisation-owned host. |
| `GET` | [`/api/coverage`](../../api/src/nimstead/app.py#L1426) | Session or read-only API token | Return assessed/inventory_only mapping counts and at most 200 unmatched groups. |
| `GET` | [`/api/directory/unmanaged`](../../api/src/nimstead/app.py#L1205) | Session or read-only API token | Return recent stored directory observations without an enrolled short-name match. |
| `POST` | [`/api/enroll-tokens`](../../api/src/nimstead/app.py#L823) | Admin browser session | Return token/id/expires once for a new enrolment credential, with HTTP 201. |
| `GET` | [`/api/enroll-tokens`](../../api/src/nimstead/app.py#L838) | Session or read-only API token | Return id/created/expires/revoked/sandbox rows, newest created first. |
| `DELETE` | [`/api/enroll-tokens/{token_id}`](../../api/src/nimstead/app.py#L849) | Admin browser session | Mark one matching organisation enrolment token revoked and return 204. |
| `GET` | [`/api/evidence/ledger`](../../api/src/nimstead/app.py#L2685) | Session or read-only API token | Return recent ledger entries, matching total, and integrity problems for the organisation. |
| `GET` | [`/api/evidence/pack`](../../api/src/nimstead/app.py#L2728) | Session or read-only API token | Return a signed ZIP evidence pack for the requested trailing days. |
| `GET` | [`/api/evidence/public-key`](../../api/src/nimstead/app.py#L2702) | No user-session dependency | Publish this out of band (website, contract, auditor email); auditors verify packs against it, not the copy in the zip. |
| `GET` | [`/api/evidence/report`](../../api/src/nimstead/app.py#L2713) | Session or read-only API token | Return the evidence report for the requested trailing days. |
| `GET` | [`/api/evidence/verify.py`](../../api/src/nimstead/app.py#L2708) | No user-session dependency | The offline verifier, published here (and by hash next to the key) rather than inside the pack it checks. |
| `GET` | [`/api/findings`](../../api/src/nimstead/app.py#L1752) | Session or read-only API token | Return an array of organisation findings matching the query filters. |
| `GET` | [`/api/findings.csv`](../../api/src/nimstead/app.py#L1812) | Session or read-only API token | Stream all matching findings as CSV, escaping spreadsheet formula prefixes. |
| `POST` | [`/api/findings/accept`](../../api/src/nimstead/app.py#L1936) | Admin browser session | Accept currently open findings for body.vuln_id in the admin's organisation. |
| `POST` | [`/api/findings/accept-many`](../../api/src/nimstead/app.py#L1954) | Admin browser session | Accept the admin's open findings among body.ids, with reason and expiry days. |
| `GET` | [`/api/findings/count`](../../api/src/nimstead/app.py#L1769) | Session or read-only API token | Return {total: integer} for the caller's findings matching query filters f. |
| `GET` | [`/api/findings/groups`](../../api/src/nimstead/app.py#L1781) | Session or read-only API token | Return up to 500 grouped finding rows for the caller's organisation. |
| `GET` | [`/api/findings/{finding_id}`](../../api/src/nimstead/app.py#L1878) | Session or read-only API token | Return an owned finding with full detail, package context, and its remediation deadline. |
| `POST` | [`/api/findings/{finding_id}/accept`](../../api/src/nimstead/app.py#L1907) | Admin browser session | Record time-limited risk acceptance with a reason and return the updated finding. |
| `POST` | [`/api/findings/{finding_id}/revoke-acceptance`](../../api/src/nimstead/app.py#L1970) | Admin browser session | Reopen an accepted finding with a recorded reason and return its updated detail. |
| `GET` | [`/api/me`](../../api/src/nimstead/app.py#L731) | Session or read-only API token | Return email/org/admin/origin/mfa/recovery_codes_left for current_user. |
| `POST` | [`/api/me/mfa`](../../api/src/nimstead/app.py#L800) | Browser session; no API token | Return recovery_codes after staging and committing an authenticator setup. |
| `POST` | [`/api/me/mfa/setup`](../../api/src/nimstead/app.py#L785) | Browser session; no API token | Return setup/secret/uri for a browser-authenticated password user. |
| `POST` | [`/api/me/password`](../../api/src/nimstead/app.py#L759) | Browser session; no API token | Return 204 after a password-origin user's credential update. |
| `POST` | [`/api/me/sessions/revoke`](../../api/src/nimstead/app.py#L741) | Browser session; no API token | Delete this user's WebSession and ApiToken rows, commit, then clear cookie. |
| `GET` | [`/api/notify/confirm`](../../api/src/nimstead/app.py#L2484) | Confirmation token | Return an email-alert consent form for query org/email/token, or HTML 404 on failed proof. |
| `POST` | [`/api/notify/confirm`](../../api/src/nimstead/app.py#L2497) | Confirmation token | Confirm query org/email/token and return HTML 200, or HTML 404 when invalid. |
| `POST` | [`/api/remediation/jobs`](../../api/src/nimstead/app.py#L2015) | Admin browser session | Plan a package fix on an owned asset and return the job without executing it. |
| `GET` | [`/api/remediation/jobs`](../../api/src/nimstead/app.py#L2058) | Session or read-only API token | Return up to 500 recent jobs, optionally filtered by comma-separated status names. |
| `POST` | [`/api/remediation/jobs/batch`](../../api/src/nimstead/app.py#L2038) | Admin browser session | Return jobs/errors after one action is planned across 1..5000 requested assets. |
| `POST` | [`/api/remediation/jobs/{job_id}/approve`](../../api/src/nimstead/app.py#L2114) | Admin browser session | Approve a planned job and return its detail. |
| `POST` | [`/api/remediation/jobs/{job_id}/cancel`](../../api/src/nimstead/app.py#L2134) | Admin browser session | Cancel a job when its current state permits cancellation; return the updated job. |
| `GET` | [`/api/settings`](../../api/src/nimstead/app.py#L2160) | Session or read-only API token | Return organisation policy, deadlines, agent update status, and server release status. |
| `PATCH` | [`/api/settings`](../../api/src/nimstead/app.py#L2175) | Admin browser session | Update organisation policy, record the decision, and return current settings. |
| `GET` | [`/api/settings/notifications`](../../api/src/nimstead/app.py#L2421) | Admin browser session | Return webhook/email configuration, confirmation state, and recent notification outcomes. |
| `PUT` | [`/api/settings/notifications`](../../api/src/nimstead/app.py#L2432) | Admin browser session | Save notification settings and request confirmation for newly added email recipients. |
| `POST` | [`/api/settings/notifications/test`](../../api/src/nimstead/app.py#L2610) | Admin browser session | Attempt a test notification and return queued=true with HTTP 202. |
| `GET` | [`/api/settings/sso`](../../api/src/nimstead/app.py#L2356) | Admin browser session | Return saved SSO fields and proof instructions for an admin browser user. |
| `PUT` | [`/api/settings/sso`](../../api/src/nimstead/app.py#L2364) | Admin browser session | Replace saved SSO configuration and return sso_json after commit. |
| `POST` | [`/api/settings/sso/verify`](../../api/src/nimstead/app.py#L2338) | Admin browser session | Check only unverified, unclaimed saved domains and return sso_json. |
| `GET` | [`/api/summary`](../../api/src/nimstead/app.py#L2774) | Session or read-only API token | Return asset/priority counts, up to ten actions and twenty attention jobs. |
| `POST` | [`/api/targets`](../../api/src/nimstead/app.py#L1549) | Admin browser session | Create an external target for a public DNS hostname and return its asset record. |
| `POST` | [`/api/targets/{target_id}/scan`](../../api/src/nimstead/app.py#L1606) | Admin browser session | Recheck ownership, scan the external target, and return its findings result. |
| `POST` | [`/api/targets/{target_id}/verify`](../../api/src/nimstead/app.py#L1578) | Admin browser session | Verify DNS and address ownership for an external target and return its asset record. |
| `POST` | [`/api/tokens`](../../api/src/nimstead/app.py#L969) | Admin browser session | Return token/id/name/expires once for a read-only credential, with HTTP 201. |
| `GET` | [`/api/tokens`](../../api/src/nimstead/app.py#L991) | Admin browser session | Return organisation token metadata/creator email, newest created first. |
| `DELETE` | [`/api/tokens/{token_id}`](../../api/src/nimstead/app.py#L1003) | Admin browser session | Delete one matching organisation API-token hash prefix and return 204. |
| `GET` | [`/api/users`](../../api/src/nimstead/app.py#L888) | Admin browser session | Return organisation user_json records sorted by email, without pagination. |
| `POST` | [`/api/users/invite`](../../api/src/nimstead/app.py#L941) | Admin browser session | Return 202 status=invited/email after an invitation request. |
| `PATCH` | [`/api/users/{user_id}`](../../api/src/nimstead/app.py#L899) | Admin browser session | Set a member's admin flag and return user_json, preserving one admin. |
| `DELETE` | [`/api/users/{user_id}`](../../api/src/nimstead/app.py#L920) | Admin browser session | Delete a member and their sessions/API tokens, append evidence and return 204. |
| `GET` | [`/api/windows-updates`](../../api/src/nimstead/app.py#L2082) | Session or read-only API token | Return Windows update groups across this organisation without the per-host detail lists. |
| `GET` | [`/api/windows-updates/{kb}`](../../api/src/nimstead/app.py#L2093) | Session or read-only API token | Return host-level detail for a Windows KB and exact product query. |
| `GET` | [`/install.ps1`](../../api/src/nimstead/app.py#L417) | No user-session dependency | Return the PowerShell installer with this server URL and release channel substituted. |
| `GET` | [`/install.sh`](../../api/src/nimstead/app.py#L405) | No user-session dependency | Return the Linux installer with this server URL and release channel substituted. |

The schema contains 83 operations and 69 schema definitions.

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
