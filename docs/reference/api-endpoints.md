# HTTP endpoint catalog

Use the [OpenAPI JSON](openapi.json) for typed parameters, request models, defaults, and declared response schemas.

The export adds server/authentication metadata and response contracts for account/authentication, assets, inventory, fleet summary/paths, findings, remediation, policy, Windows updates, baselines, notifications, AI, directory, scan reports, evidence, CSV, SBOM, agent manifests and distribution files. Request definitions come from the app.

Authentication labels describe entry requirements. Organisation ownership, roles, origin checks, quotas, and operation-specific state checks still apply. See [HTTP API reference](http-api.md).

The export defines success payloads and selected shared errors. Inspect the linked handler and its tests for returned dictionary fields. Error responses in OpenAPI are not an exhaustive list of runtime failures.

## Operations

| Method | Path | Authentication | Purpose |
| --- | --- | --- | --- |
| `GET` | [`/agent/nimstead_agent.py`](../../api/src/nimstead/app.py#L478) | No user-session dependency | Return AGENT_FILE bytes as text/x-python without user authentication. |
| `GET` | [`/agent/runtime/{arch}.zip`](../../api/src/nimstead/app.py#L487) | No user-session dependency | Return application/zip runtime bytes for arch: amd64, arm64 or win32. |
| `POST` | [`/api/agent/directory`](../../api/src/nimstead/app.py#L1238) | Asset agent key | Replace the organisation's entire stored directory list with this agent's body. |
| `POST` | [`/api/agent/enroll`](../../api/src/nimstead/app.py#L1077) | Enrolment token in JSON body | Create a new host asset and return asset_id plus its one-time agent_key. |
| `POST` | [`/api/agent/inventory`](../../api/src/nimstead/app.py#L1176) | Asset agent key | Update stored host metadata, rescan and return open/resolved counts. |
| `GET` | [`/api/agent/jobs`](../../api/src/nimstead/app.py#L1432) | Asset agent key | Dispatch eligible approved jobs to this agent and return their execution plans. |
| `POST` | [`/api/agent/jobs/{job_id}/report`](../../api/src/nimstead/app.py#L1453) | Asset agent key | Record an outcome for a job owned by this agent and return its resulting status. |
| `GET` | [`/api/agent/manifest`](../../api/src/nimstead/app.py#L1420) | Asset agent key | Return the organisation's update pause flag and any valid signed release for the served agent. |
| `POST` | [`/api/agent/network-checks`](../../api/src/nimstead/app.py#L1300) | Asset agent key | Judge what this host's opted-in agent observed on devices it chose itself (DECISIONS 129) and return counts. |
| `POST` | [`/api/ai/explain/{finding_id}`](../../api/src/nimstead/app.py#L2777) | Browser session | Return text/model for finding_id's owned detail through ai.explain. |
| `POST` | [`/api/ai/search`](../../api/src/nimstead/app.py#L2795) | Browser session | Return five validated filter fields from body.text via ai.parse_search. |
| `GET` | [`/api/ai/status`](../../api/src/nimstead/app.py#L2757) | Session or read-only API token | Return enabled configuration Boolean without a provider request. |
| `GET` | [`/api/assets`](../../api/src/nimstead/app.py#L1508) | Session or read-only API token | Return organisation assets with finding counts, agent status, and application coverage. |
| `POST` | [`/api/assets`](../../api/src/nimstead/app.py#L1747) | Admin browser session | Create an application asset and return its record plus upload_token. |
| `DELETE` | [`/api/assets/{asset_id}`](../../api/src/nimstead/app.py#L1554) | Admin browser session | Delete an owned asset and its findings, packages, jobs and scan records. |
| `PATCH` | [`/api/assets/{asset_id}`](../../api/src/nimstead/app.py#L1621) | Admin browser session | Update owned asset context, rescan and return an asset record. |
| `POST` | [`/api/assets/{asset_id}/sbom`](../../api/src/nimstead/app.py#L1766) | Asset upload/agent key or admin session | Read raw CycloneDX/SPDX JSON and return parser plus rescan counts. |
| `GET` | [`/api/assets/{asset_id}/scan-report`](../../api/src/nimstead/app.py#L1574) | Session or read-only API token | Return the grouped engine report for asset_id's stored inventory. |
| `GET` | [`/api/attack-paths`](../../api/src/nimstead/app.py#L1590) | Session or read-only API token | Return organisation fleet paths from latest stored reports and current host facts. |
| `POST` | [`/api/auth/login`](../../api/src/nimstead/app.py#L693) | No user-session dependency | Return a password-login branch, creating a session only after required MFA. |
| `POST` | [`/api/auth/logout`](../../api/src/nimstead/app.py#L772) | No user-session dependency | Return 204 after deleting the cookie-selected session when present. |
| `POST` | [`/api/auth/password/reset`](../../api/src/nimstead/app.py#L616) | No user-session dependency | Return 202 status=check_email/email for a reset request. |
| `POST` | [`/api/auth/signup`](../../api/src/nimstead/app.py#L572) | No user-session dependency | Create a first/development admin or acknowledge an email signup request. |
| `GET` | [`/api/auth/signup/confirm`](../../api/src/nimstead/app.py#L2668) | Signup confirmation token | Return password-selection HTML for a valid link, otherwise HTML 404. |
| `POST` | [`/api/auth/signup/confirm`](../../api/src/nimstead/app.py#L2679) | Signup confirmation token | Parse the first form password and complete the query token's account link. |
| `GET` | [`/api/auth/sso/callback`](../../api/src/nimstead/app.py#L2397) | SSO flow cookie and provider response | Consume a pending flow and return a success or sign-in error redirect. |
| `POST` | [`/api/auth/sso/start`](../../api/src/nimstead/app.py#L2357) | No user-session dependency | Parse URL-encoded email/org from a POST and return an SSO redirect. |
| `GET` | [`/api/baselines`](../../api/src/nimstead/app.py#L1339) | Session or read-only API token | Return baselines/hosts/no_baseline for the caller's stored Windows host facts. |
| `GET` | [`/api/baselines.csv`](../../api/src/nimstead/app.py#L1362) | Session or read-only API token | Stream the organisation's baseline results as spreadsheet-safe CSV. |
| `GET` | [`/api/baselines/{asset_id}`](../../api/src/nimstead/app.py#L1400) | Session or read-only API token | Return the Windows baseline evaluation for an organisation-owned host. |
| `GET` | [`/api/coverage`](../../api/src/nimstead/app.py#L1530) | Session or read-only API token | Return assessed/inventory_only mapping counts and at most 200 unmatched groups. |
| `GET` | [`/api/directory/unmanaged`](../../api/src/nimstead/app.py#L1267) | Session or read-only API token | Return recent stored directory observations without an enrolled short-name match. |
| `POST` | [`/api/enroll-tokens`](../../api/src/nimstead/app.py#L876) | Admin browser session | Return token/id/expires once for a new enrolment credential, with HTTP 201. |
| `GET` | [`/api/enroll-tokens`](../../api/src/nimstead/app.py#L891) | Session or read-only API token | Return id/created/expires/revoked/sandbox rows, newest created first. |
| `DELETE` | [`/api/enroll-tokens/{token_id}`](../../api/src/nimstead/app.py#L902) | Admin browser session | Mark one matching organisation enrolment token revoked and return 204. |
| `GET` | [`/api/evidence/ledger`](../../api/src/nimstead/app.py#L2819) | Session or read-only API token | Return problems, newest entries and matching total for the user's ledger. |
| `GET` | [`/api/evidence/pack`](../../api/src/nimstead/app.py#L2870) | Session or read-only API token | Return an application/zip evidence attachment for trailing days, default 90. |
| `GET` | [`/api/evidence/public-key`](../../api/src/nimstead/app.py#L2837) | No user-session dependency | Return pem, fingerprint_sha256 and verifier_sha256 without authentication. |
| `GET` | [`/api/evidence/report`](../../api/src/nimstead/app.py#L2855) | Session or read-only API token | Return current evidence data for trailing days, default 90 and range 1..730. |
| `GET` | [`/api/evidence/verify.py`](../../api/src/nimstead/app.py#L2847) | No user-session dependency | Return current offline verifier source as text/x-python, without authentication. |
| `GET` | [`/api/findings`](../../api/src/nimstead/app.py#L1873) | Session or read-only API token | Return an array of organisation findings matching the query filters. |
| `GET` | [`/api/findings.csv`](../../api/src/nimstead/app.py#L1933) | Session or read-only API token | Stream all matching findings as CSV, escaping spreadsheet formula prefixes. |
| `POST` | [`/api/findings/accept`](../../api/src/nimstead/app.py#L2061) | Admin browser session | Accept currently open findings for body.vuln_id in the admin's organisation. |
| `POST` | [`/api/findings/accept-many`](../../api/src/nimstead/app.py#L2079) | Admin browser session | Accept the admin's open findings among body.ids, with reason and expiry days. |
| `GET` | [`/api/findings/count`](../../api/src/nimstead/app.py#L1890) | Session or read-only API token | Return {total: integer} for the caller's findings matching query filters f. |
| `GET` | [`/api/findings/groups`](../../api/src/nimstead/app.py#L1902) | Session or read-only API token | Return up to 500 grouped finding rows for the caller's organisation. |
| `GET` | [`/api/findings/{finding_id}`](../../api/src/nimstead/app.py#L2000) | Session or read-only API token | Return an owned finding with full detail, package context, and its remediation deadline. |
| `POST` | [`/api/findings/{finding_id}/accept`](../../api/src/nimstead/app.py#L2029) | Admin browser session | Record time-limited risk acceptance with a reason and return the updated finding. |
| `POST` | [`/api/findings/{finding_id}/revoke-acceptance`](../../api/src/nimstead/app.py#L2095) | Admin browser session | Reopen an accepted finding with a recorded reason and return its updated detail. |
| `GET` | [`/api/me`](../../api/src/nimstead/app.py#L784) | Session or read-only API token | Return email/org/admin/origin/mfa/recovery_codes_left for current_user. |
| `POST` | [`/api/me/mfa`](../../api/src/nimstead/app.py#L853) | Browser session; no API token | Return recovery_codes after staging and committing an authenticator setup. |
| `POST` | [`/api/me/mfa/setup`](../../api/src/nimstead/app.py#L838) | Browser session; no API token | Return setup/secret/uri for a browser-authenticated password user. |
| `POST` | [`/api/me/password`](../../api/src/nimstead/app.py#L812) | Browser session; no API token | Return 204 after a password-origin user's credential update. |
| `POST` | [`/api/me/sessions/revoke`](../../api/src/nimstead/app.py#L794) | Browser session; no API token | Delete this user's WebSession and ApiToken rows, commit, then clear cookie. |
| `GET` | [`/api/network/unmanaged`](../../api/src/nimstead/app.py#L1314) | Session or read-only API token | Return devices the organisation's agents saw in their own neighbour tables that are none of its agents. |
| `GET` | [`/api/notify/confirm`](../../api/src/nimstead/app.py#L2609) | Confirmation token | Return an email-alert consent form for query org/email/token, or HTML 404 on failed proof. |
| `POST` | [`/api/notify/confirm`](../../api/src/nimstead/app.py#L2622) | Confirmation token | Confirm query org/email/token and return HTML 200, or HTML 404 when invalid. |
| `POST` | [`/api/remediation/jobs`](../../api/src/nimstead/app.py#L2140) | Admin browser session | Plan a package fix on an owned asset and return the job without executing it. |
| `GET` | [`/api/remediation/jobs`](../../api/src/nimstead/app.py#L2183) | Session or read-only API token | Return up to 500 recent jobs, optionally filtered by comma-separated status names. |
| `POST` | [`/api/remediation/jobs/batch`](../../api/src/nimstead/app.py#L2163) | Admin browser session | Return jobs/errors after one action is planned across 1..5000 requested assets. |
| `POST` | [`/api/remediation/jobs/{job_id}/approve`](../../api/src/nimstead/app.py#L2239) | Admin browser session | Approve a planned job and return its detail. |
| `POST` | [`/api/remediation/jobs/{job_id}/cancel`](../../api/src/nimstead/app.py#L2259) | Admin browser session | Cancel a job when its current state permits cancellation; return the updated job. |
| `GET` | [`/api/settings`](../../api/src/nimstead/app.py#L2285) | Session or read-only API token | Return organisation policy, deadlines, agent update status, and server release status. |
| `PATCH` | [`/api/settings`](../../api/src/nimstead/app.py#L2300) | Admin browser session | Update organisation policy, record the decision, and return current settings. |
| `GET` | [`/api/settings/notifications`](../../api/src/nimstead/app.py#L2546) | Admin browser session | Return webhook/email configuration, confirmation state, and recent notification outcomes. |
| `PUT` | [`/api/settings/notifications`](../../api/src/nimstead/app.py#L2557) | Admin browser session | Save notification settings and request confirmation for newly added email recipients. |
| `POST` | [`/api/settings/notifications/test`](../../api/src/nimstead/app.py#L2735) | Admin browser session | Queue a test notification to the saved destinations and return queued=true with HTTP 202. |
| `GET` | [`/api/settings/sso`](../../api/src/nimstead/app.py#L2481) | Admin browser session | Return saved SSO fields and proof instructions for an admin browser user. |
| `PUT` | [`/api/settings/sso`](../../api/src/nimstead/app.py#L2489) | Admin browser session | Replace saved SSO configuration and return sso_json after commit. |
| `POST` | [`/api/settings/sso/verify`](../../api/src/nimstead/app.py#L2463) | Admin browser session | Check only unverified, unclaimed saved domains and return sso_json. |
| `GET` | [`/api/summary`](../../api/src/nimstead/app.py#L2923) | Session or read-only API token | Return asset/priority counts, up to ten actions and twenty attention jobs. |
| `POST` | [`/api/targets`](../../api/src/nimstead/app.py#L1664) | Admin browser session | Create an external target for a public DNS hostname and return its asset record. |
| `POST` | [`/api/targets/{target_id}/scan`](../../api/src/nimstead/app.py#L1721) | Admin browser session | Recheck ownership, scan the external target, and return its findings result. |
| `POST` | [`/api/targets/{target_id}/verify`](../../api/src/nimstead/app.py#L1693) | Admin browser session | Verify DNS and address ownership for an external target and return its asset record. |
| `POST` | [`/api/tokens`](../../api/src/nimstead/app.py#L1022) | Admin browser session | Return token/id/name/expires once for a read-only credential, with HTTP 201. |
| `GET` | [`/api/tokens`](../../api/src/nimstead/app.py#L1044) | Admin browser session | Return organisation token metadata/creator email, newest created first. |
| `DELETE` | [`/api/tokens/{token_id}`](../../api/src/nimstead/app.py#L1056) | Admin browser session | Delete one matching organisation API-token hash prefix and return 204. |
| `GET` | [`/api/users`](../../api/src/nimstead/app.py#L941) | Admin browser session | Return organisation user_json records sorted by email, without pagination. |
| `POST` | [`/api/users/invite`](../../api/src/nimstead/app.py#L994) | Admin browser session | Return 202 status=invited/email after an invitation request. |
| `PATCH` | [`/api/users/{user_id}`](../../api/src/nimstead/app.py#L952) | Admin browser session | Set a member's admin flag and return user_json, preserving one admin. |
| `DELETE` | [`/api/users/{user_id}`](../../api/src/nimstead/app.py#L973) | Admin browser session | Delete a member and their sessions/API tokens, append evidence and return 204. |
| `GET` | [`/api/windows-updates`](../../api/src/nimstead/app.py#L2207) | Session or read-only API token | Return Windows update groups across this organisation without the per-host detail lists. |
| `GET` | [`/api/windows-updates/{kb}`](../../api/src/nimstead/app.py#L2218) | Session or read-only API token | Return host-level detail for a Windows KB and exact product query. |
| `GET` | [`/install.ps1`](../../api/src/nimstead/app.py#L465) | No user-session dependency | Return PowerShell installer text with server origin/channel substituted. |
| `GET` | [`/install.sh`](../../api/src/nimstead/app.py#L451) | No user-session dependency | Return Linux installer text with server origin and current channel substituted. |

The schema contains 85 operations and 113 schema definitions.

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
