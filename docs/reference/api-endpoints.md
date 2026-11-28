# HTTP endpoint catalog

Use the [OpenAPI JSON](openapi.json) for typed parameters, request models, defaults, and declared response schemas.

The export adds server/authentication metadata and response contracts for account/authentication, assets, inventory, fleet summary/paths, findings, remediation, policy, Windows updates, baselines, notifications, AI, directory, scan reports, evidence, CSV, SBOM, agent manifests and distribution files. Request definitions come from the app.

Authentication labels describe entry requirements. Organisation ownership, roles, origin checks, quotas, and operation-specific state checks still apply. See [HTTP API reference](http-api.md).

The export defines success payloads and selected shared errors. Inspect the linked handler and its tests for returned dictionary fields. Error responses in OpenAPI are not an exhaustive list of runtime failures.

## Operations

| Method | Path | Authentication | Purpose |
| --- | --- | --- | --- |
| `GET` | [`/agent/nimstead_agent.py`](../../api/src/nimstead/app.py#L484) | No user-session dependency | Return AGENT_FILE bytes as text/x-python without user authentication. |
| `GET` | [`/agent/runtime/{arch}.zip`](../../api/src/nimstead/app.py#L493) | No user-session dependency | Return application/zip runtime bytes for arch: amd64, arm64 or win32. |
| `POST` | [`/api/agent/containers`](../../api/src/nimstead/app.py#L1386) | Asset agent key | Record the running containers this host's agent read and the images they run (DECISIONS 138-140); return counts. |
| `POST` | [`/api/agent/directory`](../../api/src/nimstead/app.py#L1324) | Asset agent key | Replace the organisation's entire stored directory list with this agent's body. |
| `POST` | [`/api/agent/enroll`](../../api/src/nimstead/app.py#L1148) | Enrolment token in JSON body | Create a new host asset and return asset_id plus its one-time agent_key. |
| `POST` | [`/api/agent/inventory`](../../api/src/nimstead/app.py#L1250) | Asset agent key | Update stored host metadata, rescan and return open/resolved counts. |
| `GET` | [`/api/agent/jobs`](../../api/src/nimstead/app.py#L1546) | Asset agent key | Dispatch eligible approved jobs to this agent and return their execution plans. |
| `POST` | [`/api/agent/jobs/{job_id}/report`](../../api/src/nimstead/app.py#L1567) | Asset agent key | Record an outcome for a job owned by this agent and return its resulting status. |
| `GET` | [`/api/agent/manifest`](../../api/src/nimstead/app.py#L1534) | Asset agent key | Return the organisation's update pause flag and any valid signed release for the served agent. |
| `POST` | [`/api/agent/network-checks`](../../api/src/nimstead/app.py#L1414) | Asset agent key | Judge what this host's opted-in agent observed on devices it chose itself (DECISIONS 129) and return counts. |
| `POST` | [`/api/ai/explain/{finding_id}`](../../api/src/nimstead/app.py#L3236) | Browser session | Return text/model for finding_id's owned detail through ai.explain. |
| `POST` | [`/api/ai/search`](../../api/src/nimstead/app.py#L3254) | Browser session | Return five validated filter fields from body.text via ai.parse_search. |
| `GET` | [`/api/ai/status`](../../api/src/nimstead/app.py#L3216) | Session or read-only API token | Return enabled configuration Boolean without a provider request. |
| `GET` | [`/api/assets`](../../api/src/nimstead/app.py#L1639) | Session or read-only API token | Return organisation assets with finding counts, agent status, and application coverage. |
| `POST` | [`/api/assets`](../../api/src/nimstead/app.py#L1944) | Admin browser session | Create an application asset and return its record plus upload_token. |
| `DELETE` | [`/api/assets/{asset_id}`](../../api/src/nimstead/app.py#L1704) | Admin browser session | Delete an owned asset and its findings, packages, jobs and scan records. |
| `PATCH` | [`/api/assets/{asset_id}`](../../api/src/nimstead/app.py#L1792) | Admin browser session | Update owned asset context, rescan and return an asset record. |
| `GET` | [`/api/assets/{asset_id}/runtime`](../../api/src/nimstead/app.py#L2276) | Session or read-only API token | Return what runs on a host as its agent last read it: programs (listening first) with their users, listening |
| `POST` | [`/api/assets/{asset_id}/sbom`](../../api/src/nimstead/app.py#L1963) | Asset upload/agent key or admin session | Read raw CycloneDX/SPDX JSON and return parser plus rescan counts. |
| `GET` | [`/api/assets/{asset_id}/scan-report`](../../api/src/nimstead/app.py#L1729) | Session or read-only API token | Return the grouped engine report for asset_id's stored inventory. |
| `GET` | [`/api/attack-paths`](../../api/src/nimstead/app.py#L1745) | Session or read-only API token | Return organisation fleet paths from latest stored reports and current host facts. |
| `POST` | [`/api/auth/login`](../../api/src/nimstead/app.py#L730) | No user-session dependency | Return a password-login branch, creating a session only after required MFA. |
| `POST` | [`/api/auth/logout`](../../api/src/nimstead/app.py#L803) | No user-session dependency | Return 204 after deleting the cookie-selected session when present. |
| `POST` | [`/api/auth/password/reset`](../../api/src/nimstead/app.py#L627) | No user-session dependency | Return 202 status=check_email/email for a reset request. |
| `POST` | [`/api/auth/signup`](../../api/src/nimstead/app.py#L583) | No user-session dependency | Create a first/development admin or acknowledge an email signup request. |
| `GET` | [`/api/auth/signup/confirm`](../../api/src/nimstead/app.py#L2951) | Signup confirmation token | Return password-selection HTML for a valid link, otherwise HTML 404. |
| `POST` | [`/api/auth/signup/confirm`](../../api/src/nimstead/app.py#L2962) | Signup confirmation token | Parse the first form password and complete the query token's account link. |
| `GET` | [`/api/auth/sso/callback`](../../api/src/nimstead/app.py#L2668) | SSO flow cookie and provider response | Consume a pending flow and return a success or sign-in error redirect. |
| `POST` | [`/api/auth/sso/start`](../../api/src/nimstead/app.py#L2628) | No user-session dependency | Parse URL-encoded email/org from a POST and return an SSO redirect. |
| `GET` | [`/api/baselines`](../../api/src/nimstead/app.py#L1453) | Session or read-only API token | Return baselines/hosts/no_baseline for the caller's stored Windows host facts. |
| `GET` | [`/api/baselines.csv`](../../api/src/nimstead/app.py#L1476) | Session or read-only API token | Stream the organisation's baseline results as spreadsheet-safe CSV. |
| `GET` | [`/api/baselines/{asset_id}`](../../api/src/nimstead/app.py#L1514) | Session or read-only API token | Return the Windows baseline evaluation for an organisation-owned host. |
| `GET` | [`/api/coverage`](../../api/src/nimstead/app.py#L1669) | Session or read-only API token | Return assessed/inventory_only mapping counts and at most 200 unmatched groups. |
| `GET` | [`/api/directory/unmanaged`](../../api/src/nimstead/app.py#L1353) | Session or read-only API token | Return recent stored directory observations without an enrolled short-name match. |
| `POST` | [`/api/enroll-tokens`](../../api/src/nimstead/app.py#L942) | Admin browser session | Return token/id/expires once for a new enrolment credential, with HTTP 201. |
| `GET` | [`/api/enroll-tokens`](../../api/src/nimstead/app.py#L958) | Session or read-only API token | Return id/created/expires/revoked/sandbox rows, newest created first. |
| `DELETE` | [`/api/enroll-tokens/{token_id}`](../../api/src/nimstead/app.py#L969) | Admin browser session | Mark one matching organisation enrolment token revoked and return 204. |
| `GET` | [`/api/evidence/ledger`](../../api/src/nimstead/app.py#L3318) | Session or read-only API token | Return problems, newest entries and matching total for the user's ledger. |
| `GET` | [`/api/evidence/pack`](../../api/src/nimstead/app.py#L3369) | Session or read-only API token | Return an application/zip evidence attachment for trailing days, default 90. |
| `GET` | [`/api/evidence/public-key`](../../api/src/nimstead/app.py#L3336) | No user-session dependency | Return pem, fingerprint_sha256 and verifier_sha256 without authentication. |
| `GET` | [`/api/evidence/report`](../../api/src/nimstead/app.py#L3354) | Session or read-only API token | Return current evidence data for trailing days, default 90 and range 1..730. |
| `GET` | [`/api/evidence/verify.py`](../../api/src/nimstead/app.py#L3346) | No user-session dependency | Return current offline verifier source as text/x-python, without authentication. |
| `GET` | [`/api/findings`](../../api/src/nimstead/app.py#L2087) | Session or read-only API token | Return an array of organisation findings matching the query filters. |
| `GET` | [`/api/findings.csv`](../../api/src/nimstead/app.py#L2147) | Session or read-only API token | Stream all matching findings as CSV, escaping spreadsheet formula prefixes. |
| `POST` | [`/api/findings/accept`](../../api/src/nimstead/app.py#L2324) | Admin browser session | Accept currently open findings for body.vuln_id in the admin's organisation. |
| `POST` | [`/api/findings/accept-many`](../../api/src/nimstead/app.py#L2342) | Admin browser session | Accept the admin's open findings among body.ids, with reason and expiry days. |
| `GET` | [`/api/findings/count`](../../api/src/nimstead/app.py#L2104) | Session or read-only API token | Return {total: integer} for the caller's findings matching query filters f. |
| `GET` | [`/api/findings/groups`](../../api/src/nimstead/app.py#L2116) | Session or read-only API token | Return up to 500 grouped finding rows for the caller's organisation. |
| `GET` | [`/api/findings/{finding_id}`](../../api/src/nimstead/app.py#L2219) | Session or read-only API token | Return an owned finding with full detail, package context, and its remediation deadline. |
| `POST` | [`/api/findings/{finding_id}/accept`](../../api/src/nimstead/app.py#L2292) | Admin browser session | Record time-limited risk acceptance with a reason and return the updated finding. |
| `POST` | [`/api/findings/{finding_id}/revoke-acceptance`](../../api/src/nimstead/app.py#L2358) | Admin browser session | Reopen an accepted finding with a recorded reason and return its updated detail. |
| `GET` | [`/api/me`](../../api/src/nimstead/app.py#L815) | Session or read-only API token | Return email/org/admin/origin/mfa/recovery_codes_left for current_user. |
| `POST` | [`/api/me/mfa`](../../api/src/nimstead/app.py#L885) | Browser session | Return recovery_codes after staging and committing an authenticator setup. |
| `POST` | [`/api/me/mfa/setup`](../../api/src/nimstead/app.py#L869) | Browser session | Return setup/secret/uri for a browser-authenticated password user. |
| `POST` | [`/api/me/password`](../../api/src/nimstead/app.py#L843) | Browser session | Return 204 after a password-origin user's credential update. |
| `POST` | [`/api/me/sessions/revoke`](../../api/src/nimstead/app.py#L825) | Browser session | Delete this user's WebSession and ApiToken rows, commit, then clear cookie. |
| `GET` | [`/api/network/unmanaged`](../../api/src/nimstead/app.py#L1428) | Session or read-only API token | Return devices the organisation's agents saw in their own neighbour tables that are none of its agents. |
| `GET` | [`/api/notify/confirm`](../../api/src/nimstead/app.py#L2892) | Confirmation token | Return an email-alert consent form for query org/email/token, or HTML 404 on failed proof. |
| `POST` | [`/api/notify/confirm`](../../api/src/nimstead/app.py#L2905) | Confirmation token | Confirm query org/email/token and return HTML 200, or HTML 404 when invalid. |
| `GET` | [`/api/progress`](../../api/src/nimstead/app.py#L3269) | Session or read-only API token | Return open findings per day, findings opened and resolved per week, and each owner's numbers. |
| `GET` | [`/api/progress.csv`](../../api/src/nimstead/app.py#L3285) | Session or read-only API token | Return /api/progress as CSV: one row per day (table=days) or per owner (table=owners, no owner as an empty cell). |
| `POST` | [`/api/remediation/jobs`](../../api/src/nimstead/app.py#L2412) | Admin browser session | Plan a package fix on an owned asset and return the job without executing it. |
| `GET` | [`/api/remediation/jobs`](../../api/src/nimstead/app.py#L2455) | Session or read-only API token | Return up to 500 recent jobs, optionally filtered by comma-separated status names. |
| `POST` | [`/api/remediation/jobs/batch`](../../api/src/nimstead/app.py#L2435) | Admin browser session | Return jobs/errors after one action is planned across 1..5000 requested assets. |
| `POST` | [`/api/remediation/jobs/{job_id}/approve`](../../api/src/nimstead/app.py#L2512) | Admin browser session | Approve a planned job and return its detail. |
| `POST` | [`/api/remediation/jobs/{job_id}/cancel`](../../api/src/nimstead/app.py#L2532) | Admin browser session | Cancel a job when its current state permits cancellation; return the updated job. |
| `GET` | [`/api/settings`](../../api/src/nimstead/app.py#L2558) | Session or read-only API token | Return organisation policy, deadlines, agent update status, and server release status. |
| `PATCH` | [`/api/settings`](../../api/src/nimstead/app.py#L2573) | Admin browser session | Update organisation policy, record the decision, and return current settings. |
| `GET` | [`/api/settings/notifications`](../../api/src/nimstead/app.py#L2825) | Admin browser session | Return webhook/email configuration, confirmation state, and recent notification outcomes. |
| `PUT` | [`/api/settings/notifications`](../../api/src/nimstead/app.py#L2836) | Admin browser session | Save notification settings and request confirmation for newly added email recipients. |
| `POST` | [`/api/settings/notifications/test`](../../api/src/nimstead/app.py#L3022) | Admin browser session | Queue a test notification to the saved destinations and return queued=true with HTTP 202. |
| `GET` | [`/api/settings/sso`](../../api/src/nimstead/app.py#L2755) | Admin browser session | Return saved SSO fields and proof instructions for an admin browser user. |
| `PUT` | [`/api/settings/sso`](../../api/src/nimstead/app.py#L2763) | Admin browser session | Replace saved SSO configuration and return sso_json after commit. |
| `POST` | [`/api/settings/sso/verify`](../../api/src/nimstead/app.py#L2734) | Admin browser session | Check only unverified, unclaimed saved domains and return sso_json. |
| `GET` | [`/api/settings/tickets`](../../api/src/nimstead/app.py#L3079) | Admin browser session | Return the org's tracker settings (never the token: token_set says whether one is saved), the last sync, open |
| `PUT` | [`/api/settings/tickets`](../../api/src/nimstead/app.py#L3087) | Admin browser session | Save the tracker settings (DECISIONS 150-153) and return them as GET does. |
| `GET` | [`/api/settings/tickets/preview`](../../api/src/nimstead/app.py#L3183) | Admin browser session | What a sync would do now, with no call to the tracker: the tickets it would open (project, title, priority), |
| `POST` | [`/api/settings/tickets/sync`](../../api/src/nimstead/app.py#L3194) | Admin browser session | Start a sync now, after the response (it can take minutes on a slow tracker); the result appears as last_sync. |
| `POST` | [`/api/settings/tickets/test`](../../api/src/nimstead/app.py#L3166) | Admin browser session | Sign in to the saved tracker and look up every project tickets can go to; return {ok, message} in words. Writes |
| `GET` | [`/api/summary`](../../api/src/nimstead/app.py#L3476) | Session or read-only API token | Return asset/priority counts, up to ten actions and twenty attention jobs. |
| `POST` | [`/api/targets`](../../api/src/nimstead/app.py#L1854) | Admin browser session | Create an external target for a public DNS hostname and return its asset record. |
| `POST` | [`/api/targets/{target_id}/scan`](../../api/src/nimstead/app.py#L1918) | Admin browser session | Recheck ownership, scan the external target, and return its findings result. |
| `POST` | [`/api/targets/{target_id}/verify`](../../api/src/nimstead/app.py#L1883) | Admin browser session | Verify DNS and address ownership for an external target and return its asset record. |
| `POST` | [`/api/tokens`](../../api/src/nimstead/app.py#L1093) | Admin browser session | Return token/id/name/expires once for a read-only credential, with HTTP 201. |
| `GET` | [`/api/tokens`](../../api/src/nimstead/app.py#L1115) | Admin browser session | Return organisation token metadata/creator email, newest created first. |
| `DELETE` | [`/api/tokens/{token_id}`](../../api/src/nimstead/app.py#L1127) | Admin browser session | Delete one matching organisation API-token hash prefix and return 204. |
| `GET` | [`/api/users`](../../api/src/nimstead/app.py#L1008) | Admin browser session | Return organisation user_json records sorted by email, without pagination. |
| `POST` | [`/api/users/invite`](../../api/src/nimstead/app.py#L1061) | Admin browser session | Return 202 status=invited/email after an invitation request. |
| `PATCH` | [`/api/users/{user_id}`](../../api/src/nimstead/app.py#L1019) | Admin browser session | Set a member's admin flag and return user_json, preserving one admin. |
| `DELETE` | [`/api/users/{user_id}`](../../api/src/nimstead/app.py#L1040) | Admin browser session | Delete a member and their sessions/API tokens, append evidence and return 204. |
| `GET` | [`/api/windows-updates`](../../api/src/nimstead/app.py#L2480) | Session or read-only API token | Return Windows update groups across this organisation without the per-host detail lists. |
| `GET` | [`/api/windows-updates/{kb}`](../../api/src/nimstead/app.py#L2491) | Session or read-only API token | Return host-level detail for a Windows KB and exact product query. |
| `GET` | [`/install.ps1`](../../api/src/nimstead/app.py#L479) | No user-session dependency | Return the PowerShell installer with this server's origin and channel (installer()). No authentication is required. |
| `GET` | [`/install.sh`](../../api/src/nimstead/app.py#L474) | No user-session dependency | Return the Linux installer with this server's origin and channel (installer()). No authentication is required. |

The schema contains 94 operations and 129 schema definitions.

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
