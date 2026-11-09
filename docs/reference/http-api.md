# HTTP API reference

The [remediation reference](remediation-jobs.md) defines job, agent-plan, Windows update, and policy response fields.

The server uses FastAPI. Its schema is available at `/api/openapi.json`. Set `NIMSTEAD_API_DOCS=1` in the server environment to enable Swagger UI at `/api/docs`, then restart the app. Swagger UI loads scripts from a CDN; it is disabled by default.

The live schema describes typed request parameters and request models. Many routes return dictionaries without response models, so their schema does not fully describe response fields. Use the route implementation and its tests when a response schema is empty.

The [endpoint catalog](api-endpoints.md) lists every operation. The [exported OpenAPI JSON](openapi.json) provides lookup without a running server. The export adds authentication metadata, JSON response definitions and the actual HTML, CSV, ZIP and source-file media types. Its SBOM object schema does not replace the full upstream format schemas. Prefer your installed server’s schema when its version differs.

The [asset and inventory reference](assets-api.md) defines asset variants, replacement behavior, enrolment results and fleet summary fields.

For response branches, account recovery and token/SSO effects, see [authentication and account API](authentication.md).

## Credentials

| Credential | Where it is accepted | Limits |
| --- | --- | --- |
| `nimstead_session` cookie | Browser routes | Organisation membership and role apply; admin changes require two-step sign-in for password users outside open-signup development mode |
| `Bearer nmt_…` | Routes using the current-user dependency, for GET and HEAD | Read-only; acts as the admin who created it; rejected by admin-only and person-only routes |
| `nme_…` enrolment token | JSON body of `POST /api/agent/enroll` | Creates asset credentials; subject to expiry, revocation, and enrolment quotas |
| `Bearer nma_…` | Agent routes; its own asset's SBOM upload | Bound to one asset |
| `Bearer nmu_…` | Its own asset's SBOM upload | Does not authorise inventory reports, job polling, or general API reads |

Sessions expire after 14 days or 12 hours of inactivity. Activity timestamps update at bounded intervals. Cross-origin writes are refused unless their origin matches the request host or `NIMSTEAD_ALLOWED_ORIGINS`.

## Main resources

| Resource | Purpose |
| --- | --- |
| `/api/auth/*` | Signup, password login, two-step sign-in, password recovery, and SSO |
| `/api/me` | Current signed-in identity |
| `/api/assets` | List assets; create application assets |
| `/api/assets/{asset_id}/sbom` | Replace an asset's SBOM inventory |
| `/api/assets/{asset_id}/scan-report` | [Grouped report](scan-report.md) for stored inventory. Can create a retained scan record |
| `/api/attack-paths` | [Fleet path correlation](fleet-paths.md) from stored reports and current facts |
| `/api/targets`, `/api/targets/{target_id}/*` | [External target proof and scans](external-scans.md) |
| `/api/agent/*` | Enrolment, inventory, release manifests, jobs, and job reports |
| `/api/findings` | Filtered findings, with pagination |
| `/api/findings/count` | Total matching findings |
| `/api/findings/groups` | Findings grouped by vulnerability or package; at most 500 groups |
| `/api/findings.csv` | Stream findings as CSV |
| `/api/baselines`, `/api/baselines/{asset_id}`, `/api/baselines.csv` | [Stored Windows baseline results](windows-checks.md#baseline-results-and-api) |
| `/api/settings/notifications*`, `/api/notify/confirm` | [Alert settings, test requests, and email consent](notifications.md) |
| `/api/remediation/jobs` | List jobs and plan a package fix |
| `/api/evidence/*` | Ledger, reports, signed packs, public key, and verifier |
| `/api/health` | Unauthenticated deployment health check; excluded from OpenAPI |

Consult the live schema for the complete route list and each request model. Route definitions are in [app.py](../../api/src/nimstead/app.py).

## Finding pagination

The [finding reference](findings.md) defines every row/group field, filters, CSV columns, acceptance operations, and state transitions.

`GET /api/findings` returns an array. `limit` defaults to 500 and ranges from 1 to 5,000. `offset` starts at 0. Use the same filters with `/api/findings/count` to get `total`.

`sort` accepts `score`, `package`, `host`, `vuln`, or `newest`. `view=full` is the default; `view=list` returns fewer fields and one reason per finding. Changes to findings between requests can change pagination results.

The grouped endpoint does not apply the `overdue` filter. Do not use its results as an overdue count.

## Errors and limits

| HTTP status | Meaning and response |
| --- | --- |
| 400 | Invalid request for the operation; inspect `detail` |
| 401 | Missing, invalid, or expired credential |
| 403 | Role, session type, two-step sign-in, or origin does not permit the operation |
| 404 | Resource unavailable to this caller; tenant ownership checks can return this status |
| 409 | Current state refuses the operation, including remediation planning conflicts |
| 413 | Declared body exceeds 10 MiB, or a consumed request stream crosses the limit |
| 422 | Request validation failed, or the SBOM is invalid; `detail` can be a validation array or a string |
| 429 | Rate limit reached; inspect `detail` for the affected operation |
| 503 | A required service is unavailable; health also returns this when the database or migration check fails |

Limits vary by operation. Environment-controlled quotas are in [Configuration](../configuration.md). Do not retry a refused write blindly; some batch operations commit successful items independently and return errors for the rest.

Related: [upload an SBOM](../how-to/upload-sbom.md), [verify evidence](../how-to/verify-evidence.md).

See [evidence responses and pack format](evidence-format.md) for ledger, report, ZIP, and metric fields.


## Application and deployment helpers

create_app captures allowed origins, CSP, docs enablement and static-directory availability at construction. Some constants are read at module import. Changing an index file does not refresh its captured script hashes until the app is reconstructed.

The body middleware rejects excessive Content-Length before a handler runs. Otherwise it counts bytes only when the handler reads them. It does not independently drain an unread stream. Invalid Content-Length text can raise an error.

The shared write-origin check applies when Origin is present. A refusal can occur before normal response-header decoration. An absent Origin does not independently refuse the write. Authentication remains a separate check.

The API health route is public and excluded from OpenAPI:

| Condition | Status and fields |
| --- | --- |
| Database query succeeds, migrations=head or unmanaged | HTTP 200: status=ok, version, db=ok, migrations |
| Database query succeeds, migrations=behind | HTTP 503: status=error, version, db=ok, migrations |
| Query/migration helper raises | HTTP 503: status=error, version, db=unavailable. migrations is absent |

Unmanaged means no alembic_version table, rather than a full schema inspection. Session creation can fail before the handler's exception catch. Health does not establish every provider, feed or background task is available.

Static responses marked successful receive one-year immutable caching from HashedAssets. The helper does not itself require hashed filenames. The SPA fallback uses no-cache for its index. Unknown api/ paths return 404. Other missing paths can return the index.

Public security.txt responses contain the configured optional contact before Nimstead's contact and a fresh expiry date. The route does not validate the configured contact value. Installer/source/runtime behavior is in the [distribution reference](platform-updates.md#agent-distribution).

## Schema validation notes

The export declares shared authentication, write-origin and consumed-body errors where applicable. These descriptions do not enumerate every storage, backend or malformed-state failure.

SSO start, SSO callback and successful password-form confirmation use 303 redirects. They have no 2xx success response. Redocly's generic 2xx recommendation warns on these operations. Adding a fictitious 200 response would misdescribe their implementation.

Redocly also reports EvidencePackDocument as unused because it is referenced through a ZIP-member vendor extension. The response body is ZIP bytes. The extension identifies the pack.json member schema.

Event-specific ledger data and map keys remain extensible JSON. Their interpretation is in the linked evidence, report, collection and account references. The schema does not certify observations or enforce host-side behavior.
