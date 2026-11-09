# HTTP API reference

The server uses FastAPI. Its schema is available at `/api/openapi.json`. Set `NIMSTEAD_API_DOCS=1` in the server environment to enable Swagger UI at `/api/docs`, then restart the app. Swagger UI loads scripts from a CDN; it is disabled by default.

The live schema describes typed request parameters and request models. Many routes return dictionaries without response models, so their schema does not fully describe response fields. Use the route implementation and its tests when a response schema is empty.

The [endpoint catalog](api-endpoints.md) lists every operation. The [exported OpenAPI JSON](openapi.json) provides lookup without a running server. The export adds authentication metadata from route dependencies and explicit token-handling paths. Prefer your installed server’s schema when its version differs.

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
| `/api/agent/*` | Enrolment, inventory, release manifests, jobs, and job reports |
| `/api/findings` | Filtered findings, with pagination |
| `/api/findings/count` | Total matching findings |
| `/api/findings/groups` | Findings grouped by vulnerability or package; at most 500 groups |
| `/api/findings.csv` | Stream findings as CSV |
| `/api/remediation/jobs` | List jobs and plan a package fix |
| `/api/evidence/*` | Ledger, reports, signed packs, public key, and verifier |
| `/api/health` | Unauthenticated deployment health check; excluded from OpenAPI |

Consult the live schema for the complete route list and each request model. Route definitions are in [app.py](../../api/src/nimstead/app.py).

## Finding pagination

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
| 413 | Request body exceeds 10 MiB |
| 422 | Request validation failed, or the SBOM is invalid; `detail` can be a validation array or a string |
| 429 | Rate limit reached; inspect `detail` for the affected operation |
| 503 | A required service is unavailable; health also returns this when the database or migration check fails |

Limits vary by operation. Environment-controlled quotas are in [Configuration](../configuration.md). Do not retry a refused write blindly; some batch operations commit successful items independently and return errors for the rest.

Related: [upload an SBOM](../how-to/upload-sbom.md), [verify evidence](../how-to/verify-evidence.md).

See [evidence responses and pack format](evidence-format.md) for ledger, report, ZIP, and metric fields.
