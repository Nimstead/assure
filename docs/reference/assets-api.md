# Asset and inventory API reference

This reference defines asset records, enrolment, inventory replacement and fleet summary responses. The [HTTP reference](http-api.md) defines shared authentication and errors.

## Operations

| Operation | Result and effects |
| --- | --- |
| GET /api/assets | Hostname-sorted array of all organisation asset kinds. Includes open finding counts and optional Windows application mapping counts |
| POST /api/assets | HTTP 201 application record with one-time upload_token. Commit asset/evidence |
| PATCH /api/assets/{asset_id} | Context update and rescan, then asset record. Counts/context differ from the list response |
| DELETE /api/assets/{asset_id} | HTTP 204. Delete asset, findings, installed packages, jobs and scan records. Preserve the ledger |
| POST /api/agent/enroll | HTTP 201 with new asset_id and one-time agent_key. Commit a new host asset |
| POST /api/agent/inventory | Replace eligible agent inventory and return open/resolved counts. Can commit before later job/background work |
| POST /api/assets/{asset_id}/sbom | Replace SBOM-origin inventory and return mapping/rescan counts |
| GET /api/coverage | Windows application mapping counts and at most 200 unmatched groups |
| GET /api/summary | Fleet counts, up to ten action groups and twenty attention jobs. Sweep/commit job timeouts first |

Asset reads accept user sessions or eligible read tokens. Asset creation, context updates and deletion require an admin browser session. Enrolment uses its body token. Inventory uses the host's bearer key. SBOM accepts its asset key or an admin session.

Missing or differently owned assets return 404 for session operations. Asset-count quota refusals return 403. Count checks are not concurrency-safe reservations. Database, evidence, mapper and release-cache errors can propagate after earlier effects.

## Common asset fields

| Field | Value |
| --- | --- |
| id | Asset identifier |
| hostname | Hostname, application name or external DNS hostname |
| os_name, ecosystem | Stored text, normally empty for application/external assets |
| kind | host, application or external |
| criticality | low, medium, high or critical |
| internet_facing, directory_source, sandbox | Stored Boolean context flags |
| ring | Canary ring 0 or broad ring 1 |
| health_units | Configured service-name list |
| first_seen, last_seen | Stored UTC date-time strings |
| open_by_priority | Priority-to-count map supplied by the response caller |
| apps | Optional assessed/inventory_only integer mapping counts |

apps appears only when the serializer receives a truthy coverage object. List responses populate it for assets with stored WinApp rows. It describes mapping capability rather than advisory availability or completed checks.

Host rows add:

| Field | Value |
| --- | --- |
| agent_version | Last reported agent version |
| agent_outdated | Reported version differs from the process-cached served version |
| agent_update | current, off, reinstall, paused, failed or updating classification |
| agent_update_error | Last reported text or null |
| not_reporting | last_seen precedes the configured silent interval |
| facts | Selected stored facts, possibly from an earlier report |
| maintenance_window | Asset window dictionary or null to inherit the organisation window |

A version mismatch does not prove that the host is older. Update classification does not prove a newer eligible release exists. The retained fact names are os_unmatched, pending_reboot, wsus, wufb_quality_deferral_days, last_update_success, domain_role, edition_id and esu.

External rows add verified, verified_at, txt_name, txt_value and proof_path. verified records whether proof succeeded before. Scans recheck current proof. See [external scan contracts](external-scans.md).

## Creation, update and deletion

Application creation accepts name of 1–255 characters, criticality and internet_facing. It does not deduplicate names. The response adds upload_token, which permits only that asset's SBOM uploads. Storage retains its hash. Response loss can leave the asset created without the caller receiving the token.

A context patch accepts criticality, internet_facing, directory_source, ring, health_units and maintenance_window. Null values are omitted. health_units accepts at most twenty valid service names. An empty list clears it. An empty window stores null and inherits organisation policy.

Even an empty patch appends context evidence and rescans. The response supplies empty open_by_priority and omits apps. It does not mean the asset has no findings. Host update classification uses the serializer's default paused=false, so it can differ from the list response.

A rescan can commit before response serialization reads distribution state. A response error therefore does not establish that the patch failed to persist. Deletion commits rows and evidence. It does not uninstall a host agent or stop an already dispatched process.

## Agent enrolment

| Input | Constraint |
| --- | --- |
| token | Required text, at most 200 characters |
| hostname | Required text, 1–255 characters |
| os_name | Optional text, default empty, at most 255 characters |
| ecosystem | Optional text, default empty, at most 100 characters |

Each accepted call creates another host asset. No hostname deduplication or independent host attestation occurs. The asset inherits the enrolment token's sandbox flag. Token expiry/revocation and rate/asset quotas apply. Token refusal returns 403 and rate refusal returns 429.

The response has exactly asset_id and agent_key. A later local save or request failure does not undo enrolment. Revocation of the enrolment token does not independently revoke an already issued asset key.

## Agent inventory

| Field | Constraint and default |
| --- | --- |
| packages | Required list, at most 50,000 package objects |
| Package ecosystem/name/version | Required strings, at most 100/255/255 characters. Empty strings are accepted |
| Package source/source_version | Optional strings or null, at most 255 characters |
| os_name/ecosystem | Default empty, at most 255/100 characters. Empty input retains stored text |
| agent_version | Default empty, at most 50 characters |
| auto_update | Boolean or null, default null |
| update_error | Text up to 500 characters or null |
| facts | Dictionary or null. Structural limits below |
| collection | Dictionary or null. [Collection validation](inventory-format.md#collection-document) applies |

The endpoint enforces the per-host interval and organisation attempt rate. The organisation rate check commits its attempt record before subsequent processing. A refused or later failed attempt can consume quota. The API sets last_inventory_at, last_seen and reported update fields before rescan.

Invalid collection metadata becomes null. Omitted collection metadata also clears the previous document. Omitted/null facts retain older facts. A structurally invalid facts dictionary retains older facts. When valid collection metadata exists, that refusal adds a failed host_facts source.

### Fact structure limits

| Item | Limit |
| --- | --- |
| Root | At most 64 entries, key lengths at most 64 characters |
| Every dictionary | At most 200 entries, string keys at most 100 characters, accepted only below depth 3 |
| Every list | At most 500 entries, accepted only below depth 4 |
| String values | At most 500 characters |
| Scalar values | Null, Boolean, integer or float |
| Complete facts JSON | At most 64,000 characters in default json.dumps output |

Depth starts at zero for the root dictionary. These checks validate structure rather than each fact's meaning. The JSON limit counts characters in the serialized representation, not request bytes.

### Package replacement and findings

A declared package_db source prevents replacement when its state is not ok or its count is zero. The server then retains all prior agent-origin rows. It does not merge the new subset. Without that declaration, an empty package list can replace prior rows.

SBOM-origin rows remain. Facts, OS text and collection state can change even when package rows remain. A report can therefore combine new metadata with older packages or facts.

The endpoint rescans findings. When replacement occurs, it also verifies jobs against the resulting stored state. It invokes automatic planning and commits before background engine-report storage. Background report errors are logged separately. Earlier rescan persistence can survive later verification/planning errors.

The response has open and resolved integer counts. open counts currently matched identities, including accepted findings that still match. resolved counts previously open/accepted findings newly resolved in that rescan. These are not Findings pagination totals or proof of complete collection.

## SBOM authentication and effects

The endpoint reads the streamed body before authentication, with a 10 MiB cap. An exact Bearer header takes precedence over a browser session. A wrong key therefore fails even when the request also has a valid session.

The key must match the selected asset. Without that header, an admin session must own the asset. The parser runs before replacement. A valid empty document clears SBOM rows, while agent-origin rows remain.

SBOM upload updates last_seen for any asset kind. It records a raw-byte digest and parser counts in the ledger. It rescans with inventory_received=false. This path does not perform the agent endpoint's job verification and automatic planning sequence.

See the [SBOM input reference](sbom.md) for formats, parser limits, response counts and errors.

## Fleet summary

| Field | Value |
| --- | --- |
| assets | Count of all organisation asset kinds |
| hosts_not_reporting | Host last_seen values older than the silent interval |
| agents_need_attention | Hosts classified failed, off or reinstall |
| open_by_priority | Counts of status=open findings by priority |
| top_actions | Up to ten action groups below |
| attention | Up to twenty newest failed, rolled_back, rollback_failed, not_fixed or aborted jobs in [public job format](remediation-jobs.md#public-job-fields) |

Action groups use open findings with a fixed version or a supported configuration fix. Ranking uses KEV first, maximum score second and distinct vulnerability count third. Ties have no explicit stable ordering.

| Action field | Value |
| --- | --- |
| ecosystem, package | Group identity |
| fixed_version | Highest stored fix under the ecosystem comparator, otherwise lexical ordering, or null |
| hosts, asset_ids | Sorted distinct hostnames and asset IDs |
| busy_asset_ids | Sorted asset IDs with selected active jobs |
| job | Newest selected active job's id/status, or null |
| last_attempt | Newest selected finished attempt when its status needs attention. id/status/error, or null |
| vulns | Sorted distinct vulnerability identifiers |
| kev, max_score | Group KEV flag and maximum stored score |
| summary | One selected finding summary for configuration groups, otherwise null |
| fix, plannable, person_only, forward_only | [Fix-path classification](remediation-jobs.md#python-helper-ownership) |

Each action inspects at most fifty newest matching jobs. Older active or failed attempts can be absent from its hints. The displayed highest fix is a stored-data recommendation, not proof that one upgrade resolves every grouped issue.

GET summary first sweeps job timeouts and commits. It does not collect fresh host inventory. Queries can observe different moments, and comparator/distribution/storage failures can follow the sweep commit.

## Related

- [HTTP API overview](http-api.md)
- [Inventory metadata](inventory-format.md)
- [Grouped scan report](scan-report.md)
- [Fleet attack paths](fleet-paths.md)
- [Change asset context](../how-to/change-asset-context.md)
