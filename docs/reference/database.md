# Database model reference

The server uses SQLAlchemy models declared in [`db.py`](../../api/src/nimstead/db.py). Field annotations and `mapped_column()` declarations define storage types, defaults, nullability, indexes, and foreign keys. Application request validation and authorization are separate.

## Connection and session functions

| Interface | Contract |
| --- | --- |
| `now()` | Current UTC datetime without timezone metadata |
| `new_id()` | Random UUID4 as 32 lowercase hexadecimal characters |
| `make_engine(url=DB_URL)` | New SQLAlchemy engine. The caller owns disposal |
| `make_sessionmaker(url=DB_URL)` | New session factory with its own engine binding and `expire_on_commit=False` |

`DB_URL` reads `NIMSTEAD_DB` at module import, defaulting to `sqlite:///./nimstead.db`. Changing the environment later does not replace existing defaults or engine bindings.

SQLite engine creation immediately creates missing model tables and enables foreign keys on each connection. It does not migrate existing tables to new definitions. PostgreSQL normally connects lazily and requires Alembic migrations.

Callers close sessions, explicitly commit intended writes, and dispose owned engines. A plain session context closes the session without committing. Default autoflush can write pending changes before a query. Commit-capable domain helpers can also commit unrelated pending changes in the same session.

URL parsing, missing drivers, connection failures, SQL constraints, and schema errors propagate through SQLAlchemy or the database driver. Returned engines and factories do not convert those failures into application HTTP errors.

## Ownership and validation

Tenant ownership is direct through `org_id` or indirect through user/asset foreign keys. Queries do not gain automatic tenant filters from these models. Callers must scope reads and writes to the authorized organisation.

Mapped string columns are not workflow enums. Type annotations do not validate arbitrary constructor values. Defaults normally apply when SQLAlchemy inserts a row, rather than when a plain model object is constructed.

Dictionary/list fields use JSON storage. Assign a replacement value when a change must persist. Ordinary in-place nested changes are not tracked through a mutable JSON extension in these declarations.

The model does not make the evidence ledger immutable. The unique `(org_id, seq)` constraint prevents duplicate sequence positions. Hash verification detects inconsistent history, while trusted checkpoints provide a separate comparison.

## Models

| Model | Identity and role |
| --- | --- |
| `Base` | Declarative base. Dict/list annotations map to JSON |
| `Org` | Tenant policy, SSO, notifications, deadlines, and update settings |
| `User` | Globally unique email, organisation membership, authentication and role |
| `WebSession` | Hashed browser token linked to a user, with expiry and idle timestamp |
| `ApiToken` | Hashed read-only token linked to an organisation and creating user |
| `EnrollToken` | Hashed enrolment token with tenant, expiry, revocation, and sandbox assignment |
| `Asset` | Tenant-owned host, application, or external target with collection and policy state |
| `InstalledPackage` | Observed asset package, source version, and agent/SBOM origin |
| `Advisory` | Composite ID/ecosystem/package key for advisory and auxiliary feed records |
| `DirectoryComputer` | Composite organisation/domain/name key for directory-discovered computers |
| `Neighbour` | Composite asset/IP/MAC key for one row of a host's own neighbour table, with first and last seen (deleted 30 days after last seen) |
| `Kev` | CVE-keyed known-exploitation metadata |
| `Epss` | CVE-keyed probability and percentile |
| `Cvss` | CVE-keyed fallback impact score/vector |
| `Finding` | Unique asset/ecosystem/package/vulnerability identity, with workflow and risk state |
| `ScanRecord` | Stored engine inventory/report and reproducibility identifiers |
| `LedgerEntry` | Per-organisation sequence, canonical event data, previous hash and event hash |
| `RemediationJob` | Persisted plan, approval/execution state, steps, result versions, and errors |
| `AuthFailure` | Time-stamped authentication or quota attempt by key |
| `PendingSignup` | Hashed signup, invite, or reset link. No requester-chosen password is stored here |
| `PendingLogin` | SSO state, expiry, and nonce/PKCE flow data |
| `Notification` | Delivery attempt, channel, result, retry state, and retained message |

Installed-package, neighbour, finding, scan-record, and remediation-job foreign keys request cascade deletion with their asset. Other relationships have their own declarations. Do not assume every organisation or user deletion cascades through all records.

## Related

- [Finding state and API](findings.md)
- [Evidence format](evidence-format.md)
- [Server deployment](../how-to/deploy-server.md)
- [Contributing](../../CONTRIBUTING.md)
