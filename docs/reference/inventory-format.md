# Inventory and collection metadata

The engine reads package inventory and collection status separately. Package rows describe observations. Collection metadata states whether each source completed.

This reference covers the internal `Inventory` representation and collection document. HTTP request validation also applies at the [agent inventory endpoint](api-endpoints.md).

## Inventory fields

| Field | Internal value and default |
| --- | --- |
| `hostname`, `os_name`, `ecosystem`, `agent_version` | Strings, default empty |
| `collected_at` | Collection timestamp or `None`, default `None` |
| `facts` | Fact dictionary, default empty |
| `packages` | Package dictionaries, default empty |
| `document` | Collection metadata dictionary or `None`, default `None`. Serialized as `collection` |
| `received` | Whether inventory arrived, default true. Not serialized by `to_doc()` |
| `kind` | `host` by default, or `application` |
| `sbom` | Upload metadata or `None`. Metadata can include `received`, `components`, `mapped`, and `skipped` |

Direct dataclass construction does not validate nested values. `Inventory.from_doc()` reads agent input. It converts identity fields to strings, retains dictionary facts, and discards package entries without string names and versions.

The presence of the `packages` key sets `received`, even when the list is empty. Invalid collection metadata becomes `None`. The helper does not restore `kind` or `sbom`, so it is not a general inverse of `to_doc()`.

`Inventory.from_asset()` reads supplied database objects without a query. It preserves SBOM origins and sorts packages by ecosystem, name, version, source, and origin. Retained nested mappings remain shared with their source objects.

## Collection document

| Field | Validation |
| --- | --- |
| `v` | Equal to integer `1`. The current Python equality check also accepts `true` and `1.0` |
| `sources` | Dictionary with 1–16 entries |
| Other root keys | Accepted if the complete document passes JSON serialization and the length limit |

The default `json.dumps()` representation must contain at most 4000 characters. The checker measures the serialized string length. Nonserializable or circular root extras can raise an exception instead of returning false.

Source names match `[a-z_]{1,40}`. Each source entry accepts only these fields:

| Field | Validation and default |
| --- | --- |
| `state` | Required: `ok`, `partial`, `failed`, or `off` |
| `count` | Integer from 0 through 10,000,000, default 0. Boolean values are refused |
| `error` | String of at most 300 characters, or `null`. Default `null` |
| `code` | `access-denied` or `null`. Default `null` |
| `exit` | Optional integer from -1024 through 1024. Boolean values are refused |

The metadata checker does not validate package rows. When the inventory API drops invalid collection metadata, it retains valid package input.

## Derived source state

`Inventory.source(name)` returns `name`, `state`, `count`, `error`, `code`, and `reason`. These are derived values and can differ from the agent declaration.

| Condition | Derived result |
| --- | --- |
| Missing collection document | `not-reported`, reason `no-collection-document` |
| Missing source in a valid document | `not-reported`, reason `precondition-unknown` |
| Failed source with access-denied code | `failed`, reason `access-denied` |
| Other failed source | `failed`, reason `precondition-unknown` |
| Partial source | `partial`, reason `source-partial` |
| Disabled source | `off`, reason `policy-excluded` |
| OK `uninstall` or `package_db` source with zero count | `failed`, reason `empty-list` |
| Supported source declares more rows than inventory contains | `partial`, reason `source-partial` |

For the uninstall consistency check, the declared total includes the `user_hives` count. SBOM state comes from uploaded rows or metadata. It is `ok` when either exists, otherwise `not-reported` with reason `no-sbom`.

`source_count()` returns the declared count, or zero. It does not prove success. `worst()` selects the least complete named source: OK, partial, failed, then off/not-reported. Equal ranks preserve the first supplied name. No names raises `ValueError`.

## Install mapping

`installs()` maps curated Windows products or distribution packages. Language packages and SBOM components use `app_installs()` separately. Both helpers map observations without verifying collection success.

Linux rows group by source package and source version. Missing source values fall back to binary name and version. Distinct versions remain distinct installs. Kernel labels distinguish running, not-running, and unknown running state.

Application rows deduplicate by ecosystem, instance, and collection source. Agent locations distinguish separate installations. SBOM rows use their component name and version without a runtime-location claim.

Unrecognized Windows products remain inventory without an advisory comparison. Recognized products with unreadable versions can map to an install with `comparable=false`.

## Related

- [Scan report format](scan-report.md)
- [SBOM input](sbom.md)
- [Scan outcomes](scan-outcomes.md)
- Source: [`collection.py`](../../api/src/nimstead/engine/collection.py)
