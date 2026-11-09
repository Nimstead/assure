# SBOM input reference

Assure accepts raw JSON at `POST /api/assets/{asset_id}/sbom`. The body is the document itself, without a multipart wrapper.

| Property | Accepted value or limit |
| --- | --- |
| CycloneDX | `bomFormat: CycloneDX`, `specVersion: 1.4`, `1.5`, or `1.6` |
| SPDX | `spdxVersion: SPDX-2.2` or `SPDX-2.3` |
| Request size | 10 MiB, including streamed requests |
| Component count | At most 50,000, before deduplication |
| CycloneDX nesting | At most 64 component levels; top-level components are level 1 |
| Package identity | Supported package URL with a version |
| Unsupported formats | XML and SPDX tag-value are rejected |

The parser checks supported format/version markers and component/container limits. It does not validate every field against the complete upstream SBOM schemas.

## Package URL mapping

| purl type | Advisory ecosystem | Name handling |
| --- | --- | --- |
| `pypi` | PyPI | Lowercase; runs of `.`, `_`, and `-` become `-` |
| `npm` | npm | Preserve scope and package name |
| `maven` | Maven | Exactly two path parts become `group:artifact` |
| `nuget` | NuGet | Preserve package name |
| `gem` | RubyGems | Preserve package name |
| `golang` | Go | Preserve module path; remove the version's leading `v` |
| `cargo` | crates.io | Preserve package name |
| `composer` | Packagist | Preserve vendor/package path |
| `hex` | Hex | Accept one path part; organisation packages are skipped |
| `pub` | Pub | Preserve package name |

SPDX uses the first `externalRefs` entry whose `referenceType` is `purl`. If that URL has no version, `versionInfo` supplies it. CycloneDX uses each component's `purl`, including nested components. The CycloneDX display `version` does not replace a missing purl version.

## Result fields

| Field | Meaning |
| --- | --- |
| `components` | Components visited, including skipped entries and duplicates |
| `mapped` | Components with supported, versioned package URLs, including duplicates |
| `unique_packages` | Distinct `(ecosystem, name, version)` triples |
| `skipped.no_purl` | Missing, empty, or non-string package URL |
| `skipped.unsupported_or_invalid_purl` | Unsupported type, malformed identity, or missing version |

The HTTP response also includes two integer scan results:

| Field | Meaning |
| --- | --- |
| `open` | Currently matched finding identities in this rescan, including accepted findings that still match |
| `resolved` | Existing open or accepted findings newly marked resolved by this rescan |

These counts are not pagination totals for the Findings screen. Available advisories and collection completeness affect the result.

## Replacement and errors

Each successful upload replaces all packages with origin `sbom` for that asset. Agent-collected packages remain. An empty valid document clears the SBOM inventory, so upload the complete inventory for each build.

Malformed documents return HTTP 422 with `detail` beginning `Invalid SBOM:`. Oversized requests return 413. A wrong asset token returns 401. A session belonging to another organisation cannot access the asset and returns 404. A read-only session cannot replace an SBOM.

Source: [sbom.py](../../api/src/nimstead/sbom.py) and [app.py](../../api/src/nimstead/app.py). Related: [upload from CI](../how-to/upload-sbom.md).
