# SBOM input reference

Assure accepts raw JSON at `POST /api/assets/{asset_id}/sbom`. The body is the document itself, without a multipart wrapper.

| Property | Accepted value or limit |
| --- | --- |
| CycloneDX | `bomFormat: CycloneDX`, `specVersion: 1.4`, `1.5`, `1.6` or `1.7` |
| SPDX | `spdxVersion: SPDX-2.2` or `SPDX-2.3` |
| Request size | 10 MiB, including streamed requests |
| Component count | At most 50,000, before deduplication |
| CycloneDX nesting | At most 64 component levels; top-level components are level 1 |
| Package identity | Supported package URL with a version |
| Unsupported formats | XML and SPDX tag-value are rejected |

The parser checks supported format/version markers and component/container limits. It does not validate every field against the complete upstream SBOM schemas.

Uploads require the asset's upload token or agent key, or an owning admin session. Authentication and quota checks precede body reads. The limit is 60 uploads per asset per hour, within the organisation inventory quota. A quota refusal returns HTTP 429. Invalid uploads also consume quota after authentication.

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

### Operating-system packages (container images)

`deb`, `apk` and `rpm` package URLs map to the distribution release their `distro` qualifier names, only on an application asset. On a host's own upload they are skipped as `os_package_on_host`: its agent reads them from the machine.

| purl type | Distributions (`distro` qualifier) | Advisory ecosystem |
| --- | --- | --- |
| `deb` | `debian-12.8` | `Debian:12` |
| `deb` | `ubuntu-24.04` | `Ubuntu:24.04` |
| `apk` | `alpine-3.18.12` (Syft), `3.18.12` (Trivy, namespace `alpine`) | `Alpine:v3.18` |
| `rpm` | `almalinux-9.9` (Syft), `alma-9.9` (Trivy) | `AlmaLinux:9` |
| `rpm` | `rocky-9.3` | `Rocky Linux:9` |
| `rpm` | `opensuse-leap-15.6`, `opensuse.leap-15.6` | `openSUSE:Leap 15.6` |
| `rpm` | `sles-15.5` | `SUSE:Linux Enterprise Server 15 SP5` |

Distribution advisories name the source package, so Assure takes it, in this order, from Syft's `upstream` qualifier (`util-linux@2.36.1-8+deb11u2`, `openssl`, or an rpm's source file name), Trivy's `aquasecurity:trivy:SrcName`, `SrcVersion`, `SrcRelease` and `SrcEpoch` properties, or SPDX `sourceInfo` (`built package from: openssl 1.1.1w-0+deb11u8`). Without any of these, the binary's own name is used. An rpm version always carries its epoch (`0:1.2-3`); a dpkg version carries it only when it isn't zero, as the agent writes them. rpm's `gpg-pubkey` entries are signing keys, not software, and are skipped as `not_a_package`.

One SBOM is one image: the release with the most OS packages is kept, and the rest are skipped as `other_distro`. An application whose SBOM names a release is judged as that release's packages, graded unverified, including its end of support.

## Result fields

| Field | Meaning |
| --- | --- |
| `components` | Components visited, including skipped entries and duplicates |
| `mapped` | Components with supported, versioned package URLs, including duplicates |
| `unique_packages` | Distinct `(ecosystem, name, version, source, source_version)` rows |
| `distro` | The distribution release of the OS packages kept, such as `Debian:12`, or null |
| `skipped.no_purl` | Missing, empty, or non-string package URL |
| `skipped.unsupported_or_invalid_purl` | Unsupported type, malformed identity, or missing version |
| `skipped.no_distro` | An OS package URL with no `distro` qualifier |
| `skipped.unsupported_distro` | An OS package of a release no advisory feed here covers |
| `skipped.other_distro` | An OS package of a second release |
| `skipped.os_package_on_host` | An OS package in a host's own upload; its agent reads them, so they aren't reported as unjudged |
| `skipped.not_a_package` | rpm's `gpg-pubkey` entries; not reported as unjudged |

Reasons that never occurred are absent, except the first two, which are always present.

The HTTP response also includes two integer scan results:

| Field | Meaning |
| --- | --- |
| `open` | Currently matched finding identities in this rescan, including accepted findings that still match |
| `resolved` | Existing open or accepted findings newly marked resolved by this rescan |

These counts are not pagination totals for the Findings screen. Available advisories and collection completeness affect the result.

For credential precedence, last_seen updates and job-verification differences, see [SBOM authentication and effects](assets-api.md#sbom-authentication-and-effects).

## Replacement and errors

Each successful upload replaces all packages with origin `sbom` for that asset. Agent-collected packages remain. An empty valid document clears the SBOM inventory, so upload the complete inventory for each build.

Malformed documents return HTTP 422 with `detail` beginning `Invalid SBOM:`. Oversized requests return 413. A wrong asset token returns 401. A session belonging to another organisation cannot access the asset and returns 404. A read-only session cannot replace an SBOM.

Source: [sbom.py](../../api/src/nimstead/sbom.py) and [app.py](../../api/src/nimstead/app.py). Related: [upload from CI](../how-to/upload-sbom.md).
