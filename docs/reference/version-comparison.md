# Version comparison reference

The package matcher selects a comparator by ecosystem. Comparator support defines ordering, not advisory coverage or proof that a host is unaffected.

## Comparator selection

`comparator_for(ecosystem)` returns a two-string comparison callable or `None`. The case-sensitive prefix before the first colon selects the function. For example, `Ubuntu:22.04` uses the `Ubuntu` comparator.

| Ecosystem prefix | Function | Ordering or accepted form |
| --- | --- | --- |
| `Debian`, `Ubuntu` | `dpkg_cmp` | Epoch, upstream version, and revision |
| `Rocky Linux`, `AlmaLinux`, `Red Hat`, `SUSE`, `openSUSE`, `Mageia` | `rpm_cmp` | Epoch/version/release; release comparison is omitted if either side lacks a release |
| `Alpine` | `apk_cmp` | Numeric components, optional letter, underscore suffixes, and optional `-rN` revision |
| `Windows`, `Microsoft` | `windows_cmp` | Dotted numeric builds, padded with zero components for comparison |
| `WinApp` | `appver_cmp` | Dotted numeric versions, optional lowercase `v`, and optional parenthesised build suffix |
| `PyPI` | `pep440_cmp` | `packaging.version.Version` ordering |
| `npm`, `Go`, `crates.io`, `Hex`, `Pub` | `semver_cmp` | Optional lowercase `v`, omitted minor/patch components, prerelease ordering; build metadata ignored |
| `Maven` | `maven_cmp` | Case-insensitive qualifiers, aliases, and nested numeric/qualifier segments |
| `NuGet` | `nuget_cmp` | One to four numeric components and case-insensitive prerelease labels |
| `RubyGems` | `gem_cmp` | Numeric and prerelease segments |
| `Packagist` | `composer_cmp` | Composer-normalised PHP ordering; build metadata ignored; branch forms are refused |

Comparators return `-1`, `0`, or `1` for older, equivalent, or newer respectively. `sort_key(cmp)` adapts a comparator for sorting. Errors from `cmp` propagate during comparisons.

## Validation and limits

Debian and RPM ordering functions are permissive. They do not validate all package-version syntax. Other comparators can raise `ValueError` for forms they cannot parse. Callers must not treat comparator success as format validation.

The Alpine implementation treats dotted numeric components as integers. It does not implement fractional ordering for leading-zero components.

The Pub implementation uses shared SemVer ordering and treats versions differing only in build metadata as equal.

An unknown ecosystem prefix returns `None`. It is not equivalent to a comparison result of zero.

## Package matching

`match_package(pkg, ecosystem, records)` accepts a `Package` and OSV-shaped advisory dictionaries. `Package.source`, when present, selects the distribution source-package identity. Otherwise the matcher uses `Package.name`.

The matcher requires the same package name and normalized ecosystem. `normalize_ecosystem` removes a final `LTS` component only for Ubuntu. Withdrawn records are skipped.

Supported range types are `ECOSYSTEM` and `SEMVER`. The matcher processes `introduced`, `fixed`, and `last_affected` events; it ignores `limit` events. `GIT` ranges are not evaluated. Explicit affected-version lists can also produce matches.

Results collapse advisory records under the lexically first uppercase `CVE-` identifier among the record ID, aliases, and upstream IDs. Without a CVE identifier, the original record ID is used.

`Match.fixed` is the lowest candidate above the installed version from contributing matched ranges. Each advisory uses its first affected supported range. It is `None` if no such candidate exists.

Version-comparison `ValueError` is logged and skipped. Malformed advisory structures can raise other errors. This function does not validate an entire OSV schema. An empty match list alone is not evidence of safety.

Use [scan outcomes](scan-outcomes.md) for the evaluator's conclusions and [detection confidence](../explanation/detection-confidence.md) for interpretation.

Source: [versions.py](../../api/src/nimstead/versions.py), [match.py](../../api/src/nimstead/match.py), and [engine evaluator](../../api/src/nimstead/engine/evaluate.py).
