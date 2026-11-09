# Windows application mapping reference

Third-party Windows application matching uses the curated `WinApp` catalogue. A product requires a supported identity and readable version. Other applications remain inventory without guessed advisory matches.

## Registry identity

| Interface | Contract |
| --- | --- |
| `names_product(name, publisher)` | Boolean identity match without a version check |
| `identify(name, publisher, version)` | `(product key, mapped version)` or `None` |

`name` is DisplayName, `publisher` is Publisher text or `None`, and `version` is DisplayVersion. The helpers strip surrounding whitespace. Missing publisher becomes empty text. Pattern matches are case-sensitive and cover the whole string.

`identify` uses the first matching product in catalogue order. Its version mapper can use text captured from the name. The mapped result must pass the application version parser. Mapper `ValueError` or `KeyError` returns `None` without another catalogue attempt. Other mapper/type errors propagate.

`names_product=True` does not prove a usable version. Neither helper performs I/O, queries installed software, or changes its inputs.

## Catalogue fields

[`PRODUCTS` in winapps.py](../../api/src/nimstead/winapps.py) is the authoritative ordered catalogue, including exact patterns and exceptions.

| `Product` field | Meaning |
| --- | --- |
| `key` | Advisory package key, normally `vendor:product` |
| `name` | Compiled DisplayName full-match pattern |
| `cpes` | Alternate NVD `vendor:product` identities. Empty tuple uses `key` |
| `publisher` | Optional compiled Publisher full-match pattern |
| `version` | Callable from name match and stripped version text to mapped version |
| `branch` | Restrict a start-less advisory range to the upper bound's major branch |
| `nvd_dashes` | Convert NVD version hyphens to registry-compatible dots |

The frozen dataclass does not validate construction. Catalogue entries can remove installer/build suffixes or select a version from DisplayName. The mapping deliberately excludes some ambiguous names and incompatible version conventions. Microsoft applications use the [separate mapper](platforms.md#windows-matching-inputs).

## NVD conversion

`advisories(cve)` accepts one NVD CVE dictionary. It returns `(product key, OSV-shaped record)` pairs. `vulnStatus` is not checked here. The feed storage helper excludes rejected records.

The converter reads immediate configuration nodes. It skips negated configurations/nodes and non-vulnerable application matches. It uses these filters:

| CPE/configuration value | Behavior |
| --- | --- |
| Application vendor/product | Must exist in the curated CPE mapping |
| Update field | Must be `*` or `-` |
| Target software | Must be `*`, `-`, or exact `windows` |
| Software edition | Exact `classic` is excluded |
| AND with OS constraints | At least one OS string must contain `:microsoft:windows` |
| AND with Apple hardware | Excluded |

These rules do not fully evaluate CPE Boolean logic or require every environment predicate. Nested child nodes are not recursively evaluated. Missing environment requirements do not establish a general Windows compatibility proof.

| Version input | Emitted events |
| --- | --- |
| Exact readable version | `introduced` and `last_affected` at that version |
| Wildcard with inclusive start and exclusive end | `introduced` then `fixed` |
| Wildcard with inclusive end | `introduced` then `last_affected` |
| Missing start | Start at `0`, or upper bound's major `.0` when `branch=True` |
| Exclusive start, absent end, or unreadable bound | No range |
| Version `-` | No range |

The application parser accepts dotted numeric forms with its optional prefix/build syntax. Pre-release labels outside that syntax are refused. If both end forms exist, the exclusive end takes precedence. Duplicate event lists are removed per product.

## CVE List v5 conversion

`advisories_v5(rec)` reads only `PUBLISHED` records. It combines CNA and ADP affected entries. Curated CPEs and exact lowercase vendor/product aliases select product keys.

If platforms exist, at least one string must match `windows|all|x64|x86|arm64`, case-insensitively. This is a substring regex search, not a platform allowlist or exact operating-system comparison.

Version entries require status `affected`. Supported `versionType` values are absent, `custom`, `semver`, and `dotted`. These names do not select different comparators. Readable bounds use the application numeric parser.

`lessThan` emits `fixed`. `lessThanOrEqual` emits `last_affected`. A missing, empty, `*`, or `0` lower bound becomes `0`. A lower bound numerically at or above the upper bound also resets to `0`. Branch products replace that zero with the upper bound's major `.0`. Without an upper bound, only a readable nonzero exact version produces events.

The converter does not interpret every CVE schema feature, including version-change lists. Malformed nested structures can raise field, type, or indexing errors. Neither converter mutates the supplied record or accesses storage/network services.

## Advisory result fields

| Field | NVD | CVE List v5 |
| --- | --- | --- |
| `id` | Source CVE ID | `<CVE>-v5` |
| `aliases` | Empty list | Original CVE ID |
| `modified` | `lastModified`, default empty | `dateUpdated`, default empty |
| `summary` | First exact English description, up to 500 characters | First CNA description whose language starts with `en`, up to 500 characters |
| `severity` | Optional first v3.1/v3.0 vector | Optional first CNA/ADP v3.1/v3.0 vector |
| `affected` | One package with ecosystem `WinApp`, selected key, and `ECOSYSTEM` ranges | Same structure |

The NVD vector must start with `CVSS:3`. The v5 converter copies its selected vector without that prefix check. These are internal OSV-shaped records, not a claim of complete upstream schema conversion. [Feed precedence](feed-sync.md#windows-application-precedence) determines which records remain stored.

## Historical rule evidence

Finding responses expose `rule_evidence` for WinApp findings. Other ecosystems return `null`.

| Label | Derivation |
| --- | --- |
| `proven` | A run reports its proof flag, or identifies different old/new versions for the product |
| `real name` | A run identifies the product without qualifying version-change evidence |
| `pattern` | No entry exists in the generated evidence mapping |

[`sandbox/winapps_evidence.py`](../../sandbox/winapps_evidence.py) reads `sandbox/last_run_win*.json` and emits the generated mapping. Proven evidence takes precedence over real-name evidence. It retains sorted source filenames and only current curated keys. Its `derive()` helper reads files without rewriting the mapping.

Labels describe historical run data. They do not rerun a VM, prove every installer/version, verify an advisory's correctness, or guarantee successful remediation. The generated [`winapps_evidence.py`](../../api/src/nimstead/winapps_evidence.py) is the stored result. Regeneration writes that module when the script runs as a command.

## Related

- [Version comparison reference](version-comparison.md)
- [Finding API reference](findings.md)
- [Lifecycle reference](lifecycle.md)
- Source: [`winapps.py`](../../api/src/nimstead/winapps.py)
