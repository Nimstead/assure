# Lifecycle reference

Lifecycle findings identify mapped support deadlines or inferred unsupported release lines. Missing findings do not establish that a product remains supported.

## Data sources

| Input | Coverage |
| --- | --- |
| Curated `ROWS` in `lifecycle.py` | Microsoft Windows and selected Microsoft products, with source URLs and a dated `CHECKED` marker |
| `APP_EOL` mapping | Selected third-party Windows products mapped to externally supplied endoflife.date cycles |
| `m365-lines` | Minimum supported Click-to-Run build line by Office channel |
| `DISTRO_EOL` mapping | Linux ecosystem identities mapped to lifecycle feed products and cycles |

The module does not fetch these external feeds. Callers supply their data. The Microsoft table's review marker is not proof that every external feed is current.

The test suite requires recent review of Microsoft dates close to the test date. This freshness check does not validate vendor policy or every row's factual accuracy.

## Curated row and warning rules

Each `Row` has string `key`, display `label`, date `end`, source URL `source`, and optional date `esu_end`. Construction does not validate dates or their order.

`verdict(row, esu, today)` returns `("ending", text)`, `("ended", text)`, or `None`:

| Condition | Result |
| --- | --- |
| More than 90 days before the effective final support day | `None` |
| Within 90 days, including the final support day | `ending` |
| After the effective final support day | `ended` |

A truthy ESU fact selects the configured ESU final day through that date. The function trusts the supplied fact. It does not verify an ESU purchase or entitlement. Once that ESU day passes, the ordinary end date again supplies the ended result.

## Identity mapping

`windows_row(product, edition)` uses case-sensitive product and registry edition mappings. Unsupported combinations return `None`. Some shared release rows do not require a recognized edition.

`directory_row(os_name, os_version)` extracts a build from parentheses, such as `10.0 (19045)`. Enterprise/Education names select that family. Other client names default to Professional. LTSC names select EnterpriseS. This is a directory-text inference, with no host-level edition verification.

`microsoft_row(package)` recognizes supported Microsoft fact rows and qualifying Microsoft-published Uninstall entries. Inputs need `ecosystem`, `name`, `version`, and `source` attributes. Unknown mappings return `None`.

`distro_cycle(ecosystem)` returns a lifecycle product/cycle pair. It handles Alpine's `v` prefix, openSUSE Leap, and SUSE service-pack labels. Unmapped or rolling release identities return `None`. This mapping does not itself produce a host finding.

## External cycle data

`parse_eol(cycles)` accepts a nonempty list of dictionaries. Each needs a string `cycle` and an `eol` boolean or `YYYY-MM-DD` calendar date. It returns a cycle-to-value dictionary. Duplicate cycle names use the last value.

An impossible date such as `2026-99-99`, a nondictionary entry, and any other root or field failure raise `ValueError`, so the feed run keeps that product's stored cycles and `app_verdict` never meets a date it cannot read.

`app_verdict(key, version, eol, today)` returns an ended result for true lifecycle flags or dates before `today`. It prefers the configured major/minor cycle, then falls back to a major-only cycle. Missing, false, future, and unknown cycle values return `None`. This helper produces no 90-day warning.

`parse_thunderbird(versions)` uses `LATEST_THUNDERBIRD_VERSION` and `THUNDERBIRD_ESR`. It marks every positive major below the latest release as ended, except the ESR major. This is the implementation's inference, not a complete lookup of Mozilla support policy.

`m365_line(package, oldest)` compares `16.0.build.revision` against an integer minimum for the recognized channel. Older build lines produce an identity and text. Unknown channels, perpetual channels, unreadable versions, and nonolder lines return `None`.

## Finding fields

`findings(packages, facts, today, eol=None)` returns these fields:

| Field | Value |
| --- | --- |
| `package` | Curated label or mapped application key |
| `version` | Observed version string, or empty string for a facts-only OS identity |
| `vuln_id` | Stable `EOL:` identity |
| `summary` | Deadline or unsupported-line text |
| `ended` | True for ended support, false for a warning |
| `source` | Vendor/feed source URL |

The function deduplicates lifecycle identities across package instances. It checks curated Windows/Microsoft rows and supplied Windows application/Office data. Linux lifecycle verdicts are produced separately by the detection engine.

The function performs no network or persistence operations. Malformed package attributes, nested input values, and dates can raise attribute, type, or value errors.

## Related

- [Scan outcomes](scan-outcomes.md)
- [Scan report format](scan-report.md)
- [Platform support](platforms.md)
- Source: [`lifecycle.py`](../../api/src/nimstead/lifecycle.py)
