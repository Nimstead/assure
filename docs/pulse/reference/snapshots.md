# Snapshot contents and limits

A Pulse snapshot is a version 1 JSON object created after analysis of a personal CVE list. The file contains public observations and selected IDs. It does not authenticate historical observations.

## Root fields

| Field | Type and meaning |
| --- | --- |
| `format` | Literal string `nimstead-pulse` |
| `version` | Integer 1 |
| `generated` | Public data generation time, not the time the user downloaded the file. UTC timestamp with `Z` or `+00:00` |
| `deadlinesIncluded` | Boolean. Controls whether federal KEV due dates can appear |
| `sources` | Object with the source fields below |
| `findings` | Nonempty array of at most 10,000 records. Includes missing and rejected IDs |

## Source fields

| Field | Type and meaning |
| --- | --- |
| `nvd` | UTC timestamp with `Z` or `+00:00` |
| `kev` | Catalogue version string, at most 100 characters |
| `epss` | Score date in `YYYY-MM-DD` form, or an empty string |
| `epssModel` | Model identifier string, at most 100 characters, or an empty string |

## Finding fields

| Field | Type and meaning |
| --- | --- |
| `id` | Unique uppercase CVE ID matching `CVE-YYYY-NNNN…`, at most 40 characters |
| `state` | `found`, `missing`, or `rejected` |
| `epss` | Number from 0 through 1, or `null` when unavailable |
| `cvss` | Number from 0 through 10, or `null` when unavailable |
| `severity` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `NONE`, or an empty string |
| `vendor`, `product` | Public attribution strings, or empty strings |
| `kev` | Boolean catalogue membership |
| `ransomware` | Boolean known-ransomware-use flag |
| `kevAdded` | Catalogue listing date in `YYYY-MM-DD` form, or an empty string |
| `kevDue` | Federal due date in `YYYY-MM-DD` form, or an empty string |

A record without KEV membership cannot contain ransomware use or KEV dates. A KEV record requires its listing date. If `deadlinesIncluded` is false, `kevDue` must be empty.

For `missing` and `rejected` records, scores are `null`. Severity, vendor, and product are empty. KEV membership is false. Missing observations do not mean zero risk.

## Import limits

The file picker rejects files above 10,000,000 bytes. The parser also limits decoded text to 10,000,000 JavaScript characters. It rejects unsupported versions, duplicate IDs, empty finding arrays, invalid dates, inconsistent fields, and scores outside their ranges.

Imported strings cannot contain control characters. The parser reconstructs the supported fields and discards extra properties. It does not retain arbitrary imported objects. A generic scanner JSON file is not a Pulse snapshot.

Raw scanner text and downloaded descriptions are excluded from the snapshot. Keep the file private: the selected CVEs can reveal information about your environment.

## Comparison scope

Comparison includes KEV listings, ransomware flags, EPSS changes and crossings of the 10% threshold, severity, product attribution, and record availability.

Federal due dates are comparable only when both snapshots include them and comparison requests those dates. A baseline newer than the current public data prevents comparison. EPSS model changes require separate interpretation.

Changes to list membership are separate from changes in public observations. Neither proves that a host was fixed.

## Example

[Download a public test snapshot](../../examples/pulse-snapshot.json). It contains two public CVEs and one deliberately nonexistent test ID. Its observations were captured from Pulse on 9 November 2026; its public data was generated on 8 November 2026. It is a format example, not a current risk report.

See [save and compare snapshots](../how-to/snapshots.md) for the procedure.

Source: [Pulse snapshot implementation](https://github.com/Nimstead/pulse/blob/main/src/lib/snapshot.ts).
