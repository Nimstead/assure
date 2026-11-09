# Snapshot contents and limits

A Pulse snapshot is a versioned JSON file created after analysis of a personal CVE list.

| Content | Included |
| --- | --- |
| Submitted CVE IDs | Yes, including missing and rejected records |
| Public observations | KEV, EPSS, CVSS, and feed dates |
| Federal due dates | Only when the corresponding control is enabled |
| Raw scanner text | No |
| Downloaded descriptions | No |
| Authentication of historical observations | No. Imported data is user-supplied |

## Import limits

The snapshot loader rejects files above 10,000,000 bytes. Supported snapshots contain at most 10,000 CVEs. A generic scanner JSON file is not automatically a Pulse snapshot.

## Comparison scope

Comparison includes KEV listings, ransomware flags, EPSS changes and crossings of the 10% threshold, severity, product attribution, record availability, and optional federal due dates.

Changes to list membership are separate from changes in public observations. Neither proves that a host was fixed.

See [save and compare snapshots](../how-to/snapshots.md) for the procedure.

Source: [Pulse repository documentation](https://github.com/Nimstead/pulse/blob/main/README.md).
