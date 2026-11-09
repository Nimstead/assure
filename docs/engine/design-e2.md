# Engine, first slice: an end-to-end Windows scan (E2)

> **Status:** this design is from before the switch. Since 0.7.6 and 0.7.7, findings open from the engine's verdicts and close only on evidence (DECISIONS 123, 124). Where "Today" below describes `scan.rescan` deciding findings, that describes the earlier behaviour.

Design record for the first engine slice. Requirements and acceptance targets here are not a statement that every feature is implemented. Use [current operator explanations](../explanation/inventory-to-evidence.md) and [recorded proof status](../../STATUS.md) for those questions.

Requirements are in `spec-detection.md` (R and T numbers refer to it). The boundary is in DECISIONS 79: whoever builds this works from these two documents plus Microsoft, NVD and vendor sources, and doesn't open the reference scanner.

## What it must show

One command scans a real Windows VM and prints a report that says, for each check, what was concluded and why:

- `vulnerable`, with what was observed, what was expected, where each came from and how sure we are
- `not-vulnerable`, only with positive evidence
- `undetermined` or `not-run`, naming what stopped it and what to do about it
- a coverage statement: what was attempted, what was determined, and a plain line when something wasn't assessed

## Where this differs from today

Today's pipeline (`scan.rescan`) turns an inventory into findings. A finding means vulnerable and silence means everything else, so a failed collector and a patched host look the same. Its comparators and feeds are good and stay. What's new sits around them:

| Today | Engine |
|---|---|
| Packages, plus free-form facts | A collection document: each source says ok, partial or failed, with its count and error (R4.3, R9.2) |
| A finding or nothing | One verdict per check, host and instance (R4.1) |
| Reasons for priority | An evidence chain and a grade for confidence, separate from severity (R4.5, section 6) |
| Findings close when the inventory no longer matches | Closing needs a positive `not-vulnerable` (R4.2, R4.6) |

The evaluator is pure: inventory plus content in, verdicts out, no network, deterministic (section 14, T34). Agents and `scan-remote` remain the collectors, on the agent's closed list of what it reads (DECISIONS 7, 27): the server names nothing to run.

## Evidence grades (settles the spec's open item, independently)

Based on CVSS v3.1's public Report Confidence metric (Unknown, Reasonable, Confirmed: <https://www.first.org/cvss/v3.1/specification-document>), with its idea applied to one host rather than to a vulnerability in general. How sure are we that this is true here?

| Grade | Means | Windows examples |
|---|---|---|
| `confirmed` | The host's own state was read directly, and compared against the vendor's own statement of the fix | OS build against MSRC's fixed build; .NET runtime folder against MSRC |
| `reasonable` | The host's own state was read, but the fix statement is a third party's, or the state is self-reported by the product | Uninstall entry against NVD's range; product display version |
| `unverified` | Inferred, with no direct reading of the host | A remote identification; a stale or partial reading |

**Combining rule:** a conclusion is only as strong as its weakest input, so the grade is the lowest grade of what it depended on. A rule declares a ceiling and the engine can only lower it (R6.1). Two independent sources agreeing doesn't raise the grade in this slice; disagreeing gives `undetermined` (R8.4). Both are starting points, to be checked against measured false-positive rates per grade (R6.2).

Severity and priority stay separate and unchanged (`risk.py`, R6.5).

## Scope of this slice

**In:** verdict model; collection document; pure evaluator over OS build, Microsoft products and curated apps, reusing the existing advisories and comparators; incomparable versions give `undetermined` (R5.2); pending reboot as its own state (R8.5); each install judged (T19); coverage (R4.4); text and JSON reports; a stored scan record naming its content version (T34); a parity check against `scan.rescan` on the same inventory, every difference listed and explained; a real-VM harness.

**Out, next:** moving `rescan` onto the engine and changing how findings close (once parity is shown); the fact store as a separate service, scheduling, active probes, network services and sandboxed programs (sections 2, 3, 5, 10); Linux; signed content distribution (section 13), which matters once content is shipped separately from the release.

## Done when

- Unit tests for the verdicts: T14–T19 where a fake inventory can show them, T3, T5, T7, T10, T34
- `sandbox/winengine.py VM` on a real Windows VM writes `sandbox/last_run_winengine.json`, and the printed report is what a person would read
- Parity on that VM: every finding `rescan` opened is a `vulnerable` verdict, and every difference is explained
