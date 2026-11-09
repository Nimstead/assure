# Priority score reference

The generic scorer returns a `Risk` object with integer `score`, priority string, and ordered reason strings. Platform checks can supply their own score instead of this formula.

## Inputs

| Input | Meaning and default |
| --- | --- |
| `kev` | CISA known-exploitation flag; required |
| `epss` | Probability from 0 through 1, or `None`; required |
| `cvss` | Impact score from 0 through 10, or `None`; required. Missing impact uses 5 |
| `criticality` | `low`, `medium`, `high`, or `critical`; defaults to `medium`. Unknown strings use the medium weight |
| `internet_facing` | Boolean exposure flag; defaults to false |
| `fix_available` | Boolean fix-availability flag; defaults to true |
| `likelihood` | Alternative probability when EPSS is absent; defaults to `None` |
| `likelihood_reason` | Explanation for the alternative; defaults to `None` |

Inputs are trusted internal values. The scorer does not validate numeric ranges or signal consistency. Invalid numeric values can raise arithmetic or rounding errors.

## Base calculation

The likelihood factor is 1 for KEV. Otherwise it is the square root of EPSS when available. If EPSS is absent, the alternative likelihood is used, or 0.1 if neither exists.

Impact is CVSS divided by 10, with missing CVSS treated as 5. The raw value is `0.55 × likelihood + 0.45 × impact`.

| Adjustment | Multiplier |
| --- | --- |
| Low criticality | `0.6` |
| Medium or unknown criticality | `0.8` |
| High criticality | `1.0` |
| Critical criticality | `1.15` |
| Internet-facing asset | `1.0` |
| Other asset | `0.75` |
| No fix available | `0.7` |

The adjusted raw value is multiplied by 100, rounded, and clamped to 0–100. KEV then imposes a minimum score of 90 and priority `fix-now`.

| Score | Generic priority |
| --- | --- |
| At least 75 | `fix-now` |
| At least 50, below 75 | `next` |
| At least 25, below 50 | `planned` |
| Below 25 | `low` |

No-fix adjustment applies to the raw KEV score too. For example, a result can decrease from 100 to 90 while remaining `fix-now`.

## Additional context

`context` adjusts an existing `Risk`. It does not mutate the input. If nothing changes, it returns the same object.

| Signal | Effect |
| --- | --- |
| Known ransomware use | Adds a reason |
| Microsoft confirms exploitation and CISA KEV is false | Minimum score 90; priority `fix-now` |
| Microsoft rates exploitation more likely or detected, without KEV and without the preceding confirmed-exploitation override | Adds 10 points, capped at 100 |
| Public Metasploit exploit, without KEV | Adds 10 points, capped at 100 |
| Exploit-DB record, without KEV | Adds 10 points only if no Metasploit increment was used; adds a reason either way |
| Public disclosure before the fix | Adds a reason |
| Mapped Windows role absent from a nonempty known role list, without confirmed exploitation | Multiplies by 0.6 and rounds |
| Reachable listener, without KEV | Adds 15 points, capped at 100; adds the supplied exposure reason |

Empty or absent role data does not establish that a role is absent. Known exploitation is not reduced by role absence. Except for exploitation overrides, priority follows the adjusted score thresholds.

The score orders review work. It is not a probability that a particular host will be exploited. Read the individual reasons and [detection confidence](../explanation/detection-confidence.md).

Source: [risk.py](../../api/src/nimstead/risk.py) and its caller in [scan.py](../../api/src/nimstead/scan.py).
