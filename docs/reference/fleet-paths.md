# Fleet attack-path format

`GET /api/attack-paths` correlates the latest stored scan reports with current asset facts. It does not rescan hosts. A session or eligible read-only organisation token is required.

The endpoint limits an organisation to 120 reads per hour. It returns `429` when the limit is reached. This GET commits its usage counter.

## Root fields

| Field | Value |
| --- | --- |
| `hosts` | Map from asset ID to the host summary below |
| `edges` | Up to 2000 directed source-to-target edges |
| `truncated` | True when another eligible edge exists beyond the 2000-edge limit |
| `chains` | Up to 50 start-host reachability groups, largest first |

The edge limit can remove routes from subsequent chain calculation. The 50-chain limit has no separate truncation flag.

## Host summaries

| Field | Value |
| --- | --- |
| `hostname` | Asset hostname |
| `judged` | True when a stored report contains an `attack_paths` key, even if its array is empty |
| `entry` | True when the report contains a network-start path |
| `internet_facing` | Boolean asset context flag |
| `paths` | Condensed paths, or an empty array for unjudged assets |

Each condensed path has `kind`, `start`, `grade`, `steps`, and `break_at`. `steps` contains stage labels. `break_at` preserves the [host report object](scan-report.md#host-attack-paths).

## Edges

Each edge has `from`, `to`, `grade`, and `ways`. The IDs identify different assets. An edge requires an inferred source capability, a compatible target setting, and a target listener allowed by its reported firewall.

| Way field | Value |
| --- | --- |
| `via` | Setting reference: `CFG:remote-uac`, `CFG:smb-signing`, or `CFG:ntlmv1` |
| `how` | Description of the target's accepting condition |
| `port` | Selected target TCP port |
| `because` | Evidence and assumptions behind the inference |
| `grade` | `unverified`, `reasonable`, or `confirmed` |

The edge grade is its strongest way. Ways sort by descending grade. Source compromise confidence limits the result.

Domain membership can support a reasonable credential-use inference. A confirmed domain credential way requires a signed-in account on the source in the target's Administrators group. The source must also report a connection to the target. The source path must support confirmed confidence.

If known signed-in accounts do not match target administrators, the way remains present as unverified. Cross-domain credential reuse remains unverified because shared local passwords are not observable. Name-poisoning ways depend on inferred capture and relay conditions.

The listener and connection observations can come from different report times. They do not establish current routing, a successful sign-in, or exploitation.

## Chains

Each chain has `start`, `why_start`, and `reach`. A start needs a network path, or an internet-facing flag plus some host path.

| Reach field | Value |
| --- | --- |
| `host` | Reachable target asset ID |
| `hops` | Asset IDs from the next hop through the target |
| `grade` | Weakest edge grade on this route |
| `fix_on_host` | Sorted unique setting references from the final edge |

Breadth-first traversal selects one route with the fewest hops to each target. It does not select the strongest route among equal-length alternatives. `fix_on_host` concerns the final target, not every host in the chain.

## Related

- [Scan report format](scan-report.md)
- [Detection confidence](../explanation/detection-confidence.md)
- Source: [`fleet.py`](../../api/src/nimstead/engine/fleet.py)
