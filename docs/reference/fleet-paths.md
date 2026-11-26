# Fleet attack-path format

`GET /api/attack-paths` correlates the latest stored scan reports with current asset facts and each Linux host's latest access read. It does not rescan hosts. A session or eligible read-only organisation token is required.

The endpoint limits an organisation to 120 reads per hour. It returns `429` when the limit is reached. This GET commits its usage counter.

## Root fields

| Field | Value |
| --- | --- |
| `hosts` | Map from asset ID to the host summary below |
| `edges` | Up to 2000 directed source-to-target edges: Windows edges first, then SSH key edges |
| `truncated` | True when an edge exists beyond the ones listed, or when key edges stopped at their 50,000 limit |
| `chains` | Up to 50 start-host reachability groups, largest first |
| `choke_points` | Up to 10 single actions that cut the most machines off from every start, largest first |

Chains and choke points walk every edge found, not only the 2000 listed. Windows edges stop at 2000 when they're found, so past that a Windows route can be missing from both. The 50-chain limit has no separate truncation flag.

## Host summaries

| Field | Value |
| --- | --- |
| `hostname` | Asset hostname |
| `judged` | True when a stored report contains an `attack_paths` key, even if its array is empty |
| `entry` | True when the report contains a network-start path |
| `internet_facing` | Boolean asset context flag |
| `paths` | Condensed paths, or an empty array for unjudged assets |

Each condensed path has `kind`, `start`, `grade`, `steps`, and `break_at`. `steps` contains stage labels. `break_at` preserves the [host report object](scan-report.md#host-attack-paths). A Linux path also has `reaches`: `{"root": true}` when it ends with root, otherwise `{"root": false, "users": [...]}`, the accounts it holds.

## Edges

Each edge has `from`, `to`, `grade`, and `ways`. The IDs identify different assets. An SSH key edge also has `kind: "ssh"`. The edge grade is its strongest way. Ways sort by descending grade.

### Windows ways

A Windows edge requires an inferred source capability, a compatible target setting, and a target listener allowed by its reported firewall.

| Way field | Value |
| --- | --- |
| `via` | Setting reference: `CFG:remote-uac`, `CFG:smb-signing`, or `CFG:ntlmv1` |
| `how` | Description of the target's accepting condition |
| `port` | Selected target TCP port |
| `because` | Evidence and assumptions behind the inference |
| `grade` | `unverified`, `reasonable`, or `confirmed` |

Source compromise confidence limits the result. Domain membership can support a reasonable credential-use inference. A confirmed domain credential way requires a signed-in account on the source in the target's Administrators group. The source must also report a connection to the target. The source path must support confirmed confidence.

If known signed-in accounts do not match target administrators, the way remains present as unverified. Cross-domain credential reuse remains unverified because shared local passwords are not observable. Name-poisoning ways depend on inferred capture and relay conditions.

### SSH key ways

A key edge exists when a private key held on the source has the same SHA-256 fingerprint as a key the target trusts, and the target's sshd lets that account in. Concretely, all of these hold:

- sshd is installed and running, with public keys on, and doesn't refuse the account. That means DenyUsers, AllowUsers (the host after the last `@` matched against the source's addresses), DenyGroups and AllowGroups, with `*` and `?` as the only wildcards, and PermitRootLogin for uid 0, whatever its name.
- the key line's `from=` allows the source's addresses
- the target's report doesn't say sshd listens only on loopback. Only a complete runtime read under 36 hours old can say so; anything listening on sshd's port counts, as systemd does for socket activation.
- the account can sign in. An sshd without PAM (one that prints no `usepam yes`, like Alpine's) refuses an account whose password is locked with `!`, keys included. An account whose shell is `nologin` or `false` gets no session.

One way is kept per (key, account, who must hold it) per pair, the best graded; a key held or trusted twice is one way. Key ways stop at 50,000 in all (`truncated` then says so). The response lists at most 5 ways per edge, and `ways_count` gives the full number when there are more.

| Way field | Value |
| --- | --- |
| `via` | `SSH:` and the key's fingerprint |
| `key` | The fingerprint, `SHA256:` and 43 base64 characters, as `ssh-keygen -l` prints it |
| `path` | Where the source holds the private key |
| `account` | The account the target trusts the key for |
| `needs` | Who must hold the key on the source: `root`, or the account that owns the file |
| `gives` | What the target hands over: `root` when the account is root, in a root-equivalent group or has `NOPASSWD: ALL`, otherwise the account |
| `port` | 22 |
| `how` | The key and the account in words |
| `because` | What the grade rests on |
| `grade` | `unverified`, `reasonable`, or `confirmed` |

A key way is `reasonable`, or `confirmed` when the source was seen connected to one of the target's addresses. A `Match` block in the target's sshd caps it at `reasonable`. It's `unverified` when any of these holds:

- the key needs its passphrase
- the line forces a command
- the target also takes keys from an `AuthorizedKeysCommand`
- a host name in `from=` or AllowUsers decides it (nothing here resolves names)
- the key is `ssh-dss` (off by default since OpenSSH 7.0) or a security-key type (it also needs its hardware)
- a non-root account holds the key and its private half couldn't be checked against its public half

The agent checks an unencrypted Ed25519 or RSA key, and doesn't count a file whose private half belongs to another key. `restrict` alone keeps the grade and is said in `because`. No key, comment or forced command ever leaves a machine: only fingerprints do. Nothing here signs in anywhere.

The listener and connection observations can come from different report times. They do not establish current routing, a successful sign-in, or exploitation.

## Chains

Each chain has `start`, `why_start`, and `reach`. A start needs a network path, or an internet-facing flag plus some host path.

| Reach field | Value |
| --- | --- |
| `host` | Reachable target asset ID |
| `hops` | Asset IDs from the next hop through the target |
| `grade` | Weakest edge grade on this route |
| `fix_on_host` | Sorted unique `via` references from the final edge |
| `as` | What the attacker holds there: `"root"`, or a list of accounts |

The walk is breadth first and knows what the attacker holds on each host. A key way can be used only by root or the key's owner. A Windows way gives administrator rights. A host with a foothold path that reaches root upgrades any arrival to root, and reaching a host again with more accounts walks on from it. It selects the route with the fewest hops to each target, not the strongest among equal-length routes. `fix_on_host` concerns the final target, not every host in the chain.

## Choke points

Each candidate is scored by walking the whole graph again without what it removes. Every start's way in is scored, plus at most 200 other candidates, those on the most ways first, and of those only the ones that remove a way the full walk used: removing an unused way leaves every host's derivation standing, so it cuts nothing. Closing the way in of a start also marked internet-facing with another path leaves it a start, holding what that path gives. The ten that cut the most machines come back, largest first.

| Field | Value |
| --- | --- |
| `kind` | `way-in` (close one start's way in), `retire-key` (delete it where held, untrust it everywhere), `untrust-key` (one account on one machine), or `setting` (one Windows setting on one machine) |
| `action` | What to do, in words |
| `cuts` | How many machines no start reaches any more, the start itself included for `way-in` |
| `hosts` | Up to 50 of those asset IDs |
| `ways_removed` | How many ways across the action removes |
| `lower_bound` | True when the graph was cut short, so `cuts` may be higher |
| `ref` | The start's asset ID, the key's fingerprint, or the setting reference |

## Related

- [Scan report format](scan-report.md)
- [Detection confidence](../explanation/detection-confidence.md)
- Source: [`fleet.py`](../../api/src/nimstead/engine/fleet.py)
