# Platform update reference

The feed updater discovers releases and caches agent distribution files. It does not install a new server. The [server upgrade procedure](../how-to/upgrade-server.md) uses `deploy/update.sh` on the Docker host.

## Configuration and discovery

| Setting | Behavior |
| --- | --- |
| `NIMSTEAD_UPDATE_CHANNEL` | Defaults to stable. Trim whitespace and ignore case. Unknown values use stable |
| `NIMSTEAD_UPDATE_CHECK` | Exactly `0` skips release discovery, file/runtime fetches, and update alerts in `updates.check()` |
| `NIMSTEAD_RELEASE_DIR` | Cache and updater-status directory. See [configuration](../configuration.md) for defaults |

Channels accept their own level and more stable levels: preview accepts all three, beta accepts beta/stable, and stable accepts stable. Missing or unrecognized manifest channels act as preview.

Discovery requests one GitHub releases page with `per_page=30`. It ignores drafts and tags outside `vX.Y.Z`, then sorts numeric versions descending. It considers versions above the installed package version. This is not full SemVer parsing and does not include prerelease suffixes.

Each candidate needs a signature under a key pinned in the served agent. Its manifest version must match the tag and its signed channel must be eligible. GitHub's prerelease and Latest labels do not determine eligibility. Other agent-manifest fields are not fully validated at this discovery step.

Successful discovery is cached for 24 hours for the configured channel. A channel change causes a new lookup on the next check. If no eligible release appears on that page, the result is empty. Discovery does not paginate through older releases.

## Cache files

| File | Purpose |
| --- | --- |
| `release.json` | Cached manifest bytes |
| `release.json.sig` | Cached signature |
| `python-embed-ARCH.zip` | Runtime bytes named by the cached manifest |
| `latest.json` | `version`, `url`, `channel`, `for_channel`, `checked`, and optional `alerted` metadata |
| `update-status.json` | Result written by the deployment updater, with optional notification marker |

`fetch_release_files()` requests files for the running platform version. It skips the request only when the cached manifest's signature verifies against a pinned key, its version matches and its channel is eligible; a cached manifest with a missing or bad signature is fetched again. It also skips replacement when downloaded manifest bytes are identical to a verified cached manifest.

The fetch step verifies the downloaded pair before storing anything: a signature that doesn't verify, or a manifest naming another version, stores nothing. It then stores signature and manifest through separate atomic replacements. Serving and runtime-fetch helpers check the signature again. A partial pair can temporarily be unavailable to those helpers.

`fetch_runtimes()` uses the signed cached manifest's version, which can differ from the running platform version. It preserves an existing archive only when its SHA-256 matches. A fetched archive also requires a matching signed hash before storage. This step does not unpack or inspect archive programs.

For offline Windows distribution, the cache needs the signed manifest/signature and the named `python-embed-ARCH.zip` files. Copying only the manifest pair does not supply a runtime archive.

## Download limits

| Content | Maximum response body |
| --- | --- |
| Release listing | 2 MiB |
| Each manifest or signature | 64 KiB |
| Each runtime archive | 40 MiB |

Downloads follow redirects and use 30-second HTTPX operation timeouts. The body-size check occurs after the response is buffered. These limits are not streaming memory caps or whole-run deadlines.

Per-release HTTP or size failures skip that discovery candidate. Runtime HTTP, size, or hash failures skip that architecture. Local storage errors and malformed cache structures can still raise errors. Invalid JSON or unreadable cache files normally act as empty data.

## Settings status fields

The settings response includes a `platform` object from `updates.status()`:

| Field | Value |
| --- | --- |
| `version` | Installed `nimstead` distribution version, or empty string without package metadata |
| `channel` | Normalized server channel |
| `running_channel` | Channel from the cached manifest when its signature verifies and its version matches the installed version, otherwise `null` |
| `latest` | Cached discovered release version, or `null` |
| `latest_url` | Cached release-page URL, or `null` |
| `latest_channel` | Cached signed channel label, or `null` |
| `update_available` | Boolean comparison of numeric latest/running versions |
| `checked` | Cached check timestamp, or `null` |
| `last_update` | Nonempty `update-status.json` data, or `null` |

A different `for_channel` hides cached latest-release fields. Status does not fetch releases. `running_channel` comes only from a cached manifest whose signature verifies; it names the channel the running version was signed for, not a check of the installed checkout itself.

The deployment script writes `last_update` fields `outcome`, `from`, `to`, `error`, and `at`. Outcomes are `updated`, `refused`, `rolled_back`, or `rollback_failed`. `error` is text or `null`. `at` is a UTC timestamp without a timezone suffix. Notification handling can add boolean `alerted`. Other file fields pass through unchanged.

`updates.check()` returns these fields:

| Field | Value and presence |
| --- | --- |
| `release_files_fetched` | Boolean on enabled runs |
| `runtimes_fetched` | Architecture names stored during this run |
| `latest` | Discovered/cached version string or `null`, when discovery does not fail |
| `alerted` | Array containing `update_available` and/or `update_failed` when queued, otherwise empty |
| `error` | Discovery error text truncated to 200 characters. Can replace `latest` |
| `skipped` | `NIMSTEAD_UPDATE_CHECK=0`, as the sole field when disabled |

Alerts are best-effort background notifications. File markers suppress repeats for a version or failed-update outcome.

## Agent distribution

| Endpoint | Authentication and response |
| --- | --- |
| `GET /api/agent/manifest` | Asset agent key. Returns unsigned `paused` and optional `release`/`sig` strings |
| `GET /agent/nimstead_agent.py` | Public agent source bytes |
| `GET /agent/runtime/{arch}.zip` | Public archive bytes when the signed served-agent release names that architecture and its stored hash matches |

The runtime endpoint accepts only `amd64`, `arm64`, or `win32`. Missing, unsupported, or hash-mismatched archives return `404`. Malformed signed metadata can cause server errors.

The relay includes a manifest only when a pinned signature matches and `agent_sha256` matches the served file. It does not enforce agent channel policy or a newer agent version. The agent applies those rules itself.

An agent replacement requires a strictly newer signed agent version, the local channel policy, a matching downloaded hash, and a successful collection self-test. The previous agent remains as `.prev`. A failed self-test suppresses that hash for 24 hours.

An eligible manifest for the same agent version can still update its Windows runtime. The runtime step precedes the agent replacement decision. Older runtime versions are refused when the current interpreter already belongs to the bundled runtime tree. A system-Python migration does not use that same downgrade test.

## Related

- [Release manifest and keys](../release-keys.md)
- [Why agent updates are signed](../explanation/signed-updates.md)
- Source: [`updates.py`](../../api/src/nimstead/updates.py), [`sign_release.py`](../../scripts/sign_release.py), and the update functions in [`nimstead_agent.py`](../../agent/nimstead_agent.py)


## Agent helper contracts

The single-file agent's ed25519_verify(pub,msg,sig) checks point encodings, scalar bounds and the verification equation. Public key and signature must be bytes of length 32 and 64. Invalid shapes return false. Invalid message types can raise TypeError. This helper does not select trusted keys or reject every low-order/subgroup case. Release verification supplies pinned keys separately.

version_tuple(v) accepts an exact three-component numeric string and returns integer components, otherwise null. Leading zeros and Unicode decimal digits are accepted. It has no SemVer suffix support. Very long integer text can raise ValueError.
