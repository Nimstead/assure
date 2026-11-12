# Feed synchronisation reference

The feed module writes advisory data and schedules related upkeep. Its Python helpers use a caller-owned SQLAlchemy `Session` and commit at different boundaries. A complete update is not one atomic transaction.

## Commands

`python -m nimstead.feeds` accepts these commands in the configured API environment. They write the configured database and contact external services.

| Arguments | Operation |
| --- | --- |
| `update` | Select feeds from installed ecosystems, rescan assets, and perform upkeep |
| `osv ECOSYSTEM...` | Read each top-level ecosystem ZIP, such as `PyPI` or `Ubuntu` |
| `nvd YEAR...` | Read named NVD feeds. `modified` is also a valid feed name |
| `kev` | Replace CISA KEV data |
| `epss` | Replace FIRST EPSS data |
| `msrc [MONTHS]` | Read recent MSRC documents. The default is 12 months |

`main(argv)` returns `2` for an unsupported command or missing OSV/NVD arguments. It prints usage to standard error. Invalid MSRC integer text raises `ValueError`. Successful commands print Python representations, not JSON, and return `0`. Commands ignore extra arguments they do not use. Sync and database errors can propagate after earlier commits.

## Shared HTTP and transaction behavior

An optional `client` supplies feed HTTP transport. Default HTTPX clients follow redirects, with 60-second operation timeouts and a 300-second read timeout. These are not whole-run deadlines. Most requests do not retry. MSRC retries transport failures up to three attempts per request.

Callers retain ownership of supplied clients. Helpers do not close them. Helpers also create default clients without an explicit close here.

Response limits apply after HTTPX reads the full response. They do not prevent initial buffering. ZIP entries and decompressed NVD/EPSS data can consume more memory than compressed input. OSV archives stream to temporary disk before entry parsing.

Most helpers commit all pending session changes, including unrelated changes. Most do not roll back an error themselves. `sync_epss` rolls back errors during replacement. `sync_office` rolls back handled HTTP/validation errors. `update_all` rolls back at its handled failure boundaries. Earlier commits remain saved.

## Source operations

Counts describe processed rows, not proven feed freshness or successful host collection.

| Helper | Input and stored data | Return | Commit boundary |
| --- | --- | --- | --- |
| `sync_osv(session, ecosystems, client=None, batch=5000, only=None)` | Top-level ZIP names, optional exact normalized ecosystem set | `inserted`, `updated`, `skipped` | At batch threshold and each ZIP's end |
| `sync_kev(session, client=None)` | CISA vulnerabilities replace `Kev` | Row count | Once after replacement |
| `sync_epss(session, client=None)` | Compressed CSV replaces `Epss` | Row count | Once after replacement |
| `sync_nvd(session, feeds, client=None)` | Named gzip feeds update `Cvss`, then WinApp advisories | Scored row count | Scores per feed, then application batches |
| `sync_winapps(session, cves)` | NVD CVE dictionaries replace supplied CVEs' WinApp rows | Inserted row count | Each batch of at most 5000 CVEs |
| `cvelist_records(session, records)` | CVE List dictionaries replace eligible fallback rows | Inserted row count | Once |
| `sync_cvelist(session, client=None)` | Available delta ZIPs and progress marker | `deltas`, `rows` | Records, then marker, per archive |
| `sync_msrc(session, months=12, client=None, month=None, apps_months=0)` | Windows/Microsoft/Office CVE data | Five counters below | Per document, with possible separate state commit |
| `sync_eol(session, client=None)` | Curated application and distribution lifecycle cycles | Product to count or `error` object | Once for successful merges |
| `sync_office(session, client=None)` | OfficeReleases paired with stored Office CVEs | `rows` or `error` | Once on success |
| `sync_metasploit(session, client=None)` | Unique CVE references in `Exploit/metasploit` | CVE count | Once |
| `sync_exploitdb(session, client=None)` | Unique CVE references in `Exploit/exploitdb` | CVE count | Once |
| `sync_loldrivers(session, client=None)` | Parsed hashes in `WinDriver/loldrivers` | Hash count | Once |

HTTP, decompression, ZIP, JSON, field and database errors propagate unless a helper explicitly handles them. Input dictionaries are trusted source shapes, not fully validated external schemas.

### OSV

Rows use `(id, normalized ecosystem, package)` identity. Each stored record retains selected metadata, its grouped affected entries, and at most 500 details characters. Equal `modified` text skips content updates. Rows absent from a new ZIP remain stored.

Without `only`, a ZIP contributes only its top-level ecosystem. With `only`, it can contribute any exact selected ecosystem present in that ZIP. An empty set retains no rows. `batch` is a flush threshold, not a validated positive limit. One record can exceed it.

An error after one batch commits leaves that batch saved. Callers must handle the remaining transaction. Duplicate identities within one archive can cause database errors.

### KEV, EPSS and NVD scores

KEV and EPSS parse complete replacement rows before the delete. Empty KEV entries or EPSS rows raise `ValueError`. KEV ransomware status is true only for source text equal to `Known`. EPSS numeric conversion does not enforce a 0–1 range.

`nvd_score(cve)` prefers CVSS v3.1, then v3.0, then v4.0. Within one version, it selects the first `Primary` entry, otherwise the first entry. It returns `(float score, vector)` or `None`. It does not validate score ranges.

NVD score updates replace only CVEs that yield a score. Missing or unscored CVEs retain old scores. Vector text truncates to 200 characters. The return count excludes application advisory rows.

### Windows application precedence

NVD input removes existing NVD WinApp rows for every supplied CVE. Rejected or untranslatable CVEs add none. A translated row removes all fallback `<CVE>-v5` rows for that CVE, including other products. Without a translated row, existing fallback rows remain.

CVE List input skips a CVE when any NVD WinApp row exists. Otherwise it replaces the CVE's fallback rows, including with an empty result. These rules operate per CVE, not per product. See [Windows application mapping](windows-apps.md).

The delta reader inspects one GitHub releases page with ten entries. First use processes only the newest matching filename. Later uses process available newer names in order. It does not retrieve missing history through pagination.

Archive URLs must start with the configured CVEProject release prefix. The compressed limit is 200 MiB. Uncompressed ZIP content has no aggregate size limit. Records commit before the progress marker, so a later failure can cause repeat processing.

### MSRC

History cutoffs use 30 days per requested month. `apps_months` extends older history for allowlisted Microsoft applications. An explicit `month`, such as `2023-Nov`, selects one matching indexed document regardless of age.

Explicit and older application months add missing identities without replacing stored rows. Recent full documents can update changed identities. Missing rows are retained. Skip markers use stored `CurrentReleaseDate` values and the `MSRC-APPS-STATE` row. They do not compare every stored record with the source.

The converter separates cumulative and hotpatch tracks. It selects the lowest valid fixed build per product and track. Windows products require supported names and numeric builds. Other products use the Microsoft allowlist. Office Click-to-Run CVEs are retained separately for the Office channel feed.

Returned fields are `documents`, `skipped_documents`, `inserted`, `updated`, and `skipped`. The last three exclude Office CVE rows. A fetched document can produce zero counted rows.

`msrc_context(v)` returns an optional `tag` from the first nonempty Type 7 note. It reads exploitation data from the first matching Type 1 threat. The fields are `exploited`, `disclosed`, and `exploitability`. Only exact `Yes` means true. Tag and exploitability text truncate to 200 and 60 characters.

### Auxiliary sources

Lifecycle fetches use the union of application and distribution products. Thunderbird uses its separate source. Handled HTTP/parse/type errors preserve that product's row and return at most 200 error characters. Other failures propagate.

Office handles only HTTP errors and `ValueError` locally. Other malformed fields and database errors can propagate. A handled failure rolls back the entire pending session.

MAC vendor names (`oui.sync`) run only once some agent has reported a neighbour. The source is Wireshark's `manuf`, published for automated download from the IEEE MA-L, MA-M and MA-S registries; IEEE's own `oui.csv` refuses ordinary HTTP clients. It is fetched only when the stored copy is seven days old, as the file asks. It has a 16 MiB limit and needs at least 1,000 parsed prefixes; otherwise the stored copy stays.

Metasploit requires a dictionary with at least 1000 entries, but no minimum extracted CVE count. Exploit-DB requires `codes` and `type` columns and at least 1000 unique CVE IDs. Only exact lowercase `dos` rows are excluded. Both use a 100 MiB response limit. LOLDrivers uses a 200 MiB limit and its [parser rules](platforms.md#windows-matching-inputs).

## Scheduled update result

`update_all(session, client=None)` always attempts KEV, EPSS, modified NVD, Metasploit and Exploit-DB. Installed package ecosystems select OSV feeds. Windows/Microsoft use adds MSRC, Office and LOLDrivers. WinApp use adds lifecycle and CVE List data.

The result always starts with `kev`, `epss`, `nvd`, and `osv`. Successful optional sources add their named key. Handled Metasploit/Exploit-DB failures omit that key. Other handled source failures can return `error` objects. OSV results are keyed by top-level ecosystem.

The result also includes `rescanned`, `external` with `scanned`/`refused`, `webhooks_sealed`, `alerts_retried`, `hosts_not_reporting_alerted`, and `platform`. Failed host rescans add `rescan_failed` asset IDs. External scan failures outside refusal are logged without a separate result count.

Verified external targets are re-proven and scanned. Other assets are rescanned from stored inventory. The run then checkpoints organisations, seals legacy webhook secrets, retries alerts, checks silent hosts, and checks releases. These stages can write files, use key storage, and send notifications. The supplied feed client does not replace external-scan or release transports.

Feed and per-asset guards do not cover every stage. Checkpoint and notification-upkeep failures can stop the run after earlier changes commit. A returned result can also contain failures. It does not establish that every feed or asset succeeded.

## Related

- [Developer commands](tooling.md)
- [Database reference](database.md)
- [Notification reference](notifications.md)
- Source: [`feeds.py`](../../api/src/nimstead/feeds.py)
