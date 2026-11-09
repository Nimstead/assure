# Baseline conversion reference

`scripts/xccdf_rules.py` converts recognized XCCDF checks into baseline JSON for review. It uses the Python standard library. It does not inspect a Windows host, verify conformance, or install collection rules.

## CLI modes

| Argument | Meaning and default |
| --- | --- |
| `xccdf` | Input XML path for conversion. Optional to argparse, but conversion needs a usable path |
| `--id`, `--name` | Baseline labels copied into the output. No CLI requirement or content validation |
| `--os-re` | OS-name regex text copied into the output without compilation |
| `--source` | Provenance label. Default is the DISA download-directory label in the script |
| `--source-sha256` | Provenance hash text, default empty. The converter does not compute or verify it |
| `--out` | Output JSON path. Its parent directory must exist |
| `--agent-list BASELINE...` | Read local baseline JSON and print collection-list JSON. Takes precedence over conversion arguments |

Conversion overwrites its output without an atomic rename. It validates generated JSON syntax before the write. It prints counts and manual reasons to stderr. Exit zero permits partial or zero automation. Argument, XML, JSON, structure and filesystem failures can exit nonzero or raise exceptions.

## XML and traversal limits

The loader reads at most 20MiB plus one byte and refuses files above 20MiB. It rejects literal uppercase DOCTYPE/ENTITY declaration byte sequences. This is not encoding-independent XML validation. The loader does not validate an XCCDF schema or root namespace.

The builder selects direct `Group` children in `http://checklists.nist.gov/xccdf/1.1`. It reads only each group's first `Rule`, first `check`, and immediate `check-content` text. It does not traverse nested groups, additional rules/checks, or referenced content. Other namespaces can produce an empty table without refusal.

Missing expected structures can raise attribute/type errors. Missing metadata can become null labels or incomplete version text. Compare the output count and identities with the intended source scope before use.

## Baseline fields

| Field | Contents |
| --- | --- |
| `id`, `name`, `os_re`, `source`, `source_sha256` | Caller-supplied labels copied without semantic validation |
| `version` | `V` plus the XML version and `R` plus the parsed release number. Missing release number becomes `?` |
| `date` | Date text parsed from release-info, otherwise empty |
| `total` | Number of processed automated and manual records |
| `rules` | Recognized setting records with identity and setting fields below |
| `not_automated` | Identity records for processed checks that the parser refused |

Every processed record has `id` from the Rule version, `v` from the Group ID, and `sev` from Rule severity. Missing source metadata can produce null values. Manual reasons are returned separately and printed to stderr. They are not stored in `not_automated`.

| Setting fields | Contract |
| --- | --- |
| `scope` | Recognized applicability, normally `all`, `dc`, `not_dc`, `member`, or `domain` |
| `reg` | Registry path/name pair, without the HKLM hive prefix |
| `want` | Numeric/text comparison: `eq`, `in`, `ge`, or `le`, optionally `min`, `absent_ok` and `sz` |
| `no_core` | Optional true flag from the recognized registry applicability phrase |
| `audit`, `label`, `bit` | Mapped audit GUID, display name and bit 1 for Success or 2 for Failure |
| `right` | Mapped user-right constant, or a literal accepted Se-prefixed name |
| `only` | Flat permitted-holder list, including an empty list for a no-holder rule |
| `require`, `require_domain` | Required-holder groups, with SID alternatives within each group |
| `exception` | Optional true flag for recognized documentary-exception wording. It does not establish that an exception exists |

## Parser functions

All text parsers expect the annotated string/list/dictionary shapes. They perform no host collection or network requests. Ordinary unsupported text normally returns a refusal. Malformed types and numeric/regex errors can propagate.

| Function | Input and result |
| --- | --- |
| `field(line,label)` | Case-insensitive full-match using label as an unescaped regex fragment. Returns captured text or null |
| `parse_number(s)` | Nonnegative decimal or hexadecimal with optional agreeing decimal annotation. Returns int/null. No upper bound. Some Unicode digit text can raise ValueError |
| `parse_want(spec,extra)` | Comparison dictionary or null. Range forms ignore extra lines. Choice forms preserve order and duplicates |
| `registry_rule(text)` | Rule/empty-reason pair or null/refusal pair. HKLM only. Exact REG_DWORD and selected REG_SZ forms. Repeated populated hive/path/name fields are refused. Later type replaces earlier type |
| `audit_rule(text)` | Rule/refusal pair. Requires one exact Success/Failure line and a name from the audit map |
| `entry_sids(line)` | SID-alternative list or null. Preserves order/duplicates. Pattern acceptance does not validate every SID semantic rule |
| `rights_rule(text)` | Rule/refusal pair. Requires matching recognized holder-list forms and applicability. Unknown text ordinarily stays manual |
| `unknown_sentences(text)` | Whitespace-normalized fragments outside the informational regex patterns. This is not a general condition parser |
| `apply_id_scope(rule,stig_id)` | DC/MS identifiers produce shallow scoped copies or null on conflict. Other IDs return the original object. Missing required scope raises KeyError |
| `classify(text,stig_id)` | First case-sensitive marker selects registry, audit or rights parsing. A refused parser does not fall back to another parser |
| `load_benchmark(path)` | Local file to XML Element, subject to the byte/size limits above |
| `build(root,ident,name,os_re,source,source_sha256)` | Baseline dictionary and `(rule ID,reason)` list. No file writes or provenance verification |
| `agent_list(paths)` | Local baseline paths to `reg`, `audit`, `rights` arrays. No file writes |
| `main()` | CLI conversion or collection-list mode. Returns zero after successful output, including empty/partial automation |

Recognized prose patterns and dispatch rules are heuristics. They do not prove that generated logic preserves every source condition. Scope phrases use the declared pattern order. Compare the source check, generated comparison and intended host role during review.

## Collection-list output

Registry entries use `path|name`. Deduplication is case-insensitive, with the first input spelling retained. Output sorts by the lowercased key. Audit and rights lists deduplicate case-sensitively and sort their values.

`agent_list()` reads only each baseline's `rules`. It does not validate provenance or merge manual checks. File, JSON, key and type errors can propagate. Its output needs a separate reviewed agent change before collection behavior changes.

Related: [generate a baseline for review](../how-to/generate-baseline.md), [stored baseline results](windows-checks.md#baseline-results-and-api), [source](../../scripts/xccdf_rules.py).
