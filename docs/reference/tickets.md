# Ticket reference

[`tickets.py`](../../api/src/nimstead/tickets.py) turns open findings into tracker tickets, one per (project, owner, fix), and keeps the tracker matching them (DECISIONS 150-153). Jira uses REST API v2, which Cloud and Data Center both serve; GitLab uses API v4.

## Settings operations

These operations require an organisation admin browser session. API tokens are refused.

| Operation | Contract |
| --- | --- |
| `GET /api/settings/tickets` | The saved settings without the token (`token_set` says whether one is saved), `last_sync`, `open_by_project`, `closed`, up to five `failing` tickets with their last error, the org's `owners` and `public_url` (whether `NIMSTEAD_PUBLIC_URL` is set) |
| `PUT /api/settings/tickets` | Save the settings below; records `tickets_configured` in the ledger with the token redacted. HTTP `409` when the tracker or site changes while a sync is running (a claim younger than 15 minutes) |
| `POST /api/settings/tickets/test` | Sign in and look up every routed project and the default one: `{ok, message}` in words. Writes nothing to the tracker. Each call has 5 seconds to answer and the whole test 60 seconds. HTTP `409` before settings are saved. Six per organisation per hour |
| `GET /api/settings/tickets/preview` | What a sync would do now, with no tracker call: `open` (`project`, `title`, `priority`), counts to `update`, `close` and `reopen`, `tickets`, `findings` and `skipped` (owners with no route and no default project, with their finding counts) |
| `POST /api/settings/tickets/sync` | HTTP `202` with `started=true`; the sync runs after the response and its result appears as `last_sync`. HTTP `409` when ticketing is off. Six per organisation per hour |

| PUT field | Meaning |
| --- | --- |
| `kind` | `jira` or `gitlab` |
| `site` | HTTPS URL with no credentials, query or fragment. A path is kept (Jira Data Center may live under one); a trailing slash is dropped and the host is lower-cased, so the same site in another case isn't a change |
| `user` | Jira Cloud: the account email the API token belongs to (Basic sign-in). Empty: the token is sent as a bearer token (Jira Data Center personal access token). Must be empty for GitLab |
| `token` | At most 2,000 characters of printable ASCII with no spaces, after surrounding whitespace is stripped; sealed at rest like the webhook URL. Omitted, `null` or empty keeps the saved one. Required when `kind` or `site` changes. Masked as `[token]` in any error the tracker or the transport returns |
| `default_project` | Where findings of unrouted owners go. Empty: they aren't sent |
| `routes` | At most 200 `{owner, project}`. Owner names take the org's spelling and compare with casefold; one route per owner |
| `min_priority` | `fix-now` (default), `next`, `planned` or `low`: findings at or above it become tickets |
| `enabled` | Off by default. Nothing is written to the tracker while it's off. Switching on needs a saved token |

Jira projects are keys (`[A-Z][A-Z0-9_]*`, upper-cased on save). GitLab projects are `namespace/project` paths. Changing `kind` or `site` deletes the org's ticket rows: Nimstead stops updating tickets in the old tracker (`forgot_tickets` in the ledger entry).

## Which tickets should be open

Every open finding whose priority is at or above `min_priority` is in exactly one group:

- On a machine, internet target, device or application: by owner and (ecosystem, package), as Fix first groups fixes.
- On a container image: by owner and image (one "Rebuild image" ticket).

A group's project is its owner's route, else `default_project`; with neither it isn't sent and is counted in `skipped`. Its fingerprint is the first 12 hex characters of SHA-256 of the project, the owner (casefolded) and the fix. A new route or owner therefore means a new ticket, and the old one closes saying the machine is "now tracked in project …" or "now owned by …".

The title says what to do and where: "Upgrade P to V on N machines (Owner)" with the highest fixed version, "Change S on N machines", "Upgrade or replace P (end of support) on N machines", "Fix P on N machines" when no fix is published, or "Rebuild image I (N findings)". At most 250 characters.

The description gives the priority, whether a finding is known exploited, the due date (the earliest of its findings' deadlines, each from the policy in force when it was first seen) and whether it's overdue, what to do, the machines with their installed versions (100 at most, the rest counted), the vulnerabilities (50 at most), a link to the findings (only with `NIMSTEAD_PUBLIC_URL`) and how the ticket closes. Labels: `nimstead`, `nimstead-<priority>` and `nimstead-<fingerprint>`. The due date is also set as the issue's due date; on a Jira project whose screen has no due date, the issue is created or updated without it.

Every value from an agent, a feed or an admin is shown inside a Jira `{noformat}` block or a GitLab fenced code block (indented, with a fence longer than any backtick run), with control, zero-width and bidirectional characters removed, so it can't add links, mentions, markup or GitLab quick actions. GitLab titles show values as code spans. Link query values are percent-encoded.

## The sync

The hourly feed run syncs every org with ticketing on, after the re-match, so a fix verified in that hour closes its ticket. Orgs go in order of their last sync, oldest first, and no new org's sync starts once the run has spent 20 minutes on tickets: the rest go first an hour later. Each org is isolated: its failure is logged and costs no other org its sync.

1. **Claim.** The org's settings row is locked and `sync_started` set and committed before any tracker call. A claim younger than 15 minutes means another sync is running and this one is skipped.
2. **Read.** The tracker state of up to 200 open tickets is read, least recently checked first; a ticket whose read fails goes to the back of the queue too. A ticket closed in the tracker is reopened in step 3; one that no longer exists is opened afresh.
3. **Write,** in this order: reopens and new tickets (exposures with no open ticket), then updates, then closes, each most urgent first (known exploited, then worst score). At most 100 ticket changes per sync; the rest are counted as `waiting`. An unchanged ticket (the same title, description, due date and labels) isn't written.
4. **Record.** `last_sync`: `at`, `opened`, `updated`, `closed`, `reopened`, `failed`, `waiting` and the last five errors, each with its ticket's key or title and project.

A sync stops early after 5 minutes, or after 5 failures in a row that say the tracker itself is failing: it can't be reached, answers with a 5xx, refuses the sign-in (401), rate-limits (429), redirects or answers with something that isn't JSON. A refusal that concerns one ticket or project (a 400 from a create screen, a 403 on one issue, a 404) is recorded against that ticket and the sync goes on. What's left waits for the next run. Each request has a 10-second timeout and each connection a 40-second total.

| Change | What happens |
| --- | --- |
| A machine leaves a ticket | The description is rewritten and a comment says why, from the evidence: fixed (with the time and the version now in the machine's inventory, or "removed" when its package list no longer has it), resolved on fresh evidence (settings, end of support, targets, devices, images), risk accepted until a date, now owned by another team, now tracked in another project, no longer sent (its owner has no route and there's no default project), priority below the threshold, or removed from Nimstead. Lists stop at 100 machines and say how many more |
| A machine joins | The description is rewritten and a comment names it |
| The priority changes | The `nimstead-<priority>` label moves; labels a team added stay |
| No machine is left | A comment says why each machine left, headed "No finding in this ticket is open any more" when they were all fixed, accepted or removed, else "No machine is left in this ticket"; the issue is closed (Jira: the first transition to a status in the Done category, with a Resolution of Done, else Fixed, else the first offered when the transition's screen asks for one; GitLab: `state_event=close`). Ledger: `ticket_closed` with counts by reason: `fixed`, `accepted`, `moved`, `unrouted`, `below_threshold`, `removed` |
| A finding opens again | The issue is updated and reopened (Jira: a transition to To Do, else In Progress) with the machines exposed now. Ledger: `ticket_reopened`, reason `regression` |
| Closed in the tracker while findings are open | Reopened as above, saying so and how to stop tracking (accept the risk in Nimstead). Reason `closed_in_tracker` |
| Deleted in the tracker | Opened afresh. Ledger: `ticket_opened` |

A ticket's row is committed before the tracker is called to create it. If the server stops between the tracker's create and saving the key, the next sync finds the issue by its `nimstead-<fingerprint>` label (Jira: `/rest/api/2/search/jql`, then `/rest/api/2/search`; an answer with an issue id and no key is followed by a read of that issue; GitLab: the issues list filtered by label) and adopts it instead of creating another.

Nimstead never changes a finding because a ticket changed. Links are built from the site URL (`{site}/browse/{key}` for Jira, `{site}/{project}/-/issues/{iid}` for GitLab), never taken from a reply. Keys are checked (`[A-Z][A-Z0-9_]{0,49}-N` for Jira, a positive integer for GitLab, before it's used in a path); replies over 1 MB, redirects, non-JSON replies and replies of the wrong shape are errors.

## Outbound requests

Tracker requests use the same guard as webhooks and SSO: HTTPS only, every resolved address public, the connection pinned to the checked address, no redirects. A server operator can allow named hosts on a private network with `NIMSTEAD_ALLOW_PRIVATE_HOSTS` (comma-separated hostnames, exact match in any case). Those hosts may resolve to private and loopback addresses, never link-local, a cloud's metadata address (`100.100.100.200`, `fd00:ec2::254`), multicast, unspecified or reserved ones; an IPv4 address carried inside an IPv6 one is judged as itself. The setting applies to webhooks, SSO and trackers, not to outside-in scans. Org admins can't change it, but **every org on the server can reach a named host**, on any port and path: on a server shared by several organisations, name only hosts every one of them may use.

## Ticket links

`GET /api/findings/{finding_id}` returns `ticket`, `GET /api/summary` returns `tickets` on each Fix first action (one per team behind it) and `ticket` on each image to rebuild: `{key, url, state, project}` for tickets that reached the tracker. GitLab keys read `#iid`. Sessions and read-only API tokens can read them.

## Related

- [Send fixes to Jira or GitLab](../how-to/send-tickets.md)
- [Findings](findings.md)
- [Notification reference](notifications.md)
