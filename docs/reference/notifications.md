# Notification reference

Notifications use a process-local background pool with two workers. Queueing, transport, and outcome storage are separate steps. The subsystem provides best-effort delivery, without a durable outbox or exactly-once guarantee.

## Settings operations

These operations require an organisation admin browser session. API tokens are refused.

| Operation | Contract |
| --- | --- |
| `GET /api/settings/notifications` | Current configuration and recent outcomes |
| `PUT /api/settings/notifications` | Save settings, record the change, and request newly added recipients' confirmation mail |
| `POST /api/settings/notifications/test` | HTTP `202` with `queued=true` once a delivery job is submitted. HTTP `409` when there is no usable destination (no webhook, and no confirmed recipient with SMTP configured) or submission failed. Five attempts per organisation per hour, refused ones included |

| PUT field | Meaning |
| --- | --- |
| `webhook_url` | HTTPS URL of at most 500 characters. Omitted/`null` keeps the value. Empty string removes it |
| `webhook_format` | `slack` or `json`. Omitted/`null` keeps the format |
| `emails` | At most ten valid email addresses. Omitted/`null` keeps the list. Empty list clears it |

Email addresses are lowercased, deduplicated, and sorted. Confirmation remains valid only for addresses retained in the list. Newly added addresses request confirmation when SMTP configuration exists and the 20-per-hour organisation quota permits.

Settings save commits before confirmation submission. A later queue or backend error can occur after the settings change. Saving an unchanged unconfirmed address does not request mail again.

Webhook configuration checks URL syntax and literal IP eligibility without DNS resolution. Delivery repeats validation with DNS and connects through the pinned-address transport. The development private-target bypass also applies. See [configuration](../configuration.md#development-only).

## Settings response

| Field | Value |
| --- | --- |
| `webhook_set` | Boolean |
| `webhook_host` | Hostname or `null`. The secret URL is not returned |
| `webhook_format` | Saved format string |
| `emails` | Configured email strings |
| `emails_confirmed` | Configured addresses also present in the confirmed list |
| `email_available` | Both SMTP URL and sender variables are nonempty. This does not test the connection |
| `last_delivery_failed` | Whether the latest row for any channel in the recent sample failed |
| `recent` | At most five delivery rows, newest ID first |

Each recent row has UTC timestamp `ts`, `kind`, `channel`, boolean `urgent`, boolean `ok`, and nullable `error`. A channel absent from those five rows contributes no failure state. This sample does not establish current receiver availability.

## Email consent and account mail

`GET /api/notify/confirm?org=…&email=…&token=…` displays a consent form. Opening the link alone does not confirm the address. POST to the same URL confirms consent and records it. Both return HTML. Failed proof returns HTML `404`. Incompatible proof values or backend failures can produce server errors.

The token binds the organisation and email through the secret-key backend. Email text is lowercased and organisation lookup uses the first 32 query characters. Generated tokens are ASCII text. There is no time-based expiry or single-use check here. Repeated confirmation is valid while the address remains configured. Removing an address makes its link invalid while absent.

Confirmation mail bypasses the confirmed-recipient list by design. It uses fixed text and the supplied link. It is not automatically retried.

Account mail also uses fixed templates: `signup`, `exists`, `invite`, and `reset`. Its failures are logged without an organisation delivery row. The account-mail helper does not automatically retry.

## Webhook payloads

| Format | Fields |
| --- | --- |
| `slack` | `text` |
| `json` | `kind`, boolean `urgent`, `text`, and `source` equal to `nimstead` |

Urgent messages prepend `URGENT: ` to text. Slack text escapes `&`, `<`, and `>` to suppress link/mention markup. A non-Slack format supplied directly to the internal helper uses the JSON payload.

Any response other than 2xx counts as a failed delivery. Redirects are not followed, so a 3xx means the alert never reached the receiver and is recorded as failed (and retried). A receiver's successful HTTP response does not prove that a person saw the alert.

The default client has HTTPX operation timeouts and no connection reuse. System DNS resolution has no explicit deadline. An injected test client can use different transport behavior.

## SMTP behavior

`smtps://` uses TLS with certificate verification. `smtp://` attempts STARTTLS when advertised. If a username exists but STARTTLS is unavailable, credentials are refused. Without a username, the SMTP path can send message content without TLS.

Socket operations use ten-second timeouts. URL username/password values are used as parsed, without percent-decoding. The sender comes from `NIMSTEAD_SMTP_FROM`.

## Recording and retry

Delivery workers attempt channels and then record their outcomes in independent database sessions. Storage failures are logged. A successful delivery can therefore lack a stored outcome. Process termination can lose queued work.

Stored messages truncate to 2000 characters and errors to 500. Retries use that stored text, so a long initial alert can be shorter on retry. Retry targets come from the current channel configuration.

Failed, un-retried rows younger than 24 hours can retry while their attempt number is below three. The window applies separately to each failed attempt row. It is not a fixed 24-hour limit from the original event.

Retry submission marks the old row retried and commits independently of completion. The returned retry count measures queued rows, not successful sends. Confirmation mail is excluded from email retries. Retry processing also removes delivery records older than 90 days.

`notify()` can wait for database lookup or key unsealing, including Vault I/O, before queue submission. It suppresses ordinary lookup/decryption/queue exceptions. It returns `True` when a delivery job was submitted and `False` when there was no organisation, no destination, or a suppressed failure; `True` does not prove delivery. The test endpoint answers 409 on `False`.

`flush()` waits for a snapshot of current pending futures without a timeout. Jobs submitted afterward need not be included. It does not return delivery outcomes.

## Silent-host monitor

The monitor flags previously reporting hosts with `last_seen` older than 14 hours and no current silent marker. It queues one message per organisation, names up to twenty hosts, then commits markers. Hosts can be marked even without a configured destination.

`monitor.json` stores `last_check` and nullable `grace_until`. A recorded check gap over two hours starts seven hours of grace. A missing state file does not itself establish an outage. State-file writes are best effort. A later inventory clears a host's silent marker.

## Related

- [Configure alerts](../how-to/configure-alerts.md)
- [Alert environment variables](../configuration.md#alerts)
- Source: [`notify.py`](../../api/src/nimstead/notify.py) and notification handlers in [`app.py`](../../api/src/nimstead/app.py)
