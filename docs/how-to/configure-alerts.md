# Configure alerts

Send operational alerts to a webhook or confirmed email recipients. You need an organisation admin session.

## Add a webhook

1. Open the alert settings in **Settings**.
2. Enter an HTTPS webhook URL and select the receiver's format.
3. Save the settings.
4. Select **Send test alert**.
5. Confirm the message at the destination.

The saved webhook secret is not displayed again. Leave its field unchanged to retain it. Select **Remove webhook on save** to remove it.

## Add email recipients

1. Configure `NIMSTEAD_SMTP_URL` and `NIMSTEAD_SMTP_FROM` on the server. See [configuration](../configuration.md#alerts).
2. Add the recipients in **Settings** and save.
3. Ask each recipient to open the confirmation link in their email.
4. Ask each recipient to select **Yes, send me alerts** on the consent page.
5. Send a test notification after confirmation.

Unconfirmed recipients do not receive alerts. If a test fails, inspect its error and the server logs. Check SMTP credentials, TLS, and outbound network access before retrying.

Confirm the test at the destination. HTTP 202 and `queued=true` mean the alert was handed to the background sender, not that it arrived; with no usable destination the request is refused with HTTP 409 and nothing is sent. Settings shows only the five latest recorded attempts.

## Send a weekly summary

1. Add a webhook or confirmed email recipients as above.
2. Select **Weekly summary** in the alert settings and save.

The first summary goes out at the next hourly feed run (after 08:00 UTC if it's a Monday), then one each week from Monday 08:00 UTC: open, fix-now and overdue findings with their change in the week, what was resolved, and the owners most overdue. It names no machine. See [Track progress](track-progress.md) and the [notification reference](../reference/notifications.md#weekly-summary).

## Request another confirmation

Saving an unchanged unconfirmed address does not send another confirmation. The quota allows 20 confirmation requests per organisation per hour.

1. Remove the address from **Settings**.
2. Save the settings.
3. Add the address again after the quota permits.
4. Save the settings again.

Keep at least one verified alert destination before you enable automatic remediation.

See [notification reference](../reference/notifications.md) for formats, retry windows, monitoring grace, and failure limits.

Test requests use saved settings. Save form edits before a test. The UI refreshes recent results once after a short delay. Reload the settings if delivery completes later.
