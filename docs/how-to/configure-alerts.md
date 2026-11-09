# Configure alerts

Send operational alerts to a webhook or confirmed email recipients. You need an organisation admin session.

## Add a webhook

1. Open the alert settings in **Settings**.
2. Enter an HTTPS webhook URL and select the receiver's format.
3. Save the settings.
4. Send a test notification and confirm it arrives at the destination.

The saved webhook secret is not displayed again. Leave its field unchanged to retain it. Select **Remove webhook on save** to remove it.

## Add email recipients

1. Configure `NIMSTEAD_SMTP_URL` and `NIMSTEAD_SMTP_FROM` on the server. See [configuration](../configuration.md#alerts).
2. Add the recipients in **Settings** and save.
3. Ask each recipient to open the confirmation link in their email.
4. Send a test notification after confirmation.

Unconfirmed recipients do not receive alerts. If a test fails, inspect its error and the server logs. Check SMTP credentials, TLS, and outbound network access before retrying.

Keep at least one verified alert destination before you enable automatic remediation.
