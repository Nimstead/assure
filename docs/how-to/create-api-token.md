# Create a read-only API token

Create an expiring credential for an integration that reads organisation data. You need an organisation admin browser session. Password admins also need their authenticator or an unused recovery code when the server requires it.

## Create the credential

1. Open **Settings → Access → API tokens**.
2. Enter a name that identifies the integration.
3. Select 30 days, 90 days or one year.
4. Enter an authenticator code if the form requests one.
5. Select **Create token**.
6. Copy **New token (shown once)** to the integration's secret store.

Copy the secret before another creation attempt or page reload. The server does not return an existing token's secret. Another submission clears the displayed secret even if that new request fails.

## Verify access

Configure the integration to send `Authorization: Bearer TOKEN` to the intended Assure server. Replace `TOKEN` with the new secret.

Request `GET /api/me` with the integration's HTTP client. Confirm the expected organisation and creator identity. Then request the required read endpoint, such as `/api/assets`.

A token acts as its creator and permits supported GET/HEAD operations. Admin-only and person-only endpoints still refuse it. See [HTTP credentials](../reference/http-api.md#credentials) for the accepted routes and limits.

## Revoke or replace a token

If creation fails, read the displayed error before another attempt. If the secret is lost, create a replacement and revoke the inaccessible token.

1. Locate the token by its name and creator under **API tokens**.
2. Select **Revoke**.
3. Confirm **Revoke token** in the dialog.
4. Request the same read endpoint with the revoked credential.
5. Confirm that the server refuses the credential.

Revocation cannot be reversed. If you replace a live integration token, verify the new credential before revoking the old one.

Creator demotion, removal, password change, or **Sign out everywhere** can also revoke tokens. A password reset revokes them too. Keep the integration's credential owner and expiry in its operational record.
