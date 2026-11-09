# Configure single sign-on

Connect an OpenID Connect identity provider to your organisation. You need an Assure admin session, identity-provider administration, and DNS access for each email domain.

## Connect the provider

1. Set `NIMSTEAD_PUBLIC_URL` to the server's HTTPS origin.
2. Register `<NIMSTEAD_PUBLIC_URL>/api/auth/sso/callback` as the redirect URI at the provider.
3. Open **Settings → Single sign-on (OIDC)**.
4. Enter the issuer URL, client ID, client secret, and allowed email domains.
5. Leave **Require SSO** off and save the settings.
6. Publish each TXT name and value shown under **Domain ownership**.
7. Select **Verify domains** and confirm each domain is verified.

## Test before enforcement

Sign in through the provider in a separate browser session. Confirm that the user joins the intended organisation and has the intended role. New SSO users start as members. Existing users retain their stored role.

Only then enable **Require SSO**. It disables password sign-in for non-admins. Admin password sign-ins remain available as break-glass access and are recorded with an alert attempt.

If verification fails, check the exact TXT name and value, then allow DNS propagation before retrying. If provider sign-in fails, check the issuer and exact redirect URI. Keep the existing admin session open until the new sign-in works.

Leave the issuer empty to disable the SSO configuration. The [configuration reference](../configuration.md#single-sign-on) describes the DNS resolver option.

Domain verification uses saved domains. Save a changed domain list before **Verify domains**. Verification does not submit unsaved form edits.

If you disable SSO, keep a working password-admin account available. SSO-origin users have no local password sign-in. Recheck the intended sign-in route after the change.

For stored domain verification and callback limits, see [SSO API contracts](../reference/authentication.md#sso-configuration-and-browser-flow).
