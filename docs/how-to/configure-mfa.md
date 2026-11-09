# Set up or replace an authenticator

Add two-step sign-in to a password account, or move it to another authenticator. You need a signed-in account and an authenticator app. For replacement, you also need a current code or an unused recovery code.

SSO-origin accounts use the identity provider's MFA controls. This procedure applies to local password accounts.

## Configure the authenticator

1. Open **Settings → Your account → Sign-in and security**.
2. Select **Turn on two-step sign-in** or **Move to a new authenticator**.
3. Scan the QR code with the new authenticator app.
4. Enter a current code or recovery code if the replacement form requests one.
5. Enter the code from the new authenticator under **Code from the app**.
6. Select **Turn on**.
7. Save the new recovery codes in your protected credential store.

If the scanner cannot read the QR code, enter the displayed **Setup key** into the authenticator instead. The setup URI and key contain the same secret.

A successful replacement changes the stored authenticator secret and replaces the recovery-code set. Old recovery codes no longer work. Existing recovery codes can remain visible while a replacement setup is incomplete. Save the newly returned set after success.

## Verify a separate sign-in

Keep the current browser session open until the test succeeds.

1. Open a separate browser session.
2. Sign in with the account's email and password.
3. Enter a fresh code from the new authenticator.
4. Confirm that the expected account opens.

Each authenticator time-step code works once. Wait for the next code if the current one was already used for setup. Each recovery code also works once.

## Recover from a failed setup

If the server rejects the setup code, read the error and check the authenticator clock. Request a new setup if it reports expiry.

If the response is lost, inspect account state before another change. A successful replacement can commit before the browser receives its recovery codes. Test a separate sign-in with the new authenticator. Preserve your current session until recovery succeeds.

If the old authenticator is unavailable, use an unused recovery code for replacement. If neither is available, contact your operator. A password-reset email does not bypass the existing MFA requirement.

Related: [SSO configuration](configure-sso.md), [web account contracts](../reference/web-client.md#authenticator-and-account-state).

For session and recovery effects, see [authenticator operations](../reference/authentication.md#authenticator-operations-and-account-recovery).
