# Authentication and account API reference

This reference defines account, session, token and SSO operations. The [HTTP reference](http-api.md) defines shared body limits and credential families.

## Session and permission checks

| Check | Behavior |
| --- | --- |
| Current user | Exact Bearer nmt_ prefix takes precedence over the session cookie. Other authorization headers fall through to session lookup |
| Read token | Creator must remain an admin in the same organisation. Only eligible GET/HEAD operations accept it |
| Browser person | Refuses organisation API tokens, without a fresh password/code requirement |
| Organisation admin | Refuses nonadmins and API tokens. Password-origin admins need configured local MFA outside open-signup development mode |
| Write Origin | When present, Origin must match the request origin or configured allowlist. Absence does not independently refuse the request |

Invalid/expired credentials return 401. Read-token writes and role/session refusals return 403. A valid browser cookie does not override an invalid nmt_ bearer.

Browser sessions have a 14-day absolute lifetime and 12-hour idle limit. Last-use refresh occurs after five minutes. That refresh commits database changes, including on GET. Token last_used refresh uses the same interval. Proxy/Host configuration determines request identity and fallback public origins.

start_session commits the session and pending caller changes before setting the cookie. Response loss does not undo the session. It does not revoke earlier sessions. Cookies are HttpOnly and SameSite=Strict, with Secure controlled by server configuration.

Admin checks inspect stored MFA configuration. They do not independently require a fresh code for every action. SSO-origin users rely on provider authentication, and local mfa fields do not report provider MFA state.

## Password signup and login

| Operation/branch | Response and effects |
| --- | --- |
| POST /api/auth/signup, first account | HTTP 201: email, org, next=signin. Create organisation/admin. No session |
| Signup with open-signup development mode | HTTP 201: email and org. Create organisation/admin and a session |
| Later production signup | HTTP 202: status=check_email and email. SMTP configuration required. Mail can be suppressed or fail |
| POST /api/auth/login, existing authenticator without code | HTTP 200: mfa=required. No new session |
| Password-admin login without configured authenticator | HTTP 200: mfa=setup, setup, secret and uri. No new session |
| Successful password login | HTTP 200: email, with recovery_codes only after initial authenticator setup. Create a session |
| POST /api/auth/logout | HTTP 204. Delete the cookie-selected session and clear that cookie. Other sessions/tokens remain |

Signup accepts a valid email, organisation name of 1–200 characters and optional password of 12–200 characters. The first/development branch requires a password. Later production signup chooses its password through the email link.

Login accepts email, password up to 200 characters, optional code up to 40 and setup up to 1000. Password/code refusals return 401. Required SSO refuses nonadmin password login with 403. Password-admin break-glass login remains possible and records evidence plus an alert attempt.

A 200 login response can be an unfinished challenge. Only successful completion creates a new session. Setup/secret/uri contain sensitive authenticator material. A stored password account that signs in through SSO retains its origin and role.

## Account email links

| Operation | Behavior |
| --- | --- |
| POST /api/auth/password/reset | HTTP 202: status=check_email/email for unknown, SSO and password accounts. Eligible password accounts receive a link attempt |
| POST /api/users/invite | Admin browser operation. HTTP 202: status=invited/email regardless of existing account. SMTP and quota checks apply |
| GET /api/auth/signup/confirm?token=… | Password-selection HTML. Does not consume the token or create a session |
| POST to the same URL | URL-encoded password field. Completes signup, invitation or reset |

Signup/invitation links expire after 24 hours. Reset links expire after one hour. A newer link replaces the same email/purpose/organisation link. Invitations from different organisations do not replace each other. Only token hashes are stored.

The pending link commits before the mail request. Delivery is best effort. A successful acknowledgement does not prove that mail was sent or received. Existing accounts receive sign-in guidance rather than an invitation-based membership transfer.

| Confirmation result | Session and token effects |
| --- | --- |
| Invalid/expired token | HTML 404. No successful completion |
| Password outside 12–200 characters | HTML 422. Link remains available |
| Signup success | Create organisation/admin, consume link, redirect to /signin?created=1. No session |
| Invitation success | Create a member in the existing organisation, consume link, establish a browser session and redirect home |
| Password reset success | Replace password, revoke browser sessions and creator API tokens, consume link, redirect to /signin?reset=1 |
| Existing account during signup/invitation, or missing invitation organisation | HTML 409 after link consumption |

Reset preserves the authenticator secret and recovery codes. It does not bypass MFA. Confirmation does not independently lock the pending row against concurrent use. Database constraints or later backend failures can still refuse completion.

## Authenticator operations and account recovery

| Operation | Inputs, response and effects |
| --- | --- |
| POST /api/me/mfa/setup | Browser session. Password-origin user only. Return setup, secret, uri without changing stored MFA |
| POST /api/me/mfa | setup, new code, optional current_code. Return recovery_codes after commit |
| POST /api/me/password | current password, new password of 12–200 characters, optional code. HTTP 204 after commit |
| POST /api/me/sessions/revoke | Browser session. HTTP 204 after all this user's browser sessions and API tokens are deleted |

Setup proposals expire after 600 seconds. Replacement requires the existing authenticator or an unused recovery code when local MFA exists. Successful replacement overwrites secret/recovery hashes. It leaves existing sessions and API tokens intact.

TOTP time steps and recovery codes are consumed when their transaction commits. The helper stages these changes and uses row locking where supported. SQLite does not provide PostgreSQL's row-lock behavior.

Password change preserves the current cookie's session and deletes other sessions and creator API tokens. It preserves the authenticator. Sign out everywhere requires no fresh code. Neither action selects agent, upload or enrolment credentials for revocation.

The setup result or recovery-code list is shown once by the client flow. A lost response can follow a committed change. Current account state and a separate sign-in test determine recovery, rather than response text alone.

## Identity and member fields

GET /api/me accepts a session or eligible read token. It returns email, org, admin, origin, mfa and recovery_codes_left. mfa means a stored local secret. recovery_codes_left is the stored hash count.

Admin browser operations manage members:

| Operation | Behavior |
| --- | --- |
| GET /api/users | Email-sorted user records without pagination |
| PATCH /api/users/{user_id} | Set admin Boolean. Refuse the last admin's demotion with 409 |
| DELETE /api/users/{user_id} | Delete user, sessions and API tokens. Refuse the last admin's removal with 409 |

Each user record has id, email, admin, origin, mfa and created. User lookup uses the first 32 ID characters. Missing/differently owned users return 404. The organisation row is locked where supported before last-admin changes.

Promotion deletes existing browser sessions. Demotion deletes API tokens but preserves browser sessions. An unchanged role returns the record without a role-change commit. Removal and changed roles append evidence and commit. Other asset credentials remain independent.

## Read-only organisation API tokens

| Operation | Result |
| --- | --- |
| POST /api/tokens | HTTP 201: token, id, name, expires. Raw token appears once |
| GET /api/tokens | Metadata array, newest created first. Admin browser session required |
| DELETE /api/tokens/{token_id} | HTTP 204 after token deletion and evidence commit |

Creation accepts name of 1–100 characters, days from 1–365 with default 90, and optional code up to 40 characters. A stored local authenticator requires a current factor. SSO-origin accounts without one have no extra local-code challenge here.

Metadata has id, name, created_by, created, expires and last_used. Expired records remain listed. Display IDs use twelve-character hash prefixes. Revoke requires exactly twelve characters. Prefix collisions are not independently disambiguated.

Token lookup requires its creator to remain an admin. Demotion, removal, password change/reset and sign out everywhere revoke creator tokens. A token cannot read the admin-only token list or person-only routes.

## Enrolment tokens

| Operation | Result |
| --- | --- |
| POST /api/enroll-tokens | Admin browser operation. Optional sandbox Boolean defaults false. HTTP 201: token, id, expires |
| GET /api/enroll-tokens | Session/read-token operation. Metadata array, newest created first |
| DELETE /api/enroll-tokens/{token_id} | Admin browser operation. HTTP 204 after marking revoked |

Tokens expire after 30 days. Metadata has id, created, expires, revoked and sandbox, including expired/revoked entries. Prefix IDs have the same twelve-character collision limit. Repeated revocation appends another event. Revocation prevents later enrolment, while issued agent keys remain independent.

For enrolment creation effects, see [agent enrolment](assets-api.md#agent-enrolment).

## SSO configuration and browser flow

GET/PUT /api/settings/sso and POST /api/settings/sso/verify require an admin browser session. Responses have issuer, client_id, client_secret_set, domains, required, redirect_uri and domain_checks. Each domain check has domain, verified, txt_name and txt_value.

PUT replaces the configuration. Omitted issuer defaults empty and disables SSO, clearing credentials/domains. With an issuer, client ID, a stored/new secret and domains are required. Empty/null client_secret preserves the existing secret. Domains normalize case/whitespace, deduplicate and sort. Removed domains lose stored verification.

Input limits are issuer 500 characters, client ID 300, secret 500 and at most twenty domain strings. Invalid URL/domain/configuration returns 422. A domain already verified by another configured organisation returns 409. Saving does not test provider login.

Verify checks only saved domains that are unverified and not claimed elsewhere. Previously verified domains retain that state without another TXT check. Removal of their TXT records does not independently revoke stored verification. The response describes saved state.

POST /api/auth/sso/start accepts URL-encoded email or org. An organisation ID takes precedence over email-domain selection. It creates a state/nonce/PKCE flow with a 600-second expiry, commits it and returns 303 to the provider. A scoped HttpOnly/Lax cookie binds the browser flow. A newer flow replaces that cookie.

GET /api/auth/sso/callback consumes any found pending row before cookie, expiry and provider checks. The provider must return a verified email in a saved verified domain. A cross-organisation existing account is refused. New SSO users are members. Existing users keep stored role and origin.

Success commits a session and redirects home. Known errors redirect to sign-in with sso_error and clear the flow cookie. Other backend/storage failures can propagate after pending-flow consumption. A callback request alone does not establish a completed login.

## Quotas and failure effects

| Operation | Limit |
| --- | --- |
| Signup/reset request | Ten per client address per hour, independently |
| Signup/invitation address mail | Three per address per hour in their shared address-mail bucket |
| Reset address mail | Three per eligible address per hour |
| Invitations | Twenty per organisation per hour |
| Password login failures | Ten per email+address or address in fifteen minutes. Email-wide threshold is 100 with an already failing address |
| MFA login failures | Ten per account in fifteen minutes |
| Password change, MFA confirmation, MFA-protected token creation | Ten attempts per relevant account bucket in fifteen minutes |

IPv6 client addresses share a /64 rate key. Proxy configuration determines the observed client. Quota operations commit attempts, including refusals, and can commit caller changes. They are not atomic reservations across concurrent requests.

Storage, credential-hash, secret-key and evidence failures can occur after earlier commits. Account mail and alert attempts do not guarantee delivery. API schema errors are not an exhaustive list of runtime exceptions.

## Related

- [Set up or replace an authenticator](../how-to/configure-mfa.md)
- [Create a read-only API token](../how-to/create-api-token.md)
- [Configure SSO](../how-to/configure-sso.md)
- [Notification delivery contracts](notifications.md)
