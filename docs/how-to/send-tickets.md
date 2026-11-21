# Send fixes to Jira or GitLab

Open one ticket per fix per team in Jira (Cloud or Data Center) or GitLab (gitlab.com or self-managed). Nimstead keeps each ticket current, closes it only when the machines' own inventory shows the fix, and reopens it if a machine is exposed again or someone closes it while findings are still open. You need an organisation admin session.

## Before you start

- Give each machine an owner (a team). See [Change asset context](change-asset-context.md). Findings on machines with no owner go to the default project, or aren't sent if you leave it empty.
- Create a token for the tracker:
  - **Jira Cloud:** an API token for the account that will open the tickets (Atlassian account settings, Security, API tokens). You also enter that account's email.
  - **Jira Data Center:** a personal access token (your profile, Personal access tokens). Leave the email empty.
  - **GitLab:** a personal, group or project access token with the `api` scope, and at least the Reporter role in each project.
- The account needs to create, edit, comment on and close issues in every project you route to.
- Set `NIMSTEAD_PUBLIC_URL` on the server so each ticket links back to its findings. See [configuration](../configuration.md).
- A tracker on a private network needs the server operator to allow its hostname with `NIMSTEAD_ALLOW_PRIVATE_HOSTS`. See [configuration](../configuration.md#outbound-requests).

## Connect the tracker

1. Open **Settings**, then **Ticketing**.
2. Choose the tracker and enter its site URL (for example `https://acme.atlassian.net` or `https://gitlab.example.com`).
3. For Jira Cloud, enter the account email. Enter the token.
4. Under **Team routes**, add each team and its project: a Jira project key such as `PAY`, or a GitLab path such as `payments/app`.
5. Enter a **Default project** for every other finding, or leave it empty.
6. Choose **Which findings become tickets**. **Fix now only** is the default.
7. Leave **Send tickets** off and select **Save ticket settings**.
8. Select **Test connection**. It says which account signed in and whether each project was found.

The token isn't shown again. Leave the field empty to keep it. A new site or tracker needs a new token: the saved one is never sent anywhere else.

## Preview, then switch on

1. Select **Preview**. It lists every ticket a sync would open now, by project, and the findings that wouldn't be sent for want of a route.
2. Adjust routes or the threshold if the list isn't what you expect, save, and preview again.
3. Select **Send tickets**, save, then **Sync now**.

The hourly feed run syncs from then on. **Sync now** can run six times an hour. Each sync makes at most 100 ticket changes, most urgent first; the rest wait for the next run and Settings says how many.

## What a ticket says

- A title such as "Upgrade openssl to 3.0.15 on 14 machines (Payments)", "Rebuild image registry.example/api:1.4 (12 findings)" or "Change SMBv1 on 3 machines".
- The priority, whether a vulnerability is known exploited, and the due date (the earliest deadline among its findings; also the tracker's due date where the project allows one).
- What to do, the machines with their installed version, the vulnerabilities, and a link to the findings in Nimstead.
- Labels: `nimstead`, the priority (`nimstead-fix-now`) and a stable `nimstead-<id>` label.

Tickets name machines (hostname and installed version), since the team needs them to act. Every value from an agent or a feed is shown as literal text, so it can't add links, mentions or markup.

## How tickets close and reopen

- When a machine is fixed, the ticket gets a comment such as "db-1 fixed 21 Nov 10:14 UTC: 3.0.15-1~deb12u1 in the machine's inventory", and the machine leaves the list.
- When no finding in the ticket is open, Nimstead comments why each machine left (fixed, risk accepted until a date, now owned by another team, removed) and closes it. On Jira it moves to the first status in the Done category, whatever your workflow calls it.
- If a finding opens again, or someone closes the ticket while findings are open, Nimstead reopens it with the machines still exposed.
- A ticket deleted in the tracker is opened again as a new ticket.

To stop tracking a finding, accept the risk in Nimstead. That's recorded in the evidence ledger and has an end date. Closing the ticket in the tracker doesn't change the finding.

## Check that it worked

- **Settings, Ticketing** shows the last sync (opened, updated, closed, reopened, failed, waiting), open tickets by project, and the last errors in the tracker's own words.
- Each finding's drawer, each fix on **Home** and each image to rebuild show their ticket as a link.
- The evidence ledger records `tickets_configured`, `ticket_opened`, `ticket_closed` and `ticket_reopened`.

## Change tracker

Choosing another tracker or site needs a new token. Nimstead asks first, then stops updating the tickets it opened in the old one (they stay there as they are) and opens fresh tickets in the new one.

See the [ticket reference](../reference/tickets.md) for the API, the sync's limits and the exact rules.
