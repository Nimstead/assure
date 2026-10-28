# Implementation Plan (0.5): UI/UX round 1 — safe controls, connected journeys, one design system

## Overview
A senior UI/UX review of `web/` on 2026-10-28. It covered the live demo database at 1440 px and 375 px in light and dark, a code audit of every `web/src/*.tsx`, a heuristic design review, and the Impeccable detector (clean, 0 findings).

The UI is good. Every text token passes AA contrast. Dialogs are Radix. Findings state lives in the URL. The mobile tab bar and card reflow work with no overflow. The copy explains itself ("would also change: musl"). It scored **25/40 on the Nielsen heuristics** and **14/20 on the technical audit**.

What holds it back:
- **Unsafe controls:** one click or one arrow key turns on unattended fixes, and destructive actions have no confirmation.
- **Disconnected journeys:** Home offers "Plan fix" for fixes already in flight, and a finding, its job and its evidence don't link to each other.
- **Primitive drift:** a modal shell copied 4×, a switch 3×, 10 error-line variants, success feedback on some saves and not others.

This plan fixes those with the smallest changes, reusing what exists. **No visual redesign.** The "Plain Sight" identity stays: ink on paper, Archivo + Geist Mono, square corners, crimson only for "Fix now" and KEV.

## Goal: done when
All of these hold. Each task's own "Done when" is the detail.
- [ ] Every task T1–T18 below is checked off with its "Done when" met.
- [ ] `cd web && npm run lint && npm test && npm run build`: clean, and the new tests pass.
- [ ] `cd web && npm run e2e`: passes, with axe at 0 serious/critical at **1440 and 375, light and dark**, including the open dialogs added in T16.
- [ ] `cd api && uv run pytest -q` passes (T4, T6 and T12 touch the API), and `uv run ruff check src tests` is clean.
- [ ] `cd web && npm audit` reports 0 vulnerabilities after T18 adds `uqr`.
- [ ] `~/.claude/skills/impeccable/scripts/impeccable detect --json web/src` still reports `[]`.
- [ ] CHANGELOG has an "Unreleased" entry. STATUS.md has a row for this round with its evidence. No version bump or release, which is the owner's call.

## What exists (reuse, don't rebuild)
- **`web/src/ui.tsx`:**
  - Class strings `btn`, `btnPrimary`, `btnQuiet`, `input`.
  - Components `PriorityPill`, `KevBadge`, `Skeleton`, `ErrorState`, `EmptyState`, `CopyBlock`.
- **Primitives living in the wrong file** (move them, don't rewrite them):
  - `Field` in `integrations.tsx:7`.
  - `Alert` and `Done` in `people.tsx:9-10`.
  - `StatusPill` in `remediation.tsx:15`.
- **The enrolment-token revoke `AlertDialog`** (`settings.tsx:186-200`) is the confirmation pattern to extract.
- **Radix** (`radix-ui`) for Dialog, AlertDialog, RadioGroup and DropdownMenu. Focus trap and return are already handled.
- **URL state:** the findings filter ↔ URL round trip in `lib.ts:189-206` and `main.tsx:29-45`. Copy that pattern for any new URL state.
- **API guards:** `remediate.plan` already refuses a duplicate job with 409 "already in progress" (`remediate.py:72`). The `cancelled` job status already exists (`app.py:1636`).
- **Tests:**
  - e2e with axe and a 375 px overflow check in `web/e2e/app.spec.ts`.
  - Screenshots written to `web/e2e-screenshots/`.
  - README shots from `web/scripts/readme-shots.mjs` (demo DB).

## Decisions
1. **Confirm only what's high-stakes or hard to undo:**
   - Trust ladder → Auto.
   - Revoking an API token.
   - Removing a user or changing a role.
   - Sign out everywhere.
   - Cancelling a job.
   
   Low-stakes autosaves (criticality, ring, internet-facing) keep autosaving, and gain a visible "Saved" plus a re-rank note.
2. **One `ConfirmDialog`** in `ui.tsx`, extracted from the enrolment-token AlertDialog. `window.confirm` goes.
3. **Square stays.** The `rounded-full` leaks (filter chips, Met pill, "Selected" badge) and `.skeleton`'s 6 px radius are removed. The ~85 dead `rounded-md/lg/xl` classes do nothing under the zero-radius tokens and are left alone (pure churn).
4. **The server answers "is a fix already in flight?"** The summary API adds it per action, so Home never offers a button the API will refuse.

Decisions 5–7 were approved by the owner on 2026-10-28.

5. **Evidence gets a third status, `no_activity`, labelled "No activity in period".**
   - **The problem:** "Met" on a timeliness control with nothing to assess overstates the evidence. An auditor reading a signed pack should never have to work out that "1 of 1" really meant "0 of 0".
   - **Which controls:** only those whose status is *only* about fixes or changes:
     - **Cyber Essentials, security update management:** no in-scope fixes in the period and none overdue.
     - **NIST SI-2:** no fixes in the period and none overdue.
     - **CIS 7.3 / 7.4:** no fixes in the period and none overdue.
     - **SOC 2 CC8.1:** no remediation changes in the period.
   - **Which controls keep "Met":** those that include monitoring (A.8.8, RA-5, CC7.1, NIS2) or make a true negative statement (PCI 6.3.3, "0 critical open > 30 days"). Their claim is real even when nothing was fixed.
   - **Overdue findings still mean `not_met`.** `no_activity` never hides a failure.
   - **The pack format stays `nimstead-evidence/1`:**
     - The value is additive.
     - `verify_pack.py` doesn't read statuses.
     - The CHANGELOG and DECISIONS call it out for anyone parsing packs.
6. **Onboarding asks "test or production?" with no preselected answer.**
   - **Why the choice matters:**
     - Sandbox is fixed per machine at enrolment. It's carried by the enrolment token (`app.py:611,756`), and there's no API to change it later.
     - Unticked by default means the first fix is refused as a surprise.
     - Ticked by default means real machines become fixable by default.
   - **The change:** two radio cards, each stating its consequence, and the token button stays disabled until one is chosen. Secure, explicit, and no surprise later.
7. **TOTP setup shows a QR code**, rendered in the browser with `uqr` (MIT, zero dependencies, ~80 kB unpacked, pinned to the exact version `0.1.3`).
   - Use its `encode()` matrix drawn as React `<svg>` rects. No `innerHTML`, so the CSP is unaffected.
   - The `otpauth://` URI never leaves the page. It is already sent to the browser today (`mfa.py:37`, `people.tsx:18`).
   - The typed key stays as the fallback.
   - Rejected:
     - A server-side PNG: a new Python dependency in the security-critical server, and the secret travels in an image response.
     - A hand-written QR encoder: hundreds of lines to maintain.

## Not doing (this round), and why
- **Bulk actions on findings, and column sort:**
  - Both need new API endpoints and parameters.
  - Findings are already ordered by score.
  - Next round, if users ask.
- **Per-host edit drawer replacing the inline asset controls:** T7's "Saved" feedback fixes the actual complaint (silent re-scoring) with far less code.
- **Command palette searching hosts and jobs:**
  - It's useful but it's a feature, not a fix.
  - T13 only debounces it and announces the results.
- **Ledger filtering and paging, and evidence deep links per control:**
  - The pack is the auditor's real artifact.
  - Revisit with auditor feedback.

## Needs the owner
Nothing open. Decisions 5–7 settled the three earlier questions on 2026-10-28.

## Dependency graph
```
T1 ConfirmDialog + move primitives to ui.tsx ──► T2 trust ladder, T3 people/tokens, T6 job cancel, T7 save feedback
T4 summary API: asset_ids + job per action ──► T5 Home/drawer "fix in progress" + cross-links
T6 job cancel (API + UI)
T8 focus/selected states · T9 touch targets · T10 visual drift   (independent, after T1)
T11 onboarding · T12 evidence (API + UI) · T13 a11y batch · T14 settings sections · T15 code-split   (independent)
T18 TOTP QR code   (before T15, so the QR code lands in the lazy auth/settings chunks)
T16 tests (alongside each task; final axe sweep last) ──► T17 docs + screenshots (last)
```

## Task list

### Phase 1: Safety (P0/P1) — first

**T1 Shared primitives in `ui.tsx`**
- **Add `ConfirmDialog`:** extract it from `settings.tsx:186-200`. Props are title, body, confirm label, destructive flag, onConfirm and pending.
- **Move `Field`, `Alert`, `Done` and `StatusPill` into `ui.tsx`:**
  - `Field` comes from `integrations.tsx:7`, `Alert` and `Done` from `people.tsx:9-10`, `StatusPill` from `remediation.tsx:15`.
  - Update their imports.
- **Add `Loading`:** it wraps `Skeleton` in `aria-busy` plus an sr-only "Loading…".
  - Use it at the bare skeleton sites: `assets.tsx:50`, `remediation.tsx:42`, `evidence.tsx:31,37`, `settings.tsx:30,167`, `people.tsx:101,139`, `integrations.tsx:24,112`.
- **Replace the 3 copied modal shells with `ConfirmDialog` or the existing Radix Dialog shell:** `assets.tsx:65,173` and `remediation.tsx:126`. Delete the copies.
- **Done when:**
  - No page defines its own `Alert`, `Done`, `Field` or modal shell.
  - `grep -rn "window.confirm\|confirm(" web/src` is empty, after T3.
  - Existing tests pass.

**T2 Trust ladder can't switch itself to Auto** (`settings.tsx:53`)
- **Today:** `RadioGroup` saves on `onValueChange`, so arrowing from Approve saves Auto. That is unattended production-capable remediation with no confirmation.
- **Change:**
  - Keep the selection in local state, and add a Save button like the deadlines form, disabled until something changes.
  - Saving `auto` opens `ConfirmDialog`. Its body names the number of machines and "canary first, then everything else after the soak".
- **Done when:**
  - A vitest shows that arrow keys only change the selection, with no request made.
  - Saving Auto requires the confirm.
  - Suggest and Approve save without a dialog.

**T3 People, tokens and SSO domain status** (`people.tsx`, `integrations.tsx`)
- **"Verified" on an SSO domain is invisible** (`integrations.tsx:77`):
  - It uses `text-accent-ink`, which measures 1.08:1 in light and 1.00:1 in dark.
  - Use `text-ink` plus a `CircleCheck` icon, as `targets.tsx:60` does.
- **Add `ConfirmDialog` to:**
  - API token revoke (`:145`): it breaks integrations.
  - Remove user (`:108`): this replaces `window.confirm`.
  - Make admin / make member (`:107`).
  - Sign out everywhere (`:83`).
- **Hide the role and remove buttons on your own row**, the one marked "(you)".
- **Per-row pending:** disable only the row whose action is running, using `mutation.variables`, not every row.
- **Done when:**
  - A vitest covers revoke → dialog → request.
  - Your own row has no role or remove buttons.

**T4 Summary API: what Home needs per action** (`app.py:1616-1624`)
- **Add to each `top_actions` item:**
  - `asset_ids`.
  - `job`: the newest non-terminal or failed job for that package on those hosts, as `{id, status}` or `null`. Reuse the jobs join already at `app.py:1633`.
- **`PlanFixButton`** (`remediation.tsx:144-162`; callers are `home.tsx:108`, `findings.tsx:243` and `ui.test.tsx:92`): take `assetIds` instead of fetching up to 5,000 findings to resolve host names. The finding drawer already has `f.asset_id`.
- **Done when:**
  - An API test asserts `asset_ids` and `job` on a summary with one approved job.
  - No `/api/findings?…limit=5000` request is left in `web/src`.

**T5 Connected journeys**
- **Home:** when `action.job` is set, show `StatusPill` plus a "View fix" link to `/remediation` instead of "Plan fix".
- **Finding drawer** (`findings.tsx:239-247`): when a job exists for that package on that asset, show a "Fix in progress" line with `StatusPill` and a link, in place of "Plan fix".
  - Use the `["jobs"]` query that's already cached by Remediation.
- **Remediation job card** (`remediation.tsx:73-79`):
  - The hostname links to `/findings?asset=<id>`.
  - The summary links to `/findings?asset=<id>&q=<package>`, using the existing URL filter.
- **Done when:**
  - e2e: Home shows "View fix" for the package approved earlier in the spec.
  - Clicking the job's host lands on its filtered findings.

**T6 Cancel a job that hasn't started**
- **API:** `POST /api/remediation/jobs/{id}/cancel`.
  - Admin only.
  - Allowed only from planned or awaiting-approval states. Anything an agent may already hold gets 409.
  - Sets `cancelled` and writes a ledger entry, like other job transitions.
- **UI:** a "Cancel" `btnQuiet` on those cards, behind `ConfirmDialog`.
- **Why:** today a planned job can't be withdrawn, and it blocks re-planning ("already in progress").
- **Done when:**
  - API tests cover allowed, refused-when-running, non-admin 403 and the ledger entry.
  - A vitest shows the button only on cancellable states.

### Phase 2: Feedback, focus, touch, drift

**T7 Visible save feedback everywhere**
- **Use `Done` ("Saved") after a successful save:**
  - Soak (`settings.tsx:76`), deadlines (`:94`), trust ladder (T2) and the pause switch (`:110`).
  - SSO and alerts (`integrations.tsx:55,157`).
  - Asset criticality, ring, internet-facing and health units (`assets.tsx:19-31`).
- **Asset saves also say the findings were re-ranked.**
- **The deadlines form disables Save until something changes.**
- **Done when:** every mutation in `web/src` has visible success, pending and error states. The executor lists each one in its report.

**T8 Focus and selected states that meet 3:1**
- **Where `bg-accent-soft` is the only cue:**
  - More-menu items (`shell.tsx:123,127`, which also set `outline-none`).
  - Palette options (`shell.tsx:193`).
  - The selected status filter (`findings.tsx:78`).
  
  `bg-accent-soft` alone measures 1.17:1 in light and 1.21:1 in dark.
- **Fix:** add an outline or border with `outline-focus` or `border-ink`, plus `aria-pressed` or `aria-selected` where it's missing.
- **The drawer close button:** autofocus currently gives it a crimson ring that reads as an error. Focus the drawer heading (`tabIndex=-1`) instead.
- **Done when:** a manual keyboard pass through the menu, palette and filters shows a visible indicator. Record the measured ratio in the PR.

**T9 Touch targets ≥ 44 px on phones**
- **Add `max-md:min-h-11`:**
  - On `btn` (`ui.tsx:6`), which flows to every button.
  - On the filter chips (`findings.tsx:78,88,95,335`).
  - On `CopyBlock`'s button (`ui.tsx:57`).
- **Pad to 44 px:**
  - The per-asset arrow link (`assets.tsx:107`).
  - The drawer close button (`findings.tsx:192`).
  - The mobile header icons (`shell.tsx:57`).
- **Make "Forgot password?" (`auth.tsx:123`) a padded link.**
- **Separate Sign out from the theme toggle in the mobile header**, or move it into More, so it's hard to hit by accident.
- **Done when:** an e2e step at 375 asserts every visible `button, a, select, input` in `main` and `nav` is ≥ 44 px tall. Inline text links are exempt and listed.

**T10 Visual drift**
- **Remove `rounded-full`** from the chips (`findings.tsx:88`), the Met pill (`evidence.tsx:68`) and the "Selected" badge (`settings.tsx:58`). Remove the 6 px radius on `.skeleton` (`index.css:75`).
- **Retint the overlay** at `index.css:79` from blue-hued to the neutral ink.
- **Home "Low" tile:** the count uses `text-ink`, not muted, so it doesn't read as disabled.
- **Give the "Planned" pill a background distinct from the surface** (`index.css:26-27`).
- **Assets header at 375:** the title sits on its own line, with the buttons in a row below.
- **Remediation metadata at 375:** separators sit inside each item (`remediation.tsx:77-79`) so lines never start with "·".
- **Shared fixes:**
  - One Switch class in `ui.tsx` replaces the 3 copies (`assets.tsx:119`, `findings.tsx:99`, `settings.tsx:110`).
  - One `Tag` replaces the 6 hand-written 11 px bordered tags.
  - `role="alert"` error lines use `Alert`.
- **Done when:**
  - The screenshots in T17 show no rounded elements, no line-leading "·" and an un-muted Low tile.
  - `grep -n "rounded-full" web/src` matches only real circles (status dots, the switch thumb).

### Phase 3: Journeys and structure

**T11 Onboarding** (`onboarding.tsx`)
- **Replace the sandbox checkbox (`:24,82,85`) with a required choice (Decision 6).** Use a Radix `RadioGroup` of two cards with no default:
  - **"Test machines":** "Automated fixes may change these machines. Use for disposable or staging hosts."
  - **"Production machines":** "Nimstead finds vulnerabilities here. Fixes stay off until production remediation is turned on for this server."
  - Under both: "This is fixed for every machine enrolled with this command."
  - The token button is disabled until one is chosen.
- **Make the button label match its step** (`:87`): "Create install command" or a reworded step.
- **Title** (`:60`): "Add a machine" once one exists, instead of always "Add your first machine".
- **Waiting for the first report** (`:71`):
  - After 2 minutes, show a troubleshooting list: the agent's last run, firewall to the server, the Python requirement on Windows, and the docs link.
  - Surface the Windows Python requirement as text, not only inside a copy label (`:13`).
- **Replace the timed auto-redirect (`:38-40`) with a "Go to Fix first" button.**
- **Remediation refusal on a production machine:** the refusal text links to Settings, so the "why" is one click away.
- **Done when:**
  - Vitests cover:
    - The token button disabled until a choice is made.
    - Each choice posting the right `sandbox` value.
    - The troubleshooting list appearing on a fake timer.
  - The e2e onboarding passes, after updating it to pick a choice.

**T12 Evidence** (`evidence.tsx`, `api/src/nimstead/evidence.py`)
- **API, per Decision 5** (`_controls`, `evidence.py:157-187`):
  - Return `no_activity` for Cyber Essentials, SI-2, CIS 7.3/7.4 and CC8.1 under the stated conditions.
  - Overdue findings always win, giving `not_met`.
  - The evidence string stays as it is.
- **API tests** (`api/tests/test_evidence.py`):
  - A period with no fixes and nothing overdue gives `no_activity` for those four, and `met` for RA-5 and PCI 6.3.3.
  - An overdue finding still gives `not_met`.
  - A pack with `no_activity` still verifies with `verify_pack.py`.
- **Before changing anything,** grep `sandbox/*.py` for checks on control statuses, and update any harness that asserts "every control met".
- **UI:**
  - Widen `Control.status` in `lib.ts:74` to `"met" | "not_met" | "no_activity"`.
  - Render the third state as a neutral bordered tag, "No activity in period", with a `CircleMinus` icon. Not green, not crimson.
  - Any "N of M controls met" summary counts `no_activity` separately.
- **Put the period in the URL** (`?period=`), copying the findings pattern (`evidence.tsx:12`).
- **Show the period's dates and an "as of" time.**
- **Show each control's evidence counts** (already in `evidence`) directly under the status, so they're visible without reading small print.
- **Mobile:** move Evidence into the visible tab bar instead of More, for auditors. Remediation or Assets moves to More; pick whichever the e2e nav test shows as used less, and note the choice.
- **Done when:**
  - Reloading keeps the period.
  - e2e at 375 reaches Evidence in one tap.

**T13 Accessibility batch**
- **Findings table:**
  - `aria-rowcount` +1 and `aria-rowindex` +2 to count the header (`findings.tsx:146,154`).
  - Cells below `md` get sr-only column labels like Score already has.
  - `scrollMargin` comes from a measured state, not a ref read during render (`:142`).
- **`adminGate`** (`lib.ts:255`):
  - Pages show one visible line for non-admins: "Read-only — ask an organisation admin to change this."
  - Buttons use `aria-disabled` plus `aria-describedby` pointing at that line, instead of a `title` on a disabled button.
- **Palette** (`shell.tsx:144,364`):
  - Debounce the query by 150 ms.
  - Announce "N results" in a polite live region.
  - Set `aria-expanded` only when the list is shown.
- **Theme toggle** (`lib.ts:238-243`, the `index.html` script):
  - Three states: System, Light and Dark. System clears the stored value.
  - The label names the current state.
- **Reduced motion** (`index.css:88-91`): also cover transitions.
- **Settings:** the old platform-update failure (`settings.tsx:145`) moves from `role="alert"` to plain text.
- **Timestamps:**
  - Use `parseUtc` instead of a hand-added "Z" (`assets.tsx:94`, `targets.tsx:62`).
  - Valid `dateTime` values at `remediation.tsx:79` and `integrations.tsx:134`.
- **Assets:**
  - The one-time upload token uses `CopyBlock` (`assets.tsx:180`).
  - Add a "Machines" `h2`, so host names become `h3` under it (`assets.tsx:89`).
- **Badge meanings move from `title` into visible or sr-only text:**
  - `KevBadge` (`ui.tsx:22`).
  - The Sandbox and Agent-outdated badges (`assets.tsx:90-91`).
- **`ErrorState`** (`ui.tsx:32`): a plain-language lead line, with the raw `error.message` as the detail.
- **Done when:** the axe sweep in T16 is clean, and the vitest for `adminGate` asserts `aria-disabled` and the visible reason.

**T14 Settings: sections you can find**
- **Same single route.** Group into five headed sections, in this order:
  1. **Remediation:** trust ladder, soak, deadlines, agent updates.
  2. **Access:** people, SSO, enrolment tokens, API tokens.
  3. **Alerts.**
  4. **Your account.**
  5. **This server.**
- **Add an in-page anchor nav:** sticky on `lg`, a horizontal scroller on phones. Anchors are bookmarkable, for example `/settings#access`.
- **Done when:** each anchor scrolls to its section, and the e2e for people and API tokens still passes.

**T18 QR code for two-step sign-in** (`people.tsx:13-18`, `MfaEnrol`; used by both sign-in enrolment and Settings)
- **Dependency:** `cd web && npm install --save-exact uqr@0.1.3`.
- **Add `QrCode({ text })` to `ui.tsx`:**
  - Use `encode(text, { border: 2 })` from `uqr` for the module matrix.
  - Draw one `<svg viewBox>` with a `<path>` built from the dark modules. That is one path, not thousands of rects.
  - Always dark on white (`#111` on `#FFF`) in both themes, because inverted codes fail on many scanners. This is the one sanctioned hard-coded colour pair; give it a comment saying why.
  - `role="img"`, with `aria-label="QR code for your authenticator app"`.
- **`MfaEnrol` order:**
  1. "Scan this with your authenticator app."
  2. The QR code.
  3. "Can't scan? Enter this key", followed by the existing `CopyBlock` and the `otpauth` link.
- **Done when:**
  - A vitest renders `QrCode` for a fixed `otpauth://` URI and snapshots the path, so changes are caught.
  - The e2e sign-up → TOTP flow still passes. It types the key, so it is unaffected.
  - The CSP header is unchanged.
  - `npm audit` is clean.
  - Record the bundle delta in STATUS.

**T15 Code-split the routes** (`main.tsx:6-14`)
- **Lazy-load** Settings (with people and integrations), Evidence, Auth and Onboarding, using TanStack lazy routes or `React.lazy`.
- **Done when:** the build shows the entry chunk under 450 kB minified (currently 587 kB), and e2e passes. Record the before and after in STATUS.

### Phase 4: Proof

**T16 Tests that keep this fixed**
- **Write alongside each task:** the vitest and API tests listed in T2–T6, T11 and T13.
- **Then extend `web/e2e/app.spec.ts`:**
  - Run the axe sweep at **375 as well as 1440**, in light and dark.
  - Also run it with the trust-ladder confirm, a `ConfirmDialog`, the command palette and Settings anchors open, and on the auth pages.
  - Add a keyboard-only pass: Tab to Findings, open a row with Enter, close with Escape, and focus returns to the row.
- **Add a regression test for the "Verified" text fixed in T3:** a vitest asserts it renders with `text-ink` and the icon, not `text-accent-ink`.
- **Done when:** the commands in "Goal: done when" all pass.

**T17 Docs and screenshots**
- **Regenerate** `web/e2e-screenshots` via e2e.
- **Regenerate** `docs/images` via `web/scripts/readme-shots.mjs` against the demo DB (see its header).
- **CHANGELOG:** an "Unreleased" entry.
- **STATUS:** a Done row with the evidence: test counts, axe sizes, bundle before and after.
- **DECISIONS:** short entries for decisions 1–7 above. Decision 5 says plainly that packs can now carry `no_activity`.
- **Done when:** the README images show the new Home ("View fix") and no rounded elements, and the docs match the shipped behaviour.

## Order for one `/goal` run
T1 → T2 → T3 → T4 → T5 → T6 → T7 → T8 → T9 → T10 → T11 → T12 → T13 → T14 → T18 → T15 → T16 (final sweep) → T17.

- **Commits:** one per task, on a `ux-round-1` branch. Don't push or open a PR without asking.
- **Stop and report** only if a task turns up a new product, security or compliance choice that decisions 1–7 don't cover. Otherwise keep going to the end.
