# Implementation Plan (0.6): UI/UX round 2 — what round 1 left half-done, and the journeys that still dead-end

## Overview
Second senior UI/UX review, on 2026-10-28, of branch `ux-round-1` after round 1 (`tasks/plan-0.5-ux.md`, DECISIONS 41–47). It covered:
- The live demo database at 1440 px and 375 px.
- A fresh heuristic design review.
- A code-level audit of every `web/src` file.
- The Impeccable detector, which found nothing (`[]`).

Round 1 worked:
- **Heuristic score:** 25 → 27 of 40.
- **No P0s left.** The trust ladder, confirmations, linked pages, evidence honesty and phone layout all hold.

What remains falls into four groups:
- **Round-1 gaps:**
  - Focus is restored for the findings drawer only, not the other dialogs.
  - Non-admins still get live asset controls that the API refuses.
  - The focus ring shows on the drawer title.
  - A save in one Settings section wipes unsaved edits in the others.
- **Journeys that dead-end:**
  - Production remediation can only be turned on by an environment variable that no screen names.
  - Home offers "Plan fix" for a fix whose last attempt aborted.
  - "Overdue and still open" on Evidence leads nowhere.
  - Fix links land on the top of the jobs list, not on the job.
- **Feedback screen readers miss:**
  - Most success and loading messages appear already holding their text, which screen readers usually don't announce.
  - Form errors aren't linked to their fields.
  - Focus is dropped when a view swaps out.
- **Smaller polish and consistency debt.**

Two of round 1's claims were wrong, and this plan corrects them:
- **The 5,000-row fetch wasn't gone.** T4's "no `limit=5000` left in `web/src`" is false: `filtersToApi` (`lib.ts:214`) still sends it for the findings list. Only the Plan-fix lookup went.
- **The bundle figure was too low.** "392 kB" was the entry chunk alone. With the chunks `index.html` preloads, the JS a page needs before it runs is about 528 KiB.

**No visual redesign.** The "Plain Sight" identity and DECISIONS 41–47 stand.

## Goal: done when
- [x] Every task T1–T16 below is checked off with its "Done when" met.
- [x] `cd web && npm run lint && npx vitest run && npm run build`: clean, with the new tests passing.
- [x] `cd web && NIMSTEAD_API_PORT=8010 npm run e2e` passes. Port 8000 may be held by another dev server, and any free port works. Axe must report 0 serious or critical at **1440 and 375, light and dark**, now also:
  - with a **non-admin** signed in,
  - on `/add`,
  - with the palette showing "Nothing matches".
- [x] `cd api && uv run pytest -q` passes and `uv run ruff check src tests` is clean (T3, T5 and T9 touch the API).
- [x] `~/.claude/skills/impeccable/scripts/impeccable detect --json web/src` still reports `[]`.
- [x] CHANGELOG "Unreleased" is extended; STATUS has a row for round 2 with honest numbers; DECISIONS 48–50 are added. No version bump or release.

## What exists (reuse, don't rebuild)
- **Shared primitives in `ui.tsx`:** `ConfirmDialog`, `Alert`, `Done`, `Field`, `Loading`, `Tag`, `StatusPill`, `chip`, `switchRoot`/`switchThumb` and `dialogBox`.
  - `CopyBlock` already uses a persistent live region (`ui.tsx:142`), which is the pattern T6 copies.
- **Focus capture and restore** for the findings drawer (`findings.tsx:195-196`). T2 turns it into a hook.
- **Read-only text for non-admins** in Settings (`settings.tsx:92`). T1 copies it onto Assets.
- **URL filter round-trip** (`lib.ts:189-206`), which T9's `overdue` filter extends.
- **Evidence metrics** already compute `overdue_open` per SLA in force (`evidence.py`). T9 reuses the same rule for the findings filter.
- **e2e scaffolding:** `serve()` and `wrap()` in `web/src/ux.test.tsx`, the touch-target and axe helpers in `web/e2e/app.spec.ts`, and `NIMSTEAD_API_PORT`.

## Decisions (become DECISIONS 48–50)
48. **Every dialog returns focus to what opened it.** Radix only does this for a `Dialog.Trigger`. Ours open from state, so a shared `useReturnFocus()` captures the opener on open and refocuses it on close. The `:focus-visible` rule moves into `@layer base` so a deliberate `outline-none` (the drawer title) wins. Focus colour becomes ink in both themes: crimson is kept for "fix now", KEV and errors only.
49. **Feedback is announced from one place.** A single polite live region sits in the shell. `Done` and `Alert` render where they are and also announce through it, because a node that mounts already holding its text is usually not read. `Loading` stops putting `aria-busy` on its own status node.
50. **The priority tier "Planned" is renamed "Routine".**
    - "Planned" also reads as a job state and as the "Plan fix" verb, so "559 Planned" on Home looks like 559 planned fixes.
    - API keys and stored values stay `planned`; only labels change. That covers `PRIORITY_LABEL`, and the deadlines text in the evidence pack moves from keys to labels.
    - Packs are free text there, so their format is unaffected.

## Not doing (this round), and why
- **Bulk actions and general column sort:**
  - Home's multi-host "Plan fix" and "accept on every host" cover the real batch cases.
  - The sort people actually need is overdue/due, which T9 adds.
- **Per-host edit drawer:** T1 (read-only for non-admins) and T12 (explanations) fix the actual problems.
- **Ledger filtering and paging:** T10 says what the page shows and points to the signed pack, which holds the full ledger.
- **j/k row navigation:** T11's palette host search covers fast jumps; rows are reachable by Tab and Enter.
- **A screen-reader-browsable findings table:** virtualisation renders visible rows only. `aria-rowcount` is right, and "Export CSV" gives the full list. Revisit if a screen-reader user reports it.
- **ESLint / react-hooks lint:** tooling with its own churn. T15 fixes the one nested-component remount it would catch.

## Needs the owner
Nothing open. DECISIONS 50 (the "Routine" rename) is a vocabulary choice made here. Say so before running `/goal` if you'd rather keep "Planned".

## Dependency graph
```
T1 non-admin assets · T3 API attention/busy hosts · T4 production path      (independent, first)
T2 useReturnFocus + focus layer ─► T6 live region ─► T7 field errors ─► T8 focus on view swaps
T3 ─► T5 Home "last attempt aborted" + per-host plan
T9 overdue filter (API + UI) · T10 job deep links + ledger honesty · T11 palette · T12 assets clarity
T13 settings & integrations form state · T14 polish batch · T15 cleanup
T16 tests (alongside each task; final sweep last) ─► T17 docs + screenshots (last)
```

## Task list

### Phase 1: Correctness and safety

**T1 Non-admins see asset settings, not controls** (`assets.tsx:106-145`)
- **Today:** criticality, internet-facing, ring and health units are live for everyone. The API requires `Admin` (`app.py:890`), so a non-admin's change shows optimistically, then rolls back with an error at the top of the page.
- **Change:** for non-admins, render the values as text ("Criticality: High · Internet-facing · Ring: Broad · Health units: nginx, sshd"), as Settings does (`settings.tsx:92`).
- **Done when:**
  - A vitest renders `AssetRow` for a non-admin and finds no `select`, `switch` or text `input`.
  - The e2e axe sweep runs as a member (T16).

**T2 Every dialog returns focus; the focus ring is ink and layered** (DECISIONS 48)
- **Hook:** `useReturnFocus()` in `ui.tsx` returns `{ onOpenAutoFocus, onCloseAutoFocus }`, extracted from `findings.tsx:195-196`.
- **Use it in:** `ConfirmDialog` (`ui.tsx:89`), `ApproveDialog` (`remediation.tsx:131`), the palette (`shell.tsx:211`), and the drawer (replacing its inline code).
- **Focus style:** `index.css:70` moves into `@layer base`, and `--focus` becomes `light-dark(#111111, #F2F2F0)`.
- **Done when:**
  - e2e: open a ConfirmDialog, then Cancel → focus is back on its opener. Ctrl K, then Escape → focus is back where it was.
  - The drawer title has no visible ring on open (computed `outline-style: none`).
  - Focus rings elsewhere still show.

**T3 API: cancelled isn't "needs a look"; actions say which hosts are busy** (`app.py:1630-1660`)
- **Attention list:** drop `cancelled` from `attention`. A cancel is deliberate, not a problem.
- **Summary actions:**
  - Add `busy_asset_ids`: assets with an active job for that package.
  - Add `last_attempt`: the newest failed, aborted, rolled-back or not-fixed job for that action, or null.
  - Keep `job`.
- **Done when:** API tests cover:
  - A cancelled job is not in `attention`.
  - A two-host action with a job on one host lists that one in `busy_asset_ids`.
  - An aborted job appears as `last_attempt`.

**T4 Production remediation: say how to turn it on**
- **Where:** the Settings banner (`settings.tsx:83-87`), the onboarding "Production machines" card (`onboarding.tsx:27`), and the refusal note (`remediation.tsx:156`), whose link currently promises "how to allow it".
- **Text:** one sentence naming `NIMSTEAD_ALLOW_PRODUCTION_REMEDIATION=1` in `.env` and a restart, in the same style as the `NIMSTEAD_UPDATE_CHANNEL` line (`settings.tsx:208`). Check the variable name against `remediate.py:48` and `docs/configuration.md`.
- **Done when:** a vitest finds the variable name in the banner and in the onboarding card.

**T5 Home: no blind re-plan, and per-host planning** (`home.tsx:105-120`)
- **Last attempt failed:** when `action.last_attempt` is set, show its `StatusPill` plus "Last attempt <status> · Review" linking to the job (T10). Only offer "Plan fix" alongside it if the failure didn't name extra packages; otherwise the job card's "Plan again including …" is the way.
- **Some hosts busy:** when some hosts are busy, show "View fix" *and* "Plan fix for N more hosts", passing `asset_ids − busy_asset_ids`.
- **Done when:**
  - A vitest covers both card states.
  - e2e: Home still shows "View fix" for the approved openssl job.

### Phase 2: Feedback and focus for keyboard and screen-reader users

**T6 One live region; announced feedback** (DECISIONS 49)
- **Shell:** add `<div id="live" role="status" aria-live="polite" class="sr-only">` and an `announce(text)` helper in `lib.ts`.
- **`Done`:** announces its text on mount.
- **`Alert`:** announces assertively through a second `role="alert"` region.
- **`Loading`:** drop `aria-busy` from its own node; set `aria-busy` on the container being loaded instead.
- **Same treatment for:**
  - the status nodes at `auth.tsx:112-124`, `targets.tsx:81` and `people.tsx:47`;
  - "Send test alert", which gets `<Alert error={test.error}/>` and `<Done>Test alert sent</Done>` (`integrations.tsx:101-104,153`);
  - findings while new filters load (`findings.tsx:41,50`): dim the table, set `aria-busy`, and say "Updating…" instead of the stale count while `isPlaceholderData`.
- **Done when:**
  - A vitest checks that `Done` puts its text in `#live`.
  - e2e: a failed test alert shows an error (fake webhook URL on the e2e server).

**T7 Form errors belong to their fields; errors appear where they happened**
- **`Field`:** gains `error?: string`. It renders the message under the control, sets `id`, `aria-invalid` and `aria-describedby`, and keeps `hint`.
- **Move the ~15 hand-written label blocks onto `Field`:** `people.tsx:33,37,89-91,144,185-191`, `auth.tsx:75,97,102,106,119,131`, `assets.tsx:183`, `targets.tsx:27`, `settings.tsx:123,138`.
- **Fix the broken reference:** `auth.tsx:108` points to a `pw-hint` that doesn't exist on sign-in.
- **Settings errors:** an error twin of `savedHere` shows a save error beside the section that failed, replacing the page-top alert (`settings.tsx:80`).
- **Asset errors:** shown on the row that failed (`assets.tsx:50`), not the page top.
- **SLA inputs:** get a "1 to 365 days" hint and `aria-invalid`.
- **Change password:** says *before* submitting that it signs out other devices and revokes your API tokens (`people.tsx:93`).
- **Done when:**
  - A vitest: an invalid SLA value sets `aria-invalid` and describes the error.
  - `grep -n '<label className="flex flex-col gap-1' web/src` is empty.

**T8 Focus never drops to the page when a view changes**
- **"Forgot password?":** focuses the reset email field (`auth.tsx:126`).
- **MFA setup and the code step:** autofocus the code input (`auth.tsx:66-72`).
- **Route changes:** in the shell, move focus to the new page's `h1` (`tabIndex=-1`, no visible ring per T2) and announce the page title via T6. This includes Plan fix → Remediation.
- **Late callbacks:** `PlanFixButton`'s `onSuccess` and the AI filter's `set(p)` (`remediation.tsx:176`, `findings.tsx:32`) only navigate if the user is still on the page that started them.
- **Done when:** the e2e keyboard pass checks that, after clicking a nav link, focus is on that page's `h1`.

### Phase 3: Journeys

**T9 Overdue is a first-class filter and a due date** (API + UI)
- **API:** `GET /api/findings?overdue=true` uses the same rule as the evidence metrics (deadline in force at first detection, per DECISIONS 40). Each finding gets `due` (ISO date).
- **UI:**
  - An "Overdue" chip in the findings filters, round-tripped in the URL.
  - The drawer says "Due 3 Nov (in 6 days)" or "12 days overdue".
  - The Evidence tile "Overdue and still open" links to `/findings?overdue=true`.
- **Done when:**
  - An API test shows that `overdue=true` returns exactly the findings counted in `overdue_open`.
  - A vitest covers the URL round-trip.
  - e2e: the tile link lands on the filtered list.

**T10 Fixes have an address; the ledger says what it shows**
- **Job anchors:** `JobCard`'s `<li id={"job-" + j.id} className="scroll-mt-24">`.
- **Links to a job:** "View fix" (Home), "View in Remediation" (drawer), the Plan-fix success navigation and T5's "Review" all link with `hash`.
- **Hash scrolling:** Remediation and Settings scroll to `location.hash` once their data has loaded, because a lazy chunk plus a query means the browser's own jump finds nothing (`settings.tsx`, `remediation.tsx`).
- **Self-approval:** when `created_by === approved_by`, the job card adds a muted "Planned and approved by the same person". This is shown, not blocked, and matters for SOC 2 CC8.1.
- **Ledger:** add a line under the heading: "Latest 50 of N entries. The signed pack holds the full ledger." It needs N from the API's existing chain count. Ledger subjects show a hostname or vulnerability ID when the entry's data has one, and the 8-character id otherwise.
- **Ledger alert:** stored ledger problems become plain text, not `role="alert"` (`evidence.tsx:129`), for the same reason as `settings.tsx:212`.
- **Done when:**
  - e2e: Home's "View fix" lands with the job card in view and focused.
  - `/settings#access` on a cold load scrolls to Access.

**T11 Command palette: stable, findable, valid**
- **Stable highlight:** keep it by command id, not index (`shell.tsx:193,201`), so arriving results don't change what Enter runs.
- **Empty state:** "Nothing matches" moves outside the `listbox` (`:228`). `aria-expanded` is true only when there are options (`:217`).
- **Hosts:** add hosts from the cached `assetsQ` ("Host: web-prod-01" → `/findings?asset=`).
- **Input:** gets a visible focus style (`:219`).
- **Done when:**
  - The e2e palette axe run with "zzzz" typed is clean.
  - A vitest checks that the highlighted command keeps its id when results arrive.

**T12 Assets: say things once, explain the jargon** (`assets.tsx`)
- **Agent-update sentence:** shown once, as a summary above the list ("5 agents can't update themselves: build-runner-01, …. Rerun the install command on each once."). Rows keep only the tag.
- **Explain Ring and Health units inline** with `Field` hints (one short line each, shown once in the list header on desktop):
  - Ring: "Canary gets fixes first; Broad waits for a healthy canary".
  - Health units: "systemd units checked before and after a fix; saved when you leave the field".
- **Delete:** the icon-only delete button becomes "Delete" with its icon on phones, and ≥ 44px wide.
- **Long names:** add `break-words`/`min-w-0` to hostnames, emails and package names in the Host chip, drawer, job card, dialog titles and Home cards.
- **Findings table:** 25 of 29 package names are cut off at 1440.
  - Package cells show the artifact (`log4j-core`) with the group (`org.apache.logging.log4j:`) muted before it, so the part that differs survives truncation.
  - Every truncated cell (package, version, host, why) gets a `title`.
  - The grid gives the package column more of the width the version column doesn't need (`index.css:105,108`).
- **Done when:**
  - The e2e enrols a host with a 63-character hostname and finds no horizontal overflow at 375 on Assets, Findings, Remediation and the drawer.
  - The touch check also measures width for icon-only buttons.
  - An e2e check at 1440 finds no truncated findings cell without a `title`.

**T13 Settings and integrations keep what you typed**
- **Settings** (`settings.tsx:46-51`): seed the form state once from the first load. After a save, reset only the saved field from the response, never the others.
- **Integrations** (`integrations.tsx:34,134`): drop the `key={JSON.stringify(s)}` remounts. The SSO and alerts forms reset themselves only after their own successful save, and "Verify domains" no longer discards SSO edits.
- **Stale "Saved":** clears when the user edits that form again (`save.reset()` on change).
- **Done when:** a vitest types deadlines, toggles Pause, and still finds the typed deadlines.

### Phase 4: Polish, performance, cleanup

**T14 Polish batch**
- **Trust-ladder cards:** unchecked cards get `border-line-strong` and the onboarding radio glyph (`settings.tsx:96`). This meets WCAG 1.4.11; today they measure 1.27:1.
- **Status pills:** "succeeded" and "cancelled" get different fills (`ui.tsx:31-32`). Cancelled becomes outlined only.
- **Home:** "0" in the Fix now tile is ink, not crimson (`home.tsx:13`).
- **Active states:**
  - "Add machine" when active gets the ink inset bar like the other nav items (`shell.tsx:81`).
  - The More tab shows active when you're on Assets or Settings (`shell.tsx:136`).
- **Settings section bar:**
  - The scrollbar is hidden, with a fade on the right edge showing it scrolls.
  - The current section is marked (`aria-current`, from an IntersectionObserver).
  - The sticky offset and `scroll-mt` are fixed so headings land below the bar on phones (`settings.tsx:77`).
- **Findings filters on phones:** collapse into a "Filters (n)" disclosure; status and search stay visible.
- **`ConfirmDialog`:** gains `cancelLabel` (default "Cancel"; the cancel-fix dialog uses "Keep it"). `destructive` styles the confirm button with `now` colours, as round 1's plan specified (`ui.tsx:84-99`).
- **`ErrorState`:** the lead line depends on the error:
  - 0 → "Can't reach the server",
  - 403 → "You don't have access to this",
  - 5xx → "The server had a problem".
- **`SigningKey`:** gets loading and error states (`evidence.tsx:110`).
- **Evidence:** MTTR formats "0.0 days" as "under a day".
- **Done when:**
  - The e2e screenshots show each change.
  - A vitest covers `ErrorState` for the three statuses.

**T15 Performance and cleanup**
- **Findings cap:** the list keeps a cap, but says when it's hit: "Showing the first 5,000. Narrow the filters or export CSV for all." That needs the API to report a total, or the UI to check `rows.length === 5000`; take the second.
- **Onboarding polling:** starts only after a token exists, and stops when the page is hidden (`onboarding.tsx:45`).
- **Settings sections:** fetch in parallel with `/api/settings`, not after it (`settings.tsx:60`).
- **Bundle:** report the critical-path size (entry plus preloaded chunks) honestly in STATUS, and split Radix pieces that only lazy pages use if that is a one-line `manualChunks`. Otherwise just report it.
- **One source for job states:** `ACTIVE_JOB_STATUSES` in `lib.ts`, replacing `findings.tsx:271`, `remediation.tsx:10` and `lib.ts:68`. Plus one `jobsQ` replacing `remediation.tsx:16` and `findings.tsx:275`.
- **Invalidation:** one `refresh(qc, "jobs" | "findings" | …)` helper replaces the 8 hand-written invalidation lists. Re-planning must refresh the summary (`remediation.tsx:67`).
- **Dead code:**
  - The `Skeleton` export becomes module-private.
  - Remove the inert `rounded` / `rounded-md` classes (`ui.tsx:8,11`, `settings.tsx:208,210`, `people.tsx:168`).
  - Remove the unused `@custom-variant dark` (`index.css:34-37`).
  - Remove the empty-label status in `HomeSkeleton`.
  - Hoist the nested `H` component (`findings.tsx:214`).
- **Raw alerts:** `shell.tsx:67` uses `ErrorState`; `assets.tsx:217` and `integrations.tsx:126` use `Alert`. `ApproveDialog` becomes a `ConfirmDialog`, so it is an alertdialog; update `ui.test.tsx`.
- **Null expiry:** `people.tsx:174` handles a null expiry ("never expires"). The API always sets one today, but the column is nullable and `rtf.format(NaN)` throws.
- **Optimistic asset edits:** use per-asset rollback, and re-sync `HealthUnits` text after a rollback (`assets.tsx:22-28,136`).
- **Done when:**
  - The `grep`s for `limit: "5000"` without the cap message, the four status sets, and `role="alert"` outside `ui.tsx` come back empty.
  - Bundle numbers are recorded.

### Phase 5: Proof

**T16 Tests**
- **Alongside each task:** the vitests and API tests named above.
- **Fix the false-positive link test:** the `Link` mock at `ux.test.tsx:14-15` must keep `search` and `hash`, and the job-card test asserts `asset` and `q`.
- **Fix the class-name test:** replace the "Verified" class-name assertion with a computed-colour check, or keep it but also assert the icon. Don't test classes alone.
- **e2e:**
  - A **member** context, created as the people test already does, runs the axe sweep at 1440 and 375 and checks Assets shows no controls.
  - axe and the touch check on `/add`, `/signin`, `/signup`, the open drawer and an open ConfirmDialog. The touch check walks portals, not just `main`/`nav`.
  - Focus return (T2), `h1` focus on navigation (T8), cancel job → POST → card in Done, evidence `?period=30` surviving reload with a "No activity" pill, the theme toggle cycling System → Light → Dark → System, and "Fix in progress" in the drawer.
- **Done when:** the commands in "Goal: done when" all pass.

**T17 Docs and screenshots**
- Regenerate `web/e2e-screenshots` (e2e) and `docs/images` (`node scripts/readme-shots.mjs <demo URL>` against `api/demo`).
- CHANGELOG "Unreleased" gets a round-2 section.
- STATUS gets a row with test counts, axe coverage including non-admin, and critical-path bundle size. It also corrects the round-1 row's "392 kB" and "no 5000-row request" claims.
- DECISIONS 48–50.
- **Done when:** the docs match what shipped.

## Order for one `/goal` run
T1 → T3 → T4 → T2 → T5 → T6 → T7 → T8 → T13 → T9 → T10 → T11 → T12 → T14 → T15 → T16 (final sweep) → T17.

Commit in a few groups on `ux-round-1` (or a new `ux-round-2` branch cut from it): API, web, docs. Don't push or open a PR without asking. Stop and report only if a task needs a product, security or compliance choice that DECISIONS 41–50 don't cover.

## Review record (2026-10-28)
- **Nielsen heuristics:** 27/40 (round 1: 25).
- **Heuristic scores below 3:**
  - Flexibility 2: no sort or due date; the palette only searches findings.
  - Error recovery 2: the dead-end refusal link; `ErrorState` blames the connection for everything.
  - Help 2: Ring and Health units unexplained on Assets.
- **Technical audit:** Accessibility 3, Performance 3, Responsive 3, Theming 3, Implementation integrity 2 (unchanged in score, with different findings).
- **Detector:** `[]`.
- **Live demo walk:**
  - 25 of 29 visible package names truncated with no tooltip at 1440 (Maven group IDs). Covered by T12's long-name pass: the drawer and a `title` on truncated cells.
  - Findings filters fill a third of the first phone screen (T14).
  - The Settings section bar shows a scrollbar (T14).
  - The agent-update sentence is repeated on five machines (T12).

## Done (2026-10-29, branch `ux-round-1`)
Every task's "Done when" is met. The evidence is in STATUS.md (row "UI/UX round 2").

- **Checks:**
  - API 738 passed and ruff is clean.
  - Web: lint, 44 unit tests and the build all pass.
  - 10 Playwright e2e tests pass. Axe runs at 1440 and 375, light and dark, including `/add`, open dialogs, the palette with and without matches, the sign-in pages and a read-only member. The suite also covers focus return, job deep links, cancel, `?period` on reload, the theme cycle, `#access` on a cold load, truncated-cell titles, 44px targets in dialogs, the drawer and sign-in, and a 63-character hostname.
  - The Impeccable detector reports `[]` and `npm audit` reports 0.
- **Bundle:** the critical path is 536 KiB (174 KB gzip): the entry chunk plus its two preloaded chunks, `ui` and `link`. Both preloads are needed on every page, so there was no one-line split. The number is reported, as the task allowed.

### Where the work differed from the plan
- **T6, live regions:**
  - `Alert` keeps `role="alert"` instead of also announcing through the shared region. An alert is read as it appears, and doing both would read it twice.
  - `Done` and a new `Notice` (for "check your email" and similar notes) announce through the regions.
  - The signed-out pages render their own `LiveRegions`.
- **T11, the palette's empty state:** once you type, the palette always offers "Search findings for …", so a typed query can't reach "Nothing matches". The test asserts that the palette never dead-ends and that its list is valid. The empty branch is still rendered outside the listbox, for completeness.
- **T13, the SSO and alerts forms:** these rebuild after their *own* save, keyed by a counter, so the saved values and the cleared secret field show. Other refreshes, such as "Verify domains", leave unsaved edits alone.
- **T5, failed last attempts:** after a failure that didn't name extra packages, Home offers "Plan fix again" next to "Last attempt …: review". After one that did name extra packages, it only links to the job, whose card has "Plan again including …".
- **T8, guarding late callbacks:** `PlanFixButton` compares `location.pathname` at click and at success rather than reading router state. That keeps it usable outside a router (and in tests).
- **T12, package names:** the artifact comes first, then the muted group (`log4j-core org.apache.logging.log4j`), rather than the group first. With the group first, the artifact was what got truncated, the opposite of the intent. The CVE column stays at 11.5rem, because narrowing it truncated IDs that have a KEV badge.
- **T9, due dates:** the findings API computes `due` from the findings table's `first_seen`. Packs use the ledger's opening time. They are written in the same transaction, and a test asserts that the overdue filter and the pack's `overdue_open` agree.
- **Phone touch targets:** the widened check also caught the phone header's logo link (23px), which now has a 44px tap area. It caught `/add` overflowing on the unbroken setting name too, which now wraps.
- **Docs:** `docs/install.md` still said to "tick sandbox" from the round-1 onboarding; it now describes the test/production choice.
