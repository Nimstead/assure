import { expect, request as pwRequest, test, type Browser, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { spawnSync } from "node:child_process";
import { createHmac } from "node:crypto";
import { mkdirSync } from "node:fs";
import { join } from "node:path";

const STATE = "e2e-data/state.json";
const SHOTS = "e2e-screenshots";
const inv = (version: string) => ({
  ecosystem: "Debian:12",
  packages: ["libssl3", "openssl"].map((name) => ({ ecosystem: "Debian:12", name, version, source: "openssl" })),
});

test.describe.configure({ mode: "serial" });

function totp(secret: string, at = Date.now()): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bits = [...secret.replace(/=+$/, "")].map((c) => alphabet.indexOf(c).toString(2).padStart(5, "0")).join("");
  const key = Buffer.from(bits.match(/.{8}/g)!.map((b) => parseInt(b, 2)));
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(Math.floor(at / 30_000)));
  const mac = createHmac("sha1", key).update(msg).digest();
  const off = mac[mac.length - 1]! & 0x0f;
  return String((mac.readUInt32BE(off) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

// A code for a 30 s step not used yet (each works once), waiting for the next step if need be, as a person would.
let secret = "", lastStep = 0;
async function freshCode(page: Page): Promise<string> {
  while (Math.floor(Date.now() / 30_000) <= lastStep) await page.waitForTimeout(1000);
  lastStep = Math.floor(Date.now() / 30_000);
  return totp(secret);
}


test("sign up, enrol a sandbox host, plan and approve a fix, see evidence", async ({ page }) => {
  await page.goto("/signup");
  await page.getByLabel("Organisation").fill("Acme E2E");
  await page.getByLabel("Email").fill("e2e@example.com");
  await page.getByLabel("Password").fill("correct horse battery staple");
  await page.getByRole("button", { name: "Create account" }).click();

  // An admin's first session comes from signing in, which sets up two-step sign-in
  await expect(page.getByText(/Account created\. Sign in to set up two-step sign-in/)).toBeVisible();
  await page.getByLabel("Email", { exact: true }).fill("e2e@example.com");
  await page.getByLabel("Password").fill("correct horse battery staple");
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Set up two-step sign-in" })).toBeVisible();
  secret = (await page.locator("pre code").first().textContent())!.trim();
  await page.getByLabel("Code from the app").fill(await freshCode(page));
  await page.getByRole("button", { name: "Turn on" }).click();
  await expect(page.getByText(/Save these recovery codes now/)).toBeVisible();
  await page.getByRole("button", { name: /saved them, continue/ }).click();

  // Onboarding: test or production is a required choice, nothing preselected
  const create = page.getByRole("button", { name: "Create install command" });
  await expect(create).toBeDisabled();
  await page.getByRole("radio", { name: /Test machines/ }).click();
  await create.click();
  await expect(page.getByText(/install\.sh \| sudo --preserve-env=NIMSTEAD_TOKEN sh/)).toBeVisible();

  // Enrol a fake sandbox asset through the agent API
  const tok = await (await page.request.post("/api/enroll-tokens", { data: { sandbox: true } })).json();
  const agent = await (await page.request.post("/api/agent/enroll", { data: { token: tok.token, hostname: "sbx-1", ecosystem: "Debian:12" } })).json();
  const r = await page.request.post("/api/agent/inventory", { data: inv("3.0.11-1~deb12u1"), headers: { Authorization: `Bearer ${agent.agent_key}` } });
  expect(r.ok()).toBe(true);

  // Home: top action for openssl (onboarding polls, then offers the way home)
  await page.getByRole("link", { name: "Go to Fix first" }).click({ timeout: 20_000 });
  await expect(page.getByRole("heading", { name: "Fix first" })).toBeVisible();
  await expect(page.getByText(/Upgrade\s+openssl/)).toBeVisible();

  // Findings + drawer
  await page.getByRole("link", { name: "Findings", exact: true }).first().click();
  const rows = page.getByRole("row").filter({ hasText: "openssl" });
  await expect(rows.first()).toBeVisible();
  await rows.first().click();
  const drawer = page.getByRole("dialog");
  await expect(drawer.getByRole("heading", { name: "Why it matched" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Explain in plain English" })).toHaveCount(0); // AI is off here

  // Plan fix -> Remediation
  await drawer.getByRole("button", { name: /Plan fix/ }).click();
  await expect(page).toHaveURL(/\/remediation/);
  await expect(page.getByRole("heading", { name: "Needs approval" })).toBeVisible();

  // Approve
  await page.getByRole("button", { name: /^Approve/ }).click();
  const dlg = page.getByRole("dialog");
  await expect(dlg.getByText("Approve this fix?")).toBeVisible();
  await dlg.getByRole("button", { name: "Approve and run" }).click();
  await expect(page.getByRole("heading", { name: "In progress" })).toBeVisible();
  await expect(page.getByText("Approved, waiting for host")).toBeVisible();

  // Home links to the fix in flight instead of offering another one the API would refuse
  await page.getByRole("link", { name: "Fix first", exact: true }).first().click();
  const action = page.getByRole("listitem").filter({ hasText: /Upgrade\s+openssl/ });
  await expect(action.getByRole("link", { name: /View fix/ })).toBeVisible();
  await expect(action.getByRole("button", { name: /Plan fix/ })).toHaveCount(0);

  // A job's host links to that machine's findings
  await page.getByRole("link", { name: "Remediation", exact: true }).first().click();
  await page.getByRole("link", { name: "sbx-1", exact: true }).click();
  await expect(page).toHaveURL(/\/findings\?.*asset=/);
  await expect(page.getByRole("button", { name: /Host: sbx-1/ })).toBeVisible();

  // Evidence
  await page.getByRole("link", { name: "Evidence", exact: true }).first().click();
  await expect(page.getByText(/Chain verified/)).toBeVisible();
  await expect(page.getByRole("heading", { name: "Control status" })).toBeVisible();
  await expect(page.getByText(/Give auditors these separately from the pack/)).toBeVisible();
  await expect(page.getByText("Verifier script SHA-256")).toBeVisible();

  // Settings lists the tokens
  await page.goto("/settings");
  await expect(page.getByRole("heading", { name: "Enrolment tokens" })).toBeVisible();

  await page.context().storageState({ path: STATE });
});

test("admins sign in with their code, manage people and API tokens", async ({ browser }) => {
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto("/signin");
  await page.getByLabel("Email", { exact: true }).fill("e2e@example.com");
  await page.getByLabel("Password").fill("correct horse battery staple");
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Enter your code" })).toBeVisible();  // enrolled in the first test
  await page.getByLabel(/Code from your authenticator app/).fill(await freshCode(page));
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Fix first" })).toBeVisible();

  // a second member of the org, as an invitation or SSO would add (no SMTP or IdP in this test)
  const db = join(process.cwd(), "e2e-data", "e2e.db").replaceAll("\\", "/");
  const py = "from sqlalchemy import select; from sqlalchemy.orm import sessionmaker; from nimstead.db import User, make_engine; "
    + "s = sessionmaker(make_engine())(); o = s.scalar(select(User.org_id).where(User.email == 'e2e@example.com')); "
    + "s.add(User(org_id=o, email='member@example.com', password_hash='!')); s.commit()";
  expect(spawnSync("uv", ["run", "python", "-c", py], { cwd: join(process.cwd(), "..", "api"), env: { ...process.env, NIMSTEAD_DB: `sqlite:///${db}` } }).status).toBe(0);

  await page.goto("/settings");
  const people = page.locator("section[aria-labelledby=people]");
  const member = people.getByRole("listitem").filter({ hasText: "member@example.com" });
  await expect(member).toContainText("Member · password");
  await expect(people.getByRole("listitem").filter({ hasText: "(you)" })).toContainText("Admin · password + code");
  await expect(people.getByRole("listitem").filter({ hasText: "(you)" }).getByRole("button")).toHaveCount(0);  // no self-demotion
  await people.getByRole("button", { name: "Make admin member@example.com" }).click();
  await page.getByRole("alertdialog", { name: "Make member@example.com an admin?" }).getByRole("button", { name: "Make admin" }).click();
  await expect(people.getByRole("button", { name: "Make member member@example.com" })).toBeVisible();
  await expect(page.getByRole("alertdialog")).toHaveCount(0);
  await people.getByRole("button", { name: "Remove member@example.com" }).click();
  await page.getByRole("alertdialog", { name: "Remove member@example.com?" }).getByRole("button", { name: "Remove" }).click();
  await expect(member).toHaveCount(0);
  await expect(page.getByRole("alertdialog")).toHaveCount(0);  // the page is inert until the dialog has closed

  const tokens = page.locator("section[aria-labelledby=api-tokens]");
  await tokens.getByLabel("Name").fill("ci export");
  await tokens.getByLabel("Authenticator code").fill(await freshCode(page));  // a session alone can't mint a token
  await tokens.getByRole("button", { name: "Create token" }).click();
  const token = (await tokens.locator("pre code").textContent())!.trim();
  const anon = await pwRequest.newContext({ baseURL: "http://localhost:5173" });
  const csv = await anon.get("/api/findings.csv", { headers: { Authorization: `Bearer ${token}` } });
  expect(csv.ok()).toBe(true);
  expect(await csv.text()).toMatch(/^hostname,package/);
  expect((await anon.post("/api/enroll-tokens", { headers: { Authorization: `Bearer ${token}` } })).status()).toBe(403);
  await expect(tokens.getByRole("listitem").filter({ hasText: "ci export" })).toContainText("by e2e@example.com");
  await context.close();
});

const PAGES = [
  { name: "home", path: "/", ready: /Fix first/ },
  { name: "findings", path: "/findings", ready: /Findings/, drawer: true },
  { name: "assets", path: "/assets", ready: /Assets/ },
  { name: "remediation", path: "/remediation", ready: /Remediation/ },
  { name: "evidence", path: "/evidence", ready: /Evidence/ },
  { name: "settings", path: "/settings", ready: /Settings/ },
] as const;

async function load(page: Page, p: (typeof PAGES)[number]) {
  let path: string = p.path;
  if ("drawer" in p) {
    const rows = await (await page.request.get("/api/findings?status=open&limit=5")).json();
    path += `?f=${rows[0].id}`;
  }
  await page.goto(path);
  await expect(page.locator("h1")).toContainText(p.ready);
  if ("drawer" in p) await expect(page.getByRole("dialog").getByRole("heading", { name: "Why it matched" })).toBeVisible();
  await page.waitForLoadState("networkidle");
}

async function ctx(browser: Browser, width: number, colorScheme: "light" | "dark") {
  const context = await browser.newContext({ storageState: STATE, viewport: { width, height: width > 600 ? 900 : 812 }, colorScheme });
  return { context, page: await context.newPage() };
}

async function axe(page: Page, label: string) {
  const { violations } = await new AxeBuilder({ page }).analyze();
  const bad = violations.filter((v) => v.impact === "serious" || v.impact === "critical");
  expect(bad.map((v) => `${label}: ${v.id} (${v.impact}) ${v.nodes.slice(0, 3).map((n) => n.target.join(" ")).join(" | ")}`), label).toEqual([]);
}

for (const width of [1440, 375] as const) {
  for (const scheme of ["light", "dark"] as const) {
    test(`axe: no serious or critical violations (${width}, ${scheme})`, async ({ browser }) => {
      const { context, page } = await ctx(browser, width, scheme);
      for (const p of PAGES) {
        await load(page, p);
        await axe(page, `${p.name} @${width} ${scheme}`);
      }
      // open dialogs: the Auto confirmation, a ConfirmDialog, the command palette
      await load(page, PAGES[5]);
      await page.getByRole("radio", { name: /^Auto/ }).click();
      await page.locator("section[aria-labelledby=ladder]").getByRole("button", { name: "Save" }).click();
      await expect(page.getByRole("alertdialog", { name: /without asking/ })).toBeVisible();
      await axe(page, `auto confirm @${width} ${scheme}`);
      await page.keyboard.press("Escape");
      await page.locator("section[aria-labelledby=tokens]").getByRole("button", { name: /^Revoke/ }).first().click();
      await expect(page.getByRole("alertdialog", { name: "Revoke this token?" })).toBeVisible();
      await axe(page, `confirm dialog @${width} ${scheme}`);
      await page.keyboard.press("Escape");
      await page.keyboard.press("Control+k");
      await page.getByRole("combobox").fill("openssl");
      await expect(page.getByRole("option").first()).toBeVisible();
      await axe(page, `palette @${width} ${scheme}`);
      await page.keyboard.press("Escape");
      await context.close();
      // signed-out pages
      const anon = await browser.newContext({ viewport: { width, height: 812 }, colorScheme: scheme });
      const ap = await anon.newPage();
      for (const path of ["/signin", "/signup"]) {
        await ap.goto(path);
        await expect(ap.locator("h1")).toBeVisible();
        await axe(ap, `${path} @${width} ${scheme}`);
      }
      await anon.close();
    });
  }
}

test("keyboard: choosing on the trust ladder saves nothing; findings open with Enter and close with Escape", async ({ browser }) => {
  const { context, page } = await ctx(browser, 1440, "light");
  await load(page, PAGES[5]);
  const patches: string[] = [];
  page.on("request", (r) => { if (r.method() === "PATCH" && r.url().includes("/api/settings")) patches.push(r.url()); });
  await page.getByRole("radio", { name: /^Approve/ }).focus();
  await page.keyboard.press("ArrowRight");  // Approve → Auto
  await expect(page.getByRole("radio", { name: /^Auto/ })).toBeFocused();
  await page.keyboard.press("Space");  // selecting by keyboard saves nothing
  await expect(page.getByRole("radio", { name: /^Auto/ })).toBeChecked();
  await page.waitForTimeout(300);
  expect(patches).toEqual([]);
  await page.reload();
  await expect(page.getByRole("radio", { name: /^Approve/ })).toBeChecked();

  await page.goto("/findings");
  const first = page.getByRole("row").nth(1).getByRole("button");
  await first.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("dialog").getByRole("heading", { name: "Why it matched" })).toBeVisible();
  await expect(page.getByRole("dialog").getByRole("heading", { level: 2 }).first()).toBeFocused();  // the title, not the close button
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(page.getByRole("row").nth(1).getByRole("button")).toBeFocused();  // focus comes back to the row
  await context.close();
});

test("phones: Evidence is one tap away and controls are at least 44px tall", async ({ browser }) => {
  const { context, page } = await ctx(browser, 375, "light");
  await load(page, PAGES[0]);
  await page.getByRole("navigation", { name: "Main" }).getByRole("link", { name: "Evidence" }).click();
  await expect(page.locator("h1")).toContainText("Evidence");
  for (const p of PAGES) {
    await load(page, p);
    const small = await page.evaluate(() => [...document.querySelectorAll("main button, main a, main select, main input, nav button, nav a")]
      .filter((e) => {
        const r = e.getBoundingClientRect(), cs = getComputedStyle(e);
        // inline text links inside sentences are exempt (WCAG 2.5.8); so are hidden and sr-only elements
        if (!r.width || !r.height || cs.display === "inline" || e.closest(".sr-only") || (e as HTMLInputElement).type === "file") return false;
        // a findings row is one tappable card (≥104px on phones); the ID button inside it is the keyboard handle
        if (e.closest("[role=row]") && e.closest("[role=row]")!.getBoundingClientRect().height >= 44) return false;
        // switches and checkboxes are tapped through their whole label, which is the 44px target
        if ((e.getAttribute("role") === "switch" || (e as HTMLInputElement).type === "checkbox") && (e.closest("label")?.getBoundingClientRect().height ?? 0) >= 44) return false;
        return r.height < 44;
      }).map((e) => `${e.tagName.toLowerCase()} "${(e.textContent || e.getAttribute("aria-label") || "").trim().slice(0, 40)}" ${Math.round(e.getBoundingClientRect().height)}px`));
    expect(small, `${p.name}: touch targets under 44px`).toEqual([]);
  }
  await context.close();
});

test("screenshots at 1440 and 375", async ({ browser }) => {
  mkdirSync(SHOTS, { recursive: true });
  for (const [width, scheme] of [[1440, "light"], [375, "light"], [375, "dark"]] as const) {
    const { context, page } = await ctx(browser, width, scheme);
    for (const p of PAGES) {
      await load(page, p);
      await page.screenshot({ path: `${SHOTS}/${p.name}-${width}${scheme === "dark" ? "-dark" : ""}.png`, fullPage: false });
      // Nothing should force horizontal scroll
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
      expect(overflow, `${p.name} @${width} horizontal overflow`).toBeLessThanOrEqual(0);
    }
    await context.close();
  }
});
