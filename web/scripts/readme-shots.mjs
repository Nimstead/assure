// README screenshots from a served demo database: the 206-machine fleet (five real Linux hosts running the real agent,
// grown by cloning their inventories), brought to today with owners and 120 days of history by sandbox/progress_demo.py.
//   1. copy a fleet demo database, run `alembic upgrade head` on it, then `uv run python ../sandbox/progress_demo.py <url> --to-now`
//   2. serve it (NIMSTEAD_DB=..., the demo's signing and key files, a fresh NIMSTEAD_CHECKPOINT_DIR)
//   3. cd web && node scripts/readme-shots.mjs [http://127.0.0.1:8000]
// Signs in with the account in api/demo/login.txt (or the file NIMSTEAD_DEMO_LOGIN names), with a code from its TOTP key,
// as admins need both. Writes docs/images/*.png at the sizes the README uses.
import { chromium } from "@playwright/test";
import { createHmac } from "node:crypto";
import { readFileSync } from "node:fs";

const BASE = process.argv[2] ?? "http://127.0.0.1:8000";
const OUT = "../docs/images";
const login = Object.fromEntries(readFileSync(process.env.NIMSTEAD_DEMO_LOGIN ?? "../api/demo/login.txt", "utf8").split(/\r?\n/)
  .map((l) => l.match(/^([\w ]+?)(?: \(.*\))?:\s*(.+)$/)).filter(Boolean).map((m) => [m[1], m[2].trim()]));

function totp(secret, at = Date.now()) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bits = [...secret.replace(/=+$/, "")].map((c) => alphabet.indexOf(c).toString(2).padStart(5, "0")).join("");
  const key = Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)));
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(Math.floor(at / 30_000)));
  const mac = createHmac("sha1", key).update(msg).digest();
  const off = mac[mac.length - 1] & 0x0f;
  return String((mac.readUInt32BE(off) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}
// Each code works once: wait for a 30 s step not used yet.
let lastStep = 0;
async function freshCode() {
  while (Math.floor(Date.now() / 30_000) <= lastStep) await new Promise((r) => setTimeout(r, 1000));
  lastStep = Math.floor(Date.now() / 30_000);
  return totp(login["totp setup key"]);
}

const browser = await chromium.launch();
async function page(width, height, colorScheme = "light") {
  const ctx = await browser.newContext({ baseURL: BASE, viewport: { width, height }, colorScheme, reducedMotion: "reduce" });
  const p = await ctx.newPage();
  const r = await p.request.post("/api/auth/login", { data: { email: login.email, password: login.password, code: await freshCode() } });
  if (!r.ok() || (await r.json()).mfa) throw new Error(`sign-in failed: ${r.status()}`);
  return p;
}
async function shot(p, path, name, ready) {
  await p.goto(path);
  await ready(p);
  await p.waitForLoadState("networkidle");
  await p.screenshot({ path: `${OUT}/${name}.png` });
  console.log(`${OUT}/${name}.png`);
}

const desk = await page(1440, 900);
const heading = (name) => (p) => p.getByRole("heading", { name, exact: true }).first().waitFor();
await shot(desk, "/", "home-1440", heading("Recommended fixes"));
await shot(desk, "/progress", "progress-1440", heading("By owner"));
await shot(desk, "/remediation", "remediation-1440", heading("Remediation"));
await shot(desk, "/findings", "findings-1440", async (p) => {
  await p.locator("[role=rowgroup] [data-c=vuln] button").first().click();  // the most urgent finding's drawer
  await p.getByRole("dialog").getByText("Why it matched").waitFor();
  await p.evaluate(() => document.activeElement?.blur());  // no focus ring in the picture
});
await shot(desk, "/findings?group=package", "findings-fleet-1440", heading("Findings"));
await shot(desk, "/assets", "assets-1440", heading("Assets"));
await shot(desk, "/assets?view=devices", "devices-1440", heading("Assets"));
await shot(desk, "/evidence", "evidence-1440", heading("Evidence"));
const tall = await page(1440, 1400);
await shot(tall, "/progress", "progress-full-1440", heading("By owner"));
const phone = await page(375, 812, "dark");
await shot(phone, "/", "home-375-dark", heading("Fix first"));
await shot(phone, "/progress", "progress-375-dark", heading("Progress"));
await browser.close();
