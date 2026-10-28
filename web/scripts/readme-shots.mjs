// README screenshots from a served demo database (sandbox/demo.py builds it from real hosts).
//   1. cd api && uv run python ../sandbox/demo.py
//   2. serve api/demo/nimstead-demo.db as the demo's docstring shows (port 8000)
//   3. cd web && node scripts/readme-shots.mjs [http://127.0.0.1:8000]
// Signs in with the account in api/demo/login.txt (password + a code from its TOTP key: admins need both)
// and writes docs/images/*.png at the sizes the README uses.
import { chromium } from "@playwright/test";
import { createHmac } from "node:crypto";
import { readFileSync } from "node:fs";

const BASE = process.argv[2] ?? "http://127.0.0.1:8000";
const OUT = "../docs/images";
const login = Object.fromEntries(readFileSync("../api/demo/login.txt", "utf8").split(/\r?\n/)
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
await shot(desk, "/", "home-1440", (p) => p.getByRole("heading", { name: "Recommended upgrades" }).waitFor());
await shot(desk, "/remediation", "remediation-1440", (p) => p.getByRole("heading", { name: "Remediation" }).waitFor());
await shot(desk, "/findings", "findings-1440", async (p) => {
  await p.getByRole("row").filter({ hasText: "CVE-2021-44228" }).first().click();
  await p.getByRole("dialog").getByText("Why it matched").waitFor();
  await p.evaluate(() => document.activeElement?.blur());  // no focus ring in the picture
});
await shot(desk, "/assets", "assets-1440", (p) => p.getByRole("heading", { name: "Assets" }).waitFor());
await shot(desk, "/evidence", "evidence-1440", (p) => p.getByRole("heading", { name: "Evidence" }).waitFor());
const phone = await page(375, 812, "dark");
await shot(phone, "/", "home-375-dark", (p) => p.getByRole("heading", { name: "Fix first" }).waitFor());
await browser.close();
