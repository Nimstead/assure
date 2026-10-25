// Fresh e2e DB + signing key every run, seeded advisories, then the API on :8000.
import { spawn, spawnSync } from "node:child_process";
import { mkdirSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const web = join(dirname(fileURLToPath(import.meta.url)), "..");
const api = join(web, "..", "api");
const data = join(web, "e2e-data");
rmSync(data, { recursive: true, force: true });
mkdirSync(data, { recursive: true });
const env = {
  ...process.env,
  NIMSTEAD_SECURE_COOKIES: "0",
  NIMSTEAD_DB: `sqlite:///${join(data, "e2e.db").replaceAll("\\", "/")}`,
  NIMSTEAD_SIGNING_KEY_FILE: join(data, "signing.pem"),
  NIMSTEAD_AI: "0",
};
const run = (args, opts = {}) => spawnSync("uv", ["run", ...args], { cwd: api, env, stdio: "inherit", ...opts });
if (run(["python", join(web, "scripts", "seed.py")]).status !== 0) process.exit(1);
const srv = spawn("uv", ["run", "uvicorn", "--factory", "nimstead.app:create_app", "--port", "8000"], { cwd: api, env, stdio: "inherit" });
srv.on("exit", (c) => process.exit(c ?? 0));
for (const s of ["SIGINT", "SIGTERM"]) process.on(s, () => srv.kill());
