import { defineConfig } from "@playwright/test";

// Starts the API (fresh DB, seeded advisories) and Vite itself. Reuses a running Vite, never a running API.
// NIMSTEAD_API_PORT moves the API off 8000 when another server already holds it.
const API_PORT = process.env.NIMSTEAD_API_PORT ?? "8000";
// NIMSTEAD_WEB_PORT does the same for Vite: a running Vite on 5173 is reused, even when it is another project's.
const WEB_PORT = process.env.NIMSTEAD_WEB_PORT ?? "5173";
export default defineConfig({
  testDir: "./e2e",
  timeout: 90_000,
  workers: 1,
  reporter: "list",
  use: { baseURL: `http://localhost:${WEB_PORT}`, trace: "retain-on-failure" },
  webServer: [
    { command: "node e2e/start-api.mjs", url: `http://127.0.0.1:${API_PORT}/api/ai/status`, reuseExistingServer: false, timeout: 120_000,
      gracefulShutdown: { signal: "SIGTERM", timeout: 5000 } },
    { command: `npm run dev -- --port ${WEB_PORT} --strictPort`, url: `http://localhost:${WEB_PORT}`, reuseExistingServer: true, timeout: 60_000 },
  ],
});
