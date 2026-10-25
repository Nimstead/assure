import { defineConfig } from "@playwright/test";

// Starts the API (fresh DB, seeded advisories) and Vite itself. Reuses a running Vite, never a running API.
export default defineConfig({
  testDir: "./e2e",
  timeout: 90_000,
  workers: 1,
  reporter: "list",
  use: { baseURL: "http://localhost:5173", trace: "retain-on-failure" },
  webServer: [
    { command: "node e2e/start-api.mjs", url: "http://127.0.0.1:8000/api/ai/status", reuseExistingServer: false, timeout: 120_000,
      gracefulShutdown: { signal: "SIGTERM", timeout: 5000 } },
    { command: "npm run dev -- --port 5173 --strictPort", url: "http://localhost:5173", reuseExistingServer: true, timeout: 60_000 },
  ],
});
