import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    proxy: {
      // The API refuses cross-origin POSTs; the browser's Origin (:5173) never matches the upstream Host (:8000), so drop it.
      "/api": { target: `http://127.0.0.1:${process.env.NIMSTEAD_API_PORT ?? 8000}`, configure: (p) => { p.on("proxyReq", (req) => req.removeHeader("origin")); } },
    },
  },
  test: { include: ["src/**/*.test.{ts,tsx}"], globals: true, environment: "jsdom", setupFiles: ["./src/setup-tests.ts"], css: false },
});
