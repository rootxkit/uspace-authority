// The Playwright smoke run: `next start` behind test/mock-origin.mjs, which
// stands in for Caddy (one origin) with a stub api and a stub picture-ws
// serving the lab's console/* examples. Run `pnpm build` first.
import path from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig, devices } from "@playwright/test";

const here = path.dirname(fileURLToPath(import.meta.url));

const CI = process.env["CI"] !== undefined;
// Ports of this run; another checkout's run on the same machine sets its own.
const WEB_PORT = process.env["E2E_WEB_PORT"] ?? "3100";
const ORIGIN_PORT = process.env["E2E_ORIGIN_PORT"] ?? "3000";

export default defineConfig({
  testDir: "test/e2e",
  workers: 1,
  retries: 0,
  forbidOnly: CI,
  reporter: CI ? [["list"], ["github"]] : "list",
  use: {
    baseURL: `http://127.0.0.1:${ORIGIN_PORT}`,
    trace: "retain-on-failure",
    timezoneId: "UTC",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: [
    {
      command: `pnpm exec next start --port ${WEB_PORT} --hostname 127.0.0.1`,
      url: `http://127.0.0.1:${WEB_PORT}/healthz`,
      reuseExistingServer: !CI,
      env: {
        NEXT_TELEMETRY_DISABLED: "1",
        WEB_API_INTERNAL_URL: `http://127.0.0.1:${ORIGIN_PORT}`,
        // The fixture picture's area; test configuration, not a default.
        WEB_MAP_CENTER: "44.80,41.72",
        WEB_MAP_ZOOM: "9",
        // test/mock-origin.mjs stands in for Caddy, one trusted hop that sets
        // X-Forwarded-Proto and -Host (the sign-in's Origin check).
        WEB_TRUSTED_PROXY_HOPS: "1",
        // Seals the MFA challenge cookie in this run only; a test value.
        WEB_MFA_CHALLENGE_SECRET: "playwright-run-only-challenge-seal-key",
        // The rules page's Markdown for en only: ka shows the variable it lacks (test/e2e/public.spec.ts).
        WEB_RULES_FILE_EN: path.join(here, "test/fixtures/rules.en.md"),
        WEB_BRAND_NAME: "Test Authority",
        WEB_BRAND_SHORT_NAME: "TA",
      },
    },
    {
      command: "node test/mock-origin.mjs",
      url: `http://127.0.0.1:${ORIGIN_PORT}/__mock/health`,
      reuseExistingServer: !CI,
      env: { MOCK_PORT: ORIGIN_PORT, MOCK_UPSTREAM: `http://127.0.0.1:${WEB_PORT}` },
    },
  ],
});
