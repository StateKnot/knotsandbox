import { defineConfig } from "@playwright/test";
export default defineConfig({
  testDir: "./tests",
  testMatch: [
    "console.spec.ts",
    "automation.spec.ts",
    "notification-inbox.spec.ts",
    "tenant-audit.spec.ts",
    "backup-capability.spec.ts",
    "runtime-metrics.spec.ts",
  ],
  fullyParallel: false,
  workers: 1,
  timeout: 30000,
  use: {
    baseURL: "http://127.0.0.1:4173",
    headless: true,
    trace: "retain-on-failure",
    launchOptions: process.env.SANDBOX_TEST_CHROME
      ? { executablePath: process.env.SANDBOX_TEST_CHROME }
      : {},
  },
  webServer: {
    command: "npm run preview -- --port 4173",
    url: "http://127.0.0.1:4173",
    reuseExistingServer: false,
    timeout: 30000,
  },
});
