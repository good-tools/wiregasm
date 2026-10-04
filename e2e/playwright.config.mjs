import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: ".",
  testMatch: "*.spec.mjs",
  timeout: 120_000,
  use: { baseURL: "http://localhost:4173" },
  webServer: {
    command: "node e2e/serve.mjs",
    cwd: "..",
    url: "http://localhost:4173",
    reuseExistingServer: false,
  },
});
