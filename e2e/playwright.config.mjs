// SPDX-License-Identifier: GPL-2.0-or-later
import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: ".",
  testMatch: "*.spec.mjs",
  timeout: 120_000,
  use: { baseURL: "http://127.0.0.1:4173" },
  webServer: {
    command: "node e2e/serve.mjs",
    cwd: "..",
    url: "http://127.0.0.1:4173",
    reuseExistingServer: false,
  },
});
