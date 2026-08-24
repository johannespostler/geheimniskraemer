import { defineConfig, devices } from "@playwright/test";

// WebAuthn is simulated via CDP virtual authenticators, so Chromium only.
export default defineConfig({
  testDir: "e2e",
  timeout: 60_000,
  // The spec starts its own gk server on a fixed port; never run specs in
  // parallel against it.
  workers: 1,
  use: {
    ...devices["Desktop Chrome"],
    baseURL: "http://localhost:8199",
  },
});
