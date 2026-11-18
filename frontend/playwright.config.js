/**
 * Playwright config for Panelarr e2e tests.
 *
 * The backend serves the built SPA (frontend/dist), so `npm run build` must
 * run first. A fresh uvicorn instance is started on port 8811 with an empty
 * temp config dir and no Docker socket, so every run begins in the
 * "setup not complete" state and pages must degrade gracefully without Docker.
 *
 * Env overrides:
 *   PANELARR_PYTHON                 python executable (default "python")
 *   PLAYWRIGHT_CHROMIUM_EXECUTABLE  use an already-installed chromium build
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { defineConfig } from "@playwright/test";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..");
const PORT = 8811;

// Created once in the main process; workers inherit it through the env.
if (!process.env.PANELARR_E2E_DIR) {
  process.env.PANELARR_E2E_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "panelarr-e2e-"));
}
const configDir = process.env.PANELARR_E2E_DIR;

const executablePath = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE || undefined;

export default defineConfig({
  testDir: "./e2e",
  // Specs share one backend whose state evolves (wizard -> login -> routes ->
  // reset), so they run serially in filename order.
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : "list",
  timeout: 60_000,
  expect: { timeout: 10_000 },
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    trace: "retain-on-failure",
    launchOptions: executablePath ? { executablePath } : {},
  },
  webServer: {
    command: `${process.env.PANELARR_PYTHON || "python"} -m uvicorn backend.main:app --host 127.0.0.1 --port ${PORT}`,
    cwd: repoRoot,
    url: `http://127.0.0.1:${PORT}/api/healthz`,
    reuseExistingServer: false,
    timeout: 60_000,
    env: {
      ...process.env,
      CONFIG_PATH: path.join(configDir, "panelarr.json"),
      DOCKER_SOCKET: "/nonexistent",
    },
  },
});
