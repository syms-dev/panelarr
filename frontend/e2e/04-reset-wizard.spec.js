/**
 * Settings -> Re-run Setup Wizard sends the X-Confirm-Reset header (contract A)
 * and lands on /setup.
 */
import { expect, test } from "@playwright/test";

import { ensureSetupComplete, loginViaApi } from "./helpers";

test("reset wizard sends the confirm header and lands on /setup", async ({ page }) => {
  await ensureSetupComplete(page);
  await loginViaApi(page);
  await page.setViewportSize({ width: 1280, height: 800 });

  let confirmHeader;
  page.on("request", (req) => {
    if (req.url().endsWith("/api/setup/reset") && req.method() === "POST") {
      confirmHeader = req.headers()["x-confirm-reset"];
    }
  });

  await page.goto("/settings");
  await page.getByRole("button", { name: "Re-run Setup Wizard" }).click();
  await page.getByRole("button", { name: "Wipe and Re-run Wizard" }).click();

  await expect(page).toHaveURL(/\/setup/);
  expect(confirmHeader).toBe("true");
});
