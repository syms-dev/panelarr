/**
 * Wizard happy path (depends on backend contract B: setup/auth sets the
 * session cookie so the wizard can continue after the auth step).
 */
import { expect, test } from "@playwright/test";

import { ADMIN_PASSWORD, ADMIN_USER, walkWizard } from "./helpers";

test("wizard: welcome -> auth (basic) -> skip optional steps -> dashboard", async ({ page }) => {
  // A fresh instance sends every app route to the wizard.
  await page.goto("/");
  await expect(page).toHaveURL(/\/setup/);

  await walkWizard(page, async () => {
    await page.getByLabel("Username & Password").check();
    await page.locator("#auth-username").fill(ADMIN_USER);
    await page.locator("#auth-password").fill(ADMIN_PASSWORD);
    await page.locator("#auth-confirm").fill(ADMIN_PASSWORD);
  });

  await page.getByRole("button", { name: "Open Dashboard" }).click();
  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByRole("heading", { name: /dashboard|overview/i }).first()).toBeVisible();
});
