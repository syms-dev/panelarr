/**
 * Logout -> login page -> bad password -> good login (contracts B/C).
 */
import { expect, test } from "@playwright/test";

import { ADMIN_PASSWORD, ADMIN_USER, ensureSetupComplete, loginViaApi } from "./helpers";

test("logout, reject a bad password, then sign in again", async ({ page }) => {
  await ensureSetupComplete(page);
  await loginViaApi(page);
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto("/");
  await expect(page).toHaveURL(/\/$/);

  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page).toHaveURL(/\/login/);

  await page.getByLabel("Username").fill(ADMIN_USER);
  await page.getByLabel("Password").fill("definitely-wrong");
  await page.getByRole("button", { name: "Sign In" }).click();
  await expect(page.getByRole("alert").or(page.locator("[role=alert]")).first()).toBeVisible();
  await expect(page).toHaveURL(/\/login/);

  await page.getByLabel("Password").fill(ADMIN_PASSWORD);
  await page.getByRole("button", { name: "Sign In" }).click();
  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByRole("button", { name: "Sign out" })).toBeVisible();
});

test("an unauthenticated deep link returns to it after login (?next=)", async ({ page }) => {
  await ensureSetupComplete(page);
  await page.goto("/movies");
  await expect(page).toHaveURL(/\/login\?next=%2Fmovies/);
  await page.getByLabel("Username").fill(ADMIN_USER);
  await page.getByLabel("Password").fill(ADMIN_PASSWORD);
  await page.getByRole("button", { name: "Sign In" }).click();
  await expect(page).toHaveURL(/\/movies$/);
});
