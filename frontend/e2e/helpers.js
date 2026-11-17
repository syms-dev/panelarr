/**
 * Shared helpers for the e2e specs.
 */
import { expect } from "@playwright/test";

export const ADMIN_USER = "admin";
export const ADMIN_PASSWORD = "Panelarr-e2e-Passw0rd!";

/**
 * Complete the wizard through the HTTP API (idempotent), so specs that do not
 * test the wizard can start from a configured instance. Uses page.request so
 * session cookies land in the browser context.
 *
 * @param {import("@playwright/test").Page} page
 * @returns {Promise<void>}
 */
export async function ensureSetupComplete(page) {
  const status = await (await page.request.get("/api/setup/status")).json();
  if (status.setup_complete) return;
  const auth = await page.request.post("/api/setup/auth", {
    data: { mode: "basic", username: ADMIN_USER, password: ADMIN_PASSWORD },
  });
  expect(auth.ok(), `setup/auth failed: ${auth.status()}`).toBeTruthy();
  const done = await page.request.post("/api/setup/complete");
  expect(done.ok(), `setup/complete failed: ${done.status()}`).toBeTruthy();
}

/**
 * Log in through the API (cookie lands in the browser context).
 *
 * @param {import("@playwright/test").Page} page
 * @returns {Promise<void>}
 */
export async function loginViaApi(page) {
  const resp = await page.request.post("/api/auth/login", {
    data: { username: ADMIN_USER, password: ADMIN_PASSWORD },
  });
  expect(resp.ok(), `login failed: ${resp.status()}`).toBeTruthy();
}

/**
 * Click through the wizard from the current step until /setup/done.
 *
 * @param {import("@playwright/test").Page} page
 * @param {() => Promise<void>} fillAuth Fills the auth step when reached.
 * @returns {Promise<void>}
 */
export async function walkWizard(page, fillAuth) {
  await page.goto("/setup/welcome");
  await page.getByRole("button", { name: "Get Started" }).click();
  await expect(page).toHaveURL(/\/setup\/system-check$/);
  await page.getByRole("button", { name: "Next" }).click();
  await expect(page).toHaveURL(/\/setup\/auth$/);
  await fillAuth();
  await page.getByRole("button", { name: "Next" }).click();
  await expect(page).toHaveURL(/\/setup\/discover$/);
  await page.getByRole("button", { name: "Next" }).click();
  await expect(page).toHaveURL(/\/setup\/services$/);
  await page.getByRole("button", { name: /^(Skip remaining|Next)$/ }).click();
  await expect(page).toHaveURL(/\/setup\/notifications$/);
  await page.getByRole("button", { name: "Skip" }).click();
  await expect(page).toHaveURL(/\/setup\/thresholds$/);
  await page.getByRole("button", { name: "Skip" }).click();
  await expect(page).toHaveURL(/\/setup\/done$/);
}

/**
 * Complete setup and log in once, returning the session cookies so tests can
 * install them with `context.addCookies` (the login endpoint is rate limited).
 *
 * @param {import("@playwright/test").Browser} browser
 * @returns {Promise<import("@playwright/test").Cookie[]>} Session cookies.
 */
export async function loginOnce(browser) {
  const context = await browser.newContext({ baseURL: "http://127.0.0.1:8811" });
  const page = await context.newPage();
  await ensureSetupComplete(page);
  await loginViaApi(page);
  const cookies = await context.cookies();
  await context.close();
  return cookies;
}
