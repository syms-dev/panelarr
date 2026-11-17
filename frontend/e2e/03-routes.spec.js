/**
 * Smoke test every app route at desktop and mobile sizes: no uncaught
 * exceptions, no unexpected console errors, no horizontal overflow. Docker is
 * unavailable and no services are configured, so failed resource loads
 * (503/4xx from those endpoints) are expected and filtered out.
 */
import { expect, test } from "@playwright/test";

import { loginOnce } from "./helpers";

// Log in a single time (the login endpoint is rate limited) and reuse the
// session cookies for every route test.
let sessionCookies = [];

const ROUTES = ["/", "/movies", "/shows", "/calendar", "/containers", "/downloads", "/settings", "/no-such-page"];
const VIEWPORTS = [
  { name: "desktop", width: 1280, height: 800 },
  { name: "mobile", width: 390, height: 844 },
];

/** Browser-emitted noise for failed fetches (503 docker / unconfigured services). */
const EXPECTED_ERROR = /Failed to load resource|status of (4|5)\d\d/i;

test.beforeAll(async ({ browser }) => {
  sessionCookies = await loginOnce(browser);
});

for (const viewport of VIEWPORTS) {
  test.describe(`routes @ ${viewport.name}`, () => {
    test.use({ viewport: { width: viewport.width, height: viewport.height } });

    test.beforeEach(async ({ context }) => {
      await context.addCookies(sessionCookies);
    });

    for (const route of ROUTES) {
      test(`${route} renders cleanly`, async ({ page }) => {
        const pageErrors = [];
        const consoleErrors = [];
        page.on("pageerror", (err) => pageErrors.push(err.message));
        page.on("console", (msg) => {
          if (msg.type() === "error" && !EXPECTED_ERROR.test(msg.text())) {
            consoleErrors.push(msg.text());
          }
        });

        await page.goto(route);
        await page.waitForLoadState("networkidle").catch(() => {});
        await page.waitForTimeout(500);
        await expect(page.locator("#root")).not.toBeEmpty();
        // Must be on the page itself, not bounced to the wizard or login.
        await expect(page).not.toHaveURL(/\/(login|setup)/);

        const overflow = await page.evaluate(
          () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
        );
        expect(overflow, "horizontal overflow (px)").toBeLessThanOrEqual(1);
        expect(pageErrors).toEqual([]);
        expect(consoleErrors).toEqual([]);
      });
    }
  });
}
