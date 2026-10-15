// The public pages without a session: the registration check renders the
// status only (the stub adds a member api never sends, and the page must
// not show it), the register of certified providers, and the rules from
// the deployment's Markdown, configured for en and not for ka in this
// run, which names the variable instead (INV-03). Both languages render.
import { expect, test } from "@playwright/test";
import { resetMock } from "./helpers";

test.beforeEach(async ({ request }) => {
  await resetMock(request);
});

test("the public check answers the status only", async ({ page, context }) => {
  await page.goto("/en/check");
  expect((await context.cookies()).some((c) => c.name === "uspace_session")).toBe(false);
  await page.getByTestId("check-number").fill("GEOTEST00000001");
  await page.getByTestId("check-submit").click();
  const answer = page.getByTestId("check-answer");
  await expect(answer).toHaveAttribute("data-status", "valid");
  await expect(answer).toContainText("Valid until 2027-01-01");
  expect(await page.content()).not.toContain("PROBE-NEVER-RENDERED");

  await page.getByTestId("check-number").fill("GEOTEST00000099");
  await page.getByTestId("check-submit").click();
  await expect(page.getByTestId("check-answer")).toHaveAttribute("data-status", "unknown");
});

test("the register and the check in Georgian", async ({ page }) => {
  await page.goto("/ka/register");
  await expect(page.getByTestId("register-table").locator('[data-certificate="USSPTST"]')).toContainText("Test USSP Ltd");
  await expect(page.locator("h1")).toHaveText("სერტიფიცირებული U-space სერვისის პროვაიდერები");
  await page.goto("/ka/check");
  await expect(page.locator("h1")).toHaveText("ოპერატორის რეგისტრაციის შემოწმება");
});

test("the rules: rendered from the configured file in en, and naming the variable where none is configured (ka)", async ({ page }) => {
  await page.goto("/en/rules");
  const rules = page.getByTestId("rules");
  await expect(rules.locator("h2")).toHaveText("Test rules for flying");
  await expect(rules.locator("li")).toHaveCount(2);
  await expect(rules.getByRole("link", { name: "the public check" })).toHaveAttribute("href", "/en/check");
  // HTML in the file stays text.
  await expect(rules).toContainText("<b>not bold</b>");
  await expect(page.locator("article b")).toHaveCount(0);

  await page.goto("/ka/rules");
  await expect(page.getByTestId("rules-problem")).toContainText("WEB_RULES_FILE_KA");
});

// The register's services cell is a long list; it must wrap, not widen the
// page. At 1280px neither the page nor the table's container may scroll
// sideways (the container scrolls only below 640px as a fallback).
for (const lang of ["en", "ka"] as const) {
  test(`the register fits a 1280px viewport without sideways scroll (${lang})`, async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 800 });
    await page.goto(`/${lang}/register`);
    const table = page.getByTestId("register-table");
    await expect(table.locator('[data-certificate="USSPTST"]')).toBeVisible();
    const m = await page.evaluate(() => {
      const root = document.scrollingElement as Element;
      const box = document.querySelector('[data-testid="register-table"]')?.parentElement as HTMLElement;
      return {
        pageScroll: root.scrollWidth,
        pageClient: root.clientWidth,
        boxScroll: box.scrollWidth,
        boxClient: box.clientWidth,
      };
    });
    expect(m.pageScroll).toBeLessThanOrEqual(m.pageClient);
    expect(m.boxScroll).toBeLessThanOrEqual(m.boxClient);
  });
}
