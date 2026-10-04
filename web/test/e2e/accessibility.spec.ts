// The axe check of WP-23's pages (WCAG 2.2 AA, the target pending GCAA,
// as the kit's example sets it): every role's pages in English light and
// Georgian dark, run through the debugging protocol so the page's CSP
// still governs every script of its own. A page that fails lists the
// rule, how many nodes and the first one.
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { expect, test, type Page } from "@playwright/test";
import { INSPECTOR, OFFICER, POLICE, resetMock, signInTo } from "./helpers";

const AXE_SOURCE = readFileSync(createRequire(import.meta.url).resolve("axe-core/axe.min.js"), "utf8");
const AXE_TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22a", "wcag22aa"];

interface AxeWindow {
  axe: { run(ctx: Document, opts: unknown): Promise<{ violations: { id: string; nodes: { target: string[] }[] }[] }> };
}

async function axeViolations(page: Page): Promise<string[]> {
  await page.evaluate(AXE_SOURCE);
  return page.evaluate(async (tags) => {
    const r = await (globalThis as unknown as AxeWindow).axe.run(document, { runOnly: { type: "tag", values: tags } });
    return r.violations.map((v) => `${v.id} (${v.nodes.length}): ${v.nodes[0]?.target.join(" ") ?? ""}`);
  }, AXE_TAGS);
}

/** Waits for the page's content, then runs axe on it. */
async function check(page: Page, path: string, ready: string): Promise<void> {
  await page.goto(path);
  await expect(page.getByTestId(ready).first()).toBeVisible();
  expect(await axeViolations(page), path).toEqual([]);
}

test.beforeEach(async ({ request }) => {
  await resetMock(request);
});

for (const setup of [
  { lang: "en" as const, colorScheme: "light" as const },
  { lang: "ka" as const, colorScheme: "dark" as const },
]) {
  test.describe(`${setup.lang} ${setup.colorScheme}`, () => {
    test.use({ colorScheme: setup.colorScheme });
    const l = setup.lang;

    test("the public pages", async ({ page }) => {
      await check(page, `/${l}/check`, "check-form");
      await check(page, `/${l}/register`, "register-table");
      await check(page, `/${l}/rules`, l === "en" ? "rules" : "rules-problem");
    });

    test("the inspector's violations", async ({ page }) => {
      await signInTo(page, l, INSPECTOR, new RegExp(`/${l}$`));
      await check(page, `/${l}/violations`, "violations-table");
      await page.getByTestId("violations-table").locator("[data-violation-row]").first().getByRole("link").click();
      await expect(page.getByTestId("excerpt-samples")).toBeVisible();
      expect(await axeViolations(page), "violation detail").toEqual([]);
      await check(page, `/${l}/incidents`, "incidents-table");
    });

    test("the incident officer's occurrence reports", async ({ page }) => {
      await signInTo(page, l, OFFICER, new RegExp(`/${l}$`));
      await check(page, `/${l}/occurrences`, "occurrences-table");
      await check(page, `/${l}/occurrences/export`, "narrative-warning");
    });

    test("the police realm", async ({ page }) => {
      await signInTo(page, l, POLICE, new RegExp(`/${l}/police$`));
      await check(page, `/${l}/police`, "query-basis");
      await check(page, `/${l}/police/exports`, "export-new");
    });
  });
}

test("a page that fails axe is found (the pair of the checks above)", async ({ page }) => {
  await page.goto("/en/check");
  await expect(page.getByTestId("check-form")).toBeVisible();
  // An image without a name: axe's image-alt rule must catch it.
  await page.evaluate(() => {
    const img = document.createElement("img");
    img.src = "data:image/gif;base64,R0lGODlhAQABAAAAACw=";
    document.querySelector("main")?.appendChild(img);
  });
  expect((await axeViolations(page)).some((v) => v.startsWith("image-alt"))).toBe(true);
});
