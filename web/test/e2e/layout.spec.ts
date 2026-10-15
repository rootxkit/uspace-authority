// The list pages read at the widths the console is used at (1024 and
// 1440 px, the sidebar open), in English light and Georgian dark: no
// page or table wider than its container, no ED-318 enumeration or raw
// field name where a label belongs, the audit log's rows one or two lines
// with long ids shortened, the table's keyboard help for screen readers
// only, and no API pager drawn when api has nothing more. With
// UI_SHOTS_DIR set, each page is saved there at 1024 px.
import path from "node:path";
import { expect, test, type Page } from "@playwright/test";
import { ADMIN, resetMock, signInTo } from "./helpers";
import { VIEWER, expectAccessible, recorded } from "./authoring";

const SHOTS = process.env["UI_SHOTS_DIR"];

/** The ED-318 zone types as api sends them: never a label on a page. */
const RAW_ENUM = /\b(PROHIBITED|REQ_AUTHORIZATION|CONDITIONAL|NO_RESTRICTION|USPACE)\b/;
/** Field names as the API names them: never a column header. */
const RAW_FIELDS = ["identifier", "name", "type", "zone_version", "state", "valid_from", "valid_to", "code", "holder", "holder_name", "status", "valid_until"];

test.beforeEach(async ({ request }) => {
  await resetMock(request);
});

/** No horizontal scroll: neither the page nor a table wider than the box it sits in. */
async function expectNoOverflow(page: Page, where: string): Promise<void> {
  const o = await page.evaluate(() => ({
    page: document.documentElement.scrollWidth - document.documentElement.clientWidth,
    tables: [...document.querySelectorAll("main table")].map((t) => {
      const box = t.parentElement;
      return { over: t.scrollWidth - (box?.clientWidth ?? t.scrollWidth), caption: t.querySelector("caption")?.textContent ?? "" };
    }),
  }));
  expect(o.page, `${where}: the page scrolls sideways`).toBeLessThanOrEqual(0);
  for (const t of o.tables) expect(t.over, `${where}: the table "${t.caption}" is wider than its box`).toBeLessThanOrEqual(1);
}

/** The column headers name their columns in words, in the page's language. */
async function expectLabelledHeaders(page: Page, lang: "en" | "ka", where: string): Promise<void> {
  const headers = (await page.locator("main table thead th").allInnerTexts()).map((h) => h.trim()).filter((h) => h !== "");
  expect(headers.length, `${where}: headers`).toBeGreaterThan(0);
  for (const h of headers) {
    expect(RAW_FIELDS, `${where}: header "${h}"`).not.toContain(h);
    // Georgian headers are Georgian: no Latin word but the unit UTC.
    if (lang === "ka") expect(h.replace(/UTC/g, ""), `${where}: header "${h}"`).not.toMatch(/[A-Za-z]{2,}/);
  }
  expect(await page.locator("main").innerText(), `${where}: a raw ED-318 type`).not.toMatch(RAW_ENUM);
}

/** The kit DataTable's keyboard help is for a screen reader (sr-only), never drawn as text. */
async function expectKeyboardHelpHidden(page: Page): Promise<void> {
  const grid = page.locator('main table[role="grid"]').first();
  const hint = page.locator(`[id="${await grid.getAttribute("aria-describedby")}"]`);
  await expect(hint).toHaveCount(1);
  const box = await hint.boundingBox();
  expect(box === null || (box.width <= 1 && box.height <= 1)).toBe(true);
}

async function shot(page: Page, name: string, width: number): Promise<void> {
  if (SHOTS !== undefined && width === 1024) await page.screenshot({ path: path.join(SHOTS, `${name}.png`), fullPage: true });
}

for (const width of [1024, 1440]) {
  for (const { lang, colorScheme } of [
    { lang: "en" as const, colorScheme: "light" as const },
    { lang: "ka" as const, colorScheme: "dark" as const },
  ]) {
    test.describe(`${width} px, ${lang} ${colorScheme}`, () => {
      test.use({ viewport: { width, height: 900 }, colorScheme });

      test("zones, U-space airspaces and certificates fit, with labels instead of field names and enumerations", async ({ page }) => {
        await signInTo(page, lang, ADMIN, new RegExp(`/${lang}$`));
        await page.goto(`/${lang}/zones`);
        const zones = page.getByTestId("zones-page");
        await expect(zones.locator('[data-testid="zone-type"]')).toHaveCount(2);
        await expect(zones.locator('[data-testid="zone-type"][data-type="REQ_AUTHORIZATION"]')).toHaveText(lang === "en" ? "Authorisation required" : "საჭიროებს ნებართვას");
        // The type badge stays on one line.
        for (const b of await zones.locator('[data-testid="zone-type"]').all()) expect((await b.boundingBox())?.height ?? 99).toBeLessThan(28);
        // Every zone is drawn, the circle by api's outline: nothing is listed as not drawn.
        await expect(page.getByTestId("zones-map-undrawn")).toHaveCount(0);
        await expectNoOverflow(page, "/zones");
        await expectLabelledHeaders(page, lang, "/zones");
        await expectKeyboardHelpHidden(page);
        await expect(page.getByTestId("api-pager")).toHaveCount(0);
        await expectAccessible(page);
        await shot(page, `zones-${lang}-${colorScheme}`, width);

        await page.goto(`/${lang}/uspace`);
        await expect(page.getByTestId("uspace-page").locator("table")).toBeVisible();
        await expectNoOverflow(page, "/uspace");
        await expectLabelledHeaders(page, lang, "/uspace");
        await expect(page.getByTestId("api-pager")).toHaveCount(0);
        await expectAccessible(page);
        await shot(page, `uspace-${lang}-${colorScheme}`, width);

        await page.goto(`/${lang}/certificates`);
        await expect(page.getByTestId("certificates-page").locator("table tbody tr").first()).toBeVisible();
        await expectNoOverflow(page, "/certificates");
        await expectLabelledHeaders(page, lang, "/certificates");
        await expectKeyboardHelpHidden(page);
        await expectAccessible(page);
        await shot(page, `certificates-${lang}-${colorScheme}`, width);
      });

      test("the audit log fits, its rows one or two lines, long ids short with the whole id kept", async ({ page }) => {
        await signInTo(page, lang, ADMIN, new RegExp(`/${lang}$`));
        await page.goto(`/${lang}/audit`);
        await page.getByTestId("audit-search").click();
        const rows = page.getByTestId("audit-table").locator("[data-event]");
        await expect(rows).toHaveCount(3);
        await expectNoOverflow(page, "/audit");
        const line = await rows.first().evaluate((r) => parseFloat(getComputedStyle(r).lineHeight) || 20);
        for (const r of await rows.all()) expect((await r.boundingBox())?.height ?? 999, "an audit row taller than two lines").toBeLessThanOrEqual(2 * line + 24);

        // The account id api sent, 32 hex: shown short, whole in the tooltip
        // and to a screen reader; the entity id the same, with a copy button.
        const long = page.getByTestId("audit-table").locator('[data-event="13"]');
        const actor = long.getByTestId("audit-actor").locator('[data-id="315c707cc1b7d07d2ff8a23f5af46d97"]');
        await expect(actor).toHaveAttribute("title", "315c707cc1b7d07d2ff8a23f5af46d97");
        await expect(actor.locator('[aria-hidden="true"]')).toHaveText("315c707c…");
        await expect(long.getByTestId("audit-entity").locator('[data-id="01JTESTZONE0000000000000000"]')).toHaveAttribute("title", "01JTESTZONE0000000000000000");
        await expect(long.getByTestId("copy-id")).toHaveCount(1);
        // The pair: a short id is shown whole, without a tooltip.
        const short = page.getByTestId("audit-table").locator('[data-event="11"]').getByTestId("audit-actor").locator('[data-id="detect"]');
        await expect(short).toHaveText("detect");
        await expect(short).not.toHaveAttribute("title", /./);
        // The event type is a badge on one line; the hash is short, whole in its tooltip.
        const type = long.getByTestId("audit-event-type");
        await expect(type).toHaveText("zone_published");
        expect(await type.evaluate((e) => getComputedStyle(e).whiteSpace)).toBe("nowrap");
        await expect(long.getByTestId("audit-hash")).toHaveText(/^[0-9a-f]{8}$/);
        await expect(long.getByTestId("audit-hash")).toHaveAttribute("title", /^[0-9a-f]{64}$/);
        await expect(page.getByTestId("api-pager")).toHaveCount(0);
        await expectAccessible(page);
        await shot(page, `audit-${lang}-${colorScheme}`, width);
      });
    });
  }
}

test("the account menu shows the account id, and the sidebar title is never cut", async ({ page }) => {
  await page.setViewportSize({ width: 1024, height: 900 });
  await signInTo(page, "en", ADMIN, /\/en$/);
  // api's session names the account by its id only (SessionInfo.sub).
  await expect(page.getByTestId("account-menu")).toHaveAttribute("title", "user-admin1");
  await page.getByRole("button", { name: /^Account menu: / }).click();
  await expect(page.getByTestId("account-id")).toHaveText("Account id user-admin1");
  await page.keyboard.press("Escape");
  const title = page.locator("aside").getByTestId("system-name").first();
  await expect(title).toBeVisible();
  // Wrapped, not clipped: the text fits the box it is drawn in.
  expect(await title.evaluate((e) => e.scrollWidth <= e.clientWidth + 1 && e.scrollHeight <= e.clientHeight + 1)).toBe(true);
});

test("a circle a viewer may not have drawn is listed as not drawn (the pair of the circle drawn)", async ({ page, request }) => {
  await page.setViewportSize({ width: 1024, height: 900 });
  await signInTo(page, "en", VIEWER, /\/en$/);
  await page.goto("/en/zones");
  // api was asked to draw it, with the circle as published, and refused (403 to a viewer)...
  const asked = async () => (await recorded(request)).filter((r) => r.method === "GET" && r.path === "/v1/outlines/circle").at(-1)?.query;
  await expect.poll(asked).toEqual({ lat: "41.7", lng: "44.85", radius_m: "500" });
  // ...so it stays listed as not drawn, the polygon beside it drawn.
  await expect(page.getByTestId("zones-map-undrawn")).toContainText("TSTC001");
  await expect(page.getByTestId("zones-map-undrawn")).not.toContainText("TSTP001");
});
