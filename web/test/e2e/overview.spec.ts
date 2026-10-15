// The overview, the console's landing page: its figures are what api and
// picture-ws answer, counted, never a default. An inspector's queues
// equal what the BFF serves the same session; an incident officer sees
// the reports to classify and an inspector does not (the pair); a role
// whose reads admit no queue sees none and is told why. Every wait is on
// a condition, never on a sleep.
import { expect, test, type Page } from "@playwright/test";
import { ADMIN, INSPECTOR, OFFICER, REGISTRAR, apiCalls, consoleNav, resetMock, signIn, signInTo } from "./helpers";

test.beforeEach(async ({ request }) => {
  await resetMock(request);
});

/** The number of rows the BFF serves this session for `path`, as the page would read it. */
async function served(page: Page, path: string, member: string): Promise<number> {
  return page.evaluate(
    async ([p, m]) => {
      const body = (await (await fetch(`/_bff/api${String(p)}`)).json()) as Record<string, unknown[]>;
      return (body[String(m)] ?? []).length;
    },
    [path, member] as const,
  );
}

test("an inspector lands on the overview: the picture's figures and the review queue as api serves them", async ({ page }) => {
  await signIn(page, "en", INSPECTOR);
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Overview");
  await expect(consoleNav(page).getByRole("link", { name: "Overview" })).toHaveAttribute("aria-current", "page");

  // The picture's figures: the lab's three tracks, the snapshot's one active violation.
  await expect(page.getByTestId("kpi-tracks")).toHaveAttribute("data-count", "3");
  await expect(page.getByTestId("kpi-tracks")).toContainText("2 unverified");
  await expect(page.getByTestId("kpi-active-violations")).toHaveAttribute("data-count", "1");
  await expect(page.getByTestId("overview-alerts")).toContainText("1 active");
  await expect(page.getByTestId("kpi-sources")).toHaveAttribute("data-healthy", /^[0-9]+$/);

  // The review queue equals what the BFF serves this session, and its rows link to the violations.
  const review = page.getByTestId("kpi-review");
  await expect(review).toHaveAttribute("data-state", "loaded");
  const newOnes = await served(page, "/v1/violations?status=new&limit=200", "violations");
  expect(newOnes).toBeGreaterThan(0);
  await expect(review).toHaveAttribute("data-count", String(newOnes));
  await page.getByTestId("overview-review").getByRole("link").nth(1).click();
  await expect(page.getByTestId("violation-detail")).toBeVisible();

  await page.goto("/en");
  const incidents = await served(page, "/v1/incidents?status=open&limit=200", "incidents");
  await expect(page.getByTestId("kpi-incidents")).toHaveAttribute("data-count", String(incidents));
  // An inspector is not offered the occurrence reports, and none is read for it.
  await expect(page.getByTestId("kpi-occurrences")).toHaveCount(0);
  await expect(page.getByTestId("kpi-zones")).toHaveAttribute("data-state", "loaded");
});

test("an incident officer sees the reports to classify (the pair above), read with the received state", async ({ page, request }) => {
  await signInTo(page, "en", OFFICER, /\/en$/);
  const tile = page.getByTestId("kpi-occurrences");
  await expect(tile).toHaveAttribute("data-state", "loaded");
  const received = await served(page, "/v1/occurrences?state=received&limit=200", "occurrences");
  await expect(tile).toHaveAttribute("data-count", String(received));
  await expect(page.getByTestId("kpi-review")).toHaveCount(0);
  const read = (await apiCalls(request)).find((c) => c.path === "/v1/occurrences");
  expect(read?.query).toEqual(["limit", "state"]);
});

test("an inspector's overview reads no occurrence report", async ({ page, request }) => {
  await signIn(page, "en", INSPECTOR);
  await expect(page.getByTestId("kpi-review")).toHaveAttribute("data-state", "loaded");
  expect((await apiCalls(request)).filter((c) => c.path.startsWith("/v1/occurrences"))).toEqual([]);
});

test("a registrar's overview has no queue and says why; an admin's has the zones and no queue either", async ({ page, browser }) => {
  await signIn(page, "en", REGISTRAR);
  await expect(page.getByTestId("kpi-tracks")).toHaveAttribute("data-count", /^[0-9]+$/);
  await expect(page.getByTestId("kpi-review")).toHaveCount(0);
  await expect(page.getByTestId("kpi-zones")).toHaveCount(0);
  await expect(page.getByText("No work queue for your roles")).toBeVisible();

  const admin = await browser.newPage();
  await signInTo(admin, "en", ADMIN, /\/en$/);
  await expect(admin.getByTestId("kpi-zones")).toHaveAttribute("data-state", "loaded");
  await expect(admin.getByTestId("kpi-incidents")).toHaveCount(0);
  await admin.close();
});

test("the top bar's pill says the feed is live on the overview and is absent on a page without the feed", async ({ page }) => {
  await signIn(page, "en", INSPECTOR);
  const pill = page.locator('[data-slot="status-pill"]');
  await expect(pill).toHaveAttribute("data-state", "live");
  await expect(pill).toContainText("Live");
  await consoleNav(page).getByRole("link", { name: "Violations" }).click();
  await expect(page.getByTestId("violations-table")).toBeVisible();
  await expect(pill).toHaveCount(0);
});
