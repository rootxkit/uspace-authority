// The overview's counts (/v1/overview/*): each tile shows what the BFF
// serves the same session, the statuses api counted in words, and
// nothing for a role whose reads do not admit it (no tile and no
// request). A refused read is a dash with the reason, never a zero; a
// count at api's bound says "at least"; a police session is refused by
// api. Every wait is on a condition, never on a sleep.
import { expect, test, type APIRequestContext, type Page } from "@playwright/test";
import { ADMIN, AUDITOR, POLICE, REGISTRAR, apiCalls, resetMock, signIn, signInTo } from "./helpers";

test.beforeEach(async ({ request }) => {
  await resetMock(request);
});

/** What the BFF serves this session for path: its status and body. */
async function served(page: Page, path: string): Promise<{ status: number; body: Record<string, unknown> }> {
  return page.evaluate(async (p) => {
    const r = await fetch(`/_bff/api${p}`);
    return { status: r.status, body: (await r.json()) as Record<string, unknown> };
  }, path);
}

async function overviewControl(request: APIRequestContext, data: Record<string, unknown>): Promise<void> {
  expect((await request.post("/__mock/overview", { data })).ok()).toBe(true);
}

const DOMAINS = ["registry", "uspace", "certificates", "audit"] as const;

async function overviewReads(request: APIRequestContext): Promise<string[]> {
  return (await apiCalls(request)).filter((c) => c.path.startsWith("/v1/overview/")).map((c) => c.path);
}

test("a registrar sees the registry's counts as the BFF serves them, and reads no other count", async ({ page, request }) => {
  await signIn(page, "en", REGISTRAR);
  const { status, body } = await served(page, "/v1/overview/registry");
  expect(status).toBe(200);
  for (const [tile, member] of [
    ["kpi-operators", "operators"],
    ["kpi-uas", "uas"],
    ["kpi-pilots", "pilots"],
  ] as const) {
    const counts = body[member] as Record<string, number>;
    const el = page.getByTestId(tile);
    await expect(el).toHaveAttribute("data-state", "loaded");
    await expect(el).toHaveAttribute("data-count", String(counts["total"]));
    // Every status api counted is listed with its count, and none it did not.
    const listed = el.getByTestId(`${tile}-breakdown`).locator("[data-status]");
    const want = ["active", "suspended", "revoked", "expired"].filter((s) => (counts[s] ?? 0) > 0);
    await expect(listed).toHaveCount(want.length);
    for (const s of want) await expect(el.getByTestId(`${tile}-breakdown`).locator(`[data-status="${s}"]`)).toHaveAttribute("data-count", String(counts[s]));
  }
  await expect(page.getByTestId("kpi-operators")).toContainText("Registered operators");
  await expect(page.getByTestId("kpi-operators-breakdown")).toContainText("Active: 12");
  await expect(page.getByTestId("kpi-operators").getByRole("link", { name: "Open the list" })).toHaveAttribute("href", "/en/registry/operators");
  for (const tile of ["kpi-uspace", "kpi-certificates", "kpi-audit"]) await expect(page.getByTestId(tile)).toHaveCount(0);
  // The registry read is the only count the page asked for (plus the one this test asked for).
  expect(new Set(await overviewReads(request))).toEqual(new Set(["/v1/overview/registry"]));
});

test("an admin sees the U-space, certificate and audit counts and no registry count (the pair above)", async ({ page, request }) => {
  await signInTo(page, "en", ADMIN, /\/en$/);
  for (const [tile, path, member] of [
    ["kpi-uspace", "/v1/overview/uspace", "total"],
    ["kpi-certificates", "/v1/overview/certificates", "total"],
    ["kpi-audit", "/v1/overview/audit", "events"],
  ] as const) {
    const { status, body } = await served(page, path);
    expect(status, path).toBe(200);
    await expect(page.getByTestId(tile)).toHaveAttribute("data-state", "loaded");
    await expect(page.getByTestId(tile)).toHaveAttribute("data-count", String(body[member]));
  }
  await expect(page.getByTestId("kpi-uspace-breakdown")).toContainText("Published: 2");
  await expect(page.getByTestId("kpi-certificates-breakdown")).toContainText("Operating: 3");
  await expect(page.getByTestId("kpi-audit")).toHaveAttribute("data-more", "false");
  await expect(page.getByTestId("kpi-audit")).toContainText("The 24 hours to");
  await expect(page.getByTestId("kpi-operators")).toHaveCount(0);
  expect((await overviewReads(request)).filter((p) => p === "/v1/overview/registry")).toEqual([]);
  // api refuses the admin the registry's counts too, so the console asks for none.
  expect((await served(page, "/v1/overview/registry")).status).toBe(403);
});

test("an auditor sees the audit count alone; at api's bound it says at least", async ({ page, request }) => {
  await overviewControl(request, { auditMore: true });
  await signInTo(page, "en", AUDITOR, /\/en$/);
  const audit = page.getByTestId("kpi-audit");
  await expect(audit).toHaveAttribute("data-state", "loaded");
  await expect(audit).toHaveAttribute("data-more", "true");
  await expect(audit).toContainText("at least 100000");
  for (const tile of ["kpi-operators", "kpi-uspace", "kpi-certificates"]) await expect(page.getByTestId(tile)).toHaveCount(0);
  expect(new Set(await overviewReads(request))).toEqual(new Set(["/v1/overview/audit"]));
});

test("a refused count is a dash with the reason, never a zero, beside the counts that loaded", async ({ page, request }) => {
  await overviewControl(request, { refuse: ["certificates"] });
  await signInTo(page, "en", ADMIN, /\/en$/);
  const certs = page.getByTestId("kpi-certificates");
  await expect(certs).toHaveAttribute("data-state", "refused");
  await expect(certs).not.toHaveAttribute("data-count", /.*/);
  await expect(certs).toContainText("api refused the read (status 503)");
  await expect(page.getByTestId("kpi-uspace")).toHaveAttribute("data-state", "loaded");
});

test("the Georgian overview names the counts and their statuses in Georgian", async ({ page }) => {
  await signIn(page, "ka", REGISTRAR);
  await expect(page.getByTestId("kpi-operators")).toHaveAttribute("data-state", "loaded");
  await expect(page.getByTestId("kpi-operators")).toContainText("რეგისტრირებული ოპერატორები");
  await expect(page.getByTestId("kpi-operators-breakdown")).toContainText("აქტიური: 12");
});

test("a police session is refused every count by api", async ({ page }) => {
  await signInTo(page, "en", POLICE, /\/en\/police$/);
  for (const d of DOMAINS) {
    const { status, body } = await served(page, `/v1/overview/${d}`);
    expect(status, d).toBe(403);
    expect(body["type"], d).toBe("https://schemas.uspace.ge/problems/forbidden");
  }
});

test("no session is refused before any count (401)", async ({ page }) => {
  await page.goto("/en/login");
  for (const d of DOMAINS) expect((await served(page, `/v1/overview/${d}`)).status, d).toBe(401);
});
