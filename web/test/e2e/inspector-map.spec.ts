// The inspector map against the stub api and the stub picture-ws of
// test/mock-origin.mjs: sign-in in two steps through the real BFF, the
// map with the lab's picture, the bus lost and the picture frozen with
// ages, a revoked session closed with 4401, and the role-shaped zones.
// Every wait is on a condition, never on a sleep.
import { expect, test } from "@playwright/test";
import { AUTHENTICATED_TRACK, BROADCAST_TRACK, INSPECTOR, PROVIDER_TRACK, REGISTRAR, mockState, resetMock, signIn } from "./helpers";

test.beforeEach(async ({ request }) => {
  await resetMock(request);
});

test("a page without a session is the sign-in page", async ({ page }) => {
  await page.goto("/en");
  await expect(page).toHaveURL(/\/en\/login$/);
});

test("sign-in → map → the tracks appear with trust, identification and age", async ({ page, request, context }) => {
  await signIn(page, "en", INSPECTOR);

  // The cookies of the session contract: the JWT HttpOnly, the CSRF value readable.
  const cookies = await context.cookies();
  const session = cookies.find((c) => c.name === "uspace_session");
  expect(session?.httpOnly).toBe(true);
  expect(session?.secure).toBe(true);
  expect(session?.sameSite).toBe("Strict");
  expect(cookies.find((c) => c.name === "uspace_csrf")?.httpOnly).toBe(false);
  expect(cookies.some((c) => c.name === "uspace_mfa")).toBe(false);
  expect(await page.evaluate(() => document.cookie)).not.toContain("uspace_session");

  const list = page.getByTestId("track-list");
  await expect(list.locator(`[data-track="${BROADCAST_TRACK}"]`)).toBeVisible();
  await expect(list.locator(`[data-track="${AUTHENTICATED_TRACK}"]`)).toBeVisible();
  await expect(list.locator(`[data-track="${PROVIDER_TRACK}"]`)).toBeVisible();

  // R-05: every broadcast and provider track says so; the authenticated one does not.
  await expect(list.locator(`[data-track="${BROADCAST_TRACK}"]`).getByTestId("unverified")).toHaveText("as broadcast and unverified");
  await expect(list.locator(`[data-track="${PROVIDER_TRACK}"]`).getByTestId("unverified")).toBeVisible();
  await expect(list.locator(`[data-track="${AUTHENTICATED_TRACK}"]`).getByTestId("unverified")).toHaveCount(0);
  await expect(list.locator(`[data-track="${BROADCAST_TRACK}"]`)).toHaveAttribute("data-ident", "unknown_operator");

  // The thresholds are the status frame's (the lab's example: 5 s and 2 s), never a default.
  await expect(page.getByTestId("thresholds")).toContainText("stale after 5 s, live within 2 s, policy demo-2026-10-01");
  await expect(page.getByTestId("dropped-frames")).toHaveText("0");

  // The active violation from the snapshot (C-08); the lab's minimal alert is counted as refused.
  await expect(page.getByTestId("violations").locator("[data-violation]")).toHaveCount(1);
  await expect(page.getByTestId("violations")).toContainText("Above the height limit");
  await expect(page.getByTestId("not-shown")).toContainText(/[1-9][0-9]* violation frames refused/);

  // The sources: the disabled one says by whom; the never-heard one says so.
  await expect(page.getByText("admin:n.beridze", { exact: false })).toBeVisible();
  await expect(page.getByText("never heard", { exact: false }).first()).toBeVisible();

  // The subscription carried the viewport and the layers, nothing else.
  const subs = (await (await request.get("/__mock/subscribes")).json()) as { bbox: number[]; layers: string[] }[];
  expect(subs.length).toBeGreaterThan(0);
  expect(subs[0]?.layers).toEqual(["tracks", "alerts", "zones"]);
  expect(subs[0]?.bbox).toHaveLength(4);
});

test("the provider track's operator position and the registration secret never reach the page", async ({ page }) => {
  await signIn(page, "en", INSPECTOR);
  const row = page.getByTestId("track-list").locator(`[data-track="${PROVIDER_TRACK}"]`);
  await row.getByRole("button").click();
  const detail = page.getByTestId("track-detail");
  await expect(detail).toContainText("GEOTEST0042OPR");
  const html = await page.content();
  // test/fixtures/provider-track.json: operator_position 41.70987, 44.77654; operator_reg with the
  // EU secret part "-Q9Z", which picture-ws never sends (G-04): a defect upstream the kit keeps off the screen.
  expect(html).not.toContain("41.70987");
  expect(html).not.toContain("44.77654");
  expect(html).not.toContain("Q9Z");
});

test("the bus lost: the banner says since when, and the tracks stay and age", async ({ page, request }) => {
  await signIn(page, "en", INSPECTOR);
  const row = page.getByTestId("track-list").locator(`[data-track="${BROADCAST_TRACK}"]`);
  await expect(row).toBeVisible();
  await expect(page.getByTestId("degraded-banner")).toHaveCount(0);

  await mockState(request, { nats: "unavailable", natsSince: "2026-10-02T09:20:00.000Z" });
  const banner = page.getByTestId("degraded-banner");
  await expect(banner.locator('[data-slug="nats_unavailable"]')).toContainText("The bus is unavailable since 2026-10-02 09:20:00 UTC");

  // E-02: nothing leaves the picture, and the age keeps counting.
  await expect(row).toBeVisible();
  await expect(page.getByTestId("track-list").locator("[data-track]")).toHaveCount(3);
  const ageText = async () => (await row.locator("text=/since captured/").textContent()) ?? "";
  const first = await ageText();
  await expect.poll(ageText, { timeout: 15_000 }).not.toBe(first);

  // The pair: the bus back, the banner goes.
  await mockState(request, { nats: "connected" });
  await expect(page.getByTestId("degraded-banner")).toHaveCount(0);
});

test("a revoked session closes the picture with 4401 and the page returns to sign-in", async ({ page, request }) => {
  await signIn(page, "en", INSPECTOR);
  await expect(page.getByTestId("track-list")).toBeVisible();
  await mockState(request, { revoke: true });
  await expect(page).toHaveURL(/\/en\/login$/, { timeout: 15_000 });
});

test("sign-out ends the session at api and clears the cookies", async ({ page, request, context }) => {
  await signIn(page, "en", INSPECTOR);
  await page.getByTestId("account-menu").click();
  await expect(page.getByTestId("account-roles")).toHaveText("Roles: inspector");
  await page.getByTestId("sign-out").click();
  await expect(page).toHaveURL(/\/en\/login$/);
  expect((await context.cookies()).some((c) => c.name === "uspace_session" && c.value !== "")).toBe(false);
  const calls = (await (await request.get("/__mock/requests")).json()) as { method: string; path: string }[];
  expect(calls).toContainEqual(expect.objectContaining({ method: "POST", path: "/v1/auth/logout" }));
});

test("zones: drawn for an inspector, the circle listed as not drawn; refused for a registrar, and said", async ({ page, browser }) => {
  await signIn(page, "en", INSPECTOR);
  await expect(page.getByTestId("zones-undrawn")).toContainText("TSTC001");
  await expect(page.getByTestId("zones-refused")).toHaveCount(0);

  const other = await browser.newPage();
  await signIn(other, "en", REGISTRAR);
  await expect(other.getByTestId("zones-refused")).toContainText("status 403");
  await other.close();
});

test("the BFF proxy reaches only its allow-list; the pair reaches api", async ({ page, request }) => {
  await signIn(page, "en", INSPECTOR);
  const status = (path: string) => page.evaluate(async (p) => (await fetch(p)).status, path);
  expect(await status("/_bff/api/v1/auth/session")).toBe(200);
  expect(await status("/_bff/api/v1/users")).toBe(404);
  const calls = (await (await request.get("/__mock/requests")).json()) as { path: string }[];
  expect(calls.some((c) => c.path === "/v1/auth/session")).toBe(true);
  expect(calls.some((c) => c.path === "/v1/users")).toBe(false);
  // DELETE is not routed at all; a write without the CSRF pair is refused
  // by the BFF; a method a WP-23 path does not take is refused by the BFF.
  const method = (m: string, p: string) => page.evaluate(async ([mm, pp]) => (await fetch(pp ?? "", { method: mm })).status, [m, p]);
  expect(await method("DELETE", "/_bff/api/v1/zones")).toBe(405);
  expect(await method("POST", "/_bff/api/v1/zones")).toBe(403);
  expect(await method("POST", "/_bff/api/v1/violations")).toBe(405);
  const after = (await (await request.get("/__mock/requests")).json()) as { method: string; path: string }[];
  expect(after.some((c) => c.method !== "GET" && (c.path === "/v1/zones" || c.path === "/v1/violations"))).toBe(false);
});
