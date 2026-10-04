// The police realm against the stub api: its own layout and colour band
// with no console navigation, no picture WebSocket (every view of the
// airspace is a recorded query checked against the address list), a
// query without a purpose blocked by the page and, with the page's check
// removed, refused by api as the real one does; personal data only for a
// personal-data purpose; a legal export built and downloaded. Every wait
// is on a condition, never on a sleep.
import { expect, test } from "@playwright/test";
import { INSPECTOR, POLICE, apiCalls, resetMock, signInTo } from "./helpers";

test.beforeEach(async ({ request }) => {
  await resetMock(request);
});

const POLICE_HOME = /\/en\/police$/;

async function fillBox(page: import("@playwright/test").Page) {
  await page.getByTestId("bbox-min-lng").fill("44.7");
  await page.getByTestId("bbox-min-lat").fill("41.6");
  await page.getByTestId("bbox-max-lng").fill("44.9");
  await page.getByTestId("bbox-max-lat").fill("41.8");
}

test("the realm has its own band and navigation, and never opens the picture WebSocket", async ({ page, request }) => {
  const sockets: string[] = [];
  page.on("websocket", (ws) => sockets.push(ws.url()));
  await signInTo(page, "en", POLICE, POLICE_HOME);
  await expect(page.getByTestId("police-band")).toBeVisible();
  await expect(page.getByTestId("police-title")).toContainText("police realm");
  await expect(page.getByTestId("nav")).toHaveCount(0);
  await expect(page.getByTestId("police-nav").getByRole("link")).toHaveCount(2);
  await expect(page.getByTestId("police-pending-gcaa")).toBeVisible();
  // The console's map sends a police session back to its realm.
  await page.goto("/en");
  await expect(page).toHaveURL(POLICE_HOME);
  await page.goto("/en/violations");
  await expect(page).toHaveURL(POLICE_HOME);
  await page.getByTestId("police-nav").getByRole("link", { name: "Exports" }).click();
  await expect(page).toHaveURL(/\/en\/police\/exports$/);
  expect(sockets).toEqual([]);
  expect((await (await request.get("/__mock/upgrades")).json()) as unknown[]).toEqual([]);
});

test("a console session opens the picture WebSocket and is sent away from the police realm (the pair above)", async ({ page, request }) => {
  await signInTo(page, "en", INSPECTOR, /\/en$/);
  await expect(page.getByTestId("track-list")).toBeVisible();
  await expect.poll(async () => (await (await request.get("/__mock/upgrades")).json()) as { realm: string }[]).toContainEqual({ realm: "console" });
  await page.goto("/en/police");
  await expect(page).toHaveURL(/\/en$/);
});

test("a query without a purpose is blocked by the page, and with the check removed refused by api, recording nothing", async ({ page, request }) => {
  await signInTo(page, "en", POLICE, POLICE_HOME);
  await page.getByTestId("basis-case-ref").fill("TEST-CASE-1");
  await fillBox(page);
  await page.getByTestId("q-aircraft-submit").click();
  await expect(page.getByTestId("basis-blocked")).toContainText("Choose a purpose");
  expect((await apiCalls(request)).some((c) => c.path.startsWith("/v1/police/"))).toBe(false);

  // The page's check removed: the request goes as a script would send it, and api refuses it naming the field.
  const answer = await page.evaluate(async () => {
    const r = await fetch("/_bff/api/v1/police/aircraft?bbox=44.7,41.6,44.9,41.8&case_ref=TEST-CASE-1");
    return { status: r.status, body: (await r.json()) as { errors?: { field: string }[] } };
  });
  expect(answer.status).toBe(400);
  expect(answer.body.errors?.map((e) => e.field)).toEqual(["purpose"]);
  const records = (await (await request.get("/__mock/oversight")).json()) as { policeQueries: unknown[] };
  expect(records.policeQueries).toEqual([]);
});

test("a status-only purpose answers without identity; a personal-data purpose releases it and says so", async ({ page, request }) => {
  await signInTo(page, "en", POLICE, POLICE_HOME);
  await page.getByTestId("basis-purpose").selectOption("public_order");
  await page.getByTestId("basis-case-ref").fill("TEST-CASE-2");
  await fillBox(page);
  await page.getByTestId("q-aircraft-submit").click();
  const answer = page.getByTestId("aircraft-answer");
  await expect(answer.locator("[data-police-track]")).toHaveCount(1);
  await expect(answer.getByTestId("query-meta")).toHaveAttribute("data-pii", "false");
  await expect(answer.getByTestId("operator-identity")).toHaveCount(0);
  await expect(answer.getByTestId("unverified")).toHaveText("as broadcast and unverified");
  const sent = (await apiCalls(request)).find((c) => c.path === "/v1/police/aircraft");
  expect(sent?.query).toEqual(["bbox", "case_ref", "purpose"]);

  await page.getByTestId("basis-purpose").selectOption("criminal_investigation");
  await page.getByTestId("q-operator-reg").fill("GEOTEST00000001");
  await page.getByTestId("q-operator-submit").click();
  const op = page.getByTestId("operator-answer");
  await expect(op.getByTestId("query-meta")).toHaveAttribute("data-pii", "true");
  await expect(op.getByTestId("operator-identity")).toContainText("Test Operator One");
  await expect(op.getByTestId("fleet")).toContainText("TESTSN0001");
});

test("a legal export: only personal-data purposes are offered; built, then downloaded by its agency", async ({ page, request }) => {
  await signInTo(page, "en", POLICE, POLICE_HOME);
  await page.goto("/en/police/exports");
  const offered = await page.getByTestId("basis-purpose").locator("option").evaluateAll((os) => os.map((o) => (o as HTMLOptionElement).value).filter((v) => v !== ""));
  expect(offered).toEqual(["criminal_investigation", "security_threat"]);
  await page.getByTestId("basis-purpose").selectOption("criminal_investigation");
  await page.getByTestId("basis-case-ref").fill("TEST-CASE-3");
  await page.getByTestId("export-min-lng").fill("44.7");
  await page.getByTestId("export-min-lat").fill("41.6");
  await page.getByTestId("export-max-lng").fill("44.9");
  await page.getByTestId("export-max-lat").fill("41.8");
  await page.getByTestId("export-from").fill("2026-10-03T11:55");
  await page.getByTestId("export-to").fill("2026-10-03T12:05");
  await page.getByTestId("export-submit").click();
  const made = page.getByTestId("export-made");
  await expect(made).toContainText("opened for this request");
  const download = page.waitForEvent("download");
  await made.getByTestId("download").click();
  expect((await download).suggestedFilename()).toMatch(/\.zip$/);
  await expect(made.getByTestId("download-served")).toContainText("sha256:");
  const records = (await (await request.get("/__mock/oversight")).json()) as { policeQueries: { kind: string; case_ref: string }[] };
  expect(records.policeQueries.map((q) => q.kind)).toEqual(["export", "download"]);
  expect(records.policeQueries.every((q) => q.case_ref === "TEST-CASE-3")).toBe(true);
});
