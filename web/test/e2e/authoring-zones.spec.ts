// WP-22 against the stub api of test/mock/authoring.mjs: an inspector
// authors a polygon and a circle in the zone editor (the circle's body
// carries its centre and radius, never a polygon), an invalid import
// lists its problems by path, an admin approves and publishes and sees
// the publication pending, then acknowledged by the fake CISP; a viewer
// sees no edit control where an inspector does (E-01). Every wait is on
// a condition, never a sleep.
import { expect, test, type Page } from "@playwright/test";
import { INSPECTOR, resetMock, signIn } from "./helpers";
import { ADMIN, VIEWER, cispAcknowledges, expectAccessible, field, recorded } from "./authoring";

test.beforeEach(async ({ request }) => {
  await resetMock(request);
});

async function common(page: Page, id: string) {
  await field(page, "feature.properties.identifier").fill(id);
  await field(page, "feature.properties.country").fill("GEO");
  await field(page, "feature.properties.name.0.text").fill(`Test zone ${id}`);
  await field(page, "feature.geometry.layer.lower").fill("0");
  await field(page, "feature.geometry.layer.lowerReference").selectOption("AGL");
  await field(page, "feature.geometry.layer.upper").fill("120");
  await field(page, "feature.geometry.layer.upperReference").selectOption("AGL");
  await field(page, "from").fill("2026-10-01T00:00");
  await field(page, "to").fill("2027-10-01T00:00");
  await field(page, "feature.properties.zoneAuthority.0.name").fill("Test authority");
  await field(page, "feature.properties.zoneAuthority.0.purpose").selectOption("AUTHORIZATION");
}

type Sent = { feature: { geometry: Record<string, unknown>; properties: Record<string, unknown> }; valid_from: string; valid_to: string };

test("an inspector authors a polygon zone: the editor sends the ED-318 feature by its standard names", async ({ page, request }) => {
  await signIn(page, "en", INSPECTOR);
  await page.goto("/en/zones/new");
  await expect(page.getByTestId("zone-editor")).toBeVisible();
  await expectAccessible(page);
  await common(page, "TSTE010");
  await field(page, "feature.properties.type").selectOption("PROHIBITED");
  await field(page, "feature.geometry.rings").fill("44.70 41.70\n44.72 41.70\n44.72 41.72\n44.70 41.72");
  await page.getByRole("button", { name: "Save as draft" }).click();
  await expect(page).toHaveURL(/\/en\/zones\/TSTE010$/);
  await expect(page.getByTestId("zone-facts").getByTestId("zone-state")).toHaveAttribute("data-state", "draft");

  const post = (await recorded(request)).find((r) => r.method === "POST" && r.path === "/v1/zones");
  const body = post?.body as Sent;
  expect(body.valid_from).toBe("2026-10-01T00:00:00Z");
  expect(body.valid_to).toBe("2027-10-01T00:00:00Z");
  expect(body.feature.geometry).toEqual({
    type: "Polygon",
    coordinates: [
      [
        [44.7, 41.7],
        [44.72, 41.7],
        [44.72, 41.72],
        [44.7, 41.72],
        [44.7, 41.7],
      ],
    ],
    layer: { upper: 120, upperReference: "AGL", lower: 0, lowerReference: "AGL", uom: "m" },
  });
  expect(body.feature.properties).toMatchObject({ identifier: "TSTE010", country: "GEO", type: "PROHIBITED", zoneAuthority: [{ name: [{ text: "Test authority", lang: "en-GB" }], purpose: "AUTHORIZATION" }] });
});

test("an inspector authors a circle: the request carries its centre and radius, not a polygon (Z-11)", async ({ page, request }) => {
  await signIn(page, "en", INSPECTOR);
  await page.goto("/en/zones/new");
  await common(page, "TSTE011");
  await field(page, "feature.properties.type").selectOption("REQ_AUTHORIZATION");
  await field(page, "feature.geometry.kind").selectOption("circle");
  await expect(page.getByTestId("circle-fields")).toBeVisible();
  await expect(page.getByTestId("circle-fields")).toContainText("The circle's edge is not drawn here");
  await field(page, "feature.geometry.centerLng").fill("44.85");
  await field(page, "feature.geometry.centerLat").fill("41.7");
  await field(page, "feature.geometry.radiusM").fill("500");
  await page.getByRole("button", { name: "Save as draft" }).click();
  await expect(page).toHaveURL(/\/en\/zones\/TSTE011$/);

  const post = (await recorded(request)).find((r) => r.method === "POST" && r.path === "/v1/zones");
  const g = (post?.body as Sent).feature.geometry;
  expect(g["type"]).toBe("Point");
  expect(g["coordinates"]).toEqual([44.85, 41.7]);
  expect(g["extent"]).toEqual({ subType: "Circle", radius: 500 });
  expect(JSON.stringify(g)).not.toContain("Polygon");
});

test("the editor refuses an unbuilt geometry before anything is sent, and the API's refusal lands on its field (the pair)", async ({ page, request }) => {
  await signIn(page, "en", INSPECTOR);
  await page.goto("/en/zones/new");
  await common(page, "TSTE012");
  await field(page, "feature.properties.type").selectOption("PROHIBITED");
  await field(page, "feature.geometry.rings").fill("44.70 41.70\nnot a position");
  await page.getByRole("button", { name: "Save as draft" }).click();
  await expect(page.getByText("Every line must be a WGS84 position").first()).toBeVisible();
  expect((await recorded(request)).filter((r) => r.method === "POST" && r.path === "/v1/zones")).toEqual([]);

  // A well-built feature the API refuses: the authority entry removed.
  await field(page, "feature.geometry.rings").fill("44.70 41.70\n44.72 41.70\n44.72 41.72");
  await page.getByTestId("authorities").getByRole("button", { name: "Remove" }).click();
  await page.getByRole("button", { name: "Save as draft" }).click();
  await expect(page.getByText("a zone without an authority").first()).toBeVisible();
  expect((await recorded(request)).filter((r) => r.method === "POST" && r.path === "/v1/zones")).toHaveLength(1);
});

test("an invalid ED-318 import lists every problem by path and imports nothing; a valid one creates the drafts", async ({ page, request }) => {
  await signIn(page, "en", INSPECTOR);
  await page.goto("/en/zones/import");
  await expectAccessible(page);
  const bad = {
    type: "FeatureCollection",
    metadata: { validFrom: "2026-10-01T00:00:00Z", validTo: "2027-10-01T00:00:00Z" },
    features: [
      { type: "Feature", geometry: { type: "Point", coordinates: [44.8, 41.7], extent: { subType: "Circle", radius: 100 } }, properties: { identifier: "TSTI001" } },
      { type: "Feature", geometry: { type: "Point", coordinates: [44.8, 41.7], extent: { subType: "Circle", radius: 100 } }, properties: { type: "PROHIBITED" } },
    ],
  };
  await page.getByTestId("zone-file").setInputFiles({ name: "bad.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(bad)) });
  await page.getByTestId("zone-import-submit").click();
  const refused = page.getByTestId("zone-import-refused");
  await expect(refused).toContainText("features[0].properties.type");
  await expect(refused).toContainText("features[1].properties.identifier");
  await expect(refused).toContainText("Nothing was imported.");
  await expect(page.getByTestId("zone-import-result")).toHaveCount(0);

  const good = { ...bad, features: [{ ...bad.features[0], properties: { identifier: "TSTI001", type: "PROHIBITED", zoneAuthority: [{ purpose: "INFORMATION" }] } }] };
  await page.getByTestId("zone-file").setInputFiles({ name: "good.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(good)) });
  await page.getByTestId("zone-import-submit").click();
  await expect(page.getByTestId("zone-import-result")).toContainText("TSTI001, version 1 (draft)");
  const posts = (await recorded(request)).filter((r) => r.method === "POST" && r.path === "/v1/zones/import");
  expect(posts).toHaveLength(2);
});

test("an admin approves and publishes with the exact effect, and sees the publication pending, then acknowledged", async ({ page, request, browser }) => {
  // An inspector drafts a revision of the published TSTP001.
  const insp = await browser.newPage();
  await signIn(insp, "en", INSPECTOR);
  await insp.goto("/en/zones/TSTP001/edit");
  await expect(field(insp, "feature.properties.identifier")).toHaveValue("TSTP001");
  // The published version has no authority entry; ED-318 needs one.
  await insp.getByRole("button", { name: "Add an authority entry" }).click();
  await field(insp, "feature.properties.zoneAuthority.0.purpose").selectOption("INFORMATION");
  await field(insp, "from").fill("2026-01-01T00:00");
  await field(insp, "to").fill("2027-01-01T00:00");
  await insp.getByRole("button", { name: "Save the revision as a draft" }).click();
  await expect(insp).toHaveURL(/\/en\/zones\/TSTP001$/);
  await insp.close();

  await signIn(page, "en", ADMIN);
  await page.goto("/en/zones/TSTP001");
  await expect(page.getByTestId("zone-facts").getByTestId("zone-state")).toHaveAttribute("data-state", "draft");
  // The difference between the published version and the draft.
  const history = page.getByTestId("zone-history");
  await history.locator('tr[data-version="2"] input[name="diff-from"]').check();
  await history.locator('tr[data-version="3"] input[name="diff-to"]').check();
  await expect(page.getByTestId("zone-diff")).toContainText("Version 2 to 3");
  await page.getByTestId("zone-approve").click();
  await expect(page.getByRole("alertdialog")).toContainText("This approves version 3 of TSTP001");
  await page.getByRole("alertdialog").getByRole("button", { name: "Confirm" }).click();
  await expect(page.getByTestId("zone-facts").getByTestId("zone-state")).toHaveAttribute("data-state", "approved");

  await page.goto("/en/zones");
  await expect(page.getByTestId("publish-preview-text")).toContainText("1 approved versions wait; with them 2 are in force now.");
  await expectAccessible(page);
  await page.getByTestId("publish").click();
  await expect(page.getByRole("alertdialog")).toContainText("This publishes 1 approved versions and sends the CISP every geo-zone in force, 2 zones, as the next zones version.");
  await page.getByRole("alertdialog").getByRole("button", { name: "Confirm" }).click();
  await expect(page.getByTestId("publish-result")).toContainText("Published as zones version 8");
  const pub = page.getByTestId("publications-zones").getByTestId("publication").first();
  await expect(pub).toHaveAttribute("data-state", "pending");
  await expect(pub.getByTestId("publication-age")).toContainText("not yet published for");

  await cispAcknowledges(request);
  await expect(pub).toHaveAttribute("data-state", "acknowledged", { timeout: 15_000 });
  await expect(pub).toContainText("CISP version 8");
});

test("a viewer sees no edit control; an inspector sees them (E-01)", async ({ page, browser }) => {
  await signIn(page, "en", VIEWER);
  await page.goto("/en/zones");
  await expect(page.getByTestId("zones-list-loading")).toHaveCount(0);
  await expect(page.locator("[data-state]").first()).toBeVisible();
  await expect(page.getByTestId("zone-new")).toHaveCount(0);
  await expect(page.getByTestId("zone-import")).toHaveCount(0);
  await expect(page.getByTestId("publish-panel")).toHaveCount(0);
  await page.goto("/en/zones/TSTP001");
  await expect(page.getByTestId("zone-facts")).toBeVisible();
  await expect(page.getByTestId("zone-revise")).toHaveCount(0);
  await expectAccessible(page);

  const insp = await browser.newPage();
  await signIn(insp, "en", INSPECTOR);
  await insp.goto("/en/zones");
  await expect(insp.getByTestId("zone-new")).toBeVisible();
  await expect(insp.getByTestId("zone-import")).toBeVisible();
  await insp.goto("/en/zones/TSTP001");
  await expect(insp.getByTestId("zone-revise")).toBeVisible();
  await insp.close();
});

test("the editor in Georgian: every label from the ka catalogue", async ({ page }) => {
  await signIn(page, "ka", INSPECTOR);
  await page.goto("/ka/zones/new");
  await expect(page.getByRole("button", { name: "პროექტად შენახვა" })).toBeVisible();
  await expectAccessible(page);
});
