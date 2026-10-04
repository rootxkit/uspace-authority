// WP-22's U-space airspace pages against the stub api: an admin
// designates an airspace with the Art. 3(4) block and the services, and
// api, not the editor, writes the requirements block into the feature;
// an inspector, whose roles hold none of the operations, is offered
// none of it (E-01).
import { expect, test } from "@playwright/test";
import { INSPECTOR, resetMock, signIn } from "./helpers";
import { ADMIN, expectAccessible, field, recorded } from "./authoring";

test.beforeEach(async ({ request }) => {
  await resetMock(request);
});

test("an admin designates a U-space airspace with the Art. 3(4) block; an inspector is not offered it (E-01)", async ({ page, request, browser }) => {
  await signIn(page, "en", ADMIN);
  await page.goto("/en/uspace/new");
  await field(page, "feature.properties.identifier").fill("TSU001");
  await field(page, "feature.properties.country").fill("GEO");
  await field(page, "feature.properties.name.0.text").fill("Test U-space");
  await field(page, "feature.geometry.rings").fill("44.70 41.70\n44.80 41.70\n44.80 41.80\n44.70 41.80");
  await field(page, "feature.geometry.layer.lower").fill("0");
  await field(page, "feature.geometry.layer.lowerReference").selectOption("AGL");
  await field(page, "feature.geometry.layer.upper").fill("120");
  await field(page, "feature.geometry.layer.upperReference").selectOption("AGL");
  await field(page, "from").fill("2026-10-01T00:00");
  await field(page, "to").fill("2027-10-01T00:00");
  await field(page, "feature.properties.zoneAuthority.0.purpose").selectOption("AUTHORIZATION");
  await field(page, "designation.airspace_name").fill("Test U-space airspace");
  for (const s of ["NID", "GEO", "FA", "TI"]) await page.getByTestId("set-designation.services_required").locator(`input[value="${s}"]`).check();
  await field(page, "designation.nid_update_hz").fill("1");
  await field(page, "designation.ti_update_hz").fill("1");
  await field(page, "designation.cis_latency_s").fill("5");
  await field(page, "designation.max_height_agl_m").fill("120");
  await field(page, "designation.uas_requirements").fill('{"remote_id": "network"}');
  await expectAccessible(page);
  await page.getByRole("button", { name: "Save as draft" }).click();
  await expect(page).toHaveURL(/\/en\/uspace\/TSU001$/);
  const post = (await recorded(request)).find((r) => r.method === "POST" && r.path === "/v1/uspace");
  expect(post?.body).toMatchObject({
    designated_from: "2026-10-01T00:00:00Z",
    designated_to: "2027-10-01T00:00:00Z",
    feature: { properties: { identifier: "TSU001", type: "USPACE" } },
    designation: {
      airspace_name: "Test U-space airspace",
      services_required: ["NID", "GEO", "FA", "TI"],
      uas_requirements: { remote_id: "network" },
      service_performance: { nid_update_hz: 1, ti_update_hz: 1, cis_latency_s: 5 },
      airspace_constraints: { max_height_agl_m: 120 },
      in_controlled_airspace: false,
    },
  });
  // api writes the requirements block; the editor never sends one.
  expect(JSON.stringify((post?.body as { feature: unknown }).feature)).not.toContain("uspace_requirements");

  await page.getByTestId("zone-approve").click();
  await expect(page.getByRole("alertdialog")).toContainText("This designates version 1 of TSU001");
  await page.getByRole("alertdialog").getByRole("button", { name: "Confirm" }).click();
  await expect(page.getByTestId("zone-facts").getByTestId("zone-state")).toHaveAttribute("data-state", "approved");

  const insp = await browser.newPage();
  await signIn(insp, "en", INSPECTOR);
  await expect(insp.getByTestId("nav").getByText("U-space airspace")).toHaveCount(0);
  await expect(insp.getByTestId("nav").getByText("Certificates")).toHaveCount(0);
  await insp.goto("/en/uspace/new");
  await expect(insp.getByTestId("not-your-role")).toBeVisible();
  await expect(insp.getByTestId("zone-editor")).toHaveCount(0);
  await insp.close();
});
