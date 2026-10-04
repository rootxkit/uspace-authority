// WP-23's console pages against the stub api of test/mock-oversight.mjs:
// a violation with a hole renders the hole and its labels (and one
// without renders none), the review's refusals and its final state, the
// occurrence routes refused to an inspector and served to an incident
// officer, the incident's evidence pack built, verified and downloaded,
// the sources with their switches, and the audit log. Every wait is on a
// condition, never on a sleep.
import { expect, test, type Page } from "@playwright/test";
import { ADMIN, AUDITOR, INSPECTOR, OFFICER, apiCalls, resetMock, signInTo } from "./helpers";

test.beforeEach(async ({ request }) => {
  await resetMock(request);
});

const MAP = /\/en$/;

async function openViolation(page: Page, kindText: string) {
  await page.goto("/en/violations");
  const row = page.getByTestId("violations-table").locator("[data-violation-row]", { hasText: kindText });
  await expect(row).toHaveCount(1);
  await row.getByRole("link").click();
  await expect(page.getByTestId("violation-detail")).toBeVisible();
}

test("a violation with a hole: the hole is labelled, nothing is drawn across it, and every AGL number names its ground", async ({ page }) => {
  await signInTo(page, "en", INSPECTOR, MAP);
  await expect(page.getByTestId("nav").getByRole("link", { name: "Violations" })).toBeVisible();
  await openViolation(page, "Above the height limit");

  const hole = page.getByTestId("excerpt-hole");
  await expect(hole).toHaveCount(1);
  await expect(hole).toContainText("Hole of 9");
  await expect(hole.locator('[data-cause="silence"]')).toContainText("silence");
  await expect(hole.locator('[data-cause="no recorded cause"]')).toContainText("nothing is assumed");
  // The samples on either side of it are rows of their own segments: 3, the hole, 2.
  const rows = page.getByTestId("excerpt-samples").locator("tbody tr");
  await expect(rows).toHaveCount(6);
  await expect(rows.nth(3)).toHaveAttribute("data-testid", "excerpt-hole");
  await expect(page.getByTestId("excerpt-rule")).toContainText("Nothing is drawn across a hole");

  // D-05: the ground and its attribution beside every height over the ground.
  await expect(page.getByTestId("height-agl")).toContainText("128 m AGL");
  await expect(page.getByTestId("height-agl").getByTestId("terrain-note")).toContainText("TEST-DEM-30");
  await expect(page.getByTestId("peak-agl").getByTestId("terrain-attribution")).toContainText("TEST DEM fixture attribution");
  // R-05 and 06 §2 T1: broadcast evidence says so.
  await expect(page.getByTestId("broadcast-warning")).toBeVisible();
  await expect(page.getByTestId("violation-detail").getByTestId("unverified").first()).toHaveText("as broadcast and unverified");
});

test("a continuous excerpt has no hole, and authenticated evidence no broadcast warning (the pair above)", async ({ page }) => {
  await signInTo(page, "en", INSPECTOR, MAP);
  await openViolation(page, "Zone incursion");
  await expect(page.getByTestId("excerpt-samples").locator("tbody tr")).toHaveCount(3);
  await expect(page.getByTestId("excerpt-hole")).toHaveCount(0);
  await expect(page.getByTestId("broadcast-warning")).toHaveCount(0);
});

test("escalating broadcast evidence: blocked without a note, refused by api with the client check removed, then final with one", async ({ page, request }) => {
  await signInTo(page, "en", INSPECTOR, MAP);
  await openViolation(page, "Above the height limit");
  await page.getByTestId("review-decision").selectOption("escalated");
  await expect(page.getByTestId("review-note")).toHaveAttribute("required", "");
  await page.getByTestId("review-submit").click();
  // The browser's own check held the form: nothing reached api.
  expect((await apiCalls(request)).some((c) => c.path.endsWith("/review"))).toBe(false);

  // The client check removed: api's refusal names the field.
  await page.getByTestId("review-note").evaluate((el) => el.removeAttribute("required"));
  await page.getByTestId("review-submit").click();
  const problem = page.getByTestId("problem");
  await expect(problem).toHaveAttribute("data-status", "400");
  await expect(problem).toContainText("note: required for broadcast evidence");

  await page.getByTestId("review-note").fill("Corroborated by the receiver's second antenna.");
  await page.getByTestId("review-submit").click();
  await expect(page.getByTestId("violation-detail")).toHaveAttribute("data-status", "escalated");
  await expect(page.getByTestId("review-final")).toContainText("final");
  await expect(page.getByTestId("review-form")).toHaveCount(0);
  await expect(page.getByTestId("incident-link")).toBeVisible();
});

test("an inspector cannot reach the occurrence routes: no entry, a refusal, and nothing read", async ({ page, request }) => {
  await signInTo(page, "en", INSPECTOR, MAP);
  await expect(page.getByTestId("nav").getByRole("link", { name: "Occurrence reports" })).toHaveCount(0);
  for (const path of ["/en/occurrences", "/en/occurrences/export", "/en/occurrences/01K6H3BV4H15G5E4G7X0NT0001"]) {
    await page.goto(path);
    await expect(page.getByTestId("role-refused")).toContainText("incident officer");
  }
  expect((await apiCalls(request)).filter((c) => c.path.startsWith("/v1/occurrences"))).toEqual([]);
});

test("an incident officer can (the pair above): the queue with the 72 h flag, the reporter only when api returns it, the export's warning", async ({ page, request }) => {
  await signInTo(page, "en", OFFICER, MAP);
  await page.getByTestId("nav").getByRole("link", { name: "Occurrence reports" }).click();
  const table = page.getByTestId("occurrences-table");
  await expect(table.locator("[data-occurrence-row]")).toHaveCount(2);
  await expect(table.locator('[data-within="false"]')).toHaveText("late: received after the deadline");
  await expect(table.locator('[data-within="true"]')).toHaveText("within 72 h");

  await table.locator("[data-occurrence-row]").first().getByRole("link").click();
  await expect(page.getByTestId("occurrence-detail")).toBeVisible();
  await expect(page.getByTestId("reporter-block")).toHaveCount(0);
  expect((await apiCalls(request)).some((c) => c.path.endsWith("/reporter"))).toBe(false);
  await page.getByTestId("reporter-purpose").fill("376 follow-up with the reporting USSP");
  await page.getByTestId("reporter-open").click();
  await expect(page.getByTestId("reporter-block")).toContainText("TEST-PERSON-REF-7");
  const reporterCall = (await apiCalls(request)).find((c) => c.path.endsWith("/reporter"));
  expect(reporterCall?.query).toEqual(["purpose"]);

  await page.getByTestId("risk-input").fill("B");
  await page.getByTestId("classify-submit").click();
  await expect(page.getByTestId("occurrence-detail")).toHaveAttribute("data-state", "classified");

  await page.goto("/en/occurrences/export");
  await expect(page.getByTestId("narrative-warning")).toContainText("exported as the reporter wrote it");
  await page.getByTestId("export-from").fill("2026-10-01T00:00");
  await page.getByTestId("export-to").fill("2026-10-05T00:00");
  await page.getByTestId("export-submit").click();
  await expect(page.getByTestId("export-result")).toContainText("eccairs-compatible-draft");
});

test("an incident: open it, add a note, build an oversight pack, read its manifest, verify and download it", async ({ page }) => {
  await signInTo(page, "en", OFFICER, MAP);
  await page.goto("/en/incidents");
  const form = page.getByTestId("incident-create");
  await form.locator('input[name="occurred_at"]').fill("2026-10-03T11:58");
  await page.getByTestId("incident-create-submit").click();
  await expect(page.getByTestId("incident-detail")).toBeVisible();

  await page.getByTestId("note-input").fill("Receiver log requested.");
  await page.getByTestId("note-submit").click();
  await expect(page.getByTestId("incident-notes").locator("[data-note]")).toHaveCount(1);

  await page.getByTestId("pack-from").fill("2026-10-03T11:55");
  await page.getByTestId("pack-to").fill("2026-10-03T12:05");
  await page.getByTestId("pack-purpose").fill("oversight review");
  await page.getByTestId("pack-create-submit").click();
  const pack = page.getByTestId("incident-packs").locator("[data-pack]");
  await expect(pack).toHaveCount(1);
  await expect(pack.getByTestId("pack-hash")).toContainText("sha256:");

  await pack.getByTestId("pack-manifest-toggle").click();
  // A source that could not be read says so with the reason, never missing.
  await expect(pack.getByTestId("pack-manifest").locator('[data-section="manned_tracks"]')).toHaveAttribute("data-state", "unavailable");
  await expect(pack.getByTestId("pack-manifest").locator('[data-section="manned_tracks"]')).toContainText("cannot be read");

  await pack.getByTestId("pack-verify-run").click();
  await expect(pack.getByTestId("pack-hash-matches")).toContainText("equals the recorded one");
  await expect(pack.getByTestId("pack-signature")).toHaveText("signature verified");

  await expect(pack.getByTestId("download")).toBeDisabled();
  await pack.getByTestId("download-purpose").fill("archive copy for the case file");
  const download = page.waitForEvent("download");
  await pack.getByTestId("download").click();
  expect((await download).suggestedFilename()).toMatch(/\.zip$/);
  await expect(pack.getByTestId("download-served")).toContainText("sha256:");
});

test("sources: disabled says by whom and why; a switch needs a reason and is recorded", async ({ page, request }) => {
  await signInTo(page, "en", ADMIN, MAP);
  await page.getByTestId("nav").getByRole("link", { name: "Sources" }).click();
  const table = page.getByTestId("sources-table");
  await expect(table.locator('[data-source="direct_rid/rx-test-2"]').getByTestId("disabled-by")).toContainText("admin:test.admin: test maintenance");
  await expect(table.locator('[data-source="network_rid/ussp-test"]')).toContainText("lagging by 12 s");
  await expect(table.locator('[data-source="ansp_feed/ansp-1"]')).toContainText("never heard");

  await page.getByTestId("switch-direct_rid/rx-test-1").click();
  const dialog = page.getByRole("alertdialog");
  await expect(dialog).toBeVisible();
  const confirm = dialog.getByRole("button", { name: "Disable" });
  // Without a reason the dialog stays open and nothing is sent.
  await confirm.click();
  await expect(dialog).toBeVisible();
  expect((await apiCalls(request)).some((c) => c.method === "PUT")).toBe(false);
  await dialog.getByRole("textbox").fill("antenna replaced");
  await confirm.click();
  await expect(page.getByTestId("switch-result")).toHaveAttribute("data-changed", "true");
  await expect(table.locator('[data-source="direct_rid/rx-test-1"]')).toHaveAttribute("data-switch", "disabled");
});

test("audit: the log, a month verified, a month without rows never called intact, and the DPO report", async ({ page }) => {
  await signInTo(page, "en", AUDITOR, MAP);
  await page.getByTestId("nav").getByRole("link", { name: "Audit log" }).click();
  await page.getByTestId("audit-search").click();
  await expect(page.getByTestId("audit-table").locator("[data-event]")).toHaveCount(2);

  await page.getByTestId("chain-month").fill("2026-10");
  await page.getByTestId("chain-verify").click();
  await expect(page.getByTestId("chain-result")).toContainText("2 rows checked, every hash and link holds");
  await page.getByTestId("chain-month").fill("2026-09");
  await page.getByTestId("chain-verify").click();
  await expect(page.getByTestId("chain-result")).toContainText("This is not a verified chain");

  await page.getByTestId("dpo-month").fill("2026-10");
  await page.getByTestId("dpo-read").click();
  await expect(page.getByTestId("dpo-totals")).toContainText("0 police queries");
});
