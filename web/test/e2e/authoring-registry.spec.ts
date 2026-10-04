// WP-22's registry pages against the stub api: the look-up by number and
// serial, personal data only behind a purpose that is sent with the
// request (and refused by api without one), status transitions with a
// mandatory reason, the Art. 14(2) registration form, the import's dry
// run by record and field, and the applications queue that says when the
// portal is off. Each refusal beside the acceptance it differs from.
import { expect, test } from "@playwright/test";
import { INSPECTOR, REGISTRAR, resetMock, signIn } from "./helpers";
import { VIEWER, authoringState, expectAccessible, field, recorded } from "./authoring";

test.beforeEach(async ({ request }) => {
  await resetMock(request);
});

test("operators are looked up by number and aircraft by serial", async ({ page, request }) => {
  await signIn(page, "en", INSPECTOR);
  await page.goto("/en/registry/operators");
  await expect(page.getByTestId("operators")).toContainText("GEOTEST00000001");
  await expectAccessible(page);
  await page.getByTestId("search-number").fill("GEOTEST00000099");
  await page.getByTestId("filters-apply").click();
  await expect(page.getByTestId("operators")).toContainText("The registry answered no operator for this search");
  await page.getByTestId("search-number").fill("geotest00000001");
  await page.getByTestId("filters-apply").click();
  await expect(page.getByTestId("operators")).toContainText("GEOTEST00000001");

  await page.goto("/en/registry/uas");
  await page.getByTestId("search-serial").fill("TESTSERIAL0001");
  await page.getByTestId("filters-apply").click();
  await expect(page.getByTestId("uas")).toContainText("TESTSERIAL0001");
  const reqs = await recorded(request);
  expect(reqs.some((r) => r.path === "/v1/registry/operators" && r.query["number"] === "geotest00000001")).toBe(true);
  expect(reqs.some((r) => r.path === "/v1/registry/uas" && r.query["serial"] === "TESTSERIAL0001")).toBe(true);
});

test("personal data is read only with a purpose, which is sent with the request", async ({ page, request }) => {
  await signIn(page, "en", INSPECTOR);
  await page.goto("/en/registry/operators/op-1");
  const pii = page.getByTestId("operator-pii");
  await expect(pii).toBeVisible();
  await expect(pii).toContainText("default purposes, pending GCAA");
  // No purpose, no request: the button waits for one.
  await expect(pii.getByTestId("operator-pii-show")).toBeDisabled();
  expect((await recorded(request)).filter((r) => r.path.endsWith("/personal-data"))).toEqual([]);
  await expect(page.getByText("person@example.test")).toHaveCount(0);

  await pii.getByTestId("operator-pii-purpose").selectOption("oversight_inspection");
  await pii.getByTestId("operator-pii-show").click();
  await expect(pii.getByTestId("operator-pii-data")).toContainText("person@example.test");
  await expect(pii.getByTestId("operator-pii-data")).toContainText("Viewed for: Oversight inspection");
  const reads = (await recorded(request)).filter((r) => r.path === "/v1/registry/operators/op-1/personal-data");
  expect(reads.map((r) => r.query["purpose"])).toEqual(["oversight_inspection"]);
  await expectAccessible(page);

  // With the page's check out of the way, api refuses a read without a purpose.
  const status = await page.evaluate(async () => (await fetch("/_bff/api/v1/registry/operators/op-1/personal-data")).status);
  expect(status).toBe(400);
});

test("a viewer sees neither the personal data nor any edit control; a registrar sees both (E-01)", async ({ page, browser }) => {
  await signIn(page, "en", VIEWER);
  await page.goto("/en/registry/operators/op-1");
  await expect(page.getByTestId("operator-facts")).toContainText("GEOTEST00000001");
  await expect(page.getByTestId("operator-pii")).toHaveCount(0);
  await expect(page.getByTestId("status-change")).toHaveCount(0);
  await expect(page.getByTestId("operator-edit")).toHaveCount(0);
  await expect(page.getByTestId("registry-tabs").getByText("Import")).toHaveCount(0);

  const reg = await browser.newPage();
  await signIn(reg, "en", REGISTRAR);
  await reg.goto("/en/registry/operators/op-1");
  await expect(reg.getByTestId("operator-pii")).toBeVisible();
  await expect(reg.getByTestId("status-change")).toBeVisible();
  await expect(reg.getByTestId("operator-edit")).toBeVisible();
  await expect(reg.getByTestId("registry-tabs").getByText("Import")).toBeVisible();
  await reg.close();
});

test("a status transition takes a reason before anything is sent", async ({ page, request }) => {
  await signIn(page, "en", REGISTRAR);
  await page.goto("/en/registry/uas/uas-1");
  await page.getByTestId("status-to").selectOption("suspended");
  await page.getByTestId("status-apply").click();
  const dialog = page.getByRole("alertdialog");
  await expect(dialog).toContainText("This sets TESTSERIAL0001 from Active to Suspended.");
  await dialog.getByRole("button", { name: "Confirm" }).click();
  await expect(dialog.getByRole("alert")).toBeVisible();
  expect((await recorded(request)).filter((r) => r.path.endsWith("/status"))).toEqual([]);
  await dialog.getByRole("textbox").fill("Reported lost by the operator");
  await dialog.getByRole("button", { name: "Confirm" }).click();
  await expect(page.getByTestId("uas-facts").getByTestId("registry-status")).toHaveAttribute("data-status", "suspended");
  const sent = (await recorded(request)).filter((r) => r.path === "/v1/registry/uas/uas-1/status");
  expect(sent.map((r) => r.body)).toEqual([{ status: "suspended", reason: "Reported lost by the operator" }]);
});

test("a reason past api's 500 characters is refused, never cut; 500 are sent whole (the pair)", async ({ page, request }) => {
  await signIn(page, "en", REGISTRAR);
  await page.goto("/en/registry/uas/uas-1");
  const apply = async (reason: string) => {
    await page.getByTestId("status-to").selectOption("suspended");
    await page.getByTestId("status-apply").click();
    const dialog = page.getByRole("alertdialog");
    await dialog.getByRole("textbox").fill(reason);
    await dialog.getByRole("button", { name: "Confirm" }).click();
  };
  const sent = async () => (await recorded(request)).filter((r) => r.path === "/v1/registry/uas/uas-1/status");

  await apply("x".repeat(501));
  await expect(page.getByTestId("status-apply-too-long")).toContainText("501 characters; at most 500");
  expect(await sent()).toEqual([]);

  const whole = "y".repeat(500);
  await apply(whole);
  await expect(page.getByTestId("uas-facts").getByTestId("registry-status")).toHaveAttribute("data-status", "suspended");
  expect((await sent()).map((r) => r.body)).toEqual([{ status: "suspended", reason: whole }]);
});

test("a registrar registers a natural person with the Art. 14(2) fields", async ({ page, request }) => {
  await signIn(page, "en", REGISTRAR);
  await page.goto("/en/registry/operators/new");
  await expectAccessible(page);
  await field(page, "registration_number").fill("GEOTEST00000002");
  await field(page, "full_name").fill("Test Person Two");
  await field(page, "date_of_birth").fill("1991-02-03");
  await field(page, "postal_address").fill("3 Test Street");
  await field(page, "contact_email").fill("two@example.test");
  await field(page, "contact_phone").fill("+995000000004");
  await field(page, "valid_until").fill("2027-10-01T00:00");
  await page.getByRole("button", { name: "Register" }).click();
  await expect(page).toHaveURL(/\/en\/registry\/operators\/op-[0-9]+$/);
  await expect(page.getByTestId("operator-facts")).toContainText("GEOTEST00000002");
  const post = (await recorded(request)).find((r) => r.method === "POST" && r.path === "/v1/registry/operators");
  expect(post?.body).toMatchObject({
    operator_type: "natural",
    registration_number: "GEOTEST00000002",
    full_name: "Test Person Two",
    date_of_birth: "1991-02-03",
    postal_address: "3 Test Street",
    contact_email: "two@example.test",
    contact_phone: "+995000000004",
    valid_until: "2027-10-01T00:00:00Z",
    source: "manual",
    competency_confirmation: false,
  });
  // The personal data is not echoed on the record page.
  await expect(page.getByText("two@example.test")).toHaveCount(0);
});

test("the import's dry run reports by record and field; a clean dry run offers the import", async ({ page, request }) => {
  await signIn(page, "en", REGISTRAR);
  await page.goto("/en/registry/import");
  await expectAccessible(page);
  await page.getByTestId("import-file").setInputFiles({ name: "operators.csv", mimeType: "text/csv", buffer: Buffer.from("id;number\nS1;GEOTEST00000011\nS2;BAD\n") });
  await page.getByTestId("import-dry-run").click();
  await expect(page.getByTestId("import-report-problems")).toContainText("records[2].registration_number");
  await expect(page.getByTestId("import-apply")).toHaveCount(0);

  await page.getByTestId("import-file").setInputFiles({ name: "operators.csv", mimeType: "text/csv", buffer: Buffer.from("id;number\nS1;GEOTEST00000011\nS3;GEOTEST00000013\n") });
  await page.getByTestId("import-dry-run").click();
  await expect(page.getByTestId("import-report-clean")).toBeVisible();
  await page.getByTestId("import-apply").click();
  await expect(page.getByRole("alertdialog")).toContainText("2 created, 0 updated, 0 unchanged");
  await page.getByRole("alertdialog").getByRole("button", { name: "Confirm" }).click();
  await expect(page.getByTestId("import-applied")).toContainText("Import report");
  const posts = (await recorded(request)).filter((r) => r.path === "/v1/registry/import");
  expect(posts.map((r) => r.query["dry_run"])).toEqual(["true", "true", "false"]);
});

test("the applications queue says when the portal is off, and lists the queue when it is on", async ({ page, request }) => {
  await authoringState(request, { applications: "off" });
  await signIn(page, "en", REGISTRAR);
  await page.goto("/en/registry/applications");
  await expect(page.getByTestId("applications-off")).toContainText("switched off");

  await authoringState(request, { applications: "on" });
  await page.reload();
  await expect(page.getByTestId("applications-off")).toHaveCount(0);
  await page.getByText("app-1").click();
  const app = page.getByTestId("application");
  await expect(app).toBeVisible();
  await app.getByTestId("application-review").click();
  await page.getByRole("alertdialog").getByRole("button", { name: "Confirm" }).click();
  await expect(app).toContainText("Under review");
  await expectAccessible(page);
});
