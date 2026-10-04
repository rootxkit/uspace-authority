// WP-22's certificate pages against the stub api: issuing shows the
// client's secret once and only when asked; a suspension takes its
// reason, says until when issued tokens stay valid and that the USSP list
// was queued; the public register preview holds no contact; the USSP
// list's publication is shown.
import { expect, test } from "@playwright/test";
import { resetMock, signIn } from "./helpers";
import { ADMIN, expectAccessible, field, recorded } from "./authoring";

test.beforeEach(async ({ request }) => {
  await resetMock(request);
});

test("issuing a USSP certificate shows the client's secret once, behind a click", async ({ page, request }) => {
  await signIn(page, "en", ADMIN);
  await page.goto("/en/certificates/new");
  await expectAccessible(page);
  await field(page, "holder").selectOption("ussp");
  await field(page, "code").fill("TESTU2");
  await field(page, "holder_name").fill("Second Test USSP");
  await field(page, "base_url").fill("https://ussp2.test/api");
  await field(page, "terms_url").fill("https://ussp2.test/terms");
  await page.getByTestId("set-services").getByLabel("Network identification").check();
  await field(page, "valid_until").fill("2028-10-01T00:00");
  await page.getByRole("button", { name: "Issue", exact: true }).click();
  const issued = page.getByTestId("cert-issued");
  await expect(issued).toContainText("ussp-TESTU2-01");
  await expect(issued.getByTestId("client-secret-value")).toHaveCount(0);
  await issued.getByTestId("client-secret-show").click();
  await expect(issued.getByTestId("client-secret-value")).toHaveValue(/^test-secret-/);
  const post = (await recorded(request)).find((r) => r.method === "POST" && r.path === "/v1/certificates");
  expect(post?.body).toMatchObject({ holder: "ussp", code: "TESTU2", services: ["network_identification"], auth_method: "client_secret_post", valid_until: "2028-10-01T00:00:00Z" });
});

test("a suspension takes a reason and says what it did to the tokens and the USSP list", async ({ page, request }) => {
  await signIn(page, "en", ADMIN);
  await page.goto("/en/certificates/0123456789abcdef0123456789abcdef");
  await expect(page.getByTestId("cert-facts").getByTestId("cert-status")).toHaveAttribute("data-status", "operating");
  await expect(page.getByTestId("timeline")).toContainText("Started operations, reference TEST-START-1");
  await expectAccessible(page);
  await page.getByTestId("cert-suspend").click();
  const dialog = page.getByRole("alertdialog");
  await expect(dialog).toContainText("client ussp-TESTU1-01 is refused its next token");
  await dialog.getByRole("textbox").fill("Conformance report overdue");
  await dialog.getByRole("button", { name: "Confirm" }).click();
  await expect(page.getByTestId("cert-facts").getByTestId("cert-status")).toHaveAttribute("data-status", "suspended");
  await expect(page.getByTestId("tokens-valid-until")).toContainText("Tokens issued before stay valid until");
  await expect(page.getByTestId("list-publication")).toHaveAttribute("data-state", "queued");
  const sent = (await recorded(request)).filter((r) => r.path.endsWith("/suspend"));
  expect(sent.map((r) => r.body)).toEqual([{ reason: "Conformance report overdue" }]);

  await page.getByTestId("cert-reinstate").click();
  await page.getByRole("alertdialog").getByRole("textbox").fill("Report received");
  await page.getByRole("alertdialog").getByRole("button", { name: "Confirm" }).click();
  await expect(page.getByTestId("cert-facts").getByTestId("cert-status")).toHaveAttribute("data-status", "operating");
});

test("the public register preview holds no contact, address or client id; the admin's list does", async ({ page }) => {
  await signIn(page, "en", ADMIN);
  await page.goto("/en/certificates/register");
  const table = page.getByTestId("register-table");
  await expect(table).toContainText("TESTU1");
  await expect(table).toContainText("Test USSP");
  await expect(table).not.toContainText("ops@ussp.test");
  await expect(table).not.toContainText("ussp-TESTU1-01");
  await expectAccessible(page);
  await page.goto("/en/certificates/0123456789abcdef0123456789abcdef");
  await expect(page.getByTestId("cert-facts")).toContainText("ops@ussp.test");
  await expect(page.getByTestId("cert-facts")).toContainText("ussp-TESTU1-01");
});

test("the USSP list is queued on request and its publication state shown", async ({ page }) => {
  await signIn(page, "en", ADMIN);
  await page.goto("/en/certificates");
  await expect(page.getByTestId("publications-ussp_list")).toContainText("No publication of the USSP list yet.");
  await page.getByTestId("publish-list").click();
  await page.getByRole("alertdialog").getByRole("button", { name: "Confirm" }).click();
  await expect(page.getByTestId("publications-ussp_list").getByTestId("publication").first()).toHaveAttribute("data-state", "pending");
  await expectAccessible(page);
});
