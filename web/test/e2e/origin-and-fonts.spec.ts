// What leaves the browser and what it draws with: every request of a
// whole session stays on the origin (M38: the kit's CSP, self-hosted
// fonts, no third-party tile), a request to another origin is refused by
// the CSP, the Georgian catalogue renders in Noto Sans Georgian, and the
// language choice is kept in a Secure cookie.
import { expect, test } from "@playwright/test";
import { BROADCAST_TRACK, INSPECTOR, resetMock, signIn } from "./helpers";

test.beforeEach(async ({ request }) => {
  await resetMock(request);
});

test("no request leaves the origin during sign-in and the map", async ({ page, baseURL }) => {
  const origin = new URL(baseURL ?? "").origin;
  const urls: string[] = [];
  page.on("request", (r) => urls.push(r.url()));
  // A WebSocket is not a request event in Playwright; it is listed on its own.
  page.on("websocket", (ws) => urls.push(ws.url()));
  await signIn(page, "en", INSPECTOR);
  await expect(page.getByTestId("track-list").locator(`[data-track="${BROADCAST_TRACK}"]`)).toBeVisible();
  const elsewhere = urls.filter((u) => {
    if (u.startsWith("data:") || u.startsWith("blob:")) return false;
    const url = new URL(u);
    const sameHost = url.host === new URL(origin).host;
    return !sameHost || !(url.protocol === "http:" || url.protocol === "ws:");
  });
  expect(urls.length).toBeGreaterThan(5);
  expect(urls.some((u) => u.startsWith("ws://") && u.endsWith("/v1/picture/ws"))).toBe(true);
  expect(elsewhere).toEqual([]);
});

test("the CSP is the kit's and refuses a request to another origin", async ({ page }) => {
  const res = await page.goto("/en/login");
  const csp = res?.headers()["content-security-policy"] ?? "";
  expect(csp).toContain("connect-src 'self'");
  expect(csp).toContain("font-src 'self'");
  expect(csp).toContain("worker-src blob:");
  // The pair: a same-origin read is allowed, a foreign one is refused before it is sent.
  const outcome = await page.evaluate(async () => {
    const violations: string[] = [];
    // The event is queued as its own task, after the fetch has already
    // failed: wait for it (bounded), not for a frame.
    const reported = new Promise<void>((resolve) => {
      document.addEventListener("securitypolicyviolation", (e) => {
        violations.push(e.violatedDirective);
        resolve();
      });
      setTimeout(resolve, 5000);
    });
    const own = await fetch("/healthz").then(
      (r) => r.status,
      () => -1,
    );
    const foreign = await fetch("https://tiles.example.invalid/0/0/0.pbf").then(
      () => "sent",
      () => "refused",
    );
    await reported;
    return { own, foreign, violations };
  });
  expect(outcome.own).toBe(200);
  expect(outcome.foreign).toBe("refused");
  expect(outcome.violations).toContain("connect-src");
});

test("the Georgian catalogue renders in Noto Sans Georgian", async ({ page }) => {
  await page.goto("/ka/login");
  const title = page.getByRole("heading", { level: 1 });
  await expect(title).toHaveText("ინსპექტორის კონსოლში შესვლა");
  await page.evaluate(() => document.fonts.ready);
  const faces = await page.evaluate(() =>
    [...document.fonts].filter((f) => f.status === "loaded").map((f) => `${f.family} ${f.unicodeRange}`),
  );
  // The kit's face for Mkhedruli (U+10A0-10FF) is loaded and used.
  expect(faces.some((f) => /10A0|10D0|10a0|10d0/.test(f))).toBe(true);
  const kitShot = await title.screenshot();
  // The same text in a generic family is drawn differently: the page is not on a fallback face.
  await title.evaluate((el) => {
    (el as HTMLElement).style.fontFamily = "monospace";
  });
  const fallbackShot = await title.screenshot();
  expect(kitShot.equals(fallbackShot)).toBe(false);
  await test.info().attach("georgian-title", { body: kitShot, contentType: "image/png" });
});

test("the language switch remembers the choice in a Secure cookie", async ({ page, context }) => {
  await signIn(page, "en", INSPECTOR);
  await page.getByRole("link", { name: "ქართული" }).click();
  await expect(page).toHaveURL(/\/ka$/);
  const lang = (await context.cookies()).find((c) => c.name === "uspace_lang");
  expect(lang?.value).toBe("ka");
  expect(lang?.secure).toBe(true);
  expect(lang?.sameSite).toBe("Lax");
  expect(lang?.httpOnly).toBe(false);
});
