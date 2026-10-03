import { expect, type APIRequestContext, type Page } from "@playwright/test";

// The fixture server's test accounts and code (test/mock-origin.mjs), not credentials.
export const INSPECTOR = { username: "inspector1", password: "inspector1-test-password" };
export const REGISTRAR = { username: "registrar1", password: "registrar1-test-password" };
export const CODE = "246810";

/** The lab's two tracks (console/snapshot/v1 authority-picture.json) and the provider fixture. */
export const BROADCAST_TRACK = "authority-1:rid:4A:7C:91:0E:22:B5";
export const AUTHENTICATED_TRACK = "ussp-1:FL-2026-000417";
export const PROVIDER_TRACK = "authority-1:dp:TEST0042";

export async function resetMock(request: APIRequestContext): Promise<void> {
  expect((await request.post("/__mock/reset")).ok()).toBe(true);
}

export async function mockState(request: APIRequestContext, state: Record<string, unknown>): Promise<void> {
  expect((await request.post("/__mock/state", { data: state })).ok()).toBe(true);
}

/** Signs in through the page's own form: the password, then the code. */
export async function signIn(page: Page, lang: "en" | "ka", account: { username: string; password: string }): Promise<void> {
  await page.goto(`/${lang}/login`);
  await page.locator('input[autocomplete="username"], input[name="username"]').first().fill(account.username);
  await page.locator('input[type="password"]').first().fill(account.password);
  await page.locator('form button[type="submit"]').first().click();
  const otp = page.locator('input[autocomplete="one-time-code"], input[name="otp"]').first();
  await expect(otp).toBeVisible();
  await otp.fill(CODE);
  await page.locator('form button[type="submit"]').first().click();
  await expect(page).toHaveURL(new RegExp(`/${lang}$`));
}
