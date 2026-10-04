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

// WP-23's accounts (test/mock-origin.mjs), not credentials.
export const OFFICER = { username: "officer1", password: "officer1-test-password" };
export const ADMIN = { username: "admin1", password: "admin1-test-password" };
export const AUDITOR = { username: "auditor1", password: "auditor1-test-password" };
export const POLICE = { username: "police1", password: "police1-test-password" };

/** Signs in through the form and waits for the page the realm lands on (the map, or the police realm). */
export async function signInTo(page: Page, lang: "en" | "ka", account: { username: string; password: string }, landing: RegExp): Promise<void> {
  await page.goto(`/${lang}/login`);
  await page.locator('input[autocomplete="username"], input[name="username"]').first().fill(account.username);
  await page.locator('input[type="password"]').first().fill(account.password);
  await page.locator('form button[type="submit"]').first().click();
  const otp = page.locator('input[autocomplete="one-time-code"], input[name="otp"]').first();
  await expect(otp).toBeVisible();
  await otp.fill(CODE);
  await page.locator('form button[type="submit"]').first().click();
  await expect(page).toHaveURL(landing);
}

/** The api requests the stub answered. */
export async function apiCalls(request: APIRequestContext): Promise<{ method: string; path: string; keys: string[]; query: string[] }[]> {
  return (await (await request.get("/__mock/requests")).json()) as { method: string; path: string; keys: string[]; query: string[] }[];
}
