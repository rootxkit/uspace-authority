import AxeBuilder from "@axe-core/playwright";
import { expect, type APIRequestContext, type Page } from "@playwright/test";

// The WP-22 stub's test accounts (test/mock/authoring.mjs), not credentials.
export const VIEWER = { username: "viewer1", password: "viewer1-test-password" };
export const ADMIN = { username: "admin1", password: "admin1-test-password" };

export interface Recorded {
  method: string;
  path: string;
  query: Record<string, string>;
  body: unknown;
}

/** Every request the authoring stub answered, with its body. */
export async function recorded(request: APIRequestContext): Promise<Recorded[]> {
  return (await (await request.get("/__mock/authoring/requests")).json()) as Recorded[];
}

/** The fake CISP acknowledges every pending publication. */
export async function cispAcknowledges(request: APIRequestContext): Promise<void> {
  expect((await request.post("/__mock/authoring/cisp", { data: { ack: true } })).ok()).toBe(true);
}

export async function authoringState(request: APIRequestContext, state: Record<string, unknown>): Promise<void> {
  expect((await request.post("/__mock/authoring/state", { data: state })).ok()).toBe(true);
}

/** A form control by its react-hook-form name (the API's JSON path). */
export function field(page: Page, name: string) {
  return page.locator(`[name="${name}"]`);
}

/**
 * The axe check of the page as it stands: no WCAG 2.x A or AA violation
 * (the target of uspace-ui's docs/ACCESSIBILITY.md, pending GCAA). The
 * map's canvas is MapLibre's and is left out; everything around it is
 * checked.
 */
export async function expectAccessible(page: Page): Promise<void> {
  const r = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"]).exclude(".maplibregl-canvas").analyze();
  expect(r.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`)).toEqual([]);
}
