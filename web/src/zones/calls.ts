// api's zone and U-space airspace operations, one function per act and
// dataset (api/openapi.yaml /v1/zones*, /v1/uspace*), so the pages are
// written once for both. Each returns what api answered.
import type { components } from "../api/types";
import type { ConsoleClient } from "../api/client";
import { must } from "../authoring/api";
import type { ZoneVersion } from "./adapt";

export type Dataset = "zones" | "uspace_airspace";
export type ZoneState = components["schemas"]["ZoneState"];
export type ZonePublication = components["schemas"]["ZonePublication"];

export const ZONE_STATES: readonly ZoneState[] = ["draft", "approved", "published", "superseded"];
/** api's page maximum (listZones, listUSpaceAirspaces `limit`). */
export const ZONE_PAGE_LIMIT = 500;
/** At most this many pages are read for one count. A display bound; past it the count says it is incomplete. */
export const ZONE_PAGES_MAX = 20;

/**
 * api's clock when it answered, from the response's `Date` header (RFC
 * 9110 section 6.6.1, whole seconds), or null when there is none or it
 * does not parse. The browser's clock is not api's and may be wrong.
 */
export function serverClockMs(date: string | null | undefined): number | null {
  if (date === null || date === undefined || date === "") return null;
  const ms = Date.parse(date);
  return Number.isFinite(ms) ? ms : null;
}

export async function listPage(c: ConsoleClient, ds: Dataset, state: ZoneState | undefined, after: string | undefined, limit = ZONE_PAGE_LIMIT) {
  const query = { ...(state === undefined ? {} : { state }), ...(after === undefined ? {} : { after }), limit };
  const r = ds === "zones" ? await c.GET("/v1/zones", { params: { query } }) : await c.GET("/v1/uspace", { params: { query } });
  const d = must(r);
  return { rows: d.zones, next: d.next_after, serverNowMs: serverClockMs(r.response.headers.get("date")) };
}

/**
 * Every version in `state`, page by page, at most ZONE_PAGES_MAX pages;
 * `complete` false past the bound; `serverNowMs` api's clock at the last
 * page read (serverClockMs).
 */
export async function listAll(c: ConsoleClient, ds: Dataset, state: ZoneState): Promise<{ rows: ZoneVersion[]; complete: boolean; serverNowMs: number | null }> {
  const rows: ZoneVersion[] = [];
  let after: string | undefined;
  let serverNowMs: number | null = null;
  for (let i = 0; i < ZONE_PAGES_MAX; i++) {
    const p = await listPage(c, ds, state, after);
    rows.push(...p.rows);
    after = p.next;
    serverNowMs = p.serverNowMs;
    if (after === undefined) return { rows, complete: true, serverNowMs };
  }
  return { rows, complete: false, serverNowMs };
}

export async function getOne(c: ConsoleClient, ds: Dataset, identifier: string): Promise<ZoneVersion> {
  const path = { identifier };
  return ds === "zones" ? must(await c.GET("/v1/zones/{identifier}", { params: { path } })) : must(await c.GET("/v1/uspace/{identifier}", { params: { path } }));
}

export async function versions(c: ConsoleClient, ds: Dataset, identifier: string, before: number | undefined) {
  const params = { path: { identifier }, query: before === undefined ? {} : { before } };
  const d = ds === "zones" ? must(await c.GET("/v1/zones/{identifier}/versions", { params })) : must(await c.GET("/v1/uspace/{identifier}/versions", { params }));
  return { rows: d.versions, next: d.next_before };
}

/** Approves (a zone) or designates (a U-space airspace) the newest version, a draft. */
export async function approve(c: ConsoleClient, ds: Dataset, identifier: string, zoneVersion: number): Promise<ZoneVersion> {
  const opts = { params: { path: { identifier } }, body: { zone_version: zoneVersion } };
  return ds === "zones" ? must(await c.POST("/v1/zones/{identifier}/approve", opts)) : must(await c.POST("/v1/uspace/{identifier}/designate", opts));
}

export async function publish(c: ConsoleClient, ds: Dataset): Promise<ZonePublication> {
  return ds === "zones" ? must(await c.POST("/v1/zones/publish")) : must(await c.POST("/v1/uspace/publish"));
}

/** At most this many approved versions are named in the confirmation; the rest are counted. */
export const PUBLISH_NAMED_MAX = 10;

/**
 * What a publication would carry, from what api lists: the approved
 * versions it publishes (each by identifier and version, in identifier
 * order), and the identifiers in force with them (each identifier's
 * approved version, else its published one, whose period covers
 * `nowMs`, api's clock where it sent one). The count of the
 * confirmation; api's answer says what was published.
 */
export function publicationPreview(
  approved: readonly ZoneVersion[],
  published: readonly ZoneVersion[],
  nowMs: number,
): { approved: number; inForce: number; versions: { identifier: string; version: number }[] } {
  const covers = (z: ZoneVersion) => Date.parse(z.valid_from) <= nowMs && nowMs < Date.parse(z.valid_to);
  const byId = new Map<string, ZoneVersion>();
  for (const z of published) byId.set(z.identifier, z);
  for (const z of approved) byId.set(z.identifier, z);
  const versions = approved
    .map((z) => ({ identifier: z.identifier, version: z.zone_version }))
    .sort((a, b) => (a.identifier < b.identifier ? -1 : a.identifier > b.identifier ? 1 : a.version - b.version));
  return { approved: approved.length, inForce: [...byId.values()].filter(covers).length, versions };
}
