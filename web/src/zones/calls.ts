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

export async function listPage(c: ConsoleClient, ds: Dataset, state: ZoneState | undefined, after: string | undefined, limit = ZONE_PAGE_LIMIT) {
  const query = { ...(state === undefined ? {} : { state }), ...(after === undefined ? {} : { after }), limit };
  const d = ds === "zones" ? must(await c.GET("/v1/zones", { params: { query } })) : must(await c.GET("/v1/uspace", { params: { query } }));
  return { rows: d.zones, next: d.next_after };
}

/** Every version in `state`, page by page, at most ZONE_PAGES_MAX pages; `complete` false past the bound. */
export async function listAll(c: ConsoleClient, ds: Dataset, state: ZoneState): Promise<{ rows: ZoneVersion[]; complete: boolean }> {
  const rows: ZoneVersion[] = [];
  let after: string | undefined;
  for (let i = 0; i < ZONE_PAGES_MAX; i++) {
    const p = await listPage(c, ds, state, after);
    rows.push(...p.rows);
    after = p.next;
    if (after === undefined) return { rows, complete: true };
  }
  return { rows, complete: false };
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

/**
 * What a publication would carry, from what api lists: the approved
 * versions it publishes, and the identifiers in force with them (each
 * identifier's approved version, else its published one, whose period
 * covers `nowMs`). The count of the confirmation; api's answer says
 * what was published.
 */
export function publicationPreview(approved: readonly ZoneVersion[], published: readonly ZoneVersion[], nowMs: number): { approved: number; inForce: number } {
  const covers = (z: ZoneVersion) => Date.parse(z.valid_from) <= nowMs && nowMs < Date.parse(z.valid_to);
  const byId = new Map<string, ZoneVersion>();
  for (const z of published) byId.set(z.identifier, z);
  for (const z of approved) byId.set(z.identifier, z);
  return { approved: approved.length, inForce: [...byId.values()].filter(covers).length };
}
