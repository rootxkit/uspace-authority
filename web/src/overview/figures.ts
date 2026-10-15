// The overview's figures from what api and picture-ws answered: counted,
// never judged. A queue read is one page, so its count says whether api
// had more; the sources are counted by the state picture-ws gave each.
import type { SourceState } from "@rootxkit/uspace-ui/model";
import type { components } from "../api/types";

type S = components["schemas"];

export interface QueueCount {
  count: number;
  /** api has more pages: the count is a lower bound. */
  more: boolean;
}

/** The figure of one page of a queue. */
export function queueCount(rows: readonly unknown[], nextCursor: string | undefined): QueueCount {
  return { count: rows.length, more: nextCursor !== undefined };
}

/** Sources by what picture-ws says of them: how many report healthy, how many say something else. */
export function sourceSummary(sources: readonly { state: SourceState }[]): { total: number; healthy: number; disabled: number; attention: number } {
  let healthy = 0;
  let disabled = 0;
  for (const s of sources) {
    if (s.state === "healthy") healthy += 1;
    else if (s.state === "disabled") disabled += 1;
  }
  return { total: sources.length, healthy, disabled, attention: sources.length - healthy - disabled };
}

/** One status's count of a summary, in the order the contract lists the statuses. */
export interface BreakdownItem {
  status: string;
  count: number;
}

/**
 * The statuses of a summary that api counted at least once, in `order`
 * (the contract's enum order). A status api did not count is absent, not
 * a zero shown; a summary with none is an empty list, which the tile says
 * in words.
 */
export function breakdown(counts: Readonly<Record<string, number>>, order: readonly string[]): BreakdownItem[] {
  return order.filter((s) => (counts[s] ?? 0) > 0).map((s) => ({ status: s, count: counts[s] ?? 0 }));
}

/** The registry's statuses (api/openapi.yaml RegistryStatus). */
export const REGISTRY_STATUSES = ["active", "suspended", "revoked", "expired"] as const satisfies readonly S["RegistryStatus"][];
/** A U-space airspace version's states (ZoneState). */
export const ZONE_STATES = ["draft", "approved", "published", "superseded"] as const satisfies readonly S["ZoneState"][];
/** A certificate's statuses (CertificateStatus). */
export const CERTIFICATE_STATUSES = ["issued", "operating", "ceased", "suspended", "limited", "revoked", "lapsed"] as const satisfies readonly S["CertificateStatus"][];

/** One of api's counts as a tile shows it. */
export interface CountSummary {
  count: number;
  /** api stopped at its bound: the count is a lower bound. */
  more: boolean;
  items: readonly BreakdownItem[];
  /** The database clock's time of the count. */
  asOf: string;
}

/** A summary api counted by status: its total and the statuses it counted, in `order`. */
export function countSummary(counts: Readonly<Record<string, unknown>> & { total: number }, order: readonly string[], asOf: string): CountSummary {
  const n: Record<string, number> = {};
  for (const s of order) {
    const v = counts[s];
    if (typeof v === "number") n[s] = v;
  }
  return { count: counts.total, more: false, items: breakdown(n, order), asOf };
}
