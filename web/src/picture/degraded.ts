// The words of picture-ws's degraded slugs (schemas/picture/status/v1.json,
// docs/runbooks/picture.md "Degraded states"). Each slug says what is
// wrong and what it means for the picture: an empty console must never
// look like an empty sky (E-02), and no line claims a loss that has not
// happened (C-12). The ages and the instant are the server's; the console
// computes none of them.
import type { Slug } from "./generated/status";

/** Every slug of this system, in the order the banner lists them: the bus first. */
export const DEGRADED_SLUGS: readonly Slug[] = [
  "nats_unavailable",
  "projections_unreadable",
  "registry_projection_absent",
  "cis_absent",
  "cis_stale",
  "dp_unavailable",
  "manned_unavailable",
  "alerts_unconfirmed",
  "alerts_replaying",
  "session_verifier_unavailable",
  "source_control_unknown",
  "policy_default",
  "tracks_evicted",
  "no_subscription",
  "viewport_too_large",
  "session_unchecked",
];

export function isSlug(v: string): v is Slug {
  return (DEGRADED_SLUGS as readonly string[]).includes(v);
}

/** What the server said beside `degraded[]`, for the words. */
export interface DegradedContext {
  /** When the bus was lost (picture-ws's nats_since); null when not known yet. */
  natsSince: string | null;
  /** The registry projection's age, seconds (projection_age_s); null when absent. */
  projectionAgeS: number | null;
  /** The CIS restrictions' age, seconds (cis_age_s); null when absent. */
  cisAgeS: number | null;
}

export interface DegradedLine {
  slug: string;
  /** A catalogue key. */
  key: string;
  /** The values the words quote; times as RFC 3339, ages in seconds. */
  vars: Record<string, string | number>;
}

/**
 * One line per degraded slug, known slugs first in DEGRADED_SLUGS order;
 * an unknown slug is shown as the server names it, never dropped.
 */
export function degradedLines(degraded: readonly string[], ctx: DegradedContext): DegradedLine[] {
  const known = DEGRADED_SLUGS.filter((s) => degraded.includes(s));
  const unknown = degraded.filter((s) => !isSlug(s));
  const lines: DegradedLine[] = known.map((slug): DegradedLine => {
    switch (slug) {
      case "nats_unavailable":
        return ctx.natsSince === null
          ? { slug, key: "authority.degraded.nats_unavailable", vars: {} }
          : { slug, key: "authority.degraded.nats_unavailable_since", vars: { since: ctx.natsSince } };
      case "projections_unreadable":
      case "registry_projection_absent":
        return ctx.projectionAgeS === null
          ? { slug, key: `authority.degraded.${slug}`, vars: {} }
          : { slug, key: `authority.degraded.${slug}_age`, vars: { age_s: ctx.projectionAgeS } };
      case "cis_absent":
      case "cis_stale":
        return ctx.cisAgeS === null
          ? { slug, key: `authority.degraded.${slug}`, vars: {} }
          : { slug, key: `authority.degraded.${slug}_age`, vars: { age_s: ctx.cisAgeS } };
      default:
        return { slug, key: `authority.degraded.${slug}`, vars: {} };
    }
  });
  for (const slug of unknown) lines.push({ slug, key: "authority.degraded.other", vars: { slug } });
  return lines;
}
