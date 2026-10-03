// The console's navigation by role (spec 01 §1 users and roles; docs/
// PLAN.md §7). A courtesy to the layout, never a control: the roles come
// from the session cookie decoded without verification (the kit's
// sessionClaimsUnverified, M20), an item hidden here is still served or
// refused by api and picture-ws, and a page reached by its address shows
// what they answer.
import type { components } from "../api/types";

export type Role = components["schemas"]["Role"];
export type Realm = components["schemas"]["Realm"];

/** Every console role (api/openapi.yaml Role). */
export const ROLES: readonly Role[] = ["viewer", "inspector", "registrar", "incident_officer", "admin", "auditor"];

export function isRole(v: unknown): v is Role {
  return typeof v === "string" && (ROLES as readonly string[]).includes(v);
}

export interface NavItem {
  /** The path under /<locale>. */
  path: string;
  /** The catalogue key of its label. */
  labelKey: string;
  /** The roles the page's reads admit; empty means any session of the realm. */
  roles: readonly Role[];
  /** The realms the page is for. */
  realms: readonly Realm[];
}

/**
 * Every page of this work package. The inspector map reads the picture,
 * which picture-ws serves to every session of the console and police
 * realms, and the zones, which api serves to inspector, admin and viewer
 * (the map says so when the zones are refused). Later work packages
 * (WP-22 to WP-24) add their pages here with their operations' x-roles.
 */
export const NAV_ITEMS: readonly NavItem[] = [{ path: "", labelKey: "authority.nav.map", roles: [], realms: ["console", "police"] }];

/** The items a session with `roles` in `realm` is shown; none without a session. */
export function navFor(session: { roles: readonly string[]; realm: string } | null): NavItem[] {
  if (session === null) return [];
  return NAV_ITEMS.filter(
    (i) =>
      (i.realms as readonly string[]).includes(session.realm) &&
      (i.roles.length === 0 || i.roles.some((r) => session.roles.includes(r))),
  );
}

/** The roles of a session the console has words for, in the catalogue's order. */
export function knownRoles(roles: readonly string[]): Role[] {
  return ROLES.filter((r) => roles.includes(r));
}
