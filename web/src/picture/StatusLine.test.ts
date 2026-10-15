// The status line's degraded part: every slug of this system has a short
// label in both catalogues, and the pair: a slug it does not know is kept,
// after the known ones, as the server sent it.
import { describe, expect, it } from "vitest";
import { en, ka } from "../i18n/catalogues";
import { DEGRADED_SLUGS } from "./degraded";
import { degradedOrder } from "./StatusLine";

describe("degradedOrder", () => {
  it("lists known slugs in the banner's order, an unknown one after them, none dropped", () => {
    expect(degradedOrder(["dp_unavailable", "new_thing", "cis_stale"])).toEqual(["cis_stale", "dp_unavailable", "new_thing"]);
    expect(degradedOrder([])).toEqual([]);
  });

  it("every slug has a short label in en and ka, without the slug itself", () => {
    for (const s of DEGRADED_SLUGS) {
      const k = `authority.degraded.label.${s}`;
      expect(en[k], k).toBeTruthy();
      expect(ka[k], k).toBeTruthy();
      expect(en[k], k).not.toContain(s);
    }
  });
});
