import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import en from "../i18n/en.json";
import ka from "../i18n/ka.json";
import { DEGRADED_SLUGS, degradedLines } from "./degraded";

const here = path.dirname(fileURLToPath(import.meta.url));
const NONE = { natsSince: null, projectionAgeS: null, cisAgeS: null };

describe("degraded words", () => {
  it("cover every slug schemas/picture/status/v1.json names", () => {
    const schema = JSON.parse(readFileSync(path.resolve(here, "../../../schemas/picture/status/v1.json"), "utf8"));
    expect([...DEGRADED_SLUGS].sort()).toEqual([...schema.$defs.slug.enum].sort());
  });

  it("every line has words in both catalogues", () => {
    const ctxs = [NONE, { natsSince: "2026-10-02T09:20:00.000Z", projectionAgeS: 4, cisAgeS: 400 }];
    for (const ctx of ctxs) {
      for (const l of degradedLines(DEGRADED_SLUGS, ctx)) {
        expect(en, l.key).toHaveProperty([l.key]);
        expect(ka, l.key).toHaveProperty([l.key]);
      }
    }
  });

  it("nothing degraded is no line (the pair of the line below)", () => {
    expect(degradedLines([], NONE)).toEqual([]);
  });

  it("the bus line says since when, once the server said it", () => {
    expect(degradedLines(["nats_unavailable"], NONE)).toEqual([{ slug: "nats_unavailable", key: "authority.degraded.nats_unavailable", vars: {} }]);
    expect(degradedLines(["nats_unavailable"], { ...NONE, natsSince: "2026-10-02T09:20:00.000Z" })[0]).toEqual({
      slug: "nats_unavailable",
      key: "authority.degraded.nats_unavailable_since",
      vars: { since: "2026-10-02T09:20:00.000Z" },
    });
  });

  it("the projection and CIS lines carry the server's ages", () => {
    const lines = degradedLines(["cis_stale", "projections_unreadable"], { ...NONE, projectionAgeS: 12, cisAgeS: 900 });
    expect(lines.map((l) => [l.key, l.vars])).toEqual([
      ["authority.degraded.projections_unreadable_age", { age_s: 12 }],
      ["authority.degraded.cis_stale_age", { age_s: 900 }],
    ]);
  });

  it("an unknown slug is shown as the server names it, never dropped", () => {
    expect(degradedLines(["dss_gone"], NONE)).toEqual([{ slug: "dss_gone", key: "authority.degraded.other", vars: { slug: "dss_gone" } }]);
  });
});
