// The zone identifier the BFF admits is the one api/openapi.yaml pins on
// every /v1/zones/{identifier} and /v1/uspace/{identifier} operation, so
// the two cannot drift: a path the spec admits reaches api, one it does
// not is the BFF's 404.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { PROXY_ALLOW_PATHS, ZONE_IDENTIFIER } from "./handlers";

const spec = readFileSync(new URL("../../../../api/openapi.yaml", import.meta.url), "utf8");

describe("the zone identifier pattern", () => {
  it("is pinned in the spec on every zone and U-space identifier, and is the BFF's", () => {
    const params = [...spec.matchAll(/^\s*- \{name: identifier, in: path, required: true, schema: (\{.*\})\}$/gm)].map((m) => m[1]);
    expect(params.length).toBeGreaterThanOrEqual(7);
    for (const p of params) expect(p).toBe(`{type: string, maxLength: 7, pattern: "^${ZONE_IDENTIFIER}$"}`);
  });

  it("admits what the pattern admits and refuses the rest (the pair)", () => {
    const allowed = (p: string) => PROXY_ALLOW_PATHS.some((re) => re.test(p));
    const pattern = new RegExp(`^${ZONE_IDENTIFIER}$`);
    for (const id of ["TSTP001", "A", "ab_-9Z"]) {
      expect(pattern.test(id), id).toBe(true);
      expect(allowed(`/v1/zones/${id}`), id).toBe(true);
      expect(allowed(`/v1/uspace/${id}/versions`), id).toBe(true);
    }
    for (const id of ["TSTP0012", "TS.P01", "TS P01", "ზონა"]) {
      expect(pattern.test(id), id).toBe(false);
      expect(allowed(`/v1/zones/${id}`), id).toBe(false);
      expect(allowed(`/v1/uspace/${id}`), id).toBe(false);
    }
  });
});
