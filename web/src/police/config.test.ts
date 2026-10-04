// The police realm's purposes as configuration (defaults pending GCAA)
// and the client's check of every query's basis. Each refusal beside the
// acceptance it differs from (E-01).
import { describe, expect, it } from "vitest";
import { en, ka } from "../i18n/catalogues";
import { bboxParam, DEFAULT_POLICE_PII_PURPOSES, DEFAULT_POLICE_PURPOSES, policeConfigFromEnv, queryBasisProblem } from "./config";

describe("police purposes", () => {
  it("without configuration: the spec's defaults, said to be pending GCAA", () => {
    expect(policeConfigFromEnv({})).toEqual({ config: { purposes: DEFAULT_POLICE_PURPOSES, piiPurposes: DEFAULT_POLICE_PII_PURPOSES, pendingGcaa: true } });
  });

  it("configured: the lists as given, not pending (the pair above)", () => {
    const r = policeConfigFromEnv({ WEB_POLICE_PURPOSES: "a_one, b_two", WEB_POLICE_PII_PURPOSES: "b_two" });
    expect(r).toEqual({ config: { purposes: ["a_one", "b_two"], piiPurposes: ["b_two"], pendingGcaa: false } });
  });

  it("a malformed, repeated or unlisted code is a problem naming the variable", () => {
    expect(policeConfigFromEnv({ WEB_POLICE_PURPOSES: "Bad Code" })).toEqual({ problem: expect.stringContaining("WEB_POLICE_PURPOSES") });
    expect(policeConfigFromEnv({ WEB_POLICE_PURPOSES: "a,a" })).toEqual({ problem: expect.stringContaining("repeated") });
    expect(policeConfigFromEnv({ WEB_POLICE_PURPOSES: "a", WEB_POLICE_PII_PURPOSES: "b" })).toEqual({ problem: expect.stringContaining("WEB_POLICE_PII_PURPOSES") });
  });

  it("every default purpose is worded in both languages", () => {
    for (const p of DEFAULT_POLICE_PURPOSES) {
      expect(en[`authority.police.purpose.${p}`], p).toBeTruthy();
      expect(ka[`authority.police.purpose.${p}`], p).toBeTruthy();
    }
  });
});

describe("the basis of a query", () => {
  const allowed = ["public_order", "criminal_investigation"];

  it("a listed purpose and a case reference may go", () => {
    expect(queryBasisProblem("public_order", " CASE-1 ", allowed)).toBeNull();
  });

  it("without a purpose, with one off the list, or without a case reference it may not", () => {
    expect(queryBasisProblem("", "CASE-1", allowed)).toBe("authority.police.basis.purpose_missing");
    expect(queryBasisProblem("security_threat", "CASE-1", allowed)).toBe("authority.police.basis.purpose_missing");
    expect(queryBasisProblem("public_order", "   ", allowed)).toBe("authority.police.basis.case_ref_missing");
    expect(queryBasisProblem("public_order", "x".repeat(101), allowed)).toBe("authority.police.basis.case_ref_long");
    expect(queryBasisProblem("public_order", "x".repeat(100), allowed)).toBeNull();
  });

  it("a box of four numbers is a parameter; one that is not a number is none", () => {
    expect(bboxParam("44.7", "41.6", "44.9", "41.8")).toBe("44.7,41.6,44.9,41.8");
    expect(bboxParam("44.7", "", "44.9", "41.8")).toBeNull();
    expect(bboxParam("44.7", "north", "44.9", "41.8")).toBeNull();
  });
});
