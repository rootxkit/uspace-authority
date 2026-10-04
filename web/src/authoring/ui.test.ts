// A reason past api's maxLength is refused by the act, never cut to fit:
// the bound itself, one over it, and the characters counted as api counts
// them (code points, not UTF-16 units).
import { describe, expect, it } from "vitest";
import { reasonTooLong } from "./ui";

describe("reasonTooLong", () => {
  it("accepts a reason of exactly the maximum and refuses one character more", () => {
    expect(reasonTooLong("x".repeat(500), 500)).toBe(false);
    expect(reasonTooLong("x".repeat(501), 500)).toBe(true);
  });

  it("counts Georgian and astral characters once each", () => {
    expect(reasonTooLong("ა".repeat(500), 500)).toBe(false);
    expect(reasonTooLong("\u{1F6E9}".repeat(500), 500)).toBe(false);
    expect(reasonTooLong("\u{1F6E9}".repeat(501), 500)).toBe(true);
  });

  it("has no bound without a maximum", () => {
    expect(reasonTooLong("x".repeat(5000), undefined)).toBe(false);
  });
});
