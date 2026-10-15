// A long id is shown by its first characters (the whole id stays in the
// tooltip), and the pair: a short one is shown whole, never cut.
import { describe, expect, it } from "vitest";
import { SHORT_ID_KEEP, SHORT_ID_MAX, shortId } from "./ids";

describe("shortId", () => {
  it("shortens an account id as long as api's to its first characters and an ellipsis", () => {
    expect(shortId("315c707cc1b7d07d2ff8a23f5af46d97")).toBe("315c707c…");
    expect(shortId("x".repeat(SHORT_ID_MAX + 1))).toBe(`${"x".repeat(SHORT_ID_KEEP)}…`);
  });

  it("shows an id of at most the bound whole (the pair)", () => {
    expect(shortId("user-admin1")).toBe("user-admin1");
    expect(shortId("x".repeat(SHORT_ID_MAX))).toBe("x".repeat(SHORT_ID_MAX));
    expect(shortId("")).toBe("");
  });
});
