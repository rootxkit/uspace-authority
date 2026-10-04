// A police answer may carry two positions captured at the same instant
// (two sources, or a repeated broadcast): every row still has its own
// React key, so neither is dropped or merged with the other on update.
import { describe, expect, it } from "vitest";
import { positionRowKeys } from "./PoliceQueries";

describe("positionRowKeys", () => {
  it("gives two positions with the same time two keys", () => {
    const at = "2026-10-05T02:00:00Z";
    const keys = positionRowKeys([{ at }, { at }, { at: "2026-10-05T02:00:01Z" }]);
    expect(new Set(keys).size).toBe(3);
  });

  it("keeps a key per row for distinct times (the pair above)", () => {
    expect(positionRowKeys([{ at: "2026-10-05T02:00:00Z" }, { at: "2026-10-05T02:00:01Z" }])).toHaveLength(2);
  });
});
