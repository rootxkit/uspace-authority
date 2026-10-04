import { describe, expect, it } from "vitest";
import { createKeyedStore } from "./keyed";

describe("createKeyedStore", () => {
  it("holds up to its bound without evicting (the pair of the next test)", () => {
    const s = createKeyedStore<number>(3);
    for (const id of ["a", "b", "c"]) s.set(id, 1);
    expect([...s.snapshot().keys()]).toEqual(["a", "b", "c"]);
    expect(s.evicted()).toBe(0);
  });

  it("past its bound evicts the least recently set and counts it (E-10)", () => {
    const s = createKeyedStore<number>(3);
    for (const id of ["a", "b", "c"]) s.set(id, 1);
    s.set("a", 2); // a is now the newest
    s.set("d", 1);
    expect([...s.snapshot().keys()]).toEqual(["c", "a", "d"]);
    expect(s.evicted()).toBe(1);
  });

  it("retain keeps exactly the given ids and notifies once", () => {
    const s = createKeyedStore<number>(10);
    for (const id of ["a", "b", "c"]) s.set(id, 1);
    let calls = 0;
    s.subscribe(() => calls++);
    s.retain(new Set(["b"]));
    expect([...s.snapshot().keys()]).toEqual(["b"]);
    s.retain(new Set(["b"]));
    expect(calls).toBe(1);
  });

  it("the snapshot is stable between changes", () => {
    const s = createKeyedStore<number>(2);
    s.set("a", 1);
    expect(s.snapshot()).toBe(s.snapshot());
  });

  it("refuses a bound that is not a positive whole number", () => {
    expect(() => createKeyedStore(0)).toThrow(RangeError);
  });
});
