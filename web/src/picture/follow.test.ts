// What the console keeps beside the kit's alert store (a violation's
// members) follows that store: when the kit drops a cleared alert at the
// end of its hold, or a snapshot leaves an alert out, the violation goes
// too, and an alert still held keeps it.
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createAlertStore, parseFrame, type ConsoleFrame } from "@rootxkit/uspace-ui/live";
import { afterEach, describe, expect, it, vi } from "vitest";
import { adaptViolation, type AdaptedViolation } from "./adapt";
import { createKeyedStore, followKeys } from "./keyed";

const FIXTURE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../test/fixtures/violation.json");

function violation(id: string, state: "raised" | "cleared"): AdaptedViolation {
  const f = parseFrame(JSON.parse(readFileSync(FIXTURE, "utf8"))) as ConsoleFrame;
  const body = { ...(f.body as Record<string, unknown>), violation_id: id, state, clear_reason: state === "cleared" ? "landed" : null };
  const v = adaptViolation({ ...f, body });
  if (v === null) throw new Error("fixture refused");
  return v;
}

afterEach(() => {
  vi.useRealTimers();
});

describe("followKeys", () => {
  it("drops a violation when the kit drops its cleared alert, keeps an active one", () => {
    vi.useFakeTimers();
    let nowMs = 1_000_000;
    const alerts = createAlertStore({ clearedHoldMs: 30_000, now: () => nowMs });
    const held = createKeyedStore<AdaptedViolation>(10);
    const stop = followKeys(alerts, held);
    for (const id of ["v-cleared", "v-active"]) {
      const v = violation(id, "raised");
      held.set(id, v);
      alerts.apply(v.alert);
    }
    const clear = violation("v-cleared", "cleared");
    held.set("v-cleared", clear);
    alerts.apply(clear.alert);
    // Held on screen with its clear for the hold: kept.
    expect([...held.snapshot().keys()].sort()).toEqual(["v-active", "v-cleared"]);

    nowMs += 30_000;
    vi.advanceTimersByTime(30_000);
    expect(alerts.get("v-cleared")).toBeUndefined();
    expect([...held.snapshot().keys()]).toEqual(["v-active"]);
    stop();
    alerts.dispose();
  });

  it("drops a violation a snapshot leaves out", () => {
    const alerts = createAlertStore();
    const held = createKeyedStore<AdaptedViolation>(10);
    const stop = followKeys(alerts, held);
    const a = violation("v-a", "raised");
    const b = violation("v-b", "raised");
    held.set("v-a", a);
    held.set("v-b", b);
    alerts.replace([a.alert, b.alert]);
    expect(held.snapshot().size).toBe(2);
    alerts.replace([b.alert]);
    expect([...held.snapshot().keys()]).toEqual(["v-b"]);
    stop();
    alerts.dispose();
  });

  it("stops following when stopped", () => {
    const alerts = createAlertStore();
    const held = createKeyedStore<AdaptedViolation>(10);
    const stop = followKeys(alerts, held);
    const a = violation("v-a", "raised");
    held.set("v-a", a);
    alerts.apply(a.alert);
    stop();
    alerts.replace([]);
    expect(held.snapshot().has("v-a")).toBe(true);
    alerts.dispose();
  });
});
