// The adapter on the lab's examples (../internal/picture/testdata/lab,
// verbatim at the commit in its SOURCE) and this repository's fixtures:
// every valid example is accepted, every invalid one the adapter can see
// is refused, each refusal beside the acceptance it differs from (E-01).
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseFrame, type ConsoleFrame } from "@rootxkit/uspace-ui/live";
import { describe, expect, it } from "vitest";
import { adaptTrack, adaptViolation, isUnverifiedClaim } from "./adapt";

const here = path.dirname(fileURLToPath(import.meta.url));
const LAB = path.resolve(here, "../../../internal/picture/testdata/lab");
const FIXTURES = path.resolve(here, "../../test/fixtures");

function frameOf(file: string): ConsoleFrame {
  const f = parseFrame(JSON.parse(readFileSync(file, "utf8")));
  if (f === null) throw new Error(`${file}: not a console frame`);
  return f;
}

function withBody(f: ConsoleFrame, patch: Record<string, unknown>): ConsoleFrame {
  return { ...f, body: { ...(f.body as Record<string, unknown>), ...patch } };
}

const trackDir = path.join(LAB, "track/telemetry/v1/examples");

describe("adaptTrack", () => {
  const valid = readdirSync(trackDir).filter((n) => n.endsWith(".json"));

  it("accepts every valid lab example", () => {
    expect(valid.length).toBeGreaterThan(2);
    for (const n of valid) expect(adaptTrack(frameOf(path.join(trackDir, n))), n).not.toBeNull();
  });

  // The invalid examples whose fault is a member the adapter reads. The
  // other two (a cell with a leading zero, a serial conflict without the
  // mismatch flag) are faults in members the console does not judge; they
  // are refused by picture-ws's schema check before a frame is sent.
  const refused = [
    "height-without-reference.json",
    "missing-identification.json",
    "track-deg-360.json",
    "unknown-identification-basis.json",
    "unknown-trust.json",
    "wrong-schema-name.json",
  ];
  for (const n of refused) {
    it(`refuses invalid/${n}`, () => {
      const raw = JSON.parse(readFileSync(path.join(trackDir, "invalid", n), "utf8"));
      const f = parseFrame(raw);
      expect(f === null ? null : adaptTrack(f)).toBeNull();
    });
  }

  it("reads this system's extras when present and leaves them null when absent", () => {
    const lab = adaptTrack(frameOf(path.join(trackDir, "direct-rid-pressure-altitude.json")));
    expect(lab?.extras).toEqual({ ageS: null, sourceState: null });
    const provider = adaptTrack(frameOf(path.join(FIXTURES, "provider-track.json")));
    expect(provider?.extras).toEqual({ ageS: 1.4, sourceState: "live" });
  });

  it("refuses a negative age and an unknown source state (the pair: the fixture above)", () => {
    const f = frameOf(path.join(FIXTURES, "provider-track.json"));
    expect(adaptTrack(withBody(f, { age_s: -1 }))).toBeNull();
    expect(adaptTrack(withBody(f, { source_state: "asleep" }))).toBeNull();
  });

  it("never keeps the operator position", () => {
    const f = frameOf(path.join(FIXTURES, "provider-track.json"));
    expect((f.body as Record<string, unknown>)["operator_position"]).toBeDefined();
    const out = JSON.stringify(adaptTrack(f));
    expect(out).not.toContain("operator_position");
    expect(out).not.toContain("41.70987");
    expect(out).not.toContain("44.77654");
  });

  it("says a broadcast and a provider track are unverified claims, an authenticated one is not", () => {
    const broadcast = adaptTrack(frameOf(path.join(trackDir, "direct-rid-pressure-altitude.json")));
    const authenticated = adaptTrack(frameOf(path.join(trackDir, "authenticated-operator-session.json")));
    const provider = adaptTrack(frameOf(path.join(FIXTURES, "provider-track.json")));
    expect(broadcast !== null && isUnverifiedClaim(broadcast.view)).toBe(true);
    expect(provider !== null && isUnverifiedClaim(provider.view)).toBe(true);
    expect(authenticated !== null && isUnverifiedClaim(authenticated.view)).toBe(false);
  });

  it("refuses a position outside WGS84 and accepts the edge", () => {
    const f = frameOf(path.join(FIXTURES, "provider-track.json"));
    expect(adaptTrack(withBody(f, { position: { lat: 90, lng: 180 } }))).not.toBeNull();
    expect(adaptTrack(withBody(f, { position: { lat: 90.0001, lng: 180 } }))).toBeNull();
  });
});

describe("adaptViolation", () => {
  const full = () => frameOf(path.join(FIXTURES, "violation.json"));

  it("accepts the full violation/v1 fixture", () => {
    const v = adaptViolation(full());
    expect(v?.alert).toMatchObject({ kind: "height_120m", severity: "critical", state: "updated", policyVersion: "3" });
    expect(v?.alert.aircraft).toEqual(["authority-1:rid:4A:7C:91:0E:22:B5"]);
  });

  it("refuses the lab's minimal alert example, which lacks the required members", () => {
    const snap = JSON.parse(readFileSync(path.join(LAB, "console/snapshot/v1/examples/authority-picture.json"), "utf8"));
    const f = parseFrame(snap.body.alerts[0]);
    expect(f).not.toBeNull();
    expect(adaptViolation(f as ConsoleFrame)).toBeNull();
  });

  it("a clear needs its reason and a reason needs a clear", () => {
    expect(adaptViolation(withBody(full(), { state: "cleared", clear_reason: "landed" }))?.alert.clearReason).toBe("landed");
    expect(adaptViolation(withBody(full(), { state: "cleared", clear_reason: null }))).toBeNull();
    expect(adaptViolation(withBody(full(), { state: "raised", clear_reason: "landed" }))).toBeNull();
  });

  it("keeps reconfigured, which has no kit word, beside the alert", () => {
    const v = adaptViolation(withBody(full(), { state: "cleared", clear_reason: "reconfigured" }));
    expect(v?.alert.clearReason).toBeNull();
    expect(v?.clearReason).toBe("reconfigured");
  });

  it("refuses a kind this system does not raise (conflicts are never violations, D5)", () => {
    expect(adaptViolation(withBody(full(), { kind: "proximity" }))).toBeNull();
  });
});
