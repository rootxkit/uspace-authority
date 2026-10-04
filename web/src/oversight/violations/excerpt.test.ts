// The excerpt drawn as api cut it: a line through each segment's own
// samples, nothing across a hole, and the samples unjoined when api did
// not cut them (B-13). Each absence beside its presence (E-01).
import { describe, expect, it } from "vitest";
import type { components } from "../../api/types";
import { excerptFeatures, excerptView } from "./excerpt";

type Violation = components["schemas"]["Violation"];

const sample = (s: number, lng: number) => ({ captured_at: `2026-10-03T12:00:${String(s).padStart(2, "0")}.000Z`, lat: 41.7, lng, alt_source: "geodetic", alt_amsl_m: 600 });
const excerpt = [sample(0, 44.80), sample(1, 44.81), sample(9, 44.85), sample(10, 44.86)];
const at = (i: number) => excerpt[i]?.captured_at ?? "";
const hole = { from: "2026-10-03T12:00:01.000Z", to: "2026-10-03T12:00:09.000Z", duration_s: 8, causes: ["silence", "no recorded cause"], recorded: [] };

function cut(holes: (typeof hole)[], segments: { from: string; to: string; sample_indexes: number[] }[]): Pick<Violation, "evidence_excerpt" | "excerpt_segmenting"> {
  return {
    evidence_excerpt: excerpt,
    excerpt_segmenting: { state: "cut", max_gap_s: 3, policy_version: 4, writer_gaps_read: true, segments, holes, unplaced: [] },
  };
}

describe("the evidence excerpt", () => {
  it("one segment: one line through every sample, no hole", () => {
    const v = excerptView(cut([], [{ from: at(0), to: at(3), sample_indexes: [0, 1, 2, 3] }]));
    expect(v.mode).toBe("cut");
    if (v.mode !== "cut") return;
    expect(v.runs.map((r) => r.kind)).toEqual(["segment"]);
    expect(excerptFeatures(v).lines.features).toHaveLength(1);
  });

  it("a hole between two segments is a run of its own, and no line crosses it (the pair above)", () => {
    const v = excerptView(
      cut([hole], [
        { from: at(0), to: at(1), sample_indexes: [0, 1] },
        { from: at(2), to: at(3), sample_indexes: [2, 3] },
      ]),
    );
    if (v.mode !== "cut") throw new Error("not cut");
    expect(v.runs.map((r) => r.kind)).toEqual(["segment", "hole", "segment"]);
    const f = excerptFeatures(v);
    expect(f.lines.features).toHaveLength(2);
    // Each line holds its own segment's samples only: nothing joins 44.81 to 44.85.
    expect(f.lines.features.map((l) => l.geometry.coordinates.map((c) => c[0]))).toEqual([
      [44.8, 44.81],
      [44.85, 44.86],
    ]);
    expect(f.points.features).toHaveLength(4);
  });

  it("without api's cut the samples are points only, never a line", () => {
    for (const seg of [undefined, { state: "unavailable" as const, reason: "no policy", segments: [], holes: [], unplaced: [] }]) {
      const v = excerptView({ evidence_excerpt: excerpt, ...(seg === undefined ? {} : { excerpt_segmenting: seg }) });
      expect(v.mode).toBe("unjoined");
      const f = excerptFeatures(v);
      expect(f.lines.features).toEqual([]);
      expect(f.points.features).toHaveLength(4);
    }
  });
});
