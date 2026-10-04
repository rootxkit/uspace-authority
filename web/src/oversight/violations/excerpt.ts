// A violation's evidence excerpt as the page draws it: the samples api
// stored at detection, in the segments and holes api cut them into
// (excerpt_segmenting, the evidence packs' rule, B-13). Nothing is cut,
// joined or interpolated here: a segment is drawn as a line through its
// own samples, a hole is a labelled gap with nothing drawn across it,
// and without api's cut the samples are drawn unjoined.
import type { components } from "../../api/types";

type Violation = components["schemas"]["Violation"];
type Hole = components["schemas"]["ViolationExcerptHole"];

/** One stored sample (violation/v1 sample), read defensively. */
export interface Sample {
  index: number;
  capturedAt: string | null;
  lat: number | null;
  lng: number | null;
  altAmslM: number | null;
  altWgs84M: number | null;
  altPressureM: number | null;
  altSource: string | null;
  speedMs: number | null;
  trackDeg: number | null;
  source: string | null;
  sourceInstance: string | null;
  trust: string | null;
}

const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);
const str = (v: unknown): string | null => (typeof v === "string" ? v : null);

export function sampleOf(raw: Record<string, unknown>, index: number): Sample {
  return {
    index,
    capturedAt: str(raw["captured_at"]),
    lat: num(raw["lat"]),
    lng: num(raw["lng"]),
    altAmslM: num(raw["alt_amsl_m"]),
    altWgs84M: num(raw["alt_wgs84_m"]),
    altPressureM: num(raw["alt_pressure_m"]),
    altSource: str(raw["alt_source"]),
    speedMs: num(raw["speed_ms"]),
    trackDeg: num(raw["track_deg"]),
    source: str(raw["source"]),
    sourceInstance: str(raw["source_instance"]),
    trust: str(raw["trust"]),
  };
}

export type Run = { kind: "segment"; samples: Sample[] } | { kind: "hole"; hole: Hole };

export type ExcerptView =
  | { mode: "cut"; runs: Run[]; maxGapS: number | null; policyVersion: number | null; writerGapsRead: boolean; unplaced: Sample[] }
  | { mode: "unjoined"; reason: string; samples: Sample[] };

/** The excerpt in api's segments and holes, in time order; unjoined without api's cut. */
export function excerptView(v: Pick<Violation, "evidence_excerpt" | "excerpt_segmenting">): ExcerptView {
  const samples = v.evidence_excerpt.map((raw, i) => sampleOf(raw, i));
  const seg = v.excerpt_segmenting;
  if (seg === undefined || seg.state !== "cut") {
    return { mode: "unjoined", reason: seg?.reason ?? "", samples };
  }
  const at = (i: number) => samples[i];
  const runs: { t: number; order: number; run: Run }[] = [];
  for (const s of seg.segments) {
    const members = s.sample_indexes.map(at).filter((x): x is Sample => x !== undefined);
    runs.push({ t: Date.parse(s.from), order: 0, run: { kind: "segment", samples: members } });
  }
  for (const h of seg.holes) runs.push({ t: Date.parse(h.from), order: 1, run: { kind: "hole", hole: h } });
  runs.sort((a, b) => a.t - b.t || a.order - b.order);
  return {
    mode: "cut",
    runs: runs.map((r) => r.run),
    maxGapS: seg.max_gap_s ?? null,
    policyVersion: seg.policy_version ?? null,
    writerGapsRead: seg.writer_gaps_read === true,
    unplaced: seg.unplaced.map(at).filter((x): x is Sample => x !== undefined),
  };
}

type Position = [number, number];

const positioned = (s: Sample): s is Sample & { lat: number; lng: number } => s.lat !== null && s.lng !== null;

/**
 * The map's data: one line per segment of two or more positioned
 * samples, through those samples only, and a point per positioned
 * sample. Holes have no feature: nothing is drawn across one.
 */
export function excerptFeatures(view: ExcerptView) {
  const lines: Position[][] = [];
  const points: Position[] = [];
  const all = view.mode === "cut" ? view.runs.flatMap((r) => (r.kind === "segment" ? r.samples : [])) : view.samples;
  for (const s of all) if (positioned(s)) points.push([s.lng, s.lat]);
  if (view.mode === "cut") {
    for (const r of view.runs) {
      if (r.kind !== "segment") continue;
      const line = r.samples.filter(positioned).map((s): Position => [s.lng, s.lat]);
      if (line.length >= 2) lines.push(line);
    }
  }
  return {
    lines: {
      type: "FeatureCollection" as const,
      features: lines.map((coordinates, i) => ({ type: "Feature" as const, id: i, properties: {}, geometry: { type: "LineString" as const, coordinates } })),
    },
    points: {
      type: "FeatureCollection" as const,
      features: points.map((coordinates, i) => ({ type: "Feature" as const, id: i, properties: {}, geometry: { type: "Point" as const, coordinates } })),
    },
    first: points[0] ?? null,
  };
}
