// The one hand-written mapping from picture-ws frames to the kit's view
// models (uspace-ui PLAN §3.14). It copies what picture-ws said and
// decides nothing: no identification, no age bucket, no threshold, no
// geometry. A frame that breaks its schema is refused here (null, counted
// by the caller), never repaired.
//
// What the console never keeps (06 §5, G-04):
// - `operator_position`, the remote pilot or operator position a Display
//   Provider flight carries, is dropped here, before anything is stored:
//   picture-ws sends it to every console session, and no page of this
//   work package has a role that shows it.
// - the EU registration secret: picture-ws sends only the public part of
//   a registration number (`regnum.PublicPart`). The adapter passes the
//   member as sent and adds nothing.
import {
  isAltSource,
  isIdentBasis,
  isIdentReason,
  isIdentStatus,
  isSeverity,
  isTrust,
  type AlertKind,
  type ClearReason,
  type Identification,
  type TrackView,
  type ViolationKind,
} from "@rootxkit/uspace-ui/model";
import type { AlertInput, ConsoleFrame, WireSourceState } from "@rootxkit/uspace-ui/live";
import type { PictureTrackExtras } from "./generated/track";
import type { ViolationBody } from "./generated/violation";

export const TRACK_SCHEMA = "track/telemetry/v1";
export const VIOLATION_SCHEMA = "violation/v1";
export const SOURCE_STATUS_SCHEMA = "source/status/v1";

type Obj = Record<string, unknown>;

const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);
const isStr = (v: unknown): v is string => typeof v === "string";
const isNonEmpty = (v: unknown): v is string => isStr(v) && v.length > 0;
const isNum = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v);

/** A member that is a finite number or null; `undefined` when it is neither. */
function numOrNull(v: unknown): number | null | undefined {
  if (v === null) return null;
  return isNum(v) ? v : undefined;
}

function strOrNull(v: unknown): string | null | undefined {
  if (v === null) return null;
  return isStr(v) ? v : undefined;
}

const WIRE_SOURCE_STATES: readonly WireSourceState[] = ["live", "stale", "disabled", "down", "unknown"];
const HEIGHT_REFS = ["TakeoffLocation", "GroundLevel"] as const;

/** The authority's extras of a track frame (schemas/picture/track/v1.json), as sent. */
export interface TrackExtras {
  /** now - captured_at on this system's clock when picture-ws sent the frame; null when absent. */
  ageS: number | null;
  /** The track's source instance state; null when absent (a frame from the lab's examples). */
  sourceState: PictureTrackExtras["source_state"] | null;
}

export interface AdaptedTrack {
  view: Omit<TrackView, "receivedAtMs">;
  extras: TrackExtras;
}

function identificationOf(raw: unknown): Identification | null | undefined {
  if (raw === null) return null;
  if (!isObj(raw)) return undefined;
  const { status, reason, basis, mismatch } = raw;
  if (!isIdentStatus(status) || !isIdentReason(reason) || !isIdentBasis(basis) || typeof mismatch !== "boolean") return undefined;
  const serial = strOrNull(raw["serial"]);
  const operatorReg = strOrNull(raw["operator_reg"]);
  const registered = strOrNull(raw["registered_operator_reg"] ?? null);
  if (serial === undefined || operatorReg === undefined || registered === undefined) return undefined;
  return { status, reason, serial, operatorReg, registeredOperatorReg: registered, mismatch, basis };
}

/**
 * A `track/telemetry/v1` frame as the kit's TrackView and this system's
 * extras, or null when the frame breaks the lab's schema or this
 * system's extras. `operator_position` is never read.
 */
export function adaptTrack(frame: ConsoleFrame): AdaptedTrack | null {
  if (frame.schema !== TRACK_SCHEMA || frame.capturedAt === null) return null;
  const b = frame.body;
  if (!isObj(b)) return null;
  const { track_id, trust, source, source_instance, position, alt_source, emergency } = b;
  if (!isNonEmpty(track_id) || !isTrust(trust) || !isNonEmpty(source) || !isNonEmpty(source_instance)) return null;
  if (!isObj(position) || !isNum(position["lat"]) || !isNum(position["lng"])) return null;
  const lat = position["lat"];
  const lng = position["lng"];
  if (lat < -90 || lat > 90 || lng < -180 || lng > 180) return null;
  if (!isAltSource(alt_source) || typeof emergency !== "boolean") return null;
  const altAmslM = numOrNull(b["alt_amsl_m"]);
  const altWgs84M = numOrNull(b["alt_wgs84_m"]);
  const heightM = numOrNull(b["height_m"]);
  const speedMs = numOrNull(b["speed_ms"]);
  const trackDeg = numOrNull(b["track_deg"]);
  const vspeedMs = numOrNull(b["vspeed_ms"]);
  const status = strOrNull(b["status"]);
  const flightId = strOrNull(b["flight_id"]);
  const intentId = strOrNull(b["intent_id"]);
  const identification = identificationOf(b["identification"]);
  for (const v of [altAmslM, altWgs84M, heightM, speedMs, trackDeg, vspeedMs, status, flightId, intentId, identification]) {
    if (v === undefined) return null;
  }
  const hr = b["height_ref"];
  const heightRef = hr === null ? null : HEIGHT_REFS.find((r) => r === hr);
  if (heightRef === undefined) return null;
  // A height without its reference is not a height (02 §1).
  if (heightM !== null && heightRef === null) return null;
  if (trackDeg !== null && trackDeg !== undefined && (trackDeg < 0 || trackDeg >= 360)) return null;

  // This system's extras: absent on the lab's examples, typed when present.
  const age = b["age_s"];
  const state = b["source_state"];
  if (age !== undefined && !(isNum(age) && age >= 0)) return null;
  if (state !== undefined && !WIRE_SOURCE_STATES.includes(state as WireSourceState)) return null;

  return {
    view: {
      trackId: track_id,
      trust,
      source,
      sourceInstance: source_instance,
      lat,
      lng,
      altAmslM: altAmslM ?? null,
      altWgs84M: altWgs84M ?? null,
      altSource: alt_source,
      heightM: heightM ?? null,
      heightRef,
      speedMs: speedMs ?? null,
      trackDeg: trackDeg ?? null,
      vspeedMs: vspeedMs ?? null,
      status: status ?? null,
      emergency,
      identification: identification ?? null,
      flightId: flightId ?? null,
      intentId: intentId ?? null,
      times: {
        ts: frame.ts,
        rxTs: frame.rxTs,
        capturedAt: frame.capturedAt,
        timeSource: frame.timeSource,
        backlog: frame.backlog,
      },
    },
    extras: {
      ageS: isNum(age) ? age : null,
      sourceState: (state as PictureTrackExtras["source_state"] | undefined) ?? null,
    },
  };
}

/**
 * Whether a track's identity and position are a claim nobody verified:
 * every broadcast and every provider track (R-05). The words come from
 * the catalogue; this only says which tracks carry them.
 */
export function isUnverifiedClaim(t: Pick<TrackView, "trust" | "identification">): boolean {
  return (
    t.trust === "broadcast" ||
    t.trust === "provider" ||
    t.identification?.basis === "as_broadcast" ||
    t.identification?.basis === "provider"
  );
}

/** The violation kinds this system raises (schemas/violation/v1.json). */
const VIOLATION_KINDS: readonly ViolationBody["kind"][] = [
  "height_120m",
  "zone_incursion",
  "unregistered",
  "identification_mismatch",
];
const VIOLATION_STATES: readonly ViolationBody["state"][] = ["raised", "updated", "cleared"];
const KIT_CLEAR_REASONS: readonly ClearReason[] = ["resolved", "stale", "source_disabled", "flight_ended", "landed"];
const WIRE_CLEAR_REASONS: readonly NonNullable<ViolationBody["clear_reason"]>[] = [
  ...(KIT_CLEAR_REASONS as readonly NonNullable<ViolationBody["clear_reason"]>[]),
  "reconfigured",
];

/** A violation as the console keeps it: the kit's alert, with the members the panel shows. */
export interface AdaptedViolation {
  alert: AlertInput;
  /** The clear reason as sent; `reconfigured` has no kit word and is kept here. */
  clearReason: ViolationBody["clear_reason"];
  serial: string | null;
  /** The public part of the registration number only, as sent (G-04). */
  operatorReg: string | null;
  zoneId: string | null;
  peak: ViolationBody["peak"];
}

/**
 * A `violation/v1` frame as the kit's AlertInput, or null when it breaks
 * schemas/violation/v1.json's required members. `detail` is passed as
 * detect gave it; nothing is computed from it.
 */
export function adaptViolation(frame: ConsoleFrame): AdaptedViolation | null {
  if (frame.schema !== VIOLATION_SCHEMA) return null;
  const b = frame.body;
  if (!isObj(b)) return null;
  const { violation_id, kind, state, severity, track_ref, captured_at, opened_at, policy_version, detail } = b;
  if (!isNonEmpty(violation_id) || !isNonEmpty(track_ref)) return null;
  if (!VIOLATION_KINDS.includes(kind as ViolationBody["kind"])) return null;
  if (!VIOLATION_STATES.includes(state as ViolationBody["state"])) return null;
  if (!isSeverity(severity) || !isStr(captured_at) || !isStr(opened_at)) return null;
  if (!(isNum(policy_version) && Number.isInteger(policy_version) && policy_version >= 0)) return null;
  if (!isObj(detail)) return null;
  const cr = b["clear_reason"];
  if (cr !== null && !WIRE_CLEAR_REASONS.includes(cr as NonNullable<ViolationBody["clear_reason"]>)) return null;
  // Set exactly when cleared (schemas/violation/v1.json).
  if ((state === "cleared") !== (cr !== null)) return null;
  const serial = strOrNull(b["serial"]);
  const operatorReg = strOrNull(b["operator_reg"]);
  const zoneId = strOrNull(b["zone_id"]);
  if (serial === undefined || operatorReg === undefined || zoneId === undefined) return null;
  const peakRaw = b["peak"];
  const peak =
    peakRaw === null ? null : isObj(peakRaw) && isStr(peakRaw["name"]) && isNum(peakRaw["value"]) ? { name: peakRaw["name"], value: peakRaw["value"] } : undefined;
  if (peak === undefined) return null;
  const clearReason = cr as ViolationBody["clear_reason"];
  return {
    alert: {
      alertId: violation_id,
      kind: kind as ViolationKind | AlertKind,
      severity,
      state: state as ViolationBody["state"],
      clearReason: clearReason !== null && (KIT_CLEAR_REASONS as readonly string[]).includes(clearReason) ? (clearReason as ClearReason) : null,
      aircraft: [track_ref],
      peerTrackId: null,
      detail,
      capturedAt: captured_at,
      raisedAt: opened_at,
      policyVersion: String(policy_version),
    },
    clearReason,
    serial: serial ?? null,
    operatorReg: operatorReg ?? null,
    zoneId: zoneId ?? null,
    peak,
  };
}
