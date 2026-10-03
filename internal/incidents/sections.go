package incidents

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/pg/gen"
	"github.com/rootxkit/uspace-authority/internal/store/ts/gen/reader"
)

// bbox is the extent of the evidence's positions (WGS84 degrees).
type bbox struct {
	set                            bool
	minLat, minLon, maxLat, maxLon float64
}

func (b *bbox) add(lat, lon float64) {
	if math.IsNaN(lat) || math.IsNaN(lon) || lat < -90 || lat > 90 || lon < -180 || lon > 180 {
		return
	}
	if !b.set {
		*b = bbox{set: true, minLat: lat, maxLat: lat, minLon: lon, maxLon: lon}
		return
	}
	b.minLat, b.maxLat = math.Min(b.minLat, lat), math.Max(b.maxLat, lat)
	b.minLon, b.maxLon = math.Min(b.minLon, lon), math.Max(b.maxLon, lon)
}

func (st *build) public(p *string) *string {
	if p == nil || st.b.PublicPart == nil {
		return p
	}
	v := st.b.PublicPart(*p)
	return &v
}

func (st *build) telemetryUnavailable(why string) {
	for _, s := range []string{SecTracks, SecFrames, SecWriterGaps, SecUSSPFlights} {
		st.section(s, Section{State: StateUnavailable, Basis: BasisObserved, Reason: why})
	}
}

// telemetry reads the tracks, the raw frames, the recorded gaps and the
// Display Provider's rows, and cuts every track into segments.
func (st *build) telemetry() error {
	t := st.b.Telemetry
	if t == nil {
		st.telemetryUnavailable("the telemetry database is not configured for evidence (TS_URL)")
		return nil
	}
	ctx, from, to, maxRows := st.ctx, st.in.From, st.in.To, st.b.MaxRows
	lim := int32(maxRows + 1)
	var tracksErr error
	if len(st.serials) > 0 {
		ids, err := t.EvidenceTrackIDs(ctx, reader.EvidenceTrackIDsParams{FromTs: from, ToTs: to, Serials: st.serials, RowLimit: lim})
		switch {
		case err != nil:
			tracksErr = err
		case len(ids) > maxRows:
			return tooLarge(SecTracks, maxRows)
		default:
			st.tracks = addUnique(st.tracks, ids...)
		}
	}
	sort.Strings(st.tracks)

	gaps, gapsErr := t.EvidenceWriterGaps(ctx, reader.EvidenceWriterGapsParams{FromTs: from, ToTs: to, RowLimit: lim})
	if gapsErr == nil && len(gaps) > maxRows {
		return tooLarge(SecWriterGaps, maxRows)
	}
	var frames []reader.EvidenceFramesRow
	var framesErr error
	if len(st.serials) > 0 {
		var txs []string
		txs, framesErr = t.EvidenceTransmitters(ctx, reader.EvidenceTransmittersParams{FromTs: from, ToTs: to, Serials: st.serials, RowLimit: lim})
		if framesErr == nil && len(txs) > maxRows {
			return tooLarge(SecFrames, maxRows)
		}
		if framesErr == nil && len(txs) > 0 {
			frames, framesErr = t.EvidenceFrames(ctx, reader.EvidenceFramesParams{FromTs: from, ToTs: to, Transmitters: txs, RowLimit: lim})
			if framesErr == nil && len(frames) > maxRows {
				return tooLarge(SecFrames, maxRows)
			}
		}
	}
	if tracksErr == nil && len(st.tracks) > 0 {
		st.trackRows, tracksErr = t.EvidenceTracks(ctx, reader.EvidenceTracksParams{FromTs: from, ToTs: to, TrackIds: st.tracks, RowLimit: lim})
		if tracksErr == nil && len(st.trackRows) > maxRows {
			return tooLarge(SecTracks, maxRows)
		}
	}
	var usspErr error
	if len(st.tracks) > 0 {
		st.usspRows, usspErr = t.EvidenceUSSPFlights(ctx, reader.EvidenceUSSPFlightsParams{FromTs: from, ToTs: to, TrackIds: st.tracks, RowLimit: lim})
		if usspErr == nil && len(st.usspRows) > maxRows {
			return tooLarge(SecUSSPFlights, maxRows)
		}
	}

	if err := st.writerGaps(gaps, gapsErr); err != nil {
		return err
	}
	if err := st.frames(frames, framesErr); err != nil {
		return err
	}
	if err := st.trackFiles(tracksErr, gaps, frames); err != nil {
		return err
	}
	return st.usspFlights(usspErr)
}

func gapDetail(g *reader.EvidenceWriterGapsRow) string {
	d := fmt.Sprintf("%s %s at %s: %d %s (stream %s, seq %d-%d)", g.TableName, g.Cause, stamp(g.At), g.Count, g.CountUnit,
		g.Stream, g.FromSeq, g.ToSeq)
	if g.Detail != nil && *g.Detail != "" {
		d += ": " + *g.Detail
	}
	return d
}

func (st *build) writerGaps(gaps []reader.EvidenceWriterGapsRow, err error) error {
	if err != nil {
		st.section(SecWriterGaps, Section{State: StateUnavailable, Basis: BasisRecorded, Reason: "the recorded gaps cannot be read: " + reason(err)})
		return nil
	}
	if len(gaps) == 0 {
		st.section(SecWriterGaps, Section{State: StateNone, Basis: BasisRecorded, Reason: "no gap of the tracks or frames table recorded in the window"})
		return nil
	}
	out := make([]map[string]any, 0, len(gaps))
	for i := range gaps {
		g := &gaps[i]
		out = append(out, map[string]any{"dedupe_key": g.DedupeKey, "table": g.TableName, "stream": g.Stream, "from_seq": g.FromSeq,
			"to_seq": g.ToSeq, "cause": g.Cause, "count": g.Count, "count_unit": g.CountUnit, "at": stamp(g.At),
			"receiver_id": g.ReceiverID, "detail": g.Detail})
	}
	st.section(SecWriterGaps, Section{State: StateIncluded, Basis: BasisRecorded, Count: len(gaps), Files: []string{"writer_gaps.json"}})
	return st.add("writer_gaps.json", out)
}

func (st *build) frames(frames []reader.EvidenceFramesRow, err error) error {
	switch {
	case err != nil:
		st.section(SecFrames, Section{State: StateUnavailable, Basis: BasisObserved, Reason: "the raw frames cannot be read: " + reason(err)})
		return nil
	case len(st.serials) == 0:
		st.section(SecFrames, Section{State: StateNone, Basis: BasisObserved, Reason: "no serial known: frames are found by the transmitters that broadcast one"})
		return nil
	case len(frames) == 0:
		st.section(SecFrames, Section{State: StateNone, Basis: BasisObserved, Reason: "no frame of the aircraft's transmitters in the window"})
		return nil
	}
	out := make([]map[string]any, 0, len(frames))
	for i := range frames {
		f := &frames[i]
		row := map[string]any{"ingest_ts": stamp(f.IngestTs), "frame_id": f.FrameID, "receiver_id": f.ReceiverID,
			"transmitter": f.Transmitter, "receiver_ts": stampPtr(f.ReceiverTs), "msg_type": f.MsgType,
			"payload_sha256": hex.EncodeToString(f.PayloadSha256), "rssi_dbm": f.RssiDbm, "backlog": f.Backlog,
			"serial": f.Serial, "operator_reg": st.public(f.OperatorReg), "lat_deg": f.LatDeg, "lon_deg": f.LonDeg,
			"captured_at": stampPtr(f.CapturedAt), "time_source": f.TimeSource, "decode_error": f.DecodeError}
		if st.in.Kind == KindLegal || (f.MsgType != nil && f.DecodeError == nil && slices.Contains(payloadTypes, *f.MsgType)) {
			row["payload_b64"] = base64.StdEncoding.EncodeToString(f.Payload)
		} else {
			row["payload_b64"] = nil
			row["payload_withheld"] = "may carry the remote pilot position or free text (06 §2 T6); kept by payload_sha256"
			st.m.FramesWithheld++
		}
		if f.LatDeg != nil && f.LonDeg != nil {
			st.box.add(*f.LatDeg, *f.LonDeg)
		}
		out = append(out, row)
	}
	st.section(SecFrames, Section{State: StateIncluded, Basis: BasisObserved, Count: len(frames), Files: []string{"raw_frames.json"}})
	return st.add("raw_frames.json", out)
}

func sampleOf(r *reader.EvidenceTracksRow, public func(*string) *string) map[string]any {
	return map[string]any{
		"captured_at": stamp(r.CapturedAt), "msg_id": r.MsgID, "ts": stampPtr(r.Ts), "rx_ts": stamp(r.RxTs), "time_source": r.TimeSource,
		"backlog": r.Backlog, "source": r.Source, "source_instance": r.SourceInstance, "trust": r.Trust, "lat_deg": r.LatDeg,
		"lon_deg": r.LonDeg, "alt_wgs84_m": r.AltWgs84M, "alt_amsl_m": r.AltAmslM, "alt_source": r.AltSource,
		"alt_pressure_m": r.AltPressureM, "height_m": r.HeightM, "height_ref": r.HeightRef, "speed_ms": r.SpeedMs,
		"track_deg": r.TrackDeg, "vspeed_ms": r.VspeedMs, "accuracy_h_m": r.AccuracyHM, "accuracy_v_m": r.AccuracyVM,
		"status": r.Status, "emergency": r.Emergency, "airborne": r.Airborne,
		"identification": map[string]any{"status": r.IdentStatus, "reason": r.IdentReason, "mismatch": r.IdentMismatch,
			"basis": r.IdentBasis, "serial": r.Serial, "operator_reg": public(r.OperatorReg),
			"registered_operator_reg": public(r.RegisteredOperatorReg), "registry_uas_id": r.RegistryUasID},
		"flight_id": r.FlightID, "ussp_id": r.UsspID, "cell5": r.Cell5, "identity_receiver": r.IdentityReceiver,
	}
}

// positionless are the points of the frames of transmitters without a
// position: Location frames whose position is unknown and frames that
// could not be decoded, placed at captured_at when known.
func positionless(frames []reader.EvidenceFramesRow, transmitters []string) []Point {
	var out []Point
	for i := range frames {
		f := &frames[i]
		if !slices.Contains(transmitters, f.Transmitter) {
			continue
		}
		at := f.IngestTs
		if f.CapturedAt != nil {
			at = *f.CapturedAt
		}
		switch {
		case f.DecodeError != nil:
			out = append(out, Point{At: at, Cause: CauseUndecodable, Index: -1})
		case f.MsgType != nil && *f.MsgType == odidLocation && (f.LatDeg == nil || f.LonDeg == nil):
			out = append(out, Point{At: at, Cause: CauseNoPosition, Index: -1})
		}
	}
	return out
}

func (st *build) trackFiles(err error, gaps []reader.EvidenceWriterGapsRow, frames []reader.EvidenceFramesRow) error {
	switch {
	case err != nil:
		st.section(SecTracks, Section{State: StateUnavailable, Basis: BasisObserved, Reason: "the tracks cannot be read: " + reason(err)})
		return nil
	case len(st.trackRows) == 0:
		st.section(SecTracks, Section{State: StateNone, Basis: BasisObserved, Reason: "no sample of the aircraft's tracks in the window"})
		return nil
	}
	recorded := make([]RecordedGap, 0, len(gaps))
	for i := range gaps {
		recorded = append(recorded, RecordedGap{At: gaps[i].At, Detail: gapDetail(&gaps[i])})
	}
	// serial -> transmitters that broadcast it in the window.
	bySerial := map[string][]string{}
	for i := range frames {
		if s := frames[i].Serial; s != nil {
			bySerial[*s] = addUnique(bySerial[*s], frames[i].Transmitter)
		}
	}
	maxGap := time.Duration(st.m.Segmenting.MaxGapS * float64(time.Second))
	var files []string
	samples := 0
	for start := 0; start < len(st.trackRows); {
		id := st.trackRows[start].TrackID
		end := start
		var txs []string
		var points []Point
		for end < len(st.trackRows) && st.trackRows[end].TrackID == id {
			r := &st.trackRows[end]
			points = append(points, Point{At: r.CapturedAt, Positioned: true, Index: end})
			if r.Serial != nil {
				txs = addUnique(txs, bySerial[*r.Serial]...)
			}
			st.box.add(r.LatDeg, r.LonDeg)
			end++
		}
		points = append(points, positionless(frames, txs)...)
		segs, holes := Cut(points, recorded, maxGap)
		outSegs := make([]map[string]any, 0, len(segs))
		for _, sg := range segs {
			ss := make([]map[string]any, 0, len(sg.Indexes))
			for _, ix := range sg.Indexes {
				ss = append(ss, sampleOf(&st.trackRows[ix], st.public))
			}
			outSegs = append(outSegs, map[string]any{"from": stamp(sg.From), "to": stamp(sg.To), "samples": ss})
		}
		outHoles := make([]map[string]any, 0, len(holes))
		for _, h := range holes {
			outHoles = append(outHoles, map[string]any{"from": stamp(h.From), "to": stamp(h.To), "duration_s": h.DurationS,
				"causes": h.Causes, "recorded": h.Recorded})
		}
		path := fmt.Sprintf("tracks/%04d.json", len(files)+1)
		if err := st.add(path, map[string]any{"track_id": id, "max_gap_s": st.m.Segmenting.MaxGapS, "segments": outSegs,
			"holes": outHoles, "transmitters": txs}); err != nil {
			return err
		}
		files = append(files, path)
		st.m.Tracks = append(st.m.Tracks, TrackSummary{TrackID: id, File: path, Samples: end - start, Segments: len(segs), Holes: len(holes)})
		samples += end - start
		start = end
	}
	st.section(SecTracks, Section{State: StateIncluded, Basis: BasisObserved, Count: samples, Files: files})
	return nil
}

func (st *build) usspFlights(err error) error {
	held := "the Display Provider keeps a USSP's flights 24 h (F3411); older ones are disposed of, and their record is the USSP's (02 F7)"
	switch {
	case err != nil:
		st.section(SecUSSPFlights, Section{State: StateUnavailable, Basis: BasisReceived, Reason: "the Display Provider rows cannot be read: " + reason(err)})
		return nil
	case len(st.usspRows) == 0:
		why := "no Display Provider row of the aircraft's tracks in the window"
		if oldest, oerr := st.b.Telemetry.EvidenceOldestUSSPFlight(st.ctx); oerr == nil && st.in.From.Before(oldest) {
			why += "; nothing older than " + stamp(oldest) + " is held: " + held
		}
		st.section(SecUSSPFlights, Section{State: StateNone, Basis: BasisReceived, Reason: why})
		return nil
	}
	out := make([]map[string]any, 0, len(st.usspRows))
	for i := range st.usspRows {
		r := &st.usspRows[i]
		row := map[string]any{"rx_ts": stamp(r.RxTs), "ussp_id": r.UsspID, "uss_base_url": r.UssBaseUrl, "isa_id": r.IsaID,
			"flight_id": r.FlightID, "track_id": r.TrackID, "state_ts": stamp(r.StateTs), "provider_unknown": r.ProviderUnknown,
			"flight": rawOrNull(r.Flight)}
		if st.in.Kind == KindLegal {
			row["details"] = rawOrNull(r.Details)
		} else if len(r.Details) > 0 {
			row["details"] = nil
			row["details_withheld"] = "may carry the remote pilot position (F3411 operator_location, 06 §2 T6)"
		}
		out = append(out, row)
	}
	st.section(SecUSSPFlights, Section{State: StateIncluded, Basis: BasisReceived, Count: len(out), Files: []string{"ussp_flights.json"},
		Reason: held})
	return st.add("ussp_flights.json", out)
}

type zoneKey struct {
	id      string
	version int64
}

// zones are the zone versions the violations name and the published
// versions in force in the window over the evidence's extent.
func (st *build) zones() error {
	wanted := map[zoneKey][]string{}
	var ids []string
	for i := range st.violationRows {
		v := &st.violationRows[i]
		if v.ZoneID != nil && v.ZoneVersion != nil {
			k := zoneKey{*v.ZoneID, *v.ZoneVersion}
			wanted[k] = append(wanted[k], v.ViolationID)
			ids = addUnique(ids, *v.ZoneID)
		}
		var excerpt []struct {
			Lat float64 `json:"lat"`
			Lng float64 `json:"lng"`
		}
		if json.Unmarshal(v.EvidenceExcerpt, &excerpt) == nil {
			for _, s := range excerpt {
				st.box.add(s.Lat, s.Lng)
			}
		}
	}
	if len(ids) == 0 && !st.box.set {
		st.section(SecZones, Section{State: StateNone, Basis: BasisRecorded, Reason: "no zone named and no position in the evidence"})
		return nil
	}
	lim := st.b.MaxZones
	type zone struct {
		row     gen.PackZoneVersionsRow
		named   []string
		inForce bool
	}
	found := map[zoneKey]*zone{}
	var problems []string
	if len(ids) > 0 {
		rows, err := st.b.Sources.PackZoneVersions(st.ctx, gen.PackZoneVersionsParams{ZoneIds: ids, Lim: int32(lim + 1)})
		switch {
		case err != nil:
			problems = append(problems, "the zones named cannot be read: "+reason(err))
		case len(rows) > lim:
			return tooLarge(SecZones, lim)
		default:
			for i := range rows {
				k := zoneKey{rows[i].Country + "/" + rows[i].Identifier, int64(rows[i].ZoneVersion)}
				if by, ok := wanted[k]; ok {
					found[k] = &zone{row: rows[i], named: by}
				}
			}
			for k := range wanted {
				if found[k] == nil {
					problems = append(problems, fmt.Sprintf("%s version %d is not in geo_zones (a dynamic restriction of the CIS or another dataset)", k.id, k.version))
				}
			}
		}
	}
	if st.box.set {
		rows, err := st.b.Sources.PackZonesInForce(st.ctx, gen.PackZonesInForceParams{WindowFrom: st.in.From, WindowTo: st.in.To,
			MinLon: st.box.minLon, MinLat: st.box.minLat, MaxLon: st.box.maxLon, MaxLat: st.box.maxLat, Lim: int32(lim + 1)})
		switch {
		case err != nil:
			problems = append(problems, "the zones in force cannot be read: "+reason(err))
		case len(rows) > lim:
			return tooLarge(SecZones, lim)
		default:
			for i := range rows {
				r := gen.PackZoneVersionsRow(rows[i])
				k := zoneKey{r.Country + "/" + r.Identifier, int64(r.ZoneVersion)}
				if z := found[k]; z != nil {
					z.inForce = true
				} else {
					found[k] = &zone{row: r, inForce: true}
				}
			}
		}
	}
	keys := make([]zoneKey, 0, len(found))
	for k := range found {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].id != keys[j].id {
			return keys[i].id < keys[j].id
		}
		return keys[i].version < keys[j].version
	})
	sort.Strings(problems)
	out := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		z := found[k]
		r := &z.row
		named := z.named
		if named == nil {
			named = []string{}
		}
		sort.Strings(named)
		out = append(out, map[string]any{"zone_id": k.id, "zone_version": k.version, "dataset": r.Dataset, "state": r.State,
			"type": r.Type, "valid_from": stamp(r.ValidFrom), "valid_to": stamp(r.ValidTo), "published_version": r.PublishedVersion,
			"published_at": stampPtr(r.PublishedAt), "approved_by": r.ApprovedBy, "approved_at": stampPtr(r.ApprovedAt),
			"named_by_violations": named, "in_force_over_the_evidence": z.inForce, "feature": rawOrNull(r.Feature)})
	}
	s := Section{Basis: BasisRecorded, Count: len(out), Reason: strings.Join(problems, "; ")}
	switch {
	case len(out) > 0:
		s.State, s.Files = StateIncluded, []string{"zones.json"}
	case len(problems) > 0:
		s.State = StateUnavailable
	default:
		s.State, s.Reason = StateNone, "no zone version in force over the evidence in the window"
	}
	st.section(SecZones, s)
	if len(out) == 0 {
		return nil
	}
	return st.add("zones.json", out)
}

func (st *build) policies() error {
	versions := []int64{st.m.Segmenting.PolicyVersion}
	for i := range st.violationRows {
		if !slices.Contains(versions, st.violationRows[i].PolicyVersion) {
			versions = append(versions, st.violationRows[i].PolicyVersion)
		}
	}
	slices.Sort(versions)
	rows, err := st.b.Sources.PackPolicies(st.ctx, versions)
	if err != nil {
		st.section(SecPolicies, Section{State: StateUnavailable, Basis: BasisRecorded, Reason: "the policy versions cannot be read: " + reason(err)})
		return nil
	}
	out := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		out = append(out, map[string]any{"version": r.Version, "active_at_build": r.Version == st.m.Segmenting.PolicyVersion,
			"policy": rawOrNull(r.Policy)})
	}
	st.section(SecPolicies, Section{State: StateIncluded, Basis: BasisRecorded, Count: len(out), Files: []string{"policies.json"}})
	return st.add("policies.json", out)
}

func (st *build) events() error {
	vids := make([]string, 0, len(st.violationRows))
	for i := range st.violationRows {
		vids = append(vids, st.violationRows[i].ViolationID)
	}
	id := st.in.Incident.Incident.IncidentID
	rows, err := st.b.Sources.PackEvents(st.ctx, gen.PackEventsParams{IncidentID: &id, ViolationIds: vids, Lim: int32(st.b.MaxRows + 1)})
	if err != nil {
		st.section(SecEvents, Section{State: StateUnavailable, Basis: BasisRecorded, Reason: "the audit log cannot be read: " + reason(err)})
		return nil
	}
	if len(rows) > st.b.MaxRows {
		return tooLarge(SecEvents, st.b.MaxRows)
	}
	out := make([]map[string]any, 0, len(rows))
	for i := range rows {
		e := &rows[i]
		out = append(out, map[string]any{"id": e.ID, "ts": stamp(e.Ts), "actor_type": e.ActorType, "actor_id": e.ActorID,
			"realm": e.Realm, "purpose": e.Purpose, "entity_type": e.EntityType, "entity_id": e.EntityID, "event_type": e.EventType,
			"payload": rawOrNull(e.Payload), "prev_hash": e.PrevHash, "hash": e.Hash})
	}
	st.section(SecEvents, Section{State: StateIncluded, Basis: BasisRecorded, Count: len(out), Files: []string{"events.json"},
		Reason: "the rows as chained (prev_hash, hash; T7); this pack's own build event follows them"})
	return st.add("events.json", out)
}

// ground names the ground dataset and spacing of every height above
// ground the pack holds (D-05): the peak of a violation judged in AGL,
// with the terrain source detect recorded at detection.
func (st *build) ground() error {
	if s, ok := st.m.Sections[SecViolations]; ok && s.State == StateUnavailable {
		st.section(SecGround, Section{State: StateUnavailable, Basis: BasisInferred, Reason: "the violations cannot be read"})
		return nil
	}
	for i := range st.violationRows {
		v := &st.violationRows[i]
		if v.PeakName == nil || v.PeakValue == nil || !strings.Contains(*v.PeakName, "agl") {
			continue
		}
		n := AGLNumber{ViolationID: v.ViolationID, Name: *v.PeakName, ValueM: *v.PeakValue}
		if len(v.TerrainSource) == 0 || string(v.TerrainSource) == "null" {
			n.State, n.Reason = StateUnavailable, "no ground dataset recorded at detection"
		} else {
			n.State, n.TerrainSource = StateIncluded, json.RawMessage(v.TerrainSource)
		}
		st.m.AGLNumbers = append(st.m.AGLNumbers, n)
	}
	if len(st.m.AGLNumbers) == 0 {
		st.section(SecGround, Section{State: StateNone, Basis: BasisInferred, Reason: "no height above ground in the pack"})
		return nil
	}
	st.section(SecGround, Section{State: StateIncluded, Basis: BasisInferred, Count: len(st.m.AGLNumbers),
		Reason: "agl_numbers lists each with the dataset and spacing it was taken from"})
	return nil
}

type flightRef struct{ ussp, flight string }

// records fetches the USSP's service record of every USSP flight of the
// pack on demand (02 F7, Q-A18); a record that cannot be had is
// unavailable with the reason, never silently missing.
func (st *build) records() error {
	var refs []flightRef
	seen := map[flightRef]bool{}
	addRef := func(u, f string) {
		r := flightRef{u, f}
		if u != "" && f != "" && !seen[r] {
			seen[r] = true
			refs = append(refs, r)
		}
	}
	for i := range st.trackRows {
		if r := &st.trackRows[i]; r.UsspID != nil && r.FlightID != nil {
			addRef(*r.UsspID, *r.FlightID)
		}
	}
	for i := range st.usspRows {
		addRef(st.usspRows[i].UsspID, st.usspRows[i].FlightID)
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].ussp != refs[j].ussp {
			return refs[i].ussp < refs[j].ussp
		}
		return refs[i].flight < refs[j].flight
	})
	if len(refs) == 0 {
		st.section(SecUSSPRecords, Section{State: StateNone, Basis: BasisReceived, Reason: "no aircraft of the pack was seen through a USSP"})
		return nil
	}
	var bases map[string]string
	listWhy := ""
	if st.b.Records == nil {
		listWhy = ErrNoRecordsClient.Error()
	} else {
		row, err := st.b.Sources.PackUSSPList(st.ctx)
		switch {
		case store.IsNoRows(err):
			listWhy = "the CIS USSP list was never received (no base_url known)"
		case err != nil:
			listWhy = "the CIS USSP list cannot be read: " + reason(err)
		default:
			if bases, err = ParseUSSPList(row.Payload); err != nil {
				listWhy = "the CIS USSP list does not parse: " + reason(err)
			}
		}
	}
	included := 0
	var files []string
	for i, r := range refs {
		rs := RecordSummary{USSPID: r.ussp, FlightID: r.flight, State: StateUnavailable}
		base, known := bases[r.ussp]
		switch {
		case listWhy != "":
			rs.Reason = listWhy
		case i >= st.b.MaxRecords:
			rs.Reason = fmt.Sprintf("past the bound of %d records per pack: build a narrower pack", st.b.MaxRecords)
		case !known:
			rs.Reason = "the USSP is not in the CIS USSP list"
		default:
			body, err := st.b.Records.Fetch(st.ctx, base, r.flight)
			if err != nil {
				rs.Reason = reason(err)
				break
			}
			rs.SHA256 = ContentHash(body)
			if st.in.Kind != KindLegal {
				rs.State = StateWithheld
				rs.Reason = "the record's shape is fixed by no contract this system pins and may carry personal data; kept by hash in an oversight pack"
				break
			}
			path := fmt.Sprintf("ussp_records/%02d.json", len(files)+1)
			if err := st.add(path, map[string]any{"ussp_id": r.ussp, "flight_id": r.flight, "base_url": base, "record": body}); err != nil {
				return err
			}
			rs.State, rs.File = StateIncluded, path
			files = append(files, path)
			included++
		}
		st.m.USSPRecords = append(st.m.USSPRecords, rs)
	}
	s := Section{Basis: BasisReceived, Count: included, Files: files}
	switch {
	case included > 0:
		s.State = StateIncluded
	case allWithheld(st.m.USSPRecords):
		s.State, s.Reason = StateWithheld, "every record fetched is withheld from an oversight pack (kept by hash)"
	default:
		s.State, s.Reason = StateUnavailable, "no record could be had; ussp_records says why for each"
	}
	st.section(SecUSSPRecords, s)
	return nil
}

func allWithheld(rs []RecordSummary) bool {
	for _, r := range rs {
		if r.State != StateWithheld {
			return false
		}
	}
	return len(rs) > 0
}

// registryPurpose is the purpose recorded by the registry for a legal
// pack's personal-data read: the pack, the case and the officer's
// purpose, at most 200 characters.
func registryPurpose(packID, caseRef, purpose string) string {
	s := "evidence pack " + packID + " (case " + caseRef + "): " + purpose
	if utf8.RuneCountInString(s) <= 200 {
		return s
	}
	r := []rune(s)
	return string(r[:200])
}

// personal resolves the operators' personal data for a legal pack; an
// oversight pack withholds it.
func (st *build) personal() error {
	if st.in.Kind != KindLegal {
		st.section(SecPersonalData, Section{State: StateWithheld, Basis: BasisRecorded, Reason: "an oversight pack carries no personal data (06 §2 T6)"})
		return nil
	}
	sort.Strings(st.regs)
	if len(st.regs) == 0 {
		st.section(SecPersonalData, Section{State: StateNone, Basis: BasisRecorded, Reason: "no operator registration known for the aircraft"})
		return nil
	}
	if st.b.Personal == nil {
		st.section(SecPersonalData, Section{State: StateUnavailable, Basis: BasisRecorded, Reason: "the registry is not wired for personal-data reads"})
		return nil
	}
	purpose := registryPurpose(st.in.PackID, st.in.CaseRef, st.in.Purpose)
	out := make([]map[string]any, 0, len(st.regs))
	included := 0
	for _, reg := range st.regs {
		row := map[string]any{"registration": reg}
		data, err := st.b.Personal.Operator(st.ctx, reg, purpose, st.in.Actor)
		if err != nil {
			row["state"], row["reason"] = StateUnavailable, reason(err)
		} else {
			row["state"], row["personal_data"] = StateIncluded, data
			included++
		}
		out = append(out, row)
	}
	s := Section{State: StateIncluded, Basis: BasisRecorded, Count: included, Files: []string{"personal_data/operators.json"},
		Reason: "each read recorded by the registry (registry_pii_viewed) with the pack, case and purpose"}
	if included == 0 {
		s.State = StateUnavailable
	}
	st.section(SecPersonalData, s)
	return st.add("personal_data/operators.json", out)
}
