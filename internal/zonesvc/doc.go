// Package zonesvc is the authority's geo-zones and U-space airspace
// designations (spec 01 A2, A3; 02 F1; 03 §1 geo_zones and
// uspace_airspaces; docs/PLAN.md §4.1, §4.2, §5): ED-318 authoring with
// versions, ED-318 and ED-269 import, export at an instant, the F1
// outbox row of a publication, and the zones projection the hot path
// judges with. Safety-relevant: a zone missing from the projection is a
// violation never raised. Every judgement is uspace-core's (ed318,
// ed269, zones, geodesy); this package holds adapters, persistence and
// workflow.
//
// Built by WP-5:
//
//   - Versions (migration 00012_geo_zones). One geo_zones row per
//     version of a zone or of a U-space airspace (dataset zones or
//     uspace_airspace); the master copy is `feature`, the ED-318 feature
//     exactly as ed318.Export wrote it after ed318.Parse accepted it
//     (never repaired, 06 T9); the query columns are derived from it in
//     the same statement (validate.go). A circle is its centre and
//     radius (Z-11); the polygon PostGIS draws for it is display_geom,
//     for maps only. Limits of a single-layer zone are in metres with
//     their reference; the original values and unit are in ed318_extra;
//     every layer is in `layers`. The period of validity (valid_from,
//     valid_to) is mandatory (2019/947 Art. 15(3)). A U-space version
//     also has its uspace_airspaces row (the 03 §1 designation); its
//     Art. 3(4) block is written by this package into the feature's
//     extendedProperties.uspace_requirements in the CISP's
//     cis/uspace_requirements/v1 shape (M7), so the block and the
//     designation can never disagree. An identifier belongs to one
//     dataset.
//   - Validation on every write: ed318.Parse; the dataset's type (USPACE
//     only under /v1/uspace); an identifier that is not a path segment
//     (export, import, publish); ed318.ToZones on the feature, so every
//     ring passes geodesy.ValidRing (5000 positions), every limit is
//     judgeable and the applicability is evaluable for the judgement's
//     view (Z-04, Z-06, Z-07; a daylight schedule needs its dates). Its
//     daylight times there are fixed hours (structuralDaylight) and its
//     zones are discarded: it runs the structural checks only. The WGS84
//     vertical reference is accepted and named in every answer as this
//     project's extension (Z-05).
//   - Workflow: draft, approved (designated), published, superseded. A
//     new version supersedes the identifier's unpublished ones; only
//     the newest draft is approved; publishing supersedes the older
//     published versions. Every act is an events row (zone_drafted,
//     zone_approved, zones_imported, zones_published, zones_exported,
//     uspace_drafted, uspace_designated, uspace_published).
//   - Import, all or nothing (Z-02): the format by its wrapper (Z-03);
//     ED-318 through ed318.Parse, ED-269 through ed269.Parse and
//     ed318.FromED269 (what ED-318 cannot hold refused by name), every
//     zone through the write checks, every problem by JSON path, at most
//     100 with `truncated`. Bounded by ed269.DefaultLimits (4 MiB, E-10).
//     The airspace.gov.ge converter (govge.go, Z-13) reads saved copies
//     of the site's points.js and page with the authority's rules file
//     and imports the ED-269 it makes.
//   - Publication (spec 02 F1): under LockProjection, in one relational
//     transaction, the approved versions become published under a new
//     zones_version_seq value, the full set in force now is exported
//     (ed318.Export, collection metadata in ed318.Metadata's names:
//     issued, provider) into the publications outbox row (pending,
//     signature NULL: WP-6 signs and sends it; migration
//     00013_publications is the minimal outbox WP-6 owns), and the
//     projection is rewritten before the relational commit: a failed
//     projection write rolls the publication back (503
//     projection_unavailable); a failed relational commit after it is
//     counted (zones_projection_ahead) and repaired at once. Then
//     zones.v1.changed and KV zones_version announce the version
//     (BusPublisher); a failed announcement is counted and the readers'
//     re-read catches up.
//   - Export (M17): the newest published version of each identifier in
//     force at the instant; `at` filters to what applies (ed318.Applies
//     at the centre of the feature's box) and keeps what cannot be
//     evaluated, annotated unknown; `applies_at` annotates every feature
//     (applies, not_applicable, unknown) and filters nothing.
//   - Daylight. Sunrise, sunset and civil twilight come from position
//     through ground.Daylight (core's ed318.NOAADaylight, WP-11). An
//     event the source cannot resolve (the sun does not reach it that
//     day) leaves the zone unknown with the reason. Without a source
//     (NoDaylight) the applicability preview answers 503
//     daylight_unavailable, an export annotates unknown, and a reader
//     names such a zone in zones_not_judged.
//   - Projection (migration 00009_zones_projection in the telemetry
//     tree): proj_zones holds every published version whose period has
//     not ended, written whole (upserted, every other row deleted) by
//     each publication and by Reproject at startup and every
//     ZONES_REPROJECT_S (300 s) under the job lock and LockProjection.
//     ProjectionReader loads the rows, keeps per identifier the newest
//     version in force, builds the zones.Index through ed318.Parse and
//     ed318.ToZones, refreshes on Notify (Follow subscribes to
//     zones.v1.changed) and every DefaultReaderRefresh (60 s), rebuilds
//     at every period boundary without a read, keeps the index it holds
//     when a read fails, and puts projection_age_s, zones_version, the
//     zones that need terrain or the geoid (Z-09) and every zone it
//     could not build on the status line. The error-level line and the
//     detector that uses the index are WP-12's.
//
// Spec gap recorded in the PR: ED-318 has no per-feature period of
// validity, so a publication carries the versions in force when it is
// made; a version whose period starts later reaches the CISP only with a
// later publication. The projection and the export hold every period.
package zonesvc
