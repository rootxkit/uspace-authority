// Package ground is the authority's terrain and geoid (WP-11): the DEM
// tiles and the geoid grid of the mounted ground volume, wired into
// uspace-core's terrain.Store and geoid.Grid, and what every caller needs
// to know about them.
//
// Nothing here judges. Elevation, undulation, cell naming, the bounded
// tile cache and the retry of a tile that could not be read are core's
// (terrain, geoid); the daylight events are core's ed318.NOAADaylight.
// This package resolves zones.Env for a position, hands the core
// interfaces to the Remote ID pipeline (geoid.Undulator, WP-8) and the
// detector (terrain.Ground, WP-12), and reports what is loaded.
//
// Semantics (LESSONS D-02, D-04, D-05, R-07, Z-09):
//
//   - No AGL value is stored anywhere; a height over the ground is AMSL
//     minus Env.GroundM, computed by zones at the moment it is judged.
//   - Ground is GroundKnown only with an elevation from a tile or a sea
//     cell. A cell absent from the index, a nodata sample, a tile that
//     cannot be read and an index that cannot be read are GroundUnknown,
//     never 0 m; without GROUND_DIR it is GroundNotConfigured. An AGL
//     limit is then not judged (limit_not_judged) and the height limit
//     is not evaluated, both counted by zones.
//   - UndulationM is nil without a usable geoid; the Remote ID pipeline
//     then has no AMSL altitude (HAE only) and nothing is guessed.
//   - Every elevation shown carries terrain.Attribution and its dataset
//     and spacing (D-05); StatusAttrs and Log say which datasets are
//     loaded and Problems lists what cannot be judged (Z-09).
//
// Configuration: GROUND_DIR (tiles <cell>.pgm and index.json in the lab's
// PGM container), GEOID_FILE (egm2008-2_5.pgm), GROUND_TILE_CACHE and
// GROUND_RETRY_AFTER_S; deploy/fetch-ground.sh fills the volume and
// docs/runbooks/ground.md is the operator's guide.
package ground
