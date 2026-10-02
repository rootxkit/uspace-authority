// Package cell is the partition grid of this system (docs/PLAN.md D3,
// spec 05 §3 as amended by M35): a thin wrapper over uspace-core's
// geodesy/cell, which holds the grid, the names c5:<lat_idx>:<lon_idx>
// and c3:<lat_idx>:<lon_idx>, ring-1 neighbours, bbox → cell set and the
// antimeridian and pole handling, all judged and tested in core. No H3,
// no Partitioner interface (Q-A3). A cell is a key; it never crosses an
// external interface.
//
// What this package adds is local:
//
//   - Token, the subject-token form of a cell name: the name with each
//     ':' written '_' (c3_131_224), legal in a NATS subject and in a KV
//     key, which a ':' is not; ParseToken reads it back exactly.
//   - Viewport, the cells a console subscribes to: the c5 cover of its
//     bounding box plus a margin of one ring of neighbours, bounded
//     (E-10).
//   - The ownership map in KV bucket cells (key "ownership"): cell3 →
//     detect worker id, versioned, written only by api (PUT /v1/cells,
//     audited, internal/cell/assign) and rebalanced by an operator, not
//     by discovery (05 §3). Claim gives a worker its cells and refuses a
//     worker with none unless CELLS=all (the demo).
package cell
