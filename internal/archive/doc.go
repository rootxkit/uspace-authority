// Package archive is the archive store of WP-27 (spec 05 §4, 06 §2 T7,
// 06 §5): where the telemetry chunks beyond their online window and the
// USSP daily records bundles go, and the removal of the remote pilot
// position from an archived Remote ID frame. It runs in api only;
// docs/runbooks/retention.md is the procedure.
//
// Store is written once per key (Create, then Commit; never an
// overwrite), read back to verify, and deleted only after the archive
// period. Open builds the store ARCHIVE_URL names: a local directory
// (file:///<absolute directory>); an S3-compatible store is not
// implemented, and any other scheme is refused at start rather than
// accepted and lost.
//
// RedactOperator re-encodes only the System message of an ODID frame or
// pack, through uspace-core's codec, with the operator position
// unknown, and checks the result decodes as the original without it; a
// frame it cannot check is Undecodable and the caller leaves its
// payload out of the archive (never a guess at offsets, LESSONS E-03).
package archive
