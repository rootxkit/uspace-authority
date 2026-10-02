// Package switches is api's writer of source control (U-15; WP-10):
// Service.Switch and the routes /v1/sources* (admin), the periodic
// republish that repairs a lost bucket, and the overview the console
// reads. It links the relational store, so only api imports it; every
// process follows the state through internal/sources.
//
// A switch is one transaction under the advisory lock source_controls:
// the row with the next version from source_control_version_seq, its
// events row, then the KV write of the whole state. When the bucket
// cannot take it the transaction rolls back and the API answers 503
// source_control_unavailable: there is no state in which a switch is
// recorded but not on its way (B-09). If the commit fails after the
// write, the database's state is republished over it before the call
// returns. After the commit the state is pushed on ctl.sources.
//
// Republish writes the database's state when the bucket does not hold
// it, at start and every SOURCE_CONTROL_REPUBLISH_S. A bucket ahead of
// the database within the same epoch (a restored database) starts a new
// epoch, audited, so followers take the database's state.
package switches
