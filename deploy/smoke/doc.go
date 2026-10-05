// Package smoke is the staging smoke's test driver (WP-24): a test that
// runs against a deployed stack (deploy/compose.yaml behind the edge
// Caddy and deploy/caddy/authority.snippet), never against processes it
// starts itself. deploy/smoke/run.sh brings the stack up the way
// deploy/deploy.sh deploys it and then runs
//
//	STAGING_SMOKE=1 go test -count=1 -run TestStagingSmoke -v ./deploy/smoke
//
// Through the public host only, as a console, a machine client and a
// receiver would reach it, the test:
//
//   - signs the bootstrap admin in (password, then TOTP; the enrolment
//     secret of the first sign-in is kept in the state directory so a
//     second run signs in again) and creates a registrar;
//   - registers the lab's registry fixture (deploy/fixtures/operator.json:
//     the operator uspace-lab's REG-NOPII asks about, its UAS), or finds
//     it registered;
//   - reads the operator's personal data with a purpose (it is there),
//     then asks GET /v1/registry/validate with an ecosystem token and
//     finds none of it in the answer, which is status only (REG-NOPII,
//     E-01: the absence beside the presence);
//   - registers a receiver and posts signed ODID frames of the fixture's
//     aircraft until rid-ingest accepts a batch (202);
//   - opens the picture WebSocket with the session cookie and the
//     public Origin and reads the status and snapshot frames, then a
//     frame that carries the aircraft's track.
//
// It writes what the lab needs to the state directory (fixture.json: the
// registration number and serial) and logs it. Nothing secret is logged.
//
// Without STAGING_SMOKE=1 the test skips; CI runs it with the variable
// set and fails on a skip.
package smoke
