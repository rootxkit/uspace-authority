# Cutover from the predecessor

WP-24, milestone A-M5. The order in which the predecessor's two hosts,
`utm.chikox.net` (console, API, replay) and `ingest.chikox.net` (the
relay-v1 and Remote ID ingest), are retired in favour of this system on
staging, what moves, how to roll back, and the A-M5 checklist. Staging
itself is `staging.md`.

Nothing here runs by itself: each step is done by the owner, by hand,
in this order, and its check is read before the next step starts.

## Before: the new system proved on its own

1. CI green on `main` at the commit to deploy, `staging-smoke` included;
   the `image`, `sbom` and `attest` jobs green for that commit.
2. `deploy/deploy.sh` run on the droplet with those digests; its
   verification output (every process: `/healthz`, `/readyz`, version,
   status line) pasted into the A-M5 record.
3. One night of `backup.sh` and `restore-check.sh` in the log, with
   non-zero counts.
4. The predecessor still serves; nothing has moved.

## What moves

| From the predecessor | To | How | Check |
|---|---|---|---|
| Operator and drone registry (`drones`, `pilots`, `uas_operators`) | the authority's registry | export from the predecessor as the uas.gov.ge-shaped CSV the WP-20 rules file maps, then `POST /v1/registry/import?kind=operators` and `?kind=uas`, each with `dry_run=true` first (`docs/runbooks/registry-import.md`) | the dry run reports no problem; after the import the counts by status equal the export's; a sample of registration numbers answers `valid` at `/v1/registry/validate` |
| Remote ID receivers | `/v1/rid/receivers` (the F9 contract) | each receiver registered anew (`POST /v1/rid/receivers`), its new bearer key and HMAC secret installed on the device by its owner; the predecessor's station tokens are not carried over | the receiver's batches are accepted (202) and it shows on `/v1/picture/sources`; rid-ingest's `/readyz` `receiver_keys` passes |
| Zones | `/v1/zones` | re-authored or imported as ED-318 (`POST /v1/zones/import`), approved and published through the CISP (`docs/runbooks/zones.md`) | the published version reads back from the CISP |
| Console users | `/v1/users` | created anew; each enrols TOTP at first sign-in. Passwords are not carried over | each user signs in |
| relay-v1 stations (MAVLink forwarded by QGC) | none in the authority | the authority takes no MAVLink; where operator telemetry goes is the USSP's service. The stations' owners are told the retirement date before step 3 below | owner's decision, recorded |
| Flight history and replay | none | the predecessor's record is kept, read-only, with its last backup (below); it is not imported | the last backup restores |

## Order

1. **Freeze the predecessor's registry.** Announce the date; from then
   on registry changes are made in the authority only.
2. **Move the registry, the zones and the users** (table above), and
   read each check.
3. **Re-key the receivers**, one at a time; each is accepted before the
   next is touched.
4. **Retire `ingest.chikox.net`**: stop the predecessor's gateway, take
   its last backup (`/var/backups/utm/<date>/`), remove its route from
   the droplet's Caddy. Check: the host answers no relay or Remote ID
   request; every receiver still posts to the authority.
5. **Retire `utm.chikox.net`**: stop the predecessor's console and API,
   take the final backup, remove the route (or point it at a page that
   names the new console). Check: the new console signs in and its
   picture shows the receivers' traffic.
6. **Keep the old stack stopped but intact for a week**: its containers
   stopped, not removed; its volumes, `.env` and backups kept. Remove it
   only after the week, and only after the A-M5 checklist below is
   complete.

## Rollback

Within the week, if the new system cannot carry the service:

1. Put the predecessor's Caddy routes back and start its stack
   (`docker compose -f docker-compose.prod.yml up -d` in its deploy
   directory; nothing was removed).
2. Give the receivers back their predecessor tokens (kept by their
   owners until the week ends).
3. Registry changes made in the authority since the freeze are exported
   from `/v1/registry/changes` and applied to the predecessor by hand;
   there is no automatic way back, which is why the freeze is announced.
4. Record why, and what has to change before the next attempt.

After the week, there is no rollback to the predecessor: the authority's
own backups (`staging.md`) are the way back.

## A-M5 checklist

- [ ] The console and public pages live on `uspace-ui` (WP-21, WP-22,
      WP-23), behind the droplet's Caddy with `deploy/caddy/authority.snippet`.
- [ ] Registry imported from the uas.gov.ge rules file (WP-20); the
      counts by status equal the export's.
- [ ] Retention and archive jobs running (WP-27): api's status line shows
      `retention_*` (pending GCAA) and `archive_store`; `/v1/audit/verify`
      reports no broken month.
- [ ] Staging deployed from GHCR images: signatures and SBOM attestations
      verified by `deploy/verify-image.sh`, `deploy/deploy.sh` output
      recorded.
- [ ] Backups nightly with the restore check's counts in the log.
- [ ] `utm.chikox.net` and `ingest.chikox.net` retired (steps 4, 5) and
      the old stack removed after the week (step 6).
