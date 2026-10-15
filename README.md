# uspace-authority

The competent authority's system (GCAA; branding is configuration) of
the Georgian U-space rebuild: registry of UAS operators, UAS and remote
pilots; geo-zones and U-space airspace designations, published through
the CISP; USSP and CISP certificates and the public register; the Remote
ID receiver network and the authority's own airspace picture (direct
Remote ID plus an ASTM F3411-22a Display Provider view of every USSP);
violations from the authority's own evidence (120 m, zone incursion,
unregistered, identification mismatch); incidents and hash-sealed
evidence packs; occurrence reports under Reg. (EU) 376/2014, segregated
from enforcement; the audit log of every oversight act; and the
ecosystem OAuth2 token issuer (RS256, JWKS).

It observes and records. It never commands an aircraft, never alerts a
pilot in real time and never authorises a flight: those belong to the
operator and to the USSP (spec `01 §1`).

## Status

Work packages WP-0 through WP-27 are built (the registry, zones and the
CISP client, Remote ID ingest and the picture feed, the violation
detectors, the Display Provider, manned ingest, certificates, incidents
and evidence packs, occurrence reports, the police realm, the
`uas.gov.ge` registry import, the console under `web/`, the
`no_authorisation` detector, retention and archive, the scenario harness
and the staging deployment); `CHANGELOG.md` has one line per package and
lists them under Unreleased, as nothing is tagged yet. `docs/PLAN.md` and
the briefs under `docs/WORKPACKAGES/` are the plan; milestones A-M1..A-M5
follow `uspace-lab/docs/spec/07-roadmap.md` phase 3. The runbooks are in
`docs/runbooks/`. Development setup:
[`docs/runbooks/dev-setup.md`](docs/runbooks/dev-setup.md).

Live demo: the staging host, named only in `deploy/staging/hosts.env`
(`AUTHORITY_HOST`).

## Layout

```
cmd/            api, rid-ingest, dp-poller, manned-ingest, detect, tsdb-writer, picture-ws
internal/       one domain layer shared by the processes
api/            openapi.yaml (the published national API, OpenAPI 3.1) and generated code
schemas/        JSON Schemas of the messages this system produces
migrations/     relational/ (PostgreSQL + PostGIS) and timeseries/ (TimescaleDB), never merged
web/            the console and public pages (Next.js on uspace-ui)
deploy/         compose, Caddy snippet, backups
docs/           plan, work packages, runbooks
```

## Links

- Plan and architecture: [`docs/PLAN.md`](docs/PLAN.md)
- Work packages: [`docs/WORKPACKAGES/`](docs/WORKPACKAGES/)
- Rules for contributors and agents: [`CLAUDE.md`](CLAUDE.md)
- System-of-systems spec: `rootxkit/uspace-lab` `docs/spec/`
- Shared judgement library: `rootxkit/uspace-core` (pinned by tag;
  every safety judgement lives there once)
- Shared UI kit: `rootxkit/uspace-ui`
- Siblings: `uspace-cisp`, `uspace-ussp`, `uspace-ansp`, `uspace-lab`

Go 1.27, no cgo. Module path `github.com/rootxkit/uspace-authority`.
