-- WP-1: the application role and the append-only audit log `events`
-- (spec 03 §1, 06 §2 T7, docs/PLAN.md §4.1).
--
-- authority_app is the role api works as (PG_ROLE; the login user is
-- granted membership by the deployment). It is created NOLOGIN here when
-- it does not exist yet, so a deployment that provisions it beforehand
-- needs no CREATEROLE. Roles are cluster-wide: the Down never drops it.
--
-- events is partitioned by month on ts. The application role may SELECT
-- and INSERT and nothing else; a trigger refuses UPDATE and DELETE for
-- every role, the owner included. Each row carries prev_hash and hash:
-- hash = sha256(prev_hash || canonical JSON of the row without hash),
-- chained in id order within a month, the first row of a month linking
-- to the last row before it (internal/audit). Partitions are created on
-- demand by events_ensure_partition, which the writer calls under the
-- month's advisory lock.

-- +goose Up
-- +goose StatementBegin
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authority_app') THEN
    CREATE ROLE authority_app NOLOGIN;
  END IF;
EXCEPTION WHEN duplicate_object OR unique_violation THEN
  NULL; -- created concurrently by another database's migration
END
$$;
-- +goose StatementEnd

GRANT SELECT ON goose_db_version_relational TO authority_app;

CREATE TABLE events (
    id          bigserial   NOT NULL,
    ts          timestamptz NOT NULL,
    actor_type  text        NOT NULL CHECK (actor_type IN ('user', 'client', 'receiver', 'system')),
    actor_id    text        NOT NULL CHECK (actor_id <> ''),
    realm       text,
    purpose     text,
    entity_type text        NOT NULL CHECK (entity_type <> ''),
    entity_id   text,
    event_type  text        NOT NULL CHECK (event_type <> ''),
    payload     jsonb       NOT NULL DEFAULT '{}'::jsonb,
    prev_hash   text        NOT NULL CHECK (prev_hash ~ '^[0-9a-f]{64}$'),
    hash        text        NOT NULL CHECK (hash ~ '^[0-9a-f]{64}$'),
    PRIMARY KEY (id, ts)
) PARTITION BY RANGE (ts);

CREATE INDEX events_entity_idx ON events (entity_type, entity_id, ts);
CREATE INDEX events_actor_idx ON events (actor_id, ts);

-- +goose StatementBegin
CREATE FUNCTION events_refuse_change() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'events is append-only: % refused', TG_OP
    USING ERRCODE = 'insufficient_privilege';
END
$$;
-- +goose StatementEnd

CREATE TRIGGER events_append_only
    BEFORE UPDATE OR DELETE ON events
    FOR EACH ROW EXECUTE FUNCTION events_refuse_change();

-- events_ensure_partition creates the month partition holding at (UTC
-- months) when it is missing and returns its name. SECURITY DEFINER so
-- the application role, which may not create tables, can call it.
-- +goose StatementBegin
CREATE FUNCTION events_ensure_partition(at timestamptz) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
  month_start timestamptz := date_trunc('month', at AT TIME ZONE 'UTC') AT TIME ZONE 'UTC';
  month_end   timestamptz := (date_trunc('month', at AT TIME ZONE 'UTC') + interval '1 month') AT TIME ZONE 'UTC';
  part        text := 'events_' || to_char(at AT TIME ZONE 'UTC', 'YYYY_MM');
BEGIN
  IF to_regclass(part) IS NULL THEN
    EXECUTE format('CREATE TABLE %I PARTITION OF events FOR VALUES FROM (%L) TO (%L)',
                   part, month_start, month_end);
  END IF;
  RETURN part;
END
$$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION events_ensure_partition(timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION events_ensure_partition(timestamptz) TO authority_app;
GRANT SELECT, INSERT ON events TO authority_app;
GRANT USAGE ON SEQUENCE events_id_seq TO authority_app;

-- +goose Down
DROP TABLE IF EXISTS events CASCADE;
DROP FUNCTION IF EXISTS events_ensure_partition(timestamptz);
DROP FUNCTION IF EXISTS events_refuse_change();
REVOKE ALL ON goose_db_version_relational FROM authority_app;
