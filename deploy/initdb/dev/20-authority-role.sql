-- Development stack only (deploy/compose.dev.yaml): the `authority`
-- login the development URLs and CI's PostGIS service use for the
-- relational database (DEV_PG_URL in the Makefile). A superuser, as
-- POSTGRES_USER is in the PostGIS image, because the migrations create
-- the PostGIS extension. A throwaway local value; staging logs in as
-- postgres with the generated password (deploy/gen-secrets.sh).
CREATE ROLE authority LOGIN SUPERUSER PASSWORD 'authority';
