-- WP-2: the ecosystem token service's registry (docs/PLAN.md §4.1,
-- WP-2 normative tables A and B).
--
-- oauth_clients holds one client per calling system (M24): authority-01,
-- cisp-01, ansp-01, ussp-<code>-01, lab-01. scopes is the client's
-- allow-list, a subset of the scope catalogue (internal/tokens checks it
-- on every write and every token request); audiences are the hosts the
-- client may name for national scopes (standard utm.* and rid.* scopes
-- take any host, M18). A client authenticates with client_secret_post
-- (secret_hash, an argon2id PHC string; the secret is shown once) or
-- private_key_jwt (jwks, the client's public key set). certificate_id
-- links a USSP's client to its certificate (WP-16 adds the foreign key
-- when certificates exists).
--
-- signing_keys lists the RS256 keys of the issuer (purpose token) by
-- kid, the RFC 7638 thumbprint. The private key is never stored here:
-- private_ref names the PEM file (SIGNING_KEY_FILES) or a KMS reference,
-- and public_jwk is what the JWKS publishes. One token key is active (a
-- partial unique index); a retired key stays in the JWKS until
-- retired_at plus the JWKS cache TTL (24 h by default, config). A key
-- never activated is a candidate for the next rotation; requested_by and
-- requested_at hold the first admin's half of the two-person rule.

-- +goose Up
CREATE TABLE oauth_clients (
    client_id      text        PRIMARY KEY
                   CHECK (client_id ~ '^((authority|cisp|ansp|lab)-[0-9]{2}|ussp-[A-Z0-9]{1,8}-[0-9]{2})$'),
    system         text        NOT NULL CHECK (system IN ('authority', 'cisp', 'ansp', 'ussp', 'lab')),
    scopes         text[]      NOT NULL CHECK (cardinality(scopes) > 0),
    audiences      text[]      NOT NULL DEFAULT '{}',
    auth_method    text        NOT NULL CHECK (auth_method IN ('client_secret_post', 'private_key_jwt')),
    secret_hash    text,
    jwks           jsonb,
    mtls_subject   text,
    certificate_id text,
    status         text        NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'revoked')),
    note           text        NOT NULL DEFAULT '',
    created_at     timestamptz NOT NULL,
    created_by     text        NOT NULL,
    updated_at     timestamptz NOT NULL,
    updated_by     text        NOT NULL,
    CONSTRAINT oauth_clients_system_matches_id CHECK (split_part(client_id, '-', 1) = system),
    CONSTRAINT oauth_clients_credential CHECK (
        (auth_method = 'client_secret_post' AND secret_hash IS NOT NULL AND jwks IS NULL) OR
        (auth_method = 'private_key_jwt' AND jwks IS NOT NULL AND secret_hash IS NULL)
    )
);

CREATE TABLE signing_keys (
    kid          text        PRIMARY KEY CHECK (kid ~ '^[A-Za-z0-9_-]{16,128}$'),
    purpose      text        NOT NULL CHECK (purpose IN ('token', 'publication')),
    public_jwk   jsonb       NOT NULL,
    private_ref  text        NOT NULL CHECK (private_ref <> ''),
    registered_at timestamptz NOT NULL,
    active_from  timestamptz,
    retired_at   timestamptz,
    requested_by text,
    requested_at timestamptz,
    CONSTRAINT signing_keys_retired_after_active CHECK (retired_at IS NULL OR active_from IS NOT NULL),
    CONSTRAINT signing_keys_request_pair CHECK ((requested_by IS NULL) = (requested_at IS NULL))
);

CREATE UNIQUE INDEX signing_keys_one_active ON signing_keys (purpose)
    WHERE active_from IS NOT NULL AND retired_at IS NULL;

GRANT SELECT, INSERT, UPDATE ON oauth_clients TO authority_app;
GRANT SELECT, INSERT ON signing_keys TO authority_app;
GRANT UPDATE (active_from, retired_at, requested_by, requested_at, private_ref) ON signing_keys TO authority_app;

-- +goose Down
DROP TABLE IF EXISTS signing_keys;
DROP TABLE IF EXISTS oauth_clients;
