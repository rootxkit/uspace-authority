-- WP-2 review: the ids of private_key_jwt client assertions, each
-- accepted once (RFC 7523 3 item 7) by every api replica: a per-process
-- memory let an assertion be replayed against another replica. A row
-- lives until the assertion expires plus the clock skew; every use
-- deletes the expired rows first, so the table holds at most the
-- assertions of the last few minutes (bounded by the per-client token
-- rate limit times the 5 min assertion lifetime, E-10).

-- +goose Up
CREATE TABLE assertion_jtis (
    client_id  text        NOT NULL REFERENCES oauth_clients (client_id),
    jti        text        NOT NULL CHECK (jti <> '' AND length(jti) <= 256),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (client_id, jti)
);

CREATE INDEX assertion_jtis_expires_idx ON assertion_jtis (expires_at);

GRANT SELECT, INSERT, DELETE ON assertion_jtis TO authority_app;

-- +goose Down
DROP TABLE IF EXISTS assertion_jtis;
