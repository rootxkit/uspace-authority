-- WP-2: console accounts, their credentials and MFA, sign-in
-- challenges and sessions (docs/PLAN.md §4.1 and §7, spec 06 §3, M20).
--
-- users holds the account: a lower-case username, the console roles,
-- the realm (console, or police for WP-19, which adds the agency and the
-- IP allow-list columns' use), and the status. user_credentials holds
-- the argon2id PHC string of the password; user_mfa the TOTP secret
-- sealed with the PII key (key_id beside it, internal/pii), the last
-- TOTP time step accepted (a code is used once), the hashes of the
-- recovery codes, and enrolled_at (NULL while enrolment is pending).
-- login_challenges are the short, single-use MFA challenges between the
-- password step and the TOTP step, stored by the SHA-256 of the token.
-- sessions are the console sessions by jti (= the session JWT's jti), so
-- logout and revocation work and idle expiry is enforced; the expiry job
-- deletes rows a day after they expired (E-10).

-- +goose Up
CREATE TABLE users (
    id           text        PRIMARY KEY CHECK (id ~ '^[0-9a-f]{32}$'),
    username     text        NOT NULL UNIQUE CHECK (username ~ '^[a-z0-9][a-z0-9._@-]{2,63}$'),
    display_name text        NOT NULL DEFAULT '',
    roles        text[]      NOT NULL DEFAULT '{}'
                 CHECK (roles <@ ARRAY['viewer', 'inspector', 'registrar', 'incident_officer', 'admin', 'auditor']::text[]),
    realm        text        NOT NULL CHECK (realm IN ('console', 'police')),
    agency       text,
    ip_allow     text[]      NOT NULL DEFAULT '{}',
    status       text        NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at   timestamptz NOT NULL,
    created_by   text        NOT NULL,
    updated_at   timestamptz NOT NULL,
    updated_by   text        NOT NULL
);

CREATE TABLE user_credentials (
    user_id       text        PRIMARY KEY REFERENCES users (id),
    password_hash text        NOT NULL CHECK (password_hash LIKE '$argon2id$%'),
    updated_at    timestamptz NOT NULL
);

CREATE TABLE user_mfa (
    user_id         text        PRIMARY KEY REFERENCES users (id),
    key_id          text        NOT NULL,
    secret_enc      bytea       NOT NULL,
    enrolled_at     timestamptz,
    last_step       bigint      NOT NULL DEFAULT 0,
    recovery_hashes text[]      NOT NULL DEFAULT '{}',
    updated_at      timestamptz NOT NULL
);

CREATE TABLE login_challenges (
    token_hash text        PRIMARY KEY CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    user_id    text        NOT NULL REFERENCES users (id),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    attempts   integer     NOT NULL DEFAULT 0,
    used_at    timestamptz,
    remote_ip  text        NOT NULL DEFAULT ''
);

CREATE INDEX login_challenges_expires_idx ON login_challenges (expires_at);

CREATE TABLE sessions (
    jti           text        PRIMARY KEY CHECK (jti ~ '^[0-9a-f]{32}$'),
    user_id       text        NOT NULL REFERENCES users (id),
    realm         text        NOT NULL CHECK (realm IN ('console', 'police')),
    roles         text[]      NOT NULL,
    issued_at     timestamptz NOT NULL,
    expires_at    timestamptz NOT NULL,
    last_seen_at  timestamptz NOT NULL,
    revoked_at    timestamptz,
    revoked_by    text,
    revoke_reason text,
    remote_ip     text        NOT NULL DEFAULT '',
    user_agent    text        NOT NULL DEFAULT '',
    CONSTRAINT sessions_expiry CHECK (expires_at > issued_at),
    CONSTRAINT sessions_revocation CHECK ((revoked_at IS NULL) = (revoke_reason IS NULL))
);

CREATE INDEX sessions_user_live_idx ON sessions (user_id, issued_at) WHERE revoked_at IS NULL;
CREATE INDEX sessions_expires_idx ON sessions (expires_at);

GRANT SELECT, INSERT, UPDATE ON users, user_credentials, user_mfa, login_challenges, sessions TO authority_app;
GRANT DELETE ON user_mfa, login_challenges, sessions TO authority_app;

-- +goose Down
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS login_challenges;
DROP TABLE IF EXISTS user_mfa;
DROP TABLE IF EXISTS user_credentials;
DROP TABLE IF EXISTS users;
