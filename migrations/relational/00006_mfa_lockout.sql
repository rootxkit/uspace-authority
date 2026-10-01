-- WP-2 review: a per-account budget of MFA failures (NIST SP 800-63B
-- §5.2.2, rate limiting). Every wrong TOTP or recovery code counts
-- against the account, whatever challenge or address it came through;
-- from MFA_LOCKOUT_AFTER failures on the account is locked for a time
-- that doubles with each further failure up to MFA_LOCKOUT_MAX_S, and at
-- MFA_HARD_LOCK_AFTER (at most 100, the NIST bound) it stays locked
-- until an admin unlocks it. A success resets the count. The columns
-- live in the database so the budget holds across api replicas.

-- +goose Up
ALTER TABLE users
    ADD COLUMN mfa_failures     integer     NOT NULL DEFAULT 0 CHECK (mfa_failures >= 0),
    ADD COLUMN mfa_locked_until timestamptz,
    ADD COLUMN mfa_hard_locked  boolean     NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE users
    DROP COLUMN IF EXISTS mfa_hard_locked,
    DROP COLUMN IF EXISTS mfa_locked_until,
    DROP COLUMN IF EXISTS mfa_failures;
