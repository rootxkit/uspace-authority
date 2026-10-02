-- WP-2 review: the emergency retirement of a signing key. A key marked
-- compromised leaves the JWKS at once (no 24 h overlap), never signs and
-- is never a rotation candidate again; an active token key is replaced
-- by the next candidate in the same transaction.

-- +goose Up
ALTER TABLE signing_keys
    ADD COLUMN compromised_at    timestamptz,
    ADD COLUMN compromised_by    text,
    ADD COLUMN compromise_reason text,
    ADD CONSTRAINT signing_keys_compromise CHECK (
        (compromised_at IS NULL) = (compromised_by IS NULL) AND (compromised_at IS NULL) = (compromise_reason IS NULL)
    );

GRANT UPDATE (compromised_at, compromised_by, compromise_reason) ON signing_keys TO authority_app;

-- +goose Down
ALTER TABLE signing_keys
    DROP CONSTRAINT IF EXISTS signing_keys_compromise,
    DROP COLUMN IF EXISTS compromise_reason,
    DROP COLUMN IF EXISTS compromised_by,
    DROP COLUMN IF EXISTS compromised_at;
