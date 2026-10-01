-- WP-2: the token service's client registry and signing keys.

-- name: OAuthClient :one
SELECT * FROM oauth_clients WHERE client_id = sqlc.arg(client_id);

-- name: ListOAuthClients :many
SELECT * FROM oauth_clients ORDER BY client_id;

-- name: InsertOAuthClient :one
INSERT INTO oauth_clients (
    client_id, system, scopes, audiences, auth_method, secret_hash, jwks,
    mtls_subject, certificate_id, status, note, created_at, created_by,
    updated_at, updated_by
) VALUES (
    sqlc.arg(client_id), sqlc.arg(system), sqlc.arg(scopes), sqlc.arg(audiences),
    sqlc.arg(auth_method), sqlc.narg(secret_hash), sqlc.narg(jwks),
    sqlc.narg(mtls_subject), sqlc.narg(certificate_id), sqlc.arg(status),
    sqlc.arg(note), sqlc.arg(created_at), sqlc.arg(created_by),
    sqlc.arg(created_at), sqlc.arg(created_by)
)
RETURNING *;

-- name: UpdateOAuthClient :one
UPDATE oauth_clients
SET scopes = sqlc.arg(scopes), audiences = sqlc.arg(audiences), status = sqlc.arg(status),
    note = sqlc.arg(note), updated_at = sqlc.arg(updated_at), updated_by = sqlc.arg(updated_by)
WHERE client_id = sqlc.arg(client_id)
RETURNING *;

-- name: SigningKeys :many
SELECT * FROM signing_keys ORDER BY registered_at, kid;

-- name: InsertSigningKey :exec
INSERT INTO signing_keys (kid, purpose, public_jwk, private_ref, registered_at)
VALUES (sqlc.arg(kid), sqlc.arg(purpose), sqlc.arg(public_jwk), sqlc.arg(private_ref), sqlc.arg(registered_at))
ON CONFLICT (kid) DO NOTHING;

-- name: SetSigningKeyRef :exec
UPDATE signing_keys SET private_ref = sqlc.arg(private_ref) WHERE kid = sqlc.arg(kid);

-- name: ActivateSigningKey :exec
UPDATE signing_keys
SET active_from = sqlc.arg(at), requested_by = NULL, requested_at = NULL
WHERE kid = sqlc.arg(kid) AND active_from IS NULL;

-- name: RetireSigningKey :exec
UPDATE signing_keys SET retired_at = sqlc.arg(at)
WHERE kid = sqlc.arg(kid) AND active_from IS NOT NULL AND retired_at IS NULL;

-- name: RequestKeyRotation :exec
UPDATE signing_keys SET requested_by = sqlc.arg(requested_by), requested_at = sqlc.arg(requested_at)
WHERE kid = sqlc.arg(kid) AND active_from IS NULL;
