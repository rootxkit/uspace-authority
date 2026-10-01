-- WP-2: console accounts, MFA, sign-in challenges and sessions.

-- name: UserByID :one
SELECT * FROM users WHERE id = sqlc.arg(id);

-- name: UserByUsername :one
SELECT * FROM users WHERE username = sqlc.arg(username);

-- name: ListUsers :many
SELECT * FROM users ORDER BY username LIMIT sqlc.arg(page_size);

-- name: CountUsers :one
SELECT count(*)::bigint AS n FROM users;

-- name: CountActiveAdmins :one
SELECT count(*)::bigint AS n FROM users
WHERE status = 'active' AND realm = 'console' AND 'admin' = ANY (roles);

-- name: InsertUser :one
INSERT INTO users (id, username, display_name, roles, realm, status, created_at, created_by, updated_at, updated_by)
VALUES (sqlc.arg(id), sqlc.arg(username), sqlc.arg(display_name), sqlc.arg(roles), sqlc.arg(realm), 'active',
        sqlc.arg(created_at), sqlc.arg(created_by), sqlc.arg(created_at), sqlc.arg(created_by))
RETURNING *;

-- name: SetUserRoles :one
UPDATE users SET roles = sqlc.arg(roles), updated_at = sqlc.arg(updated_at), updated_by = sqlc.arg(updated_by)
WHERE id = sqlc.arg(id)
RETURNING *;

-- name: SetUserStatus :one
UPDATE users SET status = sqlc.arg(status), updated_at = sqlc.arg(updated_at), updated_by = sqlc.arg(updated_by)
WHERE id = sqlc.arg(id)
RETURNING *;

-- name: PasswordHash :one
SELECT password_hash FROM user_credentials WHERE user_id = sqlc.arg(user_id);

-- name: UpsertPassword :exec
INSERT INTO user_credentials (user_id, password_hash, updated_at)
VALUES (sqlc.arg(user_id), sqlc.arg(password_hash), sqlc.arg(updated_at))
ON CONFLICT (user_id) DO UPDATE SET password_hash = EXCLUDED.password_hash, updated_at = EXCLUDED.updated_at;

-- name: UserMFA :one
SELECT * FROM user_mfa WHERE user_id = sqlc.arg(user_id);

-- name: UpsertMFA :exec
INSERT INTO user_mfa (user_id, key_id, secret_enc, enrolled_at, last_step, recovery_hashes, updated_at)
VALUES (sqlc.arg(user_id), sqlc.arg(key_id), sqlc.arg(secret_enc), sqlc.narg(enrolled_at), sqlc.arg(last_step),
        sqlc.arg(recovery_hashes), sqlc.arg(updated_at))
ON CONFLICT (user_id) DO UPDATE SET key_id = EXCLUDED.key_id, secret_enc = EXCLUDED.secret_enc,
    enrolled_at = EXCLUDED.enrolled_at, last_step = EXCLUDED.last_step,
    recovery_hashes = EXCLUDED.recovery_hashes, updated_at = EXCLUDED.updated_at;

-- name: DeleteMFA :exec
DELETE FROM user_mfa WHERE user_id = sqlc.arg(user_id);

-- name: InsertChallenge :exec
INSERT INTO login_challenges (token_hash, user_id, created_at, expires_at, remote_ip)
VALUES (sqlc.arg(token_hash), sqlc.arg(user_id), sqlc.arg(created_at), sqlc.arg(expires_at), sqlc.arg(remote_ip));

-- name: ChallengeForUpdate :one
SELECT * FROM login_challenges WHERE token_hash = sqlc.arg(token_hash) FOR UPDATE;

-- name: CountChallengeAttempt :exec
UPDATE login_challenges SET attempts = attempts + 1 WHERE token_hash = sqlc.arg(token_hash);

-- name: UseChallenge :exec
UPDATE login_challenges SET used_at = sqlc.arg(used_at) WHERE token_hash = sqlc.arg(token_hash);

-- name: InsertSession :exec
INSERT INTO sessions (jti, user_id, realm, roles, issued_at, expires_at, last_seen_at, remote_ip, user_agent)
VALUES (sqlc.arg(jti), sqlc.arg(user_id), sqlc.arg(realm), sqlc.arg(roles), sqlc.arg(issued_at),
        sqlc.arg(expires_at), sqlc.arg(issued_at), sqlc.arg(remote_ip), sqlc.arg(user_agent));

-- name: SessionByJTI :one
SELECT * FROM sessions WHERE jti = sqlc.arg(jti);

-- name: TouchSession :exec
UPDATE sessions SET last_seen_at = sqlc.arg(last_seen_at)
WHERE jti = sqlc.arg(jti) AND revoked_at IS NULL AND last_seen_at < sqlc.arg(last_seen_at);

-- name: LiveSessionsOfUser :many
SELECT * FROM sessions
WHERE user_id = sqlc.arg(user_id) AND revoked_at IS NULL AND expires_at > sqlc.arg(now)
ORDER BY issued_at;

-- name: RevokeSession :execrows
UPDATE sessions SET revoked_at = sqlc.arg(revoked_at), revoked_by = sqlc.arg(revoked_by), revoke_reason = sqlc.arg(revoke_reason)
WHERE jti = sqlc.arg(jti) AND revoked_at IS NULL;

-- name: RevokeUserSessions :many
UPDATE sessions SET revoked_at = sqlc.arg(revoked_at), revoked_by = sqlc.arg(revoked_by), revoke_reason = sqlc.arg(revoke_reason)
WHERE user_id = sqlc.arg(user_id) AND revoked_at IS NULL AND expires_at > sqlc.arg(revoked_at)
RETURNING jti;

-- name: DeleteExpiredSessions :execrows
DELETE FROM sessions WHERE expires_at < sqlc.arg(before);

-- name: DeleteExpiredChallenges :execrows
DELETE FROM login_challenges WHERE expires_at < sqlc.arg(before);

-- name: UserForUpdate :one
SELECT * FROM users WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: SetMFALock :exec
UPDATE users
SET mfa_failures = sqlc.arg(mfa_failures), mfa_locked_until = sqlc.narg(mfa_locked_until),
    mfa_hard_locked = sqlc.arg(mfa_hard_locked)
WHERE id = sqlc.arg(id);
