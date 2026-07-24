-- Sessions: refresh-token-based, device-bound, with rotation reuse detection.
-- Access tokens are stateless (JWT); refresh tokens are stored hashed here.
-- On rotation: old refresh token's `rotated_to` is set; if an already-rotated
-- token is presented again, the entire session is revoked (reuse detected).

CREATE TABLE sessions (
    session_id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id               UUID         NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    device_id             UUID         NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,

    -- Refresh token verifier: SHA-256 hash of the raw refresh token string.
    -- Never store the raw refresh token.
    refresh_token_hash    TEXT         NOT NULL UNIQUE,
    refresh_token_jti     UUID         NOT NULL UNIQUE,

    issued_at             TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at            TIMESTAMPTZ  NOT NULL,
    revoked_at            TIMESTAMPTZ,
    revoked_reason        TEXT,

    -- Rotation chain: when this token is rotated, `rotated_to` points to the new session.
    rotated_to            UUID         REFERENCES sessions(session_id),

    -- Request metadata at creation
    user_agent            TEXT,
    ip_address            INET
);

CREATE INDEX idx_sessions_user_id ON sessions (user_id);
CREATE INDEX idx_sessions_device_id ON sessions (device_id);
CREATE INDEX idx_sessions_expires_at ON sessions (expires_at) WHERE revoked_at IS NULL;
