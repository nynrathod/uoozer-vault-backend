-- Zero-knowledge user account.
-- Server stores: email (for login lookup), salt, Argon2id params,
-- bcrypt-hashed Auth Key (never the Auth Key itself), wrapped DEK
-- (opaque ciphertext), recovery-wrapped DEK, and public keys.
-- Server NEVER stores: plaintext password, Master Key, DEK, or any
-- key that could decrypt user data.

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE users (
    user_id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    email                TEXT         NOT NULL UNIQUE,
    email_normalized     TEXT         NOT NULL UNIQUE,
		full_name TEXT NOT NULL DEFAULT '',

    -- KDF parameters (stored per-user for forward-compatible upgrades)
    salt                 BYTEA        NOT NULL,
    argon2_params        JSONB        NOT NULL,

    -- Auth Key verifiers (bcrypt hashes — never the keys themselves)
    auth_key_hash        TEXT         NOT NULL,
    recovery_auth_key_hash TEXT       NOT NULL,

    -- Wrapped DEK (encrypted under Master Key) — opaque to server
    wrapped_dek           BYTEA       NOT NULL,
    wrapped_dek_nonce     BYTEA       NOT NULL,

    -- Recovery-wrapped DEK (encrypted under Recovery Key) — opaque to server
    recovery_wrapped_dek       BYTEA  NOT NULL,
    recovery_wrapped_dek_nonce BYTEA  NOT NULL,

    -- User's identity public key (Ed25519, 32 bytes) — for future sig verification
    identity_pubkey      BYTEA        NOT NULL,

    -- Lifecycle
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ  NOT NULL DEFAULT now(),
    disabled_at          TIMESTAMPTZ,

    CONSTRAINT salt_length CHECK (length(salt) = 16),
    CONSTRAINT identity_pubkey_length CHECK (length(identity_pubkey) = 32)
);

CREATE INDEX idx_users_email_normalized ON users (email_normalized);
