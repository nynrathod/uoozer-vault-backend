-- Devices: first-class independent clients (NOT WhatsApp-style relays).
-- Each device logs in directly with email + password (or Recovery Key).
-- Device revocation kills all sessions for that device instantly.

CREATE TABLE devices (
    device_id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id              UUID         NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    device_name          TEXT         NOT NULL,
    device_pubkey        BYTEA        NOT NULL,  -- Ed25519 public key, 32 bytes

    -- Lifecycle
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_seen_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),
    revoked_at           TIMESTAMPTZ,

    CONSTRAINT device_pubkey_length CHECK (length(device_pubkey) = 32)
);

CREATE INDEX idx_devices_user_id ON devices (user_id) WHERE revoked_at IS NULL;
CREATE INDEX idx_devices_user_active ON devices (user_id, revoked_at);
