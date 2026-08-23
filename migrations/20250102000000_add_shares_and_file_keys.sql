-- Add wrapped File Key to file_versions (so files can be shared without sharing the DEK)
ALTER TABLE file_versions 
ADD COLUMN IF NOT EXISTS wrapped_file_key BYTEA,
ADD COLUMN IF NOT EXISTS wrapped_file_key_nonce BYTEA;

-- Unified table for both File and Folder shares
CREATE TABLE IF NOT EXISTS item_shares (
    share_id             UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_user_id        UUID         NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    item_type            TEXT         NOT NULL CHECK (item_type IN ('file', 'folder')),
    encrypted_payload    BYTEA        NOT NULL,
    encrypted_nonce      BYTEA        NOT NULL,
    encryption_header    BYTEA,       
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at           TIMESTAMPTZ
);

ALTER TABLE item_shares ADD COLUMN IF NOT EXISTS item_id UUID NOT NULL;