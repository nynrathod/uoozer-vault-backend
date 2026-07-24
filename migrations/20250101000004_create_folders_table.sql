-- Folders: encrypted metadata + self-referencing parent_folder_id.
-- Server sees tree structure (UUIDs) but NEVER folder names.
-- `encrypted_metadata` contains: { name, color, icon, ... } encrypted client-side.

CREATE TABLE folders (
    folder_id             UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id               UUID         NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    parent_folder_id      UUID         REFERENCES folders(folder_id) ON DELETE CASCADE,

    -- Encrypted metadata blob (XChaCha20-Poly1305)
    encrypted_metadata    BYTEA        NOT NULL,
    metadata_nonce        BYTEA        NOT NULL,  -- 24 bytes (XChaCha20 nonce)

    created_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),
    deleted_at            TIMESTAMPTZ,

    CONSTRAINT metadata_nonce_length CHECK (length(metadata_nonce) = 24)
);

CREATE INDEX idx_folders_user_id ON folders (user_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_folders_parent ON folders (parent_folder_id) WHERE deleted_at IS NULL;
