-- Files: encrypted metadata + pointer to current version.
-- `plaintext_blake3` is computed by the client on the PLAINTEXT file.
-- This enables same-user dedup (skip re-upload if hash matches).
-- Cross-user dedup is explicitly NOT supported (different DEKs → different ciphertext).

CREATE TABLE files (
    file_id               UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id               UUID         NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    folder_id             UUID         REFERENCES folders(folder_id) ON DELETE SET NULL,

    -- Encrypted metadata (filename, mime type, size, etc.)
    encrypted_metadata    BYTEA        NOT NULL,
    metadata_nonce        BYTEA        NOT NULL,

    -- Plaintext BLAKE3 hash (for same-user dedup; client-computed)
    plaintext_blake3      BYTEA        NOT NULL,
    total_size            BIGINT       NOT NULL,

    -- Points to the active version
    current_version_id    UUID,

    created_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),
    deleted_at            TIMESTAMPTZ,

    CONSTRAINT metadata_nonce_length CHECK (length(metadata_nonce) = 24),
    CONSTRAINT total_size_nonneg CHECK (total_size >= 0)
);

CREATE INDEX idx_files_user_id ON files (user_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_files_folder ON files (folder_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_files_user_blake3 ON files (user_id, plaintext_blake3) WHERE deleted_at IS NULL;
