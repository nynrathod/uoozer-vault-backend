-- File chunks: each chunk is an independent R2 object.
-- R2 key layout: {user_id}/{file_id}/{version_id}/{segment_index}/{chunk_index}
-- `chunk_blake3` is the hash of the CIPHERTEXT chunk (for upload verification).
-- Server never sees plaintext chunk content.

CREATE TABLE file_chunks (
    chunk_id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    version_id            UUID         NOT NULL REFERENCES file_versions(version_id) ON DELETE CASCADE,
    file_id               UUID         NOT NULL REFERENCES files(file_id) ON DELETE CASCADE,
    user_id               UUID         NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,

    chunk_index           INTEGER      NOT NULL,
    segment_index         INTEGER      NOT NULL DEFAULT 0,
    chunk_size            BIGINT       NOT NULL,
    chunk_blake3          BYTEA        NOT NULL,

    -- R2 object metadata
    r2_key                TEXT         NOT NULL,
    r2_etag               TEXT,
    uploaded_at           TIMESTAMPTZ,

    created_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),

    CONSTRAINT chunk_size_positive CHECK (chunk_size > 0),
    CONSTRAINT chunk_index_nonneg CHECK (chunk_index >= 0),
    CONSTRAINT segment_index_nonneg CHECK (segment_index >= 0),
    UNIQUE (version_id, chunk_index, segment_index)
);

CREATE INDEX idx_file_chunks_version ON file_chunks (version_id);
CREATE INDEX idx_file_chunks_user ON file_chunks (user_id);
CREATE INDEX idx_file_chunks_upload_pending ON file_chunks (version_id) WHERE uploaded_at IS NULL;
