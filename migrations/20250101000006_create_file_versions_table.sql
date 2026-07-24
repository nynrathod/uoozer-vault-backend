-- File versions: each upload creates a new version.
-- Versioning = new chunk set + pointer swap. Restoring = pointer swap, instant.
-- POC retains all versions indefinitely (no auto-pruning).

CREATE TABLE file_versions (
    version_id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    file_id               UUID         NOT NULL REFERENCES files(file_id) ON DELETE CASCADE,

    version_number        INTEGER      NOT NULL,
    total_size            BIGINT       NOT NULL,
    total_chunks          INTEGER      NOT NULL,
    plaintext_blake3      BYTEA        NOT NULL,

    -- secretstream header (crypto_secretstream_xchacha20poly1305 init header)
    -- Needed by client to initialize decryption stream. 24 bytes.
    encryption_header     BYTEA        NOT NULL,

    is_current            BOOLEAN      NOT NULL DEFAULT false,
    created_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),

    CONSTRAINT version_number_positive CHECK (version_number > 0),
    CONSTRAINT total_chunks_positive CHECK (total_chunks > 0),
    CONSTRAINT encryption_header_length CHECK (length(encryption_header) = 24),
    UNIQUE (file_id, version_number)
);

CREATE INDEX idx_file_versions_file_id ON file_versions (file_id);

-- Wire up the current_version_id FK (deferred because of circular dependency)
ALTER TABLE files
    ADD CONSTRAINT fk_files_current_version
    FOREIGN KEY (current_version_id) REFERENCES file_versions(version_id) ON DELETE SET NULL;
