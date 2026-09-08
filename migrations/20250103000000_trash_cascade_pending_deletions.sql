-- A folder row must never orphan its files. (Was ON DELETE SET NULL.)
-- NOTE: with CASCADE, folder rows must only ever be deleted AFTER their
-- files were explicitly deleted by the service (which all fixed paths below do).
ALTER TABLE files DROP CONSTRAINT IF EXISTS files_folder_id_fkey;
DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints tc
        JOIN information_schema.key_column_usage kcu
          ON tc.constraint_name = kcu.constraint_name
         AND tc.constraint_schema = kcu.constraint_schema
        WHERE tc.table_name = 'files' AND tc.constraint_type = 'FOREIGN KEY'
          AND kcu.column_name = 'folder_id'
    ) THEN
        ALTER TABLE files
            ADD CONSTRAINT files_folder_id_fkey
            FOREIGN KEY (folder_id) REFERENCES folders(folder_id) ON DELETE CASCADE;
    END IF;
END $$;

-- The "100%" guarantee: every object scheduled for deletion is recorded in
-- the SAME transaction that deletes the DB rows; a worker retries until HEAD
-- confirms the object is gone.
CREATE TABLE IF NOT EXISTS pending_storage_deletions (
    id              BIGSERIAL   PRIMARY KEY,
    r2_key          TEXT        NOT NULL UNIQUE,
    user_id         UUID,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    attempts        INTEGER     NOT NULL DEFAULT 0,
    last_attempt_at TIMESTAMPTZ,
    last_error      TEXT
);
CREATE INDEX IF NOT EXISTS idx_pending_deletions_created
    ON pending_storage_deletions (created_at);