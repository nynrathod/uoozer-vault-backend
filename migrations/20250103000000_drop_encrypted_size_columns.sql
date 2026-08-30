ALTER TABLE file_chunks
  DROP COLUMN IF EXISTS encrypted_size,
  DROP COLUMN IF EXISTS plaintext_size;

ALTER TABLE file_chunks
  DROP CONSTRAINT IF EXISTS encrypted_size_matches_plaintext;