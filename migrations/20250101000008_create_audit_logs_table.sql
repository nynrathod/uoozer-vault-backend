-- Audit log: append-only record of security-relevant events.
-- Cannot be modified or deleted (no UPDATE/DELETE grants in prod).

CREATE TABLE audit_logs (
    audit_id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id               UUID         REFERENCES users(user_id) ON DELETE SET NULL,
    device_id             UUID         REFERENCES devices(device_id) ON DELETE SET NULL,
    event_type            TEXT         NOT NULL,
    event_metadata        JSONB        NOT NULL DEFAULT '{}',
    ip_address            INET,
    user_agent            TEXT,
    created_at            TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_logs_user_id ON audit_logs (user_id);
CREATE INDEX idx_audit_logs_created_at ON audit_logs (created_at);
CREATE INDEX idx_audit_logs_event_type ON audit_logs (event_type);
