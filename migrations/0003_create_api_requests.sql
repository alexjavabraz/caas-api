CREATE TABLE api_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    idempotency_key TEXT,
    is_idempotent_hit BOOLEAN NOT NULL DEFAULT FALSE,
    status_code SMALLINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_api_requests_client_id ON api_requests (client_id);
CREATE INDEX idx_api_requests_created_at ON api_requests (created_at DESC);
