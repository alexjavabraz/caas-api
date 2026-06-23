ALTER TABLE developer_clients
    ADD COLUMN IF NOT EXISTS is_email_verified        BOOLEAN     NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS email_verification_token TEXT,
    ADD COLUMN IF NOT EXISTS email_verification_expires_at TIMESTAMPTZ;

-- Accounts that existed before this migration are considered pre-verified
UPDATE developer_clients
   SET is_email_verified = TRUE
 WHERE is_email_verified = FALSE;
