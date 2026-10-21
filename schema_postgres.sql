-- ==============================================================================
-- TRUSTVAULT ZERO-TRUST SECURITY PLATFORM
-- POSTGRESQL / SUPABASE / NEON / AWS RDS PRODUCTION DDL SCHEMA
-- ==============================================================================
-- Execute this SQL script in your Supabase SQL Editor, Neon Console, or psql
-- ==============================================================================

-- 1. USERS & IDENTITY DIRECTORY
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(64) PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL CHECK (role IN ('admin', 'owner', 'viewer')),
    password_hash VARCHAR(255) NOT NULL,
    title VARCHAR(255) NOT NULL,
    avatar_color VARCHAR(20) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2. ENCRYPTED DOCUMENTS METADATA
CREATE TABLE IF NOT EXISTS documents (
    id VARCHAR(64) PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    category VARCHAR(100) NOT NULL,
    filename VARCHAR(255) NOT NULL,
    stored_path VARCHAR(255) NOT NULL,
    file_size BIGINT NOT NULL,
    mime_type VARCHAR(100) NOT NULL,
    sha256_hash VARCHAR(64) NOT NULL,
    owner_id VARCHAR(64) NOT NULL REFERENCES users(id),
    owner_name VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_deleted INT DEFAULT 0
);

-- 3. SERVER-ENFORCED ACCESS PERMISSIONS
CREATE TABLE IF NOT EXISTS permissions (
    id VARCHAR(64) PRIMARY KEY,
    document_id VARCHAR(64) NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    access_level VARCHAR(20) NOT NULL CHECK (access_level IN ('read', 'edit')),
    granted_by VARCHAR(64) NOT NULL REFERENCES users(id),
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(document_id, user_id)
);

-- 4. SINGLE-USE ACTIVE DOWNLOAD TOKENS
CREATE TABLE IF NOT EXISTS active_download_tokens (
    token VARCHAR(128) PRIMARY KEY,
    document_id VARCHAR(64) NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

-- 5. PASSWORD RESETS & VERIFICATION CODES
CREATE TABLE IF NOT EXISTS password_resets (
    id VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    token VARCHAR(64) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used INT DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 6. DISPATCHED OUTBOUND SECURITY EMAILS
CREATE TABLE IF NOT EXISTS outbound_emails (
    id VARCHAR(64) PRIMARY KEY,
    recipient VARCHAR(255) NOT NULL,
    subject VARCHAR(255) NOT NULL,
    body TEXT NOT NULL,
    token VARCHAR(64),
    sent_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 7. IMMUTABLE SHA-256 HASH-CHAINED AUDIT LEDGER
CREATE TABLE IF NOT EXISTS audit_ledger (
    sequence_id BIGSERIAL PRIMARY KEY,
    prev_hash VARCHAR(64) NOT NULL,
    current_hash VARCHAR(64) NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor_id VARCHAR(64) NOT NULL,
    actor_name VARCHAR(255) NOT NULL,
    actor_role VARCHAR(50) NOT NULL,
    action VARCHAR(100) NOT NULL,
    target_type VARCHAR(50) NOT NULL,
    target_id VARCHAR(100) NOT NULL,
    target_name VARCHAR(255) NOT NULL,
    status VARCHAR(20) NOT NULL CHECK (status IN ('ALLOWED', 'REFUSED')),
    ip_address VARCHAR(50) NOT NULL,
    user_agent TEXT NOT NULL,
    details TEXT NOT NULL,
    signature VARCHAR(128) NOT NULL
);

-- CREATE ESSENTIAL PERFORMANCE INDEXES
CREATE INDEX IF NOT EXISTS idx_permissions_doc_user ON permissions(document_id, user_id);
CREATE INDEX IF NOT EXISTS idx_documents_owner ON documents(owner_id);
CREATE INDEX IF NOT EXISTS idx_ledger_seq ON audit_ledger(sequence_id);
CREATE INDEX IF NOT EXISTS idx_resets_token ON password_resets(token);
