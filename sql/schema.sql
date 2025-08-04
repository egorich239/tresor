-- Tresor Database Schema
--
-- This schema is designed for SQLite3 and follows a strict append-only model.
-- State changes, including deletions, are represented by inserting new rows.
-- The `session` is the central unit of audit: every state change is linked
-- to the session in which it occurred.
--
-- All timestamps are stored as TEXT in ISO8601 format ("YYYY-MM-DD HH:MM:SS.SSS").

--
-- Sessions and Identities
--
-- NOTE: To break the circular dependency between sessions and identities, the
-- foreign key constraints on `sessions.server_id` and `sessions.client_id` have
-- been removed. The application logic is responsible for ensuring these IDs are valid.

CREATE TABLE sessions (
    id INTEGER PRIMARY KEY,

    -- A random 32-byte string, identifying the session.
    --
    -- NOTE: This is *not* the transient session encryption key which is never
    -- stored.
    session_id TEXT NOT NULL UNIQUE,

    -- Nonce used by the client during session establishment.
    --
    -- Unique constraint is used to prevent replays.
    nonce TEXT NOT NULL UNIQUE,

    -- These are logically foreign keys to identities(id), but the schema constraint
    -- is removed to break the circular dependency.
    server_id INTEGER NOT NULL,
    client_id INTEGER NOT NULL,

    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
    expires_at TEXT NOT NULL,
    closed_at TEXT,

    -- If the session got compromised, we store when and during which session
    -- we marked this session as compromised.
    compromised_at TEXT,
    compromised_session_id INTEGER REFERENCES sessions(id)
);

CREATE TABLE identities (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    public_key TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL CHECK (role IN ('server', 'admin', 'reader')),

    -- Timestamp of the *row* creation.
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
    -- The initial root and server identities will have a NULL created_session_id.
    created_session_id INTEGER REFERENCES sessions(id),

    -- Timestamp of the *identity* compromise.
    compromised_at TEXT,
    compromised_session_id INTEGER REFERENCES sessions(id),

    -- Timestamp of the *identity* deletion.
    expires_at TEXT,
    expires_session_id INTEGER REFERENCES sessions(id)
);


--
-- Secrets and Environments
--

CREATE TABLE secrets (
    id INTEGER PRIMARY KEY,
    "key" TEXT NOT NULL,
    value BLOB, -- A NULL value indicates the key has been deleted.

    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
    created_session_id INTEGER NOT NULL REFERENCES sessions(id)
);
CREATE INDEX idx_secrets_key_created_at ON secrets("key", created_at DESC);


CREATE TABLE envs (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,

    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
    created_session_id INTEGER NOT NULL REFERENCES sessions(id),

    deleted_at TEXT,
    deleted_session_id INTEGER REFERENCES sessions(id)
);
CREATE UNIQUE INDEX idx_envs_name_unique ON envs(name) WHERE deleted_at IS NULL;


CREATE TABLE envvars (
    id INTEGER PRIMARY KEY,
    env_id INTEGER NOT NULL REFERENCES envs(id),
    envvar TEXT NOT NULL,
    "key" TEXT, -- A NULL value indicates the envvar has been unmapped/deleted.

    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
    created_session_id INTEGER NOT NULL REFERENCES sessions(id)
);
CREATE INDEX idx_envvars_keys ON envvars(env_id, envvar, created_at DESC);


CREATE TABLE reader_env_auths (
    id INTEGER PRIMARY KEY,
    reader_id INTEGER NOT NULL REFERENCES identities(id),
    env_id INTEGER NOT NULL REFERENCES envs(id),

    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
    created_session_id INTEGER NOT NULL REFERENCES sessions(id),

    revoked_at TEXT,
    revoked_session_id INTEGER REFERENCES sessions(id)
);


--
-- Backup
--

CREATE TABLE backup_recipients (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    recipient_key TEXT NOT NULL UNIQUE,

    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
    created_session_id INTEGER NOT NULL REFERENCES sessions(id),

    approved_at TEXT,
    approved_session_id INTEGER REFERENCES sessions(id),

    compromised_at TEXT,
    compromised_session_id INTEGER REFERENCES sessions(id),

    expires_at TEXT,
    expires_session_id INTEGER REFERENCES sessions(id)
);

--
-- Audit log
--
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY,
    session_id INTEGER NOT NULL REFERENCES sessions(id),
    action TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))
);
