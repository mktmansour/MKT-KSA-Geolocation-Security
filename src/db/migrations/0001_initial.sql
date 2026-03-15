CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY NOT NULL,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_login_at TEXT
);

CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    device_fingerprint TEXT NOT NULL,
    friendly_name TEXT NOT NULL,
    metadata TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS security_alerts (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    alert_type TEXT NOT NULL,
    alert_data TEXT NOT NULL,
    created_at TEXT NOT NULL
);
