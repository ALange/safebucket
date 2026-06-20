-- +goose Up
CREATE TABLE api_keys
(
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    access TEXT NOT NULL CHECK (access IN ('read_only', 'read_write')),
    expires_at DATETIME,
    revoked_at DATETIME,
    last_used_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_api_keys_user_id FOREIGN KEY (user_id) REFERENCES users (id) ON UPDATE CASCADE ON DELETE CASCADE
);

CREATE UNIQUE INDEX idx_api_keys_user_name_active
    ON api_keys (user_id, name)
    WHERE revoked_at IS NULL;

CREATE INDEX idx_api_keys_user_id ON api_keys (user_id);

-- +goose Down
DROP TABLE IF EXISTS api_keys;
