CREATE TABLE IF NOT EXISTS group_account_priority_operations (
    id BIGSERIAL PRIMARY KEY,
    group_id BIGINT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    operation_id VARCHAR(128) NOT NULL,
    request_hash VARCHAR(71) NOT NULL,
    expected_readback_hash VARCHAR(71) NOT NULL,
    readback_hash VARCHAR(71) NOT NULL DEFAULT '',
    request_json JSONB NOT NULL,
    response_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (group_id, operation_id)
);
