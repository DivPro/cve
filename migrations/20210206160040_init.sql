-- +goose Up
-- +goose StatementBegin
CREATE TABLE cve (
                     id VARCHAR NOT NULL,
                     package VARCHAR NOT NULL,
                     body JSONB NOT NULL,
                     source VARCHAR NOT NULL,
                     created_at timestamptz NOT NULL DEFAULT current_timestamp,
                     PRIMARY KEY (id, package)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE cve
-- +goose StatementEnd
