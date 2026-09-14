package scan

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
)

// isolatedSchema puts a test package's tables in a schema of its own.
//
// `go test ./...` runs different packages concurrently, and every DB-backed
// test here truncates the tables it works with. Sharing one schema means two
// packages wipe each other's fixtures mid-run and fail in ways that look like
// product defects. A schema per package makes the isolation structural rather
// than a rule someone has to remember.
func isolatedSchema(ctx context.Context, dsn, schema string) (string, error) {
	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		return "", err
	}
	defer admin.Close()
	if _, err := admin.ExecContext(ctx, "CREATE SCHEMA IF NOT EXISTS "+schema); err != nil {
		return "", fmt.Errorf("create schema %s: %w", schema, err)
	}

	u, err := url.Parse(dsn)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	return u.String(), nil
}
