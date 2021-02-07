package cve

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
)

type CVE struct {
	ID          string    `db:"id" json:"id"`
	PackageName string    `db:"package" json:"package_name"`
	Body        string    `db:"body" json:"raw"`
	Source      string    `db:"source" json:"source"`
	CreatedAt   time.Time `db:"created_at" json:"created_at"`
}

type FindFilter struct {
	ID      string `db:"id"`
	Package string `db:"package"`
	Source  string `db:"source"`
}

//go:generate mockery --name=Repository --case underscore
type Repository interface {
	Replace(ctx context.Context, cve []CVE) error
	Find(ctx context.Context, filter *FindFilter) ([]CVE, error)
}

type repository struct {
	db *sqlx.DB
}

func NewCVERepo(db *sqlx.DB) Repository {
	return repository{db: db}
}

func (r repository) Replace(ctx context.Context, cve []CVE) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("%w while get db transaction", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	q, err := tx.PrepareNamedContext(
		ctx,
		`INSERT INTO cve (id, package, body, source)
			VALUES (:id, :package, :body, :source)
			ON CONFLICT DO NOTHING`,
	)
	if err != nil {
		return fmt.Errorf("%w while prepare insert query", err)
	}

	_, err = tx.ExecContext(ctx, "TRUNCATE TABLE cve")
	if err != nil {
		return fmt.Errorf("%w while truncate old cve", err)
	}

	for _, m := range cve {
		_, err := q.ExecContext(ctx, m)
		if err != nil {
			return fmt.Errorf("%w insert new cve: %v", err, m)
		}
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("%w while commit db transaction", err)
	}

	return nil
}

func (r repository) Find(ctx context.Context, filter *FindFilter) ([]CVE, error) {
	dest := make([]CVE, 0)
	q := strings.Builder{}
	q.WriteString(`SELECT
			id,
			package,
			body,
			source,
			created_at
		FROM cve
		WHERE id = :id
	`)
	if filter.Package != "" {
		q.WriteString(" AND package = :package")
	}
	if filter.Source != "" {
		q.WriteString(" AND source = :source")
	}

	stm, err := r.db.PrepareNamedContext(ctx, q.String())
	if err != nil {
		return nil, err
	}
	err = stm.SelectContext(ctx, &dest, filter)
	if err != nil {
		return nil, err
	}

	return dest, nil
}
