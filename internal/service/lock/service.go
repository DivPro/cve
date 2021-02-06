package lock

import (
	"context"
	"errors"
	"time"

	"github.com/jmoiron/sqlx"
)

type Service interface {
	AcquireNoWait(ctx context.Context, id int64) (*Lock, error)
	Release(ctx context.Context, l *Lock) error
}

type service struct {
	db *sqlx.DB
}

var ErrLockExists = errors.New("lock already acquired")

func New(db *sqlx.DB) Service {
	return &service{db: db}
}

func (s *service) AcquireNoWait(ctx context.Context, id int64) (*Lock, error) {
	conn, err := s.db.Connx(ctx)
	if err != nil {
		return nil, err
	}

	var acquired bool
	err = conn.GetContext(ctx, &acquired, `SELECT pg_try_advisory_lock($1)`, id)
	if err != nil {
		return nil, err
	}
	if !acquired {
		return nil, ErrLockExists
	}

	return &Lock{
		id:       id,
		acquired: time.Now(),
		conn:     conn,
	}, nil
}

func (s *service) Release(ctx context.Context, l *Lock) error {
	_, err := l.conn.ExecContext(ctx, `SELECT pg_advisory_unlock($1)`, l.id)
	if err != nil {
		return err
	}

	return nil
}
