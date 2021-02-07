package lock

import (
	"context"
	"errors"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/jmoiron/sqlx"
)

type Lock interface {
	GetID() int64
	GetAcquiredAt() time.Time
}

type WorkerFn func()

type lock struct {
	id       int64
	acquired time.Time
}

func (l lock) GetID() int64 {
	return l.id
}

func (l lock) GetAcquiredAt() time.Time {
	return l.acquired
}

type Service interface {
	Acquire(ctx context.Context, id int64, worker WorkerFn) (Lock, error)
}

type service struct {
	db *sqlx.DB
}

var ErrLockExists = errors.New("lock already acquired")

func New(db *sqlx.DB) Service {
	return &service{db: db}
}

func (s *service) Acquire(ctx context.Context, id int64, worker WorkerFn) (Lock, error) {
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

	go func() {
		defer func() {
			_, err = conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, id)

			if err != nil {
				log.Error().Err(err).Msg("unlock")
			} else {
				log.Debug().Int64("id", id).Msg("lock released")
			}
		}()

		worker()
	}()

	return lock{
		id:       id,
		acquired: time.Now(),
	}, nil
}
