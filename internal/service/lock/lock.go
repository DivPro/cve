package lock

import (
	"time"

	"github.com/jmoiron/sqlx"
)

type Lock struct {
	id       int64
	acquired time.Time
	conn     *sqlx.Conn
}

func (l Lock) GetID() int64 {
	return l.id
}

func (l Lock) GetAcquiredAt() time.Time {
	return l.acquired
}
