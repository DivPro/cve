package get

import (
	"context"

	"github.com/divpro/cve/internal/entity/cve"
)

type Service interface {
	GetByID(context.Context, *cve.FindFilter) ([]cve.CVE, error)
}

type service struct {
	db cve.Repository
}

func New(db cve.Repository) Service {
	return &service{db: db}
}

func (s *service) GetByID(ctx context.Context, filter *cve.FindFilter) ([]cve.CVE, error) {
	return s.db.Find(ctx, filter)
}
