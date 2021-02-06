package source

import (
	"context"

	"github.com/divpro/cve/internal/entity"
)

const (
	sourceDebian = "debian"
	sourceRedhat = "redhat"
)

type Source interface {
	Download(ctx context.Context) ([]entity.CVE, error)
	GetName() string
}
