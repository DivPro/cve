package source

import (
	"context"

	"github.com/divpro/cve/internal/entity/cve"
)

const (
	sourceDebian = "debian"
	sourceRedhat = "redhat"
)

type Source interface {
	Download(ctx context.Context) ([]cve.CVE, error)
	GetName() string
}
